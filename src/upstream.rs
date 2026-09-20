// =========================================================
// upstream.rs — EasyWAF
// Which backend a request goes to.
//
// A site had one `target`; since 0.13.0 it has a pool, and
// something has to choose. Weighted round-robin: enough for
// almost everyone, and the weight covers backends on unequal
// hardware, which is the common real case.
//
// Least-connections is the tempting alternative and needs
// in-flight accounting per upstream. It is worth having once
// there is evidence round-robin is losing, and there is not.
//
// The pool travels with the site row as one string, so
// choosing costs no extra query on the request path — where
// re-reading rows, not matching rules, is what the
// performance work of 0.11.0 found to be the cost.
// =========================================================

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Consecutive failures before a backend is taken out of the rotation.
///
/// Three rather than one: a single failure is as likely to be a request that
/// happened to arrive during a restart as a backend that has gone. Three in a
/// row, with nothing succeeding between them, is a pattern.
const FAILURES_BEFORE_OUT: u32 = 3;

/// How long it stays out before one request is let through to find out.
///
/// The cost of this being too long is traffic going to fewer backends than
/// exist; the cost of it being too short is a backend that is still down
/// taking a share of requests every few seconds. Thirty seconds is the usual
/// answer and is short enough that a restart is noticed within one.
const OUT_FOR: Duration = Duration::from_secs(30);

/// One backend of a site, as the request path needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// The `upstreams` row, which is what health is remembered against: the
    /// URL can be edited, and editing it should not carry a reputation over.
    pub id:     i64,
    pub url:    String,
    /// Share of the rotation. At least 1; a heavier backend takes more.
    pub weight: i64,
}

/// Read the pool carried on the site row.
///
/// `id url weight` per line, built by `group_concat` in the site query. A URL
/// contains neither a space nor a newline, so nothing here has to escape
/// anything. A line that does not parse is skipped rather than guessed at: a
/// backend nobody can name is a backend nobody can reach.
pub fn parse_pool(raw: &str) -> Vec<Upstream> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (id, rest) = line.split_once(' ')?;
            let id: i64 = id.parse().ok()?;
            let (url, weight) = match rest.rsplit_once(' ') {
                Some((u, w)) => (u.trim(), w.trim().parse::<i64>().unwrap_or(1)),
                None         => (rest.trim(), 1),
            };
            if url.is_empty() {
                return None;
            }
            Some(Upstream { id, url: url.to_string(), weight: weight.max(1) })
        })
        .collect()
}

// ─── Health ──────────────────────────────────────────────
//
// Passive, circuit-breaker shaped: failures are counted on real traffic rather
// than probed for. It needs no scheduling, sends nothing at backends that may
// not want it, and measures the thing actually being asked — whether this
// proxy can serve this site from this backend. A prober can report a backend
// healthy while every real request to it fails.
//
// Its weakness is recovery latency: nothing notices a backend is back until
// the half-open request. That is a tuning question, and an active prober can
// be added for operators who want faster recovery.

/// What has been observed of one backend.
#[derive(Debug, Clone, Default)]
struct Observed {
    /// Failures since the last success. Reset by any success.
    consecutive: u32,
    /// Out of the rotation until this moment; None while it is in.
    out_until:   Option<Instant>,
}

/// Health is per node and never travels: node A may reach a backend node B
/// cannot, and copying that judgement would take a working backend out of
/// rotation everywhere because one node has a network problem.
static HEALTH: OnceLock<Mutex<HashMap<i64, Observed>>> = OnceLock::new();

fn health() -> &'static Mutex<HashMap<i64, Observed>> {
    HEALTH.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether a backend is currently taking requests.
///
/// A backend whose time is up counts as in: the request that finds it there is
/// the one that tests it, which is what half-open means.
fn taking_requests(id: i64, now: Instant) -> bool {
    match health().lock() {
        Ok(h)  => h.get(&id).and_then(|o| o.out_until).is_none_or(|until| until <= now),
        Err(_) => true,
    }
}

/// A request to this backend failed in a way that is the backend's fault.
///
/// A connection refused or a timeout is; so is a 5xx, which is the backend
/// saying it cannot answer. A 404 is not — that is the application answering,
/// and counting it would take a working backend out of rotation because
/// somebody asked for a missing page.
pub fn failed(id: i64) {
    let mut h = match health().lock() {
        Ok(h)  => h,
        Err(p) => p.into_inner(),
    };
    let o = h.entry(id).or_default();
    o.consecutive = o.consecutive.saturating_add(1);
    if o.consecutive >= FAILURES_BEFORE_OUT {
        // Each failure once it is out pushes the time back, so a backend that
        // keeps failing its half-open request is not asked again immediately.
        o.out_until = Some(Instant::now() + OUT_FOR);
    }
}

/// A request to this backend was answered. Anything remembered against it goes.
pub fn succeeded(id: i64) {
    let mut h = match health().lock() {
        Ok(h)  => h,
        Err(p) => p.into_inner(),
    };
    if let Some(o) = h.get_mut(&id) {
        o.consecutive = 0;
        o.out_until   = None;
    }
}

/// What the GUI shows beside a backend: how many failures in a row, and how
/// many seconds it is out for.
pub fn state_of(id: i64) -> (u32, Option<u64>) {
    let now = Instant::now();
    match health().lock() {
        Ok(h) => match h.get(&id) {
            Some(o) => {
                let left = o.out_until
                    .filter(|until| *until > now)
                    .map(|until| (until - now).as_secs() + 1);
                (o.consecutive, left)
            }
            None => (0, None),
        },
        Err(_) => (0, None),
    }
}

/// Forget everything observed. Tests only — the state is process-wide, and a
/// test that inherits another's failures is a test that fails for a reason
/// that is not in it.
#[cfg(test)]
fn forget_health() {
    if let Ok(mut h) = health().lock() {
        h.clear();
    }
}

// ─── Rotation ────────────────────────────────────────────

/// Where each site's rotation has got to. Per process, not per node cluster:
/// which backend served the last request is an observation, not configuration.
///
/// Nothing invalidates this when a pool changes, and nothing needs to: the
/// counter is taken modulo the weights of the pool in hand, so a count left
/// over from three backends only starts the rotation over two at a different
/// place — which a round robin has no opinion about. An entry per site id ever
/// seen is a few bytes and is gone on restart.
static TURN: OnceLock<Mutex<HashMap<i64, u64>>> = OnceLock::new();

fn turn() -> &'static Mutex<HashMap<i64, u64>> {
    TURN.get_or_init(|| Mutex::new(HashMap::new()))
}

/// What the request path needs to know about the backend it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chosen<'a> {
    pub upstream: &'a Upstream,
    /// Every backend of this site is currently out of the rotation, and this
    /// one was handed out anyway. Refusing instead would turn "all the
    /// backends look ill" into "the site is down" without ever asking one of
    /// them, and the answer to the operator has to say which of the two it is.
    pub all_out:  bool,
}

/// The next upstream for this site, skipping any that are out of the rotation.
///
/// With one upstream this returns it every time — including when it is out,
/// because a pool of one has nothing to fail over to and a request is more
/// useful than a refusal. Which is the behaviour every site had before pools
/// existed, and the behaviour almost every site keeps.
pub fn choose<'a>(site_id: i64, pool: &'a [Upstream]) -> Option<Chosen<'a>> {
    choose_except(site_id, pool, &[])
}

/// The next upstream that is not one of `tried`.
///
/// For the second attempt at a request whose first backend could not be
/// reached: trying the one that just failed again would spend the retry on the
/// answer already given.
pub fn choose_except<'a>(
    site_id: i64,
    pool:    &'a [Upstream],
    tried:   &[i64],
) -> Option<Chosen<'a>> {
    let now = Instant::now();
    let pool: Vec<&Upstream> = pool.iter().filter(|u| !tried.contains(&u.id)).collect();
    let live: Vec<&Upstream> =
        pool.iter().copied().filter(|u| taking_requests(u.id, now)).collect();

    // All of them out: hand one out regardless, and say so. A pool where every
    // backend has failed recently is not a reason to stop asking any of them —
    // they may all have been restarted together, which is what a deploy is.
    let all_out = live.is_empty() && !pool.is_empty();
    let live: Vec<&Upstream> = if all_out { pool } else { live };

    pick_from(site_id, &live).map(|upstream| Chosen { upstream, all_out })
}

/// Round-robin over whatever is in rotation.
fn pick_from<'a>(site_id: i64, pool: &[&'a Upstream]) -> Option<&'a Upstream> {
    match pool {
        []  => None,
        [u] => Some(u),
        _   => {
            let total: u64 = pool.iter().map(|u| u.weight.max(1) as u64).sum();
            if total == 0 {
                return pool.first().copied();
            }
            // The counter is advanced under the lock and the choice made from
            // the value taken, so two requests arriving together take two
            // different turns rather than the same one.
            let n = {
                let mut t = match turn().lock() {
                    Ok(t)  => t,
                    Err(p) => p.into_inner(),
                };
                let slot = t.entry(site_id).or_insert(0);
                let n = *slot;
                *slot = slot.wrapping_add(1);
                n
            };
            pick(pool, n % total)
        }
    }
}

/// The upstream whose slice of the rotation `offset` falls in.
fn pick<'a>(pool: &[&'a Upstream], offset: u64) -> Option<&'a Upstream> {
    let mut seen = 0u64;
    for u in pool {
        seen += u.weight.max(1) as u64;
        if offset < seen {
            return Some(u);
        }
    }
    pool.last().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ids are handed out from a counter so no two test pools share one:
    /// health is remembered per id for the whole process.
    fn pool(spec: &[(&str, i64)]) -> Vec<Upstream> {
        use std::sync::atomic::{AtomicI64, Ordering};
        static NEXT: AtomicI64 = AtomicI64::new(1);
        spec.iter()
            .map(|(u, w)| Upstream {
                id:     NEXT.fetch_add(1, Ordering::Relaxed),
                url:    u.to_string(),
                weight: *w,
            })
            .collect()
    }

    /// Url and weight, which is what the parse tests are about; the id is
    /// whatever the row happened to be.
    fn urls(p: &[Upstream]) -> Vec<(String, i64)> {
        p.iter().map(|u| (u.url.clone(), u.weight)).collect()
    }

    /// The url of what `choose` handed out.
    fn chose(site: i64, p: &[Upstream]) -> Option<String> {
        choose(site, p).map(|c| c.upstream.url.clone())
    }

    #[test]
    fn a_pool_is_read_from_the_row() {
        let p = parse_pool("1 http://a:8080 1\n2 http://b:8080 3\n");
        assert_eq!(urls(&p), vec![("http://a:8080".to_string(), 1), ("http://b:8080".to_string(), 3)]);
    }

    #[test]
    fn a_line_without_a_weight_or_with_a_bad_one_weighs_one() {
        assert_eq!(urls(&parse_pool("7 http://a")), vec![("http://a".to_string(), 1)]);
        assert_eq!(urls(&parse_pool("7 http://a x")), vec![("http://a".to_string(), 1)]);
        // Zero and negative would take a backend out of the rotation while
        // still being listed in it, which is not something a weight should be
        // able to express.
        assert_eq!(urls(&parse_pool("7 http://a 0")), vec![("http://a".to_string(), 1)]);
        assert_eq!(urls(&parse_pool("7 http://a -4")), vec![("http://a".to_string(), 1)]);
    }

    #[test]
    fn blank_lines_are_not_backends() {
        assert!(parse_pool("").is_empty());
        assert!(parse_pool("\n  \n").is_empty());
        assert_eq!(urls(&parse_pool("3 http://a 1\n\n")), vec![("http://a".to_string(), 1)]);
    }

    #[test]
    fn one_upstream_is_always_the_answer() {
        // The behaviour every site had before pools, and almost every site
        // keeps: no rotation state is touched at all.
        let p = pool(&[("http://only", 1)]);
        for _ in 0..5 {
            assert_eq!(chose(1, &p).as_deref(), Some("http://only"));
        }
    }

    #[test]
    fn an_empty_pool_chooses_nothing() {
        assert!(choose(2, &[]).is_none());
    }

    #[test]
    fn equal_weights_go_round_in_turn() {
        let p = pool(&[("http://a", 1), ("http://b", 1), ("http://c", 1)]);
        let got: Vec<String> = (0..6).map(|_| chose(3, &p).unwrap()).collect();
        assert_eq!(got, ["http://a", "http://b", "http://c",
                         "http://a", "http://b", "http://c"]);
    }

    #[test]
    fn a_heavier_backend_takes_more_of_the_rotation() {
        // Three to one, which is the case the weight exists for: one backend
        // on larger hardware than the other.
        let p = pool(&[("http://big", 3), ("http://small", 1)]);
        let got: Vec<String> = (0..8).map(|_| chose(4, &p).unwrap()).collect();
        assert_eq!(got.iter().filter(|u| *u == "http://big").count(), 6);
        assert_eq!(got.iter().filter(|u| *u == "http://small").count(), 2);
    }

    #[test]
    fn each_site_rotates_on_its_own() {
        let p = pool(&[("http://a", 1), ("http://b", 1)]);
        assert_eq!(chose(5, &p).unwrap(), "http://a");
        assert_eq!(chose(6, &p).unwrap(), "http://a", "another site took this one's turn");
        assert_eq!(chose(5, &p).unwrap(), "http://b");
    }

    // ── Health ──────────────────────────────────────────

    #[test]
    fn a_backend_leaves_the_rotation_after_three_failures_in_a_row() {
        forget_health();
        let p = pool(&[("http://good", 1), ("http://bad", 1)]);
        let bad = p[1].id;

        // Two failures are not a pattern; the backend is still asked.
        failed(bad);
        failed(bad);
        let got: Vec<String> = (0..4).map(|_| chose(100, &p).unwrap()).collect();
        assert!(got.iter().any(|u| u == "http://bad"), "ejected on two failures");

        failed(bad);
        let got: Vec<String> = (0..4).map(|_| chose(101, &p).unwrap()).collect();
        assert!(got.iter().all(|u| u == "http://good"),
                "a failing backend kept its turn: {got:?}");
    }

    #[test]
    fn a_success_clears_what_was_counted_against_a_backend() {
        forget_health();
        let p = pool(&[("http://a", 1), ("http://b", 1)]);
        let id = p[0].id;
        failed(id);
        failed(id);
        succeeded(id);
        failed(id);
        failed(id);
        let got: Vec<String> = (0..4).map(|_| chose(102, &p).unwrap()).collect();
        assert!(got.iter().any(|u| u == "http://a"),
                "four failures with a success between them ejected it");
    }

    #[test]
    fn a_pool_with_every_backend_out_still_hands_one_over() {
        // All of them failing is not a reason to stop asking: they may have
        // been restarted together, which is what a deploy looks like. The
        // caller is told, so the client can be given the right answer.
        forget_health();
        let p = pool(&[("http://a", 1), ("http://b", 1)]);
        for u in &p {
            for _ in 0..FAILURES_BEFORE_OUT { failed(u.id); }
        }
        let c = choose(103, &p).expect("something to try");
        assert!(c.all_out, "the caller was not told every backend is out");
    }

    #[test]
    fn a_pool_of_one_is_never_left_without_a_backend() {
        // Nothing to fail over to, so the request is worth more than the
        // refusal — and the answer still says every backend is out.
        forget_health();
        let p = pool(&[("http://only", 1)]);
        for _ in 0..FAILURES_BEFORE_OUT { failed(p[0].id); }
        let c = choose(104, &p).expect("the only backend");
        assert_eq!(c.upstream.url, "http://only");
        assert!(c.all_out);
    }

    #[test]
    fn a_retry_does_not_go_back_to_the_backend_that_just_failed() {
        forget_health();
        let p = pool(&[("http://a", 1), ("http://b", 1)]);
        let first = choose(105, &p).unwrap().upstream.id;
        let second = choose_except(105, &p, &[first]).expect("another backend");
        assert_ne!(second.upstream.id, first);
        assert!(choose_except(105, &p, &[p[0].id, p[1].id]).is_none(),
                "a pool with nothing untried offered something");
    }

    #[test]
    fn what_the_page_shows_follows_what_happened() {
        forget_health();
        let p = pool(&[("http://a", 1)]);
        let id = p[0].id;
        assert_eq!(state_of(id), (0, None));
        failed(id);
        assert_eq!(state_of(id).0, 1, "a failure was not counted");
        assert!(state_of(id).1.is_none(), "one failure took it out of rotation");
        failed(id);
        failed(id);
        let (count, out_for) = state_of(id);
        assert_eq!(count, 3);
        assert!(out_for.is_some_and(|s| s > 0 && s <= OUT_FOR.as_secs() + 1),
                "no time was reported for a backend that is out: {out_for:?}");
        succeeded(id);
        assert_eq!(state_of(id), (0, None), "a success did not put it back");
    }

    #[test]
    fn a_pool_that_shrinks_keeps_rotating() {
        // The counter is not reset when a backend is removed, because it does
        // not have to be: every choice is taken modulo the pool in hand, so
        // what is left goes on being handed out in turn.
        let three = pool(&[("http://a", 1), ("http://b", 1), ("http://c", 1)]);
        assert_eq!(chose(7, &three).unwrap(), "http://a");
        assert_eq!(chose(7, &three).unwrap(), "http://b");

        let two = pool(&[("http://a", 1), ("http://b", 1)]);
        let got: Vec<String> = (0..4).map(|_| chose(7, &two).unwrap()).collect();
        assert_eq!(got.iter().filter(|u| *u == "http://a").count(), 2);
        assert_eq!(got.iter().filter(|u| *u == "http://b").count(), 2);
    }
}

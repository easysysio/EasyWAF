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

/// One backend of a site, as the request path needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub url:    String,
    /// Share of the rotation. At least 1; a heavier backend takes more.
    pub weight: i64,
}

/// Read the pool carried on the site row.
///
/// `url weight` per line, built by `group_concat` in the site query. A URL
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
            let (url, weight) = match line.rsplit_once(' ') {
                Some((u, w)) => (u.trim(), w.trim().parse::<i64>().unwrap_or(1)),
                None         => (line, 1),
            };
            if url.is_empty() {
                return None;
            }
            Some(Upstream { url: url.to_string(), weight: weight.max(1) })
        })
        .collect()
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

/// The next upstream for this site, or None when the pool is empty.
///
/// With one upstream this returns it every time, which is the behaviour every
/// site had before pools existed and the behaviour almost every site keeps.
pub fn choose(site_id: i64, pool: &[Upstream]) -> Option<&Upstream> {
    match pool {
        []  => None,
        [u] => Some(u),
        _   => {
            let total: u64 = pool.iter().map(|u| u.weight.max(1) as u64).sum();
            if total == 0 {
                return pool.first();
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
fn pick(pool: &[Upstream], offset: u64) -> Option<&Upstream> {
    let mut seen = 0u64;
    for u in pool {
        seen += u.weight.max(1) as u64;
        if offset < seen {
            return Some(u);
        }
    }
    pool.last()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(spec: &[(&str, i64)]) -> Vec<Upstream> {
        spec.iter().map(|(u, w)| Upstream { url: u.to_string(), weight: *w }).collect()
    }

    #[test]
    fn a_pool_is_read_from_the_row() {
        let p = parse_pool("http://a:8080 1\nhttp://b:8080 3\n");
        assert_eq!(p, pool(&[("http://a:8080", 1), ("http://b:8080", 3)]));
    }

    #[test]
    fn a_line_without_a_weight_or_with_a_bad_one_weighs_one() {
        assert_eq!(parse_pool("http://a"), pool(&[("http://a", 1)]));
        assert_eq!(parse_pool("http://a x"), pool(&[("http://a", 1)]));
        // Zero and negative would take a backend out of the rotation while
        // still being listed in it, which is not something a weight should be
        // able to express.
        assert_eq!(parse_pool("http://a 0"), pool(&[("http://a", 1)]));
        assert_eq!(parse_pool("http://a -4"), pool(&[("http://a", 1)]));
    }

    #[test]
    fn blank_lines_are_not_backends() {
        assert!(parse_pool("").is_empty());
        assert!(parse_pool("\n  \n").is_empty());
        assert_eq!(parse_pool("http://a 1\n\n"), pool(&[("http://a", 1)]));
    }

    #[test]
    fn one_upstream_is_always_the_answer() {
        // The behaviour every site had before pools, and almost every site
        // keeps: no rotation state is touched at all.
        let p = pool(&[("http://only", 1)]);
        for _ in 0..5 {
            assert_eq!(choose(1, &p).map(|u| u.url.as_str()), Some("http://only"));
        }
    }

    #[test]
    fn an_empty_pool_chooses_nothing() {
        assert!(choose(2, &[]).is_none());
    }

    #[test]
    fn equal_weights_go_round_in_turn() {
        let p = pool(&[("http://a", 1), ("http://b", 1), ("http://c", 1)]);
        let got: Vec<&str> = (0..6).map(|_| choose(3, &p).unwrap().url.as_str()).collect();
        assert_eq!(got, ["http://a", "http://b", "http://c",
                         "http://a", "http://b", "http://c"]);
    }

    #[test]
    fn a_heavier_backend_takes_more_of_the_rotation() {
        // Three to one, which is the case the weight exists for: one backend
        // on larger hardware than the other.
        let p = pool(&[("http://big", 3), ("http://small", 1)]);
        let got: Vec<&str> = (0..8).map(|_| choose(4, &p).unwrap().url.as_str()).collect();
        assert_eq!(got.iter().filter(|u| **u == "http://big").count(), 6);
        assert_eq!(got.iter().filter(|u| **u == "http://small").count(), 2);
    }

    #[test]
    fn each_site_rotates_on_its_own() {
        let p = pool(&[("http://a", 1), ("http://b", 1)]);
        assert_eq!(choose(5, &p).unwrap().url, "http://a");
        assert_eq!(choose(6, &p).unwrap().url, "http://a", "another site took this one's turn");
        assert_eq!(choose(5, &p).unwrap().url, "http://b");
    }

    #[test]
    fn a_pool_that_shrinks_keeps_rotating() {
        // The counter is not reset when a backend is removed, because it does
        // not have to be: every choice is taken modulo the pool in hand, so
        // what is left goes on being handed out in turn.
        let three = pool(&[("http://a", 1), ("http://b", 1), ("http://c", 1)]);
        assert_eq!(choose(7, &three).unwrap().url, "http://a");
        assert_eq!(choose(7, &three).unwrap().url, "http://b");

        let two = pool(&[("http://a", 1), ("http://b", 1)]);
        let got: Vec<&str> = (0..4).map(|_| choose(7, &two).unwrap().url.as_str()).collect();
        assert_eq!(got.iter().filter(|u| **u == "http://a").count(), 2);
        assert_eq!(got.iter().filter(|u| **u == "http://b").count(), 2);
    }
}

// =========================================================
// rate_limit.rs — EasyWAF
// How many requests one client may make to a site within a
// window, and the count of what each client has made.
//
// A limit belongs to a site: normal traffic for a busy API
// and for a small internal tool differ by orders of
// magnitude, so one number shared through a policy would
// need overriding nearly everywhere. Each site sets its own,
// with a mode like a policy's, so a limit can be watched in
// DetectionOnly before it enforces.
//
// The count is an estimate over a sliding window, made from
// two fixed ones: the requests in this window, plus the last
// window's in proportion to how much of it the sliding window
// still covers. That is a few bytes per client however high
// the limit, where remembering each request's time would cost
// a limit's worth of them — and a busy site's limit is in the
// thousands. Every request a client makes counts, the refused
// ones included, so a client that keeps sending stays over.
//
// The counts are in memory, per node, bounded, and lost on a
// restart, which costs a client nothing but a fresh count.
// =========================================================

use sqlx::SqlitePool;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub use crate::smart_protect::{span, unit, unit_label};

// ─── The limit ───────────────────────────────────────────

/// The modes a site's limit can be in, as the column stores them.
pub const MODES: [&str; 3] = ["Off", "DetectionOnly", "On"];

/// The windows the form offers, in seconds. The traffic history a preview
/// replays is recorded to the second, so a shorter window could not be
/// previewed faithfully.
pub const WINDOWS: [u64; 4] = [10, 60, 300, 3600];

/// What the form accepts as a number of requests.
pub const REQUESTS_RANGE: std::ops::RangeInclusive<u64> = 1..=1_000_000;

/// What a new site's form offers: ten a second on average, which a person in
/// a browser does not keep up and a script hammering the site does.
pub const DEFAULT_REQUESTS:    u64 = 600;
pub const DEFAULT_WINDOW_SECS: u64 = 60;

/// What happens to a request over the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Refused with 429 Too Many Requests.
    Block,
    /// A page load is shown the CAPTCHA, and a visitor who answers it is let
    /// through while still being counted. Anything else is refused as `Block`.
    Challenge,
}

impl Action {
    /// The stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Block     => "block",
            Action::Challenge => "challenge",
        }
    }

    /// The action a stored or posted value names.
    pub fn parse(s: &str) -> Option<Action> {
        match s.trim() {
            "block"     => Some(Action::Block),
            "challenge" => Some(Action::Challenge),
            _ => None,
        }
    }
}

/// A site's limit, as the proxy applies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// Requests allowed within the window.
    pub requests:       u64,
    pub window:         Duration,
    pub action:         Action,
    /// The site records what the limit would do rather than doing it.
    pub detection_only: bool,
}

impl Limit {
    /// The limit a site's columns describe. `None` when it is Off, and for
    /// values a database edited by hand could hold and the form never offers.
    pub fn of(mode: &str, requests: i64, window_secs: i64, action: &str) -> Option<Limit> {
        let detection_only = match mode {
            "On" => false,
            "DetectionOnly" => true,
            _ => return None,
        };
        let requests = u64::try_from(requests).ok().filter(|n| REQUESTS_RANGE.contains(n))?;
        let window = u64::try_from(window_secs).ok().filter(|s| *s >= 1)?;
        Some(Limit {
            requests,
            window: Duration::from_secs(window),
            action: Action::parse(action)?,
            detection_only,
        })
    }

    /// The limit as a person says it: "600 requests a minute".
    pub fn describe(&self) -> String {
        describe(self.requests, self.window.as_secs())
    }
}

/// A number of requests and a window as a person says them: "600 requests a
/// minute", "1 request every 10 seconds".
pub fn describe(requests: u64, window_secs: u64) -> String {
    let noun = if requests == 1 { "request" } else { "requests" };
    let per = match window_secs {
        60 | 3600 => window_text(window_secs),
        s => format!("every {}", window_text(s)),
    };
    format!("{requests} {noun} {per}")
}

/// A window as the form names it: "10 seconds", "a minute", "5 minutes",
/// "an hour".
pub fn window_text(window_secs: u64) -> String {
    match window_secs {
        60   => "a minute".to_string(),
        3600 => "an hour".to_string(),
        s    => span(Duration::from_secs(s)),
    }
}

// ─── One client's count ──────────────────────────────────

/// One client's requests, in the window now running and the one before it.
///
/// Windows are numbered from a fixed origin, so two clients' windows begin
/// together; a client's own count is what slides.
#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    window_ms: u64,
    /// Which window `current` counts, as `time / window_ms`.
    slot:      u64,
    current:   u64,
    previous:  u64,
    /// The last request's time, so a full table knows whom to forget first.
    last_ms:   u64,
}

impl Tally {
    /// Bring the tally to the window `now_ms` falls in: a window that has
    /// ended becomes the previous one, and anything older counts for nothing.
    /// A changed window length starts the count again, since its slots mean
    /// something else.
    fn advance(&mut self, now_ms: u64, window_ms: u64) {
        let slot = now_ms / window_ms;
        if self.window_ms != window_ms {
            *self = Tally { window_ms, slot, ..Tally::default() };
        } else if slot == self.slot + 1 {
            self.previous = self.current;
            self.current = 0;
            self.slot = slot;
        } else if slot > self.slot {
            self.previous = 0;
            self.current = 0;
            self.slot = slot;
        }
    }

    /// The requests within the sliding window that ends at `now_ms`, times the
    /// window's length — kept scaled so nothing is lost to rounding.
    fn scaled(&self, now_ms: u64) -> u128 {
        let into = now_ms % self.window_ms;
        let w = self.window_ms as u128;
        self.previous as u128 * (w - into as u128) + self.current as u128 * w
    }

    /// Count a request at `now_ms`.
    fn record(&mut self, now_ms: u64, window_ms: u64) -> Count {
        self.advance(now_ms, window_ms);
        self.current = self.current.saturating_add(1);
        self.last_ms = now_ms;
        let scaled = self.scaled(now_ms);
        Count {
            requests: scaled.div_ceil(window_ms as u128) as u64,
            scaled,
            tally: *self,
            at_ms: now_ms,
        }
    }
}

/// What the count was when a request was counted, this request included.
#[derive(Debug, Clone, Copy)]
pub struct Count {
    /// The requests within the window, rounded up.
    pub requests: u64,
    scaled:       u128,
    tally:        Tally,
    at_ms:        u64,
}

impl Count {
    /// Whether this request takes the client over `limit`.
    pub fn over(&self, limit: u64) -> bool {
        self.scaled > limit as u128 * self.tally.window_ms as u128
    }

    /// How long until one more request would be within `limit`, if the client
    /// sends nothing meanwhile. What `Retry-After` says; at least a second,
    /// since the header counts in whole ones.
    pub fn retry_after(&self, limit: u64) -> Duration {
        let ms = wait_ms(&self.tally, self.at_ms, limit);
        Duration::from_secs(ms.div_ceil(1000).max(1))
    }
}

/// The shortest wait from `now_ms` after which one more request would be
/// within `limit`, for a tally that receives nothing meanwhile.
///
/// Within the window now running the estimate falls as the previous window
/// slides out; once it ends, as this one does. Two windows on, it is nothing.
fn wait_ms(t: &Tally, now_ms: u64, limit: u64) -> u64 {
    let w = t.window_ms as u128;
    let into = (now_ms % t.window_ms) as u128;
    let room = limit.saturating_sub(1) as u128;

    // The first offset into a window at which `count * (w - r) / w` plus
    // `rest` leaves room for one more, if there is one before it ends.
    let first_fit = |count: u128, rest: u128| -> Option<u128> {
        if rest > room {
            return None;
        }
        if count == 0 {
            return Some(0);
        }
        // count * (w - r) <= (room - rest) * w, for the least such r.
        let allowed = (room - rest) * w;
        let r = w.saturating_sub(allowed / count);
        // The division rounds down; step on until it truly fits.
        let mut r = r;
        while r < w && count * (w - r) > allowed {
            r += 1;
        }
        (r < w).then_some(r)
    };

    if let Some(r) = first_fit(t.previous as u128, t.current as u128) {
        return r.saturating_sub(into) as u64;
    }
    let to_next = (w - into) as u64;
    match first_fit(t.current as u128, 0) {
        Some(r) => to_next + r as u64,
        None    => to_next + t.window_ms,
    }
}

// ─── Every client's count ────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    site: i64,
    unit: IpAddr,
}

/// How many clients one shard of the table counts at once. Sixteen shards, so
/// the table holds about 130,000 and requests from different clients seldom
/// wait on one lock.
const SHARDS: usize = 16;
const MAX_PER_SHARD: usize = 8192;

struct Table {
    shards: Vec<Mutex<HashMap<Key, Tally>>>,
    hasher: std::collections::hash_map::RandomState,
    origin: Instant,
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| Table {
        shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        hasher: std::collections::hash_map::RandomState::new(),
        origin: Instant::now(),
    })
}

/// Count a request from this client to this site, and say where it stands.
pub fn count(site: i64, ip: IpAddr, limit: &Limit) -> Count {
    let now_ms = table().origin.elapsed().as_millis() as u64;
    count_at(site, ip, limit.window, now_ms)
}

fn count_at(site: i64, ip: IpAddr, window: Duration, now_ms: u64) -> Count {
    let t = table();
    let key = Key { site, unit: unit(ip) };
    let window_ms = (window.as_millis() as u64).max(1);
    let shard = &t.shards[(t.hasher.hash_one(key) as usize) % SHARDS];
    let mut tallies = shard.lock().unwrap_or_else(|p| p.into_inner());
    if !tallies.contains_key(&key) && tallies.len() >= MAX_PER_SHARD {
        make_room(&mut tallies, now_ms);
    }
    tallies.entry(key).or_default().record(now_ms, window_ms)
}

/// Make room in a full shard: clients whose requests no longer count go
/// first, and if that frees nothing — a spray from thousands of addresses at
/// once — the half seen longest ago goes. Forgetting a client costs it
/// nothing but a fresh count.
fn make_room(tallies: &mut HashMap<Key, Tally>, now_ms: u64) {
    tallies.retain(|_, t| now_ms.saturating_sub(t.last_ms) < 2 * t.window_ms);
    if tallies.len() < MAX_PER_SHARD {
        return;
    }
    let mut seen: Vec<u64> = tallies.values().map(|t| t.last_ms).collect();
    seen.sort_unstable();
    let cutoff = seen[seen.len() / 2];
    tallies.retain(|_, t| t.last_ms > cutoff);
}

/// Whether a request is a page being loaded, which a person sees, rather than
/// something a page fetches. Only a page load can show a CAPTCHA to anybody;
/// shown to an image or a script request it is just a request that failed.
pub fn is_page_load(method: &str, sec_fetch_mode: Option<&str>, accept: Option<&str>) -> bool {
    match sec_fetch_mode {
        Some(mode) => mode.eq_ignore_ascii_case("navigate"),
        // A browser too old to say: a GET asking for HTML is a page.
        None => method == "GET" && accept.is_some_and(|a| a.contains("text/html")),
    }
}

// ─── The preview ─────────────────────────────────────────
//
// What a limit would have done to one site's recorded traffic. The same
// counting the live path does, replayed over history, so a limit can be
// chosen from what the site's clients really send rather than guessed.

/// One address, as the preview lists it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PreviewAddress {
    /// The address, or the IPv6 /64.
    pub unit:        String,
    /// The most requests it made within any window.
    pub peak:        u64,
    /// Requests that would have been over the limit.
    pub over:        usize,
    /// How many of those were in fact served successfully.
    pub served_over: usize,
}

/// What a limit would have done over a stretch of one site's traffic.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Preview {
    /// Requests read.
    pub requests:    usize,
    /// Distinct addresses that made them.
    pub clients:     usize,
    /// Addresses with at least one request over the limit.
    pub addresses:   usize,
    /// Requests over the limit.
    pub over:        usize,
    /// Of those, the ones that were served successfully — the requests a
    /// limit set too low takes from people.
    pub served_over: usize,
    /// The busiest addresses, most requests within a window first, whether or
    /// not they went over: what the limit has to sit above.
    pub top:         Vec<PreviewAddress>,
}

/// How many addresses a preview lists.
const PREVIEW_TOP: usize = 10;

#[derive(Default)]
struct Replay {
    tally:       Tally,
    peak:        u64,
    over:        usize,
    served_over: usize,
}

/// Recorded requests replayed through a limit, oldest first. Holds a small
/// state per client and nothing per request.
struct Replayer {
    requests:  u64,
    window_ms: u64,
    clients:   HashMap<IpAddr, Replay>,
    read:      usize,
}

impl Replayer {
    fn new(requests: u64, window: Duration) -> Self {
        Replayer {
            requests,
            window_ms: (window.as_millis() as u64).max(1),
            clients: HashMap::new(),
            read: 0,
        }
    }

    /// One recorded request: the client, the second it was recorded at, and
    /// whether it was served successfully.
    fn feed(&mut self, ip: IpAddr, at_secs: i64, served: bool) {
        self.read += 1;
        let at_ms = u64::try_from(at_secs).unwrap_or(0) * 1000;
        let c = self.clients.entry(unit(ip)).or_default();
        let n = c.tally.record(at_ms, self.window_ms);
        c.peak = c.peak.max(n.requests);
        if n.over(self.requests) {
            c.over += 1;
            if served {
                c.served_over += 1;
            }
        }
    }

    fn finish(self) -> Preview {
        let clients = self.clients.len();
        let mut all: Vec<PreviewAddress> = self
            .clients
            .into_iter()
            .map(|(u, c)| PreviewAddress {
                unit: unit_label(u),
                peak: c.peak,
                over: c.over,
                served_over: c.served_over,
            })
            .collect();
        all.sort_by(|a, b| (b.peak, b.over, &a.unit).cmp(&(a.peak, a.over, &b.unit)));

        let limited: Vec<&PreviewAddress> = all.iter().filter(|a| a.over > 0).collect();
        Preview {
            requests:    self.read,
            clients,
            addresses:   limited.len(),
            over:        limited.iter().map(|a| a.over).sum(),
            served_over: limited.iter().map(|a| a.served_over).sum(),
            top:         all.into_iter().take(PREVIEW_TOP).collect(),
        }
    }
}

/// Replay recorded requests, oldest first, through a limit.
#[cfg(test)]
pub fn simulate(rows: impl IntoIterator<Item = (IpAddr, i64, bool)>, requests: u64, window: Duration) -> Preview {
    let mut replay = Replayer::new(requests, window);
    for (ip, at, served) in rows {
        replay.feed(ip, at, served);
    }
    replay.finish()
}

/// Replay one site's recorded traffic over the last `hours` through a limit.
///
/// Read as a stream, so a history of millions of rows costs the table of
/// clients rather than the rows themselves. What the live limit never sees is
/// left out: a trusted proxy, an address on the policy's allow list, and a
/// request an IP list or Smart Protect refused before the limit was reached.
pub async fn preview(
    db: &SqlitePool,
    site_id: i64,
    hours: i64,
    requests: u64,
    window: Duration,
) -> Result<Preview, sqlx::Error> {
    use futures::TryStreamExt;
    use sqlx::Row;

    // The policy whose allow list applies: none while the policy is Off,
    // since its lists are not read then.
    let policy: Option<i64> = sqlx::query_scalar(
        "SELECT p.id FROM sites s JOIN policies p ON p.id = s.waf_policy_id
          WHERE s.id = ? AND p.rule_engine <> 'Off'",
    )
    .bind(site_id)
    .fetch_optional(db)
    .await?;

    let since = format!("-{} hours", hours.max(1));
    let mut rows = sqlx::query(
        "SELECT client_ip,
                CAST(strftime('%s', timestamp) AS INTEGER) AS at,
                (blocked = 0 AND status_code < 400) AS served
           FROM traffic_events
          WHERE site_id = ? AND timestamp >= datetime('now', ?)
            AND NOT (blocked = 1 AND (COALESCE(block_reason, '') LIKE 'Client address is on the %'
                                      OR COALESCE(block_reason, '') LIKE 'Smart Protect:%'))
          ORDER BY timestamp, id",
    )
    .bind(site_id)
    .bind(since)
    .fetch(db);

    let mut exempt: HashMap<IpAddr, bool> = HashMap::new();
    let mut replay = Replayer::new(requests, window);
    while let Some(r) = rows.try_next().await? {
        let Some(ip) = r.get::<Option<String>, _>("client_ip").and_then(|s| s.parse::<IpAddr>().ok()) else {
            continue;
        };
        let skip = match exempt.get(&ip) {
            Some(skip) => *skip,
            None => {
                let allowed = match policy {
                    Some(p) => crate::iplist::check(db, p, ip).await == Some(crate::iplist::Listed::Allowed),
                    None => false,
                };
                let skip = allowed || crate::forwarded::is_trusted_proxy(ip);
                exempt.insert(ip, skip);
                skip
            }
        };
        if skip {
            continue;
        }
        let served = r.get::<Option<i64>, _>("served").unwrap_or(0) != 0;
        replay.feed(ip, r.get::<Option<i64>, _>("at").unwrap_or(0), served);
    }
    Ok(replay.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const MINUTE: Duration = Duration::from_secs(60);

    fn tally_at(t: &mut Tally, now_ms: u64) -> Count {
        t.record(now_ms, 60_000)
    }

    #[test]
    fn the_limit_is_read_from_the_columns_and_off_is_none() {
        let l = Limit::of("On", 600, 60, "block").expect("a limit");
        assert_eq!((l.requests, l.window, l.action, l.detection_only), (600, MINUTE, Action::Block, false));
        assert!(Limit::of("DetectionOnly", 10, 10, "challenge").unwrap().detection_only);
        assert_eq!(Limit::of("Off", 600, 60, "block"), None);
        assert_eq!(Limit::of("On", 0, 60, "block"), None, "a limit of nothing");
        assert_eq!(Limit::of("On", 600, 0, "block"), None, "a window of nothing");
        assert_eq!(Limit::of("On", 600, 60, "tarpit"), None);
    }

    #[test]
    fn a_limit_is_said_the_way_a_person_says_it() {
        assert_eq!(describe(600, 60), "600 requests a minute");
        assert_eq!(describe(1, 10), "1 request every 10 seconds");
        assert_eq!(describe(5000, 3600), "5000 requests an hour");
        assert_eq!(describe(100, 300), "100 requests every 5 minutes");
        assert_eq!(window_text(60), "a minute");
        assert_eq!(window_text(10), "10 seconds");
    }

    #[test]
    fn requests_within_the_limit_are_not_over_and_the_next_one_is() {
        let mut t = Tally::default();
        for i in 0..10 {
            assert!(!tally_at(&mut t, 1_000 + i * 100).over(10), "request {} was over", i + 1);
        }
        assert!(tally_at(&mut t, 2_100).over(10));
    }

    #[test]
    fn the_previous_window_counts_in_proportion_to_what_is_left_of_it() {
        let mut t = Tally::default();
        // Ten requests at the very end of one window…
        for _ in 0..10 {
            tally_at(&mut t, 59_999);
        }
        // …a quarter of the way into the next, three quarters of them count.
        assert_eq!(tally_at(&mut t, 75_000).requests, 9, "7.5 of the previous plus this one, rounded up");
        // In the window after, the one before held a single request.
        assert_eq!(tally_at(&mut t, 125_000).requests, 2);
        // Two windows on, nothing earlier counts.
        assert_eq!(tally_at(&mut t, 300_000).requests, 1);
    }

    #[test]
    fn a_changed_window_starts_the_count_again() {
        let mut t = Tally::default();
        for _ in 0..5 {
            t.record(1_000, 60_000);
        }
        assert_eq!(t.record(1_500, 10_000).requests, 1);
    }

    #[test]
    fn retry_after_is_exactly_when_one_more_request_fits() {
        // Every shape of count: what the wait says must fit, and a millisecond
        // earlier must not.
        let w = 10_000u64;
        for limit in [1u64, 2, 3, 7, 20] {
            for previous in [0u64, 1, 5, 19, 40] {
                for current in [1u64, 2, 6, 21, 45] {
                    for into in [0u64, 1, 2_500, 9_999] {
                        let now = 50 * w + into;
                        let t = Tally { window_ms: w, slot: 50, current, previous, last_ms: now };
                        let fits = |at: u64| {
                            let mut probe = t;
                            !probe.record(at, w).over(limit)
                        };
                        let wait = wait_ms(&t, now, limit);
                        assert!(fits(now + wait),
                                "limit {limit}, {previous}+{current} at {into}: no room after {wait} ms");
                        if wait > 0 {
                            assert!(!fits(now + wait - 1),
                                    "limit {limit}, {previous}+{current} at {into}: room before {wait} ms");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn clients_are_counted_apart_and_ipv6_by_its_64() {
        // Site ids of their own: the table is one for the process, and tests
        // run side by side.
        let (site, t) = (7001, 5_000);
        for _ in 0..3 {
            count_at(site, ip("2001:db8:1:2::1"), MINUTE, t);
        }
        assert_eq!(count_at(site, ip("2001:db8:1:2::ffff"), MINUTE, t).requests, 4, "another address in the /64");
        assert_eq!(count_at(site, ip("2001:db8:1:3::1"), MINUTE, t).requests, 1, "the next /64");
        assert_eq!(count_at(site, ip("203.0.113.1"), MINUTE, t).requests, 1);
        assert_eq!(count_at(site + 1, ip("2001:db8:1:2::1"), MINUTE, t).requests, 1, "another site");
    }

    #[test]
    fn a_full_shard_forgets_rather_than_grows() {
        let mut tallies: HashMap<Key, Tally> = HashMap::new();
        for i in 0..(MAX_PER_SHARD as u32 + 1000) {
            let key = Key { site: 1, unit: IpAddr::from(i.to_be_bytes()) };
            if !tallies.contains_key(&key) && tallies.len() >= MAX_PER_SHARD {
                make_room(&mut tallies, i as u64);
            }
            tallies.entry(key).or_default().record(i as u64, 60_000);
            assert!(tallies.len() <= MAX_PER_SHARD);
        }
    }

    #[test]
    fn a_page_load_is_told_apart_from_what_a_page_fetches() {
        assert!(is_page_load("GET", Some("navigate"), None));
        assert!(!is_page_load("GET", Some("no-cors"), Some("text/html")));
        assert!(!is_page_load("GET", Some("cors"), None));
        assert!(is_page_load("GET", None, Some("text/html,application/xhtml+xml")));
        assert!(!is_page_load("GET", None, Some("image/avif,image/webp")));
        assert!(!is_page_load("POST", None, Some("text/html")));
        assert!(!is_page_load("GET", None, None), "curl");
    }

    // ── The preview ──

    #[test]
    fn the_preview_counts_as_the_live_path_does() {
        let mut rows = Vec::new();
        // A scraper: 30 requests in ten seconds, all served.
        for i in 0..30 {
            rows.push((ip("203.0.113.1"), 1_000 + i / 3, true));
        }
        // A person: a few requests spread over the minute.
        for i in 0..5 {
            rows.push((ip("203.0.113.2"), 1_000 + i * 10, true));
        }
        rows.sort_by_key(|r| r.1);
        let p = simulate(rows, 10, MINUTE);
        assert_eq!((p.requests, p.clients, p.addresses), (35, 2, 1));
        assert_eq!((p.over, p.served_over), (20, 20));
        assert_eq!((p.top[0].unit.as_str(), p.top[0].peak), ("203.0.113.1", 30));
        assert_eq!(p.top[1], PreviewAddress { unit: "203.0.113.2".into(), peak: 5, over: 0, served_over: 0 });
    }

    #[test]
    fn nothing_recorded_previews_as_nothing() {
        assert_eq!(simulate(Vec::new(), 10, MINUTE), Preview::default());
    }
}

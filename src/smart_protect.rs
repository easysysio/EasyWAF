// =========================================================
// smart_protect.rs — EasyWAF
// An address a policy's rules keep refusing is refused
// outright for a while.
//
// Every request is otherwise judged alone: a scanner firing
// two hundred probes gets two hundred independent refusals,
// none of them noticing it is the same client, and carries
// on until it finds something that is not refused. This
// counts refusals per client over a sliding window, and
// blocks a client that reaches the limit for a fixed time.
//
// A policy decides whether this applies to it; the numbers —
// how many refusals, in what window, for how long — are set
// once, under Settings.
//
// What counts is a refusal by the rules, or one a
// DetectionOnly policy would have made. A rule that matched
// on a request that was served does not count, nor does a
// challenge, a country refusal, or a request refused because
// the address was already blocked — so a block lasts as long
// as it says and no longer.
//
// The state is in memory, per node, and expires by itself:
// it is an observation, not a decision anyone made, so it is
// never written to an operator's IP lists.
// =========================================================

use sqlx::SqlitePool;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// ─── The numbers ─────────────────────────────────────────

pub const KEY_REFUSALS:    &str = "smart_protect_refusals";
pub const KEY_WINDOW_SECS: &str = "smart_protect_window_secs";
pub const KEY_BLOCK_SECS:  &str = "smart_protect_block_secs";

/// Three refusals within a minute, and the address is refused for ten.
pub const DEFAULT_REFUSALS:    u64 = 3;
pub const DEFAULT_WINDOW_SECS: u64 = 60;
pub const DEFAULT_BLOCK_SECS:  u64 = 600;

/// What the Settings form accepts. Two refusals at least: one would block a
/// person for a single request a rule got wrong.
pub const REFUSALS_RANGE:    std::ops::RangeInclusive<u64> = 2..=100;
pub const WINDOW_SECS_RANGE: std::ops::RangeInclusive<u64> = 10..=3600;
pub const BLOCK_SECS_RANGE:  std::ops::RangeInclusive<u64> = 60..=86_400;

/// How many refusals, within what window, block an address, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Numbers {
    pub refusals: usize,
    pub window:   Duration,
    pub block:    Duration,
}

// Held in atomics rather than read from settings per request: this is
// consulted on the request path.
static REFUSALS:    AtomicU64 = AtomicU64::new(DEFAULT_REFUSALS);
static WINDOW_SECS: AtomicU64 = AtomicU64::new(DEFAULT_WINDOW_SECS);
static BLOCK_SECS:  AtomicU64 = AtomicU64::new(DEFAULT_BLOCK_SECS);

/// The numbers in force.
pub fn numbers() -> Numbers {
    Numbers {
        refusals: REFUSALS.load(Ordering::Relaxed) as usize,
        window:   Duration::from_secs(WINDOW_SECS.load(Ordering::Relaxed)),
        block:    Duration::from_secs(BLOCK_SECS.load(Ordering::Relaxed)),
    }
}

/// Put numbers in force, each held to the range the form accepts, so a value
/// edited into the database by hand cannot switch the feature into something
/// nobody chose.
pub fn set_numbers(refusals: u64, window_secs: u64, block_secs: u64) {
    let hold = |v: u64, r: &std::ops::RangeInclusive<u64>| v.clamp(*r.start(), *r.end());
    REFUSALS.store(hold(refusals, &REFUSALS_RANGE), Ordering::Relaxed);
    WINDOW_SECS.store(hold(window_secs, &WINDOW_SECS_RANGE), Ordering::Relaxed);
    BLOCK_SECS.store(hold(block_secs, &BLOCK_SECS_RANGE), Ordering::Relaxed);
}

/// Read the numbers from settings into force. Called at startup and after
/// they are saved.
pub async fn load(db: &SqlitePool) {
    let read = |key: &'static str, default: u64| async move {
        crate::settings::get(db, key)
            .await
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default)
    };
    set_numbers(
        read(KEY_REFUSALS, DEFAULT_REFUSALS).await,
        read(KEY_WINDOW_SECS, DEFAULT_WINDOW_SECS).await,
        read(KEY_BLOCK_SECS, DEFAULT_BLOCK_SECS).await,
    );
}

/// The rule in force, as a sentence: "An address refused 3 times within 60
/// seconds is refused for 10 minutes." Shown wherever Smart Protect is switched
/// on, so the switch says what it does.
pub fn rule_text() -> String {
    let n = numbers();
    format!(
        "An address refused {} times within {} is refused for {}.",
        n.refusals, span(n.window), span(n.block)
    )
}

// ─── Who a block applies to ──────────────────────────────

/// The unit a client is counted and blocked as: its address for IPv4, its /64
/// for IPv6.
///
/// A single IPv6 address costs an attacker nothing — most allocations hand out
/// a /64 or larger — so blocking one address blocks one of billions they hold.
/// A v4 address written as v6 is counted as the v4 address it is.
pub fn unit(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut s = v6.segments();
                s[4..].fill(0);
                IpAddr::V6(std::net::Ipv6Addr::from(s))
            }
        },
    }
}

/// A unit as a person reads it: `203.0.113.9`, or `2001:db8:1:2::/64`.
pub fn unit_label(unit: IpAddr) -> String {
    match unit {
        IpAddr::V4(_) => unit.to_string(),
        IpAddr::V6(_) => format!("{unit}/64"),
    }
}

/// A length of time as a person says it: "45 seconds", "10 minutes", "2 hours".
/// Rounded up, so a block with a second left is not said to have none.
pub fn span(d: Duration) -> String {
    let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
    let (n, word) = if secs < 120 {
        (secs.max(1), "second")
    } else if secs < 7200 {
        (secs.div_ceil(60), "minute")
    } else {
        (secs.div_ceil(3600), "hour")
    };
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

// ─── The sliding counter ─────────────────────────────────

/// Events per key over a sliding window, in bounded memory.
///
/// Written for Smart Protect and not specific to it: rate limiting counts
/// events per client in a window the same way, and is meant to use this.
pub struct SlidingCounter<K> {
    max_keys: usize,
    events:   HashMap<K, VecDeque<Instant>>,
}

impl<K: Hash + Eq + Clone> SlidingCounter<K> {
    /// A counter that tracks at most `max_keys` keys at once.
    pub fn new(max_keys: usize) -> Self {
        Self { max_keys: max_keys.max(1), events: HashMap::new() }
    }

    /// Record an event for `key` at `now`, and return how many of its events
    /// fall within `window`, this one included.
    ///
    /// At most `keep` events are remembered per key — the caller's limit, since
    /// a count beyond it changes nothing — so one busy key costs a fixed amount.
    pub fn record(&mut self, key: K, now: Instant, window: Duration, keep: usize) -> usize {
        if !self.events.contains_key(&key) && self.events.len() >= self.max_keys {
            self.make_room(now, window);
        }
        let times = self.events.entry(key).or_default();
        while times.front().is_some_and(|t| now.duration_since(*t) >= window) {
            times.pop_front();
        }
        times.push_back(now);
        while times.len() > keep.max(1) {
            times.pop_front();
        }
        times.len()
    }

    /// Forget a key's events.
    pub fn forget(&mut self, key: &K) {
        self.events.remove(key);
    }

    /// How many keys are being tracked.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Make room when the table is full: keys with nothing left in the window
    /// go first, and if that frees nothing — a spray from thousands of
    /// addresses at once — the half that was seen longest ago goes.
    ///
    /// A whole pass over the table, but only when it is full, and it frees at
    /// least half each time it has to evict by age, so the cost per event stays
    /// small however the events arrive.
    fn make_room(&mut self, now: Instant, window: Duration) {
        self.events
            .retain(|_, times| times.back().is_some_and(|t| now.duration_since(*t) < window));
        if self.events.len() < self.max_keys {
            return;
        }
        let mut latest: Vec<Instant> =
            self.events.values().filter_map(|t| t.back().copied()).collect();
        latest.sort_unstable();
        let cutoff = latest[latest.len() / 2];
        self.events.retain(|_, times| times.back().is_some_and(|t| *t > cutoff));
    }
}

// ─── Blocks ──────────────────────────────────────────────

/// How many clients are counted at once, and how many blocks are held. A spray
/// from a botnet is thousands of distinct addresses in a minute; this is the
/// ceiling on what it can make EasyWAF remember.
const MAX_COUNTED: usize = 100_000;
const MAX_BLOCKS:  usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    policy: i64,
    unit:   IpAddr,
}

/// One address blocked on one policy.
#[derive(Debug, Clone)]
pub struct Block {
    pub policy:   i64,
    /// What is blocked: an IPv4 address, or an IPv6 /64.
    pub unit:     IpAddr,
    /// The address whose refusal completed the count.
    pub address:  IpAddr,
    /// The refusal that completed the count, as the traffic row gave it.
    pub reason:   String,
    /// The numbers it was blocked under, which may since have changed.
    pub refusals: usize,
    pub window:   Duration,
    /// When it was blocked, for the page.
    pub since:    chrono::DateTime<chrono::Utc>,
    /// When the block ends.
    pub until:    Instant,
}

impl Block {
    /// How long is left.
    pub fn remaining(&self) -> Duration {
        self.until.saturating_duration_since(Instant::now())
    }

    /// Why a request from this client is refused, for the client and for the
    /// traffic row alike.
    pub fn refusal(&self) -> String {
        format!(
            "Smart Protect: this address is blocked for another {} after {} refused requests within {}",
            span(self.remaining()),
            self.refusals,
            span(self.window),
        )
    }
}

struct State {
    counter: SlidingCounter<Key>,
    blocks:  HashMap<Key, Block>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(State { counter: SlidingCounter::new(MAX_COUNTED), blocks: HashMap::new() })
    })
}

/// How many blocks are held, so the request path can skip the lock entirely
/// while nothing is blocked — which is nearly always.
static BLOCK_COUNT: AtomicUsize = AtomicUsize::new(0);

fn lock() -> std::sync::MutexGuard<'static, State> {
    state().lock().unwrap_or_else(|p| p.into_inner())
}

/// The block on this client for this policy, if one is in force.
pub fn blocked(policy: i64, ip: IpAddr) -> Option<Block> {
    if BLOCK_COUNT.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let key = Key { policy, unit: unit(ip) };
    let mut s = lock();
    match s.blocks.get(&key) {
        Some(b) if b.until > Instant::now() => Some(b.clone()),
        Some(_) => {
            s.blocks.remove(&key);
            BLOCK_COUNT.store(s.blocks.len(), Ordering::Relaxed);
            None
        }
        None => None,
    }
}

/// Count a refusal against this client on this policy. Returns the block when
/// this refusal is the one that completes the count.
///
/// A client that is already blocked is not counted: its block lasts as long as
/// it says, whatever it sends meanwhile.
pub fn offence(policy: i64, ip: IpAddr, reason: &str) -> Option<Block> {
    offence_at(policy, ip, reason, Instant::now(), numbers())
}

fn offence_at(policy: i64, ip: IpAddr, reason: &str, now: Instant, n: Numbers) -> Option<Block> {
    let key = Key { policy, unit: unit(ip) };
    let mut s = lock();

    if s.blocks.get(&key).is_some_and(|b| b.until > now) {
        return None;
    }
    if s.counter.record(key, now, n.window, n.refusals) < n.refusals {
        return None;
    }

    // The count is complete. It starts again from nothing after the block.
    s.counter.forget(&key);
    if s.blocks.len() >= MAX_BLOCKS {
        s.blocks.retain(|_, b| b.until > now);
        // Still full of live blocks: the one that ends soonest makes room.
        if s.blocks.len() >= MAX_BLOCKS
            && let Some(soonest) = s.blocks.iter().min_by_key(|(_, b)| b.until).map(|(k, _)| *k)
        {
            s.blocks.remove(&soonest);
        }
    }
    let block = Block {
        policy,
        unit: key.unit,
        address: ip,
        reason: reason.to_string(),
        refusals: n.refusals,
        window: n.window,
        since: chrono::Utc::now(),
        until: now + n.block,
    };
    s.blocks.insert(key, block.clone());
    BLOCK_COUNT.store(s.blocks.len(), Ordering::Relaxed);
    Some(block)
}

/// Every block in force, soonest to end first.
pub fn list() -> Vec<Block> {
    let now = Instant::now();
    let mut s = lock();
    s.blocks.retain(|_, b| b.until > now);
    BLOCK_COUNT.store(s.blocks.len(), Ordering::Relaxed);
    let mut all: Vec<Block> = s.blocks.values().cloned().collect();
    all.sort_by_key(|b| b.until);
    all
}

/// Lift a block. Returns whether there was one.
pub fn unblock(policy: i64, unit: IpAddr) -> bool {
    let mut s = lock();
    let key = Key { policy, unit };
    let had = s.blocks.remove(&key).is_some();
    s.counter.forget(&key);
    BLOCK_COUNT.store(s.blocks.len(), Ordering::Relaxed);
    had
}

/// Forget everything held for a policy: its counts and its blocks. For when
/// Smart Protect is switched off on it, so blocks do not outlive the decision.
pub fn forget_policy(policy: i64) {
    let mut s = lock();
    s.blocks.retain(|k, _| k.policy != policy);
    s.counter.events.retain(|k, _| k.policy != policy);
    BLOCK_COUNT.store(s.blocks.len(), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const N: Numbers = Numbers {
        refusals: 3,
        window:   Duration::from_secs(60),
        block:    Duration::from_secs(600),
    };

    // Each test uses a policy id of its own: the state is one table for the
    // process, and tests run side by side.

    #[test]
    fn the_third_refusal_within_the_window_blocks() {
        let (p, a, t) = (9001, ip("203.0.113.1"), Instant::now());
        assert!(offence_at(p, a, "r1", t, N).is_none());
        assert!(offence_at(p, a, "r2", t + Duration::from_secs(20), N).is_none());
        let b = offence_at(p, a, "r3", t + Duration::from_secs(40), N).expect("blocked on the third");
        assert_eq!(b.reason, "r3");
        assert_eq!(b.until, t + Duration::from_secs(40) + N.block);
        assert!(blocked(p, a).is_some());
        assert!(blocked(p, ip("203.0.113.2")).is_none(), "a neighbour was blocked with it");
        assert!(blocked(9999, a).is_none(), "a block reached another policy");
        unblock(p, unit(a));
    }

    #[test]
    fn refusals_spread_wider_than_the_window_do_not_block() {
        let (p, a, t) = (9002, ip("203.0.113.1"), Instant::now());
        for i in 0..10 {
            // One every 40 seconds: never three within any 60.
            assert!(offence_at(p, a, "r", t + Duration::from_secs(40 * i), N).is_none(),
                    "blocked on refusal {i} though only two fall in any minute");
        }
    }

    #[test]
    fn a_block_is_a_fixed_length_whatever_arrives_meanwhile() {
        let (p, a, t) = (9003, ip("203.0.113.1"), Instant::now());
        for _ in 0..3 { offence_at(p, a, "r", t, N); }
        let until = blocked(p, a).expect("blocked").until;
        // Refusals while blocked neither extend it nor count towards the next.
        for i in 1..50 {
            assert!(offence_at(p, a, "r", t + Duration::from_secs(i), N).is_none());
        }
        assert_eq!(blocked(p, a).unwrap().until, until, "the block was extended");
        // After it ends, the count starts from nothing.
        let later = t + N.block + Duration::from_secs(1);
        assert!(offence_at(p, a, "r", later, N).is_none());
        assert!(offence_at(p, a, "r", later, N).is_none());
        assert!(offence_at(p, a, "r", later, N).is_some());
        unblock(p, unit(a));
    }

    #[test]
    fn ipv6_is_counted_and_blocked_by_its_64() {
        let (p, t) = (9004, Instant::now());
        // Three addresses, one /64: one client.
        offence_at(p, ip("2001:db8:1:2::1"), "r", t, N);
        offence_at(p, ip("2001:db8:1:2::2"), "r", t, N);
        let b = offence_at(p, ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "r", t, N).expect("blocked");
        assert_eq!(unit_label(b.unit), "2001:db8:1:2::/64");
        assert!(blocked(p, ip("2001:db8:1:2::ffff")).is_some());
        assert!(blocked(p, ip("2001:db8:1:3::1")).is_none(), "the next /64 was blocked too");
        // A v4 address written as v6 is that v4 address.
        assert_eq!(unit(ip("::ffff:203.0.113.9")), ip("203.0.113.9"));
        unblock(p, b.unit);
    }

    #[test]
    fn unblocking_lifts_it_and_clears_the_count() {
        let (p, a, t) = (9005, ip("203.0.113.1"), Instant::now());
        for _ in 0..3 { offence_at(p, a, "r", t, N); }
        assert!(unblock(p, unit(a)));
        assert!(blocked(p, a).is_none());
        assert!(!unblock(p, unit(a)), "unblocking twice reported a block");
        assert!(offence_at(p, a, "r", t, N).is_none(), "one refusal after an unblock blocked again");
    }

    #[test]
    fn the_counter_stays_within_its_bound() {
        let mut c: SlidingCounter<u32> = SlidingCounter::new(100);
        let t = Instant::now();
        let window = Duration::from_secs(60);
        // A spray: far more distinct keys than it may hold, all inside the window.
        for k in 0..10_000u32 {
            c.record(k, t + Duration::from_millis(k as u64), window, 3);
            assert!(c.len() <= 100, "grew to {} keys", c.len());
        }
        // One busy key remembers no more than it was told to keep.
        for i in 0..1000 {
            assert!(c.record(7, t + Duration::from_secs(20) + Duration::from_millis(i), window, 3) <= 3);
        }
    }

    #[test]
    fn numbers_are_held_to_the_range_the_form_accepts() {
        // Asserted on the clamp itself rather than through the globals, which
        // other tests read.
        let hold = |v: u64, r: &std::ops::RangeInclusive<u64>| v.clamp(*r.start(), *r.end());
        assert_eq!(hold(0, &REFUSALS_RANGE), 2, "one refusal must never be enough");
        assert_eq!(hold(1_000_000, &BLOCK_SECS_RANGE), 86_400);
        assert_eq!(hold(DEFAULT_WINDOW_SECS, &WINDOW_SECS_RANGE), DEFAULT_WINDOW_SECS);
    }
}

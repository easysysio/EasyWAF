// =========================================================
// iplist.rs — EasyWAF
// Addresses allowed past everything, and addresses refused
// outright.
//
// Consulted on every proxied request, before the pipeline
// runs, so an allowed address skips the WAF, the country
// rules and the challenge alike, and a blocked one is
// refused whether or not the site has a policy at all.
//
// Kept in memory for the same reason the compiled country
// database and the trusted-proxy list are: a database round
// trip on the request path would be absurd.
//
// The structure is a sorted array of ranges per family,
// searched by bisection. A set of addresses would do for
// what an operator types by hand, and cannot answer "is this
// address inside any of these blocks" without expanding
// them — a /12 is a million addresses standing in for one
// row. Published lists (0.11.0) are ranges throughout, so
// the structure is built for them now rather than replaced
// then.
// =========================================================

use crate::forwarded::Cidr;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};

// ─── ListType ────────────────────────────────────────────

/// Which list an address is on. It is never on both: the table's `UNIQUE(ip)`
/// is what makes that true rather than a convention anybody has to remember.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListType {
    /// Skips every check, including the challenge.
    Allow,
    /// Refused outright.
    Block,
}

impl ListType {
    pub fn as_str(self) -> &'static str {
        match self {
            ListType::Allow => "allow",
            ListType::Block => "block",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "allow" => Some(ListType::Allow),
            "block" => Some(ListType::Block),
            _       => None,
        }
    }
}

// ─── Ranges ──────────────────────────────────────────────

/// Sorted, non-overlapping ranges, one array per family.
///
/// The families are kept apart deliberately, which is the same decision
/// `Cidr::contains` makes: a v4 address must not match a v6 block through its
/// mapped form. Folding both into one space would make `10.0.0.0/8` quietly
/// cover `::ffff:10.0.0.1`, which is a wider rule than the one written down.
#[derive(Debug, Default, Clone)]
struct Ranges {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

impl Ranges {
    fn build(blocks: &[Cidr]) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for c in blocks {
            if c.is_ipv4() { v4.push(c.range()) } else { v6.push(c.range()) }
        }
        Self { v4: coalesce(v4), v6: coalesce(v6) }
    }

    /// Whether any range holds this address.
    ///
    /// Bisection over ranges that are sorted and do not overlap, so the
    /// candidate is the last range starting at or below the address and one
    /// comparison settles it.
    fn contains(&self, ip: IpAddr) -> bool {
        let (ranges, value) = match ip {
            IpAddr::V4(a) => (&self.v4, u32::from(a) as u128),
            IpAddr::V6(a) => (&self.v6, u128::from(a)),
        };
        let i = ranges.partition_point(|(start, _)| *start <= value);
        i > 0 && ranges[i - 1].1 >= value
    }

    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

/// Sort and merge, so overlapping or touching blocks become one range.
///
/// Touching counts: `10.0.0.0/25` and `10.0.0.128/25` are one /24 as far as a
/// lookup is concerned, and merging them keeps the array smaller without
/// changing a single answer.
fn coalesce(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            // saturating, because the last range in v6 space ends at u128::MAX
            // and asking what comes after it must not wrap round to zero.
            Some(prev) if start <= prev.1.saturating_add(1) => {
                if end > prev.1 {
                    prev.1 = end;
                }
            }
            _ => out.push((start, end)),
        }
    }
    out
}

// ─── Lists ───────────────────────────────────────────────

/// Both lists, ready to be consulted.
///
/// A plain value with no global state, so the decision it makes can be tested
/// exhaustively without a database and without tests racing each other — the
/// same split `forwarded::resolve` uses for the same reason.
#[derive(Debug, Default, Clone)]
pub struct Lists {
    allow: Ranges,
    block: Ranges,
}

impl Lists {
    /// Build from stored rows, reporting anything that could not be read.
    ///
    /// Rejected entries are returned rather than dropped: a row that silently
    /// does nothing is an address somebody believes is blocked and is not.
    pub fn build<'a>(rows: impl IntoIterator<Item = (&'a str, &'a str)>) -> (Self, Vec<String>) {
        let (mut allow, mut block, mut bad) = (Vec::new(), Vec::new(), Vec::new());

        for (ip, list_type) in rows {
            match (Cidr::parse(ip), ListType::parse(list_type)) {
                (Some(c), Some(ListType::Allow)) => allow.push(c),
                (Some(c), Some(ListType::Block)) => block.push(c),
                _ => bad.push(ip.to_string()),
            }
        }

        (Self { allow: Ranges::build(&allow), block: Ranges::build(&block) }, bad)
    }

    /// Which list this address is on, if any.
    ///
    /// Allow is checked first and wins. An operator who has said an address is
    /// fine has overruled everything else, and that has to stay true when the
    /// same address arrives on a published block list later.
    pub fn lookup(&self, ip: IpAddr) -> Option<ListType> {
        if self.allow.contains(ip) {
            Some(ListType::Allow)
        } else if self.block.contains(ip) {
            Some(ListType::Block)
        } else {
            None
        }
    }

    /// How many ranges each list holds, after merging.
    pub fn counts(&self) -> (usize, usize) {
        (self.allow.len(), self.block.len())
    }
}

// ─── The loaded lists ────────────────────────────────────

static LISTS: OnceLock<RwLock<Lists>> = OnceLock::new();

fn lists() -> &'static RwLock<Lists> {
    LISTS.get_or_init(|| RwLock::new(Lists::default()))
}

/// Read both lists from the database into memory.
///
/// Called at startup and whenever an entry is added or removed, so a change
/// takes effect on the next request rather than the next restart.
pub async fn reload(db: &SqlitePool) -> usize {
    let rows = sqlx::query!(
        r#"SELECT ip as "ip!", list_type as "list_type!" FROM ip_rules"#
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let (built, bad) = Lists::build(
        rows.iter().map(|r| (r.ip.as_str(), r.list_type.as_str()))
    );

    if !bad.is_empty() {
        tracing::warn!("Ignoring unusable IP list entries: {}", bad.join(", "));
    }

    let (allow, block) = built.counts();
    let total = allow + block;
    if let Ok(mut w) = lists().write() {
        *w = built;
    }
    tracing::info!(allow, block, "IP lists loaded");
    total
}

/// Which list this address is on, if any.
///
/// A poisoned lock answers `None`: neither list applies, so the request goes on
/// to the pipeline and is inspected as it would have been. Failing the other
/// way would either refuse every request or wave every request past the WAF,
/// and both are worse than losing the lists until the next reload.
pub fn lookup(ip: IpAddr) -> Option<ListType> {
    lists().read().ok().and_then(|l| l.lookup(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    fn built(rows: &[(&str, &str)]) -> Lists {
        let (l, bad) = Lists::build(rows.iter().copied());
        assert!(bad.is_empty(), "unexpected rejects: {bad:?}");
        l
    }

    #[test]
    fn a_single_address_matches_only_itself() {
        let l = built(&[("203.0.113.9", "block")]);
        assert_eq!(l.lookup(ip("203.0.113.9")), Some(ListType::Block));
        assert_eq!(l.lookup(ip("203.0.113.8")), None);
        assert_eq!(l.lookup(ip("203.0.113.10")), None);
    }

    #[test]
    fn a_block_matches_its_edges_and_stops_there() {
        // The addresses either side of a range are where an off-by-one in the
        // bisection would show up, and nowhere else.
        let l = built(&[("10.0.0.0/24", "block")]);
        assert_eq!(l.lookup(ip("10.0.0.0")), Some(ListType::Block), "first address");
        assert_eq!(l.lookup(ip("10.0.0.255")), Some(ListType::Block), "last address");
        assert_eq!(l.lookup(ip("9.255.255.255")), None, "one below");
        assert_eq!(l.lookup(ip("10.0.1.0")), None, "one above");
    }

    #[test]
    fn a_large_block_stays_one_range() {
        // The whole point of ranges over a set: a /12 is 1,048,576 addresses
        // and must cost one entry, not a million.
        let l = built(&[("172.16.0.0/12", "block")]);
        assert_eq!(l.counts(), (0, 1));
        assert_eq!(l.lookup(ip("172.20.10.1")), Some(ListType::Block));
        assert_eq!(l.lookup(ip("172.32.0.1")), None);
    }

    #[test]
    fn overlapping_and_touching_blocks_merge() {
        let l = built(&[
            ("10.0.0.0/25",   "block"),   // touches the next
            ("10.0.0.128/25", "block"),
            ("10.0.0.64/26",  "block"),   // inside both
        ]);
        assert_eq!(l.counts(), (0, 1), "three blocks describing one /24");
        assert_eq!(l.lookup(ip("10.0.0.200")), Some(ListType::Block));
    }

    #[test]
    fn allow_wins_over_block() {
        // The operator's override has to survive a block arriving later, which
        // is exactly what a published list will do in 0.11.0.
        let l = built(&[("10.0.0.5", "allow"), ("10.0.0.0/8", "block")]);
        assert_eq!(l.lookup(ip("10.0.0.5")), Some(ListType::Allow));
        assert_eq!(l.lookup(ip("10.0.0.6")), Some(ListType::Block));
    }

    #[test]
    fn the_families_are_kept_apart() {
        // ::ffff:10.0.0.1 is 10.0.0.1 written as v6. Matching it against a v4
        // block would enforce a wider rule than the one written down.
        let l = built(&[("10.0.0.0/8", "block")]);
        assert_eq!(l.lookup(ip("::ffff:10.0.0.1")), None);

        let l = built(&[("2001:db8::/32", "block")]);
        assert_eq!(l.lookup(ip("2001:db8::1")), Some(ListType::Block));
        assert_eq!(l.lookup(ip("2001:db9::1")), None);
        assert_eq!(l.lookup(ip("10.0.0.1")), None);
    }

    #[test]
    fn a_sloppy_prefix_describes_the_block_it_meant() {
        // 10.1.2.3/24 is how people write it; every other tool reads it as
        // 10.1.2.0/24 rather than refusing.
        let l = built(&[("10.1.2.3/24", "block")]);
        assert_eq!(l.lookup(ip("10.1.2.0")), Some(ListType::Block));
        assert_eq!(l.lookup(ip("10.1.2.255")), Some(ListType::Block));
    }

    #[test]
    fn everything_and_nothing() {
        let all = built(&[("0.0.0.0/0", "block")]);
        assert_eq!(all.lookup(ip("1.2.3.4")), Some(ListType::Block));
        assert_eq!(all.lookup(ip("::1")), None, "a v4 default route is not every v6 address");

        let v6_all = built(&[("::/0", "block")]);
        assert_eq!(v6_all.lookup(ip("::1")), Some(ListType::Block));
        assert_eq!(v6_all.lookup(ip("ffff::ffff")), Some(ListType::Block), "the last address");

        let empty = built(&[]);
        assert_eq!(empty.lookup(ip("1.2.3.4")), None);
        assert_eq!(empty.counts(), (0, 0));
    }

    #[test]
    fn unusable_rows_are_reported_not_dropped() {
        // An entry that silently does nothing is an address somebody believes
        // is blocked and is not.
        let (l, bad) = Lists::build([
            ("10.0.0.1", "block"),
            ("not-an-address", "block"),
            ("10.0.0.2", "sideways"),
            ("10.0.0.0/33", "block"),
        ]);
        assert_eq!(bad.len(), 3, "got {bad:?}");
        assert_eq!(l.counts(), (0, 1), "the usable row still loaded");
    }
}

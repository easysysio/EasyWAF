// =========================================================
// iplist.rs — EasyWAF
// Addresses a policy lets past everything, and addresses it
// refuses outright — its own, and those of the published
// lists it has switched on.
//
// Consulted on every proxied request, before the pipeline
// runs, so an allowed address skips the WAF, the country
// rules and the challenge alike. Since 0.12.1 the lists
// belong to a policy, like everything else that decides
// what happens to a request, and a site with no policy has
// none.
//
// Kept in memory for the reason the compiled rules are: a
// database round trip on the request path would be absurd.
// Each policy's lists are rebuilt when the configuration
// generation moves, which every write to them does, so no
// handler has to remember to reload anything.
//
// The structure is a sorted array of ranges per family,
// searched by bisection. A set of addresses would do for
// what an operator types by hand, and cannot answer "is this
// address inside any of these blocks" without expanding
// them — a /12 is a million addresses standing in for one
// row. Published lists are ranges throughout, and are parsed
// once and shared by every policy that uses them.
// =========================================================

use crate::forwarded::Cidr;
use serde::Serialize;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

// ─── ListType ────────────────────────────────────────────

/// Which of a policy's own lists an address is on. It is never on both: the
/// table's `UNIQUE(policy_id, ip)` is what makes that true rather than a
/// convention anybody has to remember.
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

/// One policy's lists, ready to be consulted.
///
/// A plain value with no global state, so the decision it makes can be tested
/// exhaustively without a database and without tests racing each other — the
/// same split `forwarded::resolve` uses for the same reason.
#[derive(Debug, Default, Clone)]
pub struct Lists {
    allow: Ranges,
    block: Ranges,
    /// Published lists that are switched on. Loaded separately from the
    /// manual ones, on their own schedule — see `iplist_feeds`.
    feeds: Vec<Feed>,
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

        (Self { allow: Ranges::build(&allow), block: Ranges::build(&block), feeds: Vec::new() }, bad)
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

    /// Where this address stands across every list, manual and published.
    ///
    /// The order is the design. The manual allowlist overrules everything, the
    /// manual blocklist comes next, then published lists that block, then
    /// those that challenge. An operator who has said an address is fine has
    /// overruled every feed, and no sync can undo that.
    pub fn check(&self, ip: IpAddr) -> Option<Listed> {
        match self.lookup(ip) {
            Some(ListType::Allow) => return Some(Listed::Allowed),
            Some(ListType::Block) => return Some(Listed::Blocked),
            None => {}
        }

        // Blocking lists before challenging ones, so an address on both gets
        // the stronger answer whatever order the lists happened to load in.
        [Response::Block, Response::Challenge].into_iter().find_map(|want| {
            self.feeds
                .iter()
                .find(|f| f.response == want && f.ranges.contains(ip))
                .map(|f| Listed::Published(FeedHit {
                    id:       f.id.clone(),
                    name:     f.name.clone(),
                    response: f.response,
                }))
        })
    }

    /// How many ranges each list holds, after merging.
    #[cfg(test)]
    pub fn counts(&self) -> (usize, usize) {
        (self.allow.len(), self.block.len())
    }
}

// ─── Published lists ─────────────────────────────────────

/// What a published list does to an address on it.
///
/// Off is not a value: a list that is off is never loaded, so the request path
/// cannot mistake it for a response somebody forgot to handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Response {
    /// A CAPTCHA, which anyone human can pass — so a misclassified address is
    /// a speed bump rather than a wall.
    Challenge,
    /// Refused outright, before any rule runs.
    Block,
}

impl Response {
    pub fn as_str(self) -> &'static str {
        match self {
            Response::Challenge => "challenge",
            Response::Block     => "block",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "challenge" => Some(Response::Challenge),
            "block"     => Some(Response::Block),
            _           => None,
        }
    }
}

/// A published list's contents, parsed once for the whole installation.
#[derive(Debug)]
pub struct FeedData {
    pub id:   String,
    pub name: String,
    ranges:   Arc<Ranges>,
}

impl FeedData {
    pub fn new(id: &str, name: &str, blocks: &[Cidr]) -> Self {
        Self {
            id:     id.to_string(),
            name:   name.to_string(),
            ranges: Arc::new(Ranges::build(blocks)),
        }
    }

    /// How many ranges it holds, after merging.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }
}

/// A published list as one policy uses it: the shared ranges, and the response
/// that policy chose.
#[derive(Debug, Clone)]
pub struct Feed {
    pub id:       String,
    pub name:     String,
    pub response: Response,
    ranges:       Arc<Ranges>,
}

impl Feed {
    fn using(data: &FeedData, response: Response) -> Self {
        Self {
            id:       data.id.clone(),
            name:     data.name.clone(),
            response,
            ranges:   data.ranges.clone(),
        }
    }
}

/// The published list an address was found on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedHit {
    pub id:       String,
    pub name:     String,
    pub response: Response,
}

/// Where an address stands, every list considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listed {
    /// On the manual allowlist: skips everything, published lists included.
    Allowed,
    /// On the manual blocklist.
    Blocked,
    /// On a published list that is switched on.
    Published(FeedHit),
}

/// Read a published list: one address or block per line.
///
/// Anything after `;` or `#` is a comment. Spamhaus DROP writes
/// `192.0.2.0/24 ; SBL123`, and opens with `;` lines its terms require to stay
/// with the data. Returns the blocks read and how many lines were not
/// addresses, so a list that has quietly changed format shows up as a number
/// rather than as an empty list nobody thinks to question.
pub fn parse_feed(text: &str) -> (Vec<Cidr>, usize) {
    let mut blocks = Vec::new();
    let mut unreadable = 0;
    for line in text.lines() {
        let entry = line.split([';', '#']).next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        match Cidr::parse(entry) {
            Some(c) => blocks.push(c),
            None    => unreadable += 1,
        }
    }
    (blocks, unreadable)
}

// ─── Building every policy's lists ───────────────────────

/// Every policy's lists, from stored rows and the published data in memory.
///
/// A plain function of its inputs, so what one policy sees can be tested
/// against another without a database. Rows that cannot be read are returned
/// rather than dropped: a row that silently does nothing is an address
/// somebody believes is blocked and is not.
fn build_policies(
    rows:    &[(i64, String, String)],
    choices: &[(i64, String, Response)],
    data:    &HashMap<String, Arc<FeedData>>,
) -> (HashMap<i64, Arc<Lists>>, Vec<String>) {
    let mut grouped: HashMap<i64, Vec<(&str, &str)>> = HashMap::new();
    for (policy, ip, list_type) in rows {
        grouped.entry(*policy).or_default().push((ip.as_str(), list_type.as_str()));
    }
    let mut policies: HashMap<i64, Lists> = HashMap::new();
    let mut bad = Vec::new();
    for (policy, entries) in grouped {
        let (lists, unusable) = Lists::build(entries);
        bad.extend(unusable);
        policies.insert(policy, lists);
    }

    // A choice for a list that is not loaded — never fetched, withdrawn, or
    // refused verification — adds nothing. The IP Lists page says why.
    for (policy, id, response) in choices {
        if let Some(d) = data.get(id) {
            policies.entry(*policy).or_default().feeds.push(Feed::using(d, *response));
        }
    }

    (policies.into_iter().map(|(k, v)| (k, Arc::new(v))).collect(), bad)
}

// ─── The loaded lists ────────────────────────────────────

/// Published list contents, replaced whole whenever the mirror is reloaded.
/// The version tells the per-policy cache to rebuild, since a reload does not
/// touch the database and so does not move the generation.
struct Published {
    version: u64,
    lists:   HashMap<String, Arc<FeedData>>,
}

static PUBLISHED: OnceLock<RwLock<Published>> = OnceLock::new();

fn published() -> &'static RwLock<Published> {
    PUBLISHED.get_or_init(|| RwLock::new(Published { version: 0, lists: HashMap::new() }))
}

/// Replace the published lists held in memory.
pub fn set_feed_data(lists: HashMap<String, Arc<FeedData>>) {
    if let Ok(mut p) = published().write() {
        p.version += 1;
        p.lists = lists;
    }
}

/// Every policy's lists, as of one generation and one set of published data.
struct Loaded {
    generation: u64,
    published:  u64,
    policies:   HashMap<i64, Arc<Lists>>,
}

static LOADED: OnceLock<RwLock<Option<Loaded>>> = OnceLock::new();

fn loaded() -> &'static RwLock<Option<Loaded>> {
    LOADED.get_or_init(|| RwLock::new(None))
}

/// One policy's lists, rebuilt first if the configuration has changed.
///
/// The generation is read **before** the rows, for the reason
/// `WafModule::snapshot` gives: a write landing between the two files newer
/// rows under an older number, which the next check corrects.
async fn policy_lists(db: &SqlitePool, policy_id: i64) -> Option<Arc<Lists>> {
    let generation = crate::modules::generation::current(db).await;
    let version = published().read().map(|p| p.version).unwrap_or(0);

    if let Ok(l) = loaded().read()
        && let Some(l) = l.as_ref()
        && l.generation == generation
        && l.published == version
    {
        return l.policies.get(&policy_id).cloned();
    }

    let rows: Vec<(i64, String, String)> = sqlx::query!(
        r#"SELECT policy_id as "policy_id!", ip as "ip!", list_type as "list_type!"
           FROM ip_rules"#
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| (r.policy_id, r.ip, r.list_type))
    .collect();

    let choices: Vec<(i64, String, Response)> = sqlx::query!(
        r#"SELECT policy_id as "policy_id!", id as "id!", response as "response!"
           FROM ip_list_feeds WHERE enabled = 1"#
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    // The column's CHECK makes anything else unreachable. Were it reached,
    // challenge is the answer that cannot lock anybody out.
    .map(|r| (r.policy_id, r.id, Response::parse(&r.response).unwrap_or(Response::Challenge)))
    .collect();

    let data = published().read().map(|p| p.lists.clone()).unwrap_or_default();
    let (policies, bad) = build_policies(&rows, &choices, &data);
    if !bad.is_empty() {
        tracing::warn!("Ignoring unusable IP list entries: {}", bad.join(", "));
    }
    let wanted = policies.get(&policy_id).cloned();

    // Kept unless something newer is already there — a slow rebuild that lost
    // a race with a faster one must not put older lists back.
    if let Ok(mut l) = loaded().write() {
        let newer = l.as_ref().is_none_or(|cur| {
            (generation, version) >= (cur.generation, cur.published)
        });
        if newer {
            *l = Some(Loaded { generation, published: version, policies });
        }
    }
    wanted
}

/// Where this address stands under a policy, its own lists and its published
/// ones considered.
///
/// A poisoned lock or a database in trouble answers `None`: no list applies,
/// so the request goes on to the pipeline and is inspected as it would have
/// been. Failing the other way would either refuse every request or wave every
/// request past the WAF, and both are worse than losing the lists for a moment.
pub async fn check(db: &SqlitePool, policy_id: i64, ip: IpAddr) -> Option<Listed> {
    policy_lists(db, policy_id).await.and_then(|l| l.check(ip))
}

/// Which of a policy's own lists this address is on, for the Traffic Monitor's
/// badge. Published lists are not a badge: they are not something the row can
/// add the address to or take it off.
pub async fn lookup(db: &SqlitePool, policy_id: i64, ip: IpAddr) -> Option<ListType> {
    policy_lists(db, policy_id).await.and_then(|l| l.lookup(ip))
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
        // is exactly what a published list will do in 0.12.0.
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

    fn with_feeds(rows: &[(&str, &str)], feeds: &[(&str, Response, &[&str])]) -> Lists {
        let mut l = built(rows);
        l.feeds = feeds
            .iter()
            .map(|(id, response, blocks)| {
                let cidrs: Vec<Cidr> = blocks.iter().map(|b| Cidr::parse(b).unwrap()).collect();
                Feed::using(&FeedData::new(id, &format!("{id} list"), &cidrs), *response)
            })
            .collect();
        l
    }

    fn published(id: &str, response: Response) -> Option<Listed> {
        Some(Listed::Published(FeedHit {
            id: id.to_string(),
            name: format!("{id} list"),
            response,
        }))
    }

    #[test]
    fn an_address_on_a_published_list_is_found_with_its_response() {
        let l = with_feeds(&[], &[
            ("drop", Response::Block,     &["198.51.100.0/24"]),
            ("tor",  Response::Challenge, &["203.0.113.7"]),
        ]);
        assert_eq!(l.check(ip("198.51.100.200")), published("drop", Response::Block));
        assert_eq!(l.check(ip("203.0.113.7")),    published("tor", Response::Challenge));
        assert_eq!(l.check(ip("203.0.113.8")),    None);
    }

    #[test]
    fn the_manual_allowlist_overrules_every_published_list() {
        // The design's central promise: somebody who has said an address is
        // fine has overruled every feed, and a sync cannot take that back.
        let l = with_feeds(&[("198.51.100.9", "allow")], &[
            ("drop", Response::Block, &["198.51.100.0/24"]),
        ]);
        assert_eq!(l.check(ip("198.51.100.9")), Some(Listed::Allowed));
        assert_eq!(l.check(ip("198.51.100.10")), published("drop", Response::Block));
    }

    #[test]
    fn a_manual_block_is_reported_as_manual() {
        // The traffic row should name the operator's own list, not a feed that
        // happens to agree with it.
        let l = with_feeds(&[("198.51.100.9", "block")], &[
            ("drop", Response::Block, &["198.51.100.0/24"]),
        ]);
        assert_eq!(l.check(ip("198.51.100.9")), Some(Listed::Blocked));
    }

    #[test]
    fn blocking_beats_challenging_whatever_the_load_order() {
        for order in [
            [("et", Response::Challenge), ("drop", Response::Block)],
            [("drop", Response::Block), ("et", Response::Challenge)],
        ] {
            let l = with_feeds(&[], &[
                (order[0].0, order[0].1, &["192.0.2.0/24"]),
                (order[1].0, order[1].1, &["192.0.2.0/24"]),
            ]);
            assert_eq!(l.check(ip("192.0.2.1")), published("drop", Response::Block),
                       "order {:?}", order.map(|o| o.0));
        }
    }

    #[test]
    fn manual_reloads_leave_published_lists_alone() {
        let mut l = with_feeds(&[], &[("drop", Response::Block, &["192.0.2.0/24"])]);
        let (manual, _) = Lists::build([("203.0.113.1", "block")]);
        l.allow = manual.allow;
        l.block = manual.block;
        assert_eq!(l.check(ip("192.0.2.1")), published("drop", Response::Block));
        assert_eq!(l.check(ip("203.0.113.1")), Some(Listed::Blocked));
    }

    #[test]
    fn a_drop_style_file_reads_with_its_header_and_comments() {
        let text = "\
; Spamhaus DROP List 2026/09/16 - (c) 2026 The Spamhaus Project SLU
; https://www.spamhaus.org/drop/drop.txt
; Last-Modified: Wed, 16 Sep 2026 06:00:00 GMT

1.10.16.0/20 ; SBL256894
2.56.192.0/22 ; SBL459831
2001:db8::/32 ; SBL000001
";
        let (blocks, unreadable) = parse_feed(text);
        assert_eq!(blocks.len(), 3);
        assert_eq!(unreadable, 0);
        let l = Lists {
            feeds: vec![Feed::using(&FeedData::new("drop", "DROP", &blocks), Response::Block)],
            ..Lists::default()
        };
        assert!(l.check(ip("1.10.20.1")).is_some());
        assert!(l.check(ip("2001:db8::1")).is_some());
        assert!(l.check(ip("1.10.32.0")).is_none(), "the /20 ends at 1.10.31.255");
    }

    #[test]
    fn a_plain_address_list_reads_and_counts_what_it_cannot() {
        // The Tor exit list and ET's compromised hosts are bare addresses.
        let (blocks, unreadable) = parse_feed("203.0.113.7\n# exits\n\n2001:db8::7\nnot-an-address\n999.1.1.1\n");
        assert_eq!(blocks.len(), 2);
        assert_eq!(unreadable, 2, "a format change must be visible, not silent");
    }

    fn data(id: &str, blocks: &[&str]) -> (String, Arc<FeedData>) {
        let cidrs: Vec<Cidr> = blocks.iter().map(|b| Cidr::parse(b).unwrap()).collect();
        (id.to_string(), Arc::new(FeedData::new(id, &format!("{id} list"), &cidrs)))
    }

    #[test]
    fn each_policy_sees_only_its_own_lists() {
        // The public websites block an address and use DROP; the Nextcloud
        // policy allows that address and uses nothing published.
        let rows = vec![
            (1, "203.0.113.9".to_string(), "block".to_string()),
            (2, "203.0.113.9".to_string(), "allow".to_string()),
        ];
        let choices = vec![(1, "drop".to_string(), Response::Block)];
        let feeds: HashMap<_, _> = [data("drop", &["198.51.100.0/24"])].into();

        let (policies, bad) = build_policies(&rows, &choices, &feeds);
        assert!(bad.is_empty());
        let websites = &policies[&1];
        let nextcloud = &policies[&2];

        assert_eq!(websites.check(ip("203.0.113.9")), Some(Listed::Blocked));
        assert_eq!(nextcloud.check(ip("203.0.113.9")), Some(Listed::Allowed));
        assert_eq!(websites.check(ip("198.51.100.1")), published("drop", Response::Block));
        assert_eq!(nextcloud.check(ip("198.51.100.1")), None,
                   "a list one policy switched on reached another");
        assert!(!policies.contains_key(&3), "a policy with nothing listed has nothing");
    }

    #[test]
    fn two_policies_share_a_list_with_different_responses() {
        let choices = vec![
            (1, "tor".to_string(), Response::Block),
            (2, "tor".to_string(), Response::Challenge),
        ];
        let feeds: HashMap<_, _> = [data("tor", &["192.0.2.7"])].into();
        let (policies, _) = build_policies(&[], &choices, &feeds);
        assert_eq!(policies[&1].check(ip("192.0.2.7")), published("tor", Response::Block));
        assert_eq!(policies[&2].check(ip("192.0.2.7")), published("tor", Response::Challenge));
        // Parsed once: both policies hold the same ranges, not two copies.
        assert!(Arc::ptr_eq(&policies[&1].feeds[0].ranges, &policies[&2].feeds[0].ranges));
    }

    #[test]
    fn a_switched_on_list_that_is_not_loaded_adds_nothing() {
        let choices = vec![(1, "withdrawn".to_string(), Response::Block)];
        let (policies, _) = build_policies(&[], &choices, &HashMap::new());
        assert!(policies.get(&1).is_none_or(|l| l.check(ip("192.0.2.1")).is_none()));
    }
}


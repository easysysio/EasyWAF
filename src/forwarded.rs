// =========================================================
// forwarded.rs — EasyWAF
// Recovering the real client address when EasyWAF sits
// behind another proxy.
//
// X-Forwarded-For is a header, which means the client can
// send one. Honouring it unconditionally would let anyone
// claim any address and walk straight past country rules
// and the IP allow/block lists, so it is trusted only when
// the connection itself came from an address the operator
// has listed. An empty list trusts nothing.
// =========================================================

use axum::http::HeaderMap;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};

/// One entry in the trusted list: a single address or a CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr:   IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `10.0.0.1`, `10.0.0.0/8`, `::1` or `fd00::/8`.
    ///
    /// A bare address is the same as a full-length prefix, so the two forms do
    /// not need separate handling anywhere else.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None         => (s, None),
        };

        let addr: IpAddr = addr_part.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => p.trim().parse::<u8>().ok()?,
            None    => max,
        };

        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    /// Whether an address falls inside this block.
    ///
    /// A v4 address never matches a v6 block or the reverse — including
    /// v4-mapped forms, which are normalised by the caller before they get
    /// here, because `::ffff:10.0.0.1` matching `10.0.0.0/8` by accident would
    /// be a quiet way to trust more than was written down.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                bits_match(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                bits_match(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }

    /// Which family this block is in, so a matcher can keep the two apart.
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// The block as an inclusive `(first, last)` pair of integers.
    ///
    /// Within its own family's space: a v4 block spans 0..=u32::MAX widened to
    /// u128, a v6 block the full range. Keeping the two spaces separate is the
    /// same decision `contains` makes above — a v4 address must not match a v6
    /// block through its mapped form.
    ///
    /// Host bits below the prefix are cleared for the start and set for the
    /// end, so `10.0.0.1/8` and `10.0.0.0/8` describe the same block, which is
    /// what every other tool does with a sloppily written prefix.
    pub fn range(&self) -> (u128, u128) {
        let (bits, value) = match self.addr {
            IpAddr::V4(a) => (32u32,  u32::from(a) as u128),
            IpAddr::V6(a) => (128u32, u128::from(a)),
        };
        let host = bits - self.prefix as u32;
        if host >= bits {
            // A /0 covers everything; shifting by the full width is undefined.
            return (0, if bits == 32 { u32::MAX as u128 } else { u128::MAX });
        }
        let mask = if host == 0 { 0 } else { (1u128 << host) - 1 };
        (value & !mask, value | mask)
    }
}

/// Compare the first `prefix` bits of two addresses.
fn bits_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

// ─── The configured list ─────────────────────────────────

static TRUSTED: OnceLock<RwLock<Vec<Cidr>>> = OnceLock::new();

fn trusted() -> &'static RwLock<Vec<Cidr>> {
    TRUSTED.get_or_init(|| RwLock::new(Vec::new()))
}

/// Parse a configured list, returning the usable entries and anything rejected.
///
/// Separators are commas, spaces or newlines, so a list can be pasted from
/// wherever the operator keeps it.
pub fn parse_list(configured: &str) -> (Vec<Cidr>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for tok in configured.split(|c: char| c == ',' || c.is_whitespace()) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        match Cidr::parse(tok) {
            Some(c) => ok.push(c),
            None    => bad.push(tok.to_string()),
        }
    }
    (ok, bad)
}

/// Load the trusted list from settings into memory.
///
/// Held in memory rather than read per request: this is on the path of every
/// single request, and a database round trip there would be absurd. Reloaded
/// when the setting is saved, so a change takes effect without a restart.
pub async fn reload(db: &SqlitePool) -> usize {
    let raw = crate::routes::settings::get_trusted_proxies(db).await;
    let (list, bad) = parse_list(&raw);

    if !bad.is_empty() {
        tracing::warn!("Ignoring unparseable trusted-proxy entries: {}", bad.join(", "));
    }

    let n = list.len();
    if let Ok(mut w) = trusted().write() {
        *w = list;
    }
    tracing::info!("Trusted proxies: {} entr{}", n, if n == 1 { "y" } else { "ies" });
    n
}

// ─── client_ip ───────────────────────────────────────────

/// Every `X-Forwarded-For` line, read as the one list HTTP says they are.
///
/// A header sent on several lines means the same as one line with the values
/// joined by commas, in order, and proxies differ in which they write: nginx
/// extends the line it received, HAProxy's `option forwardfor` adds a line of
/// its own. Reading only the first line — the one the client wrote — would
/// believe a forged address behind a proxy of the second kind, and IP lists,
/// country rules and challenge clearance all go by it.
pub fn forwarded_for(headers: &HeaderMap) -> Option<String> {
    let lines: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    if lines.is_empty() { None } else { Some(lines.join(", ")) }
}


/// The address to treat as the client's.
///
/// The connection's own peer address unless it came from a trusted proxy, in
/// which case the rightmost address in `X-Forwarded-For` that is not itself a
/// trusted proxy. Walking from the right matters: entries are appended left to
/// right, so the leftmost is whatever the *original* client claimed and can be
/// anything at all. Only the entries added by hops we trust are worth
/// believing, and the first untrusted one below them is the furthest we can
/// honestly go.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    match trusted().read() {
        Ok(t) => resolve(peer, headers, &t),
        // A poisoned lock must not become a way to bypass the check.
        Err(_) => peer,
    }
}

/// Whether an address is one of the configured trusted proxies.
///
/// Smart Protect never blocks one. If forwarded headers are misconfigured,
/// every request appears to come from the proxy's address, and blocking it
/// would refuse every client behind it at once.
pub fn is_trusted_proxy(ip: IpAddr) -> bool {
    match trusted().read() {
        Ok(t)  => t.iter().any(|c| c.contains(ip)),
        Err(_) => false,
    }
}

/// Whether the client reached the site over HTTPS.
///
/// On a TLS listener it did. On a plain one it still may have: a proxy in
/// front that terminates TLS speaks plain HTTP to EasyWAF and says so in
/// `X-Forwarded-Proto`. That header is believed from a trusted proxy and from
/// nobody else — a client that could claim HTTPS would be sent HSTS and Secure
/// cookies over a connection that is not.
pub fn client_used_https(peer: IpAddr, headers: &HeaderMap, listener_is_tls: bool) -> bool {
    listener_is_tls || (is_trusted_proxy(peer) && says_https(headers))
}

/// Whether `X-Forwarded-Proto` names https. The first value, which is the hop
/// nearest the client.
fn says_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .and_then(|v| v.split(',').next().map(|first| first.trim().eq_ignore_ascii_case("https")))
        .unwrap_or(false)
}

/// The decision itself, against an explicit list.
///
/// Separate from `client_ip` so the security-critical part is a pure function:
/// it can be tested exhaustively without touching global state, and the tests
/// cannot interfere with each other by racing on it.
pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &[Cidr]) -> IpAddr {
    let trusts = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));

    if trusted.is_empty() || !trusts(peer) {
        return peer;
    }

    let Some(raw) = forwarded_for(headers) else {
        return peer;
    };

    let hops: Vec<IpAddr> = raw
        .split(',')
        .filter_map(|h| normalise(h.trim()))
        .collect();

    if hops.is_empty() {
        return peer;
    }

    for ip in hops.iter().rev() {
        if !trusts(*ip) {
            return *ip;
        }
    }

    // Every hop is a trusted proxy, so the leftmost is the closest thing to a
    // client this chain contains.
    hops[0]
}

/// Parse a hop, unwrapping v4-mapped v6 so `::ffff:1.2.3.4` is compared as the
/// v4 address an operator would have written in the list.
fn normalise(s: &str) -> Option<IpAddr> {
    // Some proxies bracket v6 addresses, and some append a port.
    let s = s.trim_start_matches('[');
    let s = match s.split_once(']') {
        Some((inner, _)) => inner,
        None             => s,
    };

    let ip: IpAddr = match s.parse() {
        Ok(ip) => ip,
        Err(_) => s.rsplit_once(':')?.0.parse().ok()?,
    };

    Some(match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None     => IpAddr::V6(v6),
        },
        v4 => v4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_a_proxy_reports_is_read_from_its_first_value() {
        let proto = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-proto", v.parse().unwrap());
            says_https(&h)
        };
        assert!(proto("https"));
        assert!(proto("HTTPS"));
        assert!(proto("https, http"), "the hop nearest the client is the first");
        assert!(!proto("http"));
        assert!(!proto("http, https"));
        assert!(!says_https(&HeaderMap::new()));
    }

    #[test]
    fn only_a_trusted_proxy_can_say_the_client_used_https() {
        // Nothing is trusted in a test process, so the header alone changes
        // nothing: a client cannot talk its way into HSTS and Secure cookies.
        let peer: IpAddr = "203.0.113.200".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(!client_used_https(peer, &h, false));
        assert!(client_used_https(peer, &HeaderMap::new(), true), "a TLS listener needs no header");
    }
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_proxy_that_adds_its_own_line_is_read_after_the_clients() {
        // HAProxy adds a line rather than extending the client's. Reading only
        // the first line believed the forger.
        let trusted = [Cidr::parse("127.0.0.1").unwrap()];
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
        h.append("x-forwarded-for", "203.0.113.50".parse().unwrap());
        assert_eq!(resolve(peer, &h, &trusted), "203.0.113.50".parse::<IpAddr>().unwrap());
        assert_eq!(forwarded_for(&h).as_deref(), Some("6.6.6.6, 203.0.113.50"));
    }

    fn list(s: &str) -> Vec<Cidr> {
        let (l, bad) = parse_list(s);
        assert!(bad.is_empty(), "test list should parse: {bad:?}");
        l
    }

    fn hdr(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", v.parse().unwrap());
        h
    }

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn cidr_parsing_and_containment() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(!c.contains(ip("11.0.0.1")));

        // A bare address is a full-length prefix.
        let single = Cidr::parse("192.168.1.5").unwrap();
        assert!(single.contains(ip("192.168.1.5")));
        assert!(!single.contains(ip("192.168.1.6")));

        // Non-byte-aligned prefixes must actually mask.
        let c = Cidr::parse("192.168.1.0/25").unwrap();
        assert!(c.contains(ip("192.168.1.127")));
        assert!(!c.contains(ip("192.168.1.128")));

        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("nonsense").is_none());
    }

    #[test]
    fn families_do_not_cross() {
        let v4 = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(!v4.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(!v6.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn nothing_trusted_means_the_header_is_ignored() {
        let t = list("");
        // The default, and the behaviour before this existed: a client can send
        // whatever it likes and it changes nothing.
        assert_eq!(resolve(ip("203.0.113.9"), &hdr("1.2.3.4"), &t), ip("203.0.113.9"));
    }

    #[test]
    fn an_untrusted_peer_cannot_spoof() {
        let t = list("10.0.0.1");
        // The peer is not the listed proxy, so its header is worthless.
        assert_eq!(resolve(ip("203.0.113.9"), &hdr("1.2.3.4"), &t), ip("203.0.113.9"));
    }

    #[test]
    fn a_trusted_peer_reveals_the_client() {
        let t = list("10.0.0.1");
        assert_eq!(resolve(ip("10.0.0.1"), &hdr("203.0.113.9"), &t), ip("203.0.113.9"));
    }

    #[test]
    fn a_client_cannot_prepend_a_forged_hop() {
        let t = list("10.0.0.0/8");
        // The client sent "1.2.3.4"; the trusted proxy appended the real
        // address. Walking from the right is what stops the forgery winning.
        assert_eq!(
            resolve(ip("10.0.0.1"), &hdr("1.2.3.4, 203.0.113.9"), &t),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn walks_back_through_a_chain_of_trusted_hops() {
        let t = list("10.0.0.0/8");
        assert_eq!(
            resolve(ip("10.0.0.1"), &hdr("203.0.113.9, 10.0.0.5, 10.0.0.6"), &t),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn falls_back_when_the_header_is_useless() {
        let t = list("10.0.0.1");
        assert_eq!(resolve(ip("10.0.0.1"), &hdr("not-an-ip"), &t), ip("10.0.0.1"));
        assert_eq!(resolve(ip("10.0.0.1"), &HeaderMap::new(), &t), ip("10.0.0.1"));
    }

    #[test]
    fn handles_ports_brackets_and_v4_mapped_forms() {
        let t = list("10.0.0.1");
        assert_eq!(resolve(ip("10.0.0.1"), &hdr("203.0.113.9:51234"), &t), ip("203.0.113.9"));
        assert_eq!(resolve(ip("10.0.0.1"), &hdr("[2001:db8::1]:443"), &t), ip("2001:db8::1"));
        // ::ffff:203.0.113.9 is the v4 address, and must be compared as one.
        assert_eq!(resolve(ip("10.0.0.1"), &hdr("::ffff:203.0.113.9"), &t), ip("203.0.113.9"));
    }
}

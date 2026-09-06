// =========================================================
// forwarded.rs — EasyWAF
// Recovering the real client address when EasyWAF sits
// behind another proxy.
//
// X-Forwarded-For is a header, which means the client can
// send one. Honouring it unconditionally would let anyone
// claim any address and walk straight past country rules —
// and past the IP allow/block lists in 0.12.0 — so it is
// trusted only when the connection itself came from an
// address the operator has listed.
//
// Empty list means trust nothing, which is the behaviour
// EasyWAF had before this existed.
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

    let Some(raw) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
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
    use std::net::{Ipv4Addr, Ipv6Addr};

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

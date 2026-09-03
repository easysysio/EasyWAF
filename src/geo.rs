// =========================================================
// geo.rs — EasyWAF
// IP-to-country lookup from a local MaxMind-format database.
//
// The DB-IP Lite country database is compiled into the
// binary, so country rules work on a fresh install with
// nothing to download and no lookup ever leaving the host.
// Setting `geoip_db` in config.toml points at a different
// .mmdb — a fresher DB-IP file, or MaxMind GeoLite2 — and
// falls back to the bundled one if that file cannot be read.
//
// The reader is built once at startup and shared: it is read
// on every proxied request, so it must not touch the disk
// per lookup.
//
// Attribution: the bundled database is "IP Geolocation by
// DB-IP" (https://db-ip.com), licensed CC BY 4.0.
// =========================================================

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::sync::OnceLock;

/// The bundled DB-IP Lite country database (CC BY 4.0).
static EMBEDDED_DB: &[u8] = include_bytes!("../assets/geo/dbip-country-lite.mmdb");

/// The loaded reader, or None when no database could be opened at all — in
/// which case every lookup returns "no country" and country rules stop
/// matching rather than blocking traffic on bad data.
static READER: OnceLock<Option<Reader<Vec<u8>>>> = OnceLock::new();

// ─── init ────────────────────────────────────────────────

/// Load the database once at startup.
///
/// `geoip_db` empty means "use the bundled database". A configured path that
/// cannot be read is a warning rather than a failure: a typo in config.toml
/// should not take country rules offline when a perfectly good database is
/// compiled in.
pub fn init(geoip_db: &str) {
    let path = geoip_db.trim();

    let reader = if path.is_empty() {
        embedded()
    } else {
        match Reader::open_readfile(path) {
            Ok(r) => {
                tracing::info!(path, "GeoIP: loaded external database");
                Some(r)
            }
            Err(e) => {
                tracing::warn!(
                    path,
                    "GeoIP: could not load external database ({}); using the bundled one",
                    e
                );
                embedded()
            }
        }
    };

    if reader.is_some() && path.is_empty() {
        tracing::info!("GeoIP: using the bundled DB-IP Lite country database");
    }
    let _ = READER.set(reader);
}

/// Open the compiled-in database.
fn embedded() -> Option<Reader<Vec<u8>>> {
    match Reader::from_source(EMBEDDED_DB.to_vec()) {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::error!("GeoIP: bundled database failed to load: {}", e);
            None
        }
    }
}

// ─── lookup ──────────────────────────────────────────────

/// Resolve an address to its ISO 3166-1 alpha-2 country code.
///
/// Returns None when the address has no meaningful country: a private or
/// loopback address, an address the database does not cover, or any lookup
/// attempted before `init` ran. Callers treat None as "unknown" and must not
/// read it as a match — a country rule should never fire on an address whose
/// country could not be established.
pub fn country_of(addr: IpAddr) -> Option<String> {
    if is_private(&addr) {
        return None;
    }

    let reader = READER.get()?.as_ref()?;

    // maxminddb returns a handle first and decodes on demand; an address
    // outside the database decodes to None.
    let found = reader.lookup(addr).ok()?;
    let record = found.decode::<geoip2::Country>().ok()??;

    match record.country.iso_code {
        Some(code) if !code.is_empty() => Some(code.to_uppercase()),
        _ => None,
    }
}

/// True for addresses with no public geolocation — the loopback and RFC 1918
/// ranges a reverse proxy sees constantly in testing and on internal networks.
fn is_private(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Addresses with no public country must resolve to None whether or not a
    /// database is loaded, so a country rule never fires on them.
    #[test]
    fn private_addresses_have_no_country() {
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.79", "169.254.1.1", "::1"] {
            assert_eq!(country_of(ip.parse().unwrap()), None, "{ip}");
        }
    }

    /// The bundled database must actually resolve well-known public addresses —
    /// this is what catches the file going missing or being replaced by a stub.
    #[test]
    fn bundled_database_resolves_public_addresses() {
        init("");
        assert_eq!(country_of("8.8.8.8".parse().unwrap()).as_deref(), Some("US"));
        assert_eq!(country_of("1.1.1.1".parse().unwrap()).as_deref(), Some("AU"));
    }
}

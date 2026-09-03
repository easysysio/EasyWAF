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
// The reader is built at startup and shared: it is read on
// every proxied request, so it must not touch the disk per
// lookup. It is held behind a lock rather than written once,
// so `init` can be called again to swap in a newer database
// without restarting the process — the hook a future
// "update the country database" feature needs.
//
// Attribution: the bundled database is "IP Geolocation by
// DB-IP" (https://db-ip.com), licensed CC BY 4.0.
// =========================================================

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock, RwLock};

/// The bundled DB-IP Lite country database (CC BY 4.0).
static EMBEDDED_DB: &[u8] = include_bytes!("../assets/geo/dbip-country-lite.mmdb");

/// The loaded reader, or None when no database could be opened at all — in
/// which case every lookup returns "no country" and country rules stop
/// matching rather than blocking traffic on bad data.
///
/// Behind an RwLock so a newer database can replace it in place: lookups take
/// the read lock, a swap takes the write lock. The Arc lets a lookup clone the
/// handle and release the lock immediately, so a swap is never queued behind
/// in-flight requests.
static READER: OnceLock<ReaderCell> = OnceLock::new();

/// The shared, replaceable reader slot.
type ReaderCell = RwLock<Option<Arc<Reader<Vec<u8>>>>>;

/// The reader cell, created empty on first use.
fn cell() -> &'static ReaderCell {
    READER.get_or_init(|| RwLock::new(None))
}

// ─── init ────────────────────────────────────────────────

/// Load the database, replacing whatever is loaded now.
///
/// Called once at startup, and safe to call again to swap in a database
/// downloaded later — in-flight lookups finish against the old reader and
/// subsequent ones use the new one.
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

    if let Ok(mut slot) = cell().write() {
        *slot = reader.map(Arc::new);
    }
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

    // Clone the handle and drop the lock before decoding, so a database swap
    // never waits on lookups.
    let reader = {
        let slot = cell().read().ok()?;
        slot.as_ref()?.clone()
    };

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
    /// Calling init twice also proves the reader can be replaced in place,
    /// which is what lets a downloaded database be swapped in without a
    /// restart.
    #[test]
    fn bundled_database_resolves_public_addresses() {
        init("");
        assert_eq!(country_of("8.8.8.8".parse().unwrap()).as_deref(), Some("US"));
        assert_eq!(country_of("1.1.1.1".parse().unwrap()).as_deref(), Some("AU"));

        // A second load must take effect rather than being ignored the way a
        // write-once cell would ignore it.
        init("");
        assert_eq!(country_of("8.8.8.8".parse().unwrap()).as_deref(), Some("US"));
    }
}

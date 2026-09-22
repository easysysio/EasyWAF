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

// ─── Where a database can come from ──────────────────────

/// Which of the four paths loaded the database now in force.
///
/// Worth recording rather than inferring: two of them are verified against a
/// signature this installation holds and two are a file somebody chose, and a
/// page that showed the date without saying which would imply they are the
/// same kind of fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Compiled into the binary: DB-IP Lite, CC BY 4.0.
    Bundled,
    /// `geoip_db` in config.toml — a deliberate local choice, which nothing in
    /// the interface may override.
    Configured,
    /// Fetched from the signed channel and verified.
    Channel,
    /// Uploaded through the interface. Not signed: a file an operator supplies
    /// cannot be checked against a key this installation holds.
    Uploaded,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Bundled    => "bundled",
            Source::Configured => "configured",
            Source::Channel    => "channel",
            Source::Uploaded   => "uploaded",
        }
    }

    /// Whether what is loaded was checked against a signature.
    pub fn verified(self) -> bool {
        matches!(self, Source::Bundled | Source::Channel)
    }
}

/// What the database in force says about itself.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Status {
    pub source:        Source,
    /// "DB-IP Lite", "GeoLite2-Country", or whatever the file calls itself.
    pub database_type: String,
    /// When the publisher built it, as a UTC date. A country database is only
    /// as good as its last build, so this is the date that matters.
    pub built:         Option<String>,
    /// Days since it was built, because that is the question being asked.
    pub age_days:      Option<i64>,
    pub ip_version:    u16,
    pub nodes:         u32,
}

static SOURCE: OnceLock<RwLock<Source>> = OnceLock::new();

fn source_cell() -> &'static RwLock<Source> {
    SOURCE.get_or_init(|| RwLock::new(Source::Bundled))
}

/// What config.toml named, remembered from startup.
///
/// So installing a database later can honour it without re-reading a file
/// whose absence is fatal to `config::load` — and so the rule stays in one
/// place: config.toml wins, whatever arrives afterwards.
static CONFIGURED: OnceLock<RwLock<String>> = OnceLock::new();

fn configured_cell() -> &'static RwLock<String> {
    CONFIGURED.get_or_init(|| RwLock::new(String::new()))
}

/// Where the database beside the database lives: `geo/country.mmdb` next to
/// `easywaf.db`, with the mirrors, never in `rules/` which packages own.
pub fn stored_path() -> std::path::PathBuf {
    crate::rules_update::cache_dir().with_file_name("geo").join("country.mmdb")
}

/// The copy an update replaced, kept so it can be put back.
pub fn previous_path() -> std::path::PathBuf {
    stored_path().with_extension("mmdb.previous")
}

/// What the loaded database says about itself, for the Updates page.
pub fn status() -> Option<Status> {
    let reader = cell().read().ok()?.clone()?;
    let m = reader.metadata();
    let built = chrono::DateTime::from_timestamp(m.build_epoch as i64, 0);
    let source = source_cell().read().map(|s| *s).unwrap_or(Source::Bundled);

    Some(Status {
        source,
        database_type: m.database_type.clone(),
        built:         built.map(|t| t.format("%Y-%m-%d").to_string()),
        age_days:      built.map(|t| (chrono::Utc::now() - t).num_days()),
        ip_version:    m.ip_version,
        nodes:         m.node_count,
    })
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
    if let Ok(mut c) = configured_cell().write() {
        *c = path.to_string();
    }

    // In order: what config.toml names, then what this installation has been
    // given through the channel or the interface, then the bundled copy.
    // config.toml wins because it is somebody's deliberate local choice, and a
    // file uploaded through a web page must not quietly override it.
    let (reader, source) = if !path.is_empty() {
        match Reader::open_readfile(path) {
            Ok(r) => {
                tracing::info!(path, "GeoIP: loaded the database named in config.toml");
                (Some(r), Source::Configured)
            }
            Err(e) => {
                tracing::warn!(
                    path,
                    "GeoIP: could not load the database named in config.toml ({});                      falling back",
                    e
                );
                (embedded(), Source::Bundled)
            }
        }
    } else {
        let stored = stored_path();
        match Reader::open_readfile(&stored) {
            Ok(r) => {
                tracing::info!(path = %stored.display(), "GeoIP: loaded the stored database");
                // Which of the two put it there is remembered separately; a
                // file on disk cannot say whether it was verified.
                (Some(r), stored_source())
            }
            Err(_) => {
                tracing::info!("GeoIP: using the bundled DB-IP Lite country database");
                (embedded(), Source::Bundled)
            }
        }
    };

    if let Ok(mut slot) = cell().write() {
        *slot = reader.map(Arc::new);
    }
    if let Ok(mut s) = source_cell().write() {
        *s = source;
    }
}

/// How the stored database got there, recorded beside it: one line, `channel`
/// or `uploaded`. A `.mmdb` cannot say whether anybody checked a signature
/// over it, and the page must not guess.
fn stored_source() -> Source {
    match std::fs::read_to_string(stored_path().with_extension("mmdb.source")) {
        Ok(s) if s.trim() == "channel" => Source::Channel,
        Ok(_)  => Source::Uploaded,
        Err(_) => Source::Uploaded,
    }
}

/// Put a database in force, keeping the one it replaces.
///
/// Written beside the database and loaded immediately: the reader is
/// replaceable by design, so a new country database takes effect on the next
/// request rather than at the next restart. Returns what it now says about
/// itself, or why the file was not usable.
pub fn install(bytes: &[u8], source: Source) -> std::result::Result<Status, String> {
    // Parsed before anything is written: a file that is not a database must
    // not replace one that is.
    Reader::from_source(bytes.to_vec())
        .map_err(|e| format!("that file is not a MaxMind-format database: {e}"))?;

    let path = stored_path();
    let dir  = path.parent().ok_or("no directory for the database")?.to_path_buf();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    // Staged and renamed, so an interrupted write cannot leave half a database
    // where a whole one was.
    let staging = path.with_extension("mmdb.new");
    std::fs::write(&staging, bytes).map_err(|e| format!("{}: {e}", staging.display()))?;
    if path.exists() {
        let _ = std::fs::rename(&path, previous_path());
    }
    std::fs::rename(&staging, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    let _ = std::fs::write(path.with_extension("mmdb.source"), source.as_str());

    // config.toml still wins: an installation that names a database means it.
    let configured = configured_cell().read().map(|c| c.clone()).unwrap_or_default();
    init(&configured);

    status().ok_or_else(|| "the database was written but could not be read back".to_string())
}

/// Put back the database an update replaced.
pub fn revert() -> std::result::Result<Status, String> {
    let previous = previous_path();
    let bytes = std::fs::read(&previous)
        .map_err(|_| "there is no earlier database to go back to".to_string())?;
    let source = stored_source();
    let status = install(&bytes, source)?;
    let _ = std::fs::remove_file(previous);
    Ok(status)
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
mod status_tests {
    use super::*;

    #[test]
    fn the_bundled_database_says_what_it_is_and_when_it_was_built() {
        // Everything the Updates page shows about the country database comes
        // from the file itself, and none of it was read before 0.13.1.
        init("");
        let s = status().expect("a database is loaded");
        assert_eq!(s.source, Source::Bundled);
        assert!(s.source.verified(), "the bundled database ships with the binary");
        assert!(s.database_type.to_lowercase().contains("country"),
                "not a country database: {}", s.database_type);
        assert!(s.built.is_some(), "no build date");
        assert!(s.age_days.is_some_and(|d| d >= 0), "built in the future: {:?}", s.built);
        assert!(s.nodes > 0, "an empty database");
    }

    #[test]
    fn a_file_that_is_not_a_database_does_not_replace_one() {
        // Checked before anything is written: the country rules of every
        // policy depend on what is loaded here.
        //
        // Loaded here rather than relying on another test having done it:
        // these share one reader and run in parallel.
        init("");
        let before = status().expect("loaded");
        let err = install(b"not an mmdb at all", Source::Uploaded)
            .expect_err("nonsense was accepted");
        assert!(err.contains("not a MaxMind-format database"), "{err}");
        let after = status().expect("still loaded");
        assert_eq!(before.database_type, after.database_type,
                   "a bad upload replaced the database in force");
    }

    #[test]
    fn where_a_database_came_from_decides_whether_it_was_verified() {
        // Two of the four are checked against a signature this installation
        // holds; two are a file somebody chose. A page that showed the date
        // without the source would imply they are the same kind of fact.
        assert!(Source::Bundled.verified());
        assert!(Source::Channel.verified());
        assert!(!Source::Uploaded.verified());
        assert!(!Source::Configured.verified());
    }
}

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

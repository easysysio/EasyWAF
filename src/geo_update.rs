// =========================================================
// geo_update.rs — EasyWAF
// The country database's signed channel.
//
// geo.rs owns the database in force: loading it, swapping
// it, and saying what it is. This owns getting a newer one
// — the same shape as rules_update and iplist_feeds, and
// deliberately so, because an installation that trusts one
// channel should not have to learn a second set of rules
// for another.
//
// A manifest signed with the key this installation pins, a
// sha256 in it for the database, and the file checked
// against that hash before it replaces anything. The
// publishing side is publish-geo.sh in EasyWAF-rules; it
// refuses to mirror a file that is not a country database
// or is older than the one already published, so a channel
// that has gone wrong upstream usually serves the previous
// month rather than something worse.
//
// Applied as it arrives by default. A country database is
// data, and its failure mode is being stale: a reassignment
// moves a client into a country a policy blocks, and an
// installation working from a database a year old is
// enforcing last year's map. An installation with change
// control turns the switch off, and then a fetch is held
// until somebody applies it.
// =========================================================

use serde::Serialize;
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::time::Duration;

/// Checked on the same schedule as the others. DB-IP builds monthly, so this
/// is far more often than anything changes — which costs one conditional
/// request a day and means a new database is in force within hours of being
/// published rather than whenever somebody next looks.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);

pub const KEY_URL: &str = "geo_url";
/// The version last taken from the channel. What "newer" is measured against,
/// rather than the database in force — which may be one somebody uploaded, or
/// the one `geoip_db` names, neither of which this channel put there.
const KEY_VERSION: &str = "geo_version";
const KEY_FETCHED: &str = "geo_fetched";
const KEY_ERROR:   &str = "geo_error";

pub const DEFAULT_URL: &str = "https://repo.easysys.io/easywaf/geo";

const MANIFEST:  &str = "geo.toml";
const SIGNATURE: &str = "geo.toml.asc";

// ─── Manifest ────────────────────────────────────────────

/// The database as the channel offers it, before anything is fetched.
///
/// Everything here is what the publisher read out of the file itself, so the
/// page can say what is on offer — which database, built when, how big —
/// without pulling eight megabytes to find out.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Offered {
    pub id:            String,
    pub name:          String,
    pub description:   String,
    pub licence:       String,
    pub attribution:   String,
    /// The date the publisher built the database, as `YYYYMMDD`. Not the date
    /// of the publishing run: the build is the fact being decided about.
    pub version:       String,
    pub database_type: String,
    pub built:         String,
    pub ip_version:    u16,
    pub nodes:         u32,
    pub bytes:         i64,
    file:              String,
    sha256:            String,
}

/// Parse the manifest.
///
/// Hand-rolled for the reason the other two are: the manifest is written by
/// another repository on its own schedule, and a key it gains later must not
/// stop an installation reading what it does understand.
pub fn parse_manifest(text: &str) -> Vec<Offered> {
    let mut out = Vec::new();
    for block in text.split("[[databases]]").skip(1) {
        let value = |key: &str| -> Option<String> {
            block.lines().find_map(|line| {
                let rest = line.trim().strip_prefix(key)?.trim_start();
                let v = rest.strip_prefix('=')?;
                Some(v.trim().trim_matches('"').to_string())
            })
        };
        let (Some(id), Some(file), Some(sha256)) = (value("id"), value("file"), value("sha256"))
        else {
            continue;
        };
        if !is_slug(&id) {
            continue;
        }
        out.push(Offered {
            name:          value("name").unwrap_or_else(|| id.clone()),
            description:   value("description").unwrap_or_default(),
            licence:       value("licence").unwrap_or_default(),
            attribution:   value("attribution").unwrap_or_default(),
            version:       value("version").unwrap_or_default(),
            database_type: value("database_type").unwrap_or_default(),
            built:         value("built").unwrap_or_default(),
            ip_version:    value("ip_version").and_then(|v| v.parse().ok()).unwrap_or(0),
            nodes:         value("nodes").and_then(|v| v.parse().ok()).unwrap_or(0),
            bytes:         value("bytes").and_then(|v| v.parse().ok()).unwrap_or(0),
            sha256:        sha256.to_ascii_lowercase(),
            file,
            id,
        });
    }
    out
}

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether a manifest's file path may be appended to the channel URL.
///
/// The manifest is signed, so this is not the line of defence — but a signed
/// manifest naming `../../something` is still not something to follow.
fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn short(digest: &str) -> &str {
    &digest[..12.min(digest.len())]
}

// ─── Held, for an installation that applies by hand ──────

/// Where a fetch waits when this installation applies the country database by
/// hand. Beside the database, never in place of it: what is answering lookups
/// must not change because something was fetched.
fn held_dir() -> PathBuf {
    crate::geo::stored_path().with_file_name("geo-held")
}

/// The database fetched and not applied, if there is one.
pub fn held() -> Option<Offered> {
    let dir = held_dir();
    let text = std::fs::read_to_string(dir.join(MANIFEST)).ok()?;
    parse_manifest(&text).into_iter().next()
}

/// Put a held database in force.
pub fn apply_held() -> Result<crate::geo::Status, String> {
    let dir = held_dir();
    let Some(offered) = held() else {
        return Err("nothing has been fetched that is waiting to be applied".to_string());
    };

    // Read back through the same door it came in by. The manifest is verified
    // again and the file checked against it again, so a held copy that changed
    // on disk between fetching and applying is caught before it serves.
    let manifest = std::fs::read(dir.join(MANIFEST)).map_err(|e| format!("{MANIFEST}: {e}"))?;
    let signature =
        std::fs::read_to_string(dir.join(SIGNATURE)).map_err(|e| format!("{SIGNATURE}: {e}"))?;
    crate::pgp_verify::verify_detached(&crate::rules_update::trusted_key(), &manifest, &signature)?;

    let body = std::fs::read(dir.join(local_name(&offered.id)))
        .map_err(|_| "its file is missing from what was held".to_string())?;
    check_hash(&body, &offered)?;

    let status = crate::geo::install(&body, crate::geo::Source::Channel)?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(status)
}

/// The name a database is stored under: its id, never the path the manifest
/// gives, so nothing a channel says can choose where a file is written.
fn local_name(id: &str) -> String {
    format!("{id}.mmdb")
}

fn check_hash(body: &[u8], offered: &Offered) -> Result<(), String> {
    let digest = sha256_hex(body);
    if digest != offered.sha256 {
        return Err(format!(
            "the database does not match the signed manifest ({} rather than {})",
            short(&digest),
            short(&offered.sha256)
        ));
    }
    Ok(())
}

// ─── Fetching ────────────────────────────────────────────

/// What a check found, so the page can say which of the three it was.
pub enum Fetched {
    /// The channel offers nothing newer than what was last taken from it.
    UpToDate,
    /// Fetched and in force.
    Applied(Box<crate::geo::Status>),
    /// Fetched and waiting, because this installation applies by hand.
    Held(Box<Offered>),
}

/// Fetch the channel, and apply or hold what it offers.
///
/// All or nothing: the manifest is verified and the database checked against
/// it before anything is written, and `geo::install` stages and renames — so a
/// refused or interrupted fetch leaves the database in force exactly as it
/// was, which is the point of a country database being the kind of thing that
/// is merely out of date rather than broken.
pub async fn sync(db: &SqlitePool) -> Result<Fetched, String> {
    let key  = crate::rules_update::trusted_key();
    let base = url(db).await;
    let base = base.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| format!("{e}"))?;
    let fetch = |u: String| {
        let c = client.clone();
        async move {
            let r = c.get(&u).send().await.map_err(|e| format!("{u}: {e}"))?;
            if !r.status().is_success() {
                return Err(format!("{u}: HTTP {}", r.status()));
            }
            r.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("{u}: {e}"))
        }
    };

    let manifest  = fetch(format!("{base}/{MANIFEST}")).await?;
    let signature = fetch(format!("{base}/{SIGNATURE}")).await?;
    let signature =
        String::from_utf8(signature).map_err(|_| "the signature is not text".to_string())?;
    crate::pgp_verify::verify_detached(&key, &manifest, &signature)?;
    let text = String::from_utf8(manifest.clone())
        .map_err(|_| "the manifest is not text".to_string())?;

    let Some(offered) = parse_manifest(&text).into_iter().next() else {
        return Err("the channel's manifest offers no country database".to_string());
    };
    if !safe_relative(&offered.file) {
        return Err(format!("{}: refusing the file path {:?}", offered.id, offered.file));
    }

    // Measured against what this channel last gave, not against what is
    // loaded: an installation may be running a database somebody uploaded, or
    // the one config.toml names, and neither is this channel's to compare
    // with. A version that is not newer is left alone — including one that is
    // older, which would mean the channel had been rolled back, and an
    // installation must not follow a channel backwards.
    let previous = get(db, KEY_VERSION).await.unwrap_or_default();
    if !previous.trim().is_empty() && offered.version.as_str() <= previous.trim() {
        return Ok(Fetched::UpToDate);
    }

    let body = fetch(format!("{base}/{}", offered.file)).await?;
    check_hash(&body, &offered)?;

    set(db, KEY_FETCHED, &chrono::Utc::now().to_rfc3339()).await;

    if crate::routes::updates::auto(db, crate::routes::updates::KEY_AUTO_GEO).await {
        let status = crate::geo::install(&body, crate::geo::Source::Channel)?;
        set(db, KEY_VERSION, &offered.version).await;
        tracing::info!(version = %offered.version, database = %offered.database_type,
                       "Country database updated from the channel");
        return Ok(Fetched::Applied(Box::new(status)));
    }

    let dir = held_dir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(dir.join(local_name(&offered.id)), &body)
        .map_err(|e| format!("{}: {e}", offered.id))?;
    std::fs::write(dir.join(MANIFEST), &manifest).map_err(|e| format!("{MANIFEST}: {e}"))?;
    std::fs::write(dir.join(SIGNATURE), signature.as_bytes())
        .map_err(|e| format!("{SIGNATURE}: {e}"))?;

    // Recorded as taken even though it is not in force. It is on disk and the
    // page offers it; fetching it again every six hours would be eight
    // megabytes an installation already has.
    set(db, KEY_VERSION, &offered.version).await;
    tracing::info!(version = %offered.version,
                   "Fetched the country database and held it — this installation applies it by hand");
    Ok(Fetched::Held(Box::new(offered)))
}

/// Check now, recording what happened for the page.
pub async fn check_now(db: &SqlitePool) -> Result<Fetched, String> {
    let outcome = sync(db).await;
    match &outcome {
        Ok(_)  => set(db, KEY_ERROR, "").await,
        Err(e) => set(db, KEY_ERROR, e).await,
    }
    outcome
}

/// Check at startup and every few hours after.
pub fn spawn_task(db: SqlitePool) {
    tokio::spawn(async move {
        loop {
            // Behind the one switch that says this installation does not reach
            // out at all, and quiet when it fails: an appliance with no
            // outbound access is the ordinary case, and one that logged every
            // six hours about a repository it cannot reach would teach its
            // operator to stop reading the log.
            if crate::rules_update::enabled(&db).await {
                let _ = check_now(&db).await;
                crate::routes::updates::refresh_waiting(&db).await;
            }
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

// ─── Settings ────────────────────────────────────────────

/// Read and write straight through, as `rules_update` does. A settings write
/// that fails must not turn a successful fetch into a failed one: the database
/// is already in force by then, and the only thing lost is the note saying so.
async fn get(db: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar!("SELECT value FROM settings WHERE key = ?", key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

async fn set(db: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query!(
        "INSERT INTO settings (key, value, updated_at)
         VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                        updated_at = excluded.updated_at",
        key, value
    )
    .execute(db)
    .await;
}

// ─── What the page reads ─────────────────────────────────

pub async fn url(db: &SqlitePool) -> String {
    match get(db, KEY_URL).await {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => DEFAULT_URL.to_string(),
    }
}

/// When the channel was last reached, and why it was not.
pub async fn status(db: &SqlitePool) -> (Option<String>, Option<String>) {
    let fetched = get(db, KEY_FETCHED).await.filter(|v| !v.trim().is_empty());
    let error   = get(db, KEY_ERROR).await.filter(|v| !v.trim().is_empty());
    (fetched, error)
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# EasyWAF published country database, generated by publish-geo.sh.

generated = "2026-09-23T11:37:05Z"

[[databases]]
id            = "dbip-country-lite"
name          = "DB-IP Lite country"
description   = "Maps an address to a country."
licence       = "CC BY 4.0"
attribution   = "IP Geolocation by DB-IP"
version       = "20260901"
database_type = "DBIP-Country-Lite"
built         = "2026-09-01"
ip_version    = 6
nodes         = 1355429
bytes         = 8182135
file          = "geo/dbip-country-lite.mmdb"
sha256        = "881E0B274FC0CC801FA7C33687A69810BE605F80593769287CDE10BDB9EE8BDE"
"#;

    #[test]
    fn reads_what_the_channel_offers() {
        let offered = parse_manifest(SAMPLE);
        assert_eq!(offered.len(), 1);
        let d = &offered[0];
        assert_eq!(d.id, "dbip-country-lite");
        assert_eq!(d.version, "20260901");
        assert_eq!(d.database_type, "DBIP-Country-Lite");
        assert_eq!(d.built, "2026-09-01");
        assert_eq!(d.ip_version, 6);
        assert_eq!(d.nodes, 1355429);
        assert_eq!(d.bytes, 8182135);
        // Compared against a hash this computes, so the case it is written in
        // must not decide whether a database verifies.
        assert_eq!(d.sha256, "881e0b274fc0cc801fa7c33687a69810be605f80593769287cde10bdb9ee8bde");
    }

    #[test]
    fn a_key_it_does_not_know_is_not_fatal() {
        // The manifest is written by another repository on its own schedule.
        let text = SAMPLE.replace("[[databases]]",
                                  "[[databases]]\nsomething_added_later = \"whatever\"");
        assert_eq!(parse_manifest(&text).len(), 1);
    }

    #[test]
    fn an_entry_without_a_hash_is_skipped() {
        let text = SAMPLE.lines()
            .filter(|l| !l.trim_start().starts_with("sha256"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_manifest(&text).is_empty());
    }

    #[test]
    fn refuses_a_file_path_that_climbs() {
        assert!(safe_relative("geo/dbip-country-lite.mmdb"));
        assert!(!safe_relative("../../etc/passwd"));
        assert!(!safe_relative("/etc/passwd"));
        assert!(!safe_relative(""));
    }

    #[test]
    fn a_mismatched_database_is_refused_by_hash() {
        let offered = parse_manifest(SAMPLE).remove(0);
        let e = check_hash(b"not the database", &offered).unwrap_err();
        assert!(e.contains("does not match the signed manifest"), "{e}");
        // The message names both, because which one is wrong is the question.
        assert!(e.contains("881e0b274fc0"), "{e}");
    }

    #[test]
    fn an_id_that_is_not_a_slug_names_no_file() {
        let text = SAMPLE.replace(r#"id            = "dbip-country-lite""#,
                                  r#"id            = "../../evil""#);
        assert!(parse_manifest(&text).is_empty());
    }
}

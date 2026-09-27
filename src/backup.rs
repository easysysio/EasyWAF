// =========================================================
// backup.rs — EasyWAF
// Snapshots: the whole database, consistent, while it runs.
//
// A snapshot is the disaster-recovery half of 0.14.0 and is
// deliberately stupid about what it holds. It does not know
// what a site or a rule is, so no later release that adds a
// table has to remember it — it answers "the host is gone"
// and nothing else. The readable export is the other half,
// and is a different file for a different job.
//
// Taken with VACUUM INTO rather than by copying the file. The
// database runs in WAL mode, so committed data can sit in
// easywaf.db-wal rather than the main file, and a copy made
// while the service runs can miss recent writes or tear.
// VACUUM INTO reads through SQLite's own view of the
// database, so it is consistent without stopping anything,
// and it compacts — the snapshot is smaller than the file.
//
// A snapshot holds every private key the appliance serves
// with and every password hash. It is written readable by
// its owner only, and the page that offers it says so.
// =========================================================

use sqlx::SqlitePool;
use std::path::{Path, PathBuf};

/// The settings key a running EasyWAF stamps with its own version on every
/// start, after its migrations. A snapshot therefore says which version last
/// ran it, which is what a restore needs to refuse one from the future.
pub const KEY_WRITTEN_BY: &str = "schema_written_by";

/// The database file, from the URL it was opened with.
pub fn db_path() -> PathBuf {
    let url = crate::config::database_url();
    let path = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .unwrap_or(&url);
    // A query string such as ?mode=rwc is part of the URL, not the file.
    PathBuf::from(path.split('?').next().unwrap_or(path))
}

/// Where snapshots are kept: `backups/` beside the database, with the mirrors,
/// owned by whoever owns the database.
pub fn dir() -> PathBuf {
    db_path().with_file_name("backups")
}

/// A snapshot's file name: when it was taken, in UTC, so a directory listing
/// sorts in the order they were taken.
pub fn file_name(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("easywaf-{}.db", now.format("%Y%m%d-%H%M%S"))
}

/// Take a snapshot into `dest`, which must not exist yet. Returns its size.
pub async fn take(db: &SqlitePool, dest: &Path) -> Result<u64, String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    sqlx::query("VACUUM INTO ?")
        .bind(dest.to_string_lossy().to_string())
        .execute(db)
        .await
        .map_err(|e| format!("the snapshot could not be taken: {e}"))?;

    owner_only(dest);
    std::fs::metadata(dest)
        .map(|m| m.len())
        .map_err(|e| format!("{}: {e}", dest.display()))
}

/// Readable and writable by the owner alone. Every private key the appliance
/// serves with is in this file.
fn owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Record which version this database was last run by. Called at startup,
/// after the migrations have brought the schema up to this version's.
pub async fn stamp(db: &SqlitePool) {
    let _ = sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(KEY_WRITTEN_BY)
    .bind(env!("CARGO_PKG_VERSION"))
    .execute(db)
    .await;
}

// ─── Scheduled snapshots ─────────────────────────────────

/// Whether EasyWAF takes a snapshot of its own every day. Off unless an
/// administrator turns it on.
pub const KEY_SCHEDULED: &str = "backup_scheduled";
/// How many scheduled snapshots are kept.
pub const KEY_KEEP: &str = "backup_keep";
pub const DEFAULT_KEEP: usize = 7;
const KEY_LAST:  &str = "backup_last";
const KEY_ERROR: &str = "backup_error";

/// Looked at hourly, and a snapshot taken when the newest is more than a day
/// old — rather than sleeping a day between them, which every restart would
/// reset. An appliance restarted daily would otherwise never take one.
const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);
const EVERY: chrono::Duration = chrono::Duration::hours(24);

/// One snapshot on disk, as the page lists it.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct Stored {
    pub name:  String,
    pub bytes: u64,
    /// When it was taken, UTC, from its name — which is what the scheduler
    /// wrote, and survives a copy that changes the file's own dates.
    pub taken: String,
}

/// Whether a name is one this module wrote. The only files it will ever list,
/// hand to a browser or delete: the directory may hold other things — an
/// operator's own copies, a restore being staged — and none of them are this
/// code's to prune. It is also what keeps a name from a URL from naming a
/// path somewhere else.
pub fn is_snapshot_name(name: &str) -> bool {
    name.len() == "easywaf-20260927-080509.db".len()
        && name.starts_with("easywaf-")
        && name.ends_with(".db")
        && name.as_bytes()[16] == b'-'
        && name[8..16].bytes().all(|b| b.is_ascii_digit())
        && name[17..23].bytes().all(|b| b.is_ascii_digit())
}

fn taken_from_name(name: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(&name[8..23], "%Y%m%d-%H%M%S").ok()
}

/// The snapshots in `dir`, newest first.
pub fn list_in(dir: &Path) -> Vec<Stored> {
    let mut out: Vec<Stored> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !is_snapshot_name(&name) {
                return None;
            }
            let taken = taken_from_name(&name)?;
            Some(Stored {
                bytes: e.metadata().map(|m| m.len()).unwrap_or(0),
                taken: taken.format("%Y-%m-%d %H:%M:%S").to_string(),
                name,
            })
        })
        .collect();
    out.sort_by(|a, b| b.name.cmp(&a.name));
    out
}

pub fn list() -> Vec<Stored> {
    list_in(&dir())
}

/// Delete all but the newest `keep` snapshots in `dir`. Returns how many went.
pub fn prune_in(dir: &Path, keep: usize) -> usize {
    let mut removed = 0;
    for old in list_in(dir).into_iter().skip(keep.max(1)) {
        if std::fs::remove_file(dir.join(&old.name)).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Whether a snapshot is due: none yet, or the newest older than a day.
pub fn due_in(dir: &Path, now: chrono::NaiveDateTime) -> bool {
    match list_in(dir).first().and_then(|s| taken_from_name(&s.name)) {
        Some(newest) => now - newest >= EVERY,
        None => true,
    }
}

/// Take a scheduled snapshot now, and prune to the number kept.
pub async fn take_scheduled(db: &SqlitePool) -> Result<Stored, String> {
    let d = dir();
    std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    // The directory as well as each file: a listing of it names what exists.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    let name = file_name(chrono::Utc::now());
    let bytes = take(db, &d.join(&name)).await?;
    let removed = prune_in(&d, keep(db).await);
    tracing::info!(file = %name, bytes, removed, "Scheduled snapshot taken");
    let taken = taken_from_name(&name)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default();
    Ok(Stored { name, bytes, taken })
}

pub async fn scheduled(db: &SqlitePool) -> bool {
    setting(db, KEY_SCHEDULED).await.as_deref() == Some("1")
}

pub async fn keep(db: &SqlitePool) -> usize {
    setting(db, KEY_KEEP).await
        .and_then(|v| v.trim().parse().ok())
        .filter(|n: &usize| (1..=365).contains(n))
        .unwrap_or(DEFAULT_KEEP)
}

/// When the last scheduled snapshot was taken, and why the last one failed.
pub async fn status(db: &SqlitePool) -> (Option<String>, Option<String>) {
    (
        setting(db, KEY_LAST).await.filter(|v| !v.is_empty()),
        setting(db, KEY_ERROR).await.filter(|v| !v.is_empty()),
    )
}

/// Look hourly; take one when due.
pub fn spawn_schedule(db: SqlitePool) {
    tokio::spawn(async move {
        loop {
            if scheduled(&db).await && due_in(&dir(), chrono::Utc::now().naive_utc()) {
                match take_scheduled(&db).await {
                    Ok(s) => {
                        put(&db, KEY_LAST, &s.taken).await;
                        put(&db, KEY_ERROR, "").await;
                    }
                    // Recorded for the page and logged once per attempt. A
                    // full disk is the usual cause, and it is exactly what an
                    // operator needs to hear about before the host is lost.
                    Err(e) => {
                        tracing::warn!("Scheduled snapshot failed: {e}");
                        put(&db, KEY_ERROR, &e).await;
                    }
                }
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

async fn setting(db: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

async fn put(db: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .execute(db)
    .await;
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_is_named_for_when_it_was_taken() {
        let t = chrono::DateTime::parse_from_rfc3339("2026-09-27T08:05:09Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(file_name(t), "easywaf-20260927-080509.db");
    }

    #[test]
    fn only_names_this_module_wrote_are_snapshots() {
        assert!(is_snapshot_name("easywaf-20260927-080509.db"));
        for other in ["easywaf.db", "easywaf-2026-09-27.db", "../easywaf-20260927-080509.db",
                      "easywaf-20260927-080509.db.restore", "notes.txt",
                      ".download-easywaf-20260927-080509.db", "easywaf-2026092x-080509.db"] {
            assert!(!is_snapshot_name(other), "{other} was taken for a snapshot");
        }
    }

    #[test]
    fn pruning_keeps_the_newest_and_touches_nothing_else() {
        let d = std::env::temp_dir().join(format!("easywaf-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for day in 20..=26 {
            std::fs::write(d.join(format!("easywaf-202609{day}-030000.db")), b"x").unwrap();
        }
        // Somebody's own file, and a restore being staged: not ours.
        std::fs::write(d.join("my-copy.db"), b"x").unwrap();
        std::fs::write(d.join("easywaf.db.restore"), b"x").unwrap();

        assert_eq!(prune_in(&d, 3), 4);
        let left: Vec<String> = list_in(&d).into_iter().map(|s| s.name).collect();
        assert_eq!(left, ["easywaf-20260926-030000.db", "easywaf-20260925-030000.db",
                          "easywaf-20260924-030000.db"], "not the newest three, newest first");
        assert!(d.join("my-copy.db").exists(), "pruning deleted a file it did not write");
        assert!(d.join("easywaf.db.restore").exists(), "pruning deleted a staged restore");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn one_is_due_a_day_after_the_last_and_not_before() {
        let d = std::env::temp_dir().join(format!("easywaf-due-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let at = |s: &str| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap();

        assert!(due_in(&d, at("2026-09-27 03:00")), "nothing taken yet, and nothing due");
        std::fs::write(d.join("easywaf-20260927-030000.db"), b"x").unwrap();
        assert!(!due_in(&d, at("2026-09-27 04:00")), "due again an hour later");
        assert!(!due_in(&d, at("2026-09-28 02:59")), "due before a day had passed");
        assert!(due_in(&d, at("2026-09-28 03:00")), "not due a day later");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The whole point: consistent while the database is open and being
    /// written, including what is still in the write-ahead log.
    #[tokio::test]
    async fn a_snapshot_holds_what_the_log_has_not_checkpointed() {
        let base = std::env::temp_dir().join(format!("easywaf-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let live = base.join("easywaf.db");
        let db = crate::db::init(&format!("sqlite://{}", live.display())).await;

        // Written and committed, and left in the log: no checkpoint is forced.
        sqlx::query("INSERT INTO policies (name) VALUES ('only-in-the-log')")
            .execute(&db).await.unwrap();

        let snap = base.join("snap.db");
        let size = take(&db, &snap).await.expect("snapshot");
        assert!(size > 0);

        let copy = sqlx::SqlitePool::connect(&format!("sqlite://{}", snap.display()))
            .await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE name = 'only-in-the-log'")
            .fetch_one(&copy).await.unwrap();
        assert_eq!(n, 1, "the snapshot lost a committed write that was still in the WAL");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&snap).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "a snapshot holding private keys is readable by others");
        }

        // A destination that exists is refused rather than overwritten.
        assert!(take(&db, &snap).await.is_err(), "an existing snapshot was overwritten");

        copy.close().await;
        db.close().await;
        let _ = std::fs::remove_dir_all(&base);
    }
}

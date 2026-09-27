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

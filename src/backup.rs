// =========================================================
// backup.rs — EasyWAF
// Snapshots: the whole database, consistent, while it runs.
//
// A snapshot is the disaster-recovery half of backup, and
// is deliberately stupid about what it holds. It does not know
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
    crate::settings::record(db, KEY_WRITTEN_BY, env!("CARGO_PKG_VERSION")).await;
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
    crate::settings::get(db, KEY_SCHEDULED).await.as_deref() == Some("1")
}

pub async fn keep(db: &SqlitePool) -> usize {
    crate::settings::get(db, KEY_KEEP).await
        .and_then(|v| v.trim().parse().ok())
        .filter(|n: &usize| (1..=365).contains(n))
        .unwrap_or(DEFAULT_KEEP)
}

/// When the last scheduled snapshot was taken, and why the last one failed.
pub async fn status(db: &SqlitePool) -> (Option<String>, Option<String>) {
    (
        crate::settings::get(db, KEY_LAST).await.filter(|v| !v.is_empty()),
        crate::settings::get(db, KEY_ERROR).await.filter(|v| !v.is_empty()),
    )
}

/// Look hourly; take one when due.
pub fn spawn_schedule(db: SqlitePool) {
    tokio::spawn(async move {
        loop {
            if scheduled(&db).await && due_in(&dir(), chrono::Utc::now().naive_utc()) {
                match take_scheduled(&db).await {
                    Ok(s) => {
                        crate::settings::record(&db, KEY_LAST, &s.taken).await;
                        crate::settings::record(&db, KEY_ERROR, "").await;
                    }
                    // Recorded for the page and logged once per attempt. A
                    // full disk is the usual cause, and it is exactly what an
                    // operator needs to hear about before the host is lost.
                    Err(e) => {
                        tracing::warn!("Scheduled snapshot failed: {e}");
                        crate::settings::record(&db, KEY_ERROR, &e).await;
                    }
                }
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

// ─── Restore ─────────────────────────────────────────────
//
// A snapshot replaces the whole database, so it cannot be applied under a
// running process: every pool, cache and listener holds the old one. It is
// validated while EasyWAF runs, staged beside the database, and swapped in by
// the next start before anything opens it. EasyWAF stops itself to get there,
// with an exit code systemd's Restart=on-failure answers.
//
// The order of that swap is the whole design, because a power cut can land
// between any two steps and the database it replaces must survive every one:
//
//   1. The current database is snapshotted to <db>.before-restore — a copy,
//      renamed into place whole, so it is either absent or complete.
//   2. A marker is written. From here the next start knows a swap began.
//   3. The staged file is renamed over the database, in one atomic step.
//   4. The service opens it and runs its migrations. Only when that succeeds
//      is the marker removed.
//
// A start that finds the marker and no staged file knows the restored
// database was swapped in and never came up — its migrations failed, or it
// would not open — and puts <db>.before-restore back. That is the case the
// design note warns about: a restore that half-works looks like success on a
// security appliance, and this one either works or undoes itself.

/// What the last restore did, for the page: "ok" or "failed", a sentence, and
/// when. Written by the start that applied or undid it.
pub const KEY_RESTORE_OUTCOME: &str = "restore_outcome";
pub const KEY_RESTORE_MESSAGE: &str = "restore_message";
pub const KEY_RESTORE_AT:      &str = "restore_at";

/// Exit code for "stopped to apply a restore". Not zero, so systemd's
/// Restart=on-failure brings the service back; not the 1 a real failure exits
/// with, so the journal says which it was.
pub const RESTART_CODE: i32 = 75;

static RESTART: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();

fn restart_cell() -> &'static tokio::sync::Notify {
    RESTART.get_or_init(tokio::sync::Notify::new)
}

/// Ask the process to stop so a staged restore can be applied.
pub fn request_restart() {
    restart_cell().notify_one();
}

/// Resolves when a restart has been asked for.
pub async fn restart_requested() {
    restart_cell().notified().await;
}

fn sibling(suffix: &str) -> PathBuf {
    let db = db_path();
    let mut name = db.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(suffix);
    db.with_file_name(name)
}

/// A snapshot waiting for the next start to swap it in.
pub fn staged_path() -> PathBuf { sibling(".restore") }
/// The database the last restore replaced. One generation, like the country
/// database's previous copy: the way back from the restore just made.
pub fn before_path() -> PathBuf { sibling(".before-restore") }
fn marker_path()  -> PathBuf { sibling(".restore-pending") }
/// What is being swapped in, when it is not a snapshot: the name of the thing
/// on the first line ("The import"), and on the rest the sentence to show
/// when it has worked. Written by whoever stages the database.
fn reason_path()  -> PathBuf { sibling(".restore-reason") }

/// Say what a staged database is, for the messages after the restart.
pub fn set_reason(subject: &str, success: &str) -> Result<(), String> {
    std::fs::write(reason_path(), format!("{subject}\n{success}"))
        .map_err(|e| format!("the import could not be staged: {e}"))
}
fn outcome_path() -> PathBuf { sibling(".restore-outcome") }
/// An upload checked and held for an administrator to look at before it is
/// staged. A dot-name in the backups directory, so nothing lists or prunes it.
pub fn candidate_path() -> PathBuf { dir().join(".restore-candidate.db") }

/// What a snapshot holds, for the page that asks whether to restore it.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct Contents {
    /// The version that last ran it, or None for one older than 0.14.0,
    /// which is when versions started being recorded.
    pub written_by: Option<String>,
    pub sites:      i64,
    pub policies:   i64,
    pub accounts:   i64,
    pub rules:      i64,
    pub certs:      i64,
    pub traffic:    i64,
    /// The newest traffic it recorded, UTC — the nearest thing a snapshot has
    /// to a date, and usually enough to tell which file this is.
    pub newest_traffic: Option<String>,
}

/// Parse "0.14.0" for comparison. Anything else is not a version.
pub(crate) fn version(v: &str) -> Option<(u32, u32, u32)> {
    let mut it = v.trim().split('.').map(|p| p.parse::<u32>().ok());
    let t = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(t)
}

/// Check that a file is an EasyWAF database this version can run, and say
/// what is in it. Nothing is written; the file is opened read-only.
pub async fn inspect(path: &Path) -> Result<Contents, String> {
    // The header first: a file that is not SQLite is refused by name rather
    // than by whatever the driver makes of it.
    let mut head = [0u8; 16];
    {
        use std::io::Read;
        let mut f = std::fs::File::open(path).map_err(|e| format!("cannot read it: {e}"))?;
        f.read_exact(&mut head).map_err(|_| "it is too short to be a database".to_string())?;
    }
    if &head != b"SQLite format 3\0" {
        return Err("it is not a SQLite database — a snapshot is the .db file Download gives".into());
    }

    // Immutable as well as read-only: a snapshot taken in WAL mode would
    // otherwise want a -shm file created beside it, which is a write.
    let url = format!("sqlite://{}?mode=ro&immutable=1", path.display());
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .map_err(|e| format!("it would not open: {e}"))?;

    let result = inspect_open(&db).await;
    db.close().await;
    result
}

async fn inspect_open(db: &SqlitePool) -> Result<Contents, String> {
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(db).await
        .map_err(|e| format!("it could not be checked: {e}"))?;
    if integrity != "ok" {
        return Err(format!("it is damaged — SQLite's own check says: {integrity}"));
    }

    // The tables every EasyWAF database has had since there were sites and
    // accounts. A SQLite file without them is somebody else's database.
    for table in ["sites", "policies", "users", "settings", "waf_rules", "certs"] {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(table).fetch_one(db).await.unwrap_or(0);
        if n == 0 {
            return Err(format!("it is not an EasyWAF database — it has no {table} table"));
        }
    }

    let written_by = crate::settings::get(db, KEY_WRITTEN_BY).await;

    // A newer EasyWAF may have tables and columns this one has never heard
    // of, and would run with them quietly ignored. Refused, with the fix.
    if let Some(w) = &written_by {
        let here = env!("CARGO_PKG_VERSION");
        match (version(w), version(here)) {
            (Some(theirs), Some(ours)) if theirs > ours => return Err(format!(
                "it was last run by EasyWAF {w}, which is newer than this {here}. \
                 Upgrade this installation to {w} or later first, then restore it")),
            (None, _) => return Err(format!(
                "it records a version this EasyWAF cannot read ({w:?})")),
            _ => {}
        }
    }

    let count = |table: &'static str| async move {
        sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(db).await.unwrap_or(0)
    };
    let traffic_table: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'traffic_events'")
        .fetch_one(db).await.unwrap_or(0);

    Ok(Contents {
        written_by,
        sites:    count("sites").await,
        policies: count("policies").await,
        accounts: count("users").await,
        rules:    count("waf_rules").await,
        certs:    count("certs").await,
        traffic:  if traffic_table > 0 { count("traffic_events").await } else { 0 },
        newest_traffic: if traffic_table > 0 {
            sqlx::query_scalar("SELECT MAX(timestamp) FROM traffic_events")
                .fetch_one(db).await.ok().flatten()
        } else { None },
    })
}

/// Move a checked candidate to where the next start will find it.
pub fn stage(candidate: &Path) -> Result<(), String> {
    std::fs::rename(candidate, staged_path())
        .map_err(|e| format!("the snapshot could not be staged: {e}"))
}

/// Called at startup, before the database is opened. Swaps a staged restore
/// in, or undoes one that did not come up. Returns nothing: what happened is
/// left in the outcome file for [`finish_restore`] to record once the database
/// is open.
pub async fn apply_staged_restore() {
    apply_staged_restore_at(&db_path()).await
}

async fn apply_staged_restore_at(db: &Path) {
    let with = |suffix: &str| {
        let mut n = db.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        n.push(suffix);
        db.with_file_name(n)
    };
    let (staged, before, marker, outcome) =
        (with(".restore"), with(".before-restore"), with(".restore-pending"), with(".restore-outcome"));
    let (wal, shm) = (with("-wal"), with("-shm"));

    // A swap began and never finished starting: the restored database is the
    // one that failed. Put back what it replaced.
    if marker.exists() && !staged.exists() {
        if before.exists() {
            let _ = std::fs::remove_file(&wal);
            let _ = std::fs::remove_file(&shm);
            match std::fs::rename(&before, db) {
                Ok(()) => {
                    let subject = std::fs::read_to_string(with(".restore-reason")).ok()
                        .and_then(|t| t.lines().next().map(str::to_string))
                        .unwrap_or_else(|| "The restored snapshot".to_string());
                    let _ = std::fs::remove_file(with(".restore-reason"));
                    tracing::error!("{subject} did not start. The database it replaced has been put back");
                    let _ = std::fs::write(&outcome, format!(
                        "failed\n{subject} did not start — it would not open, or this version could not bring its schema up to date. The database it replaced has been put back, unchanged."));
                }
                Err(e) => tracing::error!("The restored database did not start, and the one it replaced could not be put back: {e}"),
            }
        }
        let _ = std::fs::remove_file(&marker);
        return;
    }

    if !staged.exists() {
        return;
    }

    // 1. The current database, copied whole to before-restore — unless an
    //    interrupted swap already did that, in which case the marker says so
    //    and the copy is the one to keep.
    if !marker.exists() {
        if db.exists() {
            let tmp = with(".before-restore.tmp");
            let _ = std::fs::remove_file(&tmp);
            let url = format!("sqlite://{}", db.display());
            match sqlx::SqlitePool::connect(&url).await {
                Ok(current) => {
                    let taken = take(&current, &tmp).await;
                    current.close().await;
                    if let Err(e) = taken.and_then(|_| std::fs::rename(&tmp, &before)
                        .map_err(|e| e.to_string()))
                    {
                        // Without a way back there is no restore. The staged
                        // file stays for another attempt; nothing else moves.
                        tracing::error!("Restore not applied: the current database could not be kept first ({e})");
                        let _ = std::fs::write(&outcome, format!(
                            "failed\nNot applied: the current database could not be kept first, so there would have been no way back ({e}). Nothing was changed."));
                        let _ = std::fs::remove_file(&staged);
                        return;
                    }
                }
                Err(e) => {
                    tracing::error!("Restore not applied: the current database would not open ({e})");
                    let _ = std::fs::write(&outcome, format!(
                        "failed\nNot applied: the current database would not open to be kept first ({e}). Nothing was changed."));
                    let _ = std::fs::remove_file(&staged);
                    return;
                }
            }
        }
        // 2. From here a start knows a swap began. It also carries the version
        //    the snapshot was last run by: the start about to open it stamps
        //    its own version over that, and the message afterwards should say
        //    where the database came from.
        let from = match inspect(&staged).await {
            Ok(c)  => c.written_by.unwrap_or_default(),
            Err(_) => String::new(),
        };
        if std::fs::write(&marker, format!("swapping\n{from}\n")).is_err() {
            tracing::error!("Restore not applied: its marker could not be written");
            return;
        }
    }

    // 3. The log and shared memory belong to the database being replaced; the
    //    copy in step 1 read through them, so nothing in them is lost.
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&shm);
    match std::fs::rename(&staged, db) {
        Ok(()) => tracing::info!("Restore swapped in; opening it"),
        Err(e) => {
            tracing::error!("Restore not applied: the snapshot could not be moved into place ({e})");
            let _ = std::fs::write(&outcome, format!(
                "failed\nNot applied: the snapshot could not be moved into place ({e}). The database was not changed."));
            let _ = std::fs::remove_file(&marker);
        }
    }
}

/// Called once the database has opened and migrated. A marker still present
/// means this start is the one that brought a restore up: it succeeded.
pub async fn finish_restore(db: &SqlitePool) {
    let marker = marker_path();
    if marker.exists() {
        let from = std::fs::read_to_string(&marker).ok()
            .and_then(|t| t.lines().nth(1).map(str::trim).map(str::to_string))
            .filter(|v| !v.is_empty());
        let _ = std::fs::remove_file(&marker);
        let reason = std::fs::read_to_string(reason_path()).ok();
        let _ = std::fs::remove_file(reason_path());
        let message = match reason.as_deref().and_then(|t| t.split_once('\n')) {
            Some((_, success)) => format!("{} The database it replaced is kept and can be downloaded below.",
                                          success.trim()),
            None => format!(
                "Restored from a snapshot{}. The database it replaced is kept beside it and can be downloaded below.",
                from.map(|v| format!(" last run by EasyWAF {v}")).unwrap_or_default()),
        };
        let _ = std::fs::write(outcome_path(), format!("ok\n{message}"));
        tracing::info!("Restore complete");
    }
    // Recorded into the (possibly new) database for the page, then removed:
    // the file is how one start tells the next what happened.
    if let Ok(text) = std::fs::read_to_string(outcome_path()) {
        let (status, msg) = text.split_once('\n').unwrap_or((text.as_str(), ""));
        crate::settings::record(db, KEY_RESTORE_OUTCOME, status.trim()).await;
        crate::settings::record(db, KEY_RESTORE_MESSAGE, msg.trim()).await;
        crate::settings::record(db, KEY_RESTORE_AT, &chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()).await;
        let _ = std::fs::remove_file(outcome_path());
    }
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

    /// A fresh EasyWAF database with one named policy, and its path.
    async fn estate(dir: &Path, name: &str, policy: &str) -> PathBuf {
        let path = dir.join(name);
        let db = crate::db::init(&format!("sqlite://{}", path.display())).await;
        sqlx::query("INSERT INTO policies (name) VALUES (?)").bind(policy)
            .execute(&db).await.unwrap();
        sqlx::raw_sql("PRAGMA wal_checkpoint(TRUNCATE)").execute(&db).await.unwrap();
        db.close().await;
        path
    }

    async fn policies_in(path: &Path) -> Vec<String> {
        let db = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display())).await.unwrap();
        let v = sqlx::query_scalar("SELECT name FROM policies ORDER BY name")
            .fetch_all(&db).await.unwrap();
        db.close().await;
        v
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("easywaf-restore-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn only_an_easywaf_database_this_version_can_run_is_accepted() {
        let d = scratch("inspect");

        let good = estate(&d, "good.db", "websites").await;
        let c = inspect(&good).await.expect("a real snapshot was refused");
        assert_eq!(c.policies, 1);
        assert_eq!(c.written_by.as_deref(), Some(env!("CARGO_PKG_VERSION")));

        std::fs::write(d.join("text.db"), b"this is not a database at all").unwrap();
        let e = inspect(&d.join("text.db")).await.unwrap_err();
        assert!(e.contains("not a SQLite database"), "{e}");

        // SQLite, but somebody else's.
        let other = d.join("other.db");
        let o = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rwc", other.display())).await.unwrap();
        sqlx::raw_sql("CREATE TABLE notes (t TEXT)").execute(&o).await.unwrap();
        o.close().await;
        let e = inspect(&other).await.unwrap_err();
        assert!(e.contains("not an EasyWAF database"), "{e}");

        // From a newer EasyWAF: refused, and told what to do about it.
        let future = estate(&d, "future.db", "websites").await;
        let f = sqlx::SqlitePool::connect(&format!("sqlite://{}", future.display())).await.unwrap();
        sqlx::query("UPDATE settings SET value = '99.0.0' WHERE key = ?").bind(KEY_WRITTEN_BY)
            .execute(&f).await.unwrap();
        sqlx::raw_sql("PRAGMA wal_checkpoint(TRUNCATE)").execute(&f).await.unwrap();
        f.close().await;
        let e = inspect(&future).await.unwrap_err();
        assert!(e.contains("99.0.0") && e.contains("Upgrade"), "{e}");

        // From before versions were recorded: accepted — it is older by definition.
        let old = estate(&d, "old.db", "websites").await;
        let o = sqlx::SqlitePool::connect(&format!("sqlite://{}", old.display())).await.unwrap();
        sqlx::query("DELETE FROM settings WHERE key = ?").bind(KEY_WRITTEN_BY)
            .execute(&o).await.unwrap();
        sqlx::raw_sql("PRAGMA wal_checkpoint(TRUNCATE)").execute(&o).await.unwrap();
        o.close().await;
        assert!(inspect(&old).await.unwrap().written_by.is_none());

        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_staged_restore_is_swapped_in_and_the_old_database_kept() {
        let d = scratch("swap");
        let live = estate(&d, "easywaf.db", "the-old-one").await;
        let snap = estate(&d, "snap.db", "the-restored-one").await;
        std::fs::rename(&snap, d.join("easywaf.db.restore")).unwrap();

        apply_staged_restore_at(&live).await;

        assert_eq!(policies_in(&live).await, ["the-restored-one"], "the snapshot was not swapped in");
        assert_eq!(policies_in(&d.join("easywaf.db.before-restore")).await, ["the-old-one"],
                   "the database it replaced was not kept");
        assert!(!d.join("easywaf.db.restore").exists(), "the staged file was left behind");
        assert!(d.join("easywaf.db.restore-pending").exists(),
                "no marker, so a restore that fails to start could not be undone");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_restore_that_never_came_up_is_undone_at_the_next_start() {
        let d = scratch("undo");
        let live = estate(&d, "easywaf.db", "the-old-one").await;
        let snap = estate(&d, "snap.db", "the-broken-one").await;
        std::fs::rename(&snap, d.join("easywaf.db.restore")).unwrap();
        apply_staged_restore_at(&live).await;

        // The start that opened it died before clearing the marker. The next:
        apply_staged_restore_at(&live).await;

        assert_eq!(policies_in(&live).await, ["the-old-one"], "the failed restore was left in place");
        assert!(!d.join("easywaf.db.restore-pending").exists());
        let outcome = std::fs::read_to_string(d.join("easywaf.db.restore-outcome")).unwrap();
        assert!(outcome.starts_with("failed") && outcome.contains("put back"), "{outcome}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Power lost after the old database was kept and the marker written, but
    /// before the snapshot moved: the next start finishes the job without
    /// copying over the kept database — which would now be copying itself.
    #[tokio::test]
    async fn an_interrupted_swap_is_finished_not_restarted() {
        let d = scratch("interrupted");
        let live = estate(&d, "easywaf.db", "the-old-one").await;
        let kept = estate(&d, "kept.db", "the-old-one").await;
        std::fs::rename(&kept, d.join("easywaf.db.before-restore")).unwrap();
        std::fs::write(d.join("easywaf.db.restore-pending"), "swapping\n0.14.0\n").unwrap();
        let snap = estate(&d, "snap.db", "the-restored-one").await;
        std::fs::rename(&snap, d.join("easywaf.db.restore")).unwrap();

        apply_staged_restore_at(&live).await;

        assert_eq!(policies_in(&live).await, ["the-restored-one"]);
        assert_eq!(policies_in(&d.join("easywaf.db.before-restore")).await, ["the-old-one"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn versions_compare_as_numbers_not_text() {
        assert!(version("0.14.0").unwrap() > version("0.9.3").unwrap(),
                "0.14 sorted below 0.9 — which is what comparing them as text does");
        assert!(version("1.0.0").unwrap() > version("0.99.99").unwrap());
        assert_eq!(version("0.14"), None);
        assert_eq!(version("0.14.0.1"), None);
        assert_eq!(version("banana"), None);
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

// =========================================================
// routes/backup.rs — EasyWAF
// Settings → Backup: snapshots, restore, export and import.
//
// Administrator-only, every handler, including the page:
// what it offers is either the whole database — every key
// and password hash — or the power to replace it.
// =========================================================

use crate::routes::flash_redirect;
use crate::{auth::Admin, error::Result, AppState};
use axum::{
    body::Body,
    extract::{Query, State},
    http::header,
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;
use tera::Context;

/// The flash a write leaves behind.
#[derive(Debug, Deserialize)]
pub struct BackupQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

// ─── get_backup ──────────────────────────────────────────

/// GET /backup
pub async fn get_backup(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Admin(session): Admin,
    Query(q): Query<BackupQuery>,
) -> Result<Response> {
    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",  "Backup");
    ctx.insert("url",    "/backup");
    ctx.insert("result", &q.result.unwrap_or_default());
    ctx.insert("msg",    &q.msg.unwrap_or_default());

    // The size of what a snapshot will be, near enough, so nobody is surprised
    // by a download that carries months of traffic history.
    let db_bytes = std::fs::metadata(crate::backup::db_path()).map(|m| m.len()).unwrap_or(0);
    ctx.insert("db_size", &human_size(db_bytes));

    Ok((jar, Html(state.tera.render("backup.html", &ctx)?)).into_response())
}

// ─── post_snapshot ───────────────────────────────────────

/// POST /backup/snapshot — take a snapshot and hand it to the browser.
///
/// A POST, though it changes nothing: a GET that produces a file holding every
/// private key would be one a link or a prefetch could fetch, and a POST is
/// also what puts it in the audit log without a line of code here.
pub async fn post_snapshot(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
) -> Result<Response> {
    let name = crate::backup::file_name(chrono::Utc::now());
    // Taken into the backups directory under a dot-name, so a listing of
    // scheduled snapshots never shows a download that is half written.
    let tmp = crate::backup::dir().join(format!(".download-{name}"));
    let _ = std::fs::remove_file(&tmp);

    let size = match crate::backup::take(&state.db, &tmp).await {
        Ok(n)  => n,
        Err(e) => return flash_redirect("/backup", "failed", &e),
    };

    let file = match tokio::fs::File::open(&tmp).await {
        Ok(f)  => f,
        Err(e) => return flash_redirect("/backup", "failed",
                      &format!("The snapshot was taken but could not be read: {e}")),
    };
    // Unlinked while open, so the bytes are gone from disk the moment the
    // download finishes — or is abandoned — with nothing left to clean up.
    // A downloaded snapshot is the browser's copy; keeping a second one here
    // is the scheduled snapshots' job, and only when somebody asked for them.
    let _ = std::fs::remove_file(&tmp);

    tracing::info!(by = %session.username, bytes = size, file = %name, "Snapshot downloaded");

    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file));
    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.sqlite3".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
            (header::CONTENT_LENGTH, size.to_string()),
            // Never kept by a proxy or the browser's cache: it is a secret.
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response())
}

/// "8.2 MB", for a page saying roughly how large something is.
pub(crate) fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["bytes", "KB", "MB", "GB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} bytes") } else { format!("{v:.1} {}", UNITS[u]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_as_a_person_would_say_them() {
        assert_eq!(human_size(512), "512 bytes");
        assert_eq!(human_size(8_182_135), "7.8 MB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}

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
    extract::{Path, Query, State},
    http::header,
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;
use std::collections::HashMap;
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

    // ── Scheduled snapshots ──
    let stored = crate::backup::list();
    let stored_total: u64 = stored.iter().map(|s| s.bytes).sum();
    let (last, error) = crate::backup::status(&state.db).await;
    ctx.insert("scheduled",     &crate::backup::scheduled(&state.db).await);
    ctx.insert("keep",          &crate::backup::keep(&state.db).await);
    ctx.insert("stored",        &stored.iter().map(|s| serde_json::json!({
        "name": s.name, "taken": s.taken, "size": human_size(s.bytes),
    })).collect::<Vec<_>>());
    ctx.insert("stored_total",  &human_size(stored_total));
    ctx.insert("backup_dir",    &crate::backup::dir().display().to_string());
    ctx.insert("backup_last",   &last.unwrap_or_default());
    ctx.insert("backup_error",  &error.unwrap_or_default());

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

// ─── post_schedule ───────────────────────────────────────

/// POST /backup/schedule — whether EasyWAF takes one daily, and how many it keeps.
pub async fn post_schedule(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(_session): Admin,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response> {
    let keep = match form.get("keep").map(|v| v.trim().parse::<usize>()) {
        Some(Ok(n)) if (1..=365).contains(&n) => n,
        _ => return flash_redirect("/backup", "failed",
                 "Keep between 1 and 365 snapshots"),
    };
    let on = form.contains_key("scheduled");
    crate::routes::settings::set_setting(
        &state.db, crate::backup::KEY_SCHEDULED, if on { "1" } else { "0" }).await?;
    crate::routes::settings::set_setting(
        &state.db, crate::backup::KEY_KEEP, &keep.to_string()).await?;

    // Lowering the number kept takes effect now, not at the next snapshot, so
    // the page afterwards shows what the setting says.
    let removed = crate::backup::prune_in(&crate::backup::dir(), keep);

    let msg = if on {
        format!("Saved. A snapshot is taken daily and the newest {keep} are kept{}",
                if removed > 0 { format!(" — {removed} older one(s) removed") } else { String::new() })
    } else {
        "Saved. No snapshots are taken on a schedule; the ones already here are kept".to_string()
    };
    flash_redirect("/backup", "success", &msg)
}

// ─── post_take ───────────────────────────────────────────

/// POST /backup/take — take a scheduled-style snapshot now, kept on the
/// appliance. So an administrator who has just switched the schedule on can
/// see it work rather than wait a day to find out it does not.
pub async fn post_take(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(_session): Admin,
) -> Result<Response> {
    match crate::backup::take_scheduled(&state.db).await {
        Ok(s) => flash_redirect("/backup", "success", &format!(
            "Snapshot {} taken — {}. It is kept with the scheduled ones and pruned with them",
            s.name, human_size(s.bytes))),
        Err(e) => flash_redirect("/backup", "failed", &e),
    }
}

// ─── post_stored ─────────────────────────────────────────

/// POST /backup/stored/{name} — download a snapshot kept on the appliance.
pub async fn post_stored(
    State(_state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Path(name): Path<String>,
) -> Result<Response> {
    // Only a name the scheduler writes. Anything else — a path, a dot-name, a
    // file somebody else put there — is not something this route hands out.
    if !crate::backup::is_snapshot_name(&name) {
        return flash_redirect("/backup", "failed", "There is no such snapshot");
    }
    let path = crate::backup::dir().join(&name);
    let file = match tokio::fs::File::open(&path).await {
        Ok(f)  => f,
        Err(_) => return flash_redirect("/backup", "failed",
                      &format!("{name} is no longer there — it may have been pruned")),
    };
    let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    tracing::info!(by = %session.username, file = %name, "Stored snapshot downloaded");

    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.sqlite3".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
            (header::CONTENT_LENGTH, size.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from_stream(tokio_util::io::ReaderStream::new(file)),
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

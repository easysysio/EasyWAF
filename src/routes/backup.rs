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

    // ── Restore ──
    // A held upload is inspected again on every view rather than remembered:
    // it is cheap, and what the page describes is then what is on disk now.
    let candidate = crate::backup::candidate_path();
    let (held, held_error) = if candidate.exists() {
        match crate::backup::inspect(&candidate).await {
            Ok(c)  => (Some(c), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };
    ctx.insert("held",        &held);
    ctx.insert("held_error",  &held_error.unwrap_or_default());
    ctx.insert("held_size",   &human_size(std::fs::metadata(&candidate).map(|m| m.len()).unwrap_or(0)));
    for key in [crate::backup::KEY_RESTORE_OUTCOME, crate::backup::KEY_RESTORE_MESSAGE,
                crate::backup::KEY_RESTORE_AT] {
        let v = crate::routes::settings::get_setting(&state.db, key).await.unwrap_or_default();
        ctx.insert(key, &v);
    }
    let before = crate::backup::before_path();
    ctx.insert("before_size", &before.exists().then(||
        human_size(std::fs::metadata(&before).map(|m| m.len()).unwrap_or(0))));

    // ── Import: a held file, and what applying it would do ──
    // Planned again on every view, like the held snapshot, so the preview is of
    // this installation as it is now rather than when the file arrived.
    let candidate = import_candidate();
    if let Ok(text) = std::fs::read_to_string(&candidate) {
        match crate::import::parse(&text) {
            Ok(doc) => {
                let plan = crate::import::plan(&state.db, &doc, &gui_ports(&state), &session.username).await;
                ctx.insert("import_plan", &plan);
            }
            Err(e) => ctx.insert("import_error", &e),
        }
    }

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

// ─── Restore ─────────────────────────────────────────────

/// POST /backup/restore/upload — receive a snapshot, check it, and hold it
/// for an administrator to look at. Nothing is replaced here.
///
/// Held rather than applied, because the likeliest mistake is the wrong file:
/// last month's, staging's, another appliance's. The page shows what the file
/// holds before a second button does anything about it.
pub async fn post_restore_upload(
    State(_state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    mut parts: axum::extract::Multipart,
) -> Result<Response> {
    use tokio::io::AsyncWriteExt;

    let candidate = crate::backup::candidate_path();
    if let Some(dir) = candidate.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::remove_file(&candidate);

    // Streamed to disk a chunk at a time: a database with months of traffic
    // history in it does not belong in memory.
    let mut got = false;
    while let Ok(Some(mut field)) = parts.next_field().await {
        if field.file_name().is_none() {
            continue;
        }
        let mut out = match tokio::fs::File::create(&candidate).await {
            Ok(f)  => f,
            Err(e) => return flash_redirect("/backup", "failed",
                          &format!("The upload could not be written: {e}")),
        };
        loop {
            match field.chunk().await {
                Ok(Some(bytes)) => {
                    if let Err(e) = out.write_all(&bytes).await {
                        let _ = std::fs::remove_file(&candidate);
                        return flash_redirect("/backup", "failed",
                            &format!("The upload could not be written: {e}"));
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = std::fs::remove_file(&candidate);
                    return flash_redirect("/backup", "failed",
                        &format!("The upload did not arrive whole: {e}"));
                }
            }
        }
        let _ = out.flush().await;
        got = true;
        break;
    }
    if !got {
        return flash_redirect("/backup", "failed", "No file was uploaded");
    }

    match crate::backup::inspect(&candidate).await {
        Ok(c) => {
            tracing::info!(by = %session.username, sites = c.sites, policies = c.policies,
                           written_by = ?c.written_by, "Snapshot uploaded and held for restore");
            flash_redirect("/backup", "success",
                "Checked and held. Nothing has been replaced — look at what it holds below, then restore it or discard it")
        }
        Err(e) => {
            let _ = std::fs::remove_file(&candidate);
            flash_redirect("/backup", "failed", &format!("Not restorable: {e}"))
        }
    }
}

/// POST /backup/restore/apply — stage the held snapshot and restart into it.
pub async fn post_restore_apply(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
) -> Result<Response> {
    let candidate = crate::backup::candidate_path();
    // Checked again: the page that showed it may be an hour old, and the file
    // is what is about to become the database.
    if let Err(e) = crate::backup::inspect(&candidate).await {
        let _ = std::fs::remove_file(&candidate);
        return flash_redirect("/backup", "failed", &format!("Not restorable: {e}"));
    }
    if let Err(e) = crate::backup::stage(&candidate) {
        return flash_redirect("/backup", "failed", &e);
    }
    tracing::warn!(by = %session.username, "Restore staged — restarting to apply it");

    // Answered first, then stopped: the page below has to reach the browser
    // before the process that serves it goes away.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        crate::backup::request_restart();
    });

    Ok(Html(state.tera.render("restarting.html", &Context::new())?).into_response())
}

/// POST /backup/restore/discard — drop a held upload.
pub async fn post_restore_discard(
    State(_state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(_session): Admin,
) -> Result<Response> {
    let _ = std::fs::remove_file(crate::backup::candidate_path());
    flash_redirect("/backup", "success", "Discarded. Nothing was restored")
}

/// POST /backup/before-restore — download the database the last restore
/// replaced. The way back, as a file: restoring it is an upload like any other.
pub async fn post_before_restore(
    State(_state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
) -> Result<Response> {
    let path = crate::backup::before_path();
    let file = match tokio::fs::File::open(&path).await {
        Ok(f)  => f,
        Err(_) => return flash_redirect("/backup", "failed",
                      "No database from before a restore is kept"),
    };
    let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    tracing::info!(by = %session.username, "Pre-restore database downloaded");
    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.sqlite3".to_string()),
            (header::CONTENT_DISPOSITION,
             "attachment; filename=\"easywaf-before-restore.db\"".to_string()),
            (header::CONTENT_LENGTH, size.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from_stream(tokio_util::io::ReaderStream::new(file)),
    )
        .into_response())
}

// ─── post_export ─────────────────────────────────────────

/// POST /backup/export — the configuration as a TOML file.
///
/// Private keys and accounts each need their own box ticked. The file says
/// what it carries in its header; this also logs it, since a file with keys in
/// it having been produced is exactly what an audit should be able to find.
pub async fn post_export(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response> {
    let opts = crate::export::Options {
        private_keys: form.contains_key("private_keys"),
        accounts:     form.contains_key("accounts"),
    };
    let doc = match crate::export::build(&state.db, opts).await {
        Ok(d)  => d,
        Err(e) => return flash_redirect("/backup", "failed",
                      &format!("The configuration could not be read: {e}")),
    };
    let text = match crate::export::to_toml(&doc) {
        Ok(t)  => t,
        Err(e) => return flash_redirect("/backup", "failed", &e),
    };

    if opts.private_keys || opts.accounts {
        tracing::warn!(by = %session.username, private_keys = opts.private_keys,
                       accounts = opts.accounts, "Configuration exported WITH secrets");
    } else {
        tracing::info!(by = %session.username, "Configuration exported");
    }

    let name = format!("easywaf-config-{}.toml", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    Ok((
        [
            (header::CONTENT_TYPE, "application/toml; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        text,
    )
        .into_response())
}

// ─── Import ──────────────────────────────────────────────

/// A configuration file uploaded and held for its preview.
fn import_candidate() -> std::path::PathBuf {
    crate::backup::dir().join(".import-candidate.toml")
}

fn gui_ports(state: &AppState) -> Vec<u16> {
    vec![state.config.proxy.gui_port, state.config.proxy.gui_tls_port]
}

/// POST /backup/import/upload — receive a configuration file and hold it. The
/// page then shows everything applying it would create, change and remove.
pub async fn post_import_upload(
    State(_state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    mut parts: axum::extract::Multipart,
) -> Result<Response> {
    let mut text = None;
    while let Ok(Some(field)) = parts.next_field().await {
        if field.file_name().is_none() { continue; }
        match field.bytes().await {
            Ok(b) => { text = Some(b); break; }
            Err(e) => return flash_redirect("/backup", "failed",
                         &format!("The upload did not arrive whole: {e}")),
        }
    }
    let Some(bytes) = text else {
        return flash_redirect("/backup", "failed", "No file was uploaded");
    };
    let Ok(text) = String::from_utf8(bytes.to_vec()) else {
        return flash_redirect("/backup", "failed", "Not importable: it is not a text file");
    };
    // Parsed now, so a file that is not an export is refused at the door
    // rather than held and refused on every view of the page.
    if let Err(e) = crate::import::parse(&text) {
        return flash_redirect("/backup", "failed", &format!("Not importable: {e}"));
    }
    let candidate = import_candidate();
    if let Some(dir) = candidate.parent() { let _ = std::fs::create_dir_all(dir); }
    if let Err(e) = std::fs::write(&candidate, &text) {
        return flash_redirect("/backup", "failed", &format!("The file could not be held: {e}"));
    }
    tracing::info!(by = %session.username, "Configuration file uploaded and held for import");
    flash_redirect("/backup", "success",
        "Read and held. Nothing has been changed — the preview below lists everything importing it would do")
}

/// POST /backup/import/apply — make this installation match the held file.
pub async fn post_import_apply(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
) -> Result<Response> {
    let candidate = import_candidate();
    let Ok(text) = std::fs::read_to_string(&candidate) else {
        return flash_redirect("/backup", "failed", "There is no configuration file waiting to be imported");
    };
    let doc = match crate::import::parse(&text) {
        Ok(d)  => d,
        Err(e) => return flash_redirect("/backup", "failed", &format!("Not importable: {e}")),
    };
    // Planned again: the preview may be an hour old, and the installation may
    // have changed since. What is refused now is what counts.
    let plan = crate::import::plan(&state.db, &doc, &gui_ports(&state), &session.username).await;
    if !plan.blockers.is_empty() {
        return flash_redirect("/backup", "failed",
            &format!("Not imported: {}", plan.blockers.join("; ")));
    }

    // Onto a copy. The live database is not touched until the copy is whole,
    // checked and swapped in by the restart.
    let work = crate::backup::dir().join(".import-work.db");
    for sfx in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{sfx}", work.display()));
    }
    if let Err(e) = crate::backup::take(&state.db, &work).await {
        return flash_redirect("/backup", "failed", &format!("Not imported: {e}"));
    }
    let outcome = async {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", work.display()))
            .await.map_err(|e| format!("the working copy would not open: {e}"))?;
        let applied = crate::import::apply(&pool, &doc, &session.username).await;
        let _ = sqlx::raw_sql("PRAGMA wal_checkpoint(TRUNCATE)").execute(&pool).await;
        pool.close().await;
        applied
    }.await;
    for sfx in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{sfx}", work.display()));
    }
    if let Err(e) = outcome {
        let _ = std::fs::remove_file(&work);
        return flash_redirect("/backup", "failed",
            &format!("Not imported, and nothing was changed: {e}"));
    }

    let success = format!(
        "Imported the configuration exported by EasyWAF {} on {} — {} change(s).",
        doc.easywaf.version, doc.easywaf.exported, plan.changes);
    if let Err(e) = crate::backup::set_reason("The import", &success)
        .and_then(|_| crate::backup::stage(&work))
    {
        let _ = std::fs::remove_file(&work);
        return flash_redirect("/backup", "failed", &format!("Not imported: {e}"));
    }
    let _ = std::fs::remove_file(&candidate);
    tracing::warn!(by = %session.username, changes = plan.changes,
                   "Configuration import staged — restarting to apply it");

    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        crate::backup::request_restart();
    });
    let mut ctx = Context::new();
    ctx.insert("heading", "Applying the import");
    ctx.insert("what", "the imported configuration");
    ctx.insert("import", &true);
    Ok(Html(state.tera.render("restarting.html", &ctx)?).into_response())
}

/// POST /backup/import/discard — drop a held configuration file.
pub async fn post_import_discard(
    State(_state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(_session): Admin,
) -> Result<Response> {
    let _ = std::fs::remove_file(import_candidate());
    flash_redirect("/backup", "success", "Discarded. Nothing was imported")
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

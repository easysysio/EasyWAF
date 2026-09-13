// =========================================================
// routes/iplists.rs — EasyWAF
// The allow and block lists, seen and edited.
//
// Entries mostly arrive from a Traffic Monitor row, which is
// where somebody is standing when they decide an address
// should never be seen again. This page is where they are
// read back, searched and taken off again — the reactive
// path adds them, and auditing what has accumulated needs a
// real list.
//
// Every change reloads the in-memory matcher, so an address
// is refused or admitted from the next request rather than
// the next restart.
// =========================================================

use crate::routes::flash_redirect;
use crate::{auth::{Admin, Viewer}, error::Result, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use tera::Context;

// ─── Models ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Entry {
    pub id:         i64,
    pub ip:         String,
    pub list_type:  String,
    pub reason:     Option<String>,
    pub added_by:   Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub q:      Option<String>,
    pub result: Option<String>,
    pub msg:    Option<String>,
}

/// Adding an address, from a traffic row or from this page's own form.
#[derive(Debug, Deserialize)]
pub struct AddForm {
    pub ip:        String,
    pub list_type: String,
    pub reason:    Option<String>,
    /// Where to return to, preserving whatever filter was applied.
    pub back:      Option<String>,
}

// ─── get_iplists ─────────────────────────────────────────

/// GET /iplists — every entry, newest first.
pub async fn get_iplists(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(q): Query<ListQuery>,
) -> Result<Response> {

    let search = q.q.as_deref().unwrap_or("").trim().to_string();
    let like   = format!("%{}%", search);

    // Searched in SQL rather than in the template, so a long list stays one
    // query and the count below matches what is shown.
    let rows = sqlx::query!(
        r#"SELECT id as "id!", ip as "ip!", list_type as "list_type!",
                  reason, added_by, created_at as "created_at!"
           FROM   ip_rules
           WHERE  ?1 = '' OR ip LIKE ?2 OR COALESCE(reason, '') LIKE ?2
           ORDER  BY created_at DESC, id DESC"#,
        search, like
    )
    .fetch_all(&state.db)
    .await?;

    let entries: Vec<Entry> = rows.into_iter().map(|r| Entry {
        id:         r.id,
        ip:         r.ip,
        list_type:  r.list_type,
        reason:     r.reason,
        added_by:   r.added_by,
        created_at: r.created_at,
    }).collect();

    let allowed = entries.iter().filter(|e| e.list_type == "allow").count();
    let blocked = entries.iter().filter(|e| e.list_type == "block").count();

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",   "IP Lists");
    ctx.insert("url",     "/iplists");
    ctx.insert("entries", &entries);
    ctx.insert("allowed", &allowed);
    ctx.insert("blocked", &blocked);
    ctx.insert("search",  &search);
    ctx.insert("result",  &q.result.unwrap_or_default());
    ctx.insert("msg",     &q.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("iplists.html", &ctx)?)).into_response())
}

// ─── post_ip_add ─────────────────────────────────────────

/// POST /iplists/add — put an address on a list.
///
/// An address is on at most one list, so adding one that is already on the
/// other **moves** it rather than failing. That is what the operator means:
/// clicking Allow on something currently blocked is a correction, not a
/// duplicate.
pub async fn post_ip_add(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<AddForm>,
) -> Result<Response> {

    let back = form.back.clone().unwrap_or_else(|| "/iplists".to_string());
    let ip   = form.ip.trim().to_string();

    // Parsed rather than trusted, even coming from a traffic row: it arrives
    // through a form field like anything else.
    if crate::forwarded::Cidr::parse(&ip).is_none() {
        return flash_redirect(&back, "failed", &format!("\"{ip}\" is not an address or CIDR block"));
    }

    let list_type = match form.list_type.trim() {
        "allow" => "allow",
        "block" => "block",
        other   => {
            return flash_redirect(&back, "failed", &format!("\"{other}\" is not a list"));
        }
    };

    let reason = form.reason.as_deref().unwrap_or("").trim().to_string();
    let reason = if reason.is_empty() { None } else { Some(reason) };

    // What it was on before, so the message can say "moved" rather than
    // "added" when that is what happened.
    let previous: Option<String> = sqlx::query_scalar!(
        "SELECT list_type FROM ip_rules WHERE ip = ?", ip
    )
    .fetch_optional(&state.db)
    .await?;

    sqlx::query!(
        "INSERT INTO ip_rules (ip, list_type, reason, added_by)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(ip) DO UPDATE SET list_type = excluded.list_type,
                                       reason    = excluded.reason,
                                       added_by  = excluded.added_by",
        ip, list_type, reason, session.username
    )
    .execute(&state.db)
    .await?;

    // The matcher is what the proxy consults, so the change means nothing
    // until this runs.
    crate::iplist::reload(&state.db).await;

    tracing::info!(ip, list_type, by = %session.username, "IP list entry saved");

    let msg = match previous.as_deref() {
        Some(was) if was != list_type => format!(
            "{ip} moved from the {was} list to the {list_type} list"
        ),
        Some(_) => format!("{ip} is already on the {list_type} list"),
        None if list_type == "block" => format!(
            "{ip} is blocked — it is refused before any rule runs, on every site"
        ),
        None => format!(
            "{ip} is allowed — it skips the WAF, the country rules and the challenge, on every site"
        ),
    };
    flash_redirect(&back, "success", &msg)
}

// ─── post_ip_remove ──────────────────────────────────────

/// POST /iplists/{id}/remove — take an address off its list.
pub async fn post_ip_remove(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Path(id): Path<i64>,
) -> Result<Response> {

    let gone = sqlx::query!("DELETE FROM ip_rules WHERE id = ? RETURNING ip, list_type", id)
        .fetch_optional(&state.db)
        .await?;

    let Some(gone) = gone else {
        return flash_redirect("/iplists", "failed", "That entry no longer exists");
    };

    crate::iplist::reload(&state.db).await;
    tracing::info!(ip = %gone.ip, by = %session.username, "IP list entry removed");

    let msg = if gone.list_type == "block" {
        format!("{} is no longer blocked — it is inspected like any other client again", gone.ip)
    } else {
        format!("{} is no longer allowed past the checks — it is inspected again", gone.ip)
    };
    flash_redirect("/iplists", "success", &msg)
}

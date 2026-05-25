// =========================================================
// routes/sites.rs — EasyWAF
// Site management: list, create, edit, delete.
// Sites are virtual hosts routed by the Host: header.
// Each site maps to one DB row; the proxy reads it directly.
// Each site now has its own listen_port so different virtual
// hosts can bind separate TCP ports (e.g. 80, 8080).
// =========================================================

use crate::{
    auth::get_session,
    error::{AppError, Result},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use tera::Context;

// ─── Models ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Site {
    pub id:             i64,
    pub name:           String,
    pub server_name:    String,
    pub target:         String,
    pub listen_port:    i64,
    pub enabled:        bool,
    pub waf_policy_id:  Option<i64>,
    pub hsts:           bool,
    pub x_frame:        bool,
    pub x_content_type: bool,
    pub xss_protection: bool,
}

#[derive(Debug, Serialize)]
pub struct Policy {
    pub id:   i64,
    pub name: String,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SiteForm {
    pub name:           Option<String>,
    pub server_name:    String,
    pub target:         String,
    pub listen_port:    Option<String>,  // comes in as text; we parse to i64
    /// Comes in as "" when "None" is selected, or "123" when a policy is chosen.
    pub waf_policy_id:  Option<String>,
    pub hsts:           Option<String>,
    pub x_frame:        Option<String>,
    pub x_content_type: Option<String>,
    pub xss_protection: Option<String>,
}

#[derive(Deserialize)]
pub struct FlashQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

// ─── get_sites ───────────────────────────────────────────

/// List all sites with flash message support (success / failed banners).
pub async fn get_sites(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let sites    = fetch_sites(&state).await?;
    let policies = fetch_policies(&state).await?;

    let mut ctx = Context::new();
    ctx.insert("username",  &session.username);
    ctx.insert("title",     "Site Management");
    ctx.insert("url",       "/sites");
    ctx.insert("sites",     &sites);
    ctx.insert("policies",  &policies);
    ctx.insert("result",    &flash.result.unwrap_or_default());
    ctx.insert("msg",       &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("sites.html", &ctx)?)).into_response())
}

// ─── get_site_new ────────────────────────────────────────

/// Render the create-site form.
pub async fn get_site_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let policies = fetch_policies(&state).await?;

    let mut ctx = Context::new();
    ctx.insert("username",  &session.username);
    ctx.insert("title",     "Create Site");
    ctx.insert("url",       "/sites");
    ctx.insert("policies",  &policies);

    Ok((jar, Html(state.tera.render("site_create.html", &ctx)?)).into_response())
}

// ─── post_site_create ────────────────────────────────────

/// Handle site creation form submission.
/// Validates that name and hostname are non-empty and unique.
pub async fn post_site_create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<SiteForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let name        = form.name.as_deref().unwrap_or("").trim().to_string();
    let server_name = form.server_name.trim().to_lowercase();
    let listen_port = parse_port(&form.listen_port);

    if name.is_empty() {
        return flash_redirect("/sites", "failed", "Site name is required");
    }
    if server_name.is_empty() {
        return flash_redirect("/sites", "failed", "Hostname is required");
    }

    // Reject duplicate name or hostname.
    let exists: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM sites WHERE name = ? OR server_name = ?",
        name, server_name
    )
    .fetch_one(&state.db)
    .await?;

    if exists > 0 {
        return flash_redirect("/sites", "failed", "Site name or hostname already exists");
    }

    let hsts           = form.hsts.is_some();
    let x_frame        = form.x_frame.is_some();
    let x_content_type = form.x_content_type.is_some();
    let xss_protection = form.xss_protection.is_some();
    let waf_policy_id  = parse_policy_id(&form.waf_policy_id);

    sqlx::query!(
        "INSERT INTO sites
         (name, server_name, target, listen_port, waf_policy_id,
          hsts, x_frame, x_content_type, xss_protection)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        name, server_name, form.target, listen_port, waf_policy_id,
        hsts, x_frame, x_content_type, xss_protection,
    )
    .execute(&state.db)
    .await?;

    flash_redirect("/sites", "success", &format!("Site {} created successfully", name))
}

// ─── get_site_edit ───────────────────────────────────────

/// Render the site settings / edit form for an existing site.
pub async fn get_site_edit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let site     = fetch_site(&state, &name).await?;
    let policies = fetch_policies(&state).await?;

    let mut ctx = Context::new();
    ctx.insert("username",  &session.username);
    ctx.insert("title",     "Site Settings");
    ctx.insert("url",       "/sites");
    ctx.insert("site",      &site);
    ctx.insert("policies",  &policies);

    Ok((jar, Html(state.tera.render("site_settings.html", &ctx)?)).into_response())
}

// ─── post_site_update ────────────────────────────────────

/// Handle site settings form submission.
/// Note: changing listen_port takes effect only after a proxy restart,
/// because the TCP listeners are bound at startup.
pub async fn post_site_update(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(form): Form<SiteForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let hsts           = form.hsts.is_some();
    let x_frame        = form.x_frame.is_some();
    let x_content_type = form.x_content_type.is_some();
    let xss_protection = form.xss_protection.is_some();
    let server_name    = form.server_name.trim().to_lowercase();
    let listen_port    = parse_port(&form.listen_port);
    let waf_policy_id  = parse_policy_id(&form.waf_policy_id);

    sqlx::query!(
        "UPDATE sites SET
           server_name=?, target=?, listen_port=?, waf_policy_id=?,
           hsts=?, x_frame=?, x_content_type=?, xss_protection=?,
           updated_at=datetime('now')
         WHERE name=?",
        server_name, form.target, listen_port, waf_policy_id,
        hsts, x_frame, x_content_type, xss_protection,
        name,
    )
    .execute(&state.db)
    .await?;

    flash_redirect("/sites", "success", &format!("Site {} updated successfully", name))
}

// ─── post_site_delete ────────────────────────────────────

/// Delete a site by name. Traffic events are cascade-deleted by the DB.
pub async fn post_site_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    sqlx::query!("DELETE FROM sites WHERE name = ?", name)
        .execute(&state.db)
        .await?;

    flash_redirect("/sites", "success", &format!("Site {} deleted successfully", name))
}

// ─── DB helpers ──────────────────────────────────────────

/// Fetch all sites ordered by name.
async fn fetch_sites(state: &AppState) -> Result<Vec<Site>> {
    let rows = sqlx::query!(
        "SELECT id as \"id!\", name, server_name, target,
                listen_port    as \"listen_port!\",
                enabled        as \"enabled!: bool\",
                waf_policy_id,
                hsts           as \"hsts!: bool\",
                x_frame        as \"x_frame!: bool\",
                x_content_type as \"x_content_type!: bool\",
                xss_protection as \"xss_protection!: bool\"
         FROM sites ORDER BY name"
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows.into_iter().map(|r| Site {
        id:             r.id,
        name:           r.name,
        server_name:    r.server_name,
        target:         r.target,
        listen_port:    r.listen_port,
        enabled:        r.enabled,
        waf_policy_id:  r.waf_policy_id,
        hsts:           r.hsts,
        x_frame:        r.x_frame,
        x_content_type: r.x_content_type,
        xss_protection: r.xss_protection,
    }).collect())
}

/// Fetch a single site by name; returns NotFound if the site does not exist.
async fn fetch_site(state: &AppState, name: &str) -> Result<Site> {
    let r = sqlx::query!(
        "SELECT id as \"id!\", name, server_name, target,
                listen_port    as \"listen_port!\",
                enabled        as \"enabled!: bool\",
                waf_policy_id,
                hsts           as \"hsts!: bool\",
                x_frame        as \"x_frame!: bool\",
                x_content_type as \"x_content_type!: bool\",
                xss_protection as \"xss_protection!: bool\"
         FROM sites WHERE name = ?",
        name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Site '{}' not found", name)))?;

    Ok(Site {
        id:             r.id,
        name:           r.name,
        server_name:    r.server_name,
        target:         r.target,
        listen_port:    r.listen_port,
        enabled:        r.enabled,
        waf_policy_id:  r.waf_policy_id,
        hsts:           r.hsts,
        x_frame:        r.x_frame,
        x_content_type: r.x_content_type,
        xss_protection: r.xss_protection,
    })
}

/// Fetch all WAF policies for the policy dropdown.
async fn fetch_policies(state: &AppState) -> Result<Vec<Policy>> {
    let rows = sqlx::query!("SELECT id as \"id!\", name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|r| Policy { id: r.id, name: r.name }).collect())
}

// ─── Form parsing helpers ─────────────────────────────────

/// Parse listen_port from the form string.
/// Falls back to 80 if the field is missing or not a valid port number.
fn parse_port(raw: &Option<String>) -> i64 {
    raw.as_deref()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&p| p > 0 && p <= 65535)
        .unwrap_or(80)
}

/// Parse waf_policy_id from the form: empty string → None, numeric string → Some(i64).
fn parse_policy_id(raw: &Option<String>) -> Option<i64> {
    raw.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
}

// ─── Flash redirect helper ───────────────────────────────

/// Redirect to path with URL-encoded flash message query params.
fn flash_redirect(path: &str, result: &str, msg: &str) -> Result<Response> {
    let msg_enc = urlencoding::encode(msg).into_owned();
    Ok(Redirect::to(&format!("{}?result={}&msg={}", path, result, msg_enc)).into_response())
}

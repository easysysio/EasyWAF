// =========================================================
// routes/sites.rs — EasyWAF
// Site management: list, create, edit, delete.
// Each site maps to one nginx virtual-host .conf file AND a DB row.
// =========================================================

use crate::{
    auth::get_session,
    error::{AppError, Result},
    nginx::{
        delete_site_config, reload_nginx, write_site_config, SiteParams,
    },
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

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Site {
    pub id: i64,
    pub name: String,
    pub server_name: String,
    pub target: String,
    pub port: i64,
    pub waf_policy: Option<String>,
    pub hsts: bool,
    pub x_frame: bool,
    pub x_content_type: bool,
    pub xss_protection: bool,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SiteForm {
    pub name: Option<String>,
    pub server: String,
    pub target: String,
    pub port: i64,
    pub policy: Option<String>,
    pub hsts: Option<String>,
    pub x_frame: Option<String>,
    pub x_content_type: Option<String>,
    pub xss_protection: Option<String>,
}

#[derive(Deserialize)]
pub struct FlashQuery {
    pub result: Option<String>,
    pub msg: Option<String>,
}

// ─── get_sites ───────────────────────────────────────────

/// GET /sites — List all sites.
pub async fn get_sites(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let sites = sqlx::query_as!(
        Site,
        "SELECT id as \"id!\", name, server_name, target, port as \"port!\",
                waf_policy,
                hsts as \"hsts!: bool\",
                x_frame as \"x_frame!: bool\",
                x_content_type as \"x_content_type!: bool\",
                xss_protection as \"xss_protection!: bool\"
         FROM sites ORDER BY name"
    )
    .fetch_all(&state.db)
    .await?;

    let policies = sqlx::query_scalar!("SELECT name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Site Management");
    ctx.insert("url", "/sites");
    ctx.insert("sites", &sites);
    ctx.insert("policies", &policies);
    ctx.insert("result", &flash.result.unwrap_or_default());
    ctx.insert("msg", &flash.msg.unwrap_or_default());

    let html = state.tera.render("sites.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// ─── get_site_new ────────────────────────────────────────

/// GET /sites/new — Show the create-site form.
pub async fn get_site_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let policies = sqlx::query_scalar!("SELECT name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Create Site");
    ctx.insert("url", "/sites");
    ctx.insert("policies", &policies);

    let html = state.tera.render("site_create.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// ─── post_site_create ────────────────────────────────────

/// POST /sites/create — Save a new site.
pub async fn post_site_create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<SiteForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let name = form.name.as_deref().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return Ok(Redirect::to("/sites?result=failed&msg=Site+name+is+required").into_response());
    }

    // Check for duplicate.
    let exists: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM sites WHERE name = ?", name)
        .fetch_one(&state.db)
        .await?;
    if exists > 0 {
        return Ok(Redirect::to("/sites?result=failed&msg=Site+name+already+exists").into_response());
    }

    let hsts = form.hsts.is_some();
    let x_frame = form.x_frame.is_some();
    let x_content_type = form.x_content_type.is_some();
    let xss_protection = form.xss_protection.is_some();

    // Write nginx config file.
    write_site_config(
        &state.config.nginx,
        &SiteParams {
            name: &name,
            server_name: &form.server,
            target: &form.target,
            port: form.port,
            waf_policy: form.policy.as_deref(),
            hsts,
            x_frame,
            x_content_type,
            xss_protection,
        },
    )
    .map_err(AppError::Io)?;

    // Reload nginx.
    if let Err(e) = reload_nginx(&state.config.nginx.reload_cmd) {
        delete_site_config(&state.config.nginx, &name);
        let msg = urlencoding::encode(&format!("Site {} failed to save: {}", name, e)).into_owned();
        return Ok(Redirect::to(&format!("/sites?result=failed&msg={}", msg)).into_response());
    }

    // Persist to DB.
    sqlx::query!(
        "INSERT INTO sites (name, server_name, target, port, waf_policy, hsts, x_frame, x_content_type, xss_protection)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        name,
        form.server,
        form.target,
        form.port,
        form.policy,
        hsts,
        x_frame,
        x_content_type,
        xss_protection,
    )
    .execute(&state.db)
    .await?;

    let msg = urlencoding::encode(&format!("Site {} saved successfully", name)).into_owned();
    Ok(Redirect::to(&format!("/sites?result=success&msg={}", msg)).into_response())
}

// ─── get_site_edit ───────────────────────────────────────

/// GET /sites/:name/edit — Show the edit form for an existing site.
pub async fn get_site_edit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let site = sqlx::query_as!(
        Site,
        "SELECT id as \"id!\", name, server_name, target, port as \"port!\",
                waf_policy,
                hsts as \"hsts!: bool\",
                x_frame as \"x_frame!: bool\",
                x_content_type as \"x_content_type!: bool\",
                xss_protection as \"xss_protection!: bool\"
         FROM sites WHERE name = ?",
        name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Site '{}' not found", name)))?;

    let policies = sqlx::query_scalar!("SELECT name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Site Settings");
    ctx.insert("url", "/sites");
    ctx.insert("site", &site);
    ctx.insert("policies", &policies);

    let html = state.tera.render("site_settings.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// ─── post_site_update ────────────────────────────────────

/// POST /sites/:name/update — Update an existing site.
pub async fn post_site_update(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(form): Form<SiteForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let hsts = form.hsts.is_some();
    let x_frame = form.x_frame.is_some();
    let x_content_type = form.x_content_type.is_some();
    let xss_protection = form.xss_protection.is_some();

    // Backup existing config.
    let conf_path = format!("{}/{}.conf", state.config.nginx.site_dir, name);
    let backup_path = format!("{}.backup", conf_path);
    let _ = std::fs::copy(&conf_path, &backup_path);

    write_site_config(
        &state.config.nginx,
        &SiteParams {
            name: &name,
            server_name: &form.server,
            target: &form.target,
            port: form.port,
            waf_policy: form.policy.as_deref(),
            hsts,
            x_frame,
            x_content_type,
            xss_protection,
        },
    )
    .map_err(AppError::Io)?;

    if let Err(e) = reload_nginx(&state.config.nginx.reload_cmd) {
        // Restore backup.
        let _ = std::fs::copy(&backup_path, &conf_path);
        let msg = urlencoding::encode(&format!("Site {} failed to update: {}", name, e)).into_owned();
        return Ok(Redirect::to(&format!("/sites?result=failed&msg={}", msg)).into_response());
    }

    sqlx::query!(
        "UPDATE sites SET server_name=?, target=?, port=?, waf_policy=?, hsts=?, x_frame=?,
         x_content_type=?, xss_protection=?, updated_at=datetime('now') WHERE name=?",
        form.server,
        form.target,
        form.port,
        form.policy,
        hsts,
        x_frame,
        x_content_type,
        xss_protection,
        name,
    )
    .execute(&state.db)
    .await?;

    let msg = urlencoding::encode(&format!("Site {} updated successfully", name)).into_owned();
    Ok(Redirect::to(&format!("/sites?result=success&msg={}", msg)).into_response())
}

// ─── post_site_delete ────────────────────────────────────

/// POST /sites/:name/delete — Delete a site.
pub async fn post_site_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    delete_site_config(&state.config.nginx, &name);

    if let Err(e) = reload_nginx(&state.config.nginx.reload_cmd) {
        let msg = urlencoding::encode(&format!("Site {} failed to delete: {}", name, e)).into_owned();
        return Ok(Redirect::to(&format!("/sites?result=failed&msg={}", msg)).into_response());
    }

    sqlx::query!("DELETE FROM sites WHERE name = ?", name)
        .execute(&state.db)
        .await?;

    let msg = urlencoding::encode(&format!("Site {} deleted successfully", name)).into_owned();
    Ok(Redirect::to(&format!("/sites?result=success&msg={}", msg)).into_response())
}

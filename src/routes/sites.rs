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
    /// HTTPS port, or None when the site serves plain HTTP only.
    pub tls_port:       Option<i64>,
    pub cert_id:        Option<i64>,
    pub tls_redirect:   bool,
    pub enabled:        bool,
    pub waf_policy_id:  Option<i64>,
    pub hsts:           bool,
    pub x_frame:        bool,
    pub x_content_type: bool,
    pub xss_protection: bool,
}

/// A certificate as offered in the site form's dropdown.
#[derive(Debug, Serialize)]
pub struct CertOption {
    pub id:        i64,
    pub name:      String,
    pub domain:    String,
    pub not_after: String,
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
    /// HTTPS port. Empty means the site serves plain HTTP only.
    pub tls_port:       Option<String>,
    /// Certificate to present over HTTPS; empty means none selected.
    pub cert_id:        Option<String>,
    pub tls_redirect:   Option<String>,
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
    ctx.insert("certs",     &fetch_certs(&state).await?);
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
    ctx.insert("certs",     &fetch_certs(&state).await?);

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
    let server_name = normalize_server_name(&form.server_name);
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
    let tls_port       = parse_optional_port(&form.tls_port);
    let cert_id        = parse_policy_id(&form.cert_id);
    let tls_redirect   = form.tls_redirect.is_some();

    sqlx::query!(
        "INSERT INTO sites
         (name, server_name, target, listen_port, tls_port, cert_id, tls_redirect,
          waf_policy_id, hsts, x_frame, x_content_type, xss_protection)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        name, server_name, form.target, listen_port, tls_port, cert_id, tls_redirect,
        waf_policy_id, hsts, x_frame, x_content_type, xss_protection,
    )
    .execute(&state.db)
    .await?;

    announce_site(&state, listen_port, tls_port).await;

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
    ctx.insert("certs",     &fetch_certs(&state).await?);

    Ok((jar, Html(state.tera.render("site_settings.html", &ctx)?)).into_response())
}

// ─── post_site_update ────────────────────────────────────

/// Handle site settings form submission.
/// The hostname is normalised to a bare host (see `normalize_server_name`) so it
/// can match the request's `Host:` header.
/// Note: a new listen_port is bound immediately, but the previously bound port
/// keeps listening until the proxy restarts.
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
    let server_name    = normalize_server_name(&form.server_name);
    let listen_port    = parse_port(&form.listen_port);
    let waf_policy_id  = parse_policy_id(&form.waf_policy_id);

    // Normalisation can empty the field (e.g. the user typed only "http://"),
    // and a site with no hostname would never match a request.
    if server_name.is_empty() {
        return flash_redirect("/sites", "failed", "Hostname is required");
    }

    let tls_port     = parse_optional_port(&form.tls_port);
    let cert_id      = parse_policy_id(&form.cert_id);
    let tls_redirect = form.tls_redirect.is_some();

    sqlx::query!(
        "UPDATE sites SET
           server_name=?, target=?, listen_port=?, tls_port=?, cert_id=?,
           tls_redirect=?, waf_policy_id=?,
           hsts=?, x_frame=?, x_content_type=?, xss_protection=?,
           updated_at=datetime('now')
         WHERE name=?",
        server_name, form.target, listen_port, tls_port, cert_id,
        tls_redirect, waf_policy_id,
        hsts, x_frame, x_content_type, xss_protection,
        name,
    )
    .execute(&state.db)
    .await?;

    announce_site(&state, listen_port, tls_port).await;

    flash_redirect("/sites", "success", &format!("Site {} updated successfully", name))
}

// ─── post_site_toggle ────────────────────────────────────

/// POST /sites/{name}/toggle — enable or disable a site.
///
/// Disabling stops the proxy serving that hostname: `lookup_site` only matches
/// enabled rows, so requests for it get the same 404 as a hostname with no site
/// at all. Nothing else about the site is touched, so re-enabling restores it
/// exactly as it was.
///
/// Enabling signals the proxy to bind the site's port. That matters when this is
/// the only site on that port — listeners are bound from the *enabled* sites at
/// startup, so the port may not be listening at all. The proxy ignores the
/// signal for a port it already holds.
///
/// Disabling deliberately does not unbind anything: a port is shared by every
/// site that listens on it, and closing the listener would take those down too.
pub async fn post_site_toggle(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let site    = fetch_site(&state, &name).await?;
    let enabled = !site.enabled;

    sqlx::query!(
        "UPDATE sites SET enabled = ?, updated_at = datetime('now') WHERE name = ?",
        enabled,
        name
    )
    .execute(&state.db)
    .await?;

    if enabled {
        announce_site(&state, site.listen_port, site.tls_port).await;
    } else {
        // Disabling removes the site from the certificate map: its listener
        // stays bound for the other sites sharing it, but this name should no
        // longer present a certificate.
        if let Err(e) = crate::tls::reload(&state.db).await {
            tracing::error!("Could not reload site certificates: {}", e);
        }
    }

    let msg = if enabled {
        format!("Site {} enabled — now proxying on port {}", name, site.listen_port)
    } else {
        format!("Site {} disabled — requests for {} are no longer proxied", name, site.server_name)
    };
    flash_redirect("/sites", "success", &msg)
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
                tls_port,
                cert_id,
                tls_redirect   as \"tls_redirect!: bool\",
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
        tls_port:       r.tls_port,
        cert_id:        r.cert_id,
        tls_redirect:   r.tls_redirect,
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
                tls_port,
                cert_id,
                tls_redirect   as \"tls_redirect!: bool\",
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
        tls_port:       r.tls_port,
        cert_id:        r.cert_id,
        tls_redirect:   r.tls_redirect,
        enabled:        r.enabled,
        waf_policy_id:  r.waf_policy_id,
        hsts:           r.hsts,
        x_frame:        r.x_frame,
        x_content_type: r.x_content_type,
        xss_protection: r.xss_protection,
    })
}

/// Fetch all WAF policies for the policy dropdown.
/// Certificates available for a site to present over HTTPS.
async fn fetch_certs(state: &AppState) -> Result<Vec<CertOption>> {
    let rows = sqlx::query!(
        r#"SELECT id as "id!", name, COALESCE(domain, '') as "domain!", COALESCE(not_after, '') as "not_after!"
           FROM certs ORDER BY name"#
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| CertOption { id: r.id, name: r.name, domain: r.domain, not_after: r.not_after })
        .collect())
}

async fn fetch_policies(state: &AppState) -> Result<Vec<Policy>> {
    let rows = sqlx::query!("SELECT id as \"id!\", name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|r| Policy { id: r.id, name: r.name }).collect())
}

// ─── post_site_acme ──────────────────────────────────────

/// POST /sites/{name}/acme — obtain a Let's Encrypt certificate for this site.
///
/// The issued certificate is stored as an ordinary row in `certs` and assigned
/// to the site, so everything downstream — the SNI map, the detail page, the
/// deletion guard, per-site selection — treats it exactly like an uploaded one
/// and needs to know nothing about where it came from.
pub async fn post_site_acme(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let site = sqlx::query!(
        r#"SELECT id as "id!", server_name as "server_name!", listen_port
           FROM sites WHERE name = ?"#,
        name
    )
    .fetch_optional(&state.db)
    .await?;

    let site = match site {
        Some(s) => s,
        None    => return flash_redirect("/sites", "failed", "No such site"),
    };

    let back = format!("/sites/{}/edit", urlencoding::encode(&name));

    if crate::acme::config(&state.db).await?.is_none() {
        return flash_redirect(
            &back,
            "failed",
            "Set an ACME contact address under Settings before requesting a certificate",
        );
    }

    // Warned before the attempt rather than after it fails, because what the CA
    // reports for this is a timeout that reads like a network fault.
    if site.listen_port != 80 {
        tracing::warn!(
            site = %name, port = site.listen_port,
            "Requesting a certificate for a site that does not listen on port 80 — \
             HTTP-01 validation always arrives there"
        );
    }

    let (cert_pem, key_pem) = match crate::acme::issue(&state.db, &site.server_name).await {
        Ok(pair) => pair,
        Err(e)   => return flash_redirect(&back, "failed", &format!("{e}")),
    };

    // Dates come from the certificate itself rather than from an assumption
    // about validity periods, so renewal later reads what the CA issued.
    let (not_before, not_after) = match crate::routes::certs::inspect("", &cert_pem, true) {
        Ok(d)  => (Some(d.not_before), Some(d.not_after)),
        Err(_) => (None, None),
    };

    let cert_name = site.server_name.clone();
    sqlx::query!(
        "INSERT INTO certs (name, domain, not_before, not_after, cert_pem, key_pem, acme_domain)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET
             domain = excluded.domain, not_before = excluded.not_before,
             not_after = excluded.not_after, cert_pem = excluded.cert_pem,
             key_pem = excluded.key_pem, acme_domain = excluded.acme_domain",
        cert_name, site.server_name, not_before, not_after, cert_pem, key_pem, site.server_name
    )
    .execute(&state.db)
    .await?;

    let cert_id: i64 = sqlx::query_scalar!(
        r#"SELECT id as "id!" FROM certs WHERE name = ?"#, cert_name
    )
    .fetch_one(&state.db)
    .await?;

    sqlx::query!(
        "UPDATE sites SET cert_id = ?, acme_enabled = 1 WHERE id = ?",
        cert_id, site.id
    )
    .execute(&state.db)
    .await?;

    crate::tls::reload(&state.db).await?;

    flash_redirect(
        &back,
        "success",
        &format!("Issued a certificate for {} — add a TLS port to serve it", site.server_name),
    )
}

// ─── announce_site ───────────────────────────────────────

/// Tell the proxy about a site's ports and refresh the TLS certificate map.
///
/// Both listeners are signalled because a site can serve plain HTTP and HTTPS
/// at once; the proxy ignores a port it already holds. The certificate map is
/// rebuilt too, since it is resolved synchronously during a TLS handshake and
/// cannot query the database itself — a new or re-pointed site would otherwise
/// fail every handshake until the next restart.
async fn announce_site(state: &AppState, listen_port: i64, tls_port: Option<i64>) {
    let _ = state
        .port_tx
        .send(crate::proxy::BindRequest { port: listen_port as u16, tls: false })
        .await;

    if let Some(p) = tls_port {
        let _ = state
            .port_tx
            .send(crate::proxy::BindRequest { port: p as u16, tls: true })
            .await;
    }

    if let Err(e) = crate::tls::reload(&state.db).await {
        tracing::error!("Could not reload site certificates: {}", e);
    }
}

// ─── Form parsing helpers ─────────────────────────────────

/// Normalise the hostname a site is routed by.
///
/// The proxy matches this value against the request's `Host:` header, which
/// carries a bare hostname — never a scheme, a path, or (after the proxy strips
/// it) a port. Anything extra here would silently never match and the site
/// would answer 404, so the common paste-a-URL mistakes are stripped instead:
///
///   `https://Example.com:8080/app/`  →  `example.com`
///
/// A trailing dot (the DNS root, valid in a Host header) is dropped too so
/// `example.com.` and `example.com` are stored the same way.
fn normalize_server_name(raw: &str) -> String {
    let mut host = raw.trim().to_lowercase();

    // Drop a scheme prefix: "http://example.com" → "example.com".
    if let Some(pos) = host.find("://") {
        host = host[pos + 3..].to_string();
    }

    // Drop anything from the first path separator: "example.com/app" → "example.com".
    if let Some(pos) = host.find('/') {
        host.truncate(pos);
    }

    // Drop a port suffix: "example.com:8080" → "example.com".
    // The proxy strips the port from the Host header before matching, so a
    // stored port could never match.
    if let Some(pos) = host.find(':') {
        host.truncate(pos);
    }

    // Drop the DNS root dot: "example.com." → "example.com".
    while host.ends_with('.') {
        host.pop();
    }

    host
}

/// Parse listen_port from the form string.
/// Falls back to 80 if the field is missing or not a valid port number.
fn parse_port(raw: &Option<String>) -> i64 {
    raw.as_deref()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&p| p > 0 && p <= 65535)
        .unwrap_or(80)
}

/// Parse an optional port from the form: empty → None, out of range → None.
///
/// Out of range becomes None rather than a clamped value: a mistyped port
/// should leave the site without HTTPS, which is visible, rather than
/// listening somewhere nobody asked for.
fn parse_optional_port(raw: &Option<String>) -> Option<i64> {
    raw.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|p| *p > 0 && *p <= 65535)
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

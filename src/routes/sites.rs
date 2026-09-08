// =========================================================
// routes/sites.rs — EasyWAF
// Site management: list, create, edit, delete.
// Sites are virtual hosts routed by the Host: header.
// Each site maps to one DB row; the proxy reads it directly.
// Each site now has its own listen_port so different virtual
// hosts can bind separate TCP ports (e.g. 80, 8080).
// =========================================================

use crate::routes::flash_redirect;
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
use sqlx::SqlitePool;
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
    pub x_frame_value:  String,
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
    pub x_frame_value:  Option<String>,
    pub x_content_type: Option<String>,
    pub xss_protection: Option<String>,
    /// Create-form only: request a certificate as part of creating the site.
    pub acme:           Option<String>,
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
    // Offering to request a certificate when no contact address is set would be
    // a checkbox whose only outcome is an error, so the form says what is
    // missing instead.
    ctx.insert("acme_configured", &crate::acme::config(&state.db).await?.is_some());

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
    // Anything unrecognised becomes SAMEORIGIN rather than DENY: a typo should
    // not silently apply the stricter value that breaks framing.
    let x_frame_value  = match form.x_frame_value.as_deref().map(str::trim) {
        Some("DENY") => "DENY".to_string(),
        _            => "SAMEORIGIN".to_string(),
    };
    let x_content_type = form.x_content_type.is_some();
    let xss_protection = form.xss_protection.is_some();
    let waf_policy_id  = parse_policy_id(&form.waf_policy_id);
    let cert_id        = parse_policy_id(&form.cert_id);
    let tls_redirect   = form.tls_redirect.is_some();

    // Checked before the site exists: a rejected port list should leave nothing
    // behind to tidy up.
    let ports = match validated_ports(&form, &state.config) {
        Ok(v)  => v,
        Err(e) => return flash_redirect("/sites", "failed", &e),
    };
    let (listen_port, tls_port) = (ports.listen, ports.tls);
    let (extra_http, extra_https) = (ports.extra_http, ports.extra_https);

    let site_id = sqlx::query!(
        "INSERT INTO sites
         (name, server_name, target, listen_port, tls_port, cert_id, tls_redirect,
          waf_policy_id, hsts, x_frame, x_frame_value, x_content_type, xss_protection)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        name, server_name, form.target, listen_port, tls_port, cert_id, tls_redirect,
        waf_policy_id, hsts, x_frame, x_frame_value, x_content_type, xss_protection,
    )
    .execute(&state.db)
    .await?
    // From the INSERT's own result, not a following SELECT last_insert_rowid():
    // that value is per connection, and the pool would be free to answer the
    // second query on a different one.
    .last_insert_rowid();

    save_extra_ports(&state.db, site_id, &extra_http, &extra_https).await?;

    // Before any certificate request: HTTP-01 validation arrives on a port that
    // has to be listening, and the challenge is answered by the proxy.
    announce_site(&state, listen_port, tls_port, &extra_http, &extra_https).await;

    if form.acme.is_none() {
        return flash_redirect("/sites", "success", &format!("Site {} created successfully", name));
    }

    // The site is created either way. Issuing talks to a CA over the network
    // and can fail for reasons that have nothing to do with what was typed —
    // DNS, a closed port 80, the CA's rate limit — and losing the site over
    // that would mean filling the form in again to retry something the site's
    // own page already offers a button for.
    if let Err(e) = request_cert_for_new_site(&state, site_id, &server_name).await {
        return flash_redirect(
            "/sites",
            "failed",
            &format!("Site {name} was created, but no certificate was issued: {e}"),
        );
    }

    // An issued certificate with no HTTPS port is served to nobody, and the
    // renewal will go on quietly refreshing it. Said here rather than left to
    // be discovered when the site does not answer on 443.
    let msg = match tls_port {
        Some(_) => format!("Site {name} created, with a certificate issued for {server_name}"),
        None    => format!(
            "Site {name} created and a certificate issued for {server_name} — \
             set an HTTPS port on the site to serve it"
        ),
    };
    flash_redirect("/sites", "success", &msg)
}

/// Issue a certificate for a site that has just been created, and assign it.
///
/// Split out so the create path and the site page's own button cannot drift:
/// both end with a certificate stored as an ordinary row in `certs` and the
/// site pointing at it, which is all anything downstream knows about.
async fn request_cert_for_new_site(
    state:       &AppState,
    site_id:     i64,
    server_name: &str,
) -> std::result::Result<(), String> {
    if crate::acme::config(&state.db).await.ok().flatten().is_none() {
        return Err("set an ACME contact address under Settings, then request one \
                    from the site's page"
            .to_string());
    }

    let cert_id = crate::acme::issue_and_store(&state.db, server_name, server_name)
        .await
        .map_err(|e| e.to_string())?;

    sqlx::query!(
        "UPDATE sites SET cert_id = ?, acme_enabled = 1 WHERE id = ?",
        cert_id, site_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}

// ─── get_site_edit ───────────────────────────────────────

/// Render the site settings / edit form for an existing site.
pub async fn get_site_edit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Query(flash): Query<FlashQuery>,
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
    // Named on this page because this is where the policy is chosen, and so
    // where someone stands when they find it is wrong for this one site.
    let exclusion_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) as \"c!\" FROM site_rule_exclusions WHERE site_id = ?",
        site.id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    ctx.insert("exclusion_count", &exclusion_count);
    // Requesting a certificate redirects back here. Without this the page came
    // back looking exactly as it did before, whether the CA had issued one or
    // refused — which is indistinguishable from the button doing nothing.
    ctx.insert("result",    &flash.result.unwrap_or_default());
    ctx.insert("msg",       &flash.msg.unwrap_or_default());
    // One field per protocol, primary first, the way it was typed in.
    let (extra_http, extra_https) = extra_ports_of(&state.db, site.id).await;
    let join = |first: String, rest: &str| {
        if rest.is_empty() { first } else { format!("{first}, {rest}") }
    };
    ctx.insert("http_ports",  &join(site.listen_port.to_string(), &extra_http));
    ctx.insert("https_ports", &match site.tls_port {
        Some(p) => join(p.to_string(), &extra_https),
        None    => extra_https.clone(),
    });

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
    // Anything unrecognised becomes SAMEORIGIN rather than DENY: a typo should
    // not silently apply the stricter value that breaks framing.
    let x_frame_value  = match form.x_frame_value.as_deref().map(str::trim) {
        Some("DENY") => "DENY".to_string(),
        _            => "SAMEORIGIN".to_string(),
    };
    let x_content_type = form.x_content_type.is_some();
    let xss_protection = form.xss_protection.is_some();
    let server_name    = normalize_server_name(&form.server_name);
    let waf_policy_id  = parse_policy_id(&form.waf_policy_id);

    // Normalisation can empty the field (e.g. the user typed only "http://"),
    // and a site with no hostname would never match a request.
    if server_name.is_empty() {
        return flash_redirect("/sites", "failed", "Hostname is required");
    }

    let cert_id      = parse_policy_id(&form.cert_id);
    let tls_redirect = form.tls_redirect.is_some();

    // Before the UPDATE: a rejected port list should leave the site as it was,
    // not half-saved with the ports refused.
    let ports = match validated_ports(&form, &state.config) {
        Ok(v)  => v,
        Err(e) => return flash_redirect("/sites", "failed", &e),
    };
    let (listen_port, tls_port) = (ports.listen, ports.tls);
    let (extra_http, extra_https) = (ports.extra_http, ports.extra_https);

    sqlx::query!(
        "UPDATE sites SET
           server_name=?, target=?, listen_port=?, tls_port=?, cert_id=?,
           tls_redirect=?, waf_policy_id=?,
           hsts=?, x_frame=?, x_frame_value=?, x_content_type=?, xss_protection=?,
           updated_at=datetime('now')
         WHERE name=?",
        server_name, form.target, listen_port, tls_port, cert_id,
        tls_redirect, waf_policy_id,
        hsts, x_frame, x_frame_value, x_content_type, xss_protection,
        name,
    )
    .execute(&state.db)
    .await?;

    let site_id: i64 =
        sqlx::query_scalar!(r#"SELECT id as "id!" FROM sites WHERE name = ?"#, name)
            .fetch_one(&state.db)
            .await?;
    save_extra_ports(&state.db, site_id, &extra_http, &extra_https).await?;

    announce_site(&state, listen_port, tls_port, &extra_http, &extra_https).await;

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
        let (http, https) = {
            let rows = sqlx::query!(
                r#"SELECT port as "port!", tls as "tls!: bool" FROM site_ports WHERE site_id = ?"#,
                site.id
            )
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
            (
                rows.iter().filter(|r| !r.tls).map(|r| r.port).collect::<Vec<_>>(),
                rows.iter().filter(|r|  r.tls).map(|r| r.port).collect::<Vec<_>>(),
            )
        };
        announce_site(&state, site.listen_port, site.tls_port, &http, &https).await;
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
                x_frame_value  as \"x_frame_value!\",
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
        x_frame_value:  r.x_frame_value,
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
                x_frame_value  as \"x_frame_value!\",
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
        x_frame_value:  r.x_frame_value,
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

    let cert_id = match crate::acme::issue_and_store(
        &state.db, &site.server_name, &site.server_name
    ).await {
        Ok(id) => id,
        Err(e) => return flash_redirect(&back, "failed", &format!("{e}")),
    };

    sqlx::query!(
        "UPDATE sites SET cert_id = ?, acme_enabled = 1 WHERE id = ?",
        cert_id, site.id
    )
    .execute(&state.db)
    .await?;

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
async fn announce_site(
    state: &AppState,
    listen_port: i64,
    tls_port: Option<i64>,
    extra_http: &[i64],
    extra_https: &[i64],
) {
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

    // Extras bind immediately too, so a port added in the GUI answers without a
    // restart — the same promise the primary port already made.
    for (ports, tls) in [(extra_http, false), (extra_https, true)] {
        for p in ports {
            let _ = state
                .port_tx
                .send(crate::proxy::BindRequest { port: *p as u16, tls })
                .await;
        }
    }

    if let Err(e) = crate::tls::reload(&state.db).await {
        tracing::error!("Could not reload site certificates: {}", e);
    }
}

/// Split a port list into the primary and the rest.
///
/// One field per protocol, comma separated, because "80, 8080" is how someone
/// thinks about it. The first entry is the primary — `sites.listen_port` and
/// `sites.tls_port` — and the rest go to `site_ports`.
///
/// The split survives only because something has to be primary: the
/// HTTP-to-HTTPS redirect names one port, and inventing a rule for which of
/// several would be worse than taking the first. It is a storage detail, and
/// after this change it is no longer one the form asks anybody about.
fn split_ports(raw: &str) -> (Option<i64>, Vec<i64>, Vec<String>) {
    let (ports, bad) = parse_port_list(raw);
    let mut it = ports.into_iter();
    let first = it.next();
    (first, it.collect(), bad)
}

/// Validate the two extra-port fields, or return the message to show.
struct SitePorts {
    listen:      i64,
    tls:         Option<i64>,
    extra_http:  Vec<i64>,
    extra_https: Vec<i64>,
}

/// Read both port fields, or return the message to show.
fn validated_ports(
    form: &SiteForm,
    cfg: &crate::config::Config,
) -> std::result::Result<SitePorts, String> {
    let (listen_first, extra_http, bad_http) =
        split_ports(form.listen_port.as_deref().unwrap_or(""));
    let (tls_first, extra_https, bad_https) =
        split_ports(form.tls_port.as_deref().unwrap_or(""));

    let bad: Vec<String> = bad_http.into_iter().chain(bad_https).collect();
    if !bad.is_empty() {
        return Err(format!("Not a port number between 1 and 65535: {}", bad.join(", ")));
    }

    let Some(listen) = listen_first else {
        return Err("At least one HTTP port is required".to_string());
    };

    // Checked across both lists at once, which the old shape could not do: a
    // port named as both the primary and an extra was two fields agreeing, and
    // now it is one field repeating itself.
    let mut all: Vec<i64> = vec![listen];
    all.extend(&extra_http);
    if let Some(t) = tls_first { all.push(t); }
    all.extend(&extra_https);
    for (i, p) in all.iter().enumerate() {
        if all[..i].contains(p) {
            return Err(format!("Port {p} is listed twice"));
        }
        if *p == cfg.proxy.gui_port as i64 || *p == cfg.proxy.gui_tls_port as i64 {
            return Err(format!(
                "Port {p} is the management interface. Serving a site there would take away \
                 the means of changing it back."
            ));
        }
    }

    Ok(SitePorts { listen, tls: tls_first, extra_http, extra_https })
}

/// Parse a list of ports: comma or space separated, order significant only in
/// that the first is the primary.
///
/// A repeated port collapses to one — "80, 80" is redundant typing and its
/// meaning is not in doubt. The same port appearing in *both* fields does not
/// collapse and is refused, because that is a contradiction rather than a
/// repetition: a port cannot serve plain HTTP and TLS at once.
///
/// Returns the ports and the entries that were not ports. Rejected rather than
/// skipped, for the reason the trusted-proxy list is: a port someone believes
/// is open and is not is exactly the gap this field exists to close.
fn parse_port_list(raw: &str) -> (Vec<i64>, Vec<String>) {
    let mut ports = Vec::new();
    let mut bad   = Vec::new();
    for token in raw.split([',', ' ', '\n', '\t']).map(str::trim).filter(|t| !t.is_empty()) {
        match token.parse::<i64>() {
            Ok(p) if (1..=65535).contains(&p) => {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
            _ => bad.push(token.to_string()),
        }
    }
    (ports, bad)
}

/// Replace a site's extra ports.
///
/// Rewritten wholesale rather than diffed: the list is short, and a diff would
/// have to decide what a removed port means for a listener that is already
/// bound. It means nothing until a restart either way — a bound listener stays
/// bound for the life of the process, which the GUI says.
async fn save_extra_ports(
    db: &SqlitePool,
    site_id: i64,
    http: &[i64],
    https: &[i64],
) -> Result<()> {
    sqlx::query!("DELETE FROM site_ports WHERE site_id = ?", site_id)
        .execute(db)
        .await?;

    for (ports, tls) in [(http, false), (https, true)] {
        for port in ports {
            sqlx::query!(
                "INSERT INTO site_ports (site_id, port, tls) VALUES (?, ?, ?)
                 ON CONFLICT(site_id, port, tls) DO NOTHING",
                site_id, port, tls
            )
            .execute(db)
            .await?;
        }
    }
    Ok(())
}

/// The extra ports a site holds, for redisplay.
async fn extra_ports_of(db: &SqlitePool, site_id: i64) -> (String, String) {
    let rows = sqlx::query!(
        r#"SELECT port as "port!", tls as "tls!: bool" FROM site_ports
           WHERE site_id = ? ORDER BY port"#,
        site_id
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let join = |tls: bool| {
        rows.iter()
            .filter(|r| r.tls == tls)
            .map(|r| r.port.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    (join(false), join(true))
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
/// Parse an optional port from the form: empty → None, out of range → None.
///
/// Out of range becomes None rather than a clamped value: a mistyped port
/// should leave the site without HTTPS, which is visible, rather than
/// Parse waf_policy_id from the form: empty string → None, numeric string → Some(i64).
fn parse_policy_id(raw: &Option<String>) -> Option<i64> {
    raw.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
}

// ─── Flash redirect helper ───────────────────────────────


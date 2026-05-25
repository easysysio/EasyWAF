// =========================================================
// routes/certs.rs — EasyWAF
// Certificate management.
// Cert and key PEM are stored directly in the database —
// no filesystem involvement.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
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
pub struct Cert {
    pub id:         i64,
    pub name:       String,
    pub domain:     Option<String>,
    pub not_before: Option<String>,
    pub not_after:  Option<String>,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CertForm {
    pub name:     String,
    pub cert_pem: String,
    pub key_pem:  String,
}

#[derive(Deserialize)]
pub struct FlashQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

// ─── get_certs ───────────────────────────────────────────

pub async fn get_certs(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let certs = fetch_certs(&state).await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    "Certificate Management");
    ctx.insert("url",      "/certs");
    ctx.insert("certs",    &certs);
    ctx.insert("result",   &flash.result.unwrap_or_default());
    ctx.insert("msg",      &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("certs.html", &ctx)?)).into_response())
}

// ─── get_cert_new ────────────────────────────────────────

pub async fn get_cert_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    "Upload Certificate");
    ctx.insert("url",      "/certs");

    Ok((jar, Html(state.tera.render("cert_create.html", &ctx)?)).into_response())
}

// ─── post_cert_create ────────────────────────────────────

pub async fn post_cert_create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<CertForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return flash_redirect("/certs", "failed", "Certificate name is required");
    }

    // Parse the certificate to extract metadata.
    let (domain, not_before, not_after) = parse_cert_pem(&form.cert_pem);

    sqlx::query!(
        "INSERT OR REPLACE INTO certs (name, domain, not_before, not_after, cert_pem, key_pem)
         VALUES (?, ?, ?, ?, ?, ?)",
        name, domain, not_before, not_after, form.cert_pem, form.key_pem,
    )
    .execute(&state.db)
    .await?;

    flash_redirect("/certs", "success", &format!("Certificate {} saved successfully", name))
}

// ─── post_cert_delete ────────────────────────────────────

pub async fn post_cert_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    sqlx::query!("DELETE FROM certs WHERE name = ?", name)
        .execute(&state.db)
        .await?;

    flash_redirect("/certs", "success", &format!("Certificate {} deleted successfully", name))
}

// ─── Helpers ─────────────────────────────────────────────

async fn fetch_certs(state: &AppState) -> Result<Vec<Cert>> {
    let rows = sqlx::query!(
        "SELECT id as \"id!\", name, domain, not_before, not_after
         FROM certs ORDER BY name"
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows.into_iter().map(|r| Cert {
        id:         r.id,
        name:       r.name,
        domain:     r.domain,
        not_before: r.not_before,
        not_after:  r.not_after,
    }).collect())
}

/// Best-effort extraction of domain/dates from a PEM certificate using openssl CLI.
/// Returns (domain, not_before, not_after) — any field may be None on failure.
fn parse_cert_pem(pem: &str) -> (Option<String>, Option<String>, Option<String>) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let run = |args: &[&str]| -> Option<String> {
        let mut child = Command::new("openssl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.as_mut()?.write_all(pem.as_bytes()).ok()?;
        let out = child.wait_with_output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    let domain = run(&["x509", "-noout", "-subject", "-in", "/dev/stdin"])
        .and_then(|s| {
            s.split(", ")
                .find(|f| f.starts_with("CN="))
                .map(|f| f[3..].to_string())
        });

    let not_before = run(&["x509", "-noout", "-startdate", "-in", "/dev/stdin"])
        .map(|s| s.trim_start_matches("notBefore=").to_string());

    let not_after = run(&["x509", "-noout", "-enddate", "-in", "/dev/stdin"])
        .map(|s| s.trim_start_matches("notAfter=").to_string());

    (domain, not_before, not_after)
}

fn flash_redirect(path: &str, result: &str, msg: &str) -> Result<Response> {
    let msg_enc = urlencoding::encode(msg).into_owned();
    Ok(Redirect::to(&format!("{}?result={}&msg={}", path, result, msg_enc)).into_response())
}

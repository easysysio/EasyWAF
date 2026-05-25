// =========================================================
// routes/certs.rs — EasyWAF
// Certificate management: list, upload, delete.
// Cert and key files are written to nginx.cert_dir.
// Metadata (domain, dates) is extracted via openssl and stored in DB.
// =========================================================

use crate::{
    auth::get_session,
    error::{AppError, Result},
    nginx::openssl_cert_info,
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use std::fs;
use tera::Context;

// ─── Models ──────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Cert {
    pub id: i64,
    pub name: String,
    pub domain: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CertForm {
    pub name: String,
    pub cert: String,
    pub key: String,
}

#[derive(Deserialize)]
pub struct FlashQuery {
    pub result: Option<String>,
    pub msg: Option<String>,
}

// ─── get_certs ───────────────────────────────────────────

/// GET /certs — List all certificates.
pub async fn get_certs(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let certs = sqlx::query_as!(
        Cert,
        "SELECT id as \"id!\", name, domain, not_before, not_after FROM certs ORDER BY name"
    )
    .fetch_all(&state.db)
    .await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Certificate Management");
    ctx.insert("url", "/certs");
    ctx.insert("certs", &certs);
    ctx.insert("result", &flash.result.unwrap_or_default());
    ctx.insert("msg", &flash.msg.unwrap_or_default());

    let html = state.tera.render("certs.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// ─── get_cert_new ────────────────────────────────────────

/// GET /certs/new — Show the upload-cert form.
pub async fn get_cert_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Upload Certificate");
    ctx.insert("url", "/certs");

    let html = state.tera.render("cert_create.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// ─── post_cert_create ────────────────────────────────────

/// POST /certs/create — Write cert + key files and store metadata in DB.
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
        return Ok(Redirect::to("/certs?result=failed&msg=Certificate+name+is+required").into_response());
    }

    // Ensure cert directory exists.
    fs::create_dir_all(&state.config.nginx.cert_dir).map_err(AppError::Io)?;

    let cert_path = format!("{}/{}.cert", state.config.nginx.cert_dir, name);
    let key_path = format!("{}/{}.key", state.config.nginx.cert_dir, name);

    fs::write(&cert_path, form.cert.as_bytes()).map_err(AppError::Io)?;
    fs::write(&key_path, form.key.as_bytes()).map_err(AppError::Io)?;

    // Extract metadata from the cert file.
    let (domain_raw, not_before_raw, not_after_raw) = openssl_cert_info(&cert_path);
    let domain = parse_openssl_field(&domain_raw, "CN");
    let not_before = trim_openssl_date(&not_before_raw, "notBefore=");
    let not_after = trim_openssl_date(&not_after_raw, "notAfter=");

    sqlx::query!(
        "INSERT OR REPLACE INTO certs (name, domain, not_before, not_after) VALUES (?, ?, ?, ?)",
        name, domain, not_before, not_after
    )
    .execute(&state.db)
    .await?;

    let msg = urlencoding::encode(&format!("Certificate {} saved successfully", name)).into_owned();
    Ok(Redirect::to(&format!("/certs?result=success&msg={}", msg)).into_response())
}

// ─── post_cert_delete ────────────────────────────────────

/// POST /certs/:name/delete — Remove cert + key files and DB row.
pub async fn post_cert_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let _ = fs::remove_file(format!("{}/{}.cert", state.config.nginx.cert_dir, name));
    let _ = fs::remove_file(format!("{}/{}.key", state.config.nginx.cert_dir, name));

    sqlx::query!("DELETE FROM certs WHERE name = ?", name)
        .execute(&state.db)
        .await?;

    let msg = urlencoding::encode(&format!("Certificate {} deleted successfully", name)).into_owned();
    Ok(Redirect::to(&format!("/certs?result=success&msg={}", msg)).into_response())
}

// ─── Helpers ─────────────────────────────────────────────

/// Extract a field value from openssl subject output, e.g. "CN=example.com".
fn parse_openssl_field(subject: &str, field: &str) -> Option<String> {
    subject
        .split(", ")
        .find(|s| s.starts_with(&format!("{}=", field)))
        .map(|s| s[field.len() + 1..].to_string())
}

/// Strip the label prefix from an openssl date line, e.g. "notBefore=Jun 1 ...".
fn trim_openssl_date(line: &str, prefix: &str) -> Option<String> {
    if line.starts_with(prefix) {
        Some(line[prefix.len()..].trim().to_string())
    } else {
        None
    }
}

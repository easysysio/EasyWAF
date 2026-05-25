// =========================================================
// routes/login.rs — EasyWAF
// Login / logout handlers.
// =========================================================

use crate::{
    auth::{clear_session, get_session, set_session, SessionData},
    error::Result,
    AppState,
};
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use bcrypt::verify;
use serde::Deserialize;
use sqlx::SqlitePool;
use tera::Context;

// ─── LoginForm ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginForm {
    pub user: String,
    pub pass: String,
}

// ─── get_login ───────────────────────────────────────────

/// GET /login — Render the login page.
pub async fn get_login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    // Already logged in → go to dashboard.
    if get_session(&jar).is_some() {
        return Ok(Redirect::to("/").into_response());
    }
    render_login(&state, "", "", jar).await
}

// ─── post_login ──────────────────────────────────────────

/// POST /login — Validate credentials and start session.
pub async fn post_login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response> {
    match authenticate(&state.db, &form.user, &form.pass).await {
        Some(session) => {
            let jar = set_session(jar, &session);
            Ok((jar, Redirect::to("/")).into_response())
        }
        None => render_login(&state, "failed", "Bad username or password", jar).await,
    }
}

// ─── get_logout ──────────────────────────────────────────

/// GET /logout — Clear session and redirect to login.
pub async fn get_logout(jar: SignedCookieJar) -> impl IntoResponse {
    let jar = clear_session(jar);
    (jar, Redirect::to("/login"))
}

// ─── authenticate ────────────────────────────────────────

/// Look up user in DB and verify password with bcrypt. Returns SessionData on success.
async fn authenticate(db: &SqlitePool, username: &str, password: &str) -> Option<SessionData> {
    let row = sqlx::query!(
        "SELECT id as \"id!\", password_hash FROM users WHERE username = ?",
        username
    )
    .fetch_optional(db)
    .await
    .ok()??;

    if verify(password, &row.password_hash).unwrap_or(false) {
        Some(SessionData {
            user_id: row.id,
            username: username.to_string(),
        })
    } else {
        None
    }
}

// ─── render_login ────────────────────────────────────────

/// Render the login template with optional result/msg.
async fn render_login(
    state: &AppState,
    result: &str,
    msg: &str,
    jar: SignedCookieJar,
) -> Result<Response> {
    let mut ctx = Context::new();
    ctx.insert("result", result);
    ctx.insert("msg", msg);
    let html = state.tera.render("login.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

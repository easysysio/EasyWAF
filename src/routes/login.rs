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
    // Validated against the database, not merely decoded.
    //
    // Deciding "already signed in" from the cookie alone, while every other
    // page decides it from the database, is what produced a redirect loop in
    // 0.8.0: this page sent the holder of a stale cookie to the dashboard, and
    // the dashboard sent them back here. A cookie goes stale whenever a
    // session is ended — a password change, a role change, a suspension — so
    // the loop was reachable by ordinary use, and the only escape was clearing
    // cookies by hand.
    if crate::auth::authenticate(&state.db, &jar).await.is_some() {
        return Ok(Redirect::to("/").into_response());
    }

    // Nothing to sign in to yet. Every other handler already sends an
    // unauthenticated caller here, so this one redirect covers the whole GUI
    // without a middleware layer inspecting the database on every request.
    if crate::routes::setup::needs_setup(&state.db).await {
        return Ok(Redirect::to("/setup").into_response());
    }

    // A cookie that did not authenticate is spent — an ended session, a
    // suspended or deleted account. Dropped here so the browser stops
    // presenting it, rather than carrying it to every subsequent request.
    let jar = if get_session(&jar).is_some() {
        crate::auth::clear_session(jar)
    } else {
        jar
    };
    render_login(&state, "", "", jar).await
}

// ─── post_login ──────────────────────────────────────────

/// POST /login — Validate credentials and start session.
pub async fn post_login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response> {
    match verify_credentials(&state.db, &form.user, &form.pass).await {
        Some(session) => {
            // Recorded so the account list can show a dormant account, which
            // is the usual reason to suspend one. Failure to write it must not
            // fail the sign-in: it is a convenience, not part of the decision.
            if let Err(e) = sqlx::query!(
                "UPDATE users SET last_login = datetime('now') WHERE id = ?",
                session.user_id
            )
            .execute(&state.db)
            .await
            {
                tracing::warn!(user = %session.username, "Could not record the sign-in time: {e}");
            }
            tracing::info!(user = %session.username, role = %session.role, "Signed in");
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

// ─── verify_credentials ──────────────────────────────────

/// Look up the account and verify the password. `None` on any failure.
///
/// A suspended account is refused here as well as in `auth::authenticate`, so
/// it cannot obtain a new session in the first place rather than obtaining one
/// that is rejected on its next request.
///
/// The failure is deliberately not distinguished between "no such account",
/// "wrong password" and "suspended": the caller reports one message for all
/// three, so a login form cannot be used to enumerate which accounts exist.
async fn verify_credentials(
    db: &SqlitePool,
    username: &str,
    password: &str,
) -> Option<SessionData> {
    let row = sqlx::query!(
        r#"SELECT id as "id!", password_hash, role as "role!",
                  enabled as "enabled!: i64", session_epoch as "session_epoch!"
           FROM users WHERE username = ?"#,
        username
    )
    .fetch_optional(db)
    .await
    .ok()??;

    if !verify(password, &row.password_hash).unwrap_or(false) {
        return None;
    }
    if row.enabled == 0 {
        tracing::warn!(username, "Sign-in refused: the account is suspended");
        return None;
    }

    // The epoch is captured now, so this cookie survives until something
    // deliberately ends it — a password change, a role change, a suspension.
    Some(SessionData {
        user_id:  row.id,
        username: username.to_string(),
        role:     row.role,
        epoch:    row.session_epoch,
    })
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

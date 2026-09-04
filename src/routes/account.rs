// =========================================================
// routes/account.rs — EasyWAF
// The signed-in user changing their own password.
//
// Deliberately "change my own password" rather than user
// administration: it is the whole of what a single-account
// appliance needs, it closes the unchangeable admin/admin
// gap now, and it survives unchanged into multi-user work
// rather than being thrown away by it.
//
// It exists here rather than earlier because the management
// interface is served over TLS. A password-change form on a
// plain-HTTP port would put the new password on the wire in
// cleartext — worse than the default it replaces.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use bcrypt::{hash, verify, DEFAULT_COST};
use serde::Deserialize;
use sqlx::SqlitePool;
use tera::Context;

use super::settings::FlashQuery;

/// Shortest password accepted.
///
/// Eight is not much, but it is enforced against a *new* password only, so it
/// cannot lock anyone out of an existing account — and it is comfortably more
/// than the five characters of `admin` this screen exists to replace.
pub const MIN_PASSWORD_LEN: usize = 8;

/// bcrypt hashes at most 72 bytes and silently ignores the rest, so a longer
/// passphrase would be quietly truncated and the discarded tail would count
/// for nothing. Rejecting it is honest; accepting it would hand someone a
/// false sense of how strong their password is.
pub const MAX_PASSWORD_BYTES: usize = 72;

// ─── Form ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PasswordForm {
    pub current_password: String,
    pub new_password:     String,
    pub confirm_password: String,
}

// ─── get_account ─────────────────────────────────────────

/// GET /account — the password-change form.
pub async fn get_account(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    // Shown as a warning on the page itself. An operator who never reads the
    // release notes still meets it at the one screen that can fix it.
    let using_default = is_default_password(&state.db, &session.username).await;

    let mut ctx = Context::new();
    ctx.insert("username",       &session.username);
    ctx.insert("title",          "Account");
    ctx.insert("url",            "/account");
    ctx.insert("using_default",  &using_default);
    ctx.insert("min_length",     &MIN_PASSWORD_LEN);
    ctx.insert("result",         &flash.result.unwrap_or_default());
    ctx.insert("msg",            &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("account.html", &ctx)?)).into_response())
}

// ─── post_account_password ───────────────────────────────

/// POST /account/password — verify the current password and replace it.
///
/// The current password is required even though the session already proves who
/// this is: it is what stops an unattended browser, or a request forged against
/// a logged-in session, from silently changing the credential and locking the
/// real operator out.
pub async fn post_account_password(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<PasswordForm>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let stored = match password_hash(&state.db, &session.username).await {
        Some(h) => h,
        // The account behind a valid session is gone. Clearing the session is
        // the only sensible response; there is nothing to change.
        None => return flash_redirect("/login", "failed", "Your account no longer exists"),
    };

    if !verify(&form.current_password, &stored).unwrap_or(false) {
        return flash_redirect("/account", "failed", "Current password is not correct");
    }

    if form.new_password != form.confirm_password {
        return flash_redirect("/account", "failed", "The two new passwords do not match");
    }

    // Counted in characters for the message, checked in bytes for the bcrypt
    // limit — the two differ the moment a password is not pure ASCII.
    if form.new_password.chars().count() < MIN_PASSWORD_LEN {
        return flash_redirect(
            "/account",
            "failed",
            &format!("New password must be at least {MIN_PASSWORD_LEN} characters"),
        );
    }

    if form.new_password.len() > MAX_PASSWORD_BYTES {
        return flash_redirect(
            "/account",
            "failed",
            &format!(
                "New password must be {MAX_PASSWORD_BYTES} bytes or fewer — bcrypt ignores \
                 anything beyond that, so the rest would count for nothing"
            ),
        );
    }

    if form.new_password == form.current_password {
        return flash_redirect("/account", "failed", "The new password is the same as the current one");
    }

    let new_hash = hash(&form.new_password, DEFAULT_COST)
        .map_err(|e| crate::error::AppError::Internal(format!("password hashing failed: {e}")))?;

    sqlx::query!(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        new_hash,
        session.username
    )
    .execute(&state.db)
    .await?;

    tracing::info!("Password changed for user '{}'", session.username);

    flash_redirect("/account", "success", "Password changed")
}

// ─── DB helpers ──────────────────────────────────────────

/// The stored bcrypt hash for a username, if the account exists.
async fn password_hash(db: &SqlitePool, username: &str) -> Option<String> {
    sqlx::query_scalar!("SELECT password_hash FROM users WHERE username = ?", username)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// Whether an account still has the seeded `admin` password.
///
/// One bcrypt verify, on a page that is not on any hot path. Checking the hash
/// rather than a stored flag means it cannot drift out of step with reality —
/// including when the password was changed directly in the database.
pub async fn is_default_password(db: &SqlitePool, username: &str) -> bool {
    match password_hash(db, username).await {
        Some(h) => verify(crate::DEFAULT_PASSWORD, &h).unwrap_or(false),
        None    => false,
    }
}

// ─── Flash redirect helper ───────────────────────────────

fn flash_redirect(path: &str, result: &str, msg: &str) -> Result<Response> {
    let msg_enc = urlencoding::encode(msg).into_owned();
    Ok(Redirect::to(&format!("{}?result={}&msg={}", path, result, msg_enc)).into_response())
}

// =========================================================
// routes/setup.rs — EasyWAF
// First run: the administrator creates their own account.
//
// Replaces seeding admin/admin. A default credential on a
// security appliance is only as good as the operator's
// memory to change it, and the ones that are never changed
// are the ones nobody was told about. Asking at first run
// means an installation cannot exist in that state at all.
//
// There is no bootstrap window to race: the form is the only
// thing the GUI will serve until an account exists, and it
// stops existing the moment one does.
// =========================================================

use crate::{error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use bcrypt::{hash, DEFAULT_COST};
use serde::Deserialize;
use sqlx::SqlitePool;
use tera::Context;

use super::settings::FlashQuery;

/// Same bounds the password-change screen enforces. They are defined there
/// because that is where they were first needed; both screens must agree, or
/// one would accept a password the other would refuse to keep.
pub use super::account::{MAX_PASSWORD_BYTES, MIN_PASSWORD_LEN};

/// Longest username accepted — a display name, not a document.
const MAX_USERNAME_LEN: usize = 64;

// ─── needs_setup ─────────────────────────────────────────

/// True when no account exists yet, so the GUI has nothing to authenticate.
///
/// On a database error this returns false rather than true. Guessing "no users"
/// from a failed query would expose the account-creation form on a running
/// installation, which is the worse of the two mistakes by a wide margin: the
/// other is a login page that cannot be signed into until the database
/// recovers.
pub async fn needs_setup(db: &SqlitePool) -> bool {
    matches!(
        sqlx::query_scalar!("SELECT COUNT(*) FROM users").fetch_one(db).await,
        Ok(0)
    )
}

// ─── Form ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SetupForm {
    pub username:         String,
    pub password:         String,
    pub confirm_password: String,
}

// ─── get_setup ───────────────────────────────────────────

/// GET /setup — the first-run account form.
pub async fn get_setup(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    if !needs_setup(&state.db).await {
        return Ok(Redirect::to("/login").into_response());
    }

    let mut ctx = Context::new();
    ctx.insert("title",      "Welcome to EasyWAF");
    ctx.insert("min_length", &MIN_PASSWORD_LEN);
    ctx.insert("result",     &flash.result.unwrap_or_default());
    ctx.insert("msg",        &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("setup.html", &ctx)?)).into_response())
}

// ─── post_setup ──────────────────────────────────────────

/// POST /setup — create the first account.
///
/// Requires no authentication, and must therefore be impossible to reach once
/// an account exists — otherwise it is a route for creating an administrator on
/// a running appliance. The check is repeated inside the insert rather than
/// only here, so two requests arriving together cannot both pass it.
pub async fn post_setup(
    State(state): State<AppState>,
    Form(form): Form<SetupForm>,
) -> Result<Response> {
    if !needs_setup(&state.db).await {
        return Ok(Redirect::to("/login").into_response());
    }

    let username = form.username.trim();

    if username.is_empty() {
        return flash_redirect("/setup", "failed", "Choose a username");
    }
    if username.chars().count() > MAX_USERNAME_LEN {
        return flash_redirect(
            "/setup",
            "failed",
            &format!("Username must be {MAX_USERNAME_LEN} characters or fewer"),
        );
    }
    if form.password != form.confirm_password {
        return flash_redirect("/setup", "failed", "The two passwords do not match");
    }
    if form.password.chars().count() < MIN_PASSWORD_LEN {
        return flash_redirect(
            "/setup",
            "failed",
            &format!("Password must be at least {MIN_PASSWORD_LEN} characters"),
        );
    }
    if form.password.len() > MAX_PASSWORD_BYTES {
        return flash_redirect(
            "/setup",
            "failed",
            &format!(
                "Password must be {MAX_PASSWORD_BYTES} bytes or fewer — bcrypt ignores \
                 anything beyond that, so the rest would count for nothing"
            ),
        );
    }

    let password_hash = hash(&form.password, DEFAULT_COST)
        .map_err(|e| crate::error::AppError::Internal(format!("password hashing failed: {e}")))?;

    // The SELECT in the same statement is what makes the race safe: a second
    // request that arrives after the first has committed inserts nothing,
    // because by then the table is not empty.
    let inserted = sqlx::query!(
        "INSERT INTO users (username, password_hash)
         SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)",
        username,
        password_hash
    )
    .execute(&state.db)
    .await?
    .rows_affected();

    if inserted == 0 {
        return Ok(Redirect::to("/login").into_response());
    }

    tracing::info!("First-run setup complete — created the account '{}'", username);

    // To the login page rather than straight in: signing in proves the password
    // was stored as typed, at the moment it is still fresh in mind, instead of
    // at the next session when it is not.
    flash_redirect("/login", "success", "Account created — sign in to continue")
}

// ─── Flash redirect helper ───────────────────────────────

fn flash_redirect(path: &str, result: &str, msg: &str) -> Result<Response> {
    let msg_enc = urlencoding::encode(msg).into_owned();
    Ok(Redirect::to(&format!("{}?result={}&msg={}", path, result, msg_enc)).into_response())
}

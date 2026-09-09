// =========================================================
// routes/accounts.rs — EasyWAF
// Managing who may sign in, and what they may do.
//
// Every action here can lock somebody out, so the module is
// built around one question asked before each of them: would
// this leave the installation with no enabled administrator?
// See `other_enabled_admins`. That is the only guard the GUI
// cannot recover from getting wrong — everything else is
// fixable by an administrator who can still sign in.
// =========================================================

use crate::auth::{
    end_all_sessions, is_known_role, Admin, ROLES, ROLE_ADMIN, ROLE_VIEWER,
};
use crate::routes::account::{MAX_PASSWORD_BYTES, MIN_PASSWORD_LEN};
use crate::routes::flash_redirect;
use crate::{error::Result, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use bcrypt::{hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use tera::Context;

use super::policy::FlashQuery;

// ─── Models ──────────────────────────────────────────────

/// One account, as the list shows it.
#[derive(Debug, Serialize)]
pub struct Account {
    pub id:         i64,
    pub username:   String,
    pub role:       String,
    pub enabled:    bool,
    pub created_at: String,
    /// `None` for an account that has never signed in, and for one that last
    /// did so before 0.8.0 started recording it. Shown as "never" either way,
    /// which is honest about not knowing rather than inventing a date.
    pub last_login: Option<String>,
    /// The signed-in administrator's own row, which the page treats
    /// differently: you cannot delete or suspend yourself.
    pub is_self:    bool,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NewAccountForm {
    pub username:         String,
    pub password:         String,
    pub confirm_password: String,
    pub role:             String,
}

#[derive(Debug, Deserialize)]
pub struct RoleForm {
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordForm {
    pub password:         String,
    pub confirm_password: String,
}

// ─── other_enabled_admins ────────────────────────────────

/// How many enabled administrators there are *besides* this account.
///
/// The one question worth asking before deleting, suspending or demoting
/// anyone. Zero means the action would leave nobody able to administer the
/// installation, and no administrator means no way to undo it — the only
/// remedy would be editing the database by hand.
///
/// Counted rather than assumed: "there is surely another admin" is exactly the
/// belief that is wrong at 2am on a machine with one account.
async fn other_enabled_admins(db: &sqlx::SqlitePool, exclude_id: i64) -> Result<i64> {
    let n = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "n!: i64" FROM users
           WHERE role = ? AND enabled = 1 AND id != ?"#,
        ROLE_ADMIN, exclude_id
    )
    .fetch_one(db)
    .await?;
    Ok(n)
}

/// Refuse an action that would remove the last enabled administrator.
///
/// Returns the message to show, or `None` when the action is safe.
async fn would_orphan(db: &sqlx::SqlitePool, target_id: i64, what: &str) -> Result<Option<String>> {
    if other_enabled_admins(db, target_id).await? > 0 {
        return Ok(None);
    }
    // Only a problem if the target is currently an enabled admin — demoting a
    // viewer removes no administrator.
    let is_admin: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "n!: i64" FROM users
           WHERE id = ? AND role = ? AND enabled = 1"#,
        target_id, ROLE_ADMIN
    )
    .fetch_one(db)
    .await?;

    if is_admin == 0 {
        return Ok(None);
    }
    Ok(Some(format!(
        "Refused: this is the only enabled administrator, and {what} would leave \
         nobody able to administer this installation. Create or enable another \
         administrator first."
    )))
}

// ─── get_accounts ────────────────────────────────────────

/// GET /accounts — every account, with what it may do and when it last signed in.
pub async fn get_accounts(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Admin(session): Admin,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let rows = sqlx::query!(
        r#"SELECT id as "id!", username, role as "role!", enabled as "enabled!: i64",
                  created_at as "created_at!", last_login
           FROM users ORDER BY role, username"#
    )
    .fetch_all(&state.db)
    .await?;

    let accounts: Vec<Account> = rows
        .into_iter()
        .map(|r| Account {
            is_self:    r.id == session.user_id,
            id:         r.id,
            username:   r.username,
            role:       r.role,
            enabled:    r.enabled != 0,
            created_at: r.created_at,
            last_login: r.last_login,
        })
        .collect();

    // Shown on the page so an administrator can see whether they are the last
    // one before trying something the guard will refuse.
    let admin_count = accounts.iter().filter(|a| a.role == ROLE_ADMIN && a.enabled).count();

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",       "Accounts");
    ctx.insert("url",         "/accounts");
    ctx.insert("accounts",    &accounts);
    ctx.insert("admin_count", &admin_count);
    ctx.insert("roles",       &ROLES);
    ctx.insert("min_length",  &MIN_PASSWORD_LEN);
    ctx.insert("result",      &flash.result.unwrap_or_default());
    ctx.insert("msg",         &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("accounts.html", &ctx)?)).into_response())
}

// ─── post_account_create ─────────────────────────────────

pub async fn post_account_create(
    State(state): State<AppState>,
    Admin(session): Admin,
    Form(form): Form<NewAccountForm>,
) -> Result<Response> {
    let back = "/accounts";
    let username = form.username.trim();

    if username.is_empty() {
        return flash_redirect(back, "failed", "A username is required.");
    }
    if !is_known_role(&form.role) {
        return flash_redirect(back, "failed", "Choose a role of admin or viewer.");
    }
    if let Some(msg) = check_password(&form.password, &form.confirm_password) {
        return flash_redirect(back, "failed", &msg);
    }

    let password_hash = hash(&form.password, DEFAULT_COST)
        .map_err(|e| crate::error::AppError::Internal(format!("password hashing failed: {e}")))?;

    let done = sqlx::query!(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        username, password_hash, form.role
    )
    .execute(&state.db)
    .await;

    match done {
        Ok(_) => {
            tracing::info!(by = %session.username, account = username, role = %form.role,
                           "Account created");
            flash_redirect(back, "success",
                &format!("Created {username} as {}.", form.role))
        }
        Err(e) if e.to_string().contains("UNIQUE") =>
            flash_redirect(back, "failed", &format!("An account named {username} already exists.")),
        Err(e) => flash_redirect(back, "failed", &format!("Could not create the account: {e}")),
    }
}

// ─── post_account_role ───────────────────────────────────

/// Change what an account may do.
///
/// Ends its sessions: the role is read from the row on every request, so the
/// change already takes effect immediately — but a demoted administrator
/// holding an open page should be made to sign in again rather than discover
/// the change as a sudden 403 on their next click.
pub async fn post_account_role(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(id): Path<i64>,
    Form(form): Form<RoleForm>,
) -> Result<Response> {
    let back = "/accounts";

    if !is_known_role(&form.role) {
        return flash_redirect(back, "failed", "Choose a role of admin or viewer.");
    }
    if form.role == ROLE_VIEWER {
        if let Some(msg) = would_orphan(&state.db, id, "demoting it").await? {
            return flash_redirect(back, "failed", &msg);
        }
    }

    let done = sqlx::query!("UPDATE users SET role = ? WHERE id = ?", form.role, id)
        .execute(&state.db)
        .await?;
    if done.rows_affected() == 0 {
        return flash_redirect(back, "failed", "That account no longer exists.");
    }
    end_all_sessions(&state.db, id).await?;

    tracing::info!(by = %session.username, account = id, role = %form.role, "Role changed");
    flash_redirect(back, "success",
        &format!("Role changed to {}. That account has been signed out.", form.role))
}

// ─── post_account_toggle ─────────────────────────────────

/// Suspend or restore an account.
///
/// Suspending keeps the row, and with it the account's history and whatever
/// the audit trail will later attribute to it. Deleting loses both, so this is
/// the action to reach for when someone leaves.
pub async fn post_account_toggle(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(id): Path<i64>,
) -> Result<Response> {
    let back = "/accounts";

    if id == session.user_id {
        return flash_redirect(back, "failed",
            "An account cannot suspend itself. Ask another administrator.");
    }

    let enabled: i64 = match sqlx::query_scalar!(
        r#"SELECT enabled as "enabled!: i64" FROM users WHERE id = ?"#, id
    )
    .fetch_optional(&state.db)
    .await?
    {
        Some(v) => v,
        None    => return flash_redirect(back, "failed", "That account no longer exists."),
    };

    if enabled == 1 {
        if let Some(msg) = would_orphan(&state.db, id, "suspending it").await? {
            return flash_redirect(back, "failed", &msg);
        }
    }

    let now = if enabled == 1 { 0 } else { 1 };
    sqlx::query!("UPDATE users SET enabled = ? WHERE id = ?", now, id)
        .execute(&state.db)
        .await?;

    // A suspended account must not keep a session it already holds.
    if now == 0 {
        end_all_sessions(&state.db, id).await?;
    }

    tracing::info!(by = %session.username, account = id, enabled = now, "Account availability changed");
    flash_redirect(back, "success", if now == 0 {
        "Account suspended and signed out. Its history is kept; restore it at any time."
    } else {
        "Account restored. It can sign in again."
    })
}

// ─── post_account_password ───────────────────────────────

/// Set another account's password.
///
/// No current password is asked for, because an administrator resetting an
/// account they do not own does not have it — that is the point. The account
/// is signed out everywhere, so a password reset ends whatever sessions the
/// old password left behind.
pub async fn post_account_password(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(id): Path<i64>,
    Form(form): Form<PasswordForm>,
) -> Result<Response> {
    let back = "/accounts";

    if let Some(msg) = check_password(&form.password, &form.confirm_password) {
        return flash_redirect(back, "failed", &msg);
    }

    let password_hash = hash(&form.password, DEFAULT_COST)
        .map_err(|e| crate::error::AppError::Internal(format!("password hashing failed: {e}")))?;

    let done = sqlx::query!(
        "UPDATE users SET password_hash = ? WHERE id = ?", password_hash, id
    )
    .execute(&state.db)
    .await?;
    if done.rows_affected() == 0 {
        return flash_redirect(back, "failed", "That account no longer exists.");
    }
    end_all_sessions(&state.db, id).await?;

    tracing::info!(by = %session.username, account = id, "Password reset by an administrator");
    flash_redirect(back, "success",
        "Password set. That account has been signed out everywhere.")
}

// ─── post_account_signout ────────────────────────────────

/// End every session an account holds, without changing anything else.
///
/// For the laptop left on a train: the password is still good, and the person
/// should not have to change it to close the sessions it opened.
pub async fn post_account_signout(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(id): Path<i64>,
) -> Result<Response> {
    let back = "/accounts";

    let exists: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "n!: i64" FROM users WHERE id = ?"#, id
    )
    .fetch_one(&state.db)
    .await?;
    if exists == 0 {
        return flash_redirect(back, "failed", "That account no longer exists.");
    }

    end_all_sessions(&state.db, id).await?;
    tracing::info!(by = %session.username, account = id, "Sessions ended");

    flash_redirect(back, "success", if id == session.user_id {
        "Signed out everywhere. This browser included — you will be asked to sign in again."
    } else {
        "That account has been signed out everywhere."
    })
}

// ─── post_account_delete ─────────────────────────────────

pub async fn post_account_delete(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(id): Path<i64>,
) -> Result<Response> {
    let back = "/accounts";

    if id == session.user_id {
        return flash_redirect(back, "failed",
            "An account cannot delete itself. Ask another administrator, or suspend it instead.");
    }
    if let Some(msg) = would_orphan(&state.db, id, "deleting it").await? {
        return flash_redirect(back, "failed", &msg);
    }

    let done = sqlx::query!("DELETE FROM users WHERE id = ?", id)
        .execute(&state.db)
        .await?;
    if done.rows_affected() == 0 {
        return flash_redirect(back, "failed", "That account no longer exists.");
    }

    tracing::info!(by = %session.username, account = id, "Account deleted");
    flash_redirect(back, "success", "Account deleted.")
}

// ─── Helpers ─────────────────────────────────────────────

/// The password rules, shared with first-run setup and self-service change so
/// there is one answer to "what makes a password acceptable".
fn check_password(password: &str, confirm: &str) -> Option<String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Some(format!("Password must be at least {MIN_PASSWORD_LEN} characters."));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Some(format!(
            "Password must be at most {MAX_PASSWORD_BYTES} bytes — bcrypt ignores anything beyond that."
        ));
    }
    if password != confirm {
        return Some("The two passwords do not match.".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    /// A table of accounts: (id, role, enabled).
    async fn db_with(users: &[(i64, &str, i64)]) -> SqlitePool {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::raw_sql(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL,
                password_hash TEXT NOT NULL DEFAULT '', role TEXT NOT NULL,
                enabled INTEGER NOT NULL, session_epoch INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT '', last_login TEXT);"
        ).execute(&db).await.unwrap();
        for (id, role, enabled) in users {
            sqlx::query("INSERT INTO users (id,username,role,enabled) VALUES (?,?,?,?)")
                .bind(id).bind(format!("u{id}")).bind(*role).bind(enabled)
                .execute(&db).await.unwrap();
        }
        db
    }

    #[tokio::test]
    async fn the_only_admin_cannot_be_removed() {
        // The state that has no remedy: no administrator means no way to undo
        // it from the GUI at all.
        let db = db_with(&[(1, ROLE_ADMIN, 1), (2, ROLE_VIEWER, 1)]).await;
        assert!(would_orphan(&db, 1, "deleting it").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn one_of_two_admins_can_be_removed() {
        let db = db_with(&[(1, ROLE_ADMIN, 1), (2, ROLE_ADMIN, 1)]).await;
        assert!(would_orphan(&db, 1, "deleting it").await.unwrap().is_none());
        assert!(would_orphan(&db, 2, "deleting it").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_suspended_admin_does_not_count_as_one() {
        // The trap: two admin rows, but only one can actually sign in, so
        // removing that one leaves nobody. Counting rows rather than *enabled*
        // rows would allow it.
        let db = db_with(&[(1, ROLE_ADMIN, 1), (2, ROLE_ADMIN, 0)]).await;
        assert!(would_orphan(&db, 1, "deleting it").await.unwrap().is_some(),
                "a suspended admin was counted as a remaining administrator");
    }

    #[tokio::test]
    async fn removing_a_viewer_is_never_orphaning() {
        // Even when there is exactly one admin, acting on a viewer removes no
        // administrator and must not be refused.
        let db = db_with(&[(1, ROLE_ADMIN, 1), (2, ROLE_VIEWER, 1)]).await;
        assert!(would_orphan(&db, 2, "deleting it").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn removing_an_already_suspended_admin_is_allowed() {
        // It is not an enabled administrator, so it is not the one holding the
        // installation up — refusing here would strand a suspended account
        // that can never be deleted.
        let db = db_with(&[(1, ROLE_ADMIN, 1), (2, ROLE_ADMIN, 0)]).await;
        assert!(would_orphan(&db, 2, "deleting it").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_installation_with_no_admin_at_all_refuses_nothing() {
        // Nothing to protect. Reaching this state should be impossible, and if
        // it happens the guard must not also block the repair.
        let db = db_with(&[(1, ROLE_VIEWER, 1)]).await;
        assert!(would_orphan(&db, 1, "deleting it").await.unwrap().is_none());
    }

    #[test]
    fn the_password_rules_are_the_same_ones_setup_uses() {
        assert!(check_password("short", "short").is_some());
        assert!(check_password("longenough123", "different").is_some(), "mismatch not caught");
        assert!(check_password("longenough123", "longenough123").is_none());
        // bcrypt silently ignores past 72 bytes, so a longer password would
        // not mean what the person typing it thinks it means.
        let too_long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(check_password(&too_long, &too_long).is_some());
    }
}

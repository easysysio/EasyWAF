// =========================================================
// auth.rs — EasyWAF
// Session cookie helpers and authentication utilities.
// Session data is stored as signed JSON in a cookie using
// axum-extra's SignedCookieJar + a Key derived from config.secret.
// =========================================================

use axum_extra::extract::cookie::{Cookie, Key, SameSite, SignedCookieJar};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use time::Duration;

pub const SESSION_COOKIE: &str = "easywaf_session";

/// Sees and changes everything.
pub const ROLE_ADMIN: &str = "admin";
/// Sees the dashboard, traffic and the read-only pages; changes nothing.
pub const ROLE_VIEWER: &str = "viewer";

/// The roles that exist, for validating what arrives from a form.
pub const ROLES: [&str; 2] = [ROLE_ADMIN, ROLE_VIEWER];

/// Is this a role the product knows about?
pub fn is_known_role(role: &str) -> bool {
    ROLES.contains(&role)
}

/// Settings key holding the generated cookie signing key.
const KEY_COOKIE_SECRET: &str = "cookie_secret";

// ─── ensure_secret ───────────────────────────────────────

/// Return the cookie signing secret, generating it on first run.
///
/// This replaced a `secret` setting in config.toml that shipped with a literal
/// default value. Any installation that did not edit it signed session and
/// CAPTCHA-clearance cookies with a key published in the repository, and
/// nothing about a working system revealed that. A generated key has no such
/// failure mode: there is no value to leave unchanged.
///
/// Stored rather than regenerated per start, for the same reason the
/// management certificate is: a new key each boot would invalidate every
/// session on every restart.
pub async fn ensure_secret(db: &SqlitePool) -> String {
    if let Some(existing) = sqlx::query_scalar!(
        "SELECT value FROM settings WHERE key = ?", KEY_COOKIE_SECRET
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    {
        if existing.len() >= 64 {
            return existing;
        }
        // Too short to be one of ours. Fall through and replace it rather than
        // padding it out, which would keep a weak key alive.
        tracing::warn!("Stored cookie secret is too short; generating a new one");
    }

    // 64 bytes from the OS CSPRNG, hex-encoded to 128 characters so it is
    // comfortably longer than the 64 bytes make_key needs and safe to store as
    // text.
    let mut bytes = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let secret: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

    let _ = sqlx::query!(
        "INSERT INTO settings (key, value, updated_at)
         VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                        updated_at = excluded.updated_at",
        KEY_COOKIE_SECRET,
        secret
    )
    .execute(db)
    .await;

    tracing::info!("Generated a cookie signing key and stored it in the database");
    secret
}

// ─── SessionData ─────────────────────────────────────────

/// Payload stored inside the signed session cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: i64,
    pub username: String,
    /// What this account may do. Carried in the cookie so the common case
    /// needs no lookup, and checked against the database on every request
    /// anyway — see `authenticate`, which is what makes a role change take
    /// effect rather than waiting out the cookie's eight hours.
    #[serde(default = "default_role")]
    pub role: String,
    /// The value of the account's `session_epoch` when this cookie was minted.
    /// A cookie whose epoch is behind the account's is refused.
    #[serde(default)]
    pub epoch: i64,
}

/// Cookies minted before 0.8.0 carry no role. They were issued when every
/// account was an administrator by the absence of any way to say otherwise,
/// and migration 022 made that explicit, so reading them as admin is
/// consistent rather than generous. They are refused on the epoch check
/// anyway if the account has since been changed.
fn default_role() -> String { ROLE_ADMIN.to_string() }

impl SessionData {
    /// Whether this session may change things.
    pub fn is_admin(&self) -> bool { self.role == ROLE_ADMIN }
}

// ─── make_key ────────────────────────────────────────────

/// Derive a cookie signing Key from the app secret.
/// The secret must be ≥ 64 bytes for HMAC-SHA256; pad if shorter.
pub fn make_key(secret: &str) -> Key {
    let mut bytes = secret.as_bytes().to_vec();
    // Pad to 64 bytes minimum.
    while bytes.len() < 64 {
        bytes.push(b'0');
    }
    Key::from(&bytes[..64])
}

// ─── get_session ─────────────────────────────────────────

/// Decode the session cookie, without consulting the database.
///
/// The signature is verified by `SignedCookieJar`, so the contents are known
/// to have been minted here. What this cannot know is whether the account
/// still exists, is still enabled, still holds that role, or has signed out
/// everywhere since — all of which need `authenticate`.
///
/// Kept for the two places that legitimately have no database to hand: the
/// login page deciding whether to redirect an already-signed-in visitor, and
/// the layout rendering a username.
pub fn get_session(jar: &SignedCookieJar) -> Option<SessionData> {
    let cookie = jar.get(SESSION_COOKIE)?;
    serde_json::from_str(cookie.value()).ok()
}

// ─── authenticate ────────────────────────────────────────

/// The session, checked against the account it names.
///
/// A signed cookie proves only that this server issued it. Until 0.8.0 that
/// was the whole check, so a session outlived a password change by up to eight
/// hours, in any browser that held it, and there was no way to end one.
///
/// Four things are verified here, and each corresponds to something an
/// administrator can do and expects to take effect:
///
///   * the account still exists — deleting it ends its sessions;
///   * it is enabled — suspending it ends its sessions;
///   * its `session_epoch` matches the cookie's — changing a password, or
///     signing out everywhere, bumps it and ends every session at once;
///   * its role is the current one, not the one the cookie was minted with —
///     so demoting an administrator takes effect on their next request rather
///     than when their cookie expires.
///
/// One indexed lookup by primary key, on GUI requests only. The proxy data
/// path does not go through here.
pub async fn authenticate(db: &SqlitePool, jar: &SignedCookieJar) -> Option<SessionData> {
    let cookie = get_session(jar)?;

    let row = sqlx::query!(
        r#"SELECT role as "role!", enabled as "enabled!: i64",
                  session_epoch as "session_epoch!"
           FROM users WHERE id = ?"#,
        cookie.user_id
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;

    if row.enabled == 0 || row.session_epoch != cookie.epoch {
        return None;
    }

    // The role is taken from the row rather than the cookie, so a demotion
    // does not wait for the cookie to expire.
    Some(SessionData { role: row.role, ..cookie })
}

// ─── end_all_sessions ────────────────────────────────────

/// Invalidate every session belonging to an account.
///
/// Bumping the epoch is what "sign out everywhere" means. Called when a
/// password changes, when a role changes, and when an account is suspended —
/// each of which is a decision that should not wait eight hours to take
/// effect.
pub async fn end_all_sessions(db: &SqlitePool, user_id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?",
        user_id
    )
    .execute(db)
    .await?;
    Ok(())
}

// ─── set_session ─────────────────────────────────────────

/// Serialise session data into a signed cookie and add it to the jar.
pub fn set_session(jar: SignedCookieJar, data: &SessionData) -> SignedCookieJar {
    let value = serde_json::to_string(data).expect("session serialisation");
    let cookie = Cookie::build((SESSION_COOKIE, value))
        .path("/")
        .http_only(true)
        // The GUI is served over TLS only; the plain-HTTP port does nothing
        // but redirect. Secure keeps the browser from sending the session to
        // that port in cleartext on its way there.
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::hours(8))
        .build();
    jar.add(cookie)
}

// ─── clear_session ───────────────────────────────────────

/// Remove the session cookie from the jar.
pub fn clear_session(jar: SignedCookieJar) -> SignedCookieJar {
    jar.remove(Cookie::from(SESSION_COOKIE))
}

// ─── Extractors ──────────────────────────────────────────
//
// Authorisation as a requirement a handler *declares*, rather than a check it
// remembers to make.
//
// Before 0.8.0 every handler opened with the same four lines, and there were
// sixty-seven of them. Nothing enforced that a new handler included them —
// forgetting was not a compile error, it was an unauthenticated page nobody
// noticed. Taking `Viewer` or `Admin` as an argument makes the requirement
// part of the signature: a handler that needs an administrator cannot be
// written without saying so, and one that says so cannot run without one.

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};

/// A signed-in account, of any role.
///
/// Use on pages that only read. A viewer reaching one is expected.
pub struct Viewer(pub SessionData);

/// A signed-in administrator.
///
/// Use on everything that changes state, and on the pages that expose
/// credentials or other accounts. A viewer reaching one gets a 403 that says
/// why, rather than a redirect to a login page they are already past — being
/// bounced to a form you have already completed suggests a broken session
/// rather than a refused permission.
pub struct Admin(pub SessionData);

/// Extract the jar, then the account behind it.
async fn session_from<S>(parts: &mut Parts, state: &S) -> Option<SessionData>
where
    S: Send + Sync,
    Key: FromRef<S>,
    SqlitePool: FromRef<S>,
{
    let jar = SignedCookieJar::<Key>::from_request_parts(parts, state).await.ok()?;
    let db  = SqlitePool::from_ref(state);
    authenticate(&db, &jar).await
}

impl<S> FromRequestParts<S> for Viewer
where
    S: Send + Sync,
    Key: FromRef<S>,
    SqlitePool: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match session_from(parts, state).await {
            Some(s) => Ok(Viewer(s)),
            None    => Err(Redirect::to("/login").into_response()),
        }
    }
}

impl<S> FromRequestParts<S> for Admin
where
    S: Send + Sync,
    Key: FromRef<S>,
    SqlitePool: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match session_from(parts, state).await {
            Some(s) if s.is_admin() => Ok(Admin(s)),
            Some(s) => {
                tracing::info!(
                    user = %s.username, role = %s.role, path = %parts.uri.path(),
                    "Refused: this page needs an administrator"
                );
                Err((
                    StatusCode::FORBIDDEN,
                    axum::response::Html(FORBIDDEN_PAGE),
                ).into_response())
            }
            None => Err(Redirect::to("/login").into_response()),
        }
    }
}

/// Shown when a viewer reaches a page that changes something.
///
/// Deliberately plain: it renders without the layout, which needs a Tera
/// instance the extractor has no access to, and saying the one true thing
/// clearly is worth more here than matching the site's styling.
const FORBIDDEN_PAGE: &str = r#"<!doctype html>
<title>Not permitted — EasyWAF</title>
<style>
 body{font:15px/1.6 system-ui,sans-serif;margin:0;display:flex;min-height:100vh;
      align-items:center;justify-content:center;background:#f5f5f5;color:#222}
 .b{background:#fff;border:1px solid #ddd;border-radius:6px;padding:28px 32px;max-width:30rem}
 h1{font-size:19px;margin:0 0 10px} p{margin:0 0 14px} a{color:#2980b9}
</style>
<div class="b">
  <h1>You do not have permission for this page</h1>
  <p>Your account has the <strong>viewer</strong> role, which can see the
     dashboard, traffic and configuration but cannot change anything.</p>
  <p>An administrator can change your role under Settings &rsaquo; Accounts.</p>
  <p><a href="/">Back to the dashboard</a></p>
</div>"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn session(role: &str, epoch: i64) -> SessionData {
        SessionData {
            user_id: 1,
            username: "yariv".into(),
            role: role.into(),
            epoch,
        }
    }

    async fn db_with(role: &str, enabled: i64, epoch: i64) -> SqlitePool {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::raw_sql(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL,
                password_hash TEXT NOT NULL DEFAULT '', role TEXT NOT NULL,
                enabled INTEGER NOT NULL, session_epoch INTEGER NOT NULL);"
        ).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO users (id,username,role,enabled,session_epoch) VALUES (1,'yariv',?,?,?)")
            .bind(role).bind(enabled).bind(epoch)
            .execute(&db).await.unwrap();
        db
    }

    /// `authenticate` takes a jar; these exercise the same checks against the
    /// row directly, since building a signed jar in a unit test would test
    /// axum-extra rather than this logic.
    async fn check(db: &SqlitePool, cookie: &SessionData) -> Option<String> {
        let row = sqlx::query!(
            r#"SELECT role as "role!", enabled as "enabled!: i64",
                      session_epoch as "session_epoch!" FROM users WHERE id = ?"#,
            cookie.user_id
        ).fetch_optional(db).await.ok().flatten()?;
        if row.enabled == 0 || row.session_epoch != cookie.epoch {
            return None;
        }
        Some(row.role)
    }

    #[tokio::test]
    async fn a_current_session_is_accepted() {
        let db = db_with(ROLE_ADMIN, 1, 3).await;
        assert_eq!(check(&db, &session(ROLE_ADMIN, 3)).await.as_deref(), Some(ROLE_ADMIN));
    }

    #[tokio::test]
    async fn a_cookie_older_than_the_epoch_is_refused() {
        // What "sign out everywhere" has to mean. Before 0.8.0 a session
        // outlived a password change by up to eight hours.
        let db = db_with(ROLE_ADMIN, 1, 4).await;
        assert!(check(&db, &session(ROLE_ADMIN, 3)).await.is_none());
    }

    #[tokio::test]
    async fn a_suspended_account_is_refused() {
        let db = db_with(ROLE_ADMIN, 0, 1).await;
        assert!(check(&db, &session(ROLE_ADMIN, 1)).await.is_none());
    }

    #[tokio::test]
    async fn a_deleted_account_is_refused() {
        let db = db_with(ROLE_ADMIN, 1, 1).await;
        sqlx::query("DELETE FROM users").execute(&db).await.unwrap();
        assert!(check(&db, &session(ROLE_ADMIN, 1)).await.is_none());
    }

    #[tokio::test]
    async fn the_role_comes_from_the_row_not_the_cookie() {
        // A demotion must take effect on the next request. Holding an old
        // cookie that still says "admin" must not keep the privilege.
        let db = db_with(ROLE_VIEWER, 1, 1).await;
        let stale_admin_cookie = session(ROLE_ADMIN, 1);
        assert_eq!(check(&db, &stale_admin_cookie).await.as_deref(), Some(ROLE_VIEWER));
    }

    #[tokio::test]
    async fn ending_sessions_bumps_the_epoch_and_refuses_the_old_cookie() {
        let db = db_with(ROLE_ADMIN, 1, 0).await;
        let held = session(ROLE_ADMIN, 0);
        assert!(check(&db, &held).await.is_some(), "valid before");
        end_all_sessions(&db, 1).await.unwrap();
        assert!(check(&db, &held).await.is_none(), "still valid after signing out everywhere");
    }

    #[test]
    fn only_the_two_roles_are_accepted() {
        // Guards what arrives from a form: an unknown role stored on a user
        // would be neither admin nor viewer, and is_admin() would silently
        // treat it as a viewer rather than refusing the write.
        assert!(is_known_role(ROLE_ADMIN) && is_known_role(ROLE_VIEWER));
        for bad in ["", "administrator", "ADMIN", "root", "superuser"] {
            assert!(!is_known_role(bad), "{bad:?} should not be a role");
        }
    }

    #[test]
    fn only_admin_may_change_things() {
        assert!(session(ROLE_ADMIN, 0).is_admin());
        assert!(!session(ROLE_VIEWER, 0).is_admin());
        // An unrecognised role must not be treated as an administrator.
        assert!(!session("root", 0).is_admin());
    }

    #[test]
    fn a_cookie_from_before_roles_existed_reads_as_admin() {
        // Migration 022 made every existing account an admin, because those
        // are the accounts somebody has been administering with. A cookie
        // minted just before the upgrade has to agree, or the upgrade signs
        // that person out of a page they were on.
        let old: SessionData =
            serde_json::from_str(r#"{"user_id":1,"username":"yariv"}"#).unwrap();
        assert_eq!(old.role, ROLE_ADMIN);
        assert_eq!(old.epoch, 0);
    }
}

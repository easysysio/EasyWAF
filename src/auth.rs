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

/// Extract the session from the signed cookie jar, if present and valid.
pub fn get_session(jar: &SignedCookieJar) -> Option<SessionData> {
    let cookie = jar.get(SESSION_COOKIE)?;
    serde_json::from_str(cookie.value()).ok()
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

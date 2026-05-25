// =========================================================
// auth.rs — EasyWAF
// Session cookie helpers and authentication utilities.
// Session data is stored as signed JSON in a cookie using
// axum-extra's SignedCookieJar + a Key derived from config.secret.
// =========================================================

use axum_extra::extract::cookie::{Cookie, Key, SameSite, SignedCookieJar};
use serde::{Deserialize, Serialize};
use time::Duration;

pub const SESSION_COOKIE: &str = "easywaf_session";

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

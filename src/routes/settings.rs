// =========================================================
// routes/settings.rs — EasyWAF
// Installation-wide settings managed from the GUI.
//
// Settings live in the `settings` key/value table rather than
// config.toml, because config.toml is read before the database
// is open and is not editable from the web UI.
//
// Reads go through typed helpers with an explicit default, so a
// missing or malformed row degrades to the default rather than
// failing the request.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;
use sqlx::SqlitePool;
use tera::Context;

// ─── Keys ────────────────────────────────────────────────

/// Days of traffic history to keep. "0" keeps everything.
pub const KEY_RETENTION_DAYS: &str = "traffic_retention_days";

/// Text shown to visitors of a site that has been disabled.
pub const KEY_MAINTENANCE_MESSAGE: &str = "maintenance_message";

/// TLS version profile applied to every HTTPS listener.
pub const KEY_TLS_PROFILE: &str = "tls_profile";

/// Used when the row is missing or cannot be parsed.
const DEFAULT_RETENTION_DAYS: i64 = 0;

/// Upper bound offered in the GUI — ten years, enough for any sane policy
/// while keeping an accidental extra digit from meaning "forever".
const MAX_RETENTION_DAYS: i64 = 3650;

/// Used when no maintenance text has been set, so a disabled site always says
/// something sensible rather than nothing.
pub const DEFAULT_MAINTENANCE_MESSAGE: &str =
    "This site is temporarily unavailable for maintenance. Please check back shortly.";

/// Enough for a sentence or two plus a contact address. The text is rendered
/// into a page served to the public, so it is not a place for a document.
const MAX_MAINTENANCE_LEN: usize = 500;

// ─── FlashQuery ──────────────────────────────────────────

/// Flash message passed back through the query string after a redirect.
#[derive(Debug, Deserialize)]
pub struct FlashQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

// ─── Form ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SettingsForm {
    pub traffic_retention_days: Option<String>,
    pub maintenance_message:    Option<String>,
    pub tls_profile:            Option<String>,
}

// ─── get_settings ────────────────────────────────────────

/// GET /settings — render the settings form with current values.
pub async fn get_settings(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let retention_days      = get_retention_days(&state.db).await;
    let maintenance_message = get_maintenance_message(&state.db).await;
    let tls_profile         = get_tls_profile(&state.db).await;

    // Shown alongside the field so the setting's effect is concrete.
    let stored_events: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM traffic_events")
        .fetch_one(&state.db)
        .await?;

    let mut ctx = Context::new();
    ctx.insert("username",       &session.username);
    ctx.insert("title",          "Settings");
    ctx.insert("url",            "/settings");
    ctx.insert("retention_days",      &retention_days);
    ctx.insert("maintenance_message",  &maintenance_message);
    ctx.insert("tls_profile",          tls_profile.as_str());
    ctx.insert("stored_events",  &stored_events);
    ctx.insert("result",         &flash.result.unwrap_or_default());
    ctx.insert("msg",            &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("settings.html", &ctx)?)).into_response())
}

// ─── post_settings_update ────────────────────────────────

/// POST /settings — save the settings form.
/// Out-of-range or non-numeric input is rejected rather than clamped, so the
/// value that was typed is never silently changed into something else.
pub async fn post_settings_update(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<SettingsForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let raw = form.traffic_retention_days.as_deref().unwrap_or("").trim().to_string();

    let days: i64 = match raw.parse() {
        Ok(d)  => d,
        Err(_) => {
            return flash_redirect("/settings", "failed", "Retention must be a whole number of days");
        }
    };

    if days < 0 || days > MAX_RETENTION_DAYS {
        return flash_redirect(
            "/settings",
            "failed",
            &format!("Retention must be between 0 and {} days", MAX_RETENTION_DAYS),
        );
    }

    let maintenance = form.maintenance_message.as_deref().unwrap_or("").trim();
    if maintenance.chars().count() > MAX_MAINTENANCE_LEN {
        return flash_redirect(
            "/settings",
            "failed",
            &format!("Maintenance message must be {} characters or fewer", MAX_MAINTENANCE_LEN),
        );
    }

    set_setting(&state.db, KEY_RETENTION_DAYS, &days.to_string()).await?;
    set_setting(&state.db, KEY_MAINTENANCE_MESSAGE, maintenance).await?;

    // Normalised through the same parser the listeners use, so an unexpected
    // value is stored as the fallback rather than kept to surprise the next
    // listener that binds.
    let profile = crate::tls::TlsProfile::from_setting(
        form.tls_profile.as_deref().unwrap_or(""),
    );
    set_setting(&state.db, KEY_TLS_PROFILE, profile.as_str()).await?;

    let msg = if days == 0 {
        "Settings saved — traffic history is kept indefinitely".to_string()
    } else {
        format!("Settings saved — traffic history kept for {} days", days)
    };
    flash_redirect("/settings", "success", &msg)
}

// ─── DB helpers ──────────────────────────────────────────

/// Read the retention setting, falling back to the default when the row is
/// missing or does not parse. Callers get a usable number in every case.
pub async fn get_retention_days(db: &SqlitePool) -> i64 {
    match get_setting(db, KEY_RETENTION_DAYS).await {
        Some(v) => v.trim().parse().unwrap_or(DEFAULT_RETENTION_DAYS),
        None    => DEFAULT_RETENTION_DAYS,
    }
}

/// Read the maintenance text shown for a disabled site, falling back to the
/// default when it has never been set or was cleared. A visitor always gets a
/// sentence, never a blank page.
pub async fn get_maintenance_message(db: &SqlitePool) -> String {
    match get_setting(db, KEY_MAINTENANCE_MESSAGE).await {
        Some(v) if !v.trim().is_empty() => v,
        _                              => DEFAULT_MAINTENANCE_MESSAGE.to_string(),
    }
}

/// Read the appliance-wide TLS profile, defaulting to the compatible one.
///
/// Read when a TLS listener binds, so a change takes effect on the next
/// restart rather than immediately — the profile is fixed in the listener's
/// configuration and cannot be swapped under an open socket.
pub async fn get_tls_profile(db: &SqlitePool) -> crate::tls::TlsProfile {
    let raw = get_setting(db, KEY_TLS_PROFILE).await.unwrap_or_default();
    crate::tls::TlsProfile::from_setting(&raw)
}

/// Fetch one raw setting value. None when the key is not present.
async fn get_setting(db: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar!("SELECT value FROM settings WHERE key = ?", key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// Insert or replace one setting value.
async fn set_setting(db: &SqlitePool, key: &str, value: &str) -> Result<()> {
    sqlx::query!(
        "INSERT INTO settings (key, value, updated_at)
         VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                        updated_at = excluded.updated_at",
        key,
        value
    )
    .execute(db)
    .await?;
    Ok(())
}

// ─── Flash redirect helper ───────────────────────────────

/// Redirect to path with URL-encoded flash message query params.
fn flash_redirect(path: &str, result: &str, msg: &str) -> Result<Response> {
    let msg_enc = urlencoding::encode(msg).into_owned();
    Ok(Redirect::to(&format!("{}?result={}&msg={}", path, result, msg_enc)).into_response())
}

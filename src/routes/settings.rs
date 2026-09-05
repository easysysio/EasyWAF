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

/// Cipher suites offered by every HTTPS listener, space-separated. Empty means
/// every suite this build supports.
pub const KEY_TLS_CIPHERS: &str = "tls_ciphers";

/// Name of the certificate the management interface serves. Empty or missing
/// means the generated `easywaf` default.
pub const KEY_MANAGEMENT_CERT: &str = "management_cert";

/// Addresses whose `X-Forwarded-For` header is believed. Empty means none.
pub const KEY_TRUSTED_PROXIES: &str = "trusted_proxies";

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
    pub tls_ciphers:            Option<String>,
    pub management_cert:        Option<String>,
    pub acme_email:             Option<String>,
    pub acme_directory:         Option<String>,
    pub trusted_proxies:        Option<String>,
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

    // The stored line is shown as typed. When nothing has been set the field
    // is pre-filled with every supported suite rather than left blank: an
    // operator restricting ciphers needs the exact spellings to edit down
    // from, and there is nowhere else to discover them.
    let tls_ciphers = match get_setting(&state.db, KEY_TLS_CIPHERS).await {
        Some(v) if !v.trim().is_empty() => v,
        _                               => crate::tls::all_suite_names(),
    };

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
    ctx.insert("tls_ciphers",          &tls_ciphers);
    let management_cert = get_management_cert(&state.db).await;
    let cert_names      = cert_names(&state.db).await;
    // A stored name that is no longer among the certificates would otherwise
    // render as "nothing selected", and the picker would appear to say
    // something the setting does not.
    let management_cert_missing = !cert_names.contains(&management_cert);
    ctx.insert("management_cert",         &management_cert);
    ctx.insert("cert_names",              &cert_names);
    ctx.insert("management_cert_missing", &management_cert_missing);

    let acme = crate::acme::config(&state.db).await?;
    ctx.insert("acme_email",     &acme.as_ref().map(|a| a.email.clone()).unwrap_or_default());
    ctx.insert("acme_directory", &acme.map(|a| a.directory)
        .unwrap_or_else(|| crate::acme::STAGING_DIRECTORY.to_string()));
    ctx.insert("trusted_proxies", &get_trusted_proxies(&state.db).await);
    ctx.insert("acme_staging",    crate::acme::STAGING_DIRECTORY);
    ctx.insert("acme_production", crate::acme::PRODUCTION_DIRECTORY);
    ctx.insert("tls_ciphers_all",      &crate::tls::all_suite_names());
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

    // Ciphers are validated before anything is written, and a bad list is
    // refused outright. Storing one would not fail here — it would fail at the
    // next restart, when every HTTPS listener refuses every handshake and the
    // GUI that could fix it is one of them.
    let ciphers_raw = form.tls_ciphers.as_deref().unwrap_or("").trim();
    let suites = match crate::tls::parse_suites(ciphers_raw) {
        Ok(s)  => s,
        Err(e) => return flash_redirect("/settings", "failed", &format!("Cipher suites: {e}")),
    };

    if !crate::tls::suites_usable_with(profile, &suites) {
        return flash_redirect(
            "/settings",
            "failed",
            "Modern (TLS 1.3 only) needs at least one TLS13_ suite selected — \
             the suites chosen are all TLS 1.2, so no connection could be negotiated",
        );
    }

    // Checked before it is stored, and refused if it could not serve TLS. The
    // GUI is the only place this setting can be corrected, so a bad value that
    // only failed at the next start would take away the means of fixing it.
    let mgmt = form.management_cert.as_deref().unwrap_or("").trim().to_string();
    if !mgmt.is_empty() && mgmt != crate::cert::DEFAULT_CERT_NAME {
        match crate::cert::load_named(&state.db, &mgmt).await? {
            None => {
                return flash_redirect(
                    "/settings",
                    "failed",
                    &format!("'{mgmt}' has no certificate and key stored, so the management \
                              interface could not be served with it"),
                )
            }
            Some((c, k)) => {
                if let Err(e) = crate::tls::validate_pem(&c, &k) {
                    return flash_redirect(
                        "/settings",
                        "failed",
                        &format!("'{mgmt}' cannot serve TLS: {e}"),
                    );
                }
            }
        }
    }

    // ACME contact and directory. Stored in acme_accounts rather than settings
    // because the account key belongs beside them — an account is tied to one
    // directory, so changing either has to invalidate the stored credentials.
    let acme_email = form.acme_email.as_deref().unwrap_or("").trim().to_string();
    let acme_dir   = form.acme_directory.as_deref().unwrap_or("").trim().to_string();
    if !acme_email.is_empty() {
        if !acme_email.contains('@') {
            return flash_redirect("/settings", "failed", "ACME contact must be an email address");
        }
        crate::acme::set_config(&state.db, &acme_email, &acme_dir).await?;
    }

    // Rejected rather than filtered: an entry that does not parse is a range
    // the operator believes is trusted and is not, which is exactly the kind of
    // gap this setting exists to close.
    let proxies = form.trusted_proxies.as_deref().unwrap_or("").trim().to_string();
    let (_, bad) = crate::forwarded::parse_list(&proxies);
    if !bad.is_empty() {
        return flash_redirect(
            "/settings",
            "failed",
            &format!("Not an address or CIDR block: {}", bad.join(", ")),
        );
    }
    set_setting(&state.db, KEY_TRUSTED_PROXIES, &proxies).await?;
    crate::forwarded::reload(&state.db).await;

    set_setting(&state.db, KEY_MANAGEMENT_CERT, &mgmt).await?;
    set_setting(&state.db, KEY_TLS_PROFILE, profile.as_str()).await?;

    // Stored normalised: the names rustls knows, in its own preference order,
    // rather than however they were typed. What is read back is then exactly
    // what the listener will offer.
    let normalised = suites
        .iter()
        .map(crate::tls::suite_name)
        .collect::<Vec<_>>()
        .join(" ");
    set_setting(&state.db, KEY_TLS_CIPHERS, &normalised).await?;

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

/// Read the cipher suites every HTTPS listener should offer.
///
/// Falls back to all supported suites when unset or unparseable. The fallback
/// is deliberate: a corrupted value must not leave the appliance unable to
/// negotiate TLS at all, which would take the management GUI down with it.
/// The form rejects anything invalid, so this path means the row was edited
/// outside EasyWAF.
pub async fn get_tls_ciphers(db: &SqlitePool) -> Vec<rustls::SupportedCipherSuite> {
    let raw = get_setting(db, KEY_TLS_CIPHERS).await.unwrap_or_default();
    match crate::tls::parse_suites(&raw) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Stored TLS cipher list is unusable ({e}); offering all supported suites");
            crate::tls::all_suites()
        }
    }
}

/// The certificate name the management interface should use.
pub async fn get_management_cert(db: &SqlitePool) -> String {
    match get_setting(db, KEY_MANAGEMENT_CERT).await {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => crate::cert::DEFAULT_CERT_NAME.to_string(),
    }
}

/// Every stored certificate that has both halves, for the picker.
async fn cert_names(db: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar!(
        r#"SELECT name as "name!" FROM certs
           WHERE cert_pem IS NOT NULL AND key_pem IS NOT NULL
             AND trim(cert_pem) <> '' AND trim(key_pem) <> ''
           ORDER BY name"#
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
}

/// Addresses whose `X-Forwarded-For` header should be believed.
pub async fn get_trusted_proxies(db: &SqlitePool) -> String {
    get_setting(db, KEY_TRUSTED_PROXIES).await.unwrap_or_default()
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

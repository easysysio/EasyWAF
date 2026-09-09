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

use crate::routes::flash_redirect;
use crate::{auth::{Admin}, error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
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

/// Whether this node performs ACME renewals. Defaults to yes.
pub const KEY_ACME_RENEW_HERE: &str = "acme_renew_here";

/// Whether flow lines are sent to a syslog collector. "1" or "0".
pub const KEY_SYSLOG_ENABLED: &str = "syslog_enabled";

/// The collector's address — a hostname or an IP. Empty means none.
pub const KEY_SYSLOG_HOST: &str = "syslog_host";

/// The collector's UDP port.
pub const KEY_SYSLOG_PORT: &str = "syslog_port";

/// Offered when nothing has been stored — the syslog port.
pub const DEFAULT_SYSLOG_PORT: u16 = 514;

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
    pub rule_update_check:      Option<String>,
    pub rule_update_url:        Option<String>,
    pub syslog_enabled:         Option<String>,
    pub syslog_host:            Option<String>,
    pub syslog_port:            Option<String>,
}

// ─── get_settings ────────────────────────────────────────

/// GET /settings — render the settings form with current values.
pub async fn get_settings(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Admin(session): Admin,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {

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
    crate::routes::who_context(&mut ctx, &session);
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

    // Shown as stored, including a host left behind when sending was turned
    // off: turning it back on should not mean typing the address again.
    ctx.insert("syslog_enabled", &syslog_enabled(&state.db).await);
    ctx.insert("syslog_host",    &get_setting(&state.db, KEY_SYSLOG_HOST).await.unwrap_or_default());
    ctx.insert("syslog_port",    &syslog_port(&state.db).await);
    ctx.insert("log_dir",        &state.config.logging.dir);
    ctx.insert("log_keep_days",  &state.config.logging.keep_days);

    // The stored channel is shown as typed, and left blank when it is the
    // default: a field pre-filled with the default cannot be told apart from
    // one an operator deliberately set to the same value, and clearing it is
    // how you go back to the default.
    let rule_update_url = get_setting(&state.db, crate::rules_update::KEY_URL)
        .await
        .unwrap_or_default();
    let (checked, error) = crate::rules_update::status(&state.db).await;
    ctx.insert("rule_update_check",   &crate::rules_update::enabled(&state.db).await);
    ctx.insert("rule_update_url",     &rule_update_url);
    ctx.insert("rule_update_default", crate::rules_update::DEFAULT_URL);
    ctx.insert("rule_update_checked", &checked.map(|t| format_utc(&t)).unwrap_or_default());
    ctx.insert("rule_update_error",   &error.unwrap_or_default());
    let (mirrored, mirror_error) = crate::rules_update::mirror_status(&state.db).await;
    ctx.insert("mirrored_sets",  &mirrored);
    ctx.insert("mirror_error",   &mirror_error.unwrap_or_default());
    ctx.insert("mirror_dir",     &crate::rules_update::cache_dir().display().to_string());
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
    _jar: SignedCookieJar,
    _: Admin,
    Form(form): Form<SettingsForm>,
) -> Result<Response> {

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

    // The syslog collector. Refused rather than stored when it is switched on
    // with nowhere to send: an enabled collector that silently sends nothing
    // is the failure this page exists to make visible.
    let syslog_on   = form.syslog_enabled.is_some();
    let syslog_host = form.syslog_host.as_deref().unwrap_or("").trim().to_string();
    let port_raw    = form.syslog_port.as_deref().unwrap_or("").trim().to_string();

    if syslog_on && syslog_host.is_empty() {
        return flash_redirect(
            "/settings",
            "failed",
            "Sending flow logs needs a collector address",
        );
    }

    // A hostname or an address, not a URL and not "host:port" — the port has
    // its own field, and taking one here would leave two answers to the same
    // question.
    if syslog_host.contains(|c: char| c.is_whitespace()) || syslog_host.contains('/') {
        return flash_redirect(
            "/settings",
            "failed",
            "The collector is a hostname or an IP address, not a URL",
        );
    }
    if syslog_host.contains(':') && syslog_host.parse::<std::net::Ipv6Addr>().is_err() {
        return flash_redirect(
            "/settings",
            "failed",
            "Give the collector's port in the Port field, not with the address",
        );
    }

    let syslog_port: u16 = if port_raw.is_empty() {
        DEFAULT_SYSLOG_PORT
    } else {
        match port_raw.parse() {
            Ok(p) if p > 0 => p,
            _ => return flash_redirect(
                "/settings",
                "failed",
                "The collector port must be a number between 1 and 65535",
            ),
        }
    };

    set_setting(&state.db, KEY_SYSLOG_ENABLED, if syslog_on { "1" } else { "0" }).await?;
    set_setting(&state.db, KEY_SYSLOG_HOST, &syslog_host).await?;
    set_setting(&state.db, KEY_SYSLOG_PORT, &syslog_port.to_string()).await?;
    // Applied to the running logger, so the next request is logged to the new
    // collector rather than the one this appliance was started with.
    state.logger.set_collector(syslog_target(&state.db).await);

    // The rule channel. Checked before it is stored: a channel that is not a
    // fetchable URL fails six hours later in a background task, and the only
    // sign of it would be a "last check" that never advances.
    //
    // An empty field means the default, not "no channel" — turning the check
    // off is the checkbox, and conflating the two would leave a checked box
    // that quietly does nothing.
    let channel = form.rule_update_url.as_deref().unwrap_or("").trim().to_string();
    if !channel.is_empty() {
        match reqwest::Url::parse(&channel) {
            Ok(u) if u.scheme() == "http" || u.scheme() == "https" => {}
            Ok(u)  => return flash_redirect(
                "/settings",
                "failed",
                &format!("Rule channel must be http or https, not '{}'", u.scheme()),
            ),
            Err(e) => return flash_redirect(
                "/settings",
                "failed",
                &format!("Rule channel is not a URL: {e}"),
            ),
        }
    }
    set_setting(&state.db, crate::rules_update::KEY_URL, &channel).await?;

    // An unticked checkbox sends nothing at all, so the absence is the answer.
    let check = form.rule_update_check.is_some();
    set_setting(&state.db, crate::rules_update::KEY_ENABLED, if check { "1" } else { "0" }).await?;

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

/// An RFC 3339 timestamp shown the way the rest of the GUI shows times.
///
/// Stored as RFC 3339 because that is unambiguous and sorts; displayed without
/// the offset and the microseconds, which are noise to someone asking whether
/// the last check was today. An unparseable value is shown as it is rather
/// than swallowed — if something ever writes a different format, seeing it is
/// more use than an empty field.
fn format_utc(raw: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(t)  => t.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string(),
        Err(_) => raw.to_string(),
    }
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

/// Whether this node should renew ACME certificates.
///
/// Defaults to true, and there is no GUI for it yet — it exists so that
/// configuration sync can set it when there is more than one node, without
/// having to unpick an assumption that this is the only one. Every node
/// renewing independently would duplicate issuance and hit the CA's rate
/// limits.
pub async fn get_acme_renew_here(db: &SqlitePool) -> bool {
    match get_setting(db, KEY_ACME_RENEW_HERE).await {
        Some(v) => !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "no"),
        None    => true,
    }
}

/// Whether flow lines are being sent off the box. Off unless it was turned on.
pub async fn syslog_enabled(db: &SqlitePool) -> bool {
    matches!(get_setting(db, KEY_SYSLOG_ENABLED).await.as_deref().map(str::trim), Some("1"))
}

/// The collector's port, falling back to the syslog default when the row is
/// missing or does not parse.
pub async fn syslog_port(db: &SqlitePool) -> u16 {
    match get_setting(db, KEY_SYSLOG_PORT).await {
        Some(v) => v.trim().parse().unwrap_or(DEFAULT_SYSLOG_PORT),
        None    => DEFAULT_SYSLOG_PORT,
    }
}

/// Where flow lines should be sent, or `None` when they should not be.
///
/// The one place the three rows become an address, so the logger and the form
/// cannot disagree about what "enabled with an empty host" means: nowhere.
/// An IPv6 literal is bracketed here, since that is what a socket address
/// parser expects and not what anyone types into a form.
pub async fn syslog_target(db: &SqlitePool) -> Option<String> {
    if !syslog_enabled(db).await {
        return None;
    }
    let host = get_setting(db, KEY_SYSLOG_HOST).await.unwrap_or_default().trim().to_string();
    if host.is_empty() {
        return None;
    }
    let port = syslog_port(db).await;
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        Some(format!("[{host}]:{port}"))
    } else {
        Some(format!("{host}:{port}"))
    }
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


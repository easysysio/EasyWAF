// =========================================================
// config.rs — EasyWAF
// Loads TOML configuration from config.toml at startup.
// =========================================================

use serde::Deserialize;
use std::fs;

/// Where the database lives when `DATABASE_URL` is not set.
///
/// Relative to the working directory, which is where EasyWAF already resolves
/// templates, static assets and rules — the packaged service sets it to
/// /opt/easywaf.
const DEFAULT_DATABASE_URL: &str = "sqlite://easywaf.db";

// ─── Config ──────────────────────────────────────────────

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub proxy: ProxyConfig,

    /// Accepted but ignored; kept only so a config.toml written before 0.4.2
    /// still parses.
    ///
    /// The signing key is generated on first run and stored in the database
    /// now. It was a plain setting shipped with a literal default value, which
    /// meant every installation that did not edit it signed session and
    /// CAPTCHA-clearance cookies with a key printed in the public repository.
    /// A generated key cannot be left at a known value by inaction.
    #[serde(default)]
    pub secret: Option<String>,

    /// Accepted but ignored; superseded by the `DATABASE_URL` environment
    /// variable, which containers can set without editing a file inside the
    /// image. See `database_url()`.
    #[serde(default)]
    pub database_url: Option<String>,
}

// ─── ProxyConfig ─────────────────────────────────────────

#[derive(Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    /// Port for the reverse proxy (HTTP). Default: 80.
    pub http_port:  u16,
    /// Port the management GUI redirects from, in plain HTTP. Default: 8080.
    pub gui_port:   u16,
    /// Port the management GUI is served on, over TLS. Default: 8443.
    ///
    /// Defaulted rather than required so a config.toml written before TLS
    /// existed keeps parsing — an upgrade must not leave the service unable to
    /// read its own configuration.
    #[serde(default = "default_gui_tls_port")]
    pub gui_tls_port: u16,
    /// Optional: path to the MaxMind GeoLite2-Country.mmdb file.
    pub geoip_db:   Option<String>,
    /// Directory for ACME HTTP-01 challenge files.
    pub acme_webroot: Option<String>,
}

/// Default TLS port for the management GUI when config.toml predates it.
fn default_gui_tls_port() -> u16 {
    8443
}

// ─── load ────────────────────────────────────────────────

/// Where to open the database.
///
/// `DATABASE_URL` if set, otherwise the default path. An environment variable
/// rather than a config key because the case that needs to override it is a
/// container, where the config file is baked into the image and the database
/// has to live on a mounted volume to survive the container at all.
pub fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_DATABASE_URL.to_string())
}

pub fn load(path: &str) -> Config {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Cannot read config file '{}': {}", path, e));
    let cfg: Config = toml::from_str(&text)
        .unwrap_or_else(|e| panic!("Cannot parse config file '{}': {}", path, e));

    // Said once, at startup, rather than silently ignored: an operator who
    // edits a setting and sees no effect has every reason to assume it worked.
    if cfg.secret.is_some() {
        tracing::warn!(
            "config.toml still sets 'secret'. It is ignored as of 0.4.2 — the \
             cookie signing key is generated on first run and stored in the \
             database. The line can be deleted."
        );
    }
    if cfg.database_url.is_some() {
        tracing::warn!(
            "config.toml still sets 'database_url'. It is ignored as of 0.4.2 — \
             set the DATABASE_URL environment variable instead. Using {}.",
            database_url()
        );
    }

    cfg
}

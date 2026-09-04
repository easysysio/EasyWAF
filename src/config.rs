// =========================================================
// config.rs — EasyWAF
// Loads TOML configuration from config.toml at startup.
// =========================================================

use serde::Deserialize;
use std::fs;

// ─── Config ──────────────────────────────────────────────

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub secret:       String,
    pub database_url: String,
    pub proxy:        ProxyConfig,
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

pub fn load(path: &str) -> Config {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Cannot read config file '{}': {}", path, e));
    toml::from_str(&text)
        .unwrap_or_else(|e| panic!("Cannot parse config file '{}': {}", path, e))
}

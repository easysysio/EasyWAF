// =========================================================
// config.rs — EasyWAF
// Loads TOML configuration from config.toml at startup.
// =========================================================

use serde::Deserialize;
use std::fs;

// ─── Config ──────────────────────────────────────────────

/// Top-level configuration loaded from config.toml.
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    /// Bind address, e.g. "0.0.0.0"
    pub host: String,
    /// Bind port, e.g. 8080
    pub port: u16,
    /// Secret used for signing session cookies (min 32 bytes recommended).
    pub secret: String,
    /// SQLite database URL, e.g. "sqlite:///var/lib/easywaf/easywaf.db"
    pub database_url: String,
    /// nginx-related paths and commands
    pub nginx: NginxConfig,
}

// ─── NginxConfig ─────────────────────────────────────────

/// Paths to nginx directories and the reload command.
#[derive(Deserialize, Clone, Debug)]
pub struct NginxConfig {
    /// Where nginx virtual-host conf files are stored (/etc/nginx/conf.d)
    pub site_dir: String,
    /// Where TLS cert/key files are stored (/etc/nginx/certs)
    pub cert_dir: String,
    /// Where ModSecurity policy files are stored (/etc/nginx/naxsi)
    pub policy_dir: String,
    /// Where OWASP CRS rule files live (/usr/share/owasp-modsecurity-crs/rules)
    pub rules_dir: String,
    /// Where nginx access logs are written (/var/log/nginx)
    pub log_dir: String,
    /// Shell command to reload nginx after config changes
    pub reload_cmd: String,
}

// ─── load ────────────────────────────────────────────────

/// Read and parse config.toml, panic on error (required at startup).
pub fn load(path: &str) -> Config {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Cannot read config file '{}': {}", path, e));
    toml::from_str(&text)
        .unwrap_or_else(|e| panic!("Cannot parse config file '{}': {}", path, e))
}

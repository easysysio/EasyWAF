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

    /// Where flow and audit lines go. Read from the file rather than the
    /// database because logging has to work before the database is open, and
    /// because a container needs to set the directory without editing a file
    /// inside the image.
    #[serde(default)]
    pub logging: LoggingConfig,

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

// ─── LoggingConfig ───────────────────────────────────────

/// Flow and audit logging.
///
/// Every field has a default and the whole section may be absent, so a
/// config.toml written before 0.9.0 still parses. The audit log then starts
/// being written, and nothing is sent off the box until a collector is named.
#[derive(Deserialize, Clone, Debug)]
pub struct LoggingConfig {
    /// Directory holding `flow.log` and `audit.log`.
    #[serde(default = "default_log_dir")]
    pub dir: String,

    /// Daily files are kept this many days, then deleted. Nothing to configure
    /// in logrotate, matching EasyLog.
    #[serde(default = "default_keep_days")]
    pub keep_days: u32,

    #[serde(default)]
    pub syslog: SyslogConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            dir:       default_log_dir(),
            keep_days: default_keep_days(),
            syslog:    SyslogConfig::default(),
        }
    }
}

fn default_log_dir()   -> String { "/var/log/easywaf".to_string() }
fn default_keep_days() -> u32    { 14 }

/// The collector flow lines are sent to.
///
/// There is no local flow file, deliberately. Every proxied request is already
/// written to `traffic_events` and shown in Traffic Monitor, with the verdict,
/// the score and the rules that produced it — a `flow.log` beside it would be
/// the same data in a worse format. Syslog exists to get that stream *off the
/// box*, into a collector that can hold more history than an appliance should
/// and chart it across several of them.
#[derive(Deserialize, Clone, Debug, Default)]
pub struct SyslogConfig {
    /// Off by default: sending traffic off-box is a decision, not an
    /// assumption.
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub host: String,
    #[serde(default = "default_syslog_port")]
    pub port: u16,
    /// "udp" today. TCP is a possible later addition for delivery guarantees;
    /// anything else is refused at startup rather than silently ignored.
    #[serde(default = "default_syslog_protocol")]
    pub protocol: String,
}

fn default_syslog_port()     -> u16    { 514 }
fn default_syslog_protocol() -> String { "udp".to_string() }

// ─── ProxyConfig ─────────────────────────────────────────

#[derive(Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    /// Accepted but ignored; each site carries its own `listen_port` now, set
    /// in the GUI, and a single proxy-wide HTTP port stopped meaning anything
    /// once one EasyWAF could serve sites on several.
    ///
    /// Port 80 is bound unconditionally regardless of this value, because
    /// HTTP-01 validation always arrives there.
    #[serde(default)]
    pub http_port:  Option<u16>,
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
    /// Accepted but ignored. EasyWAF answers HTTP-01 challenges from memory,
    /// in the proxy, before the site lookup — there is no directory to serve
    /// them from and never was one written to.
    ///
    /// Kept parseable rather than removed because it is the field someone
    /// reaches for when a certificate request fails, and a config that refuses
    /// to load is a worse answer than one that says the setting does nothing.
    #[serde(default)]
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
    if cfg.proxy.http_port.is_some() {
        tracing::warn!(
            "config.toml still sets 'proxy.http_port'. It is ignored — the port a site \
             is served on is that site's own Listen Port, set in the GUI. Port 80 is \
             bound in any case, because Let's Encrypt validation always arrives there. \
             The line can be deleted."
        );
    }
    if cfg.proxy.acme_webroot.as_deref().is_some_and(|v| !v.trim().is_empty()) {
        tracing::warn!(
            "config.toml sets 'proxy.acme_webroot'. It is ignored — EasyWAF answers \
             HTTP-01 challenges itself, in the proxy, and writes no files. Nothing needs \
             to serve a directory. The line can be deleted."
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

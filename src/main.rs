// =========================================================
// main.rs — EasyWAF
// Entry point. Starts two servers in the same process:
//   • Management GUI — configured gui_port (default 8080)
//   • HTTP proxy     — one listener per unique listen_port;
//                      new ports can be added at runtime via
//                      AppState::port_tx without restarting.
// Both share the SQLite pool and module pipeline.
// =========================================================

mod acme;
mod auth;
mod cert;
mod challenge;
mod config;
mod db;
mod error;
mod geo;
mod modules;
mod proxy;
mod routes;
mod tls;

use auth::make_key;
use axum::{
    extract::FromRef,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use axum_extra::extract::cookie::Key;
use modules::{geoip::GeoIpModule, traffic::TrafficLogger, waf::WafModule, Pipeline};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tera::Tera;
use tokio::sync::mpsc;
use tower::ServiceBuilder;
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};
use axum::http::{header::CACHE_CONTROL, HeaderValue};
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

/// The account name and password that 0.4.0 and 0.4.1 seeded on first run.
///
/// Nothing creates this account any more: first run asks for a username and
/// password instead. They remain only so an installation upgraded from those
/// versions can still be told it is carrying a credential everybody knows —
/// the startup warning and the banner on the account page both check for it.
pub const DEFAULT_USERNAME: &str = "admin";
pub const DEFAULT_PASSWORD: &str = "admin";

// ─── AppState ────────────────────────────────────────────

/// Shared state for the management GUI handlers.
#[derive(Clone)]
pub struct AppState {
    pub db:       SqlitePool,
    pub tera:     Arc<Tera>,
    pub config:   Arc<config::Config>,
    pub key:      Key,
    /// Send a port number here to make the proxy bind a new listener at
    /// runtime — no restart needed. The proxy ignores already-bound ports.
    pub port_tx:  mpsc::Sender<proxy::BindRequest>,
}

/// Required so SignedCookieJar can extract the Key from AppState.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

// ─── main ────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // rustls needs a process-wide crypto provider chosen explicitly, since
    // axum-server is built with tls-rustls-no-provider to keep aws-lc-rs (and
    // its C build) out of the aarch64 cross-compile.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto provider");

    let cfg = config::load("config.toml");
    let db  = db::init(&config::database_url()).await;

    // Country lookups are done per request, so the database is opened once here.
    geo::init(cfg.proxy.geoip_db.as_deref().unwrap_or(""));

    // Generated and stored on first run, so no installation is left signing
    // cookies with a key published in the repository.
    let secret = auth::ensure_secret(&db).await;

    warn_if_default_password(&db).await;

    // ── Build module pipeline ─────────────────────────────
    // Modules run in order for every proxied request.
    // TrafficLogger always returns Pass; the proxy handler
    // writes the actual DB row via log_event().
    let mut pipeline = Pipeline::new();
    pipeline.add(TrafficLogger::new(db.clone()));
    // Country rules run before the pattern rules: if a whole country is denied
    // there is nothing to gain from scoring its payloads first.
    pipeline.add(GeoIpModule::new(db.clone()));
    // WAF module runs after traffic logging so every request is counted
    // even if it ends up being blocked.
    pipeline.add(WafModule::new(db.clone()));
    let pipeline = Arc::new(pipeline);

    // ── Build reqwest client ──────────────────────────────
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    // ── Channel: GUI → proxy for dynamic port binding ─────
    // Buffer of 32 is plenty — port changes are infrequent.
    let (port_tx, port_rx) = mpsc::channel::<proxy::BindRequest>(32);

    // Certificates are resolved per TLS handshake from an in-memory map, so
    // it has to be populated before any HTTPS listener starts accepting.
    if let Err(e) = tls::reload(&db).await {
        tracing::error!("Could not load site certificates: {}", e);
    }

    // ── Start proxy server (background task) ──────────────
    let proxy_state = proxy::ProxyState {
        db:         db.clone(),
        pipeline:   pipeline.clone(),
        client,
        secret:     secret.clone(),
        challenges: challenge::ChallengeStore::new(),
        is_tls:     false,
    };
    tokio::spawn(async move {
        proxy::start(proxy_state, port_rx).await;
    });

    // ── Traffic retention ─────────────────────────────────
    // Prunes traffic_events on the schedule set in Settings. Off by default.
    modules::traffic::spawn_retention_task(db.clone());

    // ── Build management GUI ──────────────────────────────
    let mut tera = Tera::new("templates/**/*.html")
        .unwrap_or_else(|e| panic!("Template loading failed: {}", e));
    // Exposes {{ version() }} to every template — see app_version().
    tera.register_function("version", app_version);
    let key = make_key(&secret);

    let gui_state = AppState {
        db:      db.clone(),
        tera:    Arc::new(tera),
        config:  Arc::new(cfg.clone()),
        key,
        port_tx,
    };

    let app = Router::new()
        .route("/",                      get(routes::dashboard::get_dashboard))
        .route("/setup",                 get(routes::setup::get_setup).post(routes::setup::post_setup))
        .route("/login",                 get(routes::login::get_login).post(routes::login::post_login))
        .route("/logout",                get(routes::login::get_logout))
        .route("/sites",                 get(routes::sites::get_sites))
        .route("/sites/new",             get(routes::sites::get_site_new))
        .route("/sites/create",          post(routes::sites::post_site_create))
        .route("/sites/{name}/edit",     get(routes::sites::get_site_edit))
        .route("/sites/{name}/update",   post(routes::sites::post_site_update))
        .route("/sites/{name}/acme",     post(routes::sites::post_site_acme))
        .route("/sites/{name}/toggle",   post(routes::sites::post_site_toggle))
        .route("/sites/{name}/delete",   post(routes::sites::post_site_delete))
        .route("/account",               get(routes::account::get_account))
        .route("/account/password",      post(routes::account::post_account_password))
        .route("/settings",              get(routes::settings::get_settings))
        .route("/settings/update",       post(routes::settings::post_settings_update))
        .route("/certs",                 get(routes::certs::get_certs))
        .route("/certs/new",             get(routes::certs::get_cert_new))
        .route("/certs/create",          post(routes::certs::post_cert_create))
        .route("/certs/{name}",          get(routes::certs::get_cert_detail))
        .route("/certs/{name}/delete",   post(routes::certs::post_cert_delete))
        .route("/policy",                get(routes::policy::get_policies))
        .route("/policy/new",            get(routes::policy::get_policy_new))
        .route("/policy/create",         post(routes::policy::post_policy_create))
        .route("/policy/{name}/edit",    get(routes::policy::get_policy_edit))
        .route("/policy/{name}/update",  post(routes::policy::post_policy_update))
        .route("/policy/{name}/delete",  post(routes::policy::post_policy_delete))
        .route("/policy/{name}/rules",                get(routes::rules::get_rules))
        .route("/policy/{name}/rules/new",            get(routes::rules::get_rule_new))
        .route("/policy/{name}/rules/create",         post(routes::rules::post_rule_create))
        .route("/policy/{name}/rules/seed",           post(routes::rules::post_seed_rules))
        .route("/policy/{name}/rules/import",         post(routes::rules::post_import_rules))
        .route("/policy/{name}/rules/bulk",           post(routes::rules::post_bulk_rules))
        .route("/policy/{name}/rules/catalog",        get(routes::rules::get_rules_catalog)
                                                         .post(routes::rules::post_rules_catalog))
        .route("/policy/{name}/rules/{id}/toggle",    post(routes::rules::post_rule_toggle))
        .route("/policy/{name}/rules/{id}/delete",    post(routes::rules::post_rule_delete))
        .route("/rules",                 get(routes::rules::get_all_rules))
        .route("/rules/new",             get(routes::rules::get_custom_rule_new))
        .route("/rules/create",          post(routes::rules::post_custom_rule_create))
        .route("/rules/{id}/edit",       get(routes::rules::get_rule_edit_global))
        .route("/rules/{id}/update",     post(routes::rules::post_rule_update_global))
        .route("/rules/{id}/toggle",     post(routes::rules::post_rule_toggle_global))
        .route("/rules/{id}/delete",     post(routes::rules::post_rule_delete_global))
        .route("/geoip",                 get(routes::geoip::get_geoip))
        .route("/traffic",               get(routes::traffic::get_traffic))
        // Serve static assets with Cache-Control: no-cache so the browser
        // always revalidates (cheap 304 when unchanged, fresh CSS/JS when
        // they change) — prevents stale cached stylesheets/scripts.
        .nest_service(
            "/static",
            ServiceBuilder::new()
                .layer(SetResponseHeaderLayer::overriding(
                    CACHE_CONTROL,
                    HeaderValue::from_static("no-cache"),
                ))
                .service(ServeDir::new("static")),
        )
        .with_state(gui_state);

    // ── Management interface: TLS, with plain HTTP redirecting to it ──
    // The certificate is generated on first run and reused afterwards, so the
    // GUI is never served over plain HTTP — the only thing on gui_port is a
    // redirect, which carries no session cookie because the cookie is Secure.
    let chosen = routes::settings::get_management_cert(&db).await;
    let (cert_name, cert_pem, key_pem) = cert::resolve_management(&db, &chosen)
        .await
        .expect("management certificate");

    // Built from the same profile and cipher settings as the proxied sites,
    // rather than from rustls's defaults. A policy that restricts ciphers
    // means the administrative interface too — it would be an odd appliance
    // whose own front door was the one exception to its TLS policy.
    let profile = routes::settings::get_tls_profile(&db).await;
    let suites  = routes::settings::get_tls_ciphers(&db).await;
    let tls = RustlsConfig::from_config(
        tls::single_cert_config(profile, &suites, &cert_pem, &key_pem)
            .expect("management TLS configuration"),
    );

    let redirect_addr: SocketAddr = format!("0.0.0.0:{}", cfg.proxy.gui_port)
        .parse()
        .expect("gui_port address");
    let tls_addr: SocketAddr = format!("0.0.0.0:{}", cfg.proxy.gui_tls_port)
        .parse()
        .expect("gui_tls_port address");

    spawn_https_redirect(redirect_addr, cfg.proxy.gui_tls_port);

    // Bind before announcing. bind_rustls binds lazily inside serve(), so
    // logging first would claim the GUI is listening and then panic if the
    // port were taken — the least helpful thing to find in a log when the
    // service will not start.
    let listener = match tls::bind_listener(tls_addr) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                "Cannot bind the management GUI to {}: {}. Another process is \
                 probably using the port — check with: ss -lntp | grep {}",
                tls_addr, e, cfg.proxy.gui_tls_port
            );
            std::process::exit(1);
        }
    };

    let server = match axum_server::from_tcp_rustls(listener, tls) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Cannot serve the management GUI on {}: {}", tls_addr, e);
            std::process::exit(1);
        }
    };

    info!("Management GUI listening on https://{} (certificate '{}')", tls_addr, cert_name);
    if let Err(e) = server.serve(app.into_make_service()).await {
        tracing::error!("Management GUI server error: {}", e);
        std::process::exit(1);
    }
}

// ─── spawn_https_redirect ────────────────────────────────

/// Serve nothing but redirects on the plain-HTTP management port.
///
/// An operator who types the old address, or a bookmark from before TLS, still
/// arrives somewhere useful instead of at a connection reset. Nothing else is
/// served here: the GUI itself only exists over TLS.
fn spawn_https_redirect(addr: SocketAddr, tls_port: u16) {
    let app = Router::new().fallback(move |req: axum::extract::Request| async move {
        redirect_to_https(req, tls_port)
    });

    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                info!("Management HTTP redirect listening on http://{}", addr);
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!("Management redirect server error: {}", e);
                }
            }
            // A failure here must not stop the GUI itself from serving: the
            // redirect is a convenience, the TLS listener is the product.
            Err(e) => tracing::error!(
                %addr,
                "Could not bind the management HTTP redirect port: {}", e
            ),
        }
    });
}

/// Build the redirect to the same host on the TLS port.
///
/// 307 rather than a permanent redirect: `gui_tls_port` is configurable, and a
/// permanently cached redirect would keep sending a browser to a port that no
/// longer listens, with no way to clear it but the user's cache.
fn redirect_to_https(req: axum::extract::Request, tls_port: u16) -> Response {
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host = host_without_port(host);

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");

    if host.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing Host header").into_response();
    }

    let location = if tls_port == 443 {
        format!("https://{}{}", host, path_and_query)
    } else {
        format!("https://{}:{}{}", host, tls_port, path_and_query)
    };

    Redirect::temporary(&location).into_response()
}

/// Strip the port from a Host header value.
///
/// An IPv6 literal arrives bracketed — `[::1]:8080` — so splitting on the
/// first colon would cut the address in half. The brackets are kept, since
/// that is how the address has to appear in the redirect URL too.
fn host_without_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.find(']') {
            Some(end) => &host[..end + 2],
            None => host,
        };
    }
    host.split(':').next().unwrap_or("")
}

// ─── app_version ─────────────────────────────────────────

/// Tera function returning the crate version, usable as `{{ version() }}` in
/// any template.
///
/// The About modal used to hard-code the version, which meant Cargo.toml and
/// the template had to be bumped together — they drifted for the 0.2.0 release,
/// which shipped a modal still reading 0.1.0. Reading it from the binary keeps
/// one source of truth.
fn app_version(_args: &HashMap<String, tera::Value>) -> tera::Result<tera::Value> {
    Ok(tera::Value::String(env!("CARGO_PKG_VERSION").to_string()))
}

// ─── warn_if_default_password ────────────────────────────

/// Warn on every start while an account still has the password 0.4.x seeded.
///
/// Nothing seeds `admin`/`admin` any more — a new installation sets its own
/// password at first run — but an installation upgraded from 0.4.0 or 0.4.1 may
/// still be carrying it, and the account that has it is the one that can change
/// everything. Repeated each start rather than logged once at creation: a
/// default credential stays dangerous until it is changed, and the single start
/// that mentioned it is long out of the journal by the time anyone looks.
async fn warn_if_default_password(db: &SqlitePool) {
    if routes::account::is_default_password(db, DEFAULT_USERNAME).await {
        tracing::warn!(
            "The '{}' account is still using the password seeded by an earlier \
             version. Change it under Account in the GUI — anyone who can reach \
             the management port knows it.",
            DEFAULT_USERNAME
        );
    }
}

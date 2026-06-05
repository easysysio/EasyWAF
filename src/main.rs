// =========================================================
// main.rs — EasyWAF
// Entry point. Starts two servers in the same process:
//   • Management GUI — configured gui_port (default 8080)
//   • HTTP proxy     — one listener per unique listen_port;
//                      new ports can be added at runtime via
//                      AppState::port_tx without restarting.
// Both share the SQLite pool and module pipeline.
// =========================================================

mod auth;
mod config;
mod db;
mod error;
mod modules;
mod proxy;
mod routes;

use auth::make_key;
use axum::{
    extract::FromRef,
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::Key;
use modules::{traffic::TrafficLogger, waf::WafModule, Pipeline};
use sqlx::SqlitePool;
use std::sync::Arc;
use tera::Tera;
use tokio::sync::mpsc;
use tower_http::services::ServeDir;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

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
    pub port_tx:  mpsc::Sender<u16>,
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

    let cfg = config::load("config.toml");
    let db  = db::init(&cfg.database_url).await;

    seed_admin(&db).await;

    // ── Build module pipeline ─────────────────────────────
    // Modules run in order for every proxied request.
    // TrafficLogger always returns Pass; the proxy handler
    // writes the actual DB row via log_event().
    let mut pipeline = Pipeline::new();
    pipeline.add(TrafficLogger::new(db.clone()));
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
    let (port_tx, port_rx) = mpsc::channel::<u16>(32);

    // ── Start proxy server (background task) ──────────────
    let proxy_state = proxy::ProxyState {
        db:       db.clone(),
        pipeline: pipeline.clone(),
        client,
    };
    tokio::spawn(async move {
        proxy::start(proxy_state, port_rx).await;
    });

    // ── Build management GUI ──────────────────────────────
    let tera = Tera::new("templates/**/*.html")
        .unwrap_or_else(|e| panic!("Template loading failed: {}", e));
    let key = make_key(&cfg.secret);

    let gui_state = AppState {
        db:      db.clone(),
        tera:    Arc::new(tera),
        config:  Arc::new(cfg.clone()),
        key,
        port_tx,
    };

    let app = Router::new()
        .route("/",                      get(routes::dashboard::get_dashboard))
        .route("/login",                 get(routes::login::get_login).post(routes::login::post_login))
        .route("/logout",                get(routes::login::get_logout))
        .route("/sites",                 get(routes::sites::get_sites))
        .route("/sites/new",             get(routes::sites::get_site_new))
        .route("/sites/create",          post(routes::sites::post_site_create))
        .route("/sites/{name}/edit",     get(routes::sites::get_site_edit))
        .route("/sites/{name}/update",   post(routes::sites::post_site_update))
        .route("/sites/{name}/delete",   post(routes::sites::post_site_delete))
        .route("/certs",                 get(routes::certs::get_certs))
        .route("/certs/new",             get(routes::certs::get_cert_new))
        .route("/certs/create",          post(routes::certs::post_cert_create))
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
        .route("/rules/{id}/edit",       get(routes::rules::get_rule_edit_global))
        .route("/rules/{id}/update",     post(routes::rules::post_rule_update_global))
        .route("/rules/{id}/toggle",     post(routes::rules::post_rule_toggle_global))
        .route("/rules/{id}/delete",     post(routes::rules::post_rule_delete_global))
        .route("/geoip",                 get(routes::geoip::get_geoip))
        .route("/traffic",               get(routes::traffic::get_traffic))
        .nest_service("/static",         ServeDir::new("static"))
        .with_state(gui_state);

    let gui_addr = format!("0.0.0.0:{}", cfg.proxy.gui_port);
    info!("Management GUI listening on http://{}", gui_addr);
    let listener = tokio::net::TcpListener::bind(&gui_addr)
        .await
        .unwrap_or_else(|e| panic!("Cannot bind GUI to {}: {}", gui_addr, e));

    axum::serve(listener, app).await.expect("GUI server error");
}

// ─── seed_admin ──────────────────────────────────────────

/// Insert a default admin/admin account if no users exist yet.
/// Logs a warning so the operator knows to change the password.
async fn seed_admin(db: &SqlitePool) {
    let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await
        .unwrap_or(0);

    if count == 0 {
        let hash = bcrypt::hash("admin", bcrypt::DEFAULT_COST).expect("bcrypt hash");
        sqlx::query!(
            "INSERT INTO users (username, password_hash) VALUES ('admin', ?)",
            hash
        )
        .execute(db)
        .await
        .expect("seed admin user");

        tracing::warn!(
            "No users found — created default account admin/admin. \
             Change this password immediately!"
        );
    }
}

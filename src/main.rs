// =========================================================
// main.rs — EasyWAF
// Server entry point: loads config, initialises DB, builds
// the Axum router with all routes and serves the app.
// =========================================================

mod auth;
mod config;
mod db;
mod error;
mod nginx;
mod routes;

use auth::make_key;
use axum::{
    extract::FromRef,
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::Key;
use sqlx::SqlitePool;
use std::sync::Arc;
use tera::Tera;
use tower_http::services::ServeDir;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

// ─── AppState ────────────────────────────────────────────

/// Shared application state cloned into every handler.
#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub tera: Arc<Tera>,
    pub config: Arc<config::Config>,
    pub key: Key,
}

// Required so SignedCookieJar can extract the Key from AppState.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

// ─── main ────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Initialise tracing.
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Load configuration.
    let cfg = config::load("config.toml");
    let bind_addr = format!("{}:{}", cfg.host, cfg.port);

    // Initialise database.
    let db = db::init(&cfg.database_url).await;

    // Seed default admin user if no users exist yet.
    seed_admin(&db).await;

    // Load Tera templates.
    let tera = Tera::new("templates/**/*.html")
        .unwrap_or_else(|e| panic!("Template loading failed: {}", e));

    // Build cookie signing key.
    let key = make_key(&cfg.secret);

    let state = AppState {
        db,
        tera: Arc::new(tera),
        config: Arc::new(cfg),
        key,
    };

    // Build router.
    let app = Router::new()
        // Dashboard
        .route("/", get(routes::dashboard::get_dashboard))
        // Auth
        .route("/login", get(routes::login::get_login).post(routes::login::post_login))
        .route("/logout", get(routes::login::get_logout))
        // Sites
        .route("/sites", get(routes::sites::get_sites))
        .route("/sites/new", get(routes::sites::get_site_new))
        .route("/sites/create", post(routes::sites::post_site_create))
        .route("/sites/{name}/edit", get(routes::sites::get_site_edit))
        .route("/sites/{name}/update", post(routes::sites::post_site_update))
        .route("/sites/{name}/delete", post(routes::sites::post_site_delete))
        // Certificates
        .route("/certs", get(routes::certs::get_certs))
        .route("/certs/new", get(routes::certs::get_cert_new))
        .route("/certs/create", post(routes::certs::post_cert_create))
        .route("/certs/{name}/delete", post(routes::certs::post_cert_delete))
        // Policies
        .route("/policy", get(routes::policy::get_policies))
        .route("/policy/new", get(routes::policy::get_policy_new))
        .route("/policy/create", post(routes::policy::post_policy_create))
        .route("/policy/{name}/edit", get(routes::policy::get_policy_edit))
        .route("/policy/{name}/update", post(routes::policy::post_policy_update))
        .route("/policy/{name}/delete", post(routes::policy::post_policy_delete))
        // GeoIP
        .route("/geoip", get(routes::geoip::get_geoip))
        // Static files (CSS, JS, fonts)
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);

    info!("EasyWAF listening on http://{}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| panic!("Cannot bind to {}: {}", bind_addr, e));

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

// ─── seed_admin ──────────────────────────────────────────

/// If no users exist, create a default admin/admin account and print a warning.
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
            "No users found - created default account admin/admin. \
             Change this password immediately!"
        );
    }
}

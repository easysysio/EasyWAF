// =========================================================
// db.rs — EasyWAF
// SQLite pool initialisation and schema migration.
// The database file is created automatically if it does not exist.
// New migrations are applied at startup without dropping existing data.
// =========================================================

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use std::str::FromStr;
use tracing::info;

// ─── init ────────────────────────────────────────────────

/// Open (or create) the SQLite database, run all migrations, and return the pool.
/// Safe to call on an existing database — each migration is applied only once.
pub async fn init(database_url: &str) -> SqlitePool {
    // Parse the URL and enable automatic file creation.
    let options = SqliteConnectOptions::from_str(database_url)
        .unwrap_or_else(|e| panic!("Invalid database URL '{}': {}", database_url, e))
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .unwrap_or_else(|e| panic!("Cannot open database '{}': {}", database_url, e));

    // Migration 001 — base schema (CREATE TABLE IF NOT EXISTS, always safe to re-run).
    let sql_001 = include_str!("../migrations/001_init.sql");
    sqlx::raw_sql(sql_001)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("Migration 001 failed: {}", e));

    // Migration 002 — per-site listen_port column.
    // ALTER TABLE fails if the column already exists, so we check first.
    run_migration_002(&pool).await;

    info!("Database ready: {}", database_url);
    pool
}

// ─── run_migration_002 ───────────────────────────────────

/// Add listen_port to the sites table if it is not already present.
/// This is the idempotent wrapper around migration 002.
async fn run_migration_002(pool: &SqlitePool) {
    // PRAGMA table_info returns one row per column; count matches for 'listen_port'.
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name = 'listen_port'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_002 = include_str!("../migrations/002_listen_port.sql");
        sqlx::raw_sql(sql_002)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 002 failed: {}", e));
        info!("Migration 002 applied: added listen_port to sites");
    }
}

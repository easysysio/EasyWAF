// =========================================================
// db.rs — EasyWAF
// SQLite pool initialisation and schema migration.
// The database file is created automatically if it does not exist.
// =========================================================

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use std::str::FromStr;
use tracing::info;

// ─── init ────────────────────────────────────────────────

/// Open (or create) the SQLite database, run migrations, and return the pool.
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

    // Run embedded migrations.
    let migration_sql = include_str!("../migrations/001_init.sql");
    sqlx::raw_sql(migration_sql)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("Migration failed: {}", e));

    info!("Database ready: {}", database_url);
    pool
}

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

    // Migration 003 — waf_rules table (CREATE TABLE IF NOT EXISTS, always safe).
    let sql_003 = include_str!("../migrations/003_waf_rules.sql");
    sqlx::raw_sql(sql_003)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("Migration 003 failed: {}", e));

    // Migration 004 — external_id column + unique index on waf_rules.
    // Uses column-exists check since ALTER TABLE fails if column already exists.
    run_migration_004(&pool).await;

    // Migration 005 — challenge_threshold column on policies.
    run_migration_005(&pool).await;
    run_migration_006(&pool).await;
    run_migration_007(&pool).await;
    run_migration_008(&pool).await;
    run_migration_009(&pool).await;
    run_migration_010(&pool).await;
    run_migration_011(&pool).await;
    run_migration_012(&pool).await;
    run_migration_013(&pool).await;
    run_migration_014(&pool).await;
    run_migration_015(&pool).await;
    run_migration_016(&pool).await;
    run_migration_017(&pool).await;
    run_migration_018(&pool).await;
    run_migration_019(&pool).await;
    run_migration_020(&pool).await;

    info!("Database ready: {}", database_url);
    pool
}

// ─── run_migration_020 ───────────────────────────────────

/// Move clones out of the set they were forked from and into custom.
async fn run_migration_020(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('waf_rules') WHERE name = 'cloned_from_set'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/020_clone_origin_set.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 020 failed: {}", e));
        info!("Migration 020 applied: a cloned rule is a custom rule");
    }
}

// ─── run_migration_019 ───────────────────────────────────

/// What the WAF would have done, so a detected-but-allowed request is
/// distinguishable from clean traffic.
async fn run_migration_019(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('traffic_events') WHERE name = 'detection'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/019_traffic_detection.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 019 failed: {}", e));
        info!("Migration 019 applied: traffic records say what the WAF would have done");
    }
}

// ─── run_migration_018 ───────────────────────────────────

/// Rules a site does not apply, so one site's false positive does not have to
/// be answered by weakening a rule for every site that shares the policy.
async fn run_migration_018(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'table' AND name = 'site_rule_exclusions'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/018_site_rule_exclusions.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 018 failed: {}", e));
        info!("Migration 018 applied: a site can exclude a rule");
    }
}

// ─── run_migration_017 ───────────────────────────────────

/// Extra ports a site answers on, beyond its primary pair.
async fn run_migration_017(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'site_ports'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/017_site_ports.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 017 failed: {}", e));
        info!("Migration 017 applied: a site can answer on more than one port");
    }
}

// ─── run_migration_016 ───────────────────────────────────

/// Claim rules that were imported before 015 gave them somewhere to say so.
///
/// Not a schema change, so it does not check for a column. It is safe to run on
/// every start and does nothing once there is nothing left to claim; see
/// `backfill_rule_sets` for why it is deliberately conservative about what it
/// will claim at all.
async fn run_migration_016(pool: &SqlitePool) {
    if let Err(e) = crate::routes::rules::backfill_rule_sets(pool).await {
        // Not fatal. A policy that stays unclaimed is a policy that is not
        // offered updates, which is where it already was — and refusing to
        // start over it would be worse than the problem.
        tracing::warn!("Could not adopt pre-0.6.0 rule sets: {e}");
    }
}

// ─── run_migration_015 ───────────────────────────────────

/// Which set a rule came from, and which version each policy holds.
async fn run_migration_015(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('waf_rules') WHERE name = 'rule_set'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/015_rule_sets.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 015 failed: {}", e));
        info!("Migration 015 applied: rules record their set, policies record set versions");
    }
}

// ─── run_migration_014 ───────────────────────────────────

/// Correct two rules by pattern, reaching databases that predate the
/// renumbering and so were missed by 012's match on external_id.
async fn run_migration_014(pool: &SqlitePool) {
    let sql = include_str!("../migrations/014_rule_false_positives_by_pattern.sql");
    match sqlx::raw_sql(sql).execute(pool).await {
        Ok(r) if r.rows_affected() > 0 => info!(
            "Migration 014 applied: corrected {} rule(s) that matched ordinary traffic",
            r.rows_affected()
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!("Migration 014 could not update rule patterns: {}", e),
    }
}

// ─── run_migration_013 ───────────────────────────────────

/// Which rules produced a verdict, stored on the traffic event.
async fn run_migration_013(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('traffic_events') WHERE name = 'matched_rules'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_013 = include_str!("../migrations/013_rule_attribution.sql");
        sqlx::raw_sql(sql_013)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 013 failed: {}", e));
        info!("Migration 013 applied: traffic events record which rules matched");
    }
}

// ─── run_migration_012 ───────────────────────────────────

/// Correct two bundled rules that scored ordinary traffic.
///
/// Unlike the others this adds no column, so there is nothing to check for
/// beforehand — it is written to be safe to run repeatedly, matching only the
/// exact patterns EasyWAF shipped and leaving an edited rule alone.
async fn run_migration_012(pool: &SqlitePool) {
    let sql_012 = include_str!("../migrations/012_rule_false_positives.sql");
    match sqlx::raw_sql(sql_012).execute(pool).await {
        Ok(r) if r.rows_affected() > 0 => {
            info!("Migration 012 applied: corrected {} bundled rule(s) that matched ordinary traffic", r.rows_affected());
        }
        Ok(_) => {}
        // Not fatal. A rule pattern that could not be corrected is a false
        // positive, not a broken schema, and refusing to start over it would
        // be the worse outcome.
        Err(e) => tracing::warn!("Migration 012 could not update rule patterns: {}", e),
    }
}

// ─── run_migration_011 ───────────────────────────────────

/// Per-site choice of X-Frame-Options value.
async fn run_migration_011(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name = 'x_frame_value'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_011 = include_str!("../migrations/011_x_frame_value.sql");
        sqlx::raw_sql(sql_011)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 011 failed: {}", e));
        info!("Migration 011 applied: X-Frame-Options value is now per site");
    }
}

// ─── run_migration_010 ───────────────────────────────────

/// Renewal tracking for ACME certificates.
async fn run_migration_010(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('certs') WHERE name = 'acme_last_attempt'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_010 = include_str!("../migrations/010_acme_renewal.sql");
        sqlx::raw_sql(sql_010)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 010 failed: {}", e));
        info!("Migration 010 applied: added ACME renewal tracking to certs");
    }
}

// ─── run_migration_004 ───────────────────────────────────

/// Add external_id to waf_rules if not already present.
/// This column links imported rules back to their source file ID.
async fn run_migration_004(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('waf_rules') WHERE name = 'external_id'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_004 = include_str!("../migrations/004_rules_external_id.sql");
        sqlx::raw_sql(sql_004)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 004 failed: {}", e));
        info!("Migration 004 applied: added external_id to waf_rules");
    }
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

// ─── run_migration_005 ───────────────────────────────────

/// Add challenge_threshold to the policies table if not already present.
async fn run_migration_005(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('policies') WHERE name = 'challenge_threshold'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_005 = include_str!("../migrations/005_challenge_threshold.sql");
        sqlx::raw_sql(sql_005)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 005 failed: {}", e));
        info!("Migration 005 applied: added challenge_threshold to policies");
    }
}

// ─── run_migration_006 ───────────────────────────────────

/// Create the settings table if it does not exist yet.
/// Unlike the column migrations above this one is checked against
/// sqlite_master, since the whole table is new rather than a single column.
async fn run_migration_006(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'settings'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_006 = include_str!("../migrations/006_settings.sql");
        sqlx::raw_sql(sql_006)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 006 failed: {}", e));
        info!("Migration 006 applied: created settings table");
    }
}

// ─── run_migration_007 ───────────────────────────────────

/// Add the per-policy country rule columns if not already present.
async fn run_migration_007(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('policies') WHERE name = 'geoip_mode'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_007 = include_str!("../migrations/007_policy_geoip.sql");
        sqlx::raw_sql(sql_007)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 007 failed: {}", e));
        info!("Migration 007 applied: added country rules to policies");
    }
}

// ─── run_migration_008 ───────────────────────────────────

/// Add the import-provenance columns to waf_rules if not already present.
async fn run_migration_008(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('waf_rules') WHERE name = 'imported_pattern'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_008 = include_str!("../migrations/008_rule_provenance.sql");
        sqlx::raw_sql(sql_008)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 008 failed: {}", e));
        info!("Migration 008 applied: added import provenance to waf_rules");
    }
}

// ─── run_migration_009 ───────────────────────────────────

/// Add the per-site HTTPS columns if not already present.
async fn run_migration_009(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name = 'tls_port'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql_009 = include_str!("../migrations/009_site_tls.sql");
        sqlx::raw_sql(sql_009)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 009 failed: {}", e));
        info!("Migration 009 applied: added HTTPS columns to sites");
    }
}

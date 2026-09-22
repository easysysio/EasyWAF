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
    run_migration_021(&pool).await;
    run_migration_022(&pool).await;
    run_migration_023(&pool).await;
    run_migration_024(&pool).await;
    run_migration_025(&pool).await;
    run_migration_026(&pool).await;
    run_migration_027(&pool).await;
    // 029 before 028 deliberately: it rebuilds both IP list tables, which
    // drops the triggers on them, and 028 is what puts those back.
    run_migration_029(&pool).await;
    run_migration_028(&pool).await;
    run_migration_030(&pool).await;
    run_migration_031(&pool).await;
    run_migration_032(&pool).await;
    run_migration_033(&pool).await;

    info!("Database ready: {}", database_url);
    pool
}

// ─── run_migration_033 ───────────────────────────────────

/// The version an update replaced, kept so it can be put back. Every start:
/// `CREATE TABLE IF NOT EXISTS`.
async fn run_migration_033(pool: &SqlitePool) {
    let sql = include_str!("../migrations/033_rule_set_rollback.sql");
    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("Migration 033 failed: {}", e));
}

// ─── run_migration_032 ───────────────────────────────────

/// Session affinity, per site. Added when the column is missing, since
/// `ALTER TABLE ADD COLUMN` fails on a database that already has it.
async fn run_migration_032(pool: &SqlitePool) {
    let done: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name = 'affinity'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    if done > 0 {
        return;
    }

    let sql = include_str!("../migrations/032_site_affinity.sql");
    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("Migration 032 failed: {}", e));

    info!("Migration 032 applied: a site can pin a client to one backend");
}

// ─── run_migration_031 ───────────────────────────────────

/// A site can have more than one upstream.
///
/// Moves `sites.target` into an `upstreams` table, one row per site, and adds
/// the traffic column naming the upstream that served a request. Nothing
/// changes for a site until a second upstream is added to it.
async fn run_migration_031(pool: &SqlitePool) {
    let done: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'upstreams'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    if done > 0 {
        return;
    }

    // One transaction: half of this is a database whose sites have no upstream
    // at all, which is every site down.
    let sql = include_str!("../migrations/031_upstreams.sql");
    let mut tx = pool
        .begin()
        .await
        .unwrap_or_else(|e| panic!("Migration 031 could not start: {}", e));
    sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("Migration 031 failed: {}", e));
    tx.commit()
        .await
        .unwrap_or_else(|e| panic!("Migration 031 could not commit: {}", e));

    info!("Migration 031 applied: a site's upstream moved into the upstreams table");
}

// ─── run_migration_030 ───────────────────────────────────

/// A country rule can apply to every policy. Every start: all of it is
/// `IF NOT EXISTS` or `INSERT OR IGNORE`.
async fn run_migration_030(pool: &SqlitePool) {
    let sql = include_str!("../migrations/030_geoip_everywhere.sql");
    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("Migration 030 failed: {}", e));
}

// ─── run_migration_029 ───────────────────────────────────

/// An IP list entry can belong to every policy.
///
/// Rebuilds both IP list tables so `policy_id` may be NULL, which means every
/// policy — the ones that exist and the ones made later. Nothing moves: every
/// existing row still names the policy it named.
async fn run_migration_029(pool: &SqlitePool) {
    // notnull is 1 while the column still refuses NULL, which is exactly the
    // database this has not been applied to.
    let pending: i64 = sqlx::query_scalar(
        r#"SELECT COALESCE(MAX("notnull"), 0) FROM pragma_table_info('ip_rules')
           WHERE name = 'policy_id'"#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    if pending == 0 {
        return;
    }

    // One transaction: half of this leaves a database with no IP lists.
    let sql = include_str!("../migrations/029_ip_lists_everywhere.sql");
    let mut tx = pool
        .begin()
        .await
        .unwrap_or_else(|e| panic!("Migration 029 could not start: {}", e));
    sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("Migration 029 failed: {}", e));
    tx.commit()
        .await
        .unwrap_or_else(|e| panic!("Migration 029 could not commit: {}", e));

    info!("Migration 029 applied: an IP list entry can now belong to every policy");
}

// ─── run_migration_028 ───────────────────────────────────

/// IP lists and exclusions move the configuration generation. Every start.
async fn run_migration_028(pool: &SqlitePool) {
    let sql = include_str!("../migrations/028_policy_scope_generation.sql");
    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("Migration 028 failed: {}", e));
}

// ─── run_migration_027 ───────────────────────────────────

/// IP lists and rule exclusions belong to a policy.
///
/// The one migration that makes something apply more widely than it did, so it
/// says so before it runs: every exclusion that now covers more sites, and
/// every one dropped, is logged by name. An operator reading the start-up log
/// after the upgrade finds out there, rather than from a request the rule
/// should have caught.
async fn run_migration_027(pool: &SqlitePool) {
    let done: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('ip_rules') WHERE name = 'policy_id'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    if done > 0 {
        return;
    }

    report_exclusion_moves(pool).await;
    report_ip_list_moves(pool).await;

    // One transaction: the tables are rebuilt and renamed, and a failure half
    // way would leave a database with no IP lists and no exclusions at all.
    let sql = include_str!("../migrations/027_policy_scope.sql");
    let mut tx = pool
        .begin()
        .await
        .unwrap_or_else(|e| panic!("Migration 027 could not start: {}", e));
    sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("Migration 027 failed: {}", e));
    tx.commit()
        .await
        .unwrap_or_else(|e| panic!("Migration 027 could not commit: {}", e));

    info!("Migration 027 applied: IP lists and rule exclusions now belong to a policy");
}

/// Log each exclusion that migration 027 widens or drops.
///
/// Runtime queries rather than `query!`: the table they read does not exist in
/// a current schema, which is the one sqlx checks them against.
async fn report_exclusion_moves(pool: &SqlitePool) {
    /// Site, policy, catalogue number, custom rule, path, client, and how many
    /// sites share the policy.
    type OldExclusion = (String, Option<String>, Option<i64>, Option<i64>, String, String, i64);

    if !table_exists(pool, "site_rule_exclusions").await {
        return;
    }
    let rows: Vec<OldExclusion> =
        sqlx::query_as(
            "SELECT s.server_name, p.name, e.external_id, e.rule_id, e.path_prefix,
                    IFNULL(e.client_cidr, ''),
                    (SELECT COUNT(*) FROM sites o
                     WHERE o.waf_policy_id = s.waf_policy_id)
             FROM   site_rule_exclusions e
             JOIN   sites s ON s.id = e.site_id
             LEFT   JOIN policies p ON p.id = s.waf_policy_id
             ORDER  BY e.id",
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    for (site, policy, external_id, rule_id, prefix, client, sharing) in rows {
        let rule = match (external_id, rule_id) {
            (Some(e), _) => format!("rule {e}"),
            (_, Some(r)) => format!("custom rule #{r}"),
            _            => "a rule".to_string(),
        };
        let scope = match (prefix.as_str(), client.as_str()) {
            ("", "") => String::new(),
            (p, "")  => format!(" under {p}"),
            ("", c)  => format!(" for {c}"),
            (p, c)   => format!(" under {p} for {c}"),
        };
        match policy {
            None => tracing::warn!(
                "Migration 027: dropped the exclusion of {rule}{scope} on {site} — \
                 the site has no policy, so the exclusion silenced nothing"
            ),
            Some(p) if sharing > 1 => tracing::warn!(
                "Migration 027: the exclusion of {rule}{scope}, made for {site}, now \
                 applies to all {sharing} sites using policy {p}"
            ),
            Some(_) => {}
        }
    }
}

/// Log what migration 027 does to the IP lists.
async fn report_ip_list_moves(pool: &SqlitePool) {
    let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_rules")
        .fetch_one(pool).await.unwrap_or(0);
    let lists_on: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_list_feeds WHERE enabled = 1")
        .fetch_one(pool).await.unwrap_or(0);
    if entries == 0 && lists_on == 0 {
        return;
    }
    let policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies")
        .fetch_one(pool).await.unwrap_or(0);
    info!(
        "Migration 027: {entries} IP list entries and {lists_on} switched-on published \
         lists are copied into each of {policies} policies"
    );
    let bare: Vec<String> = sqlx::query_scalar(
        "SELECT server_name FROM sites WHERE waf_policy_id IS NULL ORDER BY server_name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    if !bare.is_empty() {
        tracing::warn!(
            "Migration 027: these sites have no policy and no longer get IP lists — \
             attach a policy to keep them: {}",
            bare.join(", ")
        );
    }
}

async fn table_exists(pool: &SqlitePool, name: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap_or(0)
        > 0
}

// ─── run_migration_026 ───────────────────────────────────

/// What the operator has decided about each published IP list.
async fn run_migration_026(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ip_list_feeds'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/026_ip_list_feeds.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 026 failed: {}", e));
        info!("Migration 026 applied: published IP lists can be switched on per list");
    }
}

// ─── run_migration_025 ───────────────────────────────────

/// The configuration generation and the triggers that move it.
///
/// Run on every start, not only when the table is missing: every statement is
/// idempotent, and re-running restores a trigger somebody dropped by hand —
/// which would otherwise leave every cache serving what it last read, forever.
async fn run_migration_025(pool: &SqlitePool) {
    let existed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'config_generation'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let sql = include_str!("../migrations/025_config_generation.sql");
    sqlx::raw_sql(sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("Migration 025 failed: {}", e));

    if existed == 0 {
        info!("Migration 025 applied: inspection caches its configuration and notices every change");
    }
}

// ─── run_migration_024 ───────────────────────────────────

/// IP allow and block lists.
async fn run_migration_024(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ip_rules'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/024_ip_rules.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 024 failed: {}", e));
        info!("Migration 024 applied: an address can be allowed or blocked outright");
    }
}

// ─── run_migration_023 ───────────────────────────────────

/// Additional hostnames a site answers for.
async fn run_migration_023(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'site_aliases'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/023_site_aliases.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 023 failed: {}", e));
        info!("Migration 023 applied: a site can answer for more than one hostname");
    }
}

// ─── run_migration_022 ───────────────────────────────────

/// Roles, an enabled flag, and a session epoch that makes sign-out possible.
///
/// Every account that exists when this runs becomes an admin. Those are the
/// accounts somebody has been administering the appliance with, and any other
/// default locks them out of their own installation on upgrade.
async fn run_migration_022(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'role'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 {
        let sql = include_str!("../migrations/022_user_roles.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 022 failed: {}", e));
        info!("Migration 022 applied: accounts have roles, and sessions can be ended");
    }
}

// ─── run_migration_021 ───────────────────────────────────

/// Which clients a rule exclusion applies to.
async fn run_migration_021(pool: &SqlitePool) {
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('site_rule_exclusions')
         WHERE name = 'client_cidr'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    if exists == 0 && table_exists(pool, "site_rule_exclusions").await {
        let sql = include_str!("../migrations/021_exclusion_client_ip.sql");
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration 021 failed: {}", e));
        info!("Migration 021 applied: an exclusion can name a client address");
    }
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

    // Replaced by policy_rule_exclusions in 027; never recreate it after that.
    if exists == 0 && !table_exists(pool, "policy_rule_exclusions").await {
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

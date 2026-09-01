// =========================================================
// modules/traffic.rs — EasyWAF
// Traffic logging module, plus retention pruning.
//
// Always returns Pass. Logs every request to the
// traffic_events table asynchronously after the response
// is sent, so it never adds latency to the proxy path.
// The proxy handler calls log() explicitly; this module
// itself only returns Pass during pipeline inspection.
// =========================================================

use crate::modules::{InspectionModule, ModuleDecision, RequestContext};
use sqlx::SqlitePool;
use std::time::Duration;

// ─── TrafficLogger ───────────────────────────────────────

/// Pipeline module that always returns Pass.
/// Actual DB writes happen in the proxy handler via log_event(),
/// not here, so no DB handle is needed on this struct.
pub struct TrafficLogger;

impl TrafficLogger {
    /// Create a new TrafficLogger. The `db` parameter is accepted for
    /// API symmetry with other modules but is not stored here.
    pub fn new(_db: SqlitePool) -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl InspectionModule for TrafficLogger {
    fn name(&self) -> &'static str { "traffic" }

    /// Traffic logger never blocks — it always passes.
    async fn inspect(&self, _ctx: &RequestContext) -> ModuleDecision {
        ModuleDecision::Pass
    }
}

// ─── TrafficRecord ───────────────────────────────────────

/// Completed request info written to traffic_events.
pub struct TrafficRecord {
    pub site_id:      i64,
    pub client_ip:    String,
    pub method:       String,
    pub host:         String,
    pub path:         String,
    pub status_code:  i64,
    pub response_ms:  i64,
    pub blocked:      bool,
    pub block_reason: Option<String>,
    pub waf_score:    Option<i64>,
    pub country:      Option<String>,
}

/// Insert one traffic record into the DB.
/// Call this with tokio::spawn to avoid blocking the response path.
pub async fn log_event(db: SqlitePool, r: TrafficRecord) {
    let blocked = r.blocked as i64;
    let res = sqlx::query!(
        "INSERT INTO traffic_events
         (site_id, client_ip, method, host, path, status_code,
          response_ms, blocked, block_reason, waf_score, country)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        r.site_id,
        r.client_ip,
        r.method,
        r.host,
        r.path,
        r.status_code,
        r.response_ms,
        blocked,
        r.block_reason,
        r.waf_score,
        r.country,
    )
    .execute(&db)
    .await;

    if let Err(e) = res {
        tracing::error!("Failed to log traffic event: {}", e);
    }
}

// ─── Retention ───────────────────────────────────────────

/// How often the retention sweep runs after the one at startup.
const PRUNE_INTERVAL: Duration = Duration::from_secs(3600);

/// Delete traffic events older than `days`. Returns the number of rows removed.
///
/// `days <= 0` means "keep everything" and deletes nothing — that is the
/// default, so an installation that never visits Settings behaves exactly as
/// it did before retention existed.
///
/// Rows are aged by their own `timestamp` column, which is written by SQLite
/// at insert time, so a clock change does not strand old rows.
pub async fn prune_old_events(db: &SqlitePool, days: i64) -> u64 {
    if days <= 0 {
        return 0;
    }

    // datetime() takes the modifier as a string, so it is built here rather
    // than bound as a parameter.
    let cutoff = format!("-{} days", days);
    let res = sqlx::query!(
        "DELETE FROM traffic_events WHERE timestamp < datetime('now', ?)",
        cutoff
    )
    .execute(db)
    .await;

    match res {
        Ok(r)  => r.rows_affected(),
        Err(e) => {
            tracing::error!("Traffic retention prune failed: {}", e);
            0
        }
    }
}

/// Run the retention sweep once at startup and then hourly, forever.
///
/// The setting is re-read on every pass, so a change made in the GUI takes
/// effect on the next sweep without a restart.
pub fn spawn_retention_task(db: SqlitePool) {
    tokio::spawn(async move {
        loop {
            let days = crate::routes::settings::get_retention_days(&db).await;
            if days > 0 {
                let removed = prune_old_events(&db, days).await;
                if removed > 0 {
                    tracing::info!(
                        days,
                        removed,
                        "Traffic retention: deleted events older than the retention window"
                    );
                }
            }
            tokio::time::sleep(PRUNE_INTERVAL).await;
        }
    });
}

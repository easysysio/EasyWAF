// =========================================================
// modules/traffic.rs — EasyWAF
// Traffic logging module.
//
// Always returns Pass. Logs every request to the
// traffic_events table asynchronously after the response
// is sent, so it never adds latency to the proxy path.
// The proxy handler calls log() explicitly; this module
// itself only returns Pass during pipeline inspection.
// =========================================================

use crate::modules::{InspectionModule, ModuleDecision, RequestContext};
use sqlx::SqlitePool;

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

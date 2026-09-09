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
    /// The query string, if any. Carried for the flow line only — the database
    /// column has always held the path alone, and widening it is a migration
    /// and a separate decision. The line needs it because a query string is
    /// where most of what a WAF matches actually lives.
    pub query:        Option<String>,
    pub status_code:  i64,
    pub response_ms:  i64,
    pub blocked:      bool,
    pub block_reason: Option<String>,
    pub waf_score:    Option<i64>,
    /// JSON list of the rules that matched; None when none did.
    pub matched_rules: Option<String>,
    pub country:      Option<String>,
    /// What the WAF would have done, when it did not do it — see
    /// `modules::Detection`. None on clean traffic and on actual blocks.
    pub detection:    Option<String>,
}

// ─── flow_line ───────────────────────────────────────────

/// One proxied request, as the `easywaf` syslog type.
///
/// The format is a contract with EasyLog and is specified in
/// docs/design/easylog-easywaf-type.md — logfmt, unknown keys ignorable,
/// values quoted only when they could otherwise split the line. Changing a
/// field name here changes what a parser in another repository sees.
///
/// Built from the same record that becomes the database row, in the same
/// call, so the line and the row cannot describe different events.
fn flow_line(r: &TrafficRecord, site: &str) -> String {
    use crate::logging::{clip, field};

    // The verdict, collapsed from the three things that record one: whether it
    // was refused, what the WAF would have done, and whether the reason says a
    // challenge was shown.
    let challenged = r
        .block_reason
        .as_deref()
        .is_some_and(|s| s.starts_with("challenge:"));
    let verdict = if r.blocked {
        "blocked"
    } else if challenged {
        "challenged"
    } else {
        match r.detection.as_deref() {
            Some("would_block")     => "would_block",
            Some("would_challenge") => "would_challenge",
            Some(_)                 => "scored",
            None                    => "passed",
        }
    };

    // Path and query, as the specification says `path` carries.
    let target = match r.query.as_deref() {
        Some(q) if !q.is_empty() => format!("{}?{}", r.path, q),
        _ => r.path.clone(),
    };

    let mut out = format!(
        "ts={} site={} host={} client={} method={} path={} status={} ms={} verdict={}",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        field(site),
        field(&r.host),
        field(&r.client_ip),
        field(&r.method),
        field(&clip(&target, 512)),
        r.status_code,
        r.response_ms,
        verdict,
    );

    // Optional fields are omitted rather than emitted empty: the spec is
    // explicit that a missing `score` and `score=0` are different facts.
    if let Some(c) = &r.country {
        if !c.is_empty() {
            out.push_str(&format!(" country={}", field(c)));
        }
    }
    if let Some(s) = r.waf_score {
        out.push_str(&format!(" score={s}"));
    }
    if let Some(json) = &r.matched_rules
        && let Ok(hits) = serde_json::from_str::<Vec<crate::modules::RuleHit>>(json)
    {
        // Catalogue numbers only. A custom rule has none, so `rules` can be
        // absent while `score` is present — which the spec calls out.
        let ids: Vec<String> = hits.iter().filter_map(|h| h.id).map(|i| i.to_string()).collect();
        if !ids.is_empty() {
            out.push_str(&format!(" rules={}", ids.join(",")));
        }
    }
    if let Some(reason) = &r.block_reason {
        if !reason.is_empty() {
            out.push_str(&format!(" reason={}", field(&clip(reason, 256))));
        }
    }
    out
}

/// Insert one traffic record into the DB, and emit the flow line.
/// Call this with tokio::spawn to avoid blocking the response path.
pub async fn log_event(db: SqlitePool, logger: crate::logging::Logger, r: TrafficRecord) {
    let blocked = r.blocked as i64;
    let res = sqlx::query!(
        "INSERT INTO traffic_events
         (site_id, client_ip, method, host, path, status_code,
          response_ms, blocked, block_reason, waf_score, country, matched_rules,
          detection)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        r.matched_rules,
        r.detection,
    )
    .execute(&db)
    .await;

    if let Err(e) = res {
        tracing::error!("Failed to log traffic event: {}", e);
    }

    // After the row, so the site name can come from the database rather than
    // being threaded through every call site. A site deleted between the
    // request and this line reports its id, which is worth more than nothing.
    let site = sqlx::query_scalar!("SELECT name FROM sites WHERE id = ?", r.site_id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| format!("site-{}", r.site_id));
    logger.flow(flow_line(&r, &site));
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

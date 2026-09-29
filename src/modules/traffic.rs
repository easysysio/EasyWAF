// =========================================================
// modules/traffic.rs — EasyWAF
// Traffic logging module, plus retention pruning.
//
// Every request is recorded in the traffic_events table by
// one writer task, which takes rows from a bounded queue and
// inserts them in batches, so the proxy path never waits for
// a write. The proxy handler queues each row with
// TrafficWriter::record. Also the retention sweep.
// =========================================================

use sqlx::SqlitePool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

// ─── TrafficRecord ───────────────────────────────────────

/// Completed request info written to traffic_events.
pub struct TrafficRecord {
    pub site_id:      i64,
    /// The site's name, for the flow line. Passed in because the proxy has it
    /// already, rather than read back from the database for every row.
    pub site_name:    String,
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
    /// Which upstream served the request. None when none was reached: a
    /// blocked request, or a site with nothing to forward to.
    ///
    /// Without it, "this site is intermittently slow" cannot be traced to one
    /// bad backend, which is the most common thing load balancing is asked to
    /// help diagnose.
    pub upstream:     Option<String>,
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
fn flow_line(r: &TrafficRecord) -> String {
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
        field(&r.site_name),
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
    if let Some(c) = &r.country
        && !c.is_empty()
    {
        out.push_str(&format!(" country={}", field(c)));
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
    if let Some(reason) = &r.block_reason
        && !reason.is_empty()
    {
        out.push_str(&format!(" reason={}", field(&clip(reason, 256))));
    }
    out
}

// ─── The writer ──────────────────────────────────────────

/// How many rows may wait to be written before new ones are dropped.
///
/// About a second and a half of traffic at the rate a single core serves
/// blocked requests, so a burst is absorbed whole; bounded, so a database that
/// has stopped answering costs a few megabytes rather than growing until the
/// process dies. The same trade the flow log makes, and for the same reason.
const QUEUE: usize = 20_000;

/// At most this many rows in one transaction.
const BATCH: usize = 1_000;

/// Hands traffic rows to the one task that writes them.
///
/// One writer, not an insert per request: separate inserts are a transaction
/// each, and several at once compete for SQLite's single write lock and mostly
/// sleep waiting for it — about 2,850 rows a second with a backlog, which
/// grows without limit while traffic arrives faster. One writer taking
/// whatever has queued, up to [`BATCH`] rows in a transaction, never waits on
/// itself.
///
/// Cheap to clone: a channel sender and a counter.
#[derive(Clone)]
pub struct TrafficWriter {
    tx:      mpsc::Sender<TrafficRecord>,
    dropped: Arc<AtomicU64>,
}

impl TrafficWriter {
    /// Start the writer task. Flow lines go to `logger` as their rows are
    /// written, so the line and the row still come from the same record.
    pub fn start(db: SqlitePool, logger: crate::logging::Logger) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        tokio::spawn(write_rows(db, logger, rx, dropped.clone()));
        Self { tx, dropped }
    }

    /// Queue one row. Never waits: a full queue drops the row and counts it,
    /// because a request held up by its own log line has turned logging into
    /// an outage.
    pub fn record(&self, r: TrafficRecord) {
        if self.tx.try_send(r).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Write queued rows in batches until every sender is gone.
async fn write_rows(
    db: SqlitePool,
    logger: crate::logging::Logger,
    mut rx: mpsc::Receiver<TrafficRecord>,
    dropped: Arc<AtomicU64>,
) {
    // Dropped rows are reported, not left silent: they are what this design
    // trades for never stalling a request, so they have to be visible without
    // reading code.
    let mut report = tokio::time::interval(Duration::from_secs(300));
    report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_reported = 0u64;
    let mut batch = Vec::with_capacity(BATCH);

    loop {
        tokio::select! {
            n = rx.recv_many(&mut batch, BATCH) => {
                if n == 0 {
                    break;
                }
                if let Err(e) = insert_rows(&db, &batch).await {
                    dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
                    tracing::error!(rows = batch.len(), "Failed to record traffic: {e}");
                }
                if logger.flow_enabled() {
                    for r in &batch {
                        logger.flow(flow_line(r));
                    }
                }
                batch.clear();
            }
            _ = report.tick() => {
                let n = dropped.load(Ordering::Relaxed);
                if n > last_reported {
                    tracing::warn!(
                        total = n, since_last = n - last_reported,
                        "Traffic rows were dropped: requests arrived faster than they could be recorded"
                    );
                    last_reported = n;
                }
            }
        }
    }
}

/// Rows per INSERT statement. Each row binds 14 values, so 500 stays far
/// inside SQLite's 32,766-variable limit.
const ROWS_PER_STATEMENT: usize = 500;

/// Insert a batch of rows in one transaction: all of them or, on an error,
/// none.
///
/// Many rows to a statement rather than one: a statement costs a round trip to
/// the connection's thread, and one per row held the writer near 27,000 rows a
/// second — below what the proxy can serve.
async fn insert_rows(db: &SqlitePool, rows: &[TrafficRecord]) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    for chunk in rows.chunks(ROWS_PER_STATEMENT) {
        let mut insert = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO traffic_events
             (site_id, client_ip, method, host, path, status_code,
              response_ms, blocked, block_reason, waf_score, country, matched_rules,
              detection, upstream) ",
        );
        insert.push_values(chunk, |mut row, r| {
            row.push_bind(r.site_id)
                .push_bind(&r.client_ip)
                .push_bind(&r.method)
                .push_bind(&r.host)
                .push_bind(&r.path)
                .push_bind(r.status_code)
                .push_bind(r.response_ms)
                .push_bind(r.blocked as i64)
                .push_bind(&r.block_reason)
                .push_bind(r.waf_score)
                .push_bind(&r.country)
                .push_bind(&r.matched_rules)
                .push_bind(&r.detection)
                .push_bind(&r.upstream);
        });
        insert.build().execute(&mut *tx).await?;
    }
    tx.commit().await
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

#[cfg(test)]
mod writer_tests {
    use super::*;

    fn row(i: usize) -> TrafficRecord {
        let blocked = i % 2 == 1;
        TrafficRecord {
            site_id:       1,
            site_name:     "shop".into(),
            client_ip:     "203.0.113.9".into(),
            method:        "GET".into(),
            host:          "shop.example".into(),
            path:          format!("/item/{i}"),
            query:         None,
            status_code:   if blocked { 403 } else { 200 },
            response_ms:   3,
            blocked,
            block_reason:  blocked.then(|| "WAF score 10 ≥ block threshold 10".into()),
            waf_score:     blocked.then_some(10),
            matched_rules: None,
            country:       Some("NL".into()),
            detection:     None,
            upstream:      (!blocked).then(|| "http://10.0.0.1:8080".into()),
        }
    }

    #[tokio::test]
    async fn every_queued_row_is_written_across_several_batches() {
        let path = std::env::temp_dir()
            .join(format!("easywaf-traffic-{}.db", std::process::id()));
        for sfx in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{}{sfx}", path.display())); }
        let db = crate::db::init(&format!("sqlite://{}", path.display())).await;
        sqlx::raw_sql("INSERT INTO sites (name, server_name) VALUES ('shop', 'shop.example')")
            .execute(&db).await.unwrap();

        let writer = TrafficWriter::start(db.clone(), crate::logging::Logger::disabled());
        let n = BATCH * 2 + 500;
        for i in 0..n {
            writer.record(row(i));
        }

        let count = || async {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM traffic_events").fetch_one(&db).await.unwrap()
        };
        for _ in 0..100 {
            if count().await as usize == n { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(count().await as usize, n, "rows were lost between the queue and the table");
        assert_eq!(writer.dropped.load(Ordering::Relaxed), 0);

        // Each column carries its own value through the batch, not a neighbour's.
        let (blocked, score, upstream): (i64, Option<i64>, Option<String>) = sqlx::query_as(
            "SELECT blocked, waf_score, upstream FROM traffic_events WHERE path = '/item/7'")
            .fetch_one(&db).await.unwrap();
        assert_eq!((blocked, score, upstream), (1, Some(10), None));

        db.close().await;
        for sfx in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{}{sfx}", path.display())); }
    }
}

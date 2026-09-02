// =========================================================
// routes/dashboard.rs — EasyWAF
// Dashboard: summary counts + recent traffic stats, an
// hourly requests chart, and a per-site breakdown of what
// was passed, challenged and blocked over the last 24 hours.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::Serialize;
use std::collections::HashMap;
use tera::Context;

// ─── TrafficSummary ──────────────────────────────────────

#[derive(Debug, Serialize)]
struct TrafficSummary {
    total:      i64,
    passed:     i64,
    challenged: i64,
    blocked:    i64,
}

// ─── HourBucket ──────────────────────────────────────────

/// One hour of the 24-hour requests chart. Every hour in the window is
/// present, including empty ones, so the chart's x-axis spans the whole day
/// rather than collapsing quiet periods.
#[derive(Debug, Serialize)]
struct HourBucket {
    /// Hour label in UTC, "HH:00" — matches the timestamps stored by SQLite.
    hour:       String,
    passed:     i64,
    challenged: i64,
    blocked:    i64,
}

// ─── SiteTraffic ─────────────────────────────────────────

/// One row of the per-site traffic breakdown shown on the dashboard.
/// Every enabled or disabled site appears, including ones with no traffic,
/// so a site that is configured but idle is visible rather than missing.
#[derive(Debug, Serialize)]
struct SiteTraffic {
    name:        String,
    server_name: String,
    total:       i64,
    passed:      i64,
    challenged:  i64,
    blocked:     i64,
    /// Shares of this site's requests, whole percent, for the mix bar.
    /// All three are 0 when the site saw no traffic in the window.
    passed_pct:     i64,
    challenged_pct: i64,
    blocked_pct:    i64,
}

// ─── get_dashboard ───────────────────────────────────────

pub async fn get_dashboard(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    // Summary counts.
    let sites_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM sites")
            .fetch_one(&state.db).await?;

    let certs_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM certs")
            .fetch_one(&state.db).await?;

    let policies_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM policies")
            .fetch_one(&state.db).await?;

    // One window shared by every panel below. Truncating to the top of the
    // hour makes it exactly the 24 buckets the chart draws, so the totals, the
    // per-site table and the chart cannot disagree with each other.
    let window_start = window_start();

    // Traffic stats — last 24 hours.
    let totals = sqlx::query!(
        r#"SELECT COUNT(*)                  as "total!: i64",
                  COALESCE(SUM(blocked), 0) as "blocked!: i64",
                  COALESCE(SUM(
                      CASE WHEN blocked = 0
                            AND block_reason LIKE 'challenge:%'
                           THEN 1 ELSE 0 END
                  ), 0)                     as "challenged!: i64"
           FROM traffic_events
           WHERE timestamp >= ?"#,
        window_start
    )
    .fetch_one(&state.db)
    .await?;

    let traffic = TrafficSummary {
        total:      totals.total,
        passed:     totals.total - totals.blocked - totals.challenged,
        challenged: totals.challenged,
        blocked:    totals.blocked,
    };

    // Per-site breakdown and hourly chart for the same 24-hour window.
    let site_traffic = fetch_site_traffic(&state, &window_start).await?;
    let chart        = fetch_hourly_traffic(&state, &window_start).await?;

    let mut ctx = Context::new();
    ctx.insert("username",       &session.username);
    ctx.insert("title",          "Dashboard");
    ctx.insert("url",            "/");
    ctx.insert("sites_number",   &sites_count);
    ctx.insert("certs_number",   &certs_count);
    ctx.insert("policy_number",  &policies_count);
    ctx.insert("traffic",        &traffic);
    ctx.insert("site_traffic",   &site_traffic);
    ctx.insert("chart",          &chart);

    Ok((jar, Html(state.tera.render("dashboard.html", &ctx)?)).into_response())
}

// ─── DB helpers ──────────────────────────────────────────

/// Count each site's requests over the last 24 hours, split into passed,
/// challenged and blocked.
///
/// A LEFT JOIN keeps sites with no traffic in the result, and the time window
/// sits in the JOIN rather than a WHERE clause so an idle site still reports a
/// zero row instead of dropping out.
///
/// Challenges are logged with `blocked = 0` and a `challenge:` reason, so they
/// are counted separately here and excluded from `passed` — a visitor shown a
/// CAPTCHA was neither cleanly allowed through nor blocked outright.
async fn fetch_site_traffic(state: &AppState, window_start: &str) -> Result<Vec<SiteTraffic>> {
    let rows = sqlx::query!(
        r#"SELECT s.name                       as "name!",
                  s.server_name                as "server_name!",
                  COUNT(t.id)                  as "total!: i64",
                  COALESCE(SUM(t.blocked), 0)  as "blocked!: i64",
                  COALESCE(SUM(
                      CASE WHEN t.blocked = 0
                            AND t.block_reason LIKE 'challenge:%'
                           THEN 1 ELSE 0 END
                  ), 0)                        as "challenged!: i64"
           FROM sites s
           LEFT JOIN traffic_events t
                  ON t.site_id = s.id
                 AND t.timestamp >= ?
           GROUP BY s.id, s.name, s.server_name
           ORDER BY "total!: i64" DESC, s.name"#,
        window_start
    )
    .fetch_all(&state.db)
    .await?;

    let mut out = Vec::new();
    for r in rows {
        out.push(SiteTraffic {
            name:        r.name,
            server_name: r.server_name,
            total:       r.total,
            passed:      r.total - r.blocked - r.challenged,
            challenged:  r.challenged,
            blocked:        r.blocked,
            // Blocked and challenged are the figures worth being exact about;
            // passed takes the rounding remainder so the mix bar fills its
            // track instead of leaving a gap of a percent or two.
            passed_pct:     100 - percent_of(r.challenged, r.total)
                                - percent_of(r.blocked, r.total),
            challenged_pct: percent_of(r.challenged, r.total),
            blocked_pct:    percent_of(r.blocked, r.total),
        });
    }
    Ok(out)
}

/// Bucket the last 24 hours of traffic by hour, split into passed, challenged
/// and blocked.
///
/// Hours with no traffic are filled in with zeros rather than skipped: the
/// query only returns hours that have rows, and a chart built straight from
/// that would silently compress a quiet night into a narrow, misleading axis.
async fn fetch_hourly_traffic(state: &AppState, window_start: &str) -> Result<Vec<HourBucket>> {
    let rows = sqlx::query!(
        r#"SELECT strftime('%Y-%m-%d %H:00', timestamp) as "hour!: String",
                  COUNT(*)                              as "total!: i64",
                  COALESCE(SUM(blocked), 0)             as "blocked!: i64",
                  COALESCE(SUM(
                      CASE WHEN blocked = 0
                            AND block_reason LIKE 'challenge:%'
                           THEN 1 ELSE 0 END
                  ), 0)                                 as "challenged!: i64"
           FROM traffic_events
           WHERE timestamp >= ?
           GROUP BY strftime('%Y-%m-%d %H:00', timestamp)
           ORDER BY strftime('%Y-%m-%d %H:00', timestamp)"#,
        window_start
    )
    .fetch_all(&state.db)
    .await?;

    // Index the rows we have so the fill below is a lookup per hour.
    let mut counts: HashMap<String, (i64, i64, i64)> = HashMap::new();
    for r in rows {
        counts.insert(r.hour, (r.total, r.challenged, r.blocked));
    }

    // Walk all 24 hours in order, oldest first. SQLite writes timestamps in
    // UTC, so the keys are built in UTC too or they would never match.
    let start = window_hour_start();
    let mut out = Vec::with_capacity(24);
    for i in 0..24 {
        let slot = start + Duration::hours(i);
        let key  = slot.format("%Y-%m-%d %H:00").to_string();
        let (total, challenged, blocked) = counts.get(&key).copied().unwrap_or((0, 0, 0));
        out.push(HourBucket {
            hour:       slot.format("%H:00").to_string(),
            passed:     total - blocked - challenged,
            challenged,
            blocked,
        });
    }
    Ok(out)
}

// ─── Window helpers ──────────────────────────────────────

/// Start of the oldest hour the dashboard reports on: 23 hours back, truncated
/// to the top of that hour, which together with the current partial hour makes
/// 24 buckets.
fn window_hour_start() -> DateTime<Utc> {
    let approx = Utc::now() - Duration::hours(23);
    approx
        .with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        // with_* only fail on out-of-range values, which these are not.
        .unwrap_or(approx)
}

/// The same instant as a SQLite datetime string, for comparing against the
/// `timestamp` column.
fn window_start() -> String {
    window_hour_start().format("%Y-%m-%d %H:%M:%S").to_string()
}

// ─── percent_of ──────────────────────────────────────────

/// Whole-percent share of `part` in `total`, guarding against divide-by-zero
/// for a site that saw no traffic in the window.
fn percent_of(part: i64, total: i64) -> i64 {
    if total <= 0 {
        return 0;
    }
    (part * 100) / total
}

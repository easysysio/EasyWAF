// =========================================================
// routes/dashboard.rs — EasyWAF
// Dashboard: summary counts + recent traffic stats, plus a
// per-site breakdown of what was passed, challenged and
// blocked over the last 24 hours.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Serialize;
use tera::Context;

// ─── TrafficSummary ──────────────────────────────────────

#[derive(Debug, Serialize)]
struct TrafficSummary {
    total:   i64,
    blocked: i64,
    allowed: i64,
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
    /// Blocked share of this site's requests, whole percent. 0 when idle.
    blocked_pct: i64,
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

    // Traffic stats — last 24 hours.
    let total_requests: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM traffic_events
         WHERE timestamp >= datetime('now', '-1 day')"
    )
    .fetch_one(&state.db).await?;

    let blocked_requests: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM traffic_events
         WHERE blocked = 1 AND timestamp >= datetime('now', '-1 day')"
    )
    .fetch_one(&state.db).await?;

    let traffic = TrafficSummary {
        total:   total_requests,
        blocked: blocked_requests,
        allowed: total_requests - blocked_requests,
    };

    // Per-site breakdown for the same 24-hour window.
    let site_traffic = fetch_site_traffic(&state).await?;

    let mut ctx = Context::new();
    ctx.insert("username",       &session.username);
    ctx.insert("title",          "Dashboard");
    ctx.insert("url",            "/");
    ctx.insert("sites_number",   &sites_count);
    ctx.insert("certs_number",   &certs_count);
    ctx.insert("policy_number",  &policies_count);
    ctx.insert("traffic",        &traffic);
    ctx.insert("site_traffic",   &site_traffic);

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
async fn fetch_site_traffic(state: &AppState) -> Result<Vec<SiteTraffic>> {
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
                 AND t.timestamp >= datetime('now', '-1 day')
           GROUP BY s.id, s.name, s.server_name
           ORDER BY "total!: i64" DESC, s.name"#
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
            blocked:     r.blocked,
            blocked_pct: percent_of(r.blocked, r.total),
        });
    }
    Ok(out)
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

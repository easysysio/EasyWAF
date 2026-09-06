// =========================================================
// routes/traffic.rs — EasyWAF
// Traffic monitor: live view of every proxied request.
// Supports filtering by site, blocked/allowed, and time
// window. Uses Chart.js for a per-hour request chart and
// DataTables for the sortable event log.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::QueryBuilder;
use tera::Context;

// ─── Filter ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TrafficFilter {
    pub site:    Option<String>, // site name, empty = all
    pub blocked: Option<String>, // "1" blocked only · "0" allowed only · else all
    pub hours:   Option<i64>,    // lookback window in hours (1–720, default 24)
}

// ─── Output models ───────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TrafficEvent {
    pub id:           i64,
    pub timestamp:    String,
    pub site_name:    String,
    pub client_ip:    String,
    pub method:       String,
    pub host:         String,
    pub path:         String,
    pub status_code:  i64,
    pub response_ms:  i64,
    pub blocked:      bool,
    pub block_reason: Option<String>,
    /// The rules that produced the verdict, ready to render.
    pub matched_rules: Vec<crate::modules::RuleHit>,
    pub waf_score:    Option<i64>,
    pub country:      Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrafficStats {
    pub total:        i64,
    pub blocked:      i64,
    pub allowed:      i64,
    pub avg_response: i64,
}

#[derive(Debug, Serialize)]
pub struct HourBucket {
    pub hour:    String,
    pub total:   i64,
    pub blocked: i64,
}

#[derive(Debug, Serialize)]
pub struct SiteOption {
    pub name: String,
}

// ─── Raw DB rows (used with QueryBuilder / FromRow) ──────

#[derive(sqlx::FromRow)]
struct EventRow {
    id:           i64,
    timestamp:    String,
    site_name:    String,          // COALESCE never null
    client_ip:    Option<String>,
    method:       Option<String>,
    host:         Option<String>,
    path:         Option<String>,
    status_code:  Option<i64>,
    response_ms:  Option<i64>,
    blocked:      i64,             // NOT NULL DEFAULT 0
    block_reason: Option<String>,
    matched_rules: Option<String>,
    waf_score:    Option<i64>,
    country:      Option<String>,
}

#[derive(sqlx::FromRow)]
struct StatsRow {
    total:   i64,
    blocked: Option<i64>, // SUM can be NULL on empty result
    avg_ms:  Option<f64>, // AVG can be NULL on empty result
}

#[derive(sqlx::FromRow)]
struct HourRow {
    hour:    Option<String>, // strftime result; None if no rows
    total:   i64,
    blocked: Option<i64>,
}

// ─── get_traffic ─────────────────────────────────────────

pub async fn get_traffic(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(filter): Query<TrafficFilter>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let hours  = filter.hours.unwrap_or(24).max(1).min(720);
    let cutoff = (Utc::now() - chrono::Duration::hours(hours))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let site_sel    = filter.site.as_deref().unwrap_or("").trim().to_string();
    let blocked_sel = filter.blocked.as_deref().unwrap_or("").trim().to_string();

    let sites  = fetch_sites(&state).await?;
    let events = fetch_events(&state, &cutoff, &site_sel, &blocked_sel).await?;
    let stats  = fetch_stats(&state, &cutoff, &site_sel, &blocked_sel).await?;
    let chart  = fetch_chart(&state, &cutoff, &site_sel).await?;

    let mut ctx = Context::new();
    ctx.insert("username",    &session.username);
    ctx.insert("title",       "Traffic Monitor");
    ctx.insert("url",         "/traffic");
    ctx.insert("sites",       &sites);
    ctx.insert("events",      &events);
    ctx.insert("stats",       &stats);
    ctx.insert("chart",       &chart);
    ctx.insert("sel_site",    &site_sel);
    ctx.insert("sel_blocked", &blocked_sel);
    ctx.insert("sel_hours",   &hours);

    Ok((jar, Html(state.tera.render("traffic.html", &ctx)?)).into_response())
}

// ─── fetch_sites ─────────────────────────────────────────

async fn fetch_sites(state: &AppState) -> Result<Vec<SiteOption>> {
    // sites.name is NOT NULL — safe direct mapping.
    let rows = sqlx::query!("SELECT name FROM sites ORDER BY name")
        .fetch_all(&state.db)
        .await?;
    Ok(rows.into_iter().map(|r| SiteOption { name: r.name }).collect())
}

// ─── fetch_events ────────────────────────────────────────

/// Load up to 1000 most-recent events matching the filter.
async fn fetch_events(
    state:   &AppState,
    cutoff:  &str,
    site:    &str,
    blocked: &str,
) -> Result<Vec<TrafficEvent>> {
    let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new(
        "SELECT te.id,
                te.timestamp,
                COALESCE(s.name, '[deleted]') AS site_name,
                te.client_ip, te.method, te.host, te.path,
                te.status_code, te.response_ms,
                te.blocked, te.block_reason, te.country,
                te.matched_rules, te.waf_score
         FROM traffic_events te
         LEFT JOIN sites s ON s.id = te.site_id
         WHERE te.timestamp >= ",
    );
    qb.push_bind(cutoff);

    apply_site_filter(&mut qb, site);
    apply_blocked_filter(&mut qb, blocked);

    qb.push(" ORDER BY te.timestamp DESC LIMIT 1000");

    let rows: Vec<EventRow> = qb.build_query_as().fetch_all(&state.db).await?;

    Ok(rows.into_iter().map(|r| TrafficEvent {
        id:           r.id,
        timestamp:    r.timestamp,
        site_name:    r.site_name,
        client_ip:    r.client_ip.unwrap_or_default(),
        method:       r.method.unwrap_or_default(),
        host:         r.host.unwrap_or_default(),
        path:         r.path.unwrap_or_default(),
        status_code:  r.status_code.unwrap_or(0),
        response_ms:  r.response_ms.unwrap_or(0),
        blocked:      r.blocked != 0,
        block_reason: r.block_reason,
        // Stored as JSON; a row written before this existed, or by a version
        // that could not parse, simply shows nothing rather than failing.
        matched_rules: r.matched_rules
            .as_deref()
            .and_then(|j| serde_json::from_str(j).ok())
            .unwrap_or_default(),
        waf_score:    r.waf_score,
        country:      r.country,
    }).collect())
}

// ─── fetch_stats ─────────────────────────────────────────

/// Aggregate counts and average latency for the filter window.
async fn fetch_stats(
    state:   &AppState,
    cutoff:  &str,
    site:    &str,
    blocked: &str,
) -> Result<TrafficStats> {
    let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new(
        "SELECT COUNT(*) AS total,
                SUM(CASE WHEN te.blocked = 1 THEN 1 ELSE 0 END) AS blocked,
                AVG(te.response_ms) AS avg_ms
         FROM traffic_events te
         LEFT JOIN sites s ON s.id = te.site_id
         WHERE te.timestamp >= ",
    );
    qb.push_bind(cutoff);

    apply_site_filter(&mut qb, site);
    apply_blocked_filter(&mut qb, blocked);

    let row: StatsRow = qb.build_query_as().fetch_one(&state.db).await?;
    let blocked_n = row.blocked.unwrap_or(0);

    Ok(TrafficStats {
        total:        row.total,
        blocked:      blocked_n,
        allowed:      row.total - blocked_n,
        avg_response: row.avg_ms.unwrap_or(0.0).round() as i64,
    })
}

// ─── fetch_chart ─────────────────────────────────────────

/// Per-hour request/block counts for the Chart.js bar chart.
async fn fetch_chart(
    state:  &AppState,
    cutoff: &str,
    site:   &str,
) -> Result<Vec<HourBucket>> {
    let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new(
        "SELECT strftime('%Y-%m-%d %H:00', te.timestamp) AS hour,
                COUNT(*) AS total,
                SUM(CASE WHEN te.blocked = 1 THEN 1 ELSE 0 END) AS blocked
         FROM traffic_events te
         LEFT JOIN sites s ON s.id = te.site_id
         WHERE te.timestamp >= ",
    );
    qb.push_bind(cutoff);

    apply_site_filter(&mut qb, site);

    qb.push(" GROUP BY hour ORDER BY hour ASC");

    let rows: Vec<HourRow> = qb.build_query_as().fetch_all(&state.db).await?;

    Ok(rows.into_iter().filter_map(|r| {
        r.hour.map(|h| HourBucket {
            hour:    h,
            total:   r.total,
            blocked: r.blocked.unwrap_or(0),
        })
    }).collect())
}

// ─── Filter helpers ──────────────────────────────────────

fn apply_site_filter(qb: &mut QueryBuilder<sqlx::Sqlite>, site: &str) {
    if !site.is_empty() {
        qb.push(" AND s.name = ");
        qb.push_bind(site.to_string());
    }
}

fn apply_blocked_filter(qb: &mut QueryBuilder<sqlx::Sqlite>, blocked: &str) {
    match blocked {
        "1" => { qb.push(" AND te.blocked = 1"); }
        "0" => { qb.push(" AND te.blocked = 0"); }
        _   => {}
    }
}

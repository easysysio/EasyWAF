// =========================================================
// routes/traffic.rs — EasyWAF
// Traffic monitor: live view of every proxied request.
// Supports filtering by site, blocked/allowed, and time
// window. Uses Chart.js for a per-hour request chart and
// DataTables for the sortable event log.
// =========================================================

use crate::{auth::{Viewer}, error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
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
    /// One hour, as "YYYY-MM-DD HH:00" in UTC — the form the charts group by.
    /// Set by clicking a bar; narrows everything on the page to that hour.
    pub hour:    Option<String>,
    // Set when an exclusion was just added from a row on this page.
    pub result:  Option<String>,
    pub msg:     Option<String>,
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
    pub matched_rules: Vec<EventRule>,
    pub waf_score:    Option<i64>,
    pub country:      Option<String>,
    /// What the WAF would have done on a request it allowed: "observed",
    /// "would_challenge" or "would_block". None on clean traffic and on rows
    /// written before 0.6.11.
    pub detection:    Option<String>,
}

/// One rule that produced a verdict, as the Traffic Monitor shows it.
///
/// A `RuleHit` plus whether this site already excludes the rule for this
/// client. Without that, the page offers "exclude this" on a rule that is
/// already excluded, and the row gives no hint why a rule that is listed as
/// having matched is no longer acting.
#[derive(Debug, Serialize)]
pub struct EventRule {
    pub id:       Option<i64>,
    pub name:     String,
    pub score:    i64,
    pub excluded: bool,
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
    /// Allowed, but the WAF matched rules on them. Charted apart from the rest
    /// of "allowed": without this, filtering to Detected paints those hours
    /// green as ordinary traffic, which is the opposite of what the filter was
    /// selected to show.
    pub detected: i64,
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
    site_id:      Option<i64>,
    blocked:      i64,             // NOT NULL DEFAULT 0
    block_reason: Option<String>,
    detection:    Option<String>,
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
    hour:     Option<String>, // strftime result; None if no rows
    total:    i64,
    blocked:  Option<i64>,
    detected: Option<i64>,
}

// ─── get_traffic ─────────────────────────────────────────

pub async fn get_traffic(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(filter): Query<TrafficFilter>,
) -> Result<Response> {

    let hours  = filter.hours.unwrap_or(24).max(1).min(720);
    let cutoff = (Utc::now() - chrono::Duration::hours(hours))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let site_sel    = filter.site.as_deref().unwrap_or("").trim().to_string();
    let blocked_sel = filter.blocked.as_deref().unwrap_or("").trim().to_string();

    let sites  = fetch_sites(&state).await?;
    // "YYYY-MM-DD HH:00" as the charts group by; anything else selects nothing
    // rather than being interpreted loosely.
    let hour_sel = filter.hour.as_deref().unwrap_or("").trim().to_string();

    let exclusions = fetch_exclusions(&state).await?;
    let events = fetch_events(&state, &exclusions, &cutoff, &site_sel, &blocked_sel, &hour_sel).await?;
    let stats  = fetch_stats(&state, &cutoff, &site_sel, &blocked_sel, &hour_sel).await?;
    let chart  = fetch_chart(&state, &cutoff, &site_sel, &blocked_sel).await?;

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",       "Traffic Monitor");
    ctx.insert("url",         "/traffic");
    ctx.insert("sites",       &sites);
    ctx.insert("events",      &events);
    ctx.insert("stats",       &stats);
    ctx.insert("chart",       &chart);
    ctx.insert("sel_site",    &site_sel);
    ctx.insert("sel_blocked", &blocked_sel);
    ctx.insert("sel_hours",   &hours);
    ctx.insert("sel_hour",    &hour_sel);
    ctx.insert("result",      &filter.result.clone().unwrap_or_default());
    ctx.insert("msg",         &filter.msg.clone().unwrap_or_default());

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
/// One site's exclusions, in the form the coverage check needs.
struct SiteExclusion {
    external_id: Option<i64>,
    path_prefix: String,
    client:      Option<crate::forwarded::Cidr>,
}

/// Every exclusion, keyed by site, so the page can mark rules that are
/// already excluded rather than offering to exclude them twice.
///
/// Loaded once for the page rather than per row: a thousand rows would
/// otherwise be a thousand queries to answer one question about a handful of
/// exclusions.
async fn fetch_exclusions(
    state: &AppState,
) -> Result<std::collections::HashMap<i64, Vec<SiteExclusion>>> {
    let rows = sqlx::query!(
        r#"SELECT site_id as "site_id!", external_id,
                  path_prefix as "path_prefix!", client_cidr
           FROM   site_rule_exclusions"#
    )
    .fetch_all(&state.db)
    .await?;

    let mut out: std::collections::HashMap<i64, Vec<SiteExclusion>> = Default::default();
    for r in rows {
        out.entry(r.site_id).or_default().push(SiteExclusion {
            external_id: r.external_id,
            path_prefix: r.path_prefix,
            client: r.client_cidr.as_deref()
                .filter(|c| !c.is_empty())
                .and_then(crate::forwarded::Cidr::parse),
        });
    }
    Ok(out)
}

/// Does this site already exclude `rule` for this request?
///
/// Deliberately the same three conditions the engine applies in
/// `waf::Exclusion::silences` — rule, path, client — so the page cannot claim
/// a rule is excluded when the engine would still run it.
fn already_excluded(
    excls: Option<&Vec<SiteExclusion>>,
    rule_id: Option<i64>,
    path: &str,
    client_ip: &str,
) -> bool {
    let (Some(list), Some(rid)) = (excls, rule_id) else { return false };
    let parsed: Option<std::net::IpAddr> = client_ip.parse().ok();
    list.iter().any(|e| {
        e.external_id == Some(rid)
            && (e.path_prefix.is_empty() || path.starts_with(&e.path_prefix))
            && match (e.client, parsed) {
                (None, _)            => true,
                (Some(c), Some(ip))  => c.contains(ip),
                (Some(_), None)      => false,
            }
    })
}

async fn fetch_events(
    state:   &AppState,
    exclusions: &std::collections::HashMap<i64, Vec<SiteExclusion>>,
    cutoff:  &str,
    site:    &str,
    blocked: &str,
    hour:    &str,
) -> Result<Vec<TrafficEvent>> {
    let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new(
        "SELECT te.id,
                te.timestamp,
                COALESCE(s.name, '[deleted]') AS site_name,
                te.client_ip, te.method, te.host, te.path,
                te.status_code, te.response_ms,
                te.site_id, te.blocked, te.block_reason, te.country,
                te.matched_rules, te.waf_score, te.detection
         FROM traffic_events te
         LEFT JOIN sites s ON s.id = te.site_id
         WHERE te.timestamp >= ",
    );
    qb.push_bind(cutoff);

    apply_site_filter(&mut qb, site);
    apply_blocked_filter(&mut qb, blocked);
    apply_hour_filter(&mut qb, hour);

    qb.push(" ORDER BY te.timestamp DESC LIMIT 1000");

    let rows: Vec<EventRow> = qb.build_query_as().fetch_all(&state.db).await?;

    Ok(rows.into_iter().map(|r| {
      // Taken before the struct consumes them; both are needed to decide
      // whether an exclusion already covers each rule below.
      let path = r.path.clone().unwrap_or_default();
      let ip   = r.client_ip.clone().unwrap_or_default();
      TrafficEvent {
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
        detection:    r.detection,
        // Stored as JSON; a row written before this existed, or by a version
        // that could not parse, simply shows nothing rather than failing.
        // Each hit is then marked with whether the site already excludes it
        // for this client, so the page does not offer to exclude it again.
        matched_rules: {
            let hits: Vec<crate::modules::RuleHit> = r.matched_rules
                .as_deref()
                .and_then(|j| serde_json::from_str(j).ok())
                .unwrap_or_default();
            let site_excls = r.site_id.and_then(|id| exclusions.get(&id));
            hits.into_iter().map(|h| EventRule {
                excluded: already_excluded(site_excls, h.id, &path, &ip),
                id: h.id, name: h.name, score: h.score,
            }).collect()
        },
        waf_score:    r.waf_score,
        country:      r.country,
      }
    }).collect())
}

// ─── fetch_stats ─────────────────────────────────────────

/// Aggregate counts and average latency for the filter window.
async fn fetch_stats(
    state:   &AppState,
    cutoff:  &str,
    site:    &str,
    blocked: &str,
    hour:    &str,
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
    apply_hour_filter(&mut qb, hour);

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
///
/// Note what this does *not* take: the hour filter. Narrowing the chart to the
/// hour someone just clicked would leave a single bar and no way back — the
/// chart is how the hour is chosen, so it has to keep showing the others. The
/// selected hour is highlighted in the page instead.
async fn fetch_chart(
    state:   &AppState,
    cutoff:  &str,
    site:    &str,
    blocked: &str,
) -> Result<Vec<HourBucket>> {
    let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new(
        "SELECT strftime('%Y-%m-%d %H:00', te.timestamp) AS hour,
                COUNT(*) AS total,
                SUM(CASE WHEN te.blocked = 1 THEN 1 ELSE 0 END) AS blocked,
                SUM(CASE WHEN te.blocked = 0 AND te.detection IS NOT NULL
                         THEN 1 ELSE 0 END) AS detected
         FROM traffic_events te
         LEFT JOIN sites s ON s.id = te.site_id
         WHERE te.timestamp >= ",
    );
    qb.push_bind(cutoff);

    apply_site_filter(&mut qb, site);
    // The chart took the site and the time window but not the verdict, so
    // choosing Blocked Only changed the table underneath a graph that carried
    // on showing everything — two answers to one question on one page.
    apply_blocked_filter(&mut qb, blocked);

    qb.push(" GROUP BY hour ORDER BY hour ASC");

    let rows: Vec<HourRow> = qb.build_query_as().fetch_all(&state.db).await?;

    Ok(rows.into_iter().filter_map(|r| {
        r.hour.map(|h| HourBucket {
            hour:     h,
            total:    r.total,
            blocked:  r.blocked.unwrap_or(0),
            detected: r.detected.unwrap_or(0),
        })
    }).collect())
}

// ─── Filter helpers ──────────────────────────────────────

/// Narrow to a single hour, in the form the charts group by.
///
/// Bound rather than interpolated, and compared against the same
/// `strftime` expression the charts use, so a bar and the rows it stands for
/// cannot disagree about which rows they are.
fn apply_hour_filter(qb: &mut QueryBuilder<sqlx::Sqlite>, hour: &str) {
    if !hour.is_empty() {
        qb.push(" AND strftime('%Y-%m-%d %H:00', te.timestamp) = ");
        qb.push_bind(hour.to_string());
    }
}

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
        // Allowed, but the WAF had something to say. The reason this filter
        // exists: in DetectionOnly every row is "allowed", so filtering by
        // blocked/allowed cannot find the attacks the mode was turned on to
        // find.
        "detected"    => { qb.push(" AND te.detection IS NOT NULL"); }
        // Allowed only because the policy is not enforcing.
        "would_block" => { qb.push(" AND te.detection IN ('would_block', 'would_challenge')"); }
        // The two remaining slices of the dashboard's verdict chart. Clicking
        // one should land on the rows it counted, which needs the same
        // definition the chart used: passed is what is left after the other
        // three, and challenged is an unblocked row whose reason says so.
        "passed" => {
            qb.push(" AND te.blocked = 0 AND te.detection IS NULL                       AND (te.block_reason IS NULL OR te.block_reason NOT LIKE 'challenge:%')");
        }
        "challenged" => {
            qb.push(" AND te.blocked = 0 AND te.block_reason LIKE 'challenge:%'");
        }
        _   => {}
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn excl(ext: i64, prefix: &str, cidr: Option<&str>) -> SiteExclusion {
        SiteExclusion {
            external_id: Some(ext),
            path_prefix: prefix.into(),
            client: cidr.and_then(crate::forwarded::Cidr::parse),
        }
    }

    /// The page's check must apply the same three conditions the engine does in
    /// `waf::Exclusion::silences` — rule, path, client. If it is looser, the
    /// Traffic Monitor marks a rule as excluded that the engine still runs; if
    /// it is tighter, it offers to add an exclusion that already exists.
    #[test]
    fn the_marker_agrees_with_the_engine_on_all_three_conditions() {
        let list = vec![excl(913015, "/admin/", Some("203.0.113.0/24"))];
        let l = Some(&list);

        assert!( already_excluded(l, Some(913015), "/admin/x", "203.0.113.9"));
        assert!(!already_excluded(l, Some(913016), "/admin/x", "203.0.113.9"), "wrong rule");
        assert!(!already_excluded(l, Some(913015), "/other",   "203.0.113.9"), "wrong path");
        assert!(!already_excluded(l, Some(913015), "/admin/x", "198.51.100.7"), "wrong client");
    }

    #[test]
    fn an_exclusion_naming_no_client_covers_every_client() {
        let list = vec![excl(913015, "", None)];
        for ip in ["203.0.113.9", "192.168.1.1", "::1"] {
            assert!(already_excluded(Some(&list), Some(913015), "/x", ip), "{ip}");
        }
    }

    #[test]
    fn a_client_scoped_exclusion_never_matches_an_unreadable_address() {
        // A stored row could carry something that is not an address — an empty
        // client_ip on an old event, say. Marking a rule excluded on the
        // strength of an address nobody can read would be a claim the engine
        // will not honour.
        let list = vec![excl(913015, "", Some("203.0.113.0/24"))];
        assert!(!already_excluded(Some(&list), Some(913015), "/x", ""));
        assert!(!already_excluded(Some(&list), Some(913015), "/x", "not-an-ip"));
    }

    #[test]
    fn a_custom_rule_with_no_catalogue_number_is_never_marked() {
        // The Traffic Monitor stores a hit's catalogue number, and a custom
        // rule has none. Without a number there is nothing to compare, so the
        // honest answer is "not known to be excluded" rather than a guess.
        let list = vec![excl(913015, "", None)];
        assert!(!already_excluded(Some(&list), None, "/x", "203.0.113.9"));
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    /// Build the WHERE clause a filter produces, so the four verdict values the
    /// dashboard's chart can be clicked on are checked against the definitions
    /// the chart counted with. A slice that lands on the wrong rows is worse
    /// than one that does not link anywhere.
    fn clause(blocked: &str, hour: &str) -> String {
        let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new("SELECT 1 WHERE 1=1");
        apply_blocked_filter(&mut qb, blocked);
        apply_hour_filter(&mut qb, hour);
        qb.into_sql()
    }

    #[test]
    fn every_verdict_slice_maps_to_a_filter() {
        // The dashboard chart's slices, in the order its onClick indexes them.
        for (f, expect) in [
            ("passed",      "detection IS NULL"),
            ("detected",    "detection IS NOT NULL"),
            ("challenged",  "challenge:%"),
            ("1",           "blocked = 1"),
        ] {
            let c = clause(f, "");
            assert!(c.contains(expect), "{f} produced {c}, expected it to mention {expect}");
        }
    }

    #[test]
    fn passed_excludes_the_other_three_slices() {
        // Otherwise the four slices overlap and their counts do not add to the
        // total the chart was drawn from.
        let c = clause("passed", "");
        assert!(c.contains("blocked = 0"),          "passed includes blocked rows");
        assert!(c.contains("detection IS NULL"),    "passed includes scored rows");
        assert!(c.contains("NOT LIKE 'challenge:%'"), "passed includes challenged rows");
    }

    #[test]
    fn an_hour_narrows_by_the_same_expression_the_chart_groups_by() {
        // The chart groups with strftime('%Y-%m-%d %H:00', te.timestamp). If
        // the filter used anything else, a bar and the rows it stands for could
        // disagree about which rows they are.
        let c = clause("", "2026-09-08 14:00");
        assert!(c.contains("strftime('%Y-%m-%d %H:00', te.timestamp)"),
                "the hour filter does not match the chart's grouping: {c}");
    }

    #[test]
    fn no_hour_adds_no_condition() {
        assert_eq!(clause("", ""), "SELECT 1 WHERE 1=1");
    }
}

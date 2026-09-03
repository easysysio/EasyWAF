// =========================================================
// modules/geoip.rs — EasyWAF
// Country filtering module.
//
// For every proxied request this module:
//   1. Looks up the WAF policy assigned to the site.
//   2. Reads the policy's country mode and list.
//   3. Resolves the client IP to a country.
//   4. Drops the request when the country is denied.
//
// Runs before the WAF rules: if a whole country is denied
// there is no reason to score its payloads first.
//
// The rule_engine mode applies here too — a policy set to
// DetectionOnly alerts instead of dropping, so country rules
// can be trialled against real traffic exactly like the
// pattern rules.
// =========================================================

use crate::geo;
use crate::modules::{InspectionModule, ModuleDecision, RequestContext};
use async_trait::async_trait;
use axum::http::StatusCode;
use sqlx::SqlitePool;

// ─── GeoIpModule ─────────────────────────────────────────

/// Pipeline module that applies a policy's country rules.
pub struct GeoIpModule {
    db: SqlitePool,
}

impl GeoIpModule {
    /// Create a GeoIpModule backed by the given connection pool.
    pub fn new(db: SqlitePool) -> Self {
        Self { db }
    }
}

// ─── Internal DB row types ───────────────────────────────

/// The country settings of the policy assigned to a site.
struct GeoPolicy {
    rule_engine: String,
    mode:        String,
    countries:   String,
}

// ─── InspectionModule impl ───────────────────────────────

#[async_trait]
impl InspectionModule for GeoIpModule {
    fn name(&self) -> &'static str { "geoip" }

    async fn inspect(&self, ctx: &RequestContext) -> ModuleDecision {
        // Step 1 — the site's policy, if it has one.
        let policy = match get_site_geo_policy(&self.db, ctx.site_id).await {
            Some(p) => p,
            None    => return ModuleDecision::Pass,
        };

        // Step 2 — country filtering off, or the engine disabled entirely.
        if policy.mode == "off" || policy.rule_engine == "Off" {
            return ModuleDecision::Pass;
        }

        let list = parse_countries(&policy.countries);
        // An empty list means nothing was chosen. In 'allow' mode that would
        // otherwise deny every visitor, so both modes pass instead: switching
        // the mode on before picking countries must not take a site offline.
        if list.is_empty() {
            return ModuleDecision::Pass;
        }

        // Step 3 — resolve the client. An address with no country (private
        // range, or one the database does not cover) is never matched against
        // the list: blocking on a failed lookup would deny traffic on missing
        // data rather than on a rule.
        let country = match geo::country_of(ctx.client_ip) {
            Some(c) => c,
            None    => return ModuleDecision::Pass,
        };

        // Step 4 — apply the mode.
        if !is_denied(&policy.mode, &list, &country) {
            return ModuleDecision::Pass;
        }

        let reason = match policy.mode.as_str() {
            "allow" => format!("GeoIP: {} is not in the allowed countries", country),
            _       => format!("GeoIP: requests from {} are blocked", country),
        };

        // DetectionOnly records what would have happened without enforcing it.
        if policy.rule_engine == "DetectionOnly" {
            return ModuleDecision::Alert { reason };
        }
        ModuleDecision::Drop { reason, status: StatusCode::FORBIDDEN }
    }
}

// ─── is_denied ───────────────────────────────────────────

/// Whether a resolved country is denied by a mode and list.
///
/// Split out from `inspect` so the decision can be tested directly: the client
/// address of a local request is always loopback, which by design resolves to
/// no country, so this branch cannot be reached from an end-to-end test on one
/// machine.
fn is_denied(mode: &str, list: &[String], country: &str) -> bool {
    let listed = list.iter().any(|c| c == country);
    match mode {
        "block" => listed,
        "allow" => !listed,
        _       => false,
    }
}

// ─── parse_countries ─────────────────────────────────────

/// Split the stored list into upper-case ISO codes.
///
/// The field is free text in the GUI, so it is normalised here rather than
/// trusted: entries are trimmed, upper-cased, and anything that is not a
/// two-letter code is dropped instead of silently never matching.
fn parse_countries(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|c| c.trim().to_uppercase())
        .filter(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic()))
        .collect()
}

// ─── DB helpers ──────────────────────────────────────────

/// Fetch the country settings of the policy assigned to a site.
/// Returns None when the site has no policy.
async fn get_site_geo_policy(db: &SqlitePool, site_id: i64) -> Option<GeoPolicy> {
    sqlx::query!(
        r#"SELECT p.rule_engine,
                  p.geoip_mode      as "geoip_mode!",
                  p.geoip_countries as "geoip_countries!"
           FROM   policies p
           JOIN   sites    s ON s.waf_policy_id = p.id
           WHERE  s.id = ?"#,
        site_id
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map(|r| GeoPolicy {
        rule_engine: r.rule_engine,
        mode:        r.geoip_mode,
        countries:   r.geoip_countries,
    })
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The table that matters: every mode against a listed and an unlisted
    /// country. An allow list denying everything it does not name is the case
    /// most likely to lock someone out, so it is stated explicitly.
    #[test]
    fn modes_decide_correctly() {
        let list = vec!["CN".to_string(), "RU".to_string()];

        assert!(is_denied("block", &list, "CN"),  "block: listed country denied");
        assert!(!is_denied("block", &list, "US"), "block: unlisted country allowed");

        assert!(!is_denied("allow", &list, "CN"), "allow: listed country allowed");
        assert!(is_denied("allow", &list, "US"),  "allow: unlisted country denied");

        assert!(!is_denied("off", &list, "CN"),   "off: nothing denied");
        assert!(!is_denied("off", &list, "US"),   "off: nothing denied");
    }

    /// An unrecognised mode must fail open rather than deny everything.
    #[test]
    fn unknown_mode_denies_nothing() {
        assert!(!is_denied("banana", &["CN".to_string()], "CN"));
    }

    #[test]
    fn country_list_is_normalised() {
        assert_eq!(parse_countries("cn, ru ,US"), vec!["CN", "RU", "US"]);
    }

    #[test]
    fn malformed_entries_are_dropped() {
        // Trailing commas and stray words must not become codes that can never
        // match, which would look like a working rule that silently does nothing.
        assert_eq!(parse_countries("US,,   ,GBR,x,IL"), vec!["US", "IL"]);
        assert!(parse_countries("").is_empty());
    }
}

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
use crate::modules::{Findings, InspectionModule, ModuleDecision, RequestContext};
use async_trait::async_trait;
use axum::http::StatusCode;
use sqlx::SqlitePool;

// ─── GeoIpModule ─────────────────────────────────────────

/// Pipeline module that applies a policy's country rules.
pub struct GeoIpModule {
    db: SqlitePool,
    /// Each site's country settings, as of one configuration generation — the
    /// same cache and the same invalidation as the WAF module's, so the two
    /// cannot disagree about which version of a policy is in force.
    sites: super::generation::PerSite<Option<GeoPolicy>>,
}

impl GeoIpModule {
    /// Create a GeoIpModule backed by the given connection pool.
    pub fn new(db: SqlitePool) -> Self {
        Self { db, sites: super::generation::PerSite::new() }
    }
}

// ─── Internal DB row types ───────────────────────────────

/// The country settings of the policy assigned to a site, and the rule that
/// applies whatever the policy says.
///
/// Both are cached together under one generation: they are read for the same
/// request and invalidated by the same writes, and keeping them apart would
/// let a request be judged by a policy from one moment and an every-policy
/// rule from another.
struct GeoPolicy {
    rule_engine: String,
    mode:        String,
    countries:   String,
    /// The every-policy rule: applied as well as the policy's own, never
    /// instead of it.
    all_mode:      String,
    all_countries: String,
}

// ─── InspectionModule impl ───────────────────────────────

#[async_trait]
impl InspectionModule for GeoIpModule {
    fn name(&self) -> &'static str { "geoip" }

    async fn inspect(&self, ctx: &RequestContext) -> ModuleDecision {
        // Step 1 — the site's policy, if it has one, from the cache. Generation
        // read before the row, for the reason given on WafModule::snapshot.
        let generation = super::generation::current(&self.db).await;
        let cached = match self.sites.get(generation, ctx.site_id) {
            Some(c) => c,
            None    => {
                let loaded = get_site_geo_policy(&self.db, ctx.site_id).await;
                self.sites.put(generation, ctx.site_id, loaded)
            }
        };
        let policy = match &*cached {
            Some(p) => p,
            None    => return ModuleDecision::Pass,
        };

        // Step 2 — the engine disabled entirely, or neither scope asking for
        // anything. A policy with no country rule of its own is still subject
        // to the every-policy one: that is the whole of what it is for.
        if policy.rule_engine == "Off" {
            return ModuleDecision::Pass;
        }

        let own = parse_countries(&policy.countries);
        let all = parse_countries(&policy.all_countries);
        // An empty list means nothing was chosen. In 'allow' mode that would
        // otherwise deny every visitor, so both modes pass instead: switching
        // the mode on before picking countries must not take a site offline.
        if !in_force(&policy.mode, &own) && !in_force(&policy.all_mode, &all) {
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

        // Step 4 — apply both.
        let refused = refused_by(
            &policy.mode, &own, &policy.all_mode, &all, &country);
        let Some(scope) = refused else {
            return ModuleDecision::Pass;
        };

        // Named, because "why am I refused" is answered differently depending
        // on which of the two did it, and they are edited in different places.
        let (mode, whose) = match scope {
            RuleScope::Policy     => (policy.mode.as_str(), ""),
            RuleScope::Everywhere => (policy.all_mode.as_str(), " for every policy"),
        };
        let reason = match mode {
            "allow" => format!("GeoIP: {country} is not in the allowed countries{whose}"),
            _       => format!("GeoIP: requests from {country} are blocked{whose}"),
        };

        // DetectionOnly records what would have happened without enforcing it.
        if policy.rule_engine == "DetectionOnly" {
            return ModuleDecision::Alert {
                reason,
                findings: Findings {
                    detection: Some(crate::modules::Detection::WouldBlock),
                    ..Findings::default()
                },
            };
        }
        ModuleDecision::Drop { reason, status: StatusCode::FORBIDDEN, findings: Findings::default() }
    }
}

// ─── refused_by ──────────────────────────────────────────

/// Which rule refused this country, if either did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleScope {
    Policy,
    Everywhere,
}

/// Whether a country rule is doing anything at all.
///
/// Off, or on with nothing listed. The second is the case worth being careful
/// about: in `allow` mode an empty list would otherwise mean "refuse every
/// country", so switching the mode on before typing the list would take every
/// site offline between two clicks.
fn in_force(mode: &str, list: &[String]) -> bool {
    mode != "off" && !list.is_empty()
}

/// Apply a policy's country rule and the every-policy one together.
///
/// A request refused by either is refused: the rules add, they do not cancel.
/// The alternative — letting a policy's `allow` list re-admit a country the
/// appliance refuses — would mean the every-policy rule is not a rule but a
/// default, and the one thing it is for is being the rule nobody has to
/// remember to repeat.
///
/// The policy's own rule is reported first when both refuse, because that is
/// the one whose page the reader is most likely already on.
fn refused_by(
    mode: &str,
    list: &[String],
    all_mode: &str,
    all_list: &[String],
    country: &str,
) -> Option<RuleScope> {
    if in_force(mode, list) && is_denied(mode, list, country) {
        return Some(RuleScope::Policy);
    }
    if in_force(all_mode, all_list) && is_denied(all_mode, all_list, country) {
        return Some(RuleScope::Everywhere);
    }
    None
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
    // One query, so the policy's rule and the every-policy rule are read at
    // the same moment as well as cached together. A missing row — a database
    // that predates the table — reads as off, which changes nothing.
    sqlx::query!(
        r#"SELECT p.rule_engine,
                  p.geoip_mode      as "geoip_mode!",
                  p.geoip_countries as "geoip_countries!",
                  COALESCE((SELECT mode      FROM geoip_everywhere WHERE id = 1), 'off') as "all_mode!",
                  COALESCE((SELECT countries FROM geoip_everywhere WHERE id = 1), '')    as "all_countries!"
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
        rule_engine:   r.rule_engine,
        mode:          r.geoip_mode,
        countries:     r.geoip_countries,
        all_mode:      r.all_mode,
        all_countries: r.all_countries,
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

    /// The two scopes together, which is where the design decision is: they
    /// add, and neither can let in what the other refuses.
    #[test]
    fn a_policy_rule_and_an_every_policy_rule_both_apply() {
        let cn = vec!["CN".to_string()];
        let de = vec!["DE".to_string()];
        let none: Vec<String> = Vec::new();

        // Nothing set anywhere.
        assert_eq!(refused_by("off", &none, "off", &none, "CN"), None);

        // Only the every-policy rule, on a policy that has none of its own —
        // the case the scope exists for.
        assert_eq!(refused_by("off", &none, "block", &cn, "CN"), Some(RuleScope::Everywhere));
        assert_eq!(refused_by("off", &none, "block", &cn, "US"), None);

        // Only the policy's own.
        assert_eq!(refused_by("block", &cn, "off", &none, "CN"), Some(RuleScope::Policy));

        // Both refuse: the policy's own is the one reported.
        assert_eq!(refused_by("block", &cn, "block", &cn, "CN"), Some(RuleScope::Policy));

        // A policy that allows only Germany does not re-admit a country the
        // appliance refuses, and the appliance's allow-only list does not
        // re-admit what the policy refuses.
        assert_eq!(refused_by("allow", &de, "block", &cn, "DE"), None);
        assert_eq!(refused_by("allow", &de, "block", &cn, "CN"), Some(RuleScope::Policy));
        assert_eq!(refused_by("block", &cn, "allow", &de, "US"), Some(RuleScope::Everywhere));
        assert_eq!(refused_by("off", &none, "allow", &de, "DE"), None);
    }

    /// An empty list never means "refuse everyone", in either scope.
    #[test]
    fn a_mode_with_no_countries_does_nothing() {
        let none: Vec<String> = Vec::new();
        assert!(!in_force("allow", &none));
        assert!(!in_force("block", &none));
        assert!(!in_force("off", &["CN".to_string()]));
        assert_eq!(refused_by("allow", &none, "allow", &none, "US"), None,
                   "an allow mode with nothing listed refused a visitor");
    }

    /// The query, not just the decision: the every-policy rule is read with
    /// the site's policy, and a database written before the table existed
    /// reads as off rather than failing.
    #[tokio::test]
    async fn the_every_policy_rule_is_read_with_the_site_policy() {
        let path = std::env::temp_dir()
            .join(format!("easywaf-geoip-scope-{}.db", std::process::id()));
        for sfx in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", path.display()));
        }
        let db = crate::db::init(&format!("sqlite://{}", path.display())).await;

        sqlx::raw_sql(
            "INSERT INTO policies (name, geoip_mode, geoip_countries)
             VALUES ('apps', 'off', '');
             INSERT INTO sites (name, server_name, target, waf_policy_id)
             VALUES ('a', 'a.example', 'http://x', (SELECT id FROM policies WHERE name = 'apps'));
             UPDATE geoip_everywhere SET mode = 'block', countries = 'KP' WHERE id = 1;",
        )
        .execute(&db)
        .await
        .expect("seed");

        let site: i64 = sqlx::query_scalar("SELECT id FROM sites WHERE name = 'a'")
            .fetch_one(&db)
            .await
            .unwrap();
        let loaded = get_site_geo_policy(&db, site).await.expect("the site has a policy");
        assert_eq!(loaded.mode, "off", "the policy has no country rule of its own");
        assert_eq!(loaded.all_mode, "block");
        assert_eq!(loaded.all_countries, "KP");

        // And that is enough to refuse: the policy said nothing, which is the
        // case the scope exists for.
        assert_eq!(
            refused_by(&loaded.mode, &parse_countries(&loaded.countries),
                       &loaded.all_mode, &parse_countries(&loaded.all_countries), "KP"),
            Some(RuleScope::Everywhere));

        db.close().await;
        for sfx in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", path.display()));
        }
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

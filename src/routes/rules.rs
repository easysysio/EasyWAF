// =========================================================
// routes/rules.rs — EasyWAF
// WAF rule management: list, create, toggle, delete, seed,
// and import from TOML rule files in the rules/ directory.
//
// Rule files use TOML format. Each file contains an array of
// [[rules]] tables with fields: id, name, description, zone,
// pattern, score, action.  The id field becomes external_id
// in the DB — used to prevent duplicate imports.
// =========================================================

use crate::{
    auth::get_session,
    error::{AppError, Result},
    AppState,
};
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tera::Context;

// ─── Models ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Rule {
    pub id:          i64,
    pub name:        String,
    pub description: String,
    pub zone:        String,
    pub pattern:     String,
    pub score:       i64,
    pub action:      String,
    pub enabled:     bool,
}

#[derive(Debug, Serialize)]
pub struct PolicyHeader {
    pub name:            String,
    pub rule_engine:     String,
    pub score_threshold: i64,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RuleForm {
    pub name:        String,
    pub description: Option<String>,
    pub zone:        String,
    pub pattern:     String,
    pub score:       Option<String>,
    pub action:      String,
    /// Only sent by the edit form; absent on create (new rules default enabled).
    pub enabled:     Option<String>,
}

/// Form submitted by the bulk-action bar.
///
/// `ids` is a comma-separated string of rule IDs built by JavaScript
/// before form submission (e.g. "12,45,67").  We use a single field
/// rather than repeated `ids=X` fields because serde_urlencoded (which
/// axum's Form extractor uses) does not map repeated keys into Vec<T>.
///
/// `bulk_action` is one of: "enable", "disable", "delete".
#[derive(Deserialize)]
pub struct BulkForm {
    #[serde(default)]
    pub ids:         String,
    pub bulk_action: String,
}

// ─── get_rules ───────────────────────────────────────────

/// List all rules for a policy, with summary counts.
pub async fn get_rules(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(policy_name): Path<String>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let policy = fetch_policy_header(&state, &policy_name).await?;
    let rules  = fetch_rules(&state, policy.name.clone()).await?;

    let total_rules   = rules.len();
    let enabled_rules = rules.iter().filter(|r| r.enabled).count();

    let mut ctx = Context::new();
    ctx.insert("username",      &session.username);
    ctx.insert("title",         "WAF Rules");
    ctx.insert("url",           "/policy");
    ctx.insert("policy",        &policy);
    ctx.insert("rules",         &rules);
    ctx.insert("total_rules",   &total_rules);
    ctx.insert("enabled_rules", &enabled_rules);

    Ok((jar, Html(state.tera.render("policy_rules.html", &ctx)?)).into_response())
}

// ─── get_rule_new ────────────────────────────────────────

/// Render the create-rule form for a policy.
pub async fn get_rule_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(policy_name): Path<String>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let policy = fetch_policy_header(&state, &policy_name).await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    "Add Rule");
    ctx.insert("url",      "/policy");
    ctx.insert("policy",   &policy);

    Ok((jar, Html(state.tera.render("rule_create.html", &ctx)?)).into_response())
}

// ─── post_rule_create ────────────────────────────────────

/// Handle rule creation form submission.
/// Validates pattern is a valid regex before saving.
pub async fn post_rule_create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(policy_name): Path<String>,
    Form(form): Form<RuleForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let redirect = format!("/policy/{}/rules", policy_name);

    // Validate the regex pattern before saving to avoid storing broken rules.
    if regex::Regex::new(&form.pattern).is_err() {
        return Ok(Redirect::to(
            &format!("{}?error=Invalid+regex+pattern", redirect)
        ).into_response());
    }

    let description = form.description.unwrap_or_default();
    let score: i64  = form.score.as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    // Look up the policy id from its name.
    let policy_id: i64 = sqlx::query_scalar!(
        "SELECT id as \"id!\" FROM policies WHERE name = ?",
        policy_name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", policy_name)))?;

    sqlx::query!(
        "INSERT INTO waf_rules
         (policy_id, name, description, zone, pattern, score, action)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        policy_id,
        form.name,
        description,
        form.zone,
        form.pattern,
        score,
        form.action,
    )
    .execute(&state.db)
    .await?;

    Ok(Redirect::to(&redirect).into_response())
}

// ─── post_rule_toggle ────────────────────────────────────

/// Toggle a rule's enabled flag on/off.
pub async fn post_rule_toggle(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path((policy_name, rule_id)): Path<(String, i64)>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    // Flip the enabled bit: 1 → 0, 0 → 1.
    sqlx::query!(
        "UPDATE waf_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END
         WHERE id = ?",
        rule_id
    )
    .execute(&state.db)
    .await?;

    Ok(Redirect::to(&format!("/policy/{}/rules", policy_name)).into_response())
}

// ─── post_rule_delete ────────────────────────────────────

/// Delete a rule permanently.
pub async fn post_rule_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path((policy_name, rule_id)): Path<(String, i64)>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    sqlx::query!("DELETE FROM waf_rules WHERE id = ?", rule_id)
        .execute(&state.db)
        .await?;

    Ok(Redirect::to(&format!("/policy/{}/rules", policy_name)).into_response())
}

// ─── post_seed_rules ─────────────────────────────────────

/// Insert the built-in default rule set into a policy.
/// Existing rules are left untouched — this only adds the defaults
/// so it is safe to call multiple times (duplicate names are skipped).
pub async fn post_seed_rules(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(policy_name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let policy_id: i64 = sqlx::query_scalar!(
        "SELECT id as \"id!\" FROM policies WHERE name = ?",
        policy_name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", policy_name)))?;

    seed_default_rules(&state, policy_id).await?;

    Ok(Redirect::to(&format!("/policy/{}/rules", policy_name)).into_response())
}

// ─── post_bulk_rules ─────────────────────────────────────

/// Handle the bulk-action form: enable, disable, or delete a set of rules
/// identified by their IDs. Silently ignores empty ID lists.
pub async fn post_bulk_rules(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(policy_name): Path<String>,
    Form(form): Form<BulkForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let redirect = format!("/policy/{}/rules", policy_name);

    // Parse the comma-separated IDs string into a Vec<i64>.
    // Skip empty strings and non-numeric tokens silently.
    let ids: Vec<i64> = form.ids
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .collect();

    // Nothing selected — just redirect back without doing anything.
    if ids.is_empty() {
        return Ok(Redirect::to(&redirect).into_response());
    }

    match form.bulk_action.as_str() {
        "enable" => {
            for id in &ids {
                sqlx::query!("UPDATE waf_rules SET enabled = 1 WHERE id = ?", id)
                    .execute(&state.db)
                    .await?;
            }
        }
        "disable" => {
            for id in &ids {
                sqlx::query!("UPDATE waf_rules SET enabled = 0 WHERE id = ?", id)
                    .execute(&state.db)
                    .await?;
            }
        }
        "delete" => {
            for id in &ids {
                sqlx::query!("DELETE FROM waf_rules WHERE id = ?", id)
                    .execute(&state.db)
                    .await?;
            }
        }
        other => {
            tracing::warn!(action = other, "Unknown bulk action — ignored");
        }
    }

    Ok(Redirect::to(&redirect).into_response())
}

// ─── DB helpers ──────────────────────────────────────────

/// Fetch a lightweight policy header (name + engine settings) for page context.
async fn fetch_policy_header(state: &AppState, name: &str) -> Result<PolicyHeader> {
    let r = sqlx::query!(
        "SELECT name, rule_engine,
                score_threshold as \"score_threshold!\"
         FROM policies WHERE name = ?",
        name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", name)))?;

    Ok(PolicyHeader {
        name:            r.name,
        rule_engine:     r.rule_engine,
        score_threshold: r.score_threshold,
    })
}

/// Fetch all rules for a policy, ordered by id.
async fn fetch_rules(state: &AppState, policy_name: String) -> Result<Vec<Rule>> {
    let rows = sqlx::query!(
        "SELECT wr.id          as \"id!\",
                wr.name,
                wr.description,
                wr.zone,
                wr.pattern,
                wr.score       as \"score!\",
                wr.action,
                wr.enabled     as \"enabled!: bool\"
         FROM   waf_rules wr
         JOIN   policies  p  ON p.id = wr.policy_id
         WHERE  p.name = ?
         ORDER  BY wr.id",
        policy_name
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows.into_iter().map(|r| Rule {
        id:          r.id,
        name:        r.name,
        description: r.description,
        zone:        r.zone,
        pattern:     r.pattern,
        score:       r.score,
        action:      r.action,
        enabled:     r.enabled,
    }).collect())
}

// ─── Default rule set ─────────────────────────────────────

/// Built-in WAF rules covering the most common attack categories.
/// Called on new policy creation and from the "Seed defaults" button.
/// Already-existing rules with the same name are skipped.
pub async fn seed_default_rules(state: &AppState, policy_id: i64) -> Result<()> {
    // (name, description, zone, pattern, score, action)
    let defaults: &[(&str, &str, &str, &str, i64, &str)] = &[

        // ── SQL Injection ────────────────────────────────
        (
            "SQLi: UNION SELECT",
            "Union-based SQL injection attempt",
            "ANY",
            r"(?i)union[\s\S]{0,30}select",
            8, "score",
        ),
        (
            "SQLi: SELECT FROM",
            "Basic SELECT extraction attempt",
            "ANY",
            r"(?i)select[\s\S]{0,50}from[\s\S]{0,50}where",
            6, "score",
        ),
        (
            "SQLi: DROP / TRUNCATE",
            "Destructive SQL command — instant block",
            "ANY",
            r"(?i)(drop|truncate)\s+(table|database|schema)",
            10, "block",
        ),
        (
            "SQLi: Stacked queries",
            "Multiple statements via semicolon",
            "ANY",
            r"(?i);\s*(select|insert|update|delete|drop|exec)",
            7, "score",
        ),
        (
            "SQLi: SLEEP / BENCHMARK",
            "Time-based blind SQL injection",
            "ANY",
            r"(?i)(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
            8, "score",
        ),
        (
            "SQLi: Boolean injection",
            "OR/AND 1=1 style payload",
            "ANY",
            r"(?i)'\s*(or|and)\s+[\d']+\s*=\s*[\d']+",
            6, "score",
        ),
        (
            "SQLi: SQL comment",
            "SQL comment stripping suffix",
            "ANY",
            r"(?i)(--|#|/\*|\*/)",
            3, "score",
        ),

        // ── Cross-Site Scripting (XSS) ───────────────────
        (
            "XSS: script tag",
            "Inline script tag injection",
            "ANY",
            r"(?i)<\s*script",
            8, "score",
        ),
        (
            "XSS: javascript: protocol",
            "javascript: URI in links / forms",
            "ANY",
            r"(?i)javascript\s*:",
            7, "score",
        ),
        (
            "XSS: event handler",
            "Inline DOM event handler attribute",
            "ANY",
            r"(?i)\bon\w+\s*=",
            6, "score",
        ),
        (
            "XSS: iframe / object",
            "Embedded resource tags",
            "ANY",
            r"(?i)<\s*(iframe|object|embed|applet)",
            7, "score",
        ),
        (
            "XSS: SVG payload",
            "SVG-based XSS vector",
            "ANY",
            r"(?i)<\s*svg[\s>]",
            5, "score",
        ),

        // ── Path Traversal ───────────────────────────────
        (
            "Path traversal: ../",
            "Directory traversal via dot-dot-slash",
            "URL",
            r"\.\.[/\\]",
            6, "score",
        ),
        (
            "Path traversal: URL encoded",
            "Encoded traversal sequence",
            "URL",
            r"(?i)%2e%2e[%2f%5c]",
            7, "score",
        ),
        (
            "Path traversal: /etc/passwd",
            "Attempt to read Unix credentials — instant block",
            "ANY",
            r"(?i)/etc/(passwd|shadow|hosts|group)",
            10, "block",
        ),
        (
            "Path traversal: Windows system",
            "Attempt to read Windows system files — instant block",
            "ANY",
            r"(?i)\\windows\\(system32|syswow64)",
            10, "block",
        ),

        // ── Remote Code / Command Execution ──────────────
        (
            "RCE: PHP dangerous functions",
            "PHP exec/eval/system family",
            "ANY",
            r"(?i)(eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
            9, "score",
        ),
        (
            "RCE: Shell command injection",
            "Piped shell commands via special chars",
            "ANY",
            r"[;|`]\s*\w+",
            5, "score",
        ),
        (
            "RCE: Template injection",
            "Server-side template injection probe",
            "ANY",
            r"\$\{.{0,50}\}",
            6, "score",
        ),
        (
            "RCE: PHP wrapper",
            "PHP stream wrapper attempt",
            "ANY",
            r"(?i)php://(input|filter|data|expect)",
            8, "score",
        ),

        // ── Scanner / Recon tools ────────────────────────
        (
            "Scanner: known tools in User-Agent",
            "Common automated attack tools",
            "HEADERS",
            r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|burpsuite|acunetix|nessus|openvas)",
            8, "score",
        ),
        (
            "Scanner: admin path probe",
            "Brute-force scan of admin/debug paths",
            "URL",
            r"(?i)/(admin|phpmyadmin|wp-admin|manager|console|actuator|\.env|\.git|phpinfo)",
            4, "score",
        ),
    ];

    for (name, desc, zone, pattern, score, action) in defaults {
        // Skip if a rule with this name already exists for this policy.
        let exists: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM waf_rules WHERE policy_id = ? AND name = ?",
            policy_id, name
        )
        .fetch_one(&state.db)
        .await?;

        if exists > 0 {
            continue;
        }

        sqlx::query!(
            "INSERT INTO waf_rules
             (policy_id, name, description, zone, pattern, score, action)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            policy_id, name, desc, zone, pattern, score, action,
        )
        .execute(&state.db)
        .await?;
    }

    Ok(())
}

// ─── TOML rule file structs ───────────────────────────────

/// Top-level structure of a TOML rule file.
#[derive(Deserialize)]
struct RuleFile {
    rules: Vec<RuleFileDef>,
}

/// A single rule definition inside a TOML file.
#[derive(Deserialize)]
struct RuleFileDef {
    id:          i64,
    name:        String,
    description: Option<String>,
    zone:        String,
    pattern:     String,
    score:       i64,
    action:      String,
}

// ─── post_import_rules ───────────────────────────────────

/// Read every *.toml file from the rules/ directory and insert any rule
/// whose external_id is not yet present for this policy.
/// This makes repeated imports fully idempotent — safe to run many times.
pub async fn post_import_rules(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(policy_name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let redirect = format!("/policy/{}/rules", policy_name);

    let policy_id: i64 = sqlx::query_scalar!(
        "SELECT id as \"id!\" FROM policies WHERE name = ?",
        policy_name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", policy_name)))?;

    // Read all .toml files from the rules/ directory.
    let rules_dir = std::path::Path::new("rules");
    if !rules_dir.exists() {
        tracing::warn!("rules/ directory not found — nothing imported");
        return Ok(Redirect::to(&redirect).into_response());
    }

    let mut imported = 0usize;
    let mut skipped  = 0usize;

    let entries = std::fs::read_dir(rules_dir)
        .map_err(|e| AppError::Internal(format!("Cannot read rules dir: {}", e)))?;

    for entry in entries {
        let entry = match entry {
            Ok(e)  => e,
            Err(e) => { tracing::warn!("Skipping unreadable rules dir entry: {}", e); continue; }
        };

        let path = entry.path();

        // Only process .toml files.
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(s)  => s,
            Err(e) => {
                tracing::warn!(file = %path.display(), "Cannot read rule file: {}", e);
                continue;
            }
        };

        let file: RuleFile = match toml::from_str(&content) {
            Ok(f)  => f,
            Err(e) => {
                tracing::warn!(file = %path.display(), "Cannot parse rule file: {}", e);
                continue;
            }
        };

        for rule in file.rules {
            // Skip if this external_id already exists for this policy.
            let exists: i64 = sqlx::query_scalar!(
                "SELECT COUNT(*) FROM waf_rules WHERE policy_id = ? AND external_id = ?",
                policy_id, rule.id
            )
            .fetch_one(&state.db)
            .await?;

            if exists > 0 {
                skipped += 1;
                continue;
            }

            let description = rule.description.unwrap_or_default();

            sqlx::query!(
                "INSERT INTO waf_rules
                 (policy_id, name, description, zone, pattern, score, action, external_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                policy_id,
                rule.name,
                description,
                rule.zone,
                rule.pattern,
                rule.score,
                rule.action,
                rule.id,
            )
            .execute(&state.db)
            .await?;

            imported += 1;
        }
    }

    tracing::info!(
        policy = %policy_name,
        imported,
        skipped,
        "OWASP rule import complete"
    );

    Ok(Redirect::to(&redirect).into_response())
}

// ─── Rule Library (catalog) ──────────────────────────────
//
// The catalog presents every rule found in the rules/ directory,
// grouped by category, each with a checkbox. Rules already present
// in the policy are pre-checked. Saving the form syncs the policy
// to the selection: checked rules are added, unchecked catalog rules
// are removed. This is the "pick the rules applicable to me" UI.

/// One rule as shown in the catalog.
/// `pub` so other route modules (e.g. policy creation) can render the catalog.
#[derive(Serialize)]
pub struct CatalogRule {
    pub external_id: i64,
    pub name:        String,
    pub description: String,
    pub zone:        String,
    pub pattern:     String,
    pub score:       i64,
    pub action:      String,
    pub added:       bool,   // already present in this policy
}

/// A group of catalog rules sharing a source file / CRS category.
#[derive(Serialize)]
pub struct CatalogCategory {
    pub title:       String, // friendly name, e.g. "SQL Injection"
    pub code:        String, // numeric CRS-style prefix, e.g. "942"
    pub total:       usize,
    pub added_count: usize,
    pub rules:       Vec<CatalogRule>,
}

/// Derive a friendly (code, title) pair from a rule file stem like
/// "942-sqli" → ("942", "SQL Injection").
fn category_title(file_stem: &str) -> (String, String) {
    let mut parts = file_stem.splitn(2, '-');
    let code = parts.next().unwrap_or("").to_string();
    let slug = parts.next().unwrap_or("");

    let title = match slug {
        "sqli"     => "SQL Injection",
        "xss"      => "Cross-Site Scripting",
        "lfi"      => "Local File Inclusion",
        "rfi"      => "Remote File Inclusion",
        "rce"      => "Remote Code Execution",
        "php"      => "PHP Injection",
        "protocol" => "Protocol Enforcement",
        "scanners" => "Scanners & Bots",
        other      => other,
    };

    (code, title.to_string())
}

/// Read all rule definitions from the rules/ directory into a flat map
/// keyed by external_id. Used by the catalog POST handler for additions.
fn read_rule_defs() -> HashMap<i64, RuleFileDef> {
    let mut map = HashMap::new();
    let dir = std::path::Path::new("rules");
    if !dir.exists() {
        return map;
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(s)  => s,
                Err(_) => continue,
            };
            let parsed: RuleFile = match toml::from_str(&content) {
                Ok(f)  => f,
                Err(_) => continue,
            };
            for rule in parsed.rules {
                map.insert(rule.id, rule);
            }
        }
    }
    map
}

/// Read all rule files from disk and group them into catalog categories,
/// marking each rule's `added` flag against the given set of external_ids.
/// Pure file I/O — no database access — so it is reusable by any handler.
/// Pass an empty set (e.g. for a brand-new policy) to get all rules unchecked.
pub fn read_catalog_categories(existing: &HashSet<i64>) -> Result<Vec<CatalogCategory>> {
    let dir = std::path::Path::new("rules");
    let mut categories = Vec::new();
    if !dir.exists() {
        return Ok(categories);
    }

    // Collect and sort .toml files so categories appear in a stable order.
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| AppError::Internal(format!("Cannot read rules dir: {}", e)))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
        .collect();
    files.sort();

    for path in files {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        let content = match std::fs::read_to_string(&path) {
            Ok(s)  => s,
            Err(_) => continue,
        };
        let parsed: RuleFile = match toml::from_str(&content) {
            Ok(f)  => f,
            Err(e) => {
                tracing::warn!(file = %path.display(), "Cannot parse rule file: {}", e);
                continue;
            }
        };

        let (code, title) = category_title(&stem);

        let mut rules = Vec::new();
        let mut added_count = 0;
        for r in parsed.rules {
            let added = existing.contains(&r.id);
            if added {
                added_count += 1;
            }
            rules.push(CatalogRule {
                external_id: r.id,
                name:        r.name,
                description: r.description.unwrap_or_default(),
                zone:        r.zone,
                pattern:     r.pattern,
                score:       r.score,
                action:      r.action,
                added,
            });
        }

        let total = rules.len();
        categories.push(CatalogCategory { title, code, total, added_count, rules });
    }

    Ok(categories)
}

/// Build the grouped catalog for an existing policy, pre-checking the rules
/// it already contains.
async fn load_catalog(state: &AppState, policy_id: i64) -> Result<Vec<CatalogCategory>> {
    // Which external_ids are already imported into this policy?
    let existing_rows = sqlx::query_scalar!(
        "SELECT external_id as \"external_id!\" FROM waf_rules
         WHERE policy_id = ? AND external_id IS NOT NULL",
        policy_id
    )
    .fetch_all(&state.db)
    .await?;
    let existing: HashSet<i64> = existing_rows.into_iter().collect();

    read_catalog_categories(&existing)
}

/// Insert the rules identified by `ids` (external_ids) into the given policy,
/// skipping any that are already present. Returns the number actually added.
/// Used by both the catalog sync and the policy-creation flow.
pub async fn add_rules_by_external_ids(
    state:     &AppState,
    policy_id: i64,
    ids:       &HashSet<i64>,
) -> Result<usize> {
    if ids.is_empty() {
        return Ok(0);
    }

    let defs = read_rule_defs();
    let mut added = 0usize;

    for id in ids {
        let def = match defs.get(id) {
            Some(d) => d,
            None    => continue, // unknown id — ignore
        };

        // Skip if already present in this policy.
        let exists: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM waf_rules WHERE policy_id = ? AND external_id = ?",
            policy_id, id
        )
        .fetch_one(&state.db)
        .await?;
        if exists > 0 {
            continue;
        }

        let desc = def.description.as_deref().unwrap_or("");
        sqlx::query!(
            "INSERT INTO waf_rules
             (policy_id, name, description, zone, pattern, score, action, external_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            policy_id,
            def.name,
            desc,
            def.zone,
            def.pattern,
            def.score,
            def.action,
            def.id,
        )
        .execute(&state.db)
        .await?;
        added += 1;
    }

    Ok(added)
}

// ─── get_rules_catalog ───────────────────────────────────

/// Render the rule-library selection page for a policy.
pub async fn get_rules_catalog(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(policy_name): Path<String>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let policy = fetch_policy_header(&state, &policy_name).await?;

    let policy_id: i64 = sqlx::query_scalar!(
        "SELECT id as \"id!\" FROM policies WHERE name = ?",
        policy_name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", policy_name)))?;

    let catalog = load_catalog(&state, policy_id).await?;

    let total_available: usize = catalog.iter().map(|c| c.total).sum();
    let total_added:     usize = catalog.iter().map(|c| c.added_count).sum();

    let mut ctx = Context::new();
    ctx.insert("username",        &session.username);
    ctx.insert("title",           "Rule Library");
    ctx.insert("url",             "/policy");
    ctx.insert("policy",          &policy);
    ctx.insert("catalog",         &catalog);
    ctx.insert("total_available", &total_available);
    ctx.insert("total_added",     &total_added);

    Ok((jar, Html(state.tera.render("rule_catalog.html", &ctx)?)).into_response())
}

// ─── post_rules_catalog ──────────────────────────────────

/// Form submitted by the catalog: a comma-separated list of the
/// external_ids that are currently checked.
#[derive(Deserialize)]
pub struct CatalogForm {
    #[serde(default)]
    pub ids: String,
}

/// Sync the policy's rules to the catalog selection.
/// Checked rules not yet present are inserted; catalog rules that are
/// present but no longer checked are removed. Manually-created rules
/// (no external_id) are never touched.
pub async fn post_rules_catalog(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(policy_name): Path<String>,
    Form(form): Form<CatalogForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let redirect = format!("/policy/{}/rules", policy_name);

    let policy_id: i64 = sqlx::query_scalar!(
        "SELECT id as \"id!\" FROM policies WHERE name = ?",
        policy_name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", policy_name)))?;

    // Parse the checked external_ids.
    let checked: HashSet<i64> = form.ids
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .collect();

    // All rule definitions available on disk, keyed by external_id.
    let defs = read_rule_defs();
    let catalog_ids: HashSet<i64> = defs.keys().copied().collect();

    // external_ids already present in this policy.
    let db_rows = sqlx::query_scalar!(
        "SELECT external_id as \"external_id!\" FROM waf_rules
         WHERE policy_id = ? AND external_id IS NOT NULL",
        policy_id
    )
    .fetch_all(&state.db)
    .await?;
    let db_ids: HashSet<i64> = db_rows.into_iter().collect();

    // ── Additions: checked rules not yet in the policy ────
    let mut added = 0usize;
    for id in &checked {
        if db_ids.contains(id) {
            continue;
        }
        if let Some(def) = defs.get(id) {
            let desc = def.description.as_deref().unwrap_or("");
            sqlx::query!(
                "INSERT INTO waf_rules
                 (policy_id, name, description, zone, pattern, score, action, external_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                policy_id,
                def.name,
                desc,
                def.zone,
                def.pattern,
                def.score,
                def.action,
                def.id,
            )
            .execute(&state.db)
            .await?;
            added += 1;
        }
    }

    // ── Removals: catalog rules present but no longer checked ──
    let mut removed = 0usize;
    for id in &db_ids {
        if catalog_ids.contains(id) && !checked.contains(id) {
            let rid = *id;
            sqlx::query!(
                "DELETE FROM waf_rules WHERE policy_id = ? AND external_id = ?",
                policy_id, rid
            )
            .execute(&state.db)
            .await?;
            removed += 1;
        }
    }

    tracing::info!(
        policy = %policy_name,
        added,
        removed,
        "Catalog selection synced"
    );

    Ok(Redirect::to(&redirect).into_response())
}

// ─── Global Rule Editor ──────────────────────────────────
//
// A top-level view (sidebar: Security Policy → Rule Editor) that lists
// every rule across all policies and lets each one be edited, toggled,
// or deleted. Editing rule fields (pattern, score, etc.) is only
// available here and via the per-policy pages share the same handlers.

/// One row in the global rule list, including its owning policy.
#[derive(Serialize)]
pub struct AllRule {
    pub id:          i64,
    pub policy_name: String,
    pub name:        String,
    pub zone:        String,
    pub pattern:     String,
    pub score:       i64,
    pub action:      String,
    pub enabled:     bool,
}

/// Full detail of a single rule for the edit form.
#[derive(Serialize)]
pub struct RuleDetail {
    pub id:          i64,
    pub policy_name: String,
    pub name:        String,
    pub description: String,
    pub zone:        String,
    pub pattern:     String,
    pub score:       i64,
    pub action:      String,
    pub enabled:     bool,
}

// ─── get_all_rules ───────────────────────────────────────

/// Render the global rule list — every rule across every policy.
pub async fn get_all_rules(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let rows = sqlx::query!(
        "SELECT wr.id      as \"id!\",
                p.name     as \"policy_name!\",
                wr.name,
                wr.zone,
                wr.pattern,
                wr.score   as \"score!\",
                wr.action,
                wr.enabled as \"enabled!: bool\"
         FROM   waf_rules wr
         JOIN   policies  p ON p.id = wr.policy_id
         ORDER  BY p.name, wr.id"
    )
    .fetch_all(&state.db)
    .await?;

    let rules: Vec<AllRule> = rows.into_iter().map(|r| AllRule {
        id:          r.id,
        policy_name: r.policy_name,
        name:        r.name,
        zone:        r.zone,
        pattern:     r.pattern,
        score:       r.score,
        action:      r.action,
        enabled:     r.enabled,
    }).collect();

    let total    = rules.len();
    let enabled  = rules.iter().filter(|r| r.enabled).count();

    let mut ctx = Context::new();
    ctx.insert("username",      &session.username);
    ctx.insert("title",         "Rule Editor");
    ctx.insert("url",           "/rules");
    ctx.insert("rules",         &rules);
    ctx.insert("total_rules",   &total);
    ctx.insert("enabled_rules", &enabled);

    Ok((jar, Html(state.tera.render("rules_all.html", &ctx)?)).into_response())
}

// ─── get_rule_edit_global ────────────────────────────────

/// Render the edit form for a single rule (by global id).
pub async fn get_rule_edit_global(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<i64>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let r = sqlx::query!(
        "SELECT wr.id      as \"id!\",
                p.name     as \"policy_name!\",
                wr.name,
                wr.description,
                wr.zone,
                wr.pattern,
                wr.score   as \"score!\",
                wr.action,
                wr.enabled as \"enabled!: bool\"
         FROM   waf_rules wr
         JOIN   policies  p ON p.id = wr.policy_id
         WHERE  wr.id = ?",
        id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Rule {} not found", id)))?;

    let rule = RuleDetail {
        id:          r.id,
        policy_name: r.policy_name,
        name:        r.name,
        description: r.description,
        zone:        r.zone,
        pattern:     r.pattern,
        score:       r.score,
        action:      r.action,
        enabled:     r.enabled,
    };

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    "Edit Rule");
    ctx.insert("url",      "/rules");
    ctx.insert("rule",     &rule);

    Ok((jar, Html(state.tera.render("rule_edit.html", &ctx)?)).into_response())
}

// ─── post_rule_update_global ─────────────────────────────

/// Save edits to a single rule. Validates the regex before saving.
pub async fn post_rule_update_global(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<i64>,
    Form(form): Form<RuleForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    // Reject invalid regex so we never store a broken pattern.
    if regex::Regex::new(&form.pattern).is_err() {
        return Ok(Redirect::to(
            &format!("/rules/{}/edit?error=Invalid+regex+pattern", id)
        ).into_response());
    }

    let description = form.description.unwrap_or_default();
    let score: i64  = form.score.as_deref().and_then(|s| s.parse().ok()).unwrap_or(5);
    let enabled     = form.enabled.is_some();

    sqlx::query!(
        "UPDATE waf_rules
         SET name = ?, description = ?, zone = ?, pattern = ?,
             score = ?, action = ?, enabled = ?
         WHERE id = ?",
        form.name, description, form.zone, form.pattern,
        score, form.action, enabled, id,
    )
    .execute(&state.db)
    .await?;

    Ok(Redirect::to("/rules").into_response())
}

// ─── post_rule_toggle_global ─────────────────────────────

/// Toggle a rule's enabled flag, returning to the global list.
pub async fn post_rule_toggle_global(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<i64>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    sqlx::query!(
        "UPDATE waf_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END
         WHERE id = ?",
        id
    )
    .execute(&state.db)
    .await?;

    Ok(Redirect::to("/rules").into_response())
}

// ─── post_rule_delete_global ─────────────────────────────

/// Delete a rule, returning to the global list.
pub async fn post_rule_delete_global(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<i64>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    sqlx::query!("DELETE FROM waf_rules WHERE id = ?", id)
        .execute(&state.db)
        .await?;

    Ok(Redirect::to("/rules").into_response())
}

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

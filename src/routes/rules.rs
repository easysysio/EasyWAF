// =========================================================
// routes/rules.rs — EasyWAF
// WAF rule management: list, create, toggle, delete, and
// install from the rule sets in the rules/ directory or the
// published channel.
//
// There was also a "seed defaults" button, which inserted a
// hardcoded list of rules written in this file. It was a
// second copy of what the rule sets already carry, and it
// did not merely drift — a seeded rule and its set
// counterpart both matched, so the request scored twice and
// a policy's block threshold was effectively halved for
// every rule that existed in both. Removed in 0.6.6.
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
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use sqlx::SqlitePool;
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

// ─── install_set ─────────────────────────────────────────

/// Install a version of a rule set into a policy, replacing what it holds.
///
/// Every imported rule the policy holds for this set is overwritten —
/// `pattern`, `score`, `action`, `zone`, `name`, `description` — while `id`,
/// `enabled` and `policy_id` are preserved. That is safe unconditionally, not
/// merely usually: an imported row cannot carry a customisation, because
/// customising means cloning into a separate row that is no longer imported
/// and that this never touches.
///
/// `enabled` surviving is the point of doing it this way rather than deleting
/// and re-importing. An administrator who turned a noisy rule off expects it to
/// stay off across an update; a delete-and-reimport would quietly turn it back
/// on, which is the same class of surprise as an edit being reverted.
///
/// Rules new in this version are inserted. Rules the version no longer contains
/// are left alone rather than deleted — an orphan that still matches something
/// is less alarming than a rule vanishing from a policy without being asked.
pub async fn install_set(
    db: &SqlitePool,
    policy_id: i64,
    set_id: &str,
    version: i64,
    toml_text: &str,
) -> Result<usize> {
    let file: RuleFile = toml::from_str(toml_text)
        .map_err(|e| AppError::Internal(format!("rule set could not be parsed: {e}")))?;

    let mut touched = 0usize;
    for rule in &file.rules {
        let description = rule.description.clone().unwrap_or_default();

        let existing: Option<i64> = sqlx::query_scalar!(
            r#"SELECT id as "id!" FROM waf_rules
               WHERE policy_id = ? AND external_id = ?"#,
            policy_id, rule.id
        )
        .fetch_optional(db)
        .await?;

        match existing {
            Some(id) => {
                sqlx::query!(
                    "UPDATE waf_rules
                     SET name = ?, description = ?, zone = ?, pattern = ?,
                         score = ?, action = ?, rule_set = ?,
                         imported_pattern = ?, imported_score = ?, imported_action = ?
                     WHERE id = ?",
                    rule.name, description, rule.zone, rule.pattern,
                    rule.score, rule.action, set_id,
                    rule.pattern, rule.score, rule.action, id
                )
                .execute(db)
                .await?;
            }
            None => {
                sqlx::query!(
                    "INSERT INTO waf_rules
                     (policy_id, name, description, zone, pattern, score, action,
                      external_id, rule_set, imported_pattern, imported_score, imported_action)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    policy_id, rule.name, description, rule.zone, rule.pattern,
                    rule.score, rule.action, rule.id, set_id,
                    rule.pattern, rule.score, rule.action
                )
                .execute(db)
                .await?;
            }
        }
        touched += 1;
    }

    let name = file.set.as_ref().and_then(|s| s.name.clone()).unwrap_or_else(|| set_id.to_string());
    sqlx::query!(
        "INSERT INTO policy_rule_sets (policy_id, set_id, name, version, installed_at)
         VALUES (?, ?, ?, ?, datetime('now'))
         ON CONFLICT(policy_id, set_id) DO UPDATE SET
             name = excluded.name, version = excluded.version,
             installed_at = excluded.installed_at",
        policy_id, set_id, name, version
    )
    .execute(db)
    .await?;

    Ok(touched)
}

// ─── backfill_rule_sets ──────────────────────────────────

/// Adopt rules that were imported before sets were tracked.
///
/// 015 added `rule_set` and `policy_rule_sets` and backfilled neither, so an
/// installation upgraded from 0.5.x has rules but no record of where they came
/// from. Such a policy is never offered an update — `available()` reads
/// `policy_rule_sets`, which is empty — and the Rule Sets page offers to
/// install sets whose rules are already there. The whole update mechanism is
/// inert on exactly the installations that have been running longest.
///
/// **A set is adopted only when the policy holds all of it, unchanged.** Both
/// halves of that matter:
///
/// - *All of it.* The rule catalogue lets an operator take individual rules. A
///   policy holding 5 of 18 chose 5; adopting it would let the next update
///   install the other 13 and change what is enforced.
/// - *Unchanged.* Imported rules were editable before 0.6.0, so an edited rule
///   may be someone's deliberate correction. Adopting it would let an update
///   overwrite that edit silently, which is the drift this design exists to
///   prevent.
///
/// Anything else is left alone and logged. The operator can still adopt it from
/// the Rule Sets page by pressing Install, which is an explicit act with a
/// confirmation on it — the point is that this migration never makes that
/// decision on their behalf.
///
/// Runs on every start rather than behind a flag. Adopted rules no longer match
/// `rule_set IS NULL`, so it is naturally idempotent, and an installation that
/// is fixed later heals on its next restart instead of having missed its one
/// chance.
pub async fn backfill_rule_sets(db: &SqlitePool) -> Result<()> {
    let dir = crate::rules_update::rules_source();
    let dir = dir.as_path();
    if !dir.exists() {
        return Ok(());
    }

    // Nothing to adopt is the normal case after the first run.
    let orphans: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "n!: i64" FROM waf_rules
           WHERE external_id IS NOT NULL AND rule_set IS NULL"#
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);
    if orphans == 0 {
        return Ok(());
    }

    let policies = sqlx::query!(r#"SELECT id as "id!", name as "name!" FROM policies"#)
        .fetch_all(db)
        .await?;

    let entries = match std::fs::read_dir(dir) {
        Ok(e)  => e,
        Err(_) => return Ok(()),
    };

    let mut adopted = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_rule_file(&path) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(file) = toml::from_str::<RuleFile>(&text) else { continue };
        let Some(set) = file.set.as_ref() else { continue };
        if file.rules.is_empty() {
            continue;
        }

        for policy in &policies {
            // What this policy holds of the set, and has not already claimed.
            let mut held = 0usize;
            let mut differs = false;
            for rule in &file.rules {
                let row = sqlx::query!(
                    r#"SELECT pattern, zone, action FROM waf_rules
                       WHERE policy_id = ? AND external_id = ? AND rule_set IS NULL"#,
                    policy.id, rule.id
                )
                .fetch_optional(db)
                .await?;

                if let Some(row) = row {
                    held += 1;
                    if row.pattern != rule.pattern
                        || row.zone != rule.zone
                        || row.action != rule.action
                    {
                        differs = true;
                    }
                }
            }

            if held == 0 {
                continue;
            }
            if held != file.rules.len() || differs {
                tracing::info!(
                    policy = %policy.name, set = %set.id, held, total = file.rules.len(), differs,
                    "Rule set left unclaimed: the policy holds part of it, or rules that \
                     differ from what shipped. Install it from the Rule Sets page to adopt \
                     it deliberately."
                );
                continue;
            }

            for rule in &file.rules {
                sqlx::query!(
                    "UPDATE waf_rules SET rule_set = ?
                     WHERE policy_id = ? AND external_id = ? AND rule_set IS NULL",
                    set.id, policy.id, rule.id
                )
                .execute(db)
                .await?;
            }

            let name = set.name.clone().unwrap_or_else(|| set.id.clone());
            sqlx::query!(
                "INSERT INTO policy_rule_sets (policy_id, set_id, name, version, installed_at)
                 VALUES (?, ?, ?, ?, datetime('now'))
                 ON CONFLICT(policy_id, set_id) DO NOTHING",
                policy.id, set.id, name, set.version
            )
            .execute(db)
            .await?;

            tracing::info!(
                policy = %policy.name, set = %set.id, version = set.version,
                rules = file.rules.len(),
                "Adopted a rule set imported before sets were tracked"
            );
            adopted += 1;
        }
    }

    if adopted > 0 {
        tracing::info!(
            adopted,
            "Rule sets adopted — these policies can now be offered updates"
        );
    }
    Ok(())
}

// ─── uninstall_set ───────────────────────────────────────

/// Remove a rule set from a policy. Returns (rules removed, clones kept).
///
/// The mirror of `install_set`, and deliberately not a mirror of everything it
/// wrote. Two things survive:
///
/// **Clones.** A clone is an ordinary custom rule that happens to record where
/// it came from; the operator wrote it, an update never touches it, and neither
/// does this. Deleting someone's own rule because it was once copied from a set
/// they are removing would be the most surprising thing this button could do.
///
/// **Their provenance.** A surviving clone keeps `rule_set` and
/// `cloned_from_*`, so reinstalling the set later resumes telling it when the
/// original has moved on. The columns describe where the rule came from, which
/// is still true after the set is gone.
///
/// Rules the operator disabled go with the set. Disabling one is a decision
/// about a set that is installed; removing the set answers that question at a
/// level above it.
pub async fn uninstall_set(
    db: &SqlitePool,
    policy_id: i64,
    set_id: &str,
) -> Result<(usize, usize)> {
    // `external_id IS NOT NULL` is what separates the two: an imported rule has
    // one, a clone has it cleared precisely so that updates ignore it.
    let clones: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "n!: i64" FROM waf_rules
           WHERE policy_id = ? AND rule_set = ? AND external_id IS NULL"#,
        policy_id, set_id
    )
    .fetch_one(db)
    .await?;

    let removed = sqlx::query!(
        "DELETE FROM waf_rules
         WHERE policy_id = ? AND rule_set = ? AND external_id IS NOT NULL",
        policy_id, set_id
    )
    .execute(db)
    .await?
    .rows_affected();

    // The policy no longer holds it, so it stops being something to update and
    // becomes something to install again.
    sqlx::query!(
        "DELETE FROM policy_rule_sets WHERE policy_id = ? AND set_id = ?",
        policy_id, set_id
    )
    .execute(db)
    .await?;

    tracing::info!(policy_id, set_id, removed, clones, "Uninstalled a rule set");
    Ok((removed as usize, clones as usize))
}

// ─── record_installed_set ────────────────────────────────

/// Note that a policy now holds a version of a set.
///
/// Recorded on install so an update check has something to compare against. A
/// policy that does not know which version it holds cannot be told a newer one
/// exists, which is why correcting a rule has so far meant a migration
/// rewriting patterns by hand.
async fn record_installed_set(
    db: &SqlitePool,
    policy_id: i64,
    set: &RuleFileSet,
) -> Result<()> {
    let name = set.name.clone().unwrap_or_else(|| set.id.clone());
    sqlx::query!(
        "INSERT INTO policy_rule_sets (policy_id, set_id, name, version, installed_at)
         VALUES (?, ?, ?, ?, datetime('now'))
         ON CONFLICT(policy_id, set_id) DO UPDATE SET
             name = excluded.name, version = excluded.version,
             installed_at = excluded.installed_at",
        policy_id, set.id, name, set.version
    )
    .execute(db)
    .await?;
    Ok(())
}

// ─── TOML rule file structs ───────────────────────────────

/// Top-level structure of a TOML rule file.
#[derive(Deserialize)]
struct RuleFile {
    /// Which set this is. Optional so a file written before sets described
    /// themselves still parses; such a file imports with no set recorded and
    /// simply cannot be offered updates.
    set:   Option<RuleFileSet>,
    rules: Vec<RuleFileDef>,
}

/// The `[set]` header: what this file is, and which version of it.
#[derive(Deserialize, Clone)]
struct RuleFileSet {
    id:      String,
    name:    Option<String>,
    version: i64,
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

/// Whether a path is a rule set: `<something>.rules.toml`.
///
/// The double extension is deliberate. `.rules` says what the file is — which
/// matters most once sets are published and downloaded on their own — while
/// `.toml` keeps editors highlighting and validating it, which matters when
/// the content is regular expressions being edited by hand.
fn is_rule_file(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".rules.toml"))
}

/// Read every *.rules.toml file from the rules/ directory and insert any rule
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

    // Read all rule sets from the rules/ directory.
    let rules_dir = crate::rules_update::rules_source();
    let rules_dir = rules_dir.as_path();
    if !rules_dir.exists() {
        tracing::warn!("rules/ directory not found — nothing imported");
        return Ok(Redirect::to(&redirect).into_response());
    }

    let mut imported = 0usize;
    let mut skipped  = 0usize;
    let basic_only = crate::rules_update::basic_set_ids();

    let entries = std::fs::read_dir(rules_dir)
        .map_err(|e| AppError::Internal(format!("Cannot read rules dir: {}", e)))?;

    for entry in entries {
        let entry = match entry {
            Ok(e)  => e,
            Err(e) => { tracing::warn!("Skipping unreadable rules dir entry: {}", e); continue; }
        };

        let path = entry.path();

        // Only rule sets. The suffix is checked whole rather than by extension,
        // so an unrelated .toml dropped into the directory is not parsed as
        // rules and silently imported.
        if !is_rule_file(&path) {
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

        // Import means the basic sets, not every file present. The directory
        // now holds everything the channel publishes, so without this an
        // optional set — WordPress, Apache — would be installed onto every
        // policy that pressed the button, which is the one thing the optional
        // tier exists to prevent. The tier comes from the manifest beside the
        // sets; with no manifest there is no filter, which is right for a
        // bundle that only ever held basic sets.
        if let Some(basic) = &basic_only
            && let Some(set) = file.set.as_ref()
            && !basic.contains(&set.id)
        {
            tracing::debug!(set = %set.id, "Skipping an optional set on import");
            continue;
        }

        // Recorded per rule so "which rules in this policy belong to the SQLi
        // set" is a stored fact rather than arithmetic on the id range — which
        // this project's own history has already got wrong, when 931100 sat in
        // the RCE file for several releases.
        let set_id = file.set.as_ref().map(|s| s.id.clone());

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
                 (policy_id, name, description, zone, pattern, score, action, external_id,
                  rule_set, imported_pattern, imported_score, imported_action)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                policy_id,
                rule.name,
                description,
                rule.zone,
                rule.pattern,
                rule.score,
                rule.action,
                rule.id,
                set_id,
                // What the rule looked like on import, so a later update can
                // tell an untouched rule from one an administrator changed.
                rule.pattern,
                rule.score,
                rule.action,
            )
            .execute(&state.db)
            .await?;

            imported += 1;
        }

        // Recorded once the file's rules are in, and regardless of how many
        // were skipped as already present: what matters is which version of
        // the set this policy now holds, not how much of it was new.
        if let Some(set) = file.set.as_ref() {
            record_installed_set(&state.db, policy_id, set).await?;
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
    /// The set these rules belong to, when the file declares one.
    ///
    /// Carried so a category can be chosen whole. Taking every rule in a set
    /// one at a time and installing the set are not the same act: the second
    /// records what the policy holds and can be offered updates, the first
    /// leaves eighteen rules that nothing will ever correct.
    pub set_id:      Option<String>,
    /// `basic` or `optional`, for labelling. Empty when unknown.
    pub tier:        String,
    pub total:       usize,
    pub added_count: usize,
    pub rules:       Vec<CatalogRule>,
}

/// The set name from a rule file path: `942-sqli.rules.toml` → `942-sqli`.
fn rule_set_stem(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".rules.toml"))
        .unwrap_or("")
        .to_string()
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
fn read_rule_defs() -> HashMap<i64, (RuleFileDef, Option<String>)> {
    let mut map = HashMap::new();
    let dir = crate::rules_update::rules_source();
    let dir = dir.as_path();
    if !dir.exists() {
        return map;
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_rule_file(&path) {
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
            // The set is carried alongside each rule so a rule taken singly
            // from the library still records where it came from. Without it
            // those rows have an external_id and no set, which is the exact
            // signature of a leftover from a renumbering — indistinguishable
            // from real debris in anything that goes looking for it.
            let set_id = parsed.set.as_ref().map(|s| s.id.clone());
            for rule in parsed.rules {
                map.insert(rule.id, (rule, set_id.clone()));
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
    let dir = crate::rules_update::rules_source();
    let dir = dir.as_path();
    let mut categories = Vec::new();
    if !dir.exists() {
        return Ok(categories);
    }

    // Tiers come from the manifest beside the sets, so an optional set can be
    // labelled as one rather than sitting unmarked among the rest.
    let tiers: HashMap<String, String> = {
        let manifest = std::fs::read_to_string(crate::rules_update::cache_dir().join("sets.toml"))
            .or_else(|_| std::fs::read_to_string("rules/sets.toml"))
            .unwrap_or_default();
        crate::rules_update::parse_manifest(&manifest)
            .into_iter()
            .map(|s| (s.id, s.tier))
            .collect()
    };

    // Collect and sort rule sets so categories appear in a stable order.
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| AppError::Internal(format!("Cannot read rules dir: {}", e)))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
        .collect();
    files.sort();

    for path in files {
        // file_stem() leaves the ".rules" of "942-sqli.rules.toml" behind, which
        // would make the category read "sqli.rules" instead of "SQL Injection".
        let stem = rule_set_stem(&path);

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
        let set_id = parsed.set.as_ref().map(|s| s.id.clone());
        let tier = set_id
            .as_ref()
            .and_then(|id| tiers.get(id).cloned())
            .unwrap_or_default();
        categories.push(CatalogCategory { title, code, set_id, tier, total, added_count, rules });
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
        let (def, set_id) = match defs.get(id) {
            Some(d) => (&d.0, d.1.clone()),
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
        // rule_set records provenance; it does not make the policy *hold* the
        // set. That is what policy_rule_sets is for, and it is deliberately not
        // written here — a policy that took three rules out of eighteen chose
        // three, and an update must not arrive and install the other fifteen.
        sqlx::query!(
            "INSERT INTO waf_rules
             (policy_id, name, description, zone, pattern, score, action, external_id,
              rule_set, imported_pattern, imported_score, imported_action)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            policy_id,
            def.name,
            desc,
            def.zone,
            def.pattern,
            def.score,
            def.action,
            def.id,
            set_id,
            // What the rule looked like on import — see migration 008.
            def.pattern,
            def.score,
            def.action,
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
            let (def, set_id) = (&def.0, def.1.clone());
            let desc = def.description.as_deref().unwrap_or("");
            sqlx::query!(
                "INSERT INTO waf_rules
                 (policy_id, name, description, zone, pattern, score, action, external_id,
                  rule_set, imported_pattern, imported_score, imported_action)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                policy_id,
                def.name,
                desc,
                def.zone,
                def.pattern,
                def.score,
                def.action,
                def.id,
                set_id,
                // What the rule looked like on import — see migration 008.
                def.pattern,
                def.score,
                def.action,
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
pub struct EditorRule {
    pub id:          i64,
    pub policy_name: String,
    pub name:        String,
    pub zone:        String,
    pub pattern:     String,
    pub score:       i64,
    pub action:      String,
    pub enabled:     bool,
}

/// A group of rules sharing a category, for the collapsible editor view.
#[derive(Serialize)]
pub struct EditorGroup {
    pub title:   String, // friendly category name, or "Custom / Manual"
    pub code:    String, // CRS-style code, or "custom"
    pub total:   usize,
    pub enabled: usize,
    /// How many policies these rows belong to.
    ///
    /// A rule is a row per policy, so two policies holding one set produce two
    /// rows for every rule in it. The count above is rows, and reading it as
    /// rules is wrong by exactly that factor — a set of 18 showed as 36. The
    /// header says how many policies are in play when it is more than one,
    /// rather than presenting a number that means something else.
    pub policies: usize,
    pub rules:   Vec<EditorRule>,
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

/// Render the global rule list, grouped into collapsible category panels.
/// Categories come from the rule files (via external_id); rules without a
/// known external_id are placed in a "Custom / Manual" group at the end.
/// Flash, plus the rule to open the page on.
#[derive(Debug, Deserialize)]
pub struct AllRulesQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
    /// Expand this rule's group and scroll to it.
    pub focus:  Option<i64>,
}

/// A custom rule whose pattern is already matched by an imported one.
#[derive(Debug, Serialize)]
pub struct DuplicateRule {
    pub id:          i64,
    pub policy_name: String,
    pub name:        String,
    pub score:       i64,
    /// "clone" or "custom" — what the operator should weigh when deciding.
    pub origin:      String,
}

/// Custom rules that duplicate an imported one, by pattern, in the same policy.
///
/// Every matching rule adds its score, so a duplicate is not cosmetic: the pair
/// scores twice and the policy's block threshold is effectively halved for that
/// pattern. A request scoring 8 against a threshold of 10 passes; the same
/// request scoring 8 twice does not.
///
/// Matched on the pattern rather than the name, because the names drifted apart
/// while the patterns stayed identical — which is exactly how this went
/// unnoticed.
///
/// Listed, never removed. A custom rule is the operator's, and deleting one
/// because it resembles a shipped rule is not a decision to make on their
/// behalf.
async fn duplicate_rules(db: &SqlitePool) -> Vec<DuplicateRule> {
    sqlx::query!(
        r#"SELECT c.id          as "id!",
                  p.name        as "policy_name!",
                  c.name        as "name!",
                  c.score       as "score!",
                  c.cloned_from_external_id
           FROM   waf_rules c
           JOIN   policies  p ON p.id = c.policy_id
           WHERE  c.external_id IS NULL
             AND  EXISTS (SELECT 1 FROM waf_rules s
                          WHERE s.policy_id   = c.policy_id
                            AND s.external_id IS NOT NULL
                            AND s.pattern     = c.pattern)
           ORDER BY p.name, c.name"#
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| DuplicateRule {
        id:          r.id,
        policy_name: r.policy_name,
        name:        r.name,
        score:       r.score,
        origin:      if r.cloned_from_external_id.is_some() { "clone" } else { "custom" }.to_string(),
    })
    .collect()
}

pub async fn get_all_rules(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(q): Query<AllRulesQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    // Categories come from what each rule says it belongs to, which the
    // database records as of the last install or update. The rule files on disk
    // are a build-time snapshot and go stale the moment a set is updated from
    // the channel: a rule added in a newer version is not in them, so grouping
    // by them filed a correctly-installed rule under "Custom / Manual".
    //
    // The files are still consulted, but only as a fallback for a rule that has
    // no set recorded — an installation upgraded from before 0.6.0 whose policy
    // the adoption in 0.6.4 declined to claim. Those keep the old behaviour
    // rather than all collapsing into Custom.
    let set_names = sqlx::query!(
        r#"SELECT DISTINCT set_id as "set_id!", name as "name!" FROM policy_rule_sets"#
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let name_of: HashMap<String, String> =
        set_names.into_iter().map(|r| (r.set_id, r.name)).collect();

    // The disk snapshot, for rules with no set recorded.
    let cats = read_catalog_categories(&HashSet::new()).unwrap_or_default();
    let mut cat_of: HashMap<i64, (String, String)> = HashMap::new();
    for c in &cats {
        for r in &c.rules {
            cat_of.insert(r.external_id, (c.code.clone(), c.title.clone()));
        }
    }

    // Fetch every rule with its policy name and external_id.
    let rows = sqlx::query!(
        "SELECT wr.id          as \"id!\",
                p.name         as \"policy_name!\",
                wr.name,
                wr.zone,
                wr.pattern,
                wr.score       as \"score!\",
                wr.action,
                wr.enabled     as \"enabled!: bool\",
                wr.external_id,
                wr.rule_set
         FROM   waf_rules wr
         JOIN   policies  p ON p.id = wr.policy_id
         ORDER  BY p.name, wr.id"
    )
    .fetch_all(&state.db)
    .await?;

    // Bucket rules by category code.
    let mut buckets: HashMap<String, Vec<EditorRule>> = HashMap::new();
    let custom_code = "custom".to_string();

    // set_id -> title, so a group can be named without consulting the files.
    let mut titles: HashMap<String, String> = HashMap::new();
    // Lowest external_id seen in each group, which orders the bands the way
    // the catalogue used to: 913 before 920 before 930.
    let mut lowest: HashMap<String, i64> = HashMap::new();

    for r in rows {
        let code = match (&r.rule_set, r.external_id) {
            // What the rule says it belongs to. Authoritative and current.
            (Some(set), _) => {
                titles.entry(set.clone()).or_insert_with(|| {
                    name_of.get(set).cloned().unwrap_or_else(|| set.clone())
                });
                set.clone()
            }
            // No set recorded: fall back to the build-time snapshot.
            (None, Some(id)) => match cat_of.get(&id) {
                Some((code, title)) => {
                    titles.entry(code.clone()).or_insert_with(|| title.clone());
                    code.clone()
                }
                None => custom_code.clone(),
            },
            (None, None) => custom_code.clone(),
        };
        if let Some(id) = r.external_id {
            let e = lowest.entry(code.clone()).or_insert(id);
            *e = (*e).min(id);
        }
        buckets.entry(code).or_default().push(EditorRule {
            id:          r.id,
            policy_name: r.policy_name,
            name:        r.name,
            zone:        r.zone,
            pattern:     r.pattern,
            score:       r.score,
            action:      r.action,
            enabled:     r.enabled,
        });
    }

    // Assemble in band order — the lowest rule id in each group — then Custom
    // last. Ordering by the ids rather than by the order the files happened to
    // be read keeps a set in its familiar place even when the files are absent.
    let mut order: Vec<(String, String)> = titles
        .iter()
        .map(|(code, title)| (code.clone(), title.clone()))
        .collect();
    order.sort_by_key(|(code, _)| lowest.get(code).copied().unwrap_or(i64::MAX));

    let mut groups: Vec<EditorGroup> = Vec::new();
    for (code, title) in &order {
        if let Some(rules) = buckets.remove(code) {
            let enabled = rules.iter().filter(|r| r.enabled).count();
            let policies = rules
                .iter()
                .map(|r| r.policy_name.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len();
            groups.push(EditorGroup {
                title:   title.clone(),
                code:    code.clone(),
                total:   rules.len(),
                enabled,
                policies,
                rules,
            });
        }
    }
    if let Some(rules) = buckets.remove(&custom_code) {
        let enabled = rules.iter().filter(|r| r.enabled).count();
        let policies = rules
            .iter()
            .map(|r| r.policy_name.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        groups.push(EditorGroup {
            title:   "Custom / Manual".to_string(),
            code:    custom_code.clone(),
            policies,
            total:   rules.len(),
            enabled,
            rules,
        });
    }

    let total:   usize = groups.iter().map(|g| g.total).sum();
    let enabled: usize = groups.iter().map(|g| g.enabled).sum();

    let mut ctx = Context::new();
    ctx.insert("username",      &session.username);
    ctx.insert("title",         "Rule Editor");
    ctx.insert("url",           "/rules");
    ctx.insert("groups",        &groups);
    ctx.insert("total_rules",   &total);
    ctx.insert("enabled_rules", &enabled);
    ctx.insert("result",        &q.result.unwrap_or_default());
    ctx.insert("msg",           &q.msg.unwrap_or_default());
    ctx.insert("focus",         &q.focus.unwrap_or(0));
    ctx.insert("duplicates",    &duplicate_rules(&state.db).await);

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
                wr.enabled as \"enabled!: bool\",
                wr.external_id,
                wr.rule_set,
                wr.cloned_from_external_id,
                wr.cloned_from_version,
                wr.policy_id as \"policy_id!\"
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
    // An imported rule is shown but not editable, so the page has to say which
    // it is — a form whose fields silently refuse to save is worse than one
    // that explains itself.
    ctx.insert("imported",     &r.external_id.is_some());
    ctx.insert("external_id",  &r.external_id);
    ctx.insert("rule_set",     &r.rule_set);
    ctx.insert("cloned_from",  &r.cloned_from_external_id);
    ctx.insert("cloned_ver",   &r.cloned_from_version);

    // Where the set has got to since the fork. The version was recorded at
    // clone time precisely to answer this, and stopping at "so you can tell
    // when the set has moved on" asks the reader to carry two numbers from two
    // pages in their head — which is the same as not recording it.
    let set_now: Option<i64> = match (&r.rule_set, r.cloned_from_version) {
        (Some(set), Some(_)) => sqlx::query_scalar!(
            "SELECT version FROM policy_rule_sets WHERE policy_id = ? AND set_id = ?",
            r.policy_id, set
        )
        .fetch_optional(&state.db)
        .await?,
        _ => None,
    };
    // Decided here rather than in the template. Tera reads a compound
    // condition mixing truthiness with a comparison as something other than
    // what it looks like — it rendered nothing with set_now=2 and
    // cloned_ver=1 — and a notice that silently fails to appear is worse than
    // no notice, because the page then looks like it checked.
    let set_moved_on = matches!(
        (set_now, r.cloned_from_version),
        (Some(now), Some(forked)) if now > forked
    );
    ctx.insert("set_now",      &set_now);
    ctx.insert("set_moved_on", &set_moved_on);
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

    // An imported rule's content is not editable. Updating a set overwrites
    // every imported rule it owns, so an edit made here would be silently
    // reverted by the next update — and the administrator would have no way to
    // know it had happened.
    //
    // Cloning is the supported route: it produces an ordinary custom rule that
    // updates never touch. This makes drift structurally impossible rather than
    // something to detect later, so applying an update needs no comparison and
    // has no case where the comparison could be wrong.
    //
    // `enabled` is deliberately still writable below for custom rules; for
    // imported ones the toggle route handles it, since turning a rule off is a
    // subscription decision rather than a content edit.
    let imported: Option<i64> =
        sqlx::query_scalar!("SELECT external_id FROM waf_rules WHERE id = ?", id)
            .fetch_optional(&state.db)
            .await?
            .flatten();

    if imported.is_some() {
        return Ok(Redirect::to(&format!(
            "/rules/{id}/edit?error=This+rule+came+from+a+rule+set+and+cannot+be+edited.+\
             Clone+it+to+make+a+version+you+can+change."
        ))
        .into_response());
    }

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

    // Back to the list with the rule named and pointed at. A clone is bucketed
    // by external_id, which it does not have, so it leaves the category its
    // original sits in and lands in "Custom / Manual" at the bottom — collapsed,
    // like every group. Saving used to redirect here with no message and no
    // indication of that, so a rule someone had just edited appeared to be gone.
    Ok(Redirect::to(&format!(
        "/rules?focus={}&result=success&msg={}",
        id,
        urlencoding::encode(&format!("Saved '{}'", form.name.trim()))
    ))
    .into_response())
}

// ─── post_rule_clone ─────────────────────────────────────

/// POST /rules/{id}/clone — copy an imported rule into an editable custom one.
///
/// The clone is not a special kind of rule: `external_id` is cleared, so it is
/// an ordinary custom rule that rule-set updates never touch and the editor
/// treats like any other. The fork point is recorded only so an update notice
/// can say "your custom rule was forked from SQLi v2, the set is now v4" — a
/// nudge for a person, never an automatic merge.
///
/// The original is left enabled. Disabling it is a separate decision, and
/// doing it here would mean a click labelled "clone" quietly changed what the
/// policy enforces.
pub async fn post_rule_clone(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<i64>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let src = sqlx::query!(
        r#"SELECT policy_id as "policy_id!", name, description, zone, pattern,
                  score as "score!", action, external_id, rule_set
           FROM waf_rules WHERE id = ?"#,
        id
    )
    .fetch_optional(&state.db)
    .await?;

    let Some(src) = src else {
        return Ok(Redirect::to("/rules?error=No+such+rule").into_response());
    };

    // Cloning a custom rule is a reasonable thing to want, but it is not what
    // this button is for and the copy would be indistinguishable from the
    // original — so it is refused rather than quietly duplicating.
    let Some(external_id) = src.external_id else {
        return Ok(Redirect::to(
            "/rules?error=That+rule+is+already+a+custom+rule+and+can+be+edited+directly",
        )
        .into_response());
    };

    // The version of the set at the moment of cloning, when it is known.
    let version: Option<i64> = match src.rule_set.as_deref() {
        Some(set) => sqlx::query_scalar!(
            "SELECT version FROM policy_rule_sets WHERE policy_id = ? AND set_id = ?",
            src.policy_id, set
        )
        .fetch_optional(&state.db)
        .await?,
        None => None,
    };

    let name = format!("{} (custom)", src.name);
    let new_id = sqlx::query!(
        "INSERT INTO waf_rules
         (policy_id, name, description, zone, pattern, score, action,
          enabled, rule_set, cloned_from_external_id, cloned_from_version)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
        src.policy_id, name, src.description, src.zone, src.pattern,
        src.score, src.action, src.rule_set, external_id, version
    )
    .execute(&state.db)
    .await?
    // Taken from the INSERT's own result rather than a following
    // `SELECT last_insert_rowid()`: that value is per connection, and a pool
    // hands the second query to whichever connection is free, so it returned
    // the id of an unrelated earlier insert and the redirect landed on
    // somebody else's rule.
    .last_insert_rowid();

    tracing::info!(from = id, to = new_id, external_id, "Cloned an imported rule");
    Ok(Redirect::to(&format!("/rules/{new_id}/edit")).into_response())
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

// ─── Custom rule creation (global) ───────────────────────

/// Form for creating a custom rule from the Rule Editor.
/// Unlike the per-policy create form, this one chooses the target policy.
#[derive(Deserialize)]
pub struct CustomRuleForm {
    pub policy:      String,          // target policy name
    pub name:        String,
    pub description: Option<String>,
    pub zone:        String,
    pub pattern:     String,
    pub score:       Option<String>,
    pub action:      String,
}

// ─── get_custom_rule_new ─────────────────────────────────

/// Render the "create custom rule" form, with a policy picker.
pub async fn get_custom_rule_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    // Policy names for the dropdown.
    let policies = sqlx::query_scalar!("SELECT name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    "Add Custom Rule");
    ctx.insert("url",      "/rules");
    ctx.insert("policies", &policies);

    Ok((jar, Html(state.tera.render("rule_custom_new.html", &ctx)?)).into_response())
}

// ─── post_custom_rule_create ─────────────────────────────

/// Create a custom rule (no external_id) in the chosen policy.
/// Validates the regex and that the target policy exists.
pub async fn post_custom_rule_create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<CustomRuleForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    // Reject an invalid regex before saving.
    if regex::Regex::new(&form.pattern).is_err() {
        return Ok(Redirect::to("/rules/new?error=Invalid+regex+pattern").into_response());
    }

    // Resolve the target policy by name.
    let policy_id: i64 = sqlx::query_scalar!(
        "SELECT id as \"id!\" FROM policies WHERE name = ?",
        form.policy
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", form.policy)))?;

    let description = form.description.unwrap_or_default();
    let score: i64  = form.score.as_deref().and_then(|s| s.parse().ok()).unwrap_or(5);

    // external_id is left NULL → the rule appears in the "Custom / Manual" group.
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

    Ok(Redirect::to("/rules").into_response())
}

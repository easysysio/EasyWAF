// =========================================================
// routes/policy.rs — EasyWAF
// Security policy management.
// Policies are stored entirely in the DB. The WAF engine
// reads them at inspection time — no config files written.
// =========================================================

use crate::{auth::get_session, error::{AppError, Result}, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tera::Context;

// ─── Models ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Policy {
    pub id:                  i64,
    pub name:                String,
    pub rule_engine:         String,
    pub score_threshold:     i64,
    /// Score at which a request is CAPTCHA-challenged (0 = disabled).
    pub challenge_threshold: i64,
    /// Total rules attached to this policy (0 if none yet).
    pub rule_count:      i64,
    /// How many of those rules are enabled.
    pub enabled_count:   i64,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct FlashQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

// ─── get_policies ────────────────────────────────────────

pub async fn get_policies(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let policies = fetch_policies(&state).await?;

    let mut ctx = Context::new();
    ctx.insert("username",  &session.username);
    ctx.insert("title",     "Policy Manager");
    ctx.insert("url",       "/policy");
    ctx.insert("policies",  &policies);
    ctx.insert("result",    &flash.result.unwrap_or_default());
    ctx.insert("msg",       &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("policy.html", &ctx)?)).into_response())
}

// ─── get_policy_new ──────────────────────────────────────

pub async fn get_policy_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    // Load the full rule catalog with nothing pre-checked (new policy).
    let catalog = crate::routes::rules::read_catalog_categories(&HashSet::new())?;
    let total_available: usize = catalog.iter().map(|c| c.total).sum();

    let mut ctx = Context::new();
    ctx.insert("username",        &session.username);
    ctx.insert("title",           "Create Policy");
    ctx.insert("url",             "/policy");
    ctx.insert("catalog",         &catalog);
    ctx.insert("total_available", &total_available);

    Ok((jar, Html(state.tera.render("policy_create.html", &ctx)?)).into_response())
}

// ─── post_policy_create ──────────────────────────────────

pub async fn post_policy_create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(raw): Form<HashMap<String, String>>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let name = raw.get("name").map(|s| s.trim().to_string()).unwrap_or_default();
    if name.is_empty() {
        return flash_redirect("/policy", "failed", "Policy name is required");
    }

    let rule_engine     = raw.get("rule_engine").cloned().unwrap_or_else(|| "DetectionOnly".into());
    let score_threshold: i64 = raw.get("score_threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let challenge_threshold: i64 = raw.get("challenge_threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let insert = sqlx::query!(
        "INSERT INTO policies (name, rule_engine, score_threshold, challenge_threshold)
         VALUES (?, ?, ?, ?)",
        name, rule_engine, score_threshold, challenge_threshold,
    )
    .execute(&state.db)
    .await?;

    let policy_id = insert.last_insert_rowid();

    // Insert any rules the user selected in the catalog (comma-separated ids).
    let ids: HashSet<i64> = raw.get("ids")
        .map(|s| s.split(',').filter_map(|p| p.trim().parse::<i64>().ok()).collect())
        .unwrap_or_default();

    let added = crate::routes::rules::add_rules_by_external_ids(&state, policy_id, &ids).await?;

    flash_redirect(
        "/policy",
        "success",
        &format!("Policy {} created with {} rule(s)", name, added),
    )
}

// ─── get_policy_edit ─────────────────────────────────────

pub async fn get_policy_edit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

    let policy = fetch_policy(&state, &name).await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title",    "Policy Settings");
    ctx.insert("url",      "/policy");
    ctx.insert("policy",   &policy);

    Ok((jar, Html(state.tera.render("policy_settings.html", &ctx)?)).into_response())
}

// ─── post_policy_update ──────────────────────────────────

pub async fn post_policy_update(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(raw): Form<HashMap<String, String>>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let rule_engine     = raw.get("rule_engine").cloned().unwrap_or_else(|| "DetectionOnly".into());
    let score_threshold: i64 = raw.get("score_threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let challenge_threshold: i64 = raw.get("challenge_threshold")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    sqlx::query!(
        "UPDATE policies SET rule_engine=?, score_threshold=?, challenge_threshold=? WHERE name=?",
        rule_engine, score_threshold, challenge_threshold, name,
    )
    .execute(&state.db)
    .await?;

    flash_redirect("/policy", "success", &format!("Policy {} updated successfully", name))
}

// ─── post_policy_delete ──────────────────────────────────

pub async fn post_policy_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    sqlx::query!("DELETE FROM policies WHERE name = ?", name)
        .execute(&state.db)
        .await?;

    flash_redirect("/policy", "success", &format!("Policy {} deleted successfully", name))
}

// ─── Helpers ─────────────────────────────────────────────

async fn fetch_policies(state: &AppState) -> Result<Vec<Policy>> {
    // LEFT JOIN so policies with no rules still appear, with counts of 0.
    let rows = sqlx::query!(
        "SELECT p.id          as \"id!\",
                p.name,
                p.rule_engine,
                p.score_threshold     as \"score_threshold!\",
                p.challenge_threshold as \"challenge_threshold!\",
                COUNT(wr.id)   as \"rule_count!\",
                COALESCE(SUM(wr.enabled), 0) as \"enabled_count!\"
         FROM   policies p
         LEFT   JOIN waf_rules wr ON wr.policy_id = p.id
         GROUP  BY p.id
         ORDER  BY p.name"
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows.into_iter().map(|r| Policy {
        id:                  r.id,
        name:                r.name,
        rule_engine:         r.rule_engine,
        score_threshold:     r.score_threshold,
        challenge_threshold: r.challenge_threshold,
        rule_count:          r.rule_count,
        enabled_count:       r.enabled_count,
    }).collect())
}

async fn fetch_policy(state: &AppState, name: &str) -> Result<Policy> {
    let r = sqlx::query!(
        "SELECT id as \"id!\", name, rule_engine,
                score_threshold     as \"score_threshold!\",
                challenge_threshold as \"challenge_threshold!\"
         FROM policies WHERE name = ?",
        name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", name)))?;

    Ok(Policy {
        id:                  r.id,
        name:                r.name,
        rule_engine:         r.rule_engine,
        score_threshold:     r.score_threshold,
        challenge_threshold: r.challenge_threshold,
        // Counts are not shown on the single-policy edit page.
        rule_count:          0,
        enabled_count:       0,
    })
}

fn flash_redirect(path: &str, result: &str, msg: &str) -> Result<Response> {
    let msg_enc = urlencoding::encode(msg).into_owned();
    Ok(Redirect::to(&format!("{}?result={}&msg={}", path, result, msg_enc)).into_response())
}

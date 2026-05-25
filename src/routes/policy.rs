// =========================================================
// routes/policy.rs — EasyWAF
// Security policy management: list, create, edit, delete.
// Each policy maps to a ModSecurity .conf file + a DB row.
// =========================================================

use crate::{
    auth::get_session,
    error::{AppError, Result},
    nginx::{delete_policy_config, list_rules, write_policy_config},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tera::Context;

// ─── Models ──────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Policy {
    pub id: i64,
    pub name: String,
    pub rule_engine: String,
    pub rules: String,
}

// ─── Forms ───────────────────────────────────────────────

/// The create/update form sends rule checkboxes as dynamic fields;
/// captured from the raw form map (HashMap) in the handler instead.

#[derive(Deserialize)]
pub struct FlashQuery {
    pub result: Option<String>,
    pub msg: Option<String>,
}

// ─── get_policies ────────────────────────────────────────

/// GET /policy — List all policies.
pub async fn get_policies(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let policies = sqlx::query_as!(
        Policy,
        "SELECT id as \"id!\", name, rule_engine, rules FROM policies ORDER BY name"
    )
    .fetch_all(&state.db)
    .await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Policy Manager");
    ctx.insert("url", "/policy");
    ctx.insert("policies", &policies);
    ctx.insert("result", &flash.result.unwrap_or_default());
    ctx.insert("msg", &flash.msg.unwrap_or_default());

    let html = state.tera.render("policy.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// ─── get_policy_new ──────────────────────────────────────

/// GET /policy/new — Show the create-policy form.
pub async fn get_policy_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let rules = list_rules(&state.config.nginx.rules_dir);

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Create Policy");
    ctx.insert("url", "/policy");
    ctx.insert("rules", &rules);
    ctx.insert("enabled_rules", &Vec::<String>::new());

    let html = state.tera.render("policy_create.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// ─── post_policy_create ──────────────────────────────────

/// POST /policy/create — Save a new policy.
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
        return Ok(Redirect::to("/policy?result=failed&msg=Policy+name+is+required").into_response());
    }

    let rule_engine = raw.get("rule_engine").cloned().unwrap_or_else(|| "DetectionOnly".into());
    let all_rules = list_rules(&state.config.nginx.rules_dir);
    let enabled_rules: Vec<String> = all_rules.iter().filter(|r| raw.contains_key(*r)).cloned().collect();

    // Ensure policy dir exists.
    std::fs::create_dir_all(&state.config.nginx.policy_dir).map_err(AppError::Io)?;

    write_policy_config(&state.config.nginx, &name, &rule_engine, &enabled_rules)
        .map_err(AppError::Io)?;

    let rules_csv = enabled_rules.join(",");
    sqlx::query!(
        "INSERT INTO policies (name, rule_engine, rules) VALUES (?, ?, ?)",
        name, rule_engine, rules_csv
    )
    .execute(&state.db)
    .await?;

    let msg = urlencoding::encode(&format!("Policy {} created successfully", name)).into_owned();
    Ok(Redirect::to(&format!("/policy?result=success&msg={}", msg)).into_response())
}

// ─── get_policy_edit ─────────────────────────────────────

/// GET /policy/:name/edit — Show the edit form for an existing policy.
pub async fn get_policy_edit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let policy = sqlx::query_as!(
        Policy,
        "SELECT id as \"id!\", name, rule_engine, rules FROM policies WHERE name = ?",
        name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{}' not found", name)))?;

    let all_rules = list_rules(&state.config.nginx.rules_dir);
    let enabled_rules: Vec<&str> = policy.rules.split(',').filter(|s| !s.is_empty()).collect();

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Policy Settings");
    ctx.insert("url", "/policy");
    ctx.insert("policy", &policy);
    ctx.insert("rules", &all_rules);
    ctx.insert("enabled_rules", &enabled_rules);

    let html = state.tera.render("policy_settings.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// ─── post_policy_update ──────────────────────────────────

/// POST /policy/:name/update — Update an existing policy.
pub async fn post_policy_update(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(raw): Form<HashMap<String, String>>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    let rule_engine = raw.get("rule_engine").cloned().unwrap_or_else(|| "DetectionOnly".into());
    let all_rules = list_rules(&state.config.nginx.rules_dir);
    let enabled_rules: Vec<String> = all_rules.iter().filter(|r| raw.contains_key(*r)).cloned().collect();

    write_policy_config(&state.config.nginx, &name, &rule_engine, &enabled_rules)
        .map_err(AppError::Io)?;

    let rules_csv = enabled_rules.join(",");
    sqlx::query!(
        "UPDATE policies SET rule_engine=?, rules=? WHERE name=?",
        rule_engine, rules_csv, name
    )
    .execute(&state.db)
    .await?;

    let msg = urlencoding::encode(&format!("Policy {} updated successfully", name)).into_owned();
    Ok(Redirect::to(&format!("/policy?result=success&msg={}", msg)).into_response())
}

// ─── post_policy_delete ──────────────────────────────────

/// POST /policy/:name/delete — Delete a policy.
pub async fn post_policy_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

    delete_policy_config(&state.config.nginx, &name);

    sqlx::query!("DELETE FROM policies WHERE name = ?", name)
        .execute(&state.db)
        .await?;

    let msg = urlencoding::encode(&format!("Policy {} deleted successfully", name)).into_owned();
    Ok(Redirect::to(&format!("/policy?result=success&msg={}", msg)).into_response())
}

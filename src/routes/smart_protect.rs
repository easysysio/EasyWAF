// =========================================================
// routes/smart_protect.rs — EasyWAF
// Settings → Smart Protect: the numbers, and what is blocked
// right now.
//
// A policy decides whether Smart Protect applies to it — the
// checkbox is on the policy. This page holds what is set
// once for all of them: how many refusals, in what window,
// block an address, and for how long.
//
// It also lists every block in force, with why, which policy
// made it and how long is left, and a button to lift it: a
// block nobody can see or lift is what operators dislike
// most about tools of this kind.
// =========================================================

use crate::routes::flash_redirect;
use crate::smart_protect::{self, BLOCK_SECS_RANGE, REFUSALS_RANGE, WINDOW_SECS_RANGE};
use crate::{auth::{Admin, Viewer}, error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tera::Context;

#[derive(Deserialize)]
pub struct PageQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

/// One block, as the page shows it.
#[derive(Serialize)]
struct BlockView {
    policy_id:   i64,
    policy_name: String,
    /// What is blocked: an address, or an IPv6 /64.
    unit:        String,
    /// The same, as the unblock form sends it back.
    unit_raw:    String,
    /// The address whose refusal completed the count.
    address:     String,
    reason:      String,
    since:       String,
    remaining:   String,
}

/// A policy with Smart Protect switched on, as the page lists them.
#[derive(Serialize)]
struct WatchedPolicy {
    name: String,
    /// "Enforcing" or "Detection only" — Off policies are not listed.
    mode: String,
}

// ─── get_smart_protect ───────────────────────────────────

/// GET /smart-protect — the numbers, the policies it is on for, and every
/// block in force.
pub async fn get_smart_protect(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(q): Query<PageQuery>,
) -> Result<Response> {
    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title", "Smart Protect");
    ctx.insert("url",   "/smart-protect");
    ctx.insert("result", &q.result.unwrap_or_default());
    ctx.insert("msg",    &q.msg.unwrap_or_default());

    let n = smart_protect::numbers();
    ctx.insert("refusals",    &n.refusals);
    ctx.insert("window_secs", &n.window.as_secs());
    ctx.insert("block_mins",  &(n.block.as_secs() / 60));
    ctx.insert("rule",        &smart_protect::rule_text());
    ctx.insert("refusals_min", REFUSALS_RANGE.start());
    ctx.insert("refusals_max", REFUSALS_RANGE.end());
    ctx.insert("window_min",   WINDOW_SECS_RANGE.start());
    ctx.insert("window_max",   WINDOW_SECS_RANGE.end());
    ctx.insert("block_min",    &(BLOCK_SECS_RANGE.start() / 60));
    ctx.insert("block_max",    &(BLOCK_SECS_RANGE.end() / 60));

    let policies = sqlx::query!(
        r#"SELECT id as "id!", name, rule_engine, smart_protect as "smart_protect!: bool"
           FROM policies ORDER BY name"#
    )
    .fetch_all(&state.db)
    .await?;

    let names: HashMap<i64, String> = policies.iter().map(|p| (p.id, p.name.clone())).collect();
    let watched: Vec<WatchedPolicy> = policies
        .iter()
        .filter(|p| p.smart_protect && p.rule_engine != "Off")
        .map(|p| WatchedPolicy {
            name: p.name.clone(),
            mode: if p.rule_engine == "On" { "Enforcing" } else { "Detection only" }.to_string(),
        })
        .collect();
    ctx.insert("watched", &watched);
    ctx.insert("policy_count", &policies.len());

    let blocks: Vec<BlockView> = smart_protect::list()
        .into_iter()
        .map(|b| BlockView {
            policy_id:   b.policy,
            policy_name: names.get(&b.policy).cloned().unwrap_or_else(|| format!("policy {}", b.policy)),
            unit:        smart_protect::unit_label(b.unit),
            unit_raw:    b.unit.to_string(),
            address:     b.address.to_string(),
            reason:      b.reason.clone(),
            since:       b.since.format("%Y-%m-%d %H:%M:%S").to_string(),
            remaining:   smart_protect::span(b.remaining()),
        })
        .collect();
    ctx.insert("blocks", &blocks);

    Ok((jar, Html(state.tera.render("smart_protect.html", &ctx)?)).into_response())
}

// ─── post_settings ───────────────────────────────────────

#[derive(Deserialize)]
pub struct NumbersForm {
    pub refusals:    String,
    pub window_secs: String,
    pub block_mins:  String,
}

/// One field of the form, as a number within its range, or the message to
/// show. Refused rather than clamped: a value silently changed on save is a
/// setting that does not say what it does.
fn field(raw: &str, what: &str, unit: &str, range: std::ops::RangeInclusive<u64>) -> std::result::Result<u64, String> {
    match raw.trim().parse::<u64>() {
        Ok(v) if range.contains(&v) => Ok(v),
        _ => Err(format!(
            "{what} must be a whole number from {} to {} {unit}",
            range.start(), range.end()
        )),
    }
}

/// POST /smart-protect/settings — save the numbers and put them in force.
pub async fn post_settings(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<NumbersForm>,
) -> Result<Response> {
    let mins = *BLOCK_SECS_RANGE.start() / 60..=*BLOCK_SECS_RANGE.end() / 60;
    let parsed = field(&form.refusals, "Refusals", "", REFUSALS_RANGE)
        .and_then(|r| Ok((r, field(&form.window_secs, "The window", "seconds", WINDOW_SECS_RANGE)?)))
        .and_then(|(r, w)| Ok((r, w, field(&form.block_mins, "The block", "minutes", mins)?)));
    let (refusals, window_secs, block_mins) = match parsed {
        Ok(v)  => v,
        Err(e) => return flash_redirect("/smart-protect", "failed", e.trim()),
    };

    crate::settings::set(&state.db, smart_protect::KEY_REFUSALS, &refusals.to_string()).await?;
    crate::settings::set(&state.db, smart_protect::KEY_WINDOW_SECS, &window_secs.to_string()).await?;
    crate::settings::set(&state.db, smart_protect::KEY_BLOCK_SECS, &(block_mins * 60).to_string()).await?;
    smart_protect::load(&state.db).await;

    tracing::info!(by = %session.username, refusals, window_secs, block_mins, "Smart Protect numbers changed");
    // A block already in force keeps the length it was made with: changing the
    // numbers decides what happens next, not what already happened.
    flash_redirect(
        "/smart-protect",
        "success",
        &format!("Saved. {} Blocks already in force keep the length they were made with.",
                 smart_protect::rule_text()),
    )
}

// ─── post_unblock ────────────────────────────────────────

#[derive(Deserialize)]
pub struct UnblockForm {
    pub policy_id: i64,
    pub unit:      String,
}

/// POST /smart-protect/unblock — lift one block now.
pub async fn post_unblock(
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<UnblockForm>,
) -> Result<Response> {
    let Ok(unit) = form.unit.trim().parse::<std::net::IpAddr>() else {
        return flash_redirect("/smart-protect", "failed", "That is not an address");
    };
    let label = smart_protect::unit_label(unit);
    if smart_protect::unblock(form.policy_id, unit) {
        tracing::info!(by = %session.username, client = %label, policy = form.policy_id,
                       "Smart Protect block lifted");
        flash_redirect("/smart-protect", "success",
                       &format!("{label} is no longer blocked. Its count starts again from nothing."))
    } else {
        flash_redirect("/smart-protect", "failed",
                       &format!("{label} was not blocked — the block may have just ended"))
    }
}

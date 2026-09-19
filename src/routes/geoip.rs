// =========================================================
// routes/geoip.rs — EasyWAF
// Country rules overview.
//
// The rules themselves belong to a policy and are edited on
// the policy settings page; this page lists what each policy
// currently does, so the nav entry leads somewhere useful
// instead of to a form that duplicates policy settings.
// =========================================================

use crate::{auth::{Admin, Viewer}, error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;
use std::collections::HashMap;
use tera::Context;

/// The flash a write leaves behind, read back on the next render.
#[derive(Debug, Deserialize)]
pub struct GeoQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

// ─── get_geoip ───────────────────────────────────────────

/// GET /geoip — show each policy's country rules.
pub async fn get_geoip(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(q): Query<GeoQuery>,
) -> Result<Response> {

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title", "GeoLocation Rules");
    ctx.insert("url", "/geoip");
    ctx.insert("result", &q.result.unwrap_or_default());
    ctx.insert("msg",    &q.msg.unwrap_or_default());
    ctx.insert("policies", &crate::routes::policy::list_policies(&state).await?);

    // The rule that applies whatever a policy says, edited here because it
    // belongs to no policy — this is the one page that is about all of them.
    let all = everywhere(&state).await?;
    ctx.insert("all_mode",      &all.0);
    ctx.insert("all_countries", &all.1);
    ctx.insert("all_sites",     &sites_inspected(&state).await?);

    let html = state.tera.render("geoip.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

/// The every-policy country rule: its mode and its list.
///
/// Read by the policy pages too, which show what already applies there before
/// anybody sets a rule of their own.
pub async fn everywhere(state: &AppState) -> Result<(String, String)> {
    let row = sqlx::query!(
        r#"SELECT mode as "mode!", countries as "countries!"
           FROM geoip_everywhere WHERE id = 1"#
    )
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|r| (r.mode, r.countries)).unwrap_or_else(|| ("off".into(), String::new())))
}

/// How many sites the every-policy rule can reach: the ones with a policy,
/// since a site without one is not inspected at all.
async fn sites_inspected(state: &AppState) -> Result<i64> {
    Ok(sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "n!" FROM sites WHERE waf_policy_id IS NOT NULL"#
    )
    .fetch_one(&state.db)
    .await?)
}

// ─── post_geoip_all ──────────────────────────────────────

/// POST /geoip/all — set the country rule that applies on every policy.
///
/// It is applied as well as each policy's own rule, never instead: a request
/// either refuses is refused. So this form can only widen what is refused,
/// which is why it says how many sites that is before it is saved.
pub async fn post_geoip_all(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(raw): Form<HashMap<String, String>>,
) -> Result<Response> {

    let mode = match raw.get("mode").map(String::as_str) {
        Some("block") => "block",
        Some("allow") => "allow",
        _             => "off",
    };
    let countries = crate::routes::policy::normalize_countries(
        raw.get("countries").map(String::as_str).unwrap_or(""));

    sqlx::query!(
        "UPDATE geoip_everywhere
         SET mode = ?, countries = ?, changed_by = ?, updated_at = datetime('now')
         WHERE id = 1",
        mode, countries, session.username
    )
    .execute(&state.db)
    .await?;

    tracing::info!(mode, countries = %countries, by = %session.username,
                   "Every-policy country rule saved");

    let n = sites_inspected(&state).await?;
    let where_ = match n {
        0 => "every policy, though no site uses one yet".to_string(),
        1 => "every policy — the one site that has one".to_string(),
        _ => format!("every policy ({n} sites have one)"),
    };
    let msg = match (mode, countries.is_empty()) {
        ("off", _) => {
            "No country rule applies to every policy — each policy's own still does".to_string()
        }
        (_, true) => format!(
            "No countries listed, so the every-policy rule does nothing yet — {mode} mode \
is saved and waiting for a list"
        ),
        ("allow", _) => format!(
            "Only {countries} may reach {where_} — every other country is refused, on top \
of what each policy refuses"
        ),
        _ => format!(
            "{countries} refused on {where_}, on top of what each policy refuses"
        ),
    };

    crate::routes::flash_redirect("/geoip", "success", &msg)
}

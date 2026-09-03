// =========================================================
// routes/geoip.rs — EasyWAF
// Country rules overview.
//
// The rules themselves belong to a policy and are edited on
// the policy settings page; this page lists what each policy
// currently does, so the nav entry leads somewhere useful
// instead of to a form that duplicates policy settings.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use tera::Context;

// ─── get_geoip ───────────────────────────────────────────

/// GET /geoip — show each policy's country rules.
pub async fn get_geoip(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "GeoLocation Rules");
    ctx.insert("url", "/geoip");
    ctx.insert("result", "");
    ctx.insert("msg", "");
    ctx.insert("policies", &crate::routes::policy::list_policies(&state).await?);

    let html = state.tera.render("geoip.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// =========================================================
// routes/geoip.rs — EasyWAF
// GeoIP / geolocation rule management (placeholder).
// Full implementation in a future release.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use tera::Context;

// ─── get_geoip ───────────────────────────────────────────

/// GET /geoip — GeoIP rules page (stub).
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

    let html = state.tera.render("geoip.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

// =========================================================
// routes/dashboard.rs — EasyWAF
// Dashboard handler — shows site/cert/policy counts.
// =========================================================

use crate::{auth::get_session, error::Result, AppState};
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use tera::Context;

// ─── get_dashboard ───────────────────────────────────────

/// GET / — Dashboard with summary counts and charts.
pub async fn get_dashboard(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };

    // Count rows from the DB (source of truth for all managed objects).
    let sites_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM sites")
            .fetch_one(&state.db)
            .await?;

    let certs_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM certs")
            .fetch_one(&state.db)
            .await?;

    let policies_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM policies")
            .fetch_one(&state.db)
            .await?;

    let mut ctx = Context::new();
    ctx.insert("username", &session.username);
    ctx.insert("title", "Dashboard");
    ctx.insert("url", "/");
    ctx.insert("sites_number", &sites_count);
    ctx.insert("certs_number", &certs_count);
    ctx.insert("policy_number", &policies_count);

    let html = state.tera.render("dashboard.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

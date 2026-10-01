// =========================================================
// routes/tutorial.rs — EasyWAF
// The tutorial: the steps that take a new installation from
// nothing to a site with an enforced policy.
//
// It opens by itself after an administrator signs in, until
// one of them says not to show it again; after that it is
// reached from the menu. Each step that can be checked is
// ticked from what the appliance actually holds, so the page
// says where this installation has got to rather than
// reciting a list.
// =========================================================

use crate::routes::flash_redirect;
use crate::{auth::{Admin, Viewer}, error::Result, AppState};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tera::Context;

/// "1" once an administrator has said not to open the tutorial at sign-in.
const KEY_HIDDEN: &str = "tutorial_hidden";

#[derive(Deserialize)]
pub struct PageQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
}

// ─── opens_at_sign_in ────────────────────────────────────

/// Whether signing in lands on the tutorial rather than the dashboard.
pub async fn opens_at_sign_in(db: &SqlitePool) -> bool {
    crate::settings::get(db, KEY_HIDDEN).await.as_deref() != Some("1")
}

// ─── Progress ────────────────────────────────────────────

/// How far this installation has got: one answer per step that can be read
/// from the database. Steps about reading and judging traffic have none.
#[derive(Serialize)]
struct Progress {
    site:      bool,
    traffic:   bool,
    https:     bool,
    policy:    bool,
    enforcing: bool,
    smart:     bool,
    lists:     bool,
    backup:    bool,
}

impl Progress {
    async fn read(db: &SqlitePool) -> Result<Self> {
        let r = sqlx::query!(
            r#"SELECT
                 EXISTS (SELECT 1 FROM sites)                                   AS "site!: bool",
                 EXISTS (SELECT 1 FROM traffic_events)                          AS "traffic!: bool",
                 EXISTS (SELECT 1 FROM sites s
                           JOIN site_ports p ON p.site_id = s.id AND p.tls = 1
                          WHERE s.cert_id IS NOT NULL)                          AS "https!: bool",
                 EXISTS (SELECT 1 FROM sites WHERE waf_policy_id IS NOT NULL)   AS "policy!: bool",
                 EXISTS (SELECT 1 FROM sites s
                           JOIN policies p ON p.id = s.waf_policy_id
                          WHERE p.rule_engine = 'On')                           AS "enforcing!: bool",
                 EXISTS (SELECT 1 FROM sites s
                           JOIN policies p ON p.id = s.waf_policy_id
                          WHERE p.smart_protect = 1)                            AS "smart!: bool",
                 EXISTS (SELECT 1 FROM ip_list_feeds WHERE enabled = 1)         AS "lists!: bool""#
        )
        .fetch_one(db)
        .await?;
        Ok(Self {
            site:      r.site,
            traffic:   r.traffic,
            https:     r.https,
            policy:    r.policy,
            enforcing: r.enforcing,
            smart:     r.smart,
            lists:     r.lists,
            backup:    crate::backup::scheduled(db).await,
        })
    }
}

// ─── get_tutorial ────────────────────────────────────────

/// GET /tutorial — the steps, each ticked when this installation has done it.
pub async fn get_tutorial(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(q): Query<PageQuery>,
) -> Result<Response> {
    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title", "Tutorial");
    ctx.insert("url",   "/tutorial");
    ctx.insert("result", &q.result.unwrap_or_default());
    ctx.insert("msg",    &q.msg.unwrap_or_default());
    ctx.insert("done",   &Progress::read(&state.db).await?);
    ctx.insert("opens_at_sign_in", &opens_at_sign_in(&state.db).await);

    Ok((jar, Html(state.tera.render("tutorial.html", &ctx)?)).into_response())
}

// ─── post_hide ───────────────────────────────────────────

/// POST /tutorial/hide — stop opening the tutorial at sign-in. It stays in the
/// menu.
pub async fn post_hide(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
) -> Result<Response> {
    crate::settings::set(&state.db, KEY_HIDDEN, "1").await?;
    tracing::info!(by = %session.username, "The tutorial no longer opens at sign-in");
    flash_redirect("/tutorial", "success",
        "The tutorial will not open at sign-in again. It stays here, under Tutorial in the menu.")
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::raw_sql("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,
                                              updated_at TEXT NOT NULL DEFAULT (datetime('now')));
                       CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);")
            .execute(&pool).await.unwrap();
        pool
    }

    const MIGRATION: &str = include_str!("../../migrations/038_tutorial.sql");

    #[tokio::test]
    async fn a_new_installation_is_shown_the_tutorial() {
        let db = db().await;
        sqlx::raw_sql(MIGRATION).execute(&db).await.unwrap();
        assert!(opens_at_sign_in(&db).await);
    }

    #[tokio::test]
    async fn an_installation_already_in_use_is_not() {
        let db = db().await;
        sqlx::raw_sql("INSERT INTO users (username) VALUES ('boss')").execute(&db).await.unwrap();
        sqlx::raw_sql(MIGRATION).execute(&db).await.unwrap();
        assert!(!opens_at_sign_in(&db).await);
    }

    /// The first account is created after the first start, so on the second
    /// start an account exists. The answer given at the first must stand.
    #[tokio::test]
    async fn a_later_start_does_not_change_the_answer() {
        let db = db().await;
        sqlx::raw_sql(MIGRATION).execute(&db).await.unwrap();
        sqlx::raw_sql("INSERT INTO users (username) VALUES ('boss')").execute(&db).await.unwrap();
        sqlx::raw_sql(MIGRATION).execute(&db).await.unwrap();
        assert!(opens_at_sign_in(&db).await, "still shown: nobody has dismissed it");

        crate::settings::set(&db, KEY_HIDDEN, "1").await.unwrap();
        sqlx::raw_sql(MIGRATION).execute(&db).await.unwrap();
        assert!(!opens_at_sign_in(&db).await, "and once dismissed it stays dismissed");
    }
}

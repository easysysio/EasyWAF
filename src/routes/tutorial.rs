// =========================================================
// routes/tutorial.rs — EasyWAF
// The tutorial: a quick setup, one step at a time, that
// takes a new installation to a site being watched by a
// policy.
//
//   1  the site        name, hostname, where it forwards to
//   2  check it        a request through EasyWAF, then DNS
//   3  HTTPS           a certificate from Let's Encrypt
//   4  protection      a policy in DetectionOnly, on the site
//   5  backup          daily snapshots
//   6  what is next    watch, fix false positives, enforce
//
// Each step is a short form that does the thing, not a
// description of where to go and do it. The forms post to
// the same handlers the full pages use, so there is one
// place that creates a site or a policy; only HTTPS has a
// handler here, because it is three of the site page's
// actions in one press.
//
// It opens by itself after an administrator signs in, until
// one of them says not to show it again; after that it is
// reached from the menu. It works on the newest site, and
// says for each step whether that site already has it, so
// it can be left and picked up again.
// =========================================================

use crate::routes::{flash_redirect, safe_back};
use crate::{auth::{Admin, Viewer}, error::Result, AppState};
use axum::{
    extract::{Query, State},
    http::{header::HOST, HeaderMap},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use tera::Context;

/// "1" once an administrator has said not to open the tutorial at sign-in.
const KEY_HIDDEN: &str = "tutorial_hidden";

/// The last step: what to do over the following days.
const LAST_STEP: i64 = 6;

/// The port a site is given HTTPS on when it has none.
const HTTPS_PORT: i64 = 443;

/// Published lists the policy step offers switched off. Every other list is
/// offered at the response its publisher gives; using Tor is not an attack,
/// so refusing or challenging it is a decision to make, not a default.
const LISTS_LEFT_OFF: &[&str] = &["tor-exits"];

#[derive(Deserialize)]
pub struct PageQuery {
    pub step:    Option<i64>,
    /// Show the site form although a site exists, to set up another.
    pub another: Option<String>,
    pub result:  Option<String>,
    pub msg:     Option<String>,
}

// ─── opens_at_sign_in ────────────────────────────────────

/// Whether signing in lands on the tutorial rather than the dashboard.
pub async fn opens_at_sign_in(db: &SqlitePool) -> bool {
    crate::settings::get(db, KEY_HIDDEN).await.as_deref() != Some("1")
}

// ─── The site being set up ───────────────────────────────

/// The newest site, which is the one the steps after the first work on.
#[derive(Serialize)]
struct SiteNow {
    id:          i64,
    name:        String,
    server_name: String,
    http_port:   i64,
    https_port:  Option<i64>,
    has_cert:    bool,
    /// Its policy's name and mode, when it has one.
    policy:      Option<String>,
    mode:        Option<String>,
    has_traffic: bool,
}

impl SiteNow {
    async fn newest(db: &SqlitePool) -> Result<Option<Self>> {
        let row = sqlx::query!(
            r#"SELECT s.id           AS "id!",
                      s.name         AS "name!",
                      s.server_name  AS "server_name!",
                      s.listen_port  AS "http_port!",
                      s.tls_port     AS https_port,
                      s.cert_id IS NOT NULL                       AS "has_cert!: bool",
                      p.name         AS "policy?",
                      p.rule_engine  AS "mode?",
                      EXISTS (SELECT 1 FROM traffic_events t
                               WHERE t.site_id = s.id)            AS "has_traffic!: bool"
               FROM sites s
               LEFT JOIN policies p ON p.id = s.waf_policy_id
               ORDER BY s.id DESC LIMIT 1"#
        )
        .fetch_optional(db)
        .await?;
        Ok(row.map(|r| Self {
            id:          r.id,
            name:        r.name,
            server_name: r.server_name,
            http_port:   r.http_port,
            https_port:  r.https_port,
            has_cert:    r.has_cert,
            policy:      r.policy,
            mode:        r.mode,
            has_traffic: r.has_traffic,
        }))
    }
}

// ─── Done ────────────────────────────────────────────────

/// Which of the steps that do something are already done, for the newest site.
#[derive(Serialize, Default, Clone, Copy)]
struct Done {
    site:    bool,
    traffic: bool,
    https:   bool,
    policy:  bool,
    backup:  bool,
}

impl Done {
    fn of(site: Option<&SiteNow>, backup: bool) -> Self {
        match site {
            None => Self { backup, ..Self::default() },
            Some(s) => Self {
                site:    true,
                traffic: s.has_traffic,
                https:   s.has_cert && s.https_port.is_some(),
                policy:  s.policy.is_some(),
                backup,
            },
        }
    }

    /// The step to open: the one asked for, or where this installation has
    /// got to — the step after the furthest one done. Without a site it is
    /// always the first, since every other step works on one.
    fn open_step(&self, asked: Option<i64>) -> i64 {
        if !self.site {
            return 1;
        }
        if let Some(n) = asked.filter(|n| (1..=LAST_STEP).contains(n)) {
            return n;
        }
        let steps = [self.site, self.traffic, self.https, self.policy, self.backup];
        let furthest = steps.iter().rposition(|done| *done).map_or(0, |i| i as i64 + 1);
        furthest + 1
    }
}

// ─── get_tutorial ────────────────────────────────────────

/// GET /tutorial — one step of the quick setup.
pub async fn get_tutorial(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Result<Response> {
    let site = SiteNow::newest(&state.db).await?;
    let done = Done::of(site.as_ref(), crate::backup::scheduled(&state.db).await);
    let step = done.open_step(q.step);

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title", "Tutorial");
    ctx.insert("url",   "/tutorial");
    ctx.insert("result", &q.result.unwrap_or_default());
    ctx.insert("msg",    &q.msg.unwrap_or_default());
    ctx.insert("step",    &step);
    ctx.insert("done",    &done);
    ctx.insert("another", &q.another.is_some());
    ctx.insert("opens_at_sign_in", &opens_at_sign_in(&state.db).await);

    // The name this interface was reached by, for the command that sends a
    // request through EasyWAF before DNS points at it: the same host answers
    // for the sites.
    ctx.insert("this_host", &this_host(&headers));

    if step == 3 {
        let acme = crate::acme::config(&state.db).await.ok().flatten();
        ctx.insert("acme_email", &acme.map(|a| a.email).unwrap_or_default());
    }
    if step == 4 {
        // What a policy made here is given: the basic rule sets, and each
        // published list at the response its publisher suggests.
        let basic: Vec<String> = crate::rules_update::offered(&state.db).await
            .into_iter()
            .filter(|s| s.tier == "basic")
            .map(|s| s.id)
            .collect();
        ctx.insert("basic_sets", &basic.len());
        ctx.insert("set_ids",    &basic.join(","));
        let (lists, _) = crate::iplist_feeds::catalogue(
            &state.db, crate::iplist_feeds::Scope::Policy(0)).await;
        let lists: Vec<ListChoice> = lists.into_iter().map(ListChoice::from).collect();
        ctx.insert("lists", &lists);
        ctx.insert("policy_name", &free_policy_name(&state.db, site.as_ref()).await);
    }
    ctx.insert("site", &site);

    Ok((jar, Html(state.tera.render("tutorial.html", &ctx)?)).into_response())
}

/// A published list as the policy step offers it: by name, with the response
/// the form starts on.
#[derive(Serialize)]
struct ListChoice {
    id:     String,
    name:   String,
    choice: String,
}

impl From<crate::iplist_feeds::ListView> for ListChoice {
    fn from(l: crate::iplist_feeds::ListView) -> Self {
        let choice = if LISTS_LEFT_OFF.contains(&l.id.as_str()) { "off".to_string() } else { l.response };
        Self { id: l.id, name: l.name, choice }
    }
}

/// The host part of the address this page was asked for, without its port.
fn this_host(headers: &HeaderMap) -> String {
    let host = headers.get(HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    // An IPv6 literal keeps its brackets; anything else loses `:port`.
    let bare = match host.rfind(':') {
        Some(i) if !host.ends_with(']') => &host[..i],
        _ => host,
    };
    if bare.is_empty() { "this-host".to_string() } else { bare.to_string() }
}

/// A name to offer for the new policy: `websites`, or the site's own name
/// when a policy called that already exists.
async fn free_policy_name(db: &SqlitePool, site: Option<&SiteNow>) -> String {
    let taken: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM policies WHERE name = 'websites'")
        .fetch_one(db)
        .await
        .unwrap_or(0);
    match (taken, site) {
        (0, _)       => "websites".to_string(),
        (_, Some(s)) => s.name.clone(),
        (_, None)    => String::new(),
    }
}

// ─── post_https ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct HttpsForm {
    pub site:  String,
    pub email: String,
}

/// POST /tutorial/https — a Let's Encrypt certificate for the site, and HTTPS
/// switched on with it.
///
/// Three things the site's own page does one at a time: the contact address
/// the CA is given, the certificate, and a port to serve it on. The redirect
/// from HTTP is left off, as it is everywhere else, until somebody has seen
/// HTTPS work.
pub async fn post_https(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<HttpsForm>,
) -> Result<Response> {
    const HERE: &str = "/tutorial?step=3";

    let site = sqlx::query!(
        r#"SELECT id AS "id!", server_name AS "server_name!", listen_port AS "listen_port!", tls_port
           FROM sites WHERE name = ?"#,
        form.site
    )
    .fetch_optional(&state.db)
    .await?;
    let Some(site) = site else {
        return flash_redirect(HERE, "failed", "No such site");
    };

    let email = form.email.trim();
    if !email.contains('@') {
        return flash_redirect(HERE, "failed",
            "Let's Encrypt needs a contact email address, for notices about the certificate");
    }

    // The port first: a certificate nobody can be served is not what was asked for.
    let https_port = site.tls_port.unwrap_or(HTTPS_PORT);
    let gui = &state.config.proxy;
    if https_port == gui.gui_port as i64 || https_port == gui.gui_tls_port as i64 {
        return flash_redirect(HERE, "failed", &format!(
            "Port {https_port} is the management interface on this host, so the site cannot \
             serve HTTPS there. Give the site a different HTTPS port on its own page."));
    }

    // A contact already set keeps its directory — somebody chose it. A first
    // one gets certificates browsers trust.
    let directory = match crate::acme::config(&state.db).await? {
        Some(c) => c.directory,
        None    => crate::acme::PRODUCTION_DIRECTORY.to_string(),
    };
    crate::acme::set_config(&state.db, email, &directory).await?;

    let names = crate::routes::sites::site_names(&state.db, site.id, &site.server_name).await;
    let cert_id = match crate::acme::issue_and_store(&state.db, &names, &site.server_name).await {
        Ok(id) => id,
        Err(e) => return flash_redirect(HERE, "failed", &format!(
            "No certificate was issued: {e}. Every name must resolve to this host from the \
             internet, with port 80 open to it.")),
    };

    sqlx::query!(
        "UPDATE sites SET cert_id = ?, acme_enabled = 1, tls_port = ?, updated_at = datetime('now')
         WHERE id = ?",
        cert_id, https_port, site.id
    )
    .execute(&state.db)
    .await?;
    crate::routes::sites::announce_site(&state, site.listen_port, Some(https_port), &[], &[]).await;

    tracing::info!(by = %session.username, site = %form.site, port = https_port,
                   "HTTPS switched on from the tutorial");
    flash_redirect(HERE, "success", &format!(
        "A certificate was issued for {} and the site now serves HTTPS on port {https_port}. \
         It renews by itself.", names.join(", ")))
}

// ─── post_hide ───────────────────────────────────────────

/// POST /tutorial/hide — stop opening the tutorial at sign-in. It stays in the
/// menu.
pub async fn post_hide(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response> {
    crate::settings::set(&state.db, KEY_HIDDEN, "1").await?;
    tracing::info!(by = %session.username, "The tutorial no longer opens at sign-in");

    // Finishing leaves for the page the form names; dismissing part-way stays
    // and says where to find it again.
    match form.get("back") {
        Some(back) => Ok(Redirect::to(&safe_back(Some(back), "/")).into_response()),
        None => flash_redirect("/tutorial", "success",
            "The tutorial will not open at sign-in again. It stays here, under Tutorial in the menu."),
    }
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

    #[test]
    fn it_opens_where_the_installation_has_got_to() {
        let none = Done::default();
        assert_eq!(none.open_step(None), 1);
        assert_eq!(none.open_step(Some(4)), 1, "every later step needs a site");

        let site = Done { site: true, ..none };
        assert_eq!(site.open_step(None), 2);

        // HTTPS was skipped: a policy is on, so the next thing is backup, not
        // a return to the step that was passed over.
        let watching = Done { site: true, policy: true, ..none };
        assert_eq!(watching.open_step(None), 5);

        let all = Done { site: true, traffic: true, https: true, policy: true, backup: true };
        assert_eq!(all.open_step(None), LAST_STEP);
    }

    #[test]
    fn a_step_asked_for_is_the_step_shown_when_it_exists() {
        let site = Done { site: true, ..Done::default() };
        assert_eq!(site.open_step(Some(3)), 3);
        assert_eq!(site.open_step(Some(1)), 1);
        assert_eq!(site.open_step(Some(0)), 2, "not a step: where it has got to");
        assert_eq!(site.open_step(Some(99)), 2);
    }

    #[test]
    fn the_host_this_page_was_asked_for_loses_its_port() {
        let host = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(HOST, v.parse().unwrap());
            this_host(&h)
        };
        assert_eq!(host("waf.example.com:8443"), "waf.example.com");
        assert_eq!(host("192.0.2.10:8443"), "192.0.2.10");
        assert_eq!(host("waf.example.com"), "waf.example.com");
        assert_eq!(host("[2001:db8::1]:8443"), "[2001:db8::1]");
        assert_eq!(this_host(&HeaderMap::new()), "this-host");
    }
}

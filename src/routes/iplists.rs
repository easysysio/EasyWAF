// =========================================================
// routes/iplists.rs — EasyWAF
// A policy's allow and block lists, and the published lists
// it has switched on.
//
// Entries mostly arrive from a Traffic Monitor row, which is
// where somebody is standing when they decide an address
// should never be seen again; the row's site decides which
// policy they land in. This page is where they are read back,
// searched and taken off again, one policy at a time.
//
// Nothing here reloads anything. Every write moves the
// configuration generation, and the matcher rebuilds a
// policy's lists from that on its next request.
// =========================================================

use crate::routes::flash_redirect;
use crate::{auth::{Admin, Viewer}, error::Result, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use tera::Context;

// ─── Models ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Entry {
    pub id:         i64,
    pub ip:         String,
    pub list_type:  String,
    pub reason:     Option<String>,
    pub added_by:   Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// The policy shown, by name. Absent means the first.
    pub policy: Option<String>,
    pub q:      Option<String>,
    pub result: Option<String>,
    pub msg:    Option<String>,
}

/// Switching a published list on or off, and choosing what it does.
/// Where to return to, for a form rendered on a page other than IP Lists.
#[derive(Debug, Deserialize)]
pub struct BackForm {
    pub back: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FeedForm {
    pub policy:   String,
    pub back:     Option<String>,
    /// An unticked checkbox sends nothing, so its absence is the answer.
    pub enabled:  Option<String>,
    pub response: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateForm {
    /// The policy that was in view, to return to.
    pub policy: Option<String>,
    pub back:   Option<String>,
}

/// Adding an address, from a traffic row or from this page's own form.
#[derive(Debug, Deserialize)]
pub struct AddForm {
    pub ip:        String,
    pub list_type: String,
    pub reason:    Option<String>,
    /// The policy, from this page's own form.
    pub policy:    Option<String>,
    /// The traffic row's host, from Traffic Monitor. Its site's policy is the
    /// one the address is added to.
    pub host:      Option<String>,
    /// Where to return to, preserving whatever filter was applied.
    pub back:      Option<String>,
}

// ─── Helpers ─────────────────────────────────────────────

fn page(policy: &str) -> String {
    format!("/iplists?policy={}", urlencoding::encode(policy))
}

/// The policy an add is for: named by this page's form, or reached through the
/// site a traffic row belongs to. The error is the message to show.
async fn target_policy(
    state: &AppState,
    policy: Option<&str>,
    host: Option<&str>,
) -> Result<std::result::Result<(i64, String), String>> {
    if let Some(name) = policy.filter(|n| !n.is_empty()) {
        let id = sqlx::query_scalar!("SELECT id FROM policies WHERE name = ?", name)
            .fetch_optional(&state.db)
            .await?
            .flatten();
        return Ok(id.map(|id| (id, name.to_string()))
            .ok_or_else(|| format!("There is no policy named {name}.")));
    }
    let Some(host) = host.filter(|h| !h.is_empty()) else {
        return Ok(Err("Select a policy first.".to_string()));
    };
    let site = sqlx::query!(
        "SELECT s.waf_policy_id, p.name as \"policy_name?\"
         FROM   sites s LEFT JOIN policies p ON p.id = s.waf_policy_id
         WHERE  s.server_name = ?",
        host
    )
    .fetch_optional(&state.db)
    .await?;
    Ok(match site {
        None => Err(format!("No site named {host} — it may have been deleted.")),
        Some(s) => match (s.waf_policy_id, s.policy_name) {
            (Some(id), Some(name)) => Ok((id, name)),
            _ => Err(format!(
                "{host} has no policy, so it has no IP lists. Attach a policy to the site first."
            )),
        },
    })
}

// ─── get_iplists ─────────────────────────────────────────

/// GET /iplists — one policy's entries, newest first, and its published lists.
pub async fn get_iplists(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(q): Query<ListQuery>,
) -> Result<Response> {

    let policies = sqlx::query!("SELECT id as \"id!\", name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;
    let wanted = q.policy.as_deref().unwrap_or("");
    let selected = policies
        .iter()
        .find(|p| p.name == wanted)
        .or_else(|| policies.first());

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",    "IP Lists");
    ctx.insert("url",      "/iplists");
    // This page lists every policy's entries, so it carries the selector and
    // the search box; a policy's own page includes the same panels without them.
    ctx.insert("show_picker", &true);
    ctx.insert("back",        "");
    ctx.insert("policies", &policies.iter().map(|p| p.name.clone()).collect::<Vec<_>>());
    ctx.insert("result",   &q.result.clone().unwrap_or_default());
    ctx.insert("msg",      &q.msg.clone().unwrap_or_default());

    let search = q.q.as_deref().unwrap_or("").trim().to_string();
    ctx.insert("search", &search);

    let Some(policy) = selected else {
        // Lists belong to a policy, so with none there is nothing to show yet.
        ctx.insert("sel_policy", "");
        ctx.insert("entries",    &Vec::<Entry>::new());
        ctx.insert("allowed",    &0);
        ctx.insert("blocked",    &0);
        ctx.insert("sites",      &Vec::<String>::new());
        ctx.insert("reach",      "");
        ctx.insert("feeds",      &Vec::<crate::iplist_feeds::ListView>::new());
        ctx.insert("feeds_error", "");
        ctx.insert("feeds_fetched", "");
        ctx.insert("feeds_fetch_error", "");
        ctx.insert("feeds_check", &crate::rules_update::enabled(&state.db).await);
        return Ok((jar, Html(state.tera.render("iplists.html", &ctx)?)).into_response());
    };
    let like = format!("%{}%", search);

    // Searched in SQL rather than in the template, so a long list stays one
    // query and the count below matches what is shown.
    let rows = sqlx::query!(
        r#"SELECT id as "id!", ip as "ip!", list_type as "list_type!",
                  reason, added_by, created_at as "created_at!"
           FROM   ip_rules
           WHERE  policy_id = ?1
             AND  (?2 = '' OR ip LIKE ?3 OR COALESCE(reason, '') LIKE ?3)
           ORDER  BY created_at DESC, id DESC"#,
        policy.id, search, like
    )
    .fetch_all(&state.db)
    .await?;

    let entries: Vec<Entry> = rows.into_iter().map(|r| Entry {
        id:         r.id,
        ip:         r.ip,
        list_type:  r.list_type,
        reason:     r.reason,
        added_by:   r.added_by,
        created_at: r.created_at,
    }).collect();

    let allowed = entries.iter().filter(|e| e.list_type == "allow").count();
    let blocked = entries.iter().filter(|e| e.list_type == "block").count();

    // The published lists: what the verified mirror offers, and what this
    // policy has decided about each.
    let (feeds, feeds_error) = crate::iplist_feeds::catalogue(&state.db, policy.id).await;
    let (fetched, fetch_error) = crate::iplist_feeds::status(&state.db).await;
    let sites = super::exclusions::sites_using(&state, policy.id).await?;

    ctx.insert("sel_policy",        &policy.name);
    ctx.insert("entries",           &entries);
    ctx.insert("allowed",           &allowed);
    ctx.insert("blocked",           &blocked);
    ctx.insert("sites",             &sites);
    ctx.insert("reach",             &super::exclusions::reach(&policy.name, &sites));
    ctx.insert("feeds",             &feeds);
    ctx.insert("feeds_error",       &feeds_error.unwrap_or_default());
    ctx.insert("feeds_fetched",     &fetched.map(|t| crate::routes::settings::format_utc(&t)).unwrap_or_default());
    ctx.insert("feeds_fetch_error", &fetch_error.unwrap_or_default());
    ctx.insert("feeds_check",       &crate::rules_update::enabled(&state.db).await);

    Ok((jar, Html(state.tera.render("iplists.html", &ctx)?)).into_response())
}

// ─── post_ip_add ─────────────────────────────────────────

/// POST /iplists/add — put an address on one of a policy's lists.
///
/// An address is on at most one of a policy's lists, so adding one that is
/// already on the other **moves** it rather than failing. That is what the operator means:
/// clicking Allow on something currently blocked is a correction, not a
/// duplicate.
pub async fn post_ip_add(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<AddForm>,
) -> Result<Response> {

    let (policy, policy_name) = match target_policy(
        &state, form.policy.as_deref(), form.host.as_deref()).await? {
        Ok(p) => p,
        Err(msg) => {
            let back = crate::routes::safe_back(form.back.as_deref(), "/iplists");
            return flash_redirect(&back, "failed", &msg);
        }
    };
    let back = crate::routes::safe_back(form.back.as_deref(), &page(&policy_name));
    let ip   = form.ip.trim().to_string();

    // Parsed rather than trusted, even coming from a traffic row: it arrives
    // through a form field like anything else.
    if crate::forwarded::Cidr::parse(&ip).is_none() {
        return flash_redirect(&back, "failed", &format!("\"{ip}\" is not an address or CIDR block"));
    }

    let list_type = match form.list_type.trim() {
        "allow" => "allow",
        "block" => "block",
        other   => {
            return flash_redirect(&back, "failed", &format!("\"{other}\" is not a list"));
        }
    };

    let reason = form.reason.as_deref().unwrap_or("").trim().to_string();
    let reason = if reason.is_empty() { None } else { Some(reason) };

    // What it was on before, so the message can say "moved" rather than
    // "added" when that is what happened.
    let previous: Option<String> = sqlx::query_scalar!(
        "SELECT list_type FROM ip_rules WHERE policy_id = ? AND ip = ?", policy, ip
    )
    .fetch_optional(&state.db)
    .await?;

    sqlx::query!(
        "INSERT INTO ip_rules (policy_id, ip, list_type, reason, added_by)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(policy_id, ip) DO UPDATE SET list_type = excluded.list_type,
                                                  reason    = excluded.reason,
                                                  added_by  = excluded.added_by",
        policy, ip, list_type, reason, session.username
    )
    .execute(&state.db)
    .await?;

    tracing::info!(ip, list_type, policy = %policy_name, by = %session.username,
                   "IP list entry saved");
    let sites = super::exclusions::sites_using(&state, policy).await?;
    let reach = super::exclusions::reach(&policy_name, &sites);

    let msg = match previous.as_deref() {
        Some(was) if was != list_type => format!(
            "{ip} moved from {policy_name}'s {was} list to its {list_type} list"
        ),
        Some(_) => format!("{ip} is already on {policy_name}'s {list_type} list"),
        None if list_type == "block" => format!(
            "{ip} is blocked — it is refused before any rule runs, on {reach}"
        ),
        None => format!(
            "{ip} is allowed — it skips the WAF, the country rules and the challenge, on {reach}"
        ),
    };
    flash_redirect(&back, "success", &msg)
}

// ─── post_ip_remove ──────────────────────────────────────

/// POST /iplists/{id}/remove — take an address off its list.
pub async fn post_ip_remove(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Path(id): Path<i64>,
    Form(form): Form<BackForm>,
) -> Result<Response> {

    let gone = sqlx::query!(
        "DELETE FROM ip_rules WHERE id = ?
         RETURNING ip, list_type, (SELECT name FROM policies p WHERE p.id = policy_id) as \"policy_name?: String\"",
        id
    )
    .fetch_optional(&state.db)
    .await?;

    let Some(gone) = gone else {
        return flash_redirect("/iplists", "failed", "That entry no longer exists");
    };
    let back = crate::routes::safe_back(
        form.back.as_deref(), &page(gone.policy_name.as_deref().unwrap_or("")));

    tracing::info!(ip = %gone.ip, by = %session.username, "IP list entry removed");

    let msg = if gone.list_type == "block" {
        format!("{} is no longer blocked — it is inspected like any other client again", gone.ip)
    } else {
        format!("{} is no longer allowed past the checks — it is inspected again", gone.ip)
    };
    flash_redirect(&back, "success", &msg)
}

// ─── post_feed_save ──────────────────────────────────────

/// POST /iplists/feeds/{id}/save — switch a published list on or off, and say
/// what it does.
pub async fn post_feed_save(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Path(id): Path<String>,
    Form(form): Form<FeedForm>,
) -> Result<Response> {

    let (policy, policy_name) = match target_policy(&state, Some(&form.policy), None).await? {
        Ok(p) => p,
        Err(msg) => return flash_redirect("/iplists", "failed", &msg),
    };
    let back = crate::routes::safe_back(form.back.as_deref(), &page(&policy_name));
    let Some(response) = crate::iplist::Response::parse(&form.response) else {
        return flash_redirect(&back, "failed", &format!("\"{}\" is not a response", form.response));
    };
    let enabled = form.enabled.is_some();

    if let Err(e) = crate::iplist_feeds::save(
        &state.db, policy, &id, enabled, response, &session.username).await
    {
        return flash_redirect(&back, "failed", &e);
    }
    tracing::info!(list = %id, policy = %policy_name, enabled, response = response.as_str(),
                   by = %session.username, "Published IP list saved");

    let sites = super::exclusions::sites_using(&state, policy).await?;
    let reach = super::exclusions::reach(&policy_name, &sites);
    let msg = match (enabled, response) {
        (false, _) => format!("{id} is off for {policy_name} — it changes nothing"),
        (true, crate::iplist::Response::Block) => format!(
            "{id} is on — addresses on it are refused before any rule runs, on {reach}"
        ),
        (true, crate::iplist::Response::Challenge) => format!(
            "{id} is on — addresses on it are asked to solve a CAPTCHA, on {reach}"
        ),
    };
    flash_redirect(&back, "success", &msg)
}

// ─── post_feeds_update ───────────────────────────────────

/// POST /iplists/update — fetch the channel now rather than at the next check.
///
/// Refused while checking the update channels is turned off: that switch is
/// how an installation says it must not reach out at all, and a button that
/// quietly overrode it would make the switch a suggestion.
pub async fn post_feeds_update(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<UpdateForm>,
) -> Result<Response> {

    let back = crate::routes::safe_back(
        form.back.as_deref(), &page(form.policy.as_deref().unwrap_or("")));
    if !crate::rules_update::enabled(&state.db).await {
        return flash_redirect(
            &back,
            "failed",
            "Checking the update channels is turned off under Settings → Rule Updates",
        );
    }

    match crate::iplist_feeds::check_now(&state.db).await {
        Ok(n) => {
            tracing::info!(lists = n, by = %session.username, "Published IP lists updated on request");
            flash_redirect(&back, "success", &format!("Fetched {n} published lists"))
        }
        Err(e) => flash_redirect(&back, "failed", &format!("Could not update the published lists: {e}")),
    }
}

// =========================================================
// routes/policy.rs — EasyWAF
// Security policy management.
// Policies are stored entirely in the DB. The WAF engine
// reads them at inspection time — no config files written.
// =========================================================

use crate::routes::flash_redirect;
use crate::{auth::{Admin, Viewer}, error::{AppError, Result}, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use sqlx::SqlitePool;
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
    /// Country filtering: "off", "block" (deny the list) or "allow" (deny all
    /// but the list).
    pub geoip_mode:          String,
    /// Comma-separated ISO 3166-1 alpha-2 codes the mode applies to.
    pub geoip_countries:     String,
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

// ─── post_apply_rule_update ──────────────────────────────

/// POST /policy/{name}/rules/update/{set_id} — apply one set update.
///
/// One policy and one set at a time, deliberately. An "update everything"
/// button would make a single click change what several sites refuse, and the
/// point of notifying rather than auto-applying is that the decision is small
/// enough to think about.
pub async fn post_apply_rule_update(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path((name, set_id)): Path<(String, String)>,
) -> Result<Response> {

    let policy_id: Option<i64> =
        sqlx::query_scalar!(r#"SELECT id as "id!" FROM policies WHERE name = ?"#, name)
            .fetch_optional(&state.db)
            .await?;

    let Some(policy_id) = policy_id else {
        return flash_redirect("/policy", "failed", "No such policy");
    };

    let back = format!("/policy/{}/rules/sets", urlencoding::encode(&name));

    match crate::rules_update::apply(&state.db, policy_id, &set_id).await {
        Ok(msg) => flash_redirect(&back, "success", &msg),
        // Reported verbatim. A refusal here is a signature that did not verify
        // or content that did not match its hash, and paraphrasing that into
        // "update failed" would hide the one detail worth acting on.
        Err(e)  => flash_redirect(&back, "failed", &format!("Update refused: {e}")),
    }
}

// ─── post_remove_rule_set ────────────────────────────────

/// POST /policy/{name}/rules/remove/{set_id} — take a set out of a policy.
///
/// This removes protection, so it says exactly what it did: how many rules
/// went, and how many of your own were kept. "Removed" on its own would leave
/// someone wondering whether their custom rules went with it.
pub async fn post_remove_rule_set(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path((name, set_id)): Path<(String, String)>,
) -> Result<Response> {

    let policy_id: Option<i64> =
        sqlx::query_scalar!(r#"SELECT id as "id!" FROM policies WHERE name = ?"#, name)
            .fetch_optional(&state.db)
            .await?;
    let Some(policy_id) = policy_id else {
        return flash_redirect("/policy", "failed", "No such policy");
    };

    let back = format!("/policy/{}/rules/sets", urlencoding::encode(&name));

    let (removed, clones) =
        crate::routes::rules::uninstall_set(&state.db, policy_id, &set_id).await?;

    if removed == 0 && clones == 0 {
        return flash_redirect(&back, "failed", &format!("{set_id} was not installed"));
    }

    let msg = match clones {
        0 => format!("Removed {set_id} — {removed} rules deleted"),
        1 => format!(
            "Removed {set_id} — {removed} rules deleted, 1 rule you cloned from it kept"
        ),
        n => format!(
            "Removed {set_id} — {removed} rules deleted, {n} rules you cloned from it kept"
        ),
    };
    flash_redirect(&back, "success", &msg)
}

// ─── get_rule_sets ───────────────────────────────────────

/// GET /policy/{name}/rules/sets — every rule set the channel offers, and what
/// this policy has of each.
///
/// One page for installing a set, updating one, and seeing what is already
/// enforcing. Those were three different things before: updates appeared as a
/// notice on the policy list, installing came from whatever files happened to
/// be in `rules/` on disk, and a published set nobody had installed could not
/// be found at all.
pub async fn get_rule_sets(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Path(name): Path<String>,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {

    let policy_id: Option<i64> =
        sqlx::query_scalar!(r#"SELECT id as "id!" FROM policies WHERE name = ?"#, name)
            .fetch_optional(&state.db)
            .await?;
    let Some(policy_id) = policy_id else {
        return flash_redirect("/policy", "failed", "No such policy");
    };

    let sets = crate::rules_update::catalog(&state.db, policy_id).await?;
    let (checked, error) = crate::rules_update::status(&state.db).await;

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",       "Rule Sets");
    ctx.insert("url",         "/policy");
    ctx.insert("policy_name", &name);
    ctx.insert("sets",        &sets);
    // An empty list means one of two very different things — the channel has
    // never been reached, or it genuinely offers nothing — and the page has to
    // say which.
    ctx.insert("checked",       &checked.unwrap_or_default());
    ctx.insert("check_error",   &error.unwrap_or_default());
    ctx.insert("update_count",  &sets.iter().filter(|s| s.status == "update").count());
    ctx.insert("channel",       &crate::rules_update::url(&state.db).await);
    ctx.insert("result",        &flash.result.unwrap_or_default());
    ctx.insert("msg",           &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("policy_rule_sets.html", &ctx)?)).into_response())
}

// ─── get_policies ────────────────────────────────────────

pub async fn get_policies(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {

    let policies = fetch_policies(&state).await?;

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",     "Policy Manager");
    ctx.insert("url",       "/policy");
    ctx.insert("policies",  &policies);

    // Shown where policies are, because an update applies to a policy rather
    // than to the installation — "SQLi 3 is available; this policy has 2".
    let updates = crate::rules_update::available(&state.db).await?;
    let (fetched, error) = crate::rules_update::status(&state.db).await;
    ctx.insert("rule_updates",       &updates);
    ctx.insert("rule_check_fetched", &fetched);
    ctx.insert("rule_check_error",   &error);
    ctx.insert("result",    &flash.result.unwrap_or_default());
    ctx.insert("msg",       &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("policy.html", &ctx)?)).into_response())
}

// ─── get_policy_new ──────────────────────────────────────

pub async fn get_policy_new(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
) -> Result<Response> {

    // Load the full rule catalog with nothing pre-checked (new policy).
    let catalog = crate::routes::rules::read_catalog_categories(
        &crate::routes::rules::Held::default())?;
    let total_available: usize = catalog.iter().map(|c| c.total).sum();

    // The catalog above is read from the downloaded mirror, so it already
    // holds every set the channel publishes, optional ones included. What the
    // channel could not deliver is still worth saying here: with no successful
    // fetch the list is the bundle, which is the basic sets and nothing else,
    // and an optional set is then missing rather than absent.
    let (checked, check_error) = crate::rules_update::status(&state.db).await;

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",           "Create Policy");
    ctx.insert("url",             "/policy");
    ctx.insert("catalog",         &catalog);
    ctx.insert("total_available", &total_available);
    ctx.insert("check_error",     &check_error.unwrap_or_default());
    ctx.insert("checked",         &checked.unwrap_or_default());

    // Everything else a policy holds, so one can be set up in a single pass
    // rather than across four pages afterwards.
    ctx.insert("policies", &fetch_policies(&state).await?);
    // What the published channel offers. Policy ids start at 1, so nothing is
    // stored against 0: every list reads as off, with the publisher's
    // suggestion selected.
    let (lists, lists_error) = crate::iplist_feeds::catalogue(
        &state.db, crate::iplist_feeds::Scope::Policy(0)).await;
    // What the new policy will be subject to whatever is chosen here.
    let (all_mode, all_countries) = crate::routes::geoip::everywhere(&state).await?;
    ctx.insert("all_geoip_mode",      &all_mode);
    ctx.insert("all_geoip_countries", &all_countries);
    // And how the channel itself is doing, so a list chosen here is not chosen
    // blind: an installation that has never reached the channel, or whose last
    // fetch failed, says so before anything is switched on.
    let (fetched, fetch_error) = crate::iplist_feeds::status(&state.db).await;
    ctx.insert("lists",            &lists);
    ctx.insert("lists_error",      &lists_error.unwrap_or_default());
    ctx.insert("lists_fetched",    &fetched.map(|t| crate::routes::settings::format_utc(&t)).unwrap_or_default());
    ctx.insert("lists_fetch_error", &fetch_error.unwrap_or_default());

    Ok((jar, Html(state.tera.render("policy_create.html", &ctx)?)).into_response())
}

// ─── post_policy_create ──────────────────────────────────

pub async fn post_policy_create(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(raw): Form<HashMap<String, String>>,
) -> Result<Response> {

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

    let geoip_mode = match raw.get("geoip_mode").map(String::as_str) {
        Some("block") => "block",
        Some("allow") => "allow",
        _             => "off",
    };
    let geoip_countries =
        normalize_countries(raw.get("geoip_countries").map(String::as_str).unwrap_or(""));

    let insert = sqlx::query!(
        "INSERT INTO policies (name, rule_engine, score_threshold, challenge_threshold,
                               geoip_mode, geoip_countries)
         VALUES (?, ?, ?, ?, ?, ?)",
        name, rule_engine, score_threshold, challenge_threshold,
        geoip_mode, geoip_countries,
    )
    .execute(&state.db)
    .await?;

    let policy_id = insert.last_insert_rowid();

    // What else the new policy is given, in the order the form asks for it.
    // Each part reports what it did, so the one message after a create says
    // what the policy actually holds rather than only that it exists.
    let mut extras: Vec<String> = Vec::new();
    let mut refused: Vec<String> = Vec::new();

    // Copied from an existing policy first, so anything chosen below lands on
    // top of the copy rather than under it.
    let copy_from = raw.get("copy_from").map(|s| s.trim()).unwrap_or("");
    if !copy_from.is_empty() {
        match copy_policy(&state.db, copy_from, policy_id).await? {
            None => refused.push(format!("there is no policy named {copy_from} to copy")),
            Some(c) => {
                extras.push(c.describe(copy_from));
                if c.custom_exclusions > 0 {
                    refused.push(format!(
                        "{} exclusion(s) naming a custom rule were not copied — a custom \
                         rule belongs to the policy that holds it, so the copy would point \
                         at the original",
                        c.custom_exclusions
                    ));
                }
            }
        }
    }

    // IP lists, as typed: one address or block per line.
    for (field, list_type) in [("ip_block", "block"), ("ip_allow", "allow")] {
        let (addresses, bad) = parse_addresses(raw.get(field).map(String::as_str).unwrap_or(""));
        let reason = "Added when the policy was created";
        let mut added = 0usize;
        for ip in &addresses {
            let done = sqlx::query!(
                "INSERT INTO ip_rules (policy_id, ip, list_type, reason, added_by)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(policy_id, ip) WHERE policy_id IS NOT NULL
                 DO UPDATE SET list_type = excluded.list_type",
                policy_id, ip, list_type, reason, session.username
            )
            .execute(&state.db)
            .await;
            if done.is_ok() {
                added += 1;
            }
        }
        if added > 0 {
            extras.push(format!("{added} address(es) on the {list_type} list"));
        }
        if !bad.is_empty() {
            refused.push(format!(
                "these are not addresses or blocks, so they are not on the {list_type} \
                 list: {}", bad.join(", ")
            ));
        }
    }

    // Published lists: one field per list, off unless a response was chosen.
    //
    // Only lists the channel actually offers. A field naming anything else
    // would store a decision about a list that does not exist, which reads on
    // the IP Lists page as one that has been withdrawn.
    let (offered, _) = crate::iplist_feeds::catalogue(
        &state.db, crate::iplist_feeds::Scope::Policy(0)).await;
    let mut lists_on = 0usize;
    for (key, value) in raw.iter() {
        let Some(id) = key.strip_prefix("list:") else { continue };
        let Some(response) = crate::iplist::Response::parse(value) else { continue };
        if !offered.iter().any(|l| l.id == id) {
            refused.push(format!("there is no published list called {id}"));
            continue;
        }
        if crate::iplist_feeds::save(
            &state.db, crate::iplist_feeds::Scope::Policy(policy_id), id, true,
            response, &session.username).await.is_ok()
        {
            lists_on += 1;
        }
    }
    if lists_on > 0 {
        extras.push(format!("{lists_on} published list(s) switched on"));
    }

    // Insert any rules the user selected in the catalog (comma-separated ids).
    let ids: HashSet<i64> = raw.get("ids")
        .map(|s| s.split(',').filter_map(|p| p.trim().parse::<i64>().ok()).collect())
        .unwrap_or_default();

    let added = crate::routes::rules::add_rules_by_external_ids(&state, policy_id, &ids).await?;

    // Sets chosen on the form, installed through the same verified path the
    // Rule Sets page uses — signature before anything is read, hash before
    // anything is written. Nothing is trusted more for arriving during
    // creation.
    //
    // A set that fails is reported and the policy still exists. Discarding a
    // policy because one set could not be fetched would throw away the part
    // that succeeded, and the fix is to press Install again rather than to
    // fill the form in twice.
    let mut installed = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let chosen: Vec<String> = raw
        .get("set_ids")
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    for set_id in chosen {
        match crate::rules_update::apply(&state.db, policy_id, &set_id).await {
            Ok(_)  => installed += 1,
            Err(e) => failed.push(format!("{set_id} ({e})")),
        }
    }

    // Said in one line each, appended to whichever sentence the rules produce.
    let mut tail = String::new();
    if !extras.is_empty() {
        tail.push_str(&format!(", with {}", extras.join(", ")));
    }
    for note in &refused {
        tail.push_str(&format!(". Note: {note}"));
    }
    if !failed.is_empty() {
        tail.push_str(&format!(
            ". These rule sets could not be installed: {}. Install them from the \
             policy's Rule Sets page.", failed.join("; ")));
    }

    // Success even with a note: the policy was created, and colouring that red
    // would say it was not. What was refused is named in the same message.
    flash_redirect(
        "/policy",
        "success",
        &format!("{}{tail}", match (installed, added.total()) {
            // Nothing chosen is a legitimate thing to do and a bad thing to do
            // by accident, so it says what the policy is rather than reporting
            // a count of zero and leaving the reader to work it out.
            (0, 0) if extras.is_empty() => format!(
                "Policy {name} created with no rules — it will inspect nothing until \
                 you add rule sets from its Rule Sets page"
            ),
            (0, 0) => format!("Policy {name} created"),
            (0, a) => format!("Policy {name} created with {a} rule(s)"),
            (i, 0) => format!("Policy {name} created with {i} rule set(s)"),
            (i, a) => format!("Policy {name} created with {i} rule set(s) and {a} further rule(s)"),
        }),
    )
}

// ─── Setting a new policy up ─────────────────────────────

/// What copying an existing policy brought across.
#[derive(Debug, Default, PartialEq)]
struct Copied {
    rules:      u64,
    sets:       u64,
    exclusions: u64,
    addresses:  u64,
    lists:      u64,
    /// Exclusions naming a custom rule, which cannot be copied: the rule row
    /// they name belongs to the policy being copied from.
    custom_exclusions: u64,
}

impl Copied {
    fn describe(&self, from: &str) -> String {
        let mut parts = Vec::new();
        if self.rules > 0      { parts.push(format!("{} rule(s)", self.rules)) }
        if self.sets > 0       { parts.push(format!("{} installed set(s)", self.sets)) }
        if self.exclusions > 0 { parts.push(format!("{} exclusion(s)", self.exclusions)) }
        if self.addresses > 0  { parts.push(format!("{} listed address(es)", self.addresses)) }
        if self.lists > 0      { parts.push(format!("{} published list choice(s)", self.lists)) }
        if parts.is_empty() {
            format!("nothing to copy from {from}")
        } else {
            format!("{} copied from {from}", parts.join(", "))
        }
    }
}

/// Copy everything one policy holds into another, newly created one.
///
/// Rules, the record of which sets are installed, exclusions, IP list entries,
/// published-list choices and country rules — so "like that one, but for this
/// application" is one choice rather than an afternoon of re-entering.
///
/// Returns `None` when there is no such policy to copy.
async fn copy_policy(db: &SqlitePool, from: &str, into: i64) -> Result<Option<Copied>> {
    let Some(src) = sqlx::query_scalar!("SELECT id FROM policies WHERE name = ?", from)
        .fetch_optional(db)
        .await?
        .flatten()
    else {
        return Ok(None);
    };

    let rules = sqlx::query!(
        "INSERT INTO waf_rules (policy_id, name, description, zone, pattern, score, action,
                                enabled, external_id, imported_pattern, imported_score,
                                imported_action, rule_set, cloned_from_external_id,
                                cloned_from_version, cloned_from_set)
         SELECT ?, name, description, zone, pattern, score, action,
                enabled, external_id, imported_pattern, imported_score,
                imported_action, rule_set, cloned_from_external_id,
                cloned_from_version, cloned_from_set
         FROM   waf_rules WHERE policy_id = ?",
        into, src
    )
    .execute(db).await?.rows_affected();

    let sets = sqlx::query!(
        "INSERT INTO policy_rule_sets (policy_id, set_id, name, version)
         SELECT ?, set_id, name, version FROM policy_rule_sets WHERE policy_id = ?",
        into, src
    )
    .execute(db).await?.rows_affected();

    // Only exclusions naming a catalogue rule. One naming a custom rule points
    // at a row belonging to the source policy, and copying it would silence a
    // rule in the wrong place — or nothing at all.
    let exclusions = sqlx::query!(
        "INSERT INTO policy_rule_exclusions
                (policy_id, external_id, rule_id, path_prefix, client_cidr, note)
         SELECT ?, external_id, NULL, path_prefix, client_cidr, note
         FROM   policy_rule_exclusions
         WHERE  policy_id = ? AND external_id IS NOT NULL",
        into, src
    )
    .execute(db).await?.rows_affected();

    let custom_exclusions = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "n!" FROM policy_rule_exclusions
           WHERE policy_id = ? AND rule_id IS NOT NULL"#,
        src
    )
    .fetch_one(db).await? as u64;

    let addresses = sqlx::query!(
        "INSERT INTO ip_rules (policy_id, ip, list_type, reason, added_by)
         SELECT ?, ip, list_type, reason, added_by FROM ip_rules WHERE policy_id = ?",
        into, src
    )
    .execute(db).await?.rows_affected();

    let lists = sqlx::query!(
        "INSERT INTO ip_list_feeds (policy_id, id, enabled, response, changed_by)
         SELECT ?, id, enabled, response, changed_by FROM ip_list_feeds WHERE policy_id = ?",
        into, src
    )
    .execute(db).await?.rows_affected();

    // Country rules come with it. A form that named countries of its own
    // overwrites these below, which is the order the page presents them in.
    sqlx::query!(
        "UPDATE policies SET geoip_mode = (SELECT geoip_mode FROM policies WHERE id = ?),
                             geoip_countries = (SELECT geoip_countries FROM policies WHERE id = ?)
         WHERE id = ? AND geoip_mode = 'off'",
        src, src, into
    )
    .execute(db).await?;

    let c = Copied { rules, sets, exclusions, addresses, lists, custom_exclusions };
    Ok(Some(c))
}

/// Read an address list as typed: one address or CIDR block per line, with
/// anything after `#` a comment.
///
/// Returns the addresses and the lines that are not addresses, so the message
/// can name what was refused instead of dropping it quietly.
fn parse_addresses(raw: &str) -> (Vec<String>, Vec<String>) {
    let mut good = Vec::new();
    let mut bad = Vec::new();
    for line in raw.lines() {
        let entry = line.split('#').next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        match crate::forwarded::Cidr::parse(entry) {
            Some(_) => good.push(entry.to_string()),
            None    => bad.push(entry.to_string()),
        }
    }
    (good, bad)
}

// ─── get_policy_edit ─────────────────────────────────────

/// The policy page's own query: a flash, and which tab to open — so an action
/// taken on a tab comes back to it rather than to the first one.
#[derive(Debug, serde::Deserialize)]
pub struct PolicyEditQuery {
    pub result: Option<String>,
    pub msg:    Option<String>,
    pub tab:    Option<String>,
}

pub async fn get_policy_edit(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Path(name): Path<String>,
    Query(flash): Query<PolicyEditQuery>,
) -> Result<Response> {

    let policy = fetch_policy(&state, &name).await?;
    let policy_id: i64 = sqlx::query_scalar!(
        r#"SELECT id as "id!" FROM policies WHERE name = ?"#, name
    )
    .fetch_one(&state.db)
    .await?;
    let back = format!("/policy/{}/edit", name);
    // Which tab the page opens on. Only the names it has, so a query cannot
    // ask for anything else.
    let tab = match flash.tab.as_deref() {
        Some(t @ ("rules" | "countries" | "iplists" | "exclusions")) => t,
        _ => "policy",
    };

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",    "Policy Settings");
    ctx.insert("url",      "/policy");
    ctx.insert("policy",   &policy);
    ctx.insert("back",     &back);
    ctx.insert("tab",      tab);
    // Each panel returns to its own tab, so an address added on IP Lists does
    // not come back on Policy with nothing to show for it.
    ctx.insert("back_iplists",    &format!("{back}?tab=iplists"));
    ctx.insert("back_exclusions", &format!("{back}?tab=exclusions"));
    // The panels below are the same ones the IP Lists and Rule Exclusions
    // pages show. Here the policy is already decided, so they come without
    // the selector and the search box those pages carry.
    ctx.insert("show_picker", &false);
    ctx.insert("sel_policy",  &policy.name);
    ctx.insert("policies",    &Vec::<String>::new());
    ctx.insert("search",      "");

    // What is installed, and what could still be added — the same catalogue
    // the create page offers, with what this policy already holds ticked and
    // left alone.
    let held = crate::routes::rules::held(&state.db, policy_id).await?;
    let counts = sqlx::query!(
        r#"SELECT COUNT(*) as "all!", COALESCE(SUM(enabled), 0) as "on!: i64"
           FROM waf_rules WHERE policy_id = ?"#,
        policy_id
    )
    .fetch_one(&state.db)
    .await?;
    ctx.insert("rule_count",    &counts.all);
    ctx.insert("enabled_count", &counts.on);

    let catalog = crate::routes::rules::read_catalog_categories(&held)?;
    ctx.insert("total_available", &catalog.iter().map(|c| c.total).sum::<usize>());
    ctx.insert("catalog", &catalog);
    let (checked, check_error) = crate::rules_update::status(&state.db).await;
    ctx.insert("check_error", &check_error.unwrap_or_default());
    ctx.insert("checked",     &checked.unwrap_or_default());

    // Its IP lists, its published lists, and its exclusions.
    let rows = sqlx::query!(
        r#"SELECT id as "id!", ip as "ip!", list_type as "list_type!",
                  reason, added_by, created_at as "created_at!"
           FROM   ip_rules WHERE policy_id = ?
           ORDER  BY created_at DESC, id DESC"#,
        policy_id
    )
    .fetch_all(&state.db)
    .await?;
    let entries: Vec<crate::routes::iplists::Entry> = rows.into_iter()
        .map(|r| crate::routes::iplists::Entry {
            id: r.id, ip: r.ip, list_type: r.list_type, reason: r.reason,
            added_by: r.added_by, created_at: r.created_at,
        })
        .collect();
    ctx.insert("allowed", &entries.iter().filter(|e| e.list_type == "allow").count());
    ctx.insert("blocked", &entries.iter().filter(|e| e.list_type == "block").count());
    ctx.insert("entries", &entries);

    let (feeds, feeds_error) = crate::iplist_feeds::catalogue(
        &state.db, crate::iplist_feeds::Scope::Policy(policy_id)).await;
    let (all_mode, all_countries) = crate::routes::geoip::everywhere(&state).await?;
    ctx.insert("all_geoip_mode",      &all_mode);
    ctx.insert("all_geoip_countries", &all_countries);
    let (fetched, fetch_error) = crate::iplist_feeds::status(&state.db).await;
    let shared = sqlx::query!(
        r#"SELECT id as "id!", ip as "ip!", list_type as "list_type!",
                  reason, added_by, created_at as "created_at!"
           FROM   ip_rules WHERE policy_id IS NULL
           ORDER  BY created_at DESC, id DESC"#
    )
    .fetch_all(&state.db)
    .await?;
    ctx.insert("shared", &shared.into_iter().map(|r| serde_json::json!({
        "id": r.id, "ip": r.ip, "list_type": r.list_type, "reason": r.reason,
        "added_by": r.added_by, "created_at": r.created_at })).collect::<Vec<_>>());
    ctx.insert("feeds",             &feeds);
    ctx.insert("feeds_error",       &feeds_error.unwrap_or_default());
    ctx.insert("feeds_fetched",     &fetched.map(|t| crate::routes::settings::format_utc(&t)).unwrap_or_default());
    ctx.insert("feeds_fetch_error", &fetch_error.unwrap_or_default());
    ctx.insert("feeds_check",       &crate::rules_update::enabled(&state.db).await);

    ctx.insert("exclusions", &crate::routes::exclusions::list(&state, Some(policy_id)).await?);
    ctx.insert("candidates", &crate::routes::exclusions::candidates_for(&state, policy_id).await?);

    let sites = crate::routes::exclusions::sites_using(&state, policy_id).await?;
    ctx.insert("reach", &crate::routes::exclusions::reach(&policy.name, &sites));
    ctx.insert("sites", &sites);

    ctx.insert("result", &flash.result.unwrap_or_default());
    ctx.insert("msg",    &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("policy_settings.html", &ctx)?)).into_response())
}

// ─── post_policy_setup ───────────────────────────────────

/// Add rule sets and rules to a policy that already exists.
///
/// The same choice the create page offers, on the page that edits one, and
/// through the same verified path: a set's signature is checked before
/// anything is read and its hash before anything is written.
pub async fn post_policy_setup(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path(name): Path<String>,
    Form(raw): Form<HashMap<String, String>>,
) -> Result<Response> {

    let back = format!("/policy/{name}/edit?tab=rules");
    let policy_id: i64 = sqlx::query_scalar!(
        r#"SELECT id as "id!" FROM policies WHERE name = ?"#, name
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Policy '{name}' not found")))?;

    let list = |field: &str| -> HashSet<i64> {
        raw.get(field)
            .map(|s| s.split(',').filter_map(|p| p.trim().parse::<i64>().ok()).collect())
            .unwrap_or_default()
    };
    let ids = list("ids");
    let off = list("off_ids");

    let added = crate::routes::rules::add_rules_by_external_ids(&state, policy_id, &ids).await?;

    // Unticking a rule the policy holds switches it off rather than deleting
    // it: that is what survives the next update of its set, which would insert
    // a deleted rule again and start matching on it with nobody told.
    let switched_off =
        crate::routes::rules::switch_off_by_external_ids(&state.db, policy_id, &off).await?;

    let mut installed = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for set_id in raw.get("set_ids").map(String::as_str).unwrap_or("")
        .split(',').map(str::trim).filter(|s| !s.is_empty())
    {
        match crate::rules_update::apply(&state.db, policy_id, set_id).await {
            Ok(_)  => installed += 1,
            Err(e) => failed.push(format!("{set_id} ({e})")),
        }
    }

    // Each thing that happened, named, because a page that reports only what it
    // added leaves somebody who unticked a rule wondering whether it took.
    let mut did: Vec<String> = Vec::new();
    if installed > 0 {
        did.push(format!("{installed} rule set(s) installed"));
    }
    if added.inserted > 0 {
        did.push(format!("{} rule(s) added", added.inserted));
    }
    if added.switched_on > 0 {
        did.push(format!("{} rule(s) switched back on", added.switched_on));
    }
    if switched_off > 0 {
        did.push(format!("{switched_off} rule(s) switched off"));
    }

    // "Nothing happened" has more than one cause and they are not the same
    // thing to read: nothing was ticked, everything ticked was already here, or
    // a set was chosen and refused.
    let msg = if !did.is_empty() {
        format!("{} in {name}", did.join(", "))
    } else if !failed.is_empty() {
        format!("Nothing was changed in {name}")
    } else if ids.is_empty() && off.is_empty() {
        "Nothing selected, so nothing was changed".to_string()
    } else {
        format!(
            "Nothing new — {} rule(s) selected, and {name} already holds every one",
            ids.len()
        )
    };
    if failed.is_empty() {
        flash_redirect(&back, "success", &msg)
    } else {
        // A set is fetched and verified from the signed channel, so a failure
        // here is usually the channel rather than the set: say so, and say
        // what still works without it.
        flash_redirect(&back, "failed", &format!(
            "{msg}. These rule sets could not be installed: {}. A set comes from the \
             signed channel — check Settings → Rule Updates, or tick individual rules, \
             which are read from this installation's own copy.",
            failed.join("; ")))
    }
}

// ─── post_policy_update ──────────────────────────────────

pub async fn post_policy_update(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path(name): Path<String>,
    Form(raw): Form<HashMap<String, String>>,
) -> Result<Response> {

    // Only what the form actually sent. The policy's settings are edited from
    // two tabs — its mode and thresholds on one, its country rules on another
    // — and forms cannot be nested, so each posts on its own. Writing every
    // column from every post would make saving one tab reset the other.
    let back = crate::routes::safe_back(raw.get("back").map(String::as_str), "/policy");

    if raw.contains_key("rule_engine") {
        let rule_engine = raw.get("rule_engine").cloned().unwrap_or_else(|| "DetectionOnly".into());
        let score_threshold: i64 = raw.get("score_threshold")
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        let challenge_threshold: i64 = raw.get("challenge_threshold")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        sqlx::query!(
            "UPDATE policies SET rule_engine=?, score_threshold=?, challenge_threshold=?
             WHERE name=?",
            rule_engine, score_threshold, challenge_threshold, name,
        )
        .execute(&state.db)
        .await?;
    }

    if raw.contains_key("geoip_mode") {
        let geoip_mode = match raw.get("geoip_mode").map(String::as_str) {
            Some("block") => "block",
            Some("allow") => "allow",
            _             => "off",
        };
        // Stored normalised, so the module never has to guess at the formatting
        // a person typed and the field reads back tidily in the form.
        let geoip_countries =
            normalize_countries(raw.get("geoip_countries").map(String::as_str).unwrap_or(""));
        sqlx::query!(
            "UPDATE policies SET geoip_mode=?, geoip_countries=? WHERE name=?",
            geoip_mode, geoip_countries, name,
        )
        .execute(&state.db)
        .await?;
    }

    flash_redirect(&back, "success", &format!("Policy {} updated successfully", name))
}

// ─── post_policy_delete ──────────────────────────────────

pub async fn post_policy_delete(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path(name): Path<String>,
) -> Result<Response> {

    // `sites.waf_policy_id` is ON DELETE SET NULL and sqlx enables foreign keys,
    // so deleting a policy in use silently unsets it on every site that had it.
    // Those sites keep serving — they simply stop being inspected. Nothing
    // fails, nothing 500s, no page looks different; the WAF is just gone.
    //
    // That is the worst shape a mistake can take here, because the symptom of
    // having no protection is indistinguishable from having protection that
    // nothing has attacked yet. Refused rather than warned about.
    let in_use: Vec<String> = sqlx::query_scalar!(
        r#"SELECT s.name as "name!" FROM sites s
           JOIN policies p ON p.id = s.waf_policy_id
           WHERE p.name = ? ORDER BY s.name"#,
        name
    )
    .fetch_all(&state.db)
    .await?;

    if !in_use.is_empty() {
        return flash_redirect(
            "/policy",
            "failed",
            &format!(
                "'{}' is in use by {}: {}. Assign a different policy there first — \
                 deleting it would leave {} with no WAF inspection at all.",
                name,
                if in_use.len() == 1 { "one site" } else { "these sites" },
                in_use.join(", "),
                if in_use.len() == 1 { "it" } else { "them" },
            ),
        );
    }

    let deleted = sqlx::query!("DELETE FROM policies WHERE name = ?", name)
        .execute(&state.db)
        .await?
        .rows_affected();

    if deleted == 0 {
        return flash_redirect("/policy", "failed", &format!("No policy named '{name}'"));
    }

    flash_redirect("/policy", "success", &format!("Policy {} deleted successfully", name))
}

// ─── normalize_countries ─────────────────────────────────

/// Tidy a typed country list into comma-separated upper-case ISO codes.
///
/// Commas, spaces and newlines all separate, since that is how a list actually
/// gets pasted. Entries that are not two letters are dropped rather than
/// stored: a code that can never match would look like a working rule that
/// silently does nothing. Duplicates are removed so the field reads back clean.
pub fn normalize_countries(raw: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let code = part.trim().to_uppercase();
        if code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()) && !out.contains(&code) {
            out.push(code);
        }
    }
    out.join(",")
}

// ─── Helpers ─────────────────────────────────────────────

/// Every policy with its rule counts and country settings.
/// Public so the country-rules overview page can list them too.
pub async fn list_policies(state: &AppState) -> Result<Vec<Policy>> {
    fetch_policies(state).await
}

async fn fetch_policies(state: &AppState) -> Result<Vec<Policy>> {
    // LEFT JOIN so policies with no rules still appear, with counts of 0.
    let rows = sqlx::query!(
        "SELECT p.id          as \"id!\",
                p.name,
                p.rule_engine,
                p.score_threshold     as \"score_threshold!\",
                p.challenge_threshold as \"challenge_threshold!\",
                p.geoip_mode          as \"geoip_mode!\",
                p.geoip_countries     as \"geoip_countries!\",
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
        geoip_mode:          r.geoip_mode,
        geoip_countries:     r.geoip_countries,
        rule_count:          r.rule_count,
        enabled_count:       r.enabled_count,
    }).collect())
}

async fn fetch_policy(state: &AppState, name: &str) -> Result<Policy> {
    let r = sqlx::query!(
        "SELECT id as \"id!\", name, rule_engine,
                score_threshold     as \"score_threshold!\",
                challenge_threshold as \"challenge_threshold!\",
                geoip_mode          as \"geoip_mode!\",
                geoip_countries     as \"geoip_countries!\"
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
        geoip_mode:          r.geoip_mode,
        geoip_countries:     r.geoip_countries,
        // Counts are not shown on the single-policy edit page.
        rule_count:          0,
        enabled_count:       0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_list_is_read_as_typed() {
        let (good, bad) = parse_addresses(
            "203.0.113.9\n  198.51.100.0/24  # the office\n\n2001:db8::/32\n# a whole comment\n",
        );
        assert_eq!(good, ["203.0.113.9", "198.51.100.0/24", "2001:db8::/32"]);
        assert!(bad.is_empty());
    }

    #[test]
    fn what_is_not_an_address_is_reported_rather_than_dropped() {
        // Silently ignoring a line is how somebody ends up believing an
        // address is blocked when it is not.
        let (good, bad) = parse_addresses("203.0.113.9\nnot-an-address\n999.1.1.1\nexample.com\n");
        assert_eq!(good, ["203.0.113.9"]);
        assert_eq!(bad, ["not-an-address", "999.1.1.1", "example.com"]);
    }

    #[test]
    fn a_copy_says_what_it_brought() {
        let c = Copied { rules: 99, sets: 8, exclusions: 2, addresses: 3, lists: 1,
                         custom_exclusions: 0 };
        let said = c.describe("websites");
        for part in ["99 rule(s)", "8 installed set(s)", "2 exclusion(s)",
                     "3 listed address(es)", "1 published list choice(s)", "from websites"] {
            assert!(said.contains(part), "{part} missing from: {said}");
        }
        assert_eq!(Copied::default().describe("empty"), "nothing to copy from empty");
    }

    /// The copy is the risky half of setting a policy up from another one: it
    /// writes rows into a policy that is about to protect real sites, so what
    /// it carries and what it refuses to carry are both checked against a real
    /// database rather than reasoned about.
    #[tokio::test]
    async fn copying_a_policy_brings_everything_a_policy_holds() {
        let path = std::env::temp_dir()
            .join(format!("easywaf-copy-{}.db", std::process::id()));
        for sfx in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", path.display()));
        }
        let db = crate::db::init(&format!("sqlite://{}", path.display())).await;

        sqlx::raw_sql(
            "INSERT INTO policies (name, rule_engine, geoip_mode, geoip_countries)
                 VALUES ('websites', 'On', 'block', 'CN,RU');
             INSERT INTO policies (name) VALUES ('new');
             INSERT INTO waf_rules (policy_id, name, pattern, external_id)
                 VALUES ((SELECT id FROM policies WHERE name='websites'), 'sqli', 'x', 942100);
             INSERT INTO waf_rules (policy_id, name, pattern)
                 VALUES ((SELECT id FROM policies WHERE name='websites'), 'mine', 'y');
             INSERT INTO policy_rule_sets (policy_id, set_id, version)
                 VALUES ((SELECT id FROM policies WHERE name='websites'), 'owasp-sqli', 2);
             INSERT INTO policy_rule_exclusions (policy_id, external_id, path_prefix)
                 VALUES ((SELECT id FROM policies WHERE name='websites'), 942100, '/dav');
             INSERT INTO policy_rule_exclusions (policy_id, rule_id, path_prefix)
                 VALUES ((SELECT id FROM policies WHERE name='websites'),
                         (SELECT id FROM waf_rules WHERE name='mine'), '');
             INSERT INTO ip_rules (policy_id, ip, list_type)
                 VALUES ((SELECT id FROM policies WHERE name='websites'), '203.0.113.9', 'block');
             INSERT INTO ip_list_feeds (policy_id, id, enabled, response)
                 VALUES ((SELECT id FROM policies WHERE name='websites'), 'tor-exits', 1, 'challenge');",
        )
        .execute(&db)
        .await
        .expect("seed");

        let into: i64 = sqlx::query_scalar("SELECT id FROM policies WHERE name = 'new'")
            .fetch_one(&db).await.unwrap();
        let copied = copy_policy(&db, "websites", into).await.unwrap().expect("policy exists");

        assert_eq!(copied.rules, 2, "both rules");
        assert_eq!(copied.sets, 1);
        assert_eq!(copied.addresses, 1);
        assert_eq!(copied.lists, 1);
        // The catalogue exclusion comes; the one naming a custom rule cannot,
        // because that rule row belongs to the policy it was written in.
        assert_eq!(copied.exclusions, 1);
        assert_eq!(copied.custom_exclusions, 1);
        let dangling: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM policy_rule_exclusions e JOIN waf_rules r ON r.id = e.rule_id
             WHERE e.policy_id = ?1 AND r.policy_id <> ?1")
            .bind(into).fetch_one(&db).await.unwrap();
        assert_eq!(dangling, 0, "an exclusion points at another policy's rule");

        // Country rules come with it, onto a policy that had none.
        let geo: (String, String) = sqlx::query_as(
            "SELECT geoip_mode, geoip_countries FROM policies WHERE id = ?")
            .bind(into).fetch_one(&db).await.unwrap();
        assert_eq!(geo, ("block".to_string(), "CN,RU".to_string()));

        // And a name that is not a policy is refused rather than half-applied.
        assert!(copy_policy(&db, "nonesuch", into).await.unwrap().is_none());

        db.close().await;
        for sfx in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", path.display()));
        }
    }
}


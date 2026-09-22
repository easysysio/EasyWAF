// =========================================================
// routes/updates.rs — EasyWAF
// Everything that arrives from outside, in one place.
//
// Three kinds — rule sets, published IP lists, the country
// database — which were configured in a panel named after
// one of them, shown on three different pages, and in the
// country database's case not shown at all.
//
// Two stages, and the page says which is which: a fetch
// fills the verified mirror; applying is what puts something
// in force. Data applies itself, because its value is its
// freshness; rule sets wait for an administrator, because a
// new pattern can refuse traffic that was fine yesterday.
// See docs/design/updates.md.
// =========================================================

use crate::routes::{flash_redirect, settings::{get_setting, set_setting}};
use crate::{auth::{Admin, Viewer}, error::Result, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;
use std::collections::HashMap;
use tera::Context;

/// Settings keys owned by this page.
///
/// Whether each kind is applied as it arrives. The first two default to on:
/// a list and a country database are data, and stale data is the failure they
/// have. The third defaults to off, and stays off until there is a way back
/// from an update that turns out badly.
pub const KEY_AUTO_LISTS: &str = "auto_apply_lists";
pub const KEY_AUTO_GEO:   &str = "auto_apply_geo";
pub const KEY_AUTO_RULES: &str = "auto_apply_rules";

/// The flash a write leaves behind.
#[derive(Debug, Deserialize)]
pub struct UpdatesQuery {
    pub result: Option<String>,
    pub msg: Option<String>,
}

/// Whether a kind is applied as it arrives, with the defaults above.
pub async fn auto(db: &sqlx::SqlitePool, key: &str) -> bool {
    let default = key != KEY_AUTO_RULES;
    match get_setting(db, key).await {
        Some(v) => v.trim() == "1",
        None => default,
    }
}

// ─── get_updates ─────────────────────────────────────────

/// GET /updates — what has arrived, what is in force, and what is waiting.
pub async fn get_updates(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(q): Query<UpdatesQuery>,
) -> Result<Response> {

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",  "Updates");
    ctx.insert("url", "/updates");
    ctx.insert("result", &q.result.unwrap_or_default());
    ctx.insert("msg", &q.msg.unwrap_or_default());

    // ── Whether anything reaches out at all ──
    ctx.insert("check_enabled", &crate::rules_update::enabled(&state.db).await);
    ctx.insert("auto_lists", &auto(&state.db, KEY_AUTO_LISTS).await);
    ctx.insert("auto_geo",   &auto(&state.db, KEY_AUTO_GEO).await);
    ctx.insert("auto_rules", &auto(&state.db, KEY_AUTO_RULES).await);

    // ── Rule sets ──
    let rules_url = get_setting(&state.db, crate::rules_update::KEY_URL)
        .await
        .unwrap_or_default();
    let (checked, check_error) = crate::rules_update::status(&state.db).await;
    ctx.insert("rules_url", &rules_url);
    ctx.insert("rules_default", crate::rules_update::DEFAULT_URL);
    ctx.insert("rules_checked", &checked.map(|t| crate::routes::settings::format_utc(&t)).unwrap_or_default());
    ctx.insert("rules_error",   &check_error.unwrap_or_default());
    ctx.insert("offered_sets",  &crate::rules_update::offered(&state.db).await);
    // What is waiting for somebody: a set is only reported for a policy that
    // holds it, since an update to a set nobody installed is not news.
    ctx.insert("behind", &crate::rules_update::available(&state.db).await?);

    // ── Published IP lists ──
    let lists_url = get_setting(&state.db, crate::iplist_feeds::KEY_URL)
        .await
        .unwrap_or_default();
    let (fetched, fetch_error) = crate::iplist_feeds::status(&state.db).await;
    let (lists, lists_error) =
        crate::iplist_feeds::catalogue(&state.db, crate::iplist_feeds::Scope::Everywhere).await;
    ctx.insert("lists_url", &lists_url);
    ctx.insert("lists_default", crate::iplist_feeds::DEFAULT_URL);
    ctx.insert("lists_fetched", &fetched.map(|t| crate::routes::settings::format_utc(&t)).unwrap_or_default());
    ctx.insert("lists_error",   &fetch_error.or(lists_error).unwrap_or_default());
    ctx.insert("lists", &lists);
    // How many policies each list is switched on for, so a list that is doing
    // nothing anywhere reads as what it is.
    let in_use: HashMap<String, i64> = sqlx::query!(
        r#"SELECT id as "id!", COUNT(*) as "n!: i64"
           FROM ip_list_feeds WHERE enabled = 1 GROUP BY id"#
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .map(|r| (r.id, r.n))
    .collect();
    ctx.insert("lists_in_use", &in_use);

    // ── The country database ──
    ctx.insert("geo", &crate::geo::status());
    ctx.insert("geo_previous", &crate::geo::previous_path().exists());

    Ok((jar, Html(state.tera.render("updates.html", &ctx)?)).into_response())
}

// ─── post_updates_settings ───────────────────────────────

/// POST /updates/settings — the channels, and what is applied without asking.
pub async fn post_updates_settings(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response> {

    let field = |k: &str| form.get(k).map(String::as_str);

    // An empty field means the default channel, not "no channel" — turning the
    // check off is the switch, and conflating the two would leave a ticked box
    // that quietly does nothing.
    let rules = match crate::routes::settings::channel_url(field("rules_url"), "Rule channel") {
        Ok(c)  => c,
        Err(e) => return flash_redirect("/updates", "failed", &e),
    };
    let lists = match crate::routes::settings::channel_url(field("lists_url"), "IP list channel") {
        Ok(c)  => c,
        Err(e) => return flash_redirect("/updates", "failed", &e),
    };
    set_setting(&state.db, crate::rules_update::KEY_URL, &rules).await?;
    set_setting(&state.db, crate::iplist_feeds::KEY_URL, &lists).await?;

    // Unticked checkboxes send nothing at all, so absence is the answer.
    let on = |k: &str| if form.contains_key(k) { "1" } else { "0" };
    set_setting(&state.db, crate::rules_update::KEY_ENABLED, on("check_enabled")).await?;
    set_setting(&state.db, KEY_AUTO_LISTS, on("auto_lists")).await?;
    set_setting(&state.db, KEY_AUTO_GEO,   on("auto_geo")).await?;
    set_setting(&state.db, KEY_AUTO_RULES, on("auto_rules")).await?;

    tracing::info!(by = %session.username, auto_rules = form.contains_key("auto_rules"),
                   "Update settings saved");

    // The one that changes what this appliance does on its own is said back,
    // because it was a decision and the page should confirm which one.
    let msg = if form.contains_key("auto_rules") {
        "Saved. Rule set updates will be applied to every policy that holds \
         the set, without asking"
    } else if !form.contains_key("check_enabled") {
        "Saved. Nothing will be fetched — use Upload for an appliance with no \
         outbound access"
    } else {
        "Saved"
    };
    flash_redirect("/updates", "success", msg)
}

// ─── post_upload ─────────────────────────────────────────

/// POST /updates/{kind}/upload — a bundle carried in by hand.
///
/// The way in for an appliance with no outbound access, and **not** a lower
/// bar: a rule set or IP list bundle is checked exactly as a download is —
/// the manifest's detached signature first, then every file against the hash
/// that signed manifest gives for it. What makes offline safe here is that the
/// signature travels with the files.
///
/// The country database is the exception and says so: DB-IP and MaxMind do not
/// sign their databases, so a file an operator supplies is checked for being a
/// database and nothing more. The page records that it was not verified.
pub async fn post_upload(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Path(kind): Path<String>,
    mut parts: axum::extract::Multipart,
) -> Result<Response> {

    // Read every part first: which file is the manifest and which are its
    // contents is decided by name, not by the order a browser sent them.
    let mut files: HashMap<String, Vec<u8>> = HashMap::new();
    while let Ok(Some(field)) = parts.next_field().await {
        let Some(name) = field.file_name().map(|n| {
            // The last component only. A part claiming to be called
            // "../../etc/passwd" names nothing here.
            std::path::Path::new(n)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        }) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        match field.bytes().await {
            Ok(b)  => { files.insert(name, b.to_vec()); }
            Err(e) => return flash_redirect("/updates", "failed",
                          &format!("Could not read the upload: {e}")),
        }
    }

    if files.is_empty() {
        return flash_redirect("/updates", "failed", "No files were uploaded");
    }

    let outcome = match kind.as_str() {
        "rules" => bundle(&files, "sets.toml", |m, sig, rest| {
            crate::rules_update::install_bundle(m, sig, rest)
                .map(|n| format!(
                    "{n} rule set(s) verified and mirrored from the upload. Nothing is in force until it is applied to a policy"))
        }),
        "lists" => bundle(&files, "lists.toml", |m, sig, rest| {
            // Keyed by list id, which is the file's own name without .txt.
            let by_id = rest.iter()
                .map(|(name, body)| {
                    (name.trim_end_matches(".txt").to_string(), body.clone())
                })
                .collect();
            crate::iplist_feeds::install_bundle(m, sig, &by_id)
                .map(|n| format!("{n} published list(s) verified, mirrored and in force"))
        }),
        "geo" => {
            // One file, and no manifest to check it against: nobody signs a
            // country database.
            let Some((name, body)) = files.iter().next() else {
                return flash_redirect("/updates", "failed", "No file was uploaded");
            };
            if files.len() > 1 {
                return flash_redirect("/updates", "failed",
                    "Upload one country database, not several");
            }
            crate::geo::install(body, crate::geo::Source::Uploaded).map(|s| format!(
                "{} is in force — built {}. It was not signature-checked: a database an operator supplies cannot be, and the page says so",
                name,
                s.built.unwrap_or_else(|| "on an unstated date".to_string())))
        }
        other => Err(format!("\"{other}\" is not something that can be uploaded")),
    };

    match outcome {
        Ok(msg) => {
            tracing::info!(kind = %kind, files = files.len(), by = %session.username,
                           "Bundle uploaded");
            // A list bundle changes what is in force, so it is reloaded here
            // rather than at the next check.
            if kind == "lists" {
                crate::iplist_feeds::reload();
            }
            flash_redirect("/updates", "success", &msg)
        }
        // Verbatim, as for a download: a refusal is a signature that did not
        // verify or a hash that did not match, and "upload failed" would hide
        // the one detail worth acting on.
        Err(e) => flash_redirect("/updates", "failed", &format!("Refused: {e}")),
    }
}

/// Split an uploaded bundle into its manifest, its signature and the rest.
fn bundle<F>(
    files: &HashMap<String, Vec<u8>>,
    manifest: &str,
    install:  F,
) -> std::result::Result<String, String>
where
    F: FnOnce(&[u8], &str, &HashMap<String, Vec<u8>>) -> std::result::Result<String, String>,
{
    let signature = format!("{manifest}.asc");
    let Some(m) = files.get(manifest) else {
        return Err(format!("the bundle has no {manifest}"));
    };
    let Some(sig) = files.get(&signature) else {
        return Err(format!(
            "the bundle has no {signature} — the signature is what makes an upload \
safe, so a bundle without one is refused"));
    };
    let sig = String::from_utf8(sig.clone())
        .map_err(|_| format!("{signature} is not text"))?;

    let rest: HashMap<String, Vec<u8>> = files.iter()
        .filter(|(name, _)| *name != manifest && **name != signature)
        .map(|(name, body)| (name.clone(), body.clone()))
        .collect();

    install(m, &sig, &rest)
}

// ─── post_update_now ─────────────────────────────────────

/// POST /updates/{kind}/fetch — look at the channel now, rather than in six
/// hours.
///
/// Fetching is not applying: this fills the mirror, and what happens next is
/// the split the page describes. The message says which of the three answers
/// it got, because "nothing happened" is what people re-press buttons over.
pub async fn post_update_now(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    Admin(session): Admin,
    Path(kind): Path<String>,
) -> Result<Response> {

    // The switch is how an installation says it must not reach out at all. A
    // button that overrode it would make the switch a suggestion, so this
    // refuses and names the way in that such an installation does have.
    if !crate::rules_update::enabled(&state.db).await {
        return flash_redirect("/updates", "failed",
            "Checking the update channels is turned off. Turn it on above, or \
             upload a bundle — which is the way in for an appliance with no \
             outbound access");
    }

    let outcome = match kind.as_str() {
        "rules" => match crate::rules_update::sync_cache(&state.db).await {
            Ok(0) => Ok("The rule channel has nothing newer than the mirror".to_string()),
            Ok(n) => Ok(format!(
                "{n} rule set(s) fetched into the mirror. Nothing is in force until \
                 it is applied to a policy")),
            Err(e) => Err(e),
        },
        "lists" => match crate::iplist_feeds::check_now(&state.db).await {
            Ok(n)  => Ok(format!("{n} published list(s) fetched and in force")),
            Err(e) => Err(e),
        },
        "geo" => Err("The country database is not published to a channel yet — \
                      upload one, or point geoip_db at a file".to_string()),
        other => Err(format!("\"{other}\" is not something that can be fetched")),
    };

    match outcome {
        Ok(msg) => {
            tracing::info!(kind = %kind, by = %session.username, "Update channel checked on request");
            flash_redirect("/updates", "success", &msg)
        }
        // Reported verbatim: a refusal here is a signature that did not verify
        // or a hash that did not match, and "update failed" would hide the one
        // detail worth acting on.
        Err(e) => flash_redirect("/updates", "failed", &format!("Could not fetch: {e}")),
    }
}

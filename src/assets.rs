// =========================================================
// assets.rs — EasyWAF
// Templates and static files, compiled into the binary.
//
// EasyWAF is meant to be one executable. Before this, it
// also needed templates/ and static/ sitting beside it in
// the right working directory, and getting that wrong did
// not fail at startup — it failed on the first page load,
// as a panic or a stack of 404s with no stylesheet.
//
// In a debug build these are read from disk at runtime, so
// editing a template still only needs a restart. A release
// build embeds them, which is what ships.
// =========================================================

use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;

/// Tera templates. Flat directory, so the embedded name is the file name and
/// matches what `render()` and `{% extends %}` already ask for.
#[derive(Embed)]
#[folder = "templates/"]
pub struct Templates;

/// CSS, JS and icons served under `/static`.
#[derive(Embed)]
#[folder = "static/"]
pub struct Static;

/// Build the Tera instance from the embedded templates.
///
/// Replaces `Tera::new("templates/**/*.html")`, which globbed the working
/// directory. An error here is fatal for the same reason it was before: every
/// page of the GUI is a template, so a broken one is not something to discover
/// per request.
pub fn tera() -> Result<tera::Tera, tera::Error> {
    let mut tera = tera::Tera::default();

    let mut items = Vec::new();
    for name in Templates::iter() {
        let file = match Templates::get(&name) {
            Some(f) => f,
            // Cannot happen: the name came from iter(). Skipped rather than
            // unwrapped so a future change to rust-embed cannot turn it into a
            // panic at startup.
            None => continue,
        };
        match String::from_utf8(file.data.into_owned()) {
            Ok(text) => items.push((name.to_string(), text)),
            Err(_)   => {
                return Err(tera::Error::msg(format!("template {name} is not valid UTF-8")))
            }
        }
    }

    if items.is_empty() {
        return Err(tera::Error::msg(
            "no templates were embedded — the build did not include templates/",
        ));
    }

    tera.add_raw_templates(items)?;

    // Registered here rather than by the caller, so every Tera instance built
    // from this function is complete. The layout every page extends calls
    // version(), so an instance without it renders nothing at all — and the
    // failure is at render time, on a page, not at startup.
    tera.register_function("version", app_version);

    Ok(tera)
}

/// Tera function returning the crate version, usable as `{{ version() }}` in
/// any template.
///
/// The About modal used to hard-code the version, which meant Cargo.toml and
/// the template had to be bumped together — they drifted for the 0.2.0 release,
/// which shipped a modal still reading 0.1.0. Reading it from the binary keeps
/// one source of truth.
fn app_version(_args: &std::collections::HashMap<String, tera::Value>) -> tera::Result<tera::Value> {
    Ok(tera::Value::String(env!("CARGO_PKG_VERSION").to_string()))
}

/// GET /static/{*path} — serve an embedded asset.
///
/// `Cache-Control: no-cache` for the same reason the old `ServeDir` layer set
/// it: the browser revalidates cheaply and a changed stylesheet is never served
/// from a stale cache.
pub async fn serve_static(Path(path): Path<String>) -> Response {
    // A path that climbs out cannot reach anything — the embedded set is a
    // fixed list of names, not a directory — but it is rejected rather than
    // looked up, so the intent is refused rather than merely failing.
    if path.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }

    match Static::get(&path) {
        Some(file) => (
            [
                (header::CONTENT_TYPE, file.metadata.mimetype().to_string()),
                (header::CACHE_CONTROL, "no-cache".to_string()),
            ],
            file.data.into_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_is_embedded_and_compiles() {
        // Tera parses on add, so this also catches a template with broken
        // syntax — which otherwise surfaces as a panic at startup.
        let tera = tera().expect("templates should build");
        let names: Vec<_> = tera.get_template_names().collect();

        assert!(names.len() >= 20, "expected the full template set, got {}", names.len());
        for required in ["layout_default.html", "settings.html", "policy_rule_sets.html"] {
            assert!(names.contains(&required), "{required} is missing from the binary");
        }
    }

    #[test]
    fn the_static_assets_are_embedded_with_types() {
        for (name, expected) in [
            ("css/easywaf.css", "text/css"),
            ("js/easywaf.js",   "javascript"),
            ("favicon.svg",     "image/svg+xml"),
        ] {
            let file = Static::get(name).unwrap_or_else(|| panic!("{name} is not embedded"));
            let mime = file.metadata.mimetype();
            assert!(
                mime.contains(expected),
                "{name} served as {mime}, which does not look like {expected}"
            );
            assert!(!file.data.is_empty(), "{name} is empty");
        }
    }

    #[test]
    fn the_traffic_table_renders_every_verdict_state() {
        // Including detection = null, which is every row written before the
        // column existed. Tera resolves a missing field at render time, so a
        // mistake here is not a compile error — it is a 500 on the page an
        // operator opens when something is going wrong.
        let tera = tera().expect("templates should build");
        let mut ctx = tera::Context::new();

        let event = |path: &str, blocked: bool, detection: Option<&str>,
                     listed: Option<&str>| {
            serde_json::json!({
                "id": 1, "timestamp": "2026-09-07 12:00:00", "site_name": "s",
                "client_ip": "1.2.3.4", "method": "GET", "host": "h", "path": path,
                "status_code": 200, "response_ms": 4, "blocked": blocked,
                "block_reason": null, "waf_score": 9, "country": null,
                "detection": detection,
                // Whether this client is already on a list. A row that is
                // shows a badge; one that is not offers to put it on one.
                "listed": listed,
                // The site's policy, which the list and exclusion buttons
                // act on and whose reach they state.
                "policy": "websites", "policy_sites": 3,
                // One rule already excluded for this client and one not, so
                // both the marker and the offer to exclude are rendered.
                "matched_rules": [
                    {"id": 913015, "name": "Scanner probe", "score": 4, "excluded": false},
                    {"id": 942100, "name": "SQLi union",    "score": 5, "excluded": true},
                ],
            })
        };

        ctx.insert("events", &vec![
            event("/pre-0.6.11", false, None, None),          // the upgrade case
            event("/clean",      false, None, None),
            event("/observed",   false, Some("observed"), None),
            event("/would",      false, Some("would_block"), None),
            event("/wouldch",    false, Some("would_challenge"), None),
            event("/blocked",    true,  None, None),
            // Both list states, so the badges are rendered rather than only
            // the branch that offers to add one.
            event("/on-block",   false, None, Some("block")),
            event("/on-allow",   false, None, Some("allow")),
            // A site with no policy: no lists, nothing to exclude, so neither
            // offer may be rendered for it.
            {
                let mut e = event("/no-policy", false, None, None);
                e["policy"] = serde_json::Value::Null;
                e["policy_sites"] = serde_json::json!(0);
                e
            },
        ]);
        ctx.insert("stats", &serde_json::json!({
            "total": 6, "blocked": 1, "allowed": 5, "avg_response": 4 }));
        ctx.insert("sites",   &Vec::<String>::new());
        // Chart data too, so the chart block is rendered rather than skipped —
        // it reads fields off each bucket, and a missing one is a render-time
        // failure, not a compile-time one.
        ctx.insert("chart", &vec![
            serde_json::json!({ "hour": "2026-09-08 10:00", "total": 9, "blocked": 2, "detected": 3 }),
            serde_json::json!({ "hour": "2026-09-08 11:00", "total": 4, "blocked": 0, "detected": 0 }),
        ]);
        ctx.insert("username",    "t");
        ctx.insert("title",       "Traffic");
        ctx.insert("url",         "/traffic");
        ctx.insert("sel_site",    "");
        ctx.insert("sel_blocked", "");
        ctx.insert("sel_hours",   &24);
        ctx.insert("result",      "success");
        ctx.insert("msg",         "Rule excluded.");

        let html = tera.render("traffic.html", &ctx)
            .unwrap_or_else(|e| panic!("traffic.html failed to render: {e:#?}"));

        assert!(html.contains("WOULD BLOCK"),   "a would-block row lost its verdict");
        // Deliberately not the word "detected": it read as "DetectionOnly", so an
        // enforcing policy showing these looked like it had stopped enforcing.
        assert!(html.contains("SCORED"),        "an observed row lost its verdict");
        assert!(!html.contains("DETECTED"),
                "the ambiguous label is back — it reads as DetectionOnly");
        assert!(html.contains("BLOCKED"),       "a blocked row lost its verdict");
        assert!(html.contains("PASS"),          "a clean row lost its verdict");
        // A client already on a list says so; one that is not is offered both
        // ways. Asserted because a row that renders but shows neither would
        // pass every check above while the feature was invisible.
        assert!(html.contains("refused before any rule runs, on every site using it"),
                "a blocklisted client lost its badge");
        assert!(html.contains("skips the WAF, the country rules and the challenge, on every site using it"),
                "an allowlisted client lost its badge");
        assert!(html.contains("/iplists/add"),
                "an unlisted client is not offered block or allow");

        // The chart's three series must all reach the page, or an hour of
        // detected traffic is drawn as ordinary traffic.
        for series in ["'Allowed'", "'Detected'", "'Blocked'"] {
            assert!(html.contains(series), "the chart is missing its {series} series");
        }
        // The fix has to be reachable from the row that showed the problem,
        // and a rule already excluded must say so instead of offering again.
        assert!(html.contains("exclude for this IP"),
                "no way to exclude a rule from the row that matched it");
        assert!(html.contains("excluded for this IP"),
                "an already-excluded rule is not marked as such");
        assert!(html.contains("/exclusions/from-traffic"),
                "the exclude button posts nowhere");
    }

    #[test]
    fn a_site_with_no_policy_is_reported_as_uninspected() {
        // The one state in which EasyWAF inspects nothing: both modules return
        // Pass before looking at the request. It showed only as a muted "None"
        // in the sites list, which reads as a neutral absence. These assertions
        // exist so it cannot quietly become one again.
        let tera = tera().expect("templates should build");

        // Dashboard: names the sites, and says nothing when there are none.
        let mut ctx = tera::Context::new();
        for (k, v) in [("username", "t"), ("title", "Dashboard"), ("url", "/")] {
            ctx.insert(k, v);
        }
        for k in ["sites_number", "certs_number", "policy_number"] { ctx.insert(k, &0); }
        ctx.insert("traffic", &serde_json::json!({
            "total": 0, "passed": 0, "challenged": 0, "blocked": 0,
            "detected": 0, "would_block": 0 }));
        ctx.insert("site_traffic", &Vec::<String>::new());
        ctx.insert("chart", &Vec::<String>::new());

        ctx.insert("unprotected_sites", &vec!["docs.example", "repo.example"]);
        let html = tera.render("dashboard.html", &ctx).expect("dashboard renders");
        assert!(html.contains("no inspection at all"), "the warning is missing");
        assert!(html.contains("docs.example") && html.contains("repo.example"),
                "the warning does not name the sites");

        ctx.insert("unprotected_sites", &Vec::<String>::new());
        let clean = tera.render("dashboard.html", &ctx).expect("dashboard renders");
        assert!(!clean.contains("no inspection at all"),
                "the warning shows when every site has a policy");

        // Site settings: the same fact, next to the control that causes it.
        let mut sctx = tera::Context::new();
        for (k, v) in [("username", "t"), ("title", "Site"), ("url", "/sites"),
                       ("result", ""), ("msg", ""),
                       ("http_ports", "80"), ("https_ports", "")] {
            sctx.insert(k, v);
        }
        sctx.insert("policies", &Vec::<String>::new());
        sctx.insert("certs",    &Vec::<String>::new());
        sctx.insert("exclusion_count", &0);
        let site = |pid: Option<i64>| serde_json::json!({
            "id": 1, "name": "s", "server_name": "s.example", "aliases": "",
            "target": "http://a",
            "enabled": true, "listen_port": 80, "tls_port": null, "cert_id": null,
            "tls_redirect": false, "waf_policy_id": pid, "hsts": false,
            "x_frame": false, "x_frame_value": "SAMEORIGIN",
            "x_content_type": false, "xss_protection": false });

        sctx.insert("site", &site(None));
        let none = tera.render("site_settings.html", &sctx).expect("site settings render");
        assert!(none.contains("This site is not inspected"), "no warning without a policy");

        sctx.insert("site", &site(Some(3)));
        let with = tera.render("site_settings.html", &sctx).expect("site settings render");
        assert!(!with.contains("This site is not inspected"),
                "the warning shows on a site that does have a policy");
    }

    #[test]
    fn the_ip_lists_page_renders_every_published_list_state() {
        // Every state a published list can be in, because each is a different
        // branch of the template and Tera only finds a missing field when that
        // branch is rendered — on the page an operator opens to find out why an
        // address was refused.
        let tera = tera().expect("templates should build");
        let mut ctx = tera::Context::new();
        for (k, v) in [("username", "t"), ("title", "IP Lists"), ("url", "/iplists"),
                       ("search", ""), ("result", ""), ("msg", ""),
                       ("feeds_error", ""), ("feeds_fetched", "2026-09-16 06:00"),
                       ("feeds_fetch_error", "channel unreachable"),
                       ("sel_policy", "websites"),
                       ("reach", "every site using websites (2 sites)")] {
            ctx.insert(k, v);
        }
        ctx.insert("policies", &vec!["nextcloud", "websites"]);
        ctx.insert("sites", &vec!["a.example", "b.example"]);
        ctx.insert("show_picker", &true);
        ctx.insert("back", "");
        ctx.insert("entries", &Vec::<String>::new());
        ctx.insert("allowed", &0);
        ctx.insert("blocked", &0);
        ctx.insert("feeds_check", &true);

        let feed = |id: &str, enabled: bool, response: &str, error: Option<&str>,
                    offered: bool, unreadable: usize| {
            serde_json::json!({
                "id": id, "name": format!("{id} name"), "description": "what it covers",
                "licence": "CC0", "attribution": "Someone", "version": "2026091601",
                "entries": 1432, "enabled": enabled, "response": response,
                "ranges": 1400, "unreadable": unreadable, "error": error,
                "offered": offered,
            })
        };
        ctx.insert("feeds", &vec![
            feed("off-list",       false, "challenge", None, true, 0),
            feed("block-list",     true,  "block",     None, true, 0),
            feed("challenge-list", true,  "challenge", None, true, 3),
            feed("broken-list",    true,  "block",     Some("its file does not match the signed manifest"), true, 0),
            feed("gone-list",      true,  "challenge", Some("the channel no longer publishes this list"), false, 0),
        ]);

        let html = tera.render("iplists.html", &ctx)
            .unwrap_or_else(|e| panic!("iplists.html failed to render: {e:#?}"));
        for label in ["OFF", "BLOCK", "CHALLENGE", "NOT LOADED"] {
            assert!(html.contains(label), "the {label} state is not shown");
        }
        assert!(html.contains("does not match the signed manifest"),
                "a list that failed to load does not say why");
        assert!(html.contains("No longer published"), "a withdrawn list is not flagged");
        assert!(html.contains("3 unreadable"), "unreadable lines are not counted");
        assert!(html.contains("The last update failed"), "a failed update is not shown");
        assert!(html.contains("Update now"), "no way to fetch the lists on demand");
        assert!(html.contains("every site using websites (2 sites)"),
                "the page does not say which sites the policy's lists reach");

        // And with nothing mirrored yet, which is every new installation.
        ctx.insert("feeds", &Vec::<String>::new());
        ctx.insert("feeds_error", "nothing has been fetched from the channel yet");
        ctx.insert("feeds_check", &false);
        let html = tera.render("iplists.html", &ctx).expect("renders with no lists");
        assert!(html.contains("nothing has been fetched"), "the empty state does not say why");
        assert!(html.contains("turned off under"), "a disabled channel check is not explained");

        // And an installation with no policy yet, where there is nothing a
        // list could belong to.
        ctx.insert("sel_policy", "");
        ctx.insert("policies", &Vec::<String>::new());
        let html = tera.render("iplists.html", &ctx).expect("renders with no policies");
        assert!(html.contains("Create a policy"), "no way forward with no policies");
        assert!(!html.contains("Published Lists"), "lists shown with no policy to own them");
    }

    #[test]
    fn creating_a_policy_offers_everything_a_policy_holds() {
        // A policy holds rules, country rules, IP lists, published lists and
        // exclusions. Until 0.12.2 the create page offered only rules, so a new
        // policy meant four more pages afterwards — and the parts nobody
        // remembered were the ones that never got set.
        let tera = tera().expect("templates should build");
        let mut ctx = tera::Context::new();
        for (k, v) in [("username", "t"), ("title", "Create Policy"), ("url", "/policy"),
                       ("check_error", ""), ("checked", "2026-09-18 06:00"),
                       ("lists_error", ""), ("lists_fetched", "2026-09-18 06:00"),
                       ("lists_fetch_error", "")] {
            ctx.insert(k, v);
        }
        ctx.insert("catalog", &Vec::<String>::new());
        ctx.insert("total_available", &0);
        ctx.insert("policies", &vec![serde_json::json!({
            "id": 1, "name": "websites", "rule_engine": "On", "score_threshold": 10,
            "challenge_threshold": 0, "geoip_mode": "off", "geoip_countries": "",
            "rule_count": 99, "enabled_count": 99 })]);
        let list = |id: &str, ranges: usize, unreadable: usize, error: Option<&str>| {
            serde_json::json!({
                "id": id, "name": format!("{id} list"), "description": "Relays.",
                "licence": "CC0", "attribution": "The Tor Project", "version": "2026091801",
                "entries": 1349, "enabled": false, "response": "challenge",
                "ranges": ranges, "unreadable": unreadable, "error": error, "offered": true })
        };
        // Loaded, loaded with lines it could not read, and not loaded at all —
        // a list chosen here must not look ready when it is not.
        ctx.insert("lists", &vec![
            list("tor-exits", 1342, 0, None),
            list("et-compromised", 588, 3, None),
            list("spamhaus-drop", 0, 0, Some("its file does not match the signed manifest")),
        ]);

        let html = tera.render("policy_create.html", &ctx)
            .unwrap_or_else(|e| panic!("policy_create.html failed to render: {e:#?}"));
        for (field, what) in [
            ("copy_from",        "no way to start from an existing policy"),
            ("geoip_mode",       "country rules are not offered"),
            ("geoip_countries",  "no country list"),
            ("ip_block",         "no block list"),
            ("ip_allow",         "no allow list"),
            ("list:tor-exits",   "published lists are not offered"),
        ] {
            assert!(html.contains(field), "{what}");
        }
        // A heading is a set and the rules under it are copies, so taking every
        // rule of a set has to become the set — in the script, which sends the
        // set id rather than the rules, and on the page, which says so.
        assert!(html.contains("the heading ticks"), "the page does not say a full set ticks its heading");
        for (js, what) in [
            ("master.dataset.follow = '1'", "a full set of ticks no longer takes the heading with it"),
            ("delete master.dataset.follow", "a heading that followed its rules never lets go"),
        ] {
            assert!(html.contains(js), "{what}");
        }
        assert!(html.contains("websites"), "an existing policy is not offered to copy");
        assert!(html.contains("tor-exits list"), "the published list is not named");
        for (what, why) in [
            ("1342 ranges ready", "a loaded list does not say it is ready"),
            ("not loaded",        "a list that failed to load looks the same as a loaded one"),
            ("does not match the signed manifest", "the reason a list is not loaded is hidden"),
            ("3 unreadable lines", "unreadable lines are not counted"),
            ("2026091801",        "the list version is not shown"),
            ("channel updated",   "the channel's own status is missing"),
        ] {
            assert!(html.contains(what), "{why}");
        }

        // With nothing published and no policies yet — a first installation.
        ctx.insert("lists", &Vec::<String>::new());
        ctx.insert("policies", &Vec::<String>::new());
        ctx.insert("lists_error", "nothing has been fetched from the channel yet");
        let first = tera.render("policy_create.html", &ctx).expect("renders");
        // The shared script mentions the form by id and finds nothing, which is
        // the point: there is no policy here yet to switch a rule off in, so
        // neither the form nor a button that posts it is on the page.
        assert!(!html.contains(r#"id="ruleStateForm""#) && !html.contains(r#"form="ruleStateForm""#),
                "the create page offers to change rules in a policy that does not exist yet");
        assert!(first.contains("nothing has been fetched"), "the empty state does not say why");
        assert!(!first.contains("copy_from"), "offers to copy when there is nothing to copy");
    }

    #[test]
    fn a_policys_own_page_shows_everything_it_holds() {
        // Rules, country rules, IP lists and exclusions all belong to the
        // policy, so editing one should not mean four pages. Every tab is
        // rendered here: a field missing from one of them is a 500 on the page
        // an operator opens to change what their sites enforce.
        let tera = tera().expect("templates should build");
        let mut ctx = tera::Context::new();
        for (k, v) in [("username", "t"), ("title", "Policy Settings"), ("url", "/policy"),
                       ("result", ""), ("msg", ""), ("back", "/policy/websites/edit"),
                       ("sel_policy", "websites"), ("search", ""),
                       ("reach", "every site using websites (2 sites)"),
                       ("tab", "iplists"),
                       ("back_iplists", "/policy/websites/edit?tab=iplists"),
                       ("back_exclusions", "/policy/websites/edit?tab=exclusions"),
                       ("check_error", ""), ("checked", "2026-09-18 06:00"),
                       ("feeds_error", ""), ("feeds_fetched", "2026-09-18 06:00"),
                       ("feeds_fetch_error", "")] {
            ctx.insert(k, v);
        }
        ctx.insert("policy", &serde_json::json!({
            "id": 1, "name": "websites", "rule_engine": "On", "score_threshold": 10,
            "challenge_threshold": 5, "geoip_mode": "block", "geoip_countries": "CN,RU",
            "rule_count": 99, "enabled_count": 98 }));
        ctx.insert("show_picker", &false);
        ctx.insert("policies", &Vec::<String>::new());
        // Two sets the policy stands in a different relation to: one it holds
        // half of as loose rules, one it holds as an installed set.
        ctx.insert("catalog", &vec![serde_json::json!({
            "title": "Scanners", "code": "913", "set_id": "owasp-scanners",
            "tier": "basic", "total": 2, "added_count": 1, "set_added": false,
            "rules": [
                {"external_id": 913001, "name": "Scanner probe", "description": "",
                 "zone": "ANY", "pattern": "x", "score": 5, "action": "score",
                 "added": true, "off": true},
                {"external_id": 913002, "name": "Another probe", "description": "",
                 "zone": "ANY", "pattern": "y", "score": 5, "action": "score",
                 "added": false, "off": false},
            ]}), serde_json::json!({
            "title": "SQL Injection", "code": "942", "set_id": "owasp-sqli",
            "tier": "basic", "total": 1, "added_count": 1, "set_added": true,
            "rules": [
                {"external_id": 942001, "name": "Union select", "description": "",
                 "zone": "ARGS", "pattern": "z", "score": 5, "action": "block",
                 "added": true, "off": false},
            ]})]);
        ctx.insert("total_available", &100);
        ctx.insert("rule_count", &99);
        ctx.insert("enabled_count", &98);
        ctx.insert("sites", &vec!["a.example", "b.example"]);
        ctx.insert("entries", &vec![serde_json::json!({
            "id": 7, "ip": "203.0.113.9", "list_type": "block", "reason": "scanner",
            "added_by": "admin", "created_at": "2026-09-18 09:00" })]);
        ctx.insert("allowed", &0);
        ctx.insert("blocked", &1);
        ctx.insert("feeds", &vec![serde_json::json!({
            "id": "tor-exits", "name": "Tor exit nodes", "description": "Relays.",
            "licence": "CC0", "attribution": "The Tor Project", "version": "1",
            "entries": 1349, "enabled": true, "response": "challenge",
            "ranges": 693, "unreadable": 0, "error": null, "offered": true })]);
        ctx.insert("feeds_check", &true);
        ctx.insert("exclusions", &vec![serde_json::json!({
            "id": 3, "policy_name": "websites", "rule_label": "SQLi union",
            "external_id": 942100, "path_prefix": "/dav", "client_cidr": "",
            "note": "WebDAV", "created_at": "2026-09-18 09:00" })]);
        ctx.insert("candidates", &vec![serde_json::json!({
            "value": "e:913015", "label": "913015 — Scanner probe", "set": "owasp-scanners" })]);

        let html = tera.render("policy_settings.html", &ctx)
            .unwrap_or_else(|e| panic!("policy_settings.html failed to render: {e:#?}"));

        for (what, why) in [
            ("tab-rules",       "no rules tab"),
            ("tab-countries",   "no countries tab"),
            ("tab-iplists",     "no IP lists tab"),
            ("tab-exclusions",  "no exclusions tab"),
            ("geoip_countries", "country rules cannot be edited here"),
            ("203.0.113.9",     "the policy's IP entries are not shown"),
            ("Tor exit nodes",  "the policy's published lists are not shown"),
            ("SQLi union",      "the policy's exclusions are not shown"),
            ("Exclude this rule", "an exclusion cannot be added here"),
            ("/policy/websites/setup", "rules cannot be added here"),
            // A rule already installed is shown as such, and is not a choice:
            // offering it again is how "nothing was added" happens.
            ("in this policy",         "a rule the policy holds is not marked"),
            ("cat-held",               "a held rule is offered as a selection"),
            ("already here",           "the heading does not say how many are installed"),
            // The heading follows a full set of ticks, and the rules already
            // here are part of what makes a set full — so it has to know how
            // many of them there are.
            ("data-held=\"1\"",        "a heading cannot tell how many of its rules are here"),
            ("installed as a set",     "a set the policy holds is not said to be installed"),
            // One rule of a set is often the one rule that is wrong here, so
            // both ways out are offered beside it — they differ in what a later
            // update of the set does about it.
            ("disable:942001",         "a rule in the policy cannot be switched off from here"),
            ("enable:913001",          "a rule already off cannot be switched back on"),
            ("remove:942001",          "a rule in the policy cannot be removed from here"),
            ("/rules/state",           "the per-rule buttons have nowhere to post"),
            (r#"form="ruleStateForm""#, "the buttons would post the selection form they sit in"),
            // Tera escapes "/" in an attribute, so this is matched on the part
            // that survives escaping; the browser decodes it before posting.
            ("websites&#x2F;edit",     "a form does not return to this page"),
        ] {
            assert!(html.contains(what), "{why}");
        }
        assert!(!html.contains("remove:913002"),
                "a rule the policy does not hold is offered for removal");

        // The state form is declared beside the selection form. Nested forms do
        // not survive parsing, so the buttons would lose the action they name.
        let state_at = html.find("id=\"ruleStateForm\"").expect("no state form");
        let select_at = html.find("id=\"policyForm\"").expect("no selection form");
        assert!(state_at < select_at, "the state form is inside the selection form");

        // A set already installed is not a choice: it is ticked, left alone, and
        // has no heading checkbox to submit, so there is one of those and not
        // two. Offering it again would install what is already there.
        assert_eq!(html.matches("class=\"cat-master\"").count(), 1,
                   "an installed set is still offered as a selection");
        assert!(html.contains("This set is installed in this policy"),
                "an installed set's heading does not say why it cannot be ticked");

        // The panels are the shared ones: on a policy's page they come without
        // the selector and search box that belong to the standalone pages.
        assert!(!html.contains("every policy</option>"), "the exclusions picker leaked in");
        assert!(!html.contains("Search address or reason"), "the IP list search box leaked in");

        // The tab named in the query is the one that opens, and each panel's
        // forms return to their own tab rather than to the first one.
        assert!(html.contains(r#"class="tab-pane active" id="tab-iplists""#)
                || html.contains(r#"class="tab-pane active"  id="tab-iplists""#),
                "the tab asked for is not the one opened");
        assert!(html.contains("tab=iplists"), "the IP list forms do not return to their tab");
        assert!(html.contains("tab=exclusions"), "the exclusion forms do not return to their tab");
    }

    #[test]
    fn the_exclusions_page_is_reachable_from_the_menu() {
        // The page existed in 0.7.0 and was reachable only from an unlabelled
        // icon on the policy list. Someone looking for it in the Security
        // Policy menu, which is where it was asked for, did not find it.
        let tera = tera().expect("templates should build");
        let mut ctx = tera::Context::new();
        for (k, v) in [("username", "t"), ("title", "Rule Exclusions"),
                       ("url", "/exclusions"), ("sel_policy", ""),
                       ("result", ""), ("msg", "")] {
            ctx.insert(k, v);
        }
        ctx.insert("policies", &vec!["prod", "staging"]);
        ctx.insert("show_picker", &true);
        ctx.insert("back", "");
        ctx.insert("candidates", &Vec::<String>::new());
        ctx.insert("sites", &Vec::<String>::new());
        ctx.insert("reach", "");
        ctx.insert("exclusions", &vec![serde_json::json!({
            "id": 1, "policy_name": "prod",
            "rule_label": "Scanner probe", "external_id": 913015,
            "path_prefix": "", "client_cidr": "203.0.113.0/24",
            "note": "office range", "created_at": "2026-09-08 10:00:00" })]);

        let html = tera.render("policy_exclusions.html", &ctx).expect("renders");
        // Tera escapes "/" as &#x2F; in HTML, so these are matched on the
        // parts that survive escaping rather than on the literal URLs.
        assert!(html.contains("203.0.113.0"), "the client block is not shown");
        assert!(html.contains("prod"), "the policy column is missing");
        assert!(html.contains("exclusions") && html.contains("remove"),
                "no way to un-exclude");
        assert!(html.contains("Scanner probe") && html.contains("office range"),
                "the exclusion row did not render");

        // The menu entry that makes the page findable at all — it was reachable
        // only from an unlabelled icon before.
        assert!(html.contains("Rule Exclusions</a>"),
                "the Security Policy menu has no Rule Exclusions entry");

        // One policy selected: where exclusions are added, and where the page
        // must say how many sites an exclusion reaches before anyone adds one.
        ctx.insert("sel_policy", "websites");
        ctx.insert("sites", &vec!["a.example", "b.example"]);
        ctx.insert("reach", "every site using websites (2 sites)");
        ctx.insert("candidates", &vec![serde_json::json!({
            "value": "e:913015", "label": "913015 — Scanner probe", "set": "owasp-scanners" })]);
        let selected = tera.render("policy_exclusions.html", &ctx).expect("renders");
        assert!(selected.contains("Exclude this rule"), "no way to add an exclusion");
        assert!(selected.contains("every site using websites (2 sites)"),
                "the reach of an exclusion is not stated");
        assert!(!selected.contains("<th>Policy</th>"),
                "the policy column is repeated for a single policy");

        // And the empty state, so an installation with none says so.
        ctx.insert("exclusions", &Vec::<String>::new());
        let empty = tera.render("policy_exclusions.html", &ctx).expect("renders");
        assert!(empty.contains("No exclusions"), "the empty state is missing");
    }

    #[test]
    fn a_path_that_climbs_out_finds_nothing() {
        assert!(Static::get("../Cargo.toml").is_none());
        assert!(Static::get("/etc/passwd").is_none());
    }
}

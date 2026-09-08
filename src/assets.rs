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

        let event = |path: &str, blocked: bool, detection: Option<&str>| {
            serde_json::json!({
                "id": 1, "timestamp": "2026-09-07 12:00:00", "site_name": "s",
                "client_ip": "1.2.3.4", "method": "GET", "host": "h", "path": path,
                "status_code": 200, "response_ms": 4, "blocked": blocked,
                "block_reason": null, "waf_score": 9, "country": null,
                "detection": detection,
                // One rule already excluded for this client and one not, so
                // both the marker and the offer to exclude are rendered.
                "matched_rules": [
                    {"id": 913015, "name": "Scanner probe", "score": 4, "excluded": false},
                    {"id": 942100, "name": "SQLi union",    "score": 5, "excluded": true},
                ],
            })
        };

        ctx.insert("events", &vec![
            event("/pre-0.6.11", false, None),          // the upgrade case
            event("/clean",      false, None),
            event("/observed",   false, Some("observed")),
            event("/would",      false, Some("would_block")),
            event("/wouldch",    false, Some("would_challenge")),
            event("/blocked",    true,  None),
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
        assert!(html.contains("DETECTED"),      "an observed row lost its verdict");
        assert!(html.contains("BLOCKED"),       "a blocked row lost its verdict");
        assert!(html.contains("PASS"),          "a clean row lost its verdict");
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
            "id": 1, "name": "s", "server_name": "s.example", "target": "http://a",
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
    fn a_path_that_climbs_out_finds_nothing() {
        assert!(Static::get("../Cargo.toml").is_none());
        assert!(Static::get("/etc/passwd").is_none());
    }
}

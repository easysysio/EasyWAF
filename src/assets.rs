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
    Ok(tera)
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
    fn a_path_that_climbs_out_finds_nothing() {
        assert!(Static::get("../Cargo.toml").is_none());
        assert!(Static::get("/etc/passwd").is_none());
    }
}

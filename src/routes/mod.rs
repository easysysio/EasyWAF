// =========================================================
// routes/mod.rs — EasyWAF
// Re-exports all route modules.
// =========================================================

pub mod account;
pub mod accounts;
pub mod certs;
pub mod dashboard;
pub mod exclusions;
pub mod geoip;
pub mod iplists;
pub mod login;
pub mod policy;
pub mod rules;
pub mod settings;
pub mod setup;
pub mod sites;
pub mod traffic;
pub mod updates;

// ─── who_context ─────────────────────────────────────────

/// Tell the page who is looking at it.
///
/// Inserted through one helper rather than by each handler remembering three
/// `ctx.insert` calls, for the same reason authorisation became an extractor:
/// the thing every page must do should not be the thing every page can forget.
///
/// Templates read `is_admin` to decide whether to *offer* an action. That is
/// presentation only — the extractor on the route is what refuses it — so a
/// page that somehow arrived without this renders as a viewer rather than
/// breaking or, worse, offering controls it should not. Hence
/// `default(value=false)` at every use site.
pub fn who_context(ctx: &mut tera::Context, session: &crate::auth::SessionData) {
    ctx.insert("username", &session.username);
    ctx.insert("role",     &session.role);
    ctx.insert("is_admin", &session.is_admin());
}

// ─── flash_redirect ──────────────────────────────────────

/// Redirect to `path`, carrying a one-shot message for the page to render.
///
/// Lived as seven identical private copies until 0.7.1, one per route module,
/// and every one of them assumed `path` had no query string of its own. The
/// Traffic Monitor's exclude button broke on exactly that: it returns to
/// `/traffic?site=…&blocked=…&hours=24` to preserve the filter, the flash was
/// appended with a second `?`, and `hours` arrived as `24?result=success&…`.
/// Axum rejected the request before any handler ran — "invalid digit found in
/// string" — so the exclusion was saved and the page that would have confirmed
/// it never rendered.
///
/// One implementation now, and it picks the separator by looking.
pub fn flash_redirect(
    path: &str,
    result: &str,
    msg: &str,
) -> crate::error::Result<axum::response::Response> {
    use axum::response::{IntoResponse, Redirect};
    Ok(Redirect::to(&flash_url(path, result, msg)).into_response())
}

/// Where a form says to return to afterwards, when that is somewhere this
/// server serves.
///
/// A page that manages one thing from two places — IP lists on their own page
/// and on a policy's — has to send the operator back where they were. The
/// value arrives in a form field, so it is a path this application serves or
/// it is the fallback: anything with a scheme, a host, or a leading `//`
/// would turn a button into an open redirect.
pub fn safe_back(raw: Option<&str>, fallback: &str) -> String {
    match raw.map(str::trim) {
        Some(p) if p.starts_with('/') && !p.starts_with("//") && !p.contains("://") => {
            p.to_string()
        }
        _ => fallback.to_string(),
    }
}

/// The redirect target, separated out so the separator logic is testable
/// without building a response.
fn flash_url(path: &str, result: &str, msg: &str) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}result={result}&msg={}", urlencoding::encode(msg))
}

#[cfg(test)]
mod tests {
    use super::{flash_url, safe_back};

    #[test]
    fn a_return_path_is_followed_only_when_it_is_ours() {
        assert_eq!(safe_back(Some("/policy/web/edit"), "/iplists"), "/policy/web/edit");
        assert_eq!(safe_back(Some("/iplists?policy=a"), "/iplists"), "/iplists?policy=a");
        // Anything that could leave this server falls back instead.
        for away in ["https://elsewhere.example/x", "//elsewhere.example/x",
                     "javascript:alert(1)", "elsewhere.example", "", "   "] {
            assert_eq!(safe_back(Some(away), "/iplists"), "/iplists", "{away:?}");
        }
        assert_eq!(safe_back(None, "/iplists"), "/iplists");
    }

    #[test]
    fn a_plain_path_starts_a_query_string() {
        assert_eq!(flash_url("/policy", "success", "done"),
                   "/policy?result=success&msg=done");
    }

    #[test]
    fn a_path_that_already_has_a_query_string_extends_it() {
        // The Traffic Monitor case. A second '?' made the preceding parameter
        // swallow the rest of the URL, and axum refused to deserialise it.
        assert_eq!(
            flash_url("/traffic?site=a&blocked=1&hours=24", "success", "done"),
            "/traffic?site=a&blocked=1&hours=24&result=success&msg=done");
    }

    #[test]
    fn the_message_is_encoded_so_it_cannot_add_parameters() {
        // Messages carry rule names and addresses chosen elsewhere; one
        // containing & or = must not be able to invent a query parameter.
        let url = flash_url("/x", "failed", "a&b=c d");
        assert!(url.ends_with("msg=a%26b%3Dc%20d"), "{url}");
    }
}

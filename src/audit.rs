// =========================================================
// audit.rs — EasyWAF
// Who changed what through the management interface.
//
// One line per state-changing request, written by a layer on
// the management router rather than by each handler. Every
// such request is a POST — sixty-odd of them — and a trail
// that depends on sixty handlers each remembering to call a
// function is a trail with holes in it. The holes would be
// exactly where somebody did something they should not have.
//
// This is the same reasoning that made authorisation an
// extractor in 0.8.0: state the requirement once, where it
// cannot be forgotten.
//
// The line records what was done, never what it was done
// with. Method, path, account, address and outcome — no
// bodies, no query strings, so a certificate key, a password
// or a session secret cannot reach the file by being an
// argument to something.
// =========================================================

use crate::{auth::get_session, logging, AppState};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header::LOCATION, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::SignedCookieJar;
use chrono::Utc;
use std::net::SocketAddr;
use std::time::Instant;

/// Longest path recorded. Long enough for any route the GUI has, short enough
/// that one absurd URL cannot dominate a day's file.
const MAX_PATH: usize = 256;

/// Longest explanation recorded, which is the flash message a refused save
/// would have shown on screen.
const MAX_DETAIL: usize = 256;

/// Shown when nobody is signed in — a failed sign-in, or a POST from a browser
/// with no session. `-` rather than an empty field, so the column is never
/// missing.
const NOBODY: &str = "-";

// ─── Note ────────────────────────────────────────────────

/// What a handler knows that the router cannot see.
///
/// There is one case: signing in. The account is in the request body, which
/// this layer deliberately does not read, and a failed attempt returns 200
/// with the form re-rendered — indistinguishable from success by status alone.
/// The handler attaches the name and the outcome to its response instead.
///
/// Everything else is visible from the request and the response, and stays
/// that way: this is an escape hatch, not the interface.
#[derive(Clone, Debug, Default)]
pub struct Note {
    pub user:   Option<String>,
    pub result: Option<String>,
}

impl Note {
    /// A sign-in attempt by `user`, which either worked or did not.
    pub fn sign_in(user: &str, ok: bool) -> Self {
        Self {
            user:   Some(user.to_string()),
            result: Some(if ok { "ok" } else { "refused" }.to_string()),
        }
    }
}

// ─── The layer ───────────────────────────────────────────

/// Record one state-changing request, after it has been answered.
///
/// Runs on every management request and returns early for the ones that only
/// read, so the cost on a page view is a method comparison.
pub async fn record(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    jar: SignedCookieJar,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path   = req.uri().path().to_string();

    if !is_auditable(&method, &path) {
        return next.run(req).await;
    }

    // The cookie, not the database. Its signature has already been verified —
    // it is a name this server issued, not one a client made up — and whether
    // the session is still valid is the handler's answer, which shows up in
    // the status. A request refused for a stale session is worth a line
    // naming who presented it.
    let who = get_session(&jar);

    let started = Instant::now();
    let res     = next.run(req).await;
    let ms      = started.elapsed().as_millis();

    let note = res.extensions().get::<Note>().cloned().unwrap_or_default();
    let (result, detail) = outcome(&note, &res);

    state.logger.audit(line(&Event {
        user:   note.user.as_deref()
                    .or(who.as_ref().map(|s| s.username.as_str()))
                    .unwrap_or(NOBODY),
        role:   who.as_ref().map(|s| s.role.as_str()).unwrap_or(NOBODY),
        client: peer.ip().to_string(),
        method: method.as_str(),
        path:   &path,
        status: res.status().as_u16(),
        result: &result,
        detail: &detail,
        ms,
    }));

    res
}

/// Whether a request changes something.
///
/// Every state-changing route in the GUI is a POST, with one exception:
/// signing out is a link, so it is a GET. Taking "not a GET" alone would miss
/// it, and taking every GET would record page views — which is traffic, not an
/// audit trail.
fn is_auditable(method: &Method, path: &str) -> bool {
    if method == Method::GET || method == Method::HEAD {
        return path == "/logout";
    }
    true
}

// ─── The line ────────────────────────────────────────────

struct Event<'a> {
    user:   &'a str,
    role:   &'a str,
    client: String,
    method: &'a str,
    path:   &'a str,
    status: u16,
    result: &'a str,
    detail: &'a str,
    ms:     u128,
}

/// The same logfmt shape as the flow line, and the same escaping: a username
/// or a path arrives from outside and must not be able to invent a field.
fn line(e: &Event) -> String {
    let mut out = format!(
        "ts={} user={} role={} client={} method={} path={} status={} result={} ms={}",
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        logging::field(e.user),
        logging::field(e.role),
        logging::field(&e.client),
        logging::field(e.method),
        logging::field(&logging::clip(e.path, MAX_PATH)),
        e.status,
        logging::field(e.result),
        e.ms,
    );
    if !e.detail.is_empty() {
        out.push_str(&format!(
            " detail={}",
            logging::field(&logging::clip(e.detail, MAX_DETAIL))
        ));
    }
    out
}

/// What happened, and why if it did not work.
///
/// A handler that refuses a save redirects with `result=failed` and the
/// message the page would show. Reading it back out of the redirect is how the
/// line can say *why* a change did not happen — "Cipher suites: unknown suite"
/// rather than a bare 303 that looks exactly like a success.
fn outcome(note: &Note, res: &Response) -> (String, String) {
    if let Some(r) = &note.result {
        return (r.clone(), String::new());
    }

    if let Some(location) = res.headers().get(LOCATION).and_then(|v| v.to_str().ok())
        && let Some((result, msg)) = flash(location)
    {
        return (result, msg);
    }

    let status = res.status();
    let result = if status.is_success() || status.is_redirection() {
        "ok"
    } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        "refused"
    } else if status.is_client_error() {
        "failed"
    } else {
        "error"
    };
    (result.to_string(), String::new())
}

/// Pull `result` and `msg` back out of a flash redirect, if it carries them.
fn flash(location: &str) -> Option<(String, String)> {
    let query = location.split_once('?')?.1;
    let (mut result, mut msg) = (None, String::new());

    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else { continue };
        let decoded = urlencoding::decode(v).unwrap_or_else(|_| v.into()).to_string();
        match k {
            "result" => result = Some(decoded),
            "msg"    => msg = decoded,
            _        => {}
        }
    }

    // Only a failure carries an explanation worth keeping. A success message
    // restates what the request already said.
    match result?.as_str() {
        "success" => Some(("ok".to_string(), String::new())),
        other     => Some((other.to_string(), msg)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    fn event() -> Event<'static> {
        Event {
            user: "admin", role: "admin", client: "10.0.0.5".to_string(),
            method: "POST", path: "/settings/update", status: 303,
            result: "ok", detail: "", ms: 12,
        }
    }

    #[test]
    fn an_ordinary_change_records_who_what_and_where() {
        let out = line(&event());
        for expected in [
            "user=admin", "role=admin", "client=10.0.0.5",
            "method=POST", "path=/settings/update", "status=303", "result=ok",
        ] {
            assert!(out.contains(expected), "{expected} missing from: {out}");
        }
        assert!(out.starts_with("ts="), "the line must start with the time: {out}");
        assert!(!out.contains("detail="), "nothing to explain, so no detail field");
    }

    #[test]
    fn a_username_cannot_forge_a_field() {
        // The account name on a failed sign-in comes from the login form, so
        // it is whatever the attacker typed. A line that lies about who did
        // something is worse than no line.
        let e = Event { user: r#"x" result=ok user="root"#, ..event() };
        let out = line(&e);
        assert!(out.contains(r#"user="x\" result=ok user=\"root""#),
                "the name was not escaped: {out}");
        assert_eq!(out.matches("result=").count(), 2,
                   "the forged result must be inside the quotes: {out}");
    }

    #[test]
    fn only_state_changing_requests_are_recorded() {
        assert!(is_auditable(&Method::POST, "/settings/update"));
        assert!(is_auditable(&Method::DELETE, "/anything"));
        // Signing out is a link, so it is a GET, and it belongs in the trail.
        assert!(is_auditable(&Method::GET, "/logout"));
        // Page views are traffic, not an audit trail.
        assert!(!is_auditable(&Method::GET, "/settings"));
        assert!(!is_auditable(&Method::GET, "/static/css/style.css"));
        assert!(!is_auditable(&Method::HEAD, "/"));
    }

    #[test]
    fn a_refused_save_records_why() {
        // The reason is the message the operator saw on screen, which is the
        // difference between "something was refused" and a usable trail.
        let res = crate::routes::flash_redirect(
            "/settings", "failed", "Cipher suites: unknown suite 'TLS_NONSENSE'",
        ).unwrap();
        let (result, detail) = outcome(&Note::default(), &res);
        assert_eq!(result, "failed");
        assert_eq!(detail, "Cipher suites: unknown suite 'TLS_NONSENSE'");
    }

    #[test]
    fn a_successful_save_does_not_repeat_its_own_message() {
        let res = crate::routes::flash_redirect("/settings", "success", "Settings saved").unwrap();
        let (result, detail) = outcome(&Note::default(), &res);
        assert_eq!(result, "ok");
        assert_eq!(detail, "", "a success message restates the request");
    }

    #[test]
    fn a_refused_page_is_recorded_as_refused_not_failed() {
        // What a viewer gets from an administrator's page. It is the line
        // somebody reviewing the trail is looking for.
        let res = StatusCode::FORBIDDEN.into_response();
        assert_eq!(outcome(&Note::default(), &res).0, "refused");

        let res = StatusCode::INTERNAL_SERVER_ERROR.into_response();
        assert_eq!(outcome(&Note::default(), &res).0, "error");

        let res = StatusCode::OK.into_response();
        assert_eq!(outcome(&Note::default(), &res).0, "ok");
    }

    #[test]
    fn a_failed_sign_in_is_not_read_as_a_success() {
        // It answers 200 with the form again, so the status says nothing. The
        // handler's note is what makes the line true.
        let res = StatusCode::OK.into_response();
        assert_eq!(outcome(&Note::sign_in("admin", false), &res).0, "refused");
        assert_eq!(outcome(&Note::sign_in("admin", true), &res).0, "ok");
    }
}

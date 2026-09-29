// =========================================================
// routes/login.rs — EasyWAF
// Login / logout handlers.
// =========================================================

use crate::{
    audit,
    auth::{clear_session, get_session, set_session, SessionData},
    error::Result,
    AppState,
};
use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use bcrypt::verify;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tera::Context;

// ─── LoginForm ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginForm {
    pub user: String,
    pub pass: String,
}

// ─── get_login ───────────────────────────────────────────

/// GET /login — Render the login page.
pub async fn get_login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<Response> {
    // Validated against the database, not merely decoded.
    //
    // Deciding "already signed in" from the cookie alone, while every other
    // page decides it from the database, would loop: this page would send the
    // holder of a stale cookie to the dashboard, and the dashboard would send
    // them back here. A cookie goes stale whenever a session is ended — a
    // password change, a role change, a suspension — so ordinary use reaches
    // it.
    if crate::auth::authenticate(&state.db, &jar).await.is_some() {
        return Ok(Redirect::to("/").into_response());
    }

    // Nothing to sign in to yet. Every other handler already sends an
    // unauthenticated caller here, so this one redirect covers the whole GUI
    // without a middleware layer inspecting the database on every request.
    if crate::routes::setup::needs_setup(&state.db).await {
        return Ok(Redirect::to("/setup").into_response());
    }

    // A cookie that did not authenticate is spent — an ended session, a
    // suspended or deleted account. Dropped here so the browser stops
    // presenting it, rather than carrying it to every subsequent request.
    let jar = if get_session(&jar).is_some() {
        crate::auth::clear_session(jar)
    } else {
        jar
    };
    render_login(&state, "", "", jar).await
}

// ─── post_login ──────────────────────────────────────────

/// POST /login — Validate credentials and start session.
pub async fn post_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response> {
    // The address attempts are counted against: the connection's, or the
    // client a trusted proxy reported, as everywhere else.
    let client = crate::forwarded::client_ip(peer.ip(), &headers);
    if let Some(wait) = throttled(client) {
        tracing::warn!(%client, user = %form.user, "Sign-in refused: too many failed attempts from this address");
        let minutes = wait.as_secs().div_ceil(60).max(1);
        let msg = format!(
            "Too many failed sign-ins from this address. Try again in {minutes} minute{}.",
            if minutes == 1 { "" } else { "s" }
        );
        let mut res = render_login(&state, "failed", &msg, jar).await?;
        res.extensions_mut().insert(audit::Note::sign_in(&form.user, false));
        return Ok(res);
    }

    // The audit layer cannot see either half of this on its own: the account
    // is in the request body, which it does not read, and a refused sign-in
    // answers 200 with the form again — the same status as anything else that
    // renders a page. Both are attached to the response instead.
    match verify_credentials(&state.db, &form.user, &form.pass).await {
        Some(session) => {
            // Recorded so the account list can show a dormant account, which
            // is the usual reason to suspend one. Failure to write it must not
            // fail the sign-in: it is a convenience, not part of the decision.
            if let Err(e) = sqlx::query!(
                "UPDATE users SET last_login = datetime('now') WHERE id = ?",
                session.user_id
            )
            .execute(&state.db)
            .await
            {
                tracing::warn!(user = %session.username, "Could not record the sign-in time: {e}");
            }
            tracing::info!(user = %session.username, role = %session.role, "Signed in");
            forget_failures(client);
            let jar = set_session(jar, &session);
            let mut res = (jar, Redirect::to("/")).into_response();
            res.extensions_mut().insert(audit::Note::sign_in(&form.user, true));
            Ok(res)
        }
        None => {
            note_failure(client);
            let mut res =
                render_login(&state, "failed", "Bad username or password", jar).await?;
            // The name as typed, escaped when it is written: a failed sign-in
            // is the one line in the trail whose account is attacker-chosen.
            res.extensions_mut().insert(audit::Note::sign_in(&form.user, false));
            Ok(res)
        }
    }
}

// ─── get_logout ──────────────────────────────────────────

/// GET /logout — Clear session and redirect to login.
///
/// Recorded by the audit layer, which treats this one GET as state-changing:
/// it is a link rather than a form, and a trail with sign-ins but no sign-outs
/// leaves every session looking open.
pub async fn get_logout(jar: SignedCookieJar) -> impl IntoResponse {
    let jar = clear_session(jar);
    (jar, Redirect::to("/login"))
}

// ─── verify_credentials ──────────────────────────────────

/// Look up the account and verify the password. `None` on any failure.
///
/// A suspended account is refused here as well as in `auth::authenticate`, so
/// it cannot obtain a new session in the first place rather than obtaining one
/// that is rejected on its next request.
///
/// The failure is deliberately not distinguished between "no such account",
/// "wrong password" and "suspended": the caller reports one message for all
/// three, so a login form cannot be used to enumerate which accounts exist.
async fn verify_credentials(
    db: &SqlitePool,
    username: &str,
    password: &str,
) -> Option<SessionData> {
    let row = sqlx::query!(
        r#"SELECT id as "id!", password_hash, role as "role!",
                  enabled as "enabled!: i64", session_epoch as "session_epoch!"
           FROM users WHERE username = ?"#,
        username
    )
    .fetch_optional(db)
    .await
    .ok()?;

    // An unknown name costs the same password check a known one does.
    // Refused at once, it would take about 2 ms against 230, and the time a
    // refusal took would say whether the account existed, whatever the
    // message.
    let Some(row) = row else {
        let _ = verify(password, stand_in_hash());
        return None;
    };

    if !verify(password, &row.password_hash).unwrap_or(false) {
        return None;
    }
    if row.enabled == 0 {
        tracing::warn!(username, "Sign-in refused: the account is suspended");
        return None;
    }

    // The epoch is captured now, so this cookie survives until something
    // deliberately ends it — a password change, a role change, a suspension.
    Some(SessionData {
        user_id:  row.id,
        username: username.to_string(),
        role:     row.role,
        epoch:    row.session_epoch,
        issued:   chrono::Utc::now().timestamp(),
    })
}

/// A hash to check a password against when no account has the name given, so
/// that refusal takes as long as a wrong password does. Made once, at the cost
/// every stored hash uses.
fn stand_in_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        bcrypt::hash("no account has this name", bcrypt::DEFAULT_COST).unwrap_or_default()
    })
}

// ─── Throttling ──────────────────────────────────────────
//
// How fast passwords can be guessed. Attempts are counted per address, not per
// account: locking an account would let anyone who knows its name keep the
// administrator out.

/// Failed sign-ins an address may make within [`WINDOW`].
const MAX_FAILURES: u32 = 10;

/// How long failures are remembered, counted from the first. An address that
/// reaches [`MAX_FAILURES`] is refused until the window ends.
const WINDOW: Duration = Duration::from_secs(15 * 60);

/// Addresses held at most, so a spread of guessing addresses cannot grow the
/// table without end. Expired entries are dropped when it fills.
const MAX_TRACKED: usize = 10_000;

struct Failures {
    count: u32,
    since: Instant,
}

fn failures() -> &'static Mutex<HashMap<IpAddr, Failures>> {
    static FAILURES: OnceLock<Mutex<HashMap<IpAddr, Failures>>> = OnceLock::new();
    FAILURES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How much longer this address must wait, if it has used up its attempts.
fn throttled(client: IpAddr) -> Option<Duration> {
    let map = failures().lock().unwrap_or_else(|p| p.into_inner());
    let f = map.get(&client)?;
    let elapsed = f.since.elapsed();
    (f.count >= MAX_FAILURES && elapsed < WINDOW).then(|| WINDOW - elapsed)
}

/// Count a failed sign-in against this address.
fn note_failure(client: IpAddr) {
    let mut map = failures().lock().unwrap_or_else(|p| p.into_inner());
    if map.len() >= MAX_TRACKED {
        map.retain(|_, f| f.since.elapsed() < WINDOW);
    }
    let f = map.entry(client).or_insert(Failures { count: 0, since: Instant::now() });
    if f.since.elapsed() >= WINDOW {
        *f = Failures { count: 0, since: Instant::now() };
    }
    f.count += 1;
}

/// A successful sign-in clears the address's count.
fn forget_failures(client: IpAddr) {
    failures().lock().unwrap_or_else(|p| p.into_inner()).remove(&client);
}

// ─── render_login ────────────────────────────────────────

/// Render the login template with optional result/msg.
async fn render_login(
    state: &AppState,
    result: &str,
    msg: &str,
    jar: SignedCookieJar,
) -> Result<Response> {
    let mut ctx = Context::new();
    ctx.insert("result", result);
    ctx.insert("msg", msg);
    let html = state.tera.render("login.html", &ctx)?;
    Ok((jar, Html(html)).into_response())
}

#[cfg(test)]
mod throttle_tests {
    use super::*;

    #[test]
    fn an_address_is_refused_after_too_many_failures_and_others_are_not() {
        let guesser: IpAddr = "198.51.100.77".parse().unwrap();
        let other:   IpAddr = "198.51.100.78".parse().unwrap();
        for _ in 0..MAX_FAILURES - 1 {
            note_failure(guesser);
        }
        assert!(throttled(guesser).is_none(), "refused before the limit");
        note_failure(guesser);
        let wait = throttled(guesser).expect("not refused at the limit");
        assert!(wait <= WINDOW && wait > WINDOW - Duration::from_secs(5));
        assert!(throttled(other).is_none(), "another address was refused with it");

        forget_failures(guesser);
        assert!(throttled(guesser).is_none(), "a successful sign-in did not clear the count");
    }
}

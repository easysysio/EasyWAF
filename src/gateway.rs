// =========================================================
// gateway.rs — EasyWAF
// The sign-in gateway: a site, or paths within it, that a
// visitor has to sign in to reach.
//
// The rules ask what a request is, and the CAPTCHA asks
// whether there is a person. This asks who they are — which
// is not a property of a request. It is established once and
// carried, so it needs a session and the other two do not.
//
// What is here is the part that can be reasoned about on its
// own: where identities come from (a realm), which paths ask
// for one, the session a sign-in buys, how fast passwords
// can be guessed, and the page that asks. The request path
// in proxy/mod.rs decides when each is used.
//
// Three properties everything below is written to keep:
//
//   * A session is not bound to the client's address. A phone
//     moving from wifi to its carrier would be signed out, and
//     on a network where every client arrives as the router,
//     one sign-in would sign in everybody.
//   * Site identities are not the `users` table. Those are the
//     accounts that open EasyWAF itself.
//   * The headers that name the visitor to the application are
//     removed from every request before they are set. A client
//     that could send one would not need to sign in.
// =========================================================

use crate::smart_protect::SlidingCounter;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

/// The session cookie. Not the management interface's name: a site and the
/// interface can share a hostname, and a browser keeps cookies by host, not
/// by port.
pub const SESSION_COOKIE: &str = "easywaf_gate";

/// Where the sign-in form is posted, and where a visitor goes to sign out. On
/// the site's own hostname, under the prefix the CAPTCHA already reserves.
pub const LOGIN_PATH: &str = "/__easywaf/login";
pub const LOGOUT_PATH: &str = "/__easywaf/logout";

/// How stale a session's "last seen" may get before the cookie is minted
/// again. The idle timeout slides by re-issuing the cookie as it is used, and
/// doing that on every response would be a header on every response.
const REFRESH_AFTER_SECS: i64 = 60;

/// How far ahead of this clock a cookie's times may be and still be believed.
const CLOCK_SKEW_SECS: i64 = 60;

// ─── Realms ──────────────────────────────────────────────

/// Where a realm's identities come from.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// Accounts kept in EasyWAF's own database.
    Local,
    /// A directory, asked at each sign-in.
    Ldap(LdapConfig),
}

/// How to ask a directory whether a password is somebody's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LdapConfig {
    /// `ldap://host[:port]` or `ldaps://host[:port]`.
    pub url:           String,
    /// Upgrade an `ldap://` connection with StartTLS before anything is sent.
    pub starttls:      bool,
    /// Check the directory's certificate. On unless switched off.
    pub verify_tls:    bool,
    /// The account searches are made as. Empty searches anonymously.
    pub bind_dn:       String,
    pub bind_password: String,
    /// Where under the directory to look for users.
    pub base_dn:       String,
    /// The search that finds one user. `{user}` is the name typed, escaped.
    /// Whatever else it requires — membership of a group — is who may sign in.
    pub user_filter:   String,
    /// The attribute of a user's entry that lists their groups, for the
    /// header the application is sent. Empty sends none.
    pub groups_attribute: String,
}

/// A directory nobody has described yet: its certificate is checked, and a
/// person is found by `uid`, which is where most directories keep the name.
impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url:              String::new(),
            starttls:         false,
            verify_tls:       true,
            bind_dn:          String::new(),
            bind_password:    String::new(),
            base_dn:          String::new(),
            user_filter:      "(uid={user})".to_string(),
            groups_attribute: String::new(),
        }
    }
}

/// One account of a local realm, as a sign-in and a session need it.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalUser {
    pub password_hash: String,
    pub enabled:       bool,
    /// Raised to end this account's sessions.
    pub epoch:         i64,
}

/// A source of identities, and how long a sign-in from it lasts.
#[derive(Debug, Clone, PartialEq)]
pub struct Realm {
    pub id:      i64,
    pub name:    String,
    pub kind:    Kind,
    /// How long a sign-in lasts whatever the visitor does.
    pub session: Duration,
    /// How long it lasts unused.
    pub idle:    Duration,
    /// Raised to end every session of the realm.
    pub epoch:   i64,
    /// A local realm's accounts, by name. Held in memory with the realm so a
    /// request that carries a session costs no query to check it.
    pub users:   HashMap<String, LocalUser>,
}

// ─── A site's settings ───────────────────────────────────

/// What a site asks of its visitors.
#[derive(Debug, Clone)]
pub struct SiteAuth {
    pub realm:         Arc<Realm>,
    /// Path prefixes that need a sign-in. Empty means every path.
    pub protect:       Vec<String>,
    /// Path prefixes that never do.
    pub bypass:        Vec<String>,
    /// Whether HTTP Basic is accepted in place of the form.
    pub basic:         bool,
    pub user_header:   HeaderName,
    pub groups_header: HeaderName,
}

impl SiteAuth {
    /// Whether a request for `path` has to be signed in.
    ///
    /// Decided on the path as the application will read it, in every reading a
    /// server may make of it — not as it was written. Written is what the
    /// visitor controls: `/public/../admin` is under `/public` as typed and is
    /// `/admin` when it arrives, and `//admin` is not under `/admin` until a
    /// server merges the slashes. If any reading needs a sign-in, the request
    /// does.
    ///
    /// A protected prefix is matched without regard to case, since a backend
    /// that ignores case serves `/Admin` as `/admin`. A bypass is matched
    /// exactly: reading it loosely could only open more than was meant.
    pub fn needs_sign_in(&self, path: &str) -> bool {
        let mut readings = vec![crate::modules::waf::path_as_forwarded(path)];
        readings.extend(crate::modules::waf::normalised_paths(path));
        readings.iter().any(|read| {
            let protected = self.protect.is_empty()
                || self.protect.iter().any(|p| under(&read.to_ascii_lowercase(), &p.to_ascii_lowercase()));
            let bypassed = self.bypass.iter().any(|b| under(read, b));
            protected && !bypassed
        })
    }

    /// Remove what a client must never be able to say for itself, and what is
    /// the gateway's own: the two identity headers, and the session cookie,
    /// which the application has no use for and should not be handed.
    pub fn strip(&self, headers: &mut HeaderMap) {
        headers.remove(&self.user_header);
        headers.remove(&self.groups_header);
        strip_cookie(headers, SESSION_COOKIE);
    }

    /// Tell the application who the visitor is.
    pub fn announce(&self, headers: &mut HeaderMap, who: &Identity) {
        if let Ok(v) = HeaderValue::from_str(&who.subject) {
            headers.insert(self.user_header.clone(), v);
        }
        if !who.groups.is_empty()
            && let Ok(v) = HeaderValue::from_str(&who.groups.join(","))
        {
            headers.insert(self.groups_header.clone(), v);
        }
    }
}

/// `path` is `prefix` or below it, a whole segment at a time. A prefix is
/// written with or without its trailing slash and means the same.
fn under(path: &str, prefix: &str) -> bool {
    let prefix = if prefix.len() > 1 { prefix.trim_end_matches('/') } else { prefix };
    crate::modules::waf::under_prefix(path, prefix)
}

/// Path prefixes as an administrator typed them, one per line or separated by
/// commas: trimmed, each beginning with a slash, no duplicates. The second
/// value is what was typed that is not a path.
pub fn parse_prefixes(raw: &str) -> (Vec<String>, Vec<String>) {
    let (mut ok, mut bad) = (Vec::new(), Vec::new());
    for token in raw.split(['\n', '\r', ',']).map(str::trim).filter(|t| !t.is_empty()) {
        if token.starts_with('/') && !token.contains(char::is_whitespace) && !token.contains(['?', '#']) {
            if !ok.iter().any(|p| p == token) {
                ok.push(token.to_string());
            }
        } else {
            bad.push(token.to_string());
        }
    }
    (ok, bad)
}

/// Drop one cookie from the `Cookie` header, leaving the rest as they were.
fn strip_cookie(headers: &mut HeaderMap, name: &str) {
    let Some(raw) = headers.get(axum::http::header::COOKIE) else { return };
    let text = String::from_utf8_lossy(raw.as_bytes()).into_owned();
    let kept: Vec<&str> = text
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty() && pair.split_once('=').map_or(*pair, |(k, _)| k) != name)
        .collect();
    if kept.len() == text.split(';').filter(|p| !p.trim().is_empty()).count() {
        return;
    }
    match HeaderValue::from_bytes(kept.join("; ").as_bytes()) {
        Ok(v) if !kept.is_empty() => { headers.insert(axum::http::header::COOKIE, v); }
        _ => { headers.remove(axum::http::header::COOKIE); }
    }
}

// ─── Identity and the session ────────────────────────────

/// Who a visitor proved to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    /// The groups a directory lists for them. Empty for a local account.
    pub groups:  Vec<String>,
}

/// A session read from a cookie and found good.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub who:     Identity,
    /// When the visitor signed in, which the absolute lifetime runs from.
    pub issued:  i64,
    /// The account's epoch the cookie was minted with.
    pub user_epoch: i64,
    /// The cookie is due to be minted again so the idle timeout slides.
    pub refresh: bool,
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn unb64(s: &str) -> Option<String> {
    String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()?).ok()
}

/// A session cookie's value:
///
/// ```text
/// v1.<realm>.<subject>.<groups>.<issued>.<seen>.<realm epoch>.<account epoch>.<signature>
/// ```
///
/// Signed over every field and the site's id, so a cookie for one site means
/// nothing to another that uses the same realm. Subject and groups are
/// base64url: a name may hold a dot, and the dot is the separator.
pub fn mint(secret: &str, site_id: i64, realm: &Realm, who: &Identity, user_epoch: i64, issued: i64, seen: i64) -> String {
    let body = format!(
        "v1.{}.{}.{}.{}.{}.{}.{}",
        realm.id, b64(&who.subject), b64(&who.groups.join("\n")), issued, seen, realm.epoch, user_epoch
    );
    let sig = sign(secret, site_id, &body);
    format!("{body}.{sig}")
}

fn sign(secret: &str, site_id: i64, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"gate|");
    mac.update(site_id.to_string().as_bytes());
    mac.update(b"|");
    mac.update(body.as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The session a cookie holds, if it is one this site would still honour.
///
/// Refused, each for something an administrator can do and expects to take
/// effect: a signature that is not ours or was made for another site; a realm
/// the site no longer uses; a realm or an account whose epoch has moved since;
/// an account that is gone or disabled; and a session past its lifetime or
/// left idle too long.
pub fn read(secret: &str, site_id: i64, realm: &Realm, cookie: &str, now: i64) -> Option<Session> {
    let (body, sig) = cookie.rsplit_once('.')?;
    if !same(sig.as_bytes(), sign(secret, site_id, body).as_bytes()) {
        return None;
    }
    let f: Vec<&str> = body.split('.').collect();
    let [version, realm_id, subject, groups, issued, seen, realm_epoch, user_epoch] = f[..] else {
        return None;
    };
    if version != "v1" || realm_id.parse::<i64>().ok()? != realm.id {
        return None;
    }
    let (issued, seen): (i64, i64) = (issued.parse().ok()?, seen.parse().ok()?);
    let (realm_epoch, user_epoch): (i64, i64) = (realm_epoch.parse().ok()?, user_epoch.parse().ok()?);
    if realm_epoch != realm.epoch {
        return None;
    }
    let subject = unb64(subject)?;
    if realm.kind == Kind::Local {
        let user = realm.users.get(&subject)?;
        if !user.enabled || user.epoch != user_epoch {
            return None;
        }
    }
    if issued > now + CLOCK_SKEW_SECS || seen > now + CLOCK_SKEW_SECS || seen < issued {
        return None;
    }
    if now >= issued + realm.session.as_secs() as i64 || now >= seen + realm.idle.as_secs() as i64 {
        return None;
    }
    let groups = unb64(groups)?;
    Some(Session {
        who: Identity {
            subject,
            groups: groups.split('\n').filter(|g| !g.is_empty()).map(str::to_string).collect(),
        },
        issued,
        user_epoch,
        refresh: now - seen >= REFRESH_AFTER_SECS,
    })
}

/// The `Set-Cookie` value that carries a session.
///
/// `Secure` always: the gateway is offered over HTTPS only. `SameSite=Lax` so
/// that following a link to the site arrives signed in. `Max-Age` is the idle
/// timeout, since an unused cookie is refused after it anyway.
pub fn set_cookie(value: &str, realm: &Realm) -> String {
    format!(
        "{SESSION_COOKIE}={value}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
        realm.idle.as_secs().min(realm.session.as_secs())
    )
}

/// The `Set-Cookie` value that removes it.
pub fn clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

// ─── Checking a password ─────────────────────────────────

/// A hash to check against when a local realm has no account of the name
/// given, so that refusal takes as long as a wrong password does and the time
/// it took does not say which it was.
fn stand_in_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| bcrypt::hash("no account has this name", bcrypt::DEFAULT_COST).unwrap_or_default())
}

/// Whether `password` is `username`'s in this realm, and if so who they are
/// and their account's epoch.
///
/// One answer for every way of failing — no such account, wrong password,
/// disabled, the directory unreachable — so the form cannot be used to learn
/// which names exist. What went wrong with a directory is returned beside it
/// for the log, never for the page.
pub async fn check_password(realm: &Realm, username: &str, password: &str) -> (Option<(Identity, i64)>, Option<String>) {
    // An empty password is refused before anything is asked. To a directory,
    // a bind with a name and no password is an anonymous bind, and succeeds.
    if username.is_empty() || password.is_empty() {
        return (None, None);
    }
    match &realm.kind {
        Kind::Local => {
            let user = realm.users.get(username).cloned();
            let hash = user.as_ref().map_or_else(|| stand_in_hash().to_string(), |u| u.password_hash.clone());
            let password = password.to_string();
            // bcrypt is a quarter of a second of arithmetic, and must not be
            // done on a thread that is serving other requests.
            let matches = tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
                .await
                .unwrap_or(false);
            match user {
                Some(u) if matches && u.enabled => (
                    Some((Identity { subject: username.to_string(), groups: Vec::new() }, u.epoch)),
                    None,
                ),
                _ => (None, None),
            }
        }
        Kind::Ldap(cfg) => match ldap_check(cfg, username, password).await {
            Ok(Some(who)) => (Some((who, 0)), None),
            Ok(None)      => (None, None),
            Err(e)        => (None, Some(e)),
        },
    }
}

/// How long a directory is given to answer before a sign-in is refused.
const LDAP_TIMEOUT: Duration = Duration::from_secs(10);

/// Ask a directory. `Ok(None)` is the directory saying no; `Err` is the
/// directory not being asked successfully, which is the administrator's
/// problem and not the visitor's.
///
/// Search, then bind: the service account finds the one entry the filter
/// matches for this name, and the password is checked by binding as that
/// entry. A filter that matches nobody or several people signs nobody in.
pub async fn ldap_check(cfg: &LdapConfig, username: &str, password: &str) -> Result<Option<Identity>, String> {
    if password.is_empty() {
        return Ok(None);
    }
    tokio::time::timeout(LDAP_TIMEOUT, ldap_ask(cfg, username, password))
        .await
        .map_err(|_| format!("{} did not answer within {} seconds", cfg.url, LDAP_TIMEOUT.as_secs()))?
}

async fn ldap_ask(cfg: &LdapConfig, username: &str, password: &str) -> Result<Option<Identity>, String> {
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

    let settings = LdapConnSettings::new()
        .set_conn_timeout(LDAP_TIMEOUT)
        .set_starttls(cfg.starttls)
        .set_no_tls_verify(!cfg.verify_tls);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &cfg.url)
        .await
        .map_err(|e| format!("could not connect to {}: {e}", cfg.url))?;
    ldap3::drive!(conn);

    if !cfg.bind_dn.is_empty() {
        ldap.simple_bind(&cfg.bind_dn, &cfg.bind_password)
            .await
            .and_then(|r| r.success())
            .map_err(|e| format!("the search account could not bind: {e}"))?;
    }

    let filter = cfg.user_filter.replace("{user}", &ldap3::ldap_escape(username));
    let attrs: Vec<&str> = if cfg.groups_attribute.is_empty() { vec!["1.1"] } else { vec![&cfg.groups_attribute] };
    let (entries, _) = ldap
        .search(&cfg.base_dn, Scope::Subtree, &filter, attrs)
        .await
        .and_then(|r| r.success())
        .map_err(|e| format!("the search for a user failed: {e}"))?;

    // Exactly one. Several entries for one name is a filter too loose to
    // trust with a sign-in, and the visitor is not signed in as any of them.
    if entries.len() != 1 {
        let _ = ldap.unbind().await;
        return Ok(None);
    }
    let entry = SearchEntry::construct(entries.into_iter().next().expect("one entry"));

    let bound = ldap.simple_bind(&entry.dn, password).await.and_then(|r| r.success()).is_ok();
    let _ = ldap.unbind().await;
    if !bound {
        return Ok(None);
    }

    let groups = entry
        .attrs
        .get(&cfg.groups_attribute)
        .map(|values| values.iter().map(|dn| group_name(dn)).collect())
        .unwrap_or_default();
    Ok(Some(Identity { subject: username.to_string(), groups }))
}

/// A group as an application wants to read it: `staff`, from
/// `cn=staff,ou=groups,dc=example,dc=com`. A value that is not a DN is passed
/// as it is.
fn group_name(value: &str) -> String {
    value
        .split(',')
        .next()
        .and_then(|first| first.split_once('='))
        .map_or_else(|| value.trim().to_string(), |(_, name)| name.trim().to_string())
}

// ─── How fast passwords can be guessed ───────────────────
//
// A sign-in form on the edge is tried against lists of passwords from the hour
// it goes up. Failures are counted two ways, in memory, and are gone on a
// restart.
//
// Per address, strictly: ten failures and the address waits. Per name, across
// every address, loosely: a name being tried from a thousand addresses is
// slowed too, but at a count no one person reaches by mistyping — because
// refusing a name is something anybody who knows it can do to its owner.

/// Failures an address may make within [`WINDOW`].
const MAX_FAILURES_PER_ADDRESS: usize = 10;

/// Failures a name may collect within [`WINDOW`], from everywhere.
const MAX_FAILURES_PER_NAME: usize = 50;

/// How long failures are remembered, and so how long a refusal lasts at most.
const WINDOW: Duration = Duration::from_secs(10 * 60);

/// How many addresses and names are counted at once.
const MAX_COUNTED: usize = 50_000;

struct Throttle {
    addresses: SlidingCounter<IpAddr>,
    names:     SlidingCounter<(i64, String)>,
}

fn throttle() -> &'static Mutex<Throttle> {
    static T: OnceLock<Mutex<Throttle>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(Throttle {
        addresses: SlidingCounter::new(MAX_COUNTED),
        names:     SlidingCounter::new(MAX_COUNTED),
    }))
}

/// Whether a sign-in from this address, for this name, is refused unheard.
pub fn throttled(realm_id: i64, username: &str, address: IpAddr) -> bool {
    let now = Instant::now();
    let t = throttle().lock().unwrap_or_else(|p| p.into_inner());
    t.addresses.count(&address, now, WINDOW) >= MAX_FAILURES_PER_ADDRESS
        || t.names.count(&(realm_id, username.to_lowercase()), now, WINDOW) >= MAX_FAILURES_PER_NAME
}

/// Count a failed sign-in.
pub fn note_failure(realm_id: i64, username: &str, address: IpAddr) {
    let now = Instant::now();
    let mut t = throttle().lock().unwrap_or_else(|p| p.into_inner());
    t.addresses.record(address, now, WINDOW, MAX_FAILURES_PER_ADDRESS);
    t.names.record((realm_id, username.to_lowercase()), now, WINDOW, MAX_FAILURES_PER_NAME);
}

/// A sign-in succeeded: the address is not guessing.
pub fn note_success(address: IpAddr) {
    throttle().lock().unwrap_or_else(|p| p.into_inner()).addresses.forget(&address);
}

// ─── HTTP Basic ──────────────────────────────────────────

/// The name and password of an `Authorization: Basic` header.
pub fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// How long a Basic credential that was checked is taken as checked. A client
/// using Basic sends it with every request, and each check is a bcrypt or a
/// round trip to a directory.
const BASIC_REMEMBERED: Duration = Duration::from_secs(60);

/// How many are remembered.
const MAX_BASIC_REMEMBERED: usize = 10_000;

struct Remembered {
    who:        Identity,
    user_epoch: i64,
    until:      Instant,
}

fn basic_cache() -> &'static Mutex<HashMap<[u8; 32], Remembered>> {
    static C: OnceLock<Mutex<HashMap<[u8; 32], Remembered>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// What a Basic credential is remembered under: a digest, keyed with the
/// installation's secret, so the table holds no password and its keys cannot
/// be tried offline.
fn basic_key(secret: &str, realm: &Realm, username: &str, password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [secret, &realm.id.to_string(), &realm.epoch.to_string(), username, password] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().into()
}

/// Check a Basic credential, remembering a good one for a minute.
///
/// A remembered answer is still checked against the realm as it is now: a
/// local account disabled or signed out since is refused at once.
pub async fn check_basic(secret: &str, realm: &Realm, username: &str, password: &str) -> (Option<Identity>, Option<String>) {
    let key = basic_key(secret, realm, username, password);
    let now = Instant::now();
    {
        let mut cache = basic_cache().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(r) = cache.get(&key) {
            let still_good = r.until > now
                && (realm.kind != Kind::Local
                    || realm.users.get(username).is_some_and(|u| u.enabled && u.epoch == r.user_epoch));
            if still_good {
                return (Some(r.who.clone()), None);
            }
            cache.remove(&key);
        }
    }
    let (checked, trouble) = check_password(realm, username, password).await;
    let Some((who, user_epoch)) = checked else { return (None, trouble) };
    let mut cache = basic_cache().lock().unwrap_or_else(|p| p.into_inner());
    if cache.len() >= MAX_BASIC_REMEMBERED {
        cache.retain(|_, r| r.until > now);
        if cache.len() >= MAX_BASIC_REMEMBERED {
            cache.clear();
        }
    }
    cache.insert(key, Remembered { who: who.clone(), user_epoch, until: now + BASIC_REMEMBERED });
    (Some(who), None)
}

// ─── The page ────────────────────────────────────────────

/// What the sign-in page has to say besides asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    None,
    /// The name or password was not right. One message for every reason.
    Refused,
    /// Too many failures; come back later.
    Throttled,
    /// The visitor signed out.
    SignedOut,
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// The sign-in page. Self-contained, like the CAPTCHA's: nothing is fetched
/// from anywhere, and nothing of the site behind it is shown.
pub fn login_page(host: &str, dest: &str, notice: Notice) -> String {
    let notice = match notice {
        Notice::None      => String::new(),
        Notice::Refused   => r#"<p class="note bad">That name and password were not accepted.</p>"#.to_string(),
        Notice::Throttled => r#"<p class="note bad">Too many attempts. Try again in a few minutes.</p>"#.to_string(),
        Notice::SignedOut => r#"<p class="note">You have signed out.</p>"#.to_string(),
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a;
         color:#f1f5f9; display:flex; min-height:100vh; margin:0; align-items:center;
         justify-content:center; }}
  .card {{ background:#111827; border:1px solid rgba(255,255,255,0.08); border-radius:14px;
           padding:32px 36px; max-width:360px; width:100%; box-shadow:0 8px 32px rgba(0,0,0,0.4); }}
  h1 {{ font-size:18px; margin:0 0 6px; }}
  p.sub {{ color:#94a3b8; font-size:13px; margin:0 0 20px; word-break:break-all; }}
  p.note {{ font-size:13px; margin:0 0 14px; color:#94a3b8; }}
  p.note.bad {{ color:#f87171; }}
  label {{ display:block; font-size:12px; color:#94a3b8; margin:0 0 4px; }}
  input[type=text], input[type=password] {{ width:100%; box-sizing:border-box; padding:11px 14px;
           font-size:15px; background:#0b1120; border:1px solid rgba(255,255,255,0.12);
           border-radius:8px; color:#f1f5f9; margin-bottom:14px; }}
  button {{ width:100%; padding:11px; font-size:15px; font-weight:600; border:none;
           border-radius:8px; background:linear-gradient(135deg,#0ea5e9,#0284c7); color:#fff;
           cursor:pointer; }}
  .foot {{ color:#64748b; font-size:11px; margin-top:18px; text-align:center; }}
</style>
</head>
<body>
  <div class="card">
    <h1>Sign in</h1>
    <p class="sub">{host}</p>
    {notice}
    <form method="post" action="{login}">
      <input type="hidden" name="dest" value="{dest}">
      <label for="user">Name</label>
      <input type="text" id="user" name="user" autocomplete="username" autocapitalize="none" autofocus required>
      <label for="pass">Password</label>
      <input type="password" id="pass" name="pass" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
    <div class="foot">Protected by EasyWAF</div>
  </div>
</body>
</html>"#,
        host = escape(host),
        dest = escape(dest),
        login = LOGIN_PATH,
    )
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn local_realm() -> Realm {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), LocalUser {
            password_hash: bcrypt::hash("correct horse", 4).unwrap(),
            enabled: true,
            epoch: 0,
        });
        Realm {
            id: 7, name: "staff".into(), kind: Kind::Local,
            session: Duration::from_secs(8 * 3600), idle: Duration::from_secs(3600),
            epoch: 0, users,
        }
    }

    fn alice() -> Identity {
        Identity { subject: "alice".into(), groups: Vec::new() }
    }

    fn site(protect: &[&str], bypass: &[&str]) -> SiteAuth {
        SiteAuth {
            realm: Arc::new(local_realm()),
            protect: protect.iter().map(|s| s.to_string()).collect(),
            bypass: bypass.iter().map(|s| s.to_string()).collect(),
            basic: false,
            user_header: HeaderName::from_static("x-forwarded-user"),
            groups_header: HeaderName::from_static("x-forwarded-groups"),
        }
    }

    const SECRET: &str = "a secret that is long enough to be one";
    const NOW: i64 = 1_800_000_000;

    #[test]
    fn a_session_is_read_back_as_it_was_minted() {
        let realm = local_realm();
        let who = Identity { subject: "john.doe@example.com".into(), groups: vec!["staff".into(), "ops".into()] };
        let mut realm_with = realm.clone();
        realm_with.users.insert(who.subject.clone(), realm.users["alice"].clone());
        let cookie = mint(SECRET, 3, &realm_with, &who, 0, NOW, NOW);
        let s = read(SECRET, 3, &realm_with, &cookie, NOW + 10).expect("a fresh session was refused");
        assert_eq!(s.who, who);
        assert!(!s.refresh);
    }

    #[test]
    fn a_session_is_good_for_one_site_and_one_secret() {
        let realm = local_realm();
        let cookie = mint(SECRET, 3, &realm, &alice(), 0, NOW, NOW);
        assert!(read(SECRET, 3, &realm, &cookie, NOW).is_some());
        assert!(read(SECRET, 4, &realm, &cookie, NOW).is_none(), "another site on the same realm took it");
        assert!(read("another installation's secret", 3, &realm, &cookie, NOW).is_none());
    }

    #[test]
    fn a_session_cannot_be_edited() {
        let realm = local_realm();
        let cookie = mint(SECRET, 3, &realm, &alice(), 0, NOW, NOW);
        // Somebody else's name under alice's signature.
        let forged = cookie.replacen(&b64("alice"), &b64("admin"), 1);
        assert!(read(SECRET, 3, &realm, &forged, NOW).is_none());
        // A later "last seen", to outlive the idle timeout.
        let stretched = cookie.replacen(&format!(".{NOW}.{NOW}."), &format!(".{NOW}.{}.", NOW + 30), 1);
        assert_ne!(stretched, cookie);
        assert!(read(SECRET, 3, &realm, &stretched, NOW + 30).is_none());
        for junk in ["", "v1", "v1.7.x.y.z", "........", &cookie[..cookie.len() - 1]] {
            assert!(read(SECRET, 3, &realm, junk, NOW).is_none(), "{junk:?}");
        }
    }

    #[test]
    fn a_session_ends_when_its_time_is_up_or_it_sits_unused() {
        let realm = local_realm();
        let cookie = mint(SECRET, 3, &realm, &alice(), 0, NOW, NOW);
        assert!(read(SECRET, 3, &realm, &cookie, NOW + 3599).is_some());
        assert!(read(SECRET, 3, &realm, &cookie, NOW + 3600).is_none(), "idle for the whole timeout");

        // Used all day: the cookie is minted again as it goes, and still ends
        // at the absolute lifetime.
        let used = mint(SECRET, 3, &realm, &alice(), 0, NOW, NOW + 8 * 3600 - 30);
        assert!(read(SECRET, 3, &realm, &used, NOW + 8 * 3600 - 1).is_some());
        assert!(read(SECRET, 3, &realm, &used, NOW + 8 * 3600).is_none(), "past the absolute lifetime");
    }

    #[test]
    fn a_session_is_due_a_new_cookie_once_it_has_gone_a_minute() {
        let realm = local_realm();
        let cookie = mint(SECRET, 3, &realm, &alice(), 0, NOW, NOW);
        assert!(!read(SECRET, 3, &realm, &cookie, NOW + 59).unwrap().refresh);
        assert!(read(SECRET, 3, &realm, &cookie, NOW + 60).unwrap().refresh);
    }

    #[test]
    fn what_an_administrator_does_ends_a_session_at_once() {
        let realm = local_realm();
        let cookie = mint(SECRET, 3, &realm, &alice(), 0, NOW, NOW);

        let mut everyone_out = realm.clone();
        everyone_out.epoch += 1;
        assert!(read(SECRET, 3, &everyone_out, &cookie, NOW).is_none(), "sign everyone out");

        let mut disabled = realm.clone();
        disabled.users.get_mut("alice").unwrap().enabled = false;
        assert!(read(SECRET, 3, &disabled, &cookie, NOW).is_none(), "a disabled account");

        let mut new_password = realm.clone();
        new_password.users.get_mut("alice").unwrap().epoch += 1;
        assert!(read(SECRET, 3, &new_password, &cookie, NOW).is_none(), "a changed password");

        let mut deleted = realm.clone();
        deleted.users.clear();
        assert!(read(SECRET, 3, &deleted, &cookie, NOW).is_none(), "a deleted account");

        let mut other_realm = realm.clone();
        other_realm.id = 8;
        assert!(read(SECRET, 3, &other_realm, &cookie, NOW).is_none(), "the site moved to another realm");
    }

    #[test]
    fn a_whole_site_is_protected_unless_paths_are_named() {
        let all = site(&[], &[]);
        for p in ["/", "/index.html", "/a/b/c", "/__easywaf/anything"] {
            assert!(all.needs_sign_in(p), "{p}");
        }
        let some = site(&["/admin", "/settings/"], &[]);
        for p in ["/admin", "/admin/", "/admin/users", "/settings", "/settings/profile"] {
            assert!(some.needs_sign_in(p), "{p}");
        }
        for p in ["/", "/administrator", "/public/admin", "/settingsx"] {
            assert!(!some.needs_sign_in(p), "{p}");
        }
    }

    #[test]
    fn a_bypass_is_never_asked_whatever_is_protected() {
        let s = site(&[], &["/api", "/.well-known/"]);
        for p in ["/api", "/api/v1/items", "/.well-known/caldav"] {
            assert!(!s.needs_sign_in(p), "{p}");
        }
        assert!(s.needs_sign_in("/apiary"));
        assert!(s.needs_sign_in("/admin"));
    }

    /// The path as typed is what the visitor controls. What needs a sign-in is
    /// decided on the path the application will read.
    #[test]
    fn a_protected_path_cannot_be_reached_by_writing_it_another_way() {
        let s = site(&["/admin"], &["/public"]);
        for sneaky in ["//admin", "/public/../admin", "/x/../admin/users", "/./admin", "/public/..//admin",
                       "/%61dmin", "/ADMIN", "/Admin/users", "/public/%2e%2e/admin", "\\admin"] {
            assert!(s.needs_sign_in(sneaky), "{sneaky:?} reached the application without a sign-in");
        }
        // And a bypass is only what it says.
        assert!(!s.needs_sign_in("/public/readme.txt"));
        let whole = site(&[], &["/api"]);
        for sneaky in ["/api/../admin", "/api/..%2fadmin", "/api/%2e%2e/admin"] {
            assert!(whole.needs_sign_in(sneaky), "{sneaky:?} was let through as the bypass");
        }
    }

    #[test]
    fn a_client_cannot_name_itself_to_the_application() {
        let s = site(&[], &[]);
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-user", "admin".parse().unwrap());
        h.insert("x-forwarded-groups", "wheel".parse().unwrap());
        h.insert("cookie", format!("theme=dark; {SESSION_COOKIE}=abc.def; lang=en").parse().unwrap());
        s.strip(&mut h);
        assert!(!h.contains_key("x-forwarded-user"));
        assert!(!h.contains_key("x-forwarded-groups"));
        assert_eq!(h["cookie"], "theme=dark; lang=en", "the application's own cookies are left as they were");

        s.announce(&mut h, &Identity { subject: "alice".into(), groups: vec!["staff".into(), "ops".into()] });
        assert_eq!(h["x-forwarded-user"], "alice");
        assert_eq!(h["x-forwarded-groups"], "staff,ops");

        // Ours was the only cookie: the header goes with it.
        let mut h = HeaderMap::new();
        h.insert("cookie", format!("{SESSION_COOKIE}=abc").parse().unwrap());
        s.strip(&mut h);
        assert!(!h.contains_key("cookie"));
    }

    #[tokio::test]
    async fn a_local_password_is_checked_and_nothing_else_gets_in() {
        let realm = local_realm();
        let (ok, _) = check_password(&realm, "alice", "correct horse").await;
        assert_eq!(ok.map(|(who, _)| who), Some(alice()));
        for (user, pass) in [("alice", "wrong"), ("alice", ""), ("", "correct horse"), ("nobody", "correct horse")] {
            assert!(check_password(&realm, user, pass).await.0.is_none(), "{user:?} / {pass:?}");
        }
        let mut disabled = realm.clone();
        disabled.users.get_mut("alice").unwrap().enabled = false;
        assert!(check_password(&disabled, "alice", "correct horse").await.0.is_none());
    }

    #[test]
    fn an_address_that_keeps_failing_waits_and_others_do_not() {
        let guesser: IpAddr = "198.51.100.201".parse().unwrap();
        let other:   IpAddr = "198.51.100.202".parse().unwrap();
        for i in 0..MAX_FAILURES_PER_ADDRESS {
            assert!(!throttled(901, &format!("name{i}"), guesser), "refused after {i} failures");
            note_failure(901, &format!("name{i}"), guesser);
        }
        assert!(throttled(901, "anyone", guesser));
        assert!(!throttled(901, "anyone", other), "another address was refused with it");
        note_success(guesser);
        assert!(!throttled(901, "anyone", guesser), "a success did not clear the count");
    }

    #[test]
    fn a_name_tried_from_everywhere_is_slowed_too() {
        for i in 0..MAX_FAILURES_PER_NAME {
            let from: IpAddr = format!("203.0.113.{}", i % 250 + 1).parse().unwrap();
            note_failure(902, "Carol", from);
        }
        let fresh: IpAddr = "192.0.2.77".parse().unwrap();
        assert!(throttled(902, "carol", fresh), "a new address could go on guessing a name under attack");
        assert!(!throttled(903, "carol", fresh), "the same name in another realm was refused");
        assert!(!throttled(902, "dave", fresh));
    }

    #[test]
    fn basic_credentials_are_read_from_the_header() {
        let header = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("authorization", v.parse().unwrap());
            basic_credentials(&h)
        };
        // alice:correct horse
        assert_eq!(header("Basic YWxpY2U6Y29ycmVjdCBob3JzZQ=="), Some(("alice".into(), "correct horse".into())));
        assert_eq!(header("basic YWxpY2U6Y29ycmVjdCBob3JzZQ=="), Some(("alice".into(), "correct horse".into())));
        // a:b:c — the password may hold a colon.
        assert_eq!(header("Basic YTpiOmM="), Some(("a".into(), "b:c".into())));
        assert_eq!(header("Bearer abc"), None);
        assert_eq!(header("Basic not-base64!"), None);
        assert_eq!(basic_credentials(&HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn a_remembered_basic_credential_still_answers_to_the_realm() {
        let realm = local_realm();
        assert!(check_basic(SECRET, &realm, "alice", "correct horse").await.0.is_some());
        assert!(check_basic(SECRET, &realm, "alice", "wrong").await.0.is_none());

        // Disabled a moment later: the remembered answer is not used.
        let mut disabled = realm.clone();
        disabled.users.get_mut("alice").unwrap().enabled = false;
        assert!(check_basic(SECRET, &disabled, "alice", "correct horse").await.0.is_none());
    }

    #[test]
    fn prefixes_are_read_as_typed_and_what_is_not_a_path_is_said() {
        let (ok, bad) = parse_prefixes("/admin\n /settings/ ,/api\n\n/admin\nadmin\n/a b\n/x?y=1");
        assert_eq!(ok, ["/admin", "/settings/", "/api"]);
        assert_eq!(bad, ["admin", "/a b", "/x?y=1"]);
    }

    /// Settings stored before a field existed, or stored without one, read as
    /// the safe value: the certificate is checked.
    #[test]
    fn a_directory_setting_that_is_missing_reads_as_the_safe_one() {
        let c: LdapConfig = serde_json::from_str(r#"{"url":"ldaps://dc.example.com","base_dn":"dc=example,dc=com"}"#).unwrap();
        assert!(c.verify_tls);
        assert_eq!(c.user_filter, "(uid={user})");
        assert!(!c.starttls);
        assert!(LdapConfig::default().verify_tls);
    }

    #[test]
    fn a_group_is_named_as_an_application_reads_it() {
        assert_eq!(group_name("cn=staff,ou=groups,dc=example,dc=com"), "staff");
        assert_eq!(group_name("CN=Domain Admins,CN=Users,DC=corp,DC=example"), "Domain Admins");
        assert_eq!(group_name("staff"), "staff");
    }

    #[test]
    fn the_page_shows_nothing_a_visitor_typed_as_markup() {
        let page = login_page("shop.example.com", "/cart?x=\"><script>alert(1)</script>", Notice::Refused);
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("not accepted"));
        assert!(page.contains(LOGIN_PATH));
    }
}

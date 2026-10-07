// =========================================================
// routes/realms.rs — EasyWAF
// Settings → Sign-in Realms: where the people who sign in to
// a site come from.
//
// A realm is a source of identities — accounts kept here, or
// a directory — and how long a sign-in from it lasts. Sites
// choose a realm on their own page; a realm is shared by the
// sites that use it, so the people let into three admin
// panels are written down once.
//
// These are not EasyWAF's own accounts and are never mixed
// with them: nothing here can sign in to this interface, and
// nothing under Accounts can sign in to a site.
//
// Everything that should end a session does so at once —
// disabling an account, changing its password, deleting it,
// or signing a whole realm out — by raising the epoch the
// session cookie was minted with.
// =========================================================

use crate::auth::Admin;
use crate::gateway::LdapConfig;
use crate::routes::account::{MAX_PASSWORD_BYTES, MIN_PASSWORD_LEN};
use crate::routes::flash_redirect;
use crate::{error::Result, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tera::Context;

use super::policy::FlashQuery;

/// The shortest and longest a sign-in may be set to last, in minutes: five
/// minutes, and thirty days.
const MINUTES: std::ops::RangeInclusive<i64> = 5..=43_200;

/// The longest name a realm or an account may have.
const MAX_NAME: usize = 64;

// ─── Models ──────────────────────────────────────────────

/// One realm, as the list shows it.
#[derive(Debug, Serialize)]
struct RealmRow {
    name:            String,
    kind:            String,
    session_minutes: i64,
    idle_minutes:    i64,
    accounts:        i64,
    /// The sites that ask for a sign-in from it.
    sites:           Vec<String>,
}

/// One account of a local realm.
#[derive(Debug, Serialize)]
struct AccountRow {
    username:   String,
    enabled:    bool,
    created_at: String,
    last_login: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RealmForm {
    pub name:            Option<String>,
    pub kind:            Option<String>,
    pub session_minutes: String,
    pub idle_minutes:    String,
    // A directory's settings. Ignored for a local realm.
    pub ldap_url:        Option<String>,
    pub ldap_starttls:   Option<String>,
    pub ldap_skip_verify: Option<String>,
    pub ldap_bind_dn:    Option<String>,
    pub ldap_bind_password: Option<String>,
    pub ldap_base_dn:    Option<String>,
    pub ldap_user_filter: Option<String>,
    pub ldap_groups_attribute: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NewAccountForm {
    pub username:         String,
    pub password:         String,
    pub confirm_password: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordForm {
    pub password:         String,
    pub confirm_password: String,
}

#[derive(Debug, Deserialize)]
pub struct TestForm {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

// ─── Helpers ─────────────────────────────────────────────

fn realm_url(name: &str) -> String {
    format!("/realms/{}", urlencoding::encode(name))
}

/// A realm's id and kind by name.
async fn find(db: &SqlitePool, name: &str) -> Result<Option<(i64, String)>> {
    Ok(sqlx::query!(r#"SELECT id as "id!", kind as "kind!" FROM auth_realms WHERE name = ?"#, name)
        .fetch_optional(db)
        .await?
        .map(|r| (r.id, r.kind)))
}

/// A name for a realm or an account: something a person reads, with nothing in
/// it that would have to be escaped to be shown, logged or put in a header.
fn check_name(what: &str, name: &str) -> Option<String> {
    if name.is_empty() {
        return Some(format!("{what} needs a name."));
    }
    if name.chars().count() > MAX_NAME {
        return Some(format!("{what} names are at most {MAX_NAME} characters."));
    }
    // A colon cannot be carried in an HTTP Basic name, and the rest have no
    // place in one.
    if name.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, ':' | '"' | '\\' | '/' | '<' | '>')) {
        return Some(format!(
            "{what} names cannot hold spaces, colons, quotes, slashes or angle brackets."));
    }
    None
}

fn check_password(password: &str, confirm: &str) -> Option<String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Some(format!("Password must be at least {MIN_PASSWORD_LEN} characters."));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Some(format!(
            "Password must be at most {MAX_PASSWORD_BYTES} bytes — bcrypt ignores anything beyond that."));
    }
    if password != confirm {
        return Some("The two passwords do not match.".to_string());
    }
    None
}

/// How long a sign-in lasts, as typed. The idle time cannot be longer than the
/// whole: a session that may sit unused for longer than it may exist is a
/// setting that does nothing.
fn read_minutes(form: &RealmForm) -> std::result::Result<(i64, i64), String> {
    let read = |raw: &str, what: &str| {
        raw.trim().parse::<i64>().ok().filter(|m| MINUTES.contains(m)).ok_or_else(|| format!(
            "{what} must be between {} minutes and {} days.", MINUTES.start(), MINUTES.end() / 1440))
    };
    let session = read(&form.session_minutes, "How long a sign-in lasts")?;
    let idle = read(&form.idle_minutes, "How long it lasts unused")?;
    if idle > session {
        return Err("A sign-in cannot last longer unused than it lasts at all.".to_string());
    }
    Ok((session, idle))
}

/// A directory's settings as typed, checked for what would make every sign-in
/// fail. `kept_password` is the one already stored, used when the field is
/// left empty: the page never shows it, so empty means unchanged.
fn read_ldap(form: &RealmForm, kept_password: &str) -> std::result::Result<LdapConfig, String> {
    let text = |v: &Option<String>| v.as_deref().unwrap_or("").trim().to_string();
    let url = text(&form.ldap_url);
    if !(url.starts_with("ldap://") || url.starts_with("ldaps://")) || url.contains(char::is_whitespace) {
        return Err("The directory's address must begin ldap:// or ldaps://.".to_string());
    }
    let starttls = form.ldap_starttls.is_some();
    if starttls && url.starts_with("ldaps://") {
        return Err("StartTLS upgrades an ldap:// connection. An ldaps:// one is encrypted already.".to_string());
    }
    let base_dn = text(&form.ldap_base_dn);
    if base_dn.is_empty() {
        return Err("Say where in the directory to look for users (the base DN).".to_string());
    }
    let user_filter = match text(&form.ldap_user_filter) {
        f if f.is_empty() => LdapConfig::default().user_filter,
        f => f,
    };
    // Without the placeholder the search is the same for every name typed, and
    // signs in whoever it happens to find.
    if !user_filter.contains("{user}") {
        return Err("The user filter must contain {user}, where the name typed goes.".to_string());
    }
    if !(user_filter.starts_with('(') && user_filter.ends_with(')'))
        || user_filter.matches('(').count() != user_filter.matches(')').count()
    {
        return Err("The user filter is not a complete LDAP filter: check its brackets.".to_string());
    }
    let typed = form.ldap_bind_password.as_deref().unwrap_or("");
    Ok(LdapConfig {
        url,
        starttls,
        verify_tls: form.ldap_skip_verify.is_none(),
        bind_dn: text(&form.ldap_bind_dn),
        bind_password: if typed.is_empty() { kept_password.to_string() } else { typed.to_string() },
        base_dn,
        user_filter,
        groups_attribute: text(&form.ldap_groups_attribute),
    })
}

fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| crate::error::AppError::Internal(format!("password hashing failed: {e}")))
}

// ─── get_realms ──────────────────────────────────────────

/// GET /realms — every realm, and the form that makes one.
pub async fn get_realms(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Admin(session): Admin,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let rows = sqlx::query!(
        r#"SELECT r.id as "id!", r.name as "name!", r.kind as "kind!",
                  r.session_minutes as "session_minutes!", r.idle_minutes as "idle_minutes!",
                  (SELECT COUNT(*) FROM auth_users u WHERE u.realm_id = r.id) as "accounts!: i64",
                  (SELECT group_concat(s.name, char(10)) FROM site_auth a JOIN sites s ON s.id = a.site_id
                    WHERE a.realm_id = r.id) as "sites?: String"
           FROM auth_realms r ORDER BY r.name"#
    )
    .fetch_all(&state.db)
    .await?;
    let realms: Vec<RealmRow> = rows.into_iter().map(|r| RealmRow {
        name: r.name,
        kind: r.kind,
        session_minutes: r.session_minutes,
        idle_minutes: r.idle_minutes,
        accounts: r.accounts,
        sites: r.sites.map(|s| s.lines().map(str::to_string).collect()).unwrap_or_default(),
    }).collect();

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",  "Sign-in Realms");
    ctx.insert("url",    "/realms");
    ctx.insert("realms", &realms);
    ctx.insert("default_filter", &LdapConfig::default().user_filter);
    ctx.insert("result", &flash.result.unwrap_or_default());
    ctx.insert("msg",    &flash.msg.unwrap_or_default());
    Ok((jar, Html(state.tera.render("realms.html", &ctx)?)).into_response())
}

// ─── post_realm_create ───────────────────────────────────

pub async fn post_realm_create(
    State(state): State<AppState>,
    Admin(session): Admin,
    Form(form): Form<RealmForm>,
) -> Result<Response> {
    let back = "/realms";
    let name = form.name.as_deref().unwrap_or("").trim().to_string();
    if let Some(msg) = check_name("A realm", &name) {
        return flash_redirect(back, "failed", &msg);
    }
    let kind = match form.kind.as_deref() {
        Some("ldap") => "ldap",
        _            => "local",
    };
    let (session_minutes, idle_minutes) = match read_minutes(&form) {
        Ok(m)  => m,
        Err(e) => return flash_redirect(back, "failed", &e),
    };
    let config = if kind == "ldap" {
        match read_ldap(&form, "") {
            Ok(c)  => serde_json::to_string(&c).unwrap_or_else(|_| "{}".into()),
            Err(e) => return flash_redirect(back, "failed", &e),
        }
    } else {
        "{}".to_string()
    };
    if find(&state.db, &name).await?.is_some() {
        return flash_redirect(back, "failed", &format!("There is already a realm named {name}."));
    }

    sqlx::query!(
        "INSERT INTO auth_realms (name, kind, session_minutes, idle_minutes, config) VALUES (?, ?, ?, ?, ?)",
        name, kind, session_minutes, idle_minutes, config
    )
    .execute(&state.db)
    .await?;
    tracing::info!(by = %session.username, realm = %name, kind, "Sign-in realm created");

    let next = if kind == "local" {
        "Add the accounts that may sign in, then choose this realm on a site."
    } else {
        "Try a sign-in below before choosing this realm on a site."
    };
    flash_redirect(&realm_url(&name), "success", &format!("Realm {name} created. {next}"))
}

// ─── get_realm ───────────────────────────────────────────

/// GET /realms/{name} — one realm: its settings, its accounts or its
/// directory, and the sites that use it.
pub async fn get_realm(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Admin(session): Admin,
    Path(name): Path<String>,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let page = realm_page(&state, &session, &name, flash, None).await?;
    Ok((jar, page).into_response())
}

/// A realm's page — with what a test of its directory found, when one was
/// just run.
async fn realm_page(
    state:   &AppState,
    session: &crate::auth::SessionData,
    name:    &str,
    flash:   FlashQuery,
    tested:  Option<Vec<crate::gateway::Step>>,
) -> Result<Response> {
    let Some(r) = sqlx::query!(
        r#"SELECT id as "id!", kind as "kind!", session_minutes as "session_minutes!",
                  idle_minutes as "idle_minutes!", config as "config!"
           FROM auth_realms WHERE name = ?"#,
        name
    )
    .fetch_optional(&state.db)
    .await?
    else {
        return flash_redirect("/realms", "failed", &format!("There is no realm named {name}."));
    };

    let accounts: Vec<AccountRow> = sqlx::query!(
        r#"SELECT username as "username!", enabled as "enabled!: bool",
                  created_at as "created_at!", last_login
           FROM auth_users WHERE realm_id = ? ORDER BY username"#,
        r.id
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .map(|u| AccountRow {
        username: u.username,
        enabled: u.enabled,
        created_at: u.created_at,
        last_login: u.last_login,
    })
    .collect();

    let sites: Vec<String> = sqlx::query_scalar!(
        r#"SELECT s.name as "name!" FROM site_auth a JOIN sites s ON s.id = a.site_id
           WHERE a.realm_id = ? ORDER BY s.name"#,
        r.id
    )
    .fetch_all(&state.db)
    .await?;

    // The directory's settings, without its password: the page says whether
    // one is stored, and never what it is.
    let ldap: LdapConfig = serde_json::from_str(&r.config).unwrap_or_default();
    let has_bind_password = !ldap.bind_password.is_empty();
    let ldap = LdapConfig { bind_password: String::new(), ..ldap };

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, session);
    ctx.insert("title",  &format!("Realm {name}"));
    ctx.insert("url",    "/realms");
    ctx.insert("name",   &name);
    ctx.insert("kind",   &r.kind);
    ctx.insert("session_minutes", &r.session_minutes);
    ctx.insert("idle_minutes",    &r.idle_minutes);
    ctx.insert("accounts", &accounts);
    ctx.insert("sites",    &sites);
    ctx.insert("ldap",     &ldap);
    ctx.insert("has_bind_password", &has_bind_password);
    ctx.insert("min_length", &MIN_PASSWORD_LEN);
    ctx.insert("result", &flash.result.unwrap_or_default());
    ctx.insert("msg",    &flash.msg.unwrap_or_default());
    ctx.insert("tested", &tested);
    Ok(Html(state.tera.render("realm.html", &ctx)?).into_response())
}

// ─── post_realm_update ───────────────────────────────────

pub async fn post_realm_update(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(name): Path<String>,
    Form(form): Form<RealmForm>,
) -> Result<Response> {
    let back = realm_url(&name);
    let Some(r) = sqlx::query!(
        r#"SELECT id as "id!", kind as "kind!", config as "config!" FROM auth_realms WHERE name = ?"#, name)
        .fetch_optional(&state.db)
        .await?
    else {
        return flash_redirect("/realms", "failed", &format!("There is no realm named {name}."));
    };
    let (session_minutes, idle_minutes) = match read_minutes(&form) {
        Ok(m)  => m,
        Err(e) => return flash_redirect(&back, "failed", &e),
    };
    let config = if r.kind == "ldap" {
        let kept = serde_json::from_str::<LdapConfig>(&r.config).unwrap_or_default().bind_password;
        match read_ldap(&form, &kept) {
            Ok(c)  => serde_json::to_string(&c).unwrap_or_else(|_| "{}".into()),
            Err(e) => return flash_redirect(&back, "failed", &e),
        }
    } else {
        r.config
    };

    sqlx::query!(
        "UPDATE auth_realms SET session_minutes = ?, idle_minutes = ?, config = ?,
                                updated_at = datetime('now') WHERE id = ?",
        session_minutes, idle_minutes, config, r.id
    )
    .execute(&state.db)
    .await?;
    tracing::info!(by = %session.username, realm = %name, "Sign-in realm updated");
    flash_redirect(&back, "success",
        "Saved. How long a sign-in lasts applies to sessions already open as well.")
}

// ─── post_realm_sign_out ─────────────────────────────────

/// POST /realms/{name}/sign-out — end every session of the realm, on every
/// site that uses it.
pub async fn post_realm_sign_out(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(name): Path<String>,
) -> Result<Response> {
    let done = sqlx::query!(
        "UPDATE auth_realms SET epoch = epoch + 1, updated_at = datetime('now') WHERE name = ?", name)
        .execute(&state.db)
        .await?
        .rows_affected();
    if done == 0 {
        return flash_redirect("/realms", "failed", &format!("There is no realm named {name}."));
    }
    tracing::warn!(by = %session.username, realm = %name, "Everyone signed out of a sign-in realm");
    flash_redirect(&realm_url(&name), "success",
        "Everyone is signed out. Each visitor is asked to sign in again at their next request.")
}

// ─── post_realm_delete ───────────────────────────────────

pub async fn post_realm_delete(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(name): Path<String>,
) -> Result<Response> {
    let Some((id, _)) = find(&state.db, &name).await? else {
        return flash_redirect("/realms", "failed", &format!("There is no realm named {name}."));
    };
    // A site that lost its realm would go from asking everybody to sign in to
    // asking nobody, without a word. Refused, and the sites are named.
    let in_use: Vec<String> = sqlx::query_scalar!(
        r#"SELECT s.name as "name!" FROM site_auth a JOIN sites s ON s.id = a.site_id
           WHERE a.realm_id = ? ORDER BY s.name"#,
        id
    )
    .fetch_all(&state.db)
    .await?;
    if !in_use.is_empty() {
        return flash_redirect(&realm_url(&name), "failed", &format!(
            "{name} is what {} asks its visitors to sign in with: {}. Choose another realm there, \
             or switch sign-in off, first — deleting it would leave {} open to everybody.",
            if in_use.len() == 1 { "one site" } else { "these sites" },
            in_use.join(", "),
            if in_use.len() == 1 { "it" } else { "them" },
        ));
    }
    sqlx::query!("DELETE FROM auth_realms WHERE id = ?", id).execute(&state.db).await?;
    tracing::warn!(by = %session.username, realm = %name, "Sign-in realm deleted");
    flash_redirect("/realms", "success", &format!("Realm {name} deleted, with its accounts."))
}

// ─── post_realm_test ─────────────────────────────────────

/// POST /realms/{name}/test — try a name and password against the realm, and
/// say what happened. For a directory this is where a wrong address, a search
/// account that cannot bind or a filter that finds nobody shows itself, while
/// somebody is looking, and not at the first visitor's sign-in.
pub async fn post_realm_test(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(name): Path<String>,
    Form(form): Form<TestForm>,
) -> Result<Response> {
    let back = realm_url(&name);
    let Some(r) = sqlx::query!(
        r#"SELECT kind as "kind!", config as "config!" FROM auth_realms WHERE name = ?"#, name)
        .fetch_optional(&state.db)
        .await?
    else {
        return flash_redirect("/realms", "failed", &format!("There is no realm named {name}."));
    };
    if r.kind != "ldap" {
        return flash_redirect(&back, "failed", "Only a directory has a connection to test.");
    }
    let cfg: LdapConfig = serde_json::from_str(&r.config).unwrap_or_default();
    // With no name it tests the connection and the filter; with a name, that
    // the filter finds that one person; with their password too, a sign-in.
    let steps = crate::gateway::ldap_probe(&cfg, form.username.trim(), &form.password).await;
    // Answered with the page itself: what the directory said is shown once
    // and is in no address somebody could copy.
    realm_page(&state, &session, &name, FlashQuery { result: None, msg: None }, Some(steps)).await
}

// ─── Accounts of a local realm ───────────────────────────

/// The realm's id, when it is one that keeps its own accounts.
async fn local_realm(db: &SqlitePool, name: &str) -> Result<std::result::Result<i64, String>> {
    Ok(match find(db, name).await? {
        None => Err(format!("There is no realm named {name}.")),
        Some((_, kind)) if kind != "local" =>
            Err("A directory's accounts are kept in the directory.".to_string()),
        Some((id, _)) => Ok(id),
    })
}

pub async fn post_account_add(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path(name): Path<String>,
    Form(form): Form<NewAccountForm>,
) -> Result<Response> {
    let back = realm_url(&name);
    let realm_id = match local_realm(&state.db, &name).await? {
        Ok(id) => id,
        Err(e) => return flash_redirect(&back, "failed", &e),
    };
    let username = form.username.trim();
    if let Some(msg) = check_name("An account", username).or_else(|| check_password(&form.password, &form.confirm_password)) {
        return flash_redirect(&back, "failed", &msg);
    }
    let taken: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM auth_users WHERE realm_id = ? AND username = ?", realm_id, username)
        .fetch_one(&state.db)
        .await?;
    if taken > 0 {
        return flash_redirect(&back, "failed", &format!("{name} already has an account named {username}."));
    }
    let password_hash = hash_password(&form.password)?;
    sqlx::query!(
        "INSERT INTO auth_users (realm_id, username, password_hash) VALUES (?, ?, ?)",
        realm_id, username, password_hash
    )
    .execute(&state.db)
    .await?;
    tracing::info!(by = %session.username, realm = %name, account = username, "Site sign-in account created");
    flash_redirect(&back, "success", &format!("{username} can now sign in."))
}

pub async fn post_account_password(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path((name, username)): Path<(String, String)>,
    Form(form): Form<PasswordForm>,
) -> Result<Response> {
    let back = realm_url(&name);
    let realm_id = match local_realm(&state.db, &name).await? {
        Ok(id) => id,
        Err(e) => return flash_redirect(&back, "failed", &e),
    };
    if let Some(msg) = check_password(&form.password, &form.confirm_password) {
        return flash_redirect(&back, "failed", &msg);
    }
    let password_hash = hash_password(&form.password)?;
    // The epoch moves with the password: whoever was signed in with the old
    // one is signed out.
    let done = sqlx::query!(
        "UPDATE auth_users SET password_hash = ?, epoch = epoch + 1 WHERE realm_id = ? AND username = ?",
        password_hash, realm_id, username
    )
    .execute(&state.db)
    .await?
    .rows_affected();
    if done == 0 {
        return flash_redirect(&back, "failed", &format!("There is no account named {username}."));
    }
    tracing::info!(by = %session.username, realm = %name, account = %username, "Site sign-in password changed");
    flash_redirect(&back, "success", &format!("Password changed. {username} is signed out everywhere."))
}

pub async fn post_account_toggle(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path((name, username)): Path<(String, String)>,
) -> Result<Response> {
    let back = realm_url(&name);
    let realm_id = match local_realm(&state.db, &name).await? {
        Ok(id) => id,
        Err(e) => return flash_redirect(&back, "failed", &e),
    };
    let enabled: Option<bool> = sqlx::query_scalar!(
        r#"SELECT enabled as "enabled!: bool" FROM auth_users WHERE realm_id = ? AND username = ?"#,
        realm_id, username
    )
    .fetch_optional(&state.db)
    .await?;
    let Some(enabled) = enabled else {
        return flash_redirect(&back, "failed", &format!("There is no account named {username}."));
    };
    let now = !enabled;
    sqlx::query!(
        "UPDATE auth_users SET enabled = ?, epoch = epoch + 1 WHERE realm_id = ? AND username = ?",
        now, realm_id, username
    )
    .execute(&state.db)
    .await?;
    tracing::info!(by = %session.username, realm = %name, account = %username, enabled = now,
                   "Site sign-in account switched");
    flash_redirect(&back, "success", &if now {
        format!("{username} can sign in again.")
    } else {
        format!("{username} is disabled, and signed out everywhere.")
    })
}

pub async fn post_account_delete(
    State(state): State<AppState>,
    Admin(session): Admin,
    Path((name, username)): Path<(String, String)>,
) -> Result<Response> {
    let back = realm_url(&name);
    let realm_id = match local_realm(&state.db, &name).await? {
        Ok(id) => id,
        Err(e) => return flash_redirect(&back, "failed", &e),
    };
    let done = sqlx::query!(
        "DELETE FROM auth_users WHERE realm_id = ? AND username = ?", realm_id, username)
        .execute(&state.db)
        .await?
        .rows_affected();
    if done == 0 {
        return flash_redirect(&back, "failed", &format!("There is no account named {username}."));
    }
    tracing::info!(by = %session.username, realm = %name, account = %username, "Site sign-in account deleted");
    flash_redirect(&back, "success", &format!("{username} deleted, and signed out everywhere."))
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> RealmForm {
        RealmForm {
            name: Some("staff".into()), kind: Some("ldap".into()),
            session_minutes: "480".into(), idle_minutes: "60".into(),
            ldap_url: Some("ldaps://dc.example.com".into()),
            ldap_starttls: None, ldap_skip_verify: None,
            ldap_bind_dn: Some("cn=easywaf,dc=example,dc=com".into()),
            ldap_bind_password: Some("s3cret".into()),
            ldap_base_dn: Some("ou=people,dc=example,dc=com".into()),
            ldap_user_filter: Some("(&(uid={user})(memberOf=cn=staff,ou=groups,dc=example,dc=com))".into()),
            ldap_groups_attribute: Some("memberOf".into()),
        }
    }

    #[test]
    fn a_directory_is_read_as_typed_and_verified_unless_told_not_to() {
        let c = read_ldap(&form(), "").unwrap();
        assert_eq!(c.url, "ldaps://dc.example.com");
        assert!(c.verify_tls, "verification was off without being switched off");
        assert_eq!(c.bind_password, "s3cret");
        let c = read_ldap(&RealmForm { ldap_skip_verify: Some("1".into()), ..form() }, "").unwrap();
        assert!(!c.verify_tls);
    }

    /// The page never shows the stored password, so an empty field means
    /// "leave it", not "remove it".
    #[test]
    fn an_empty_password_field_keeps_the_one_stored() {
        let c = read_ldap(&RealmForm { ldap_bind_password: Some(String::new()), ..form() }, "kept").unwrap();
        assert_eq!(c.bind_password, "kept");
        let c = read_ldap(&form(), "kept").unwrap();
        assert_eq!(c.bind_password, "s3cret", "a new one typed was ignored");
    }

    #[test]
    fn settings_that_would_fail_every_sign_in_are_refused_when_saved() {
        let bad = |f: RealmForm| read_ldap(&f, "").is_err();
        assert!(bad(RealmForm { ldap_url: Some("dc.example.com".into()), ..form() }));
        assert!(bad(RealmForm { ldap_url: Some("https://dc.example.com".into()), ..form() }));
        assert!(bad(RealmForm { ldap_base_dn: Some(" ".into()), ..form() }));
        assert!(bad(RealmForm { ldap_starttls: Some("1".into()), ..form() }), "StartTLS over ldaps");
        assert!(bad(RealmForm { ldap_user_filter: Some("(uid=admin)".into()), ..form() }),
                "a filter with no {{user}} finds the same person for every name");
        assert!(bad(RealmForm { ldap_user_filter: Some("(&(uid={user})".into()), ..form() }));
        // Left empty, the filter is the ordinary one.
        let c = read_ldap(&RealmForm { ldap_user_filter: Some(String::new()), ..form() }, "").unwrap();
        assert_eq!(c.user_filter, "(uid={user})");
    }

    #[test]
    fn how_long_a_sign_in_lasts_is_kept_within_reason() {
        let minutes = |s: &str, i: &str| read_minutes(&RealmForm {
            session_minutes: s.into(), idle_minutes: i.into(), ..form() });
        assert_eq!(minutes("480", "60"), Ok((480, 60)));
        assert_eq!(minutes(" 60 ", "60"), Ok((60, 60)));
        assert!(minutes("60", "120").is_err(), "idle longer than the session");
        assert!(minutes("1", "1").is_err());
        assert!(minutes("eight hours", "60").is_err());
        assert!(minutes("99999999", "60").is_err());
    }

    #[test]
    fn a_name_holds_nothing_that_would_need_escaping() {
        for ok in ["alice", "john.doe", "j.doe@example.com", "ops-team_1"] {
            assert_eq!(check_name("An account", ok), None, "{ok}");
        }
        for bad in ["", "a b", "a:b", "a\"b", "a/b", "<a>", "a\tb", &"x".repeat(65)] {
            assert!(check_name("An account", bad).is_some(), "{bad:?}");
        }
    }
}

// =========================================================
// routes/exclusions.rs — EasyWAF
// Rules a single site does not apply.
//
// A policy is shared on purpose: several sites use one, and
// a rule update reaches all of them at once. That leaves no
// way to say "this rule is wrong for this one site" without
// either weakening it for every site or giving the site a
// policy of its own and losing the shared updates. Both are
// worse than the false positive being answered.
//
// An exclusion is that third answer, and it is deliberately
// small: one named rule, optionally confined to a path
// prefix, with a note saying why. It turns a rule off, so
// everything here is written to make what is off obvious —
// the list is on the site's own page, the rule editor names
// the sites that exclude it, and nothing is ever excluded
// implicitly.
// =========================================================

use crate::routes::flash_redirect;
use crate::{auth::{Admin, Viewer}, error::Result, AppState};
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::{Deserialize, Serialize};
use tera::Context;

use super::policy::FlashQuery;

// ─── Models ──────────────────────────────────────────────

/// One exclusion, as the page shows it.
#[derive(Debug, Serialize)]
pub struct Exclusion {
    pub id:          i64,
    /// The catalogue number, when the rule has one.
    pub external_id: Option<i64>,
    pub rule_id:     Option<i64>,
    /// The rule's name, resolved through the site's current policy. `None`
    /// when the policy no longer holds the rule — which is not an error and
    /// not something to clean up automatically; see `load`.
    pub rule_name:   Option<String>,
    pub path_prefix: String,
    /// The clients this covers; empty means every client.
    pub client_cidr: String,
    pub note:        String,
    pub created_at:  String,
}

/// A rule that can be excluded, for the add form.
#[derive(Debug, Serialize)]
pub struct Candidate {
    pub value: String,
    pub label: String,
    pub set:   String,
}

// ─── Forms ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ExclusionForm {
    /// Either "e:913015" (catalogue number) or "r:42" (custom rule row).
    /// One field rather than two, because the form offers one list.
    pub rule:        String,
    pub path_prefix: String,
    /// An address or CIDR block, or empty for every client.
    pub client_cidr: String,
    pub note:        String,
}

// ─── Queries ─────────────────────────────────────────────

/// The site's id and the policy it uses, or `None` if there is no such site.
async fn site_and_policy(state: &AppState, name: &str) -> Result<Option<(i64, Option<i64>)>> {
    let row = sqlx::query!(
        "SELECT id as \"id!\", waf_policy_id FROM sites WHERE server_name = ?",
        name
    )
    .fetch_optional(&state.db)
    .await?;

    Ok(row.map(|r| (r.id, r.waf_policy_id)))
}

/// Every exclusion recorded for a site, newest first.
///
/// The rule name is resolved through the site's policy at read time rather
/// than copied in at write time. A copied name goes stale when the rule is
/// renamed by an update, and the name is the only part of this a person reads.
///
/// A rule the policy no longer holds resolves to `None` and is shown as
/// unknown rather than deleted. The policy can be changed back, or the set
/// reinstalled, and an exclusion that quietly removed itself in between would
/// come back as a false positive nobody remembers the cause of.
async fn load(state: &AppState, site_id: i64, policy_id: Option<i64>) -> Result<Vec<Exclusion>> {
    let rows = sqlx::query!(
        "SELECT e.id          as \"id!\",
                e.external_id,
                e.rule_id,
                e.path_prefix as \"path_prefix!\",
                e.client_cidr,
                e.note        as \"note!\",
                e.created_at  as \"created_at!\",
                r.name        as \"rule_name?\"
         FROM   site_rule_exclusions e
         LEFT   JOIN waf_rules r
                ON  r.policy_id = ?
                AND (   (e.external_id IS NOT NULL AND r.external_id = e.external_id)
                     OR (e.rule_id     IS NOT NULL AND r.id          = e.rule_id))
         WHERE  e.site_id = ?
         ORDER  BY e.id DESC",
        policy_id, site_id
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Exclusion {
            id:          r.id,
            external_id: r.external_id,
            rule_id:     r.rule_id,
            rule_name:   r.rule_name,
            path_prefix: r.path_prefix,
            client_cidr: r.client_cidr.unwrap_or_default(),
            note:        r.note,
            created_at:  r.created_at,
        })
        .collect())
}

/// The rules this site's policy holds, as choices for the add form.
///
/// Only enabled rules. A disabled rule is already not running, so offering it
/// here would be offering to turn off something that is off — and would make
/// the exclusion list longer than the set of rules it explains.
async fn candidates(state: &AppState, policy_id: Option<i64>) -> Result<Vec<Candidate>> {
    let Some(policy_id) = policy_id else { return Ok(Vec::new()) };

    let rows = sqlx::query!(
        "SELECT id as \"id!\", external_id, name, rule_set
         FROM   waf_rules
         WHERE  policy_id = ? AND enabled = 1
         ORDER  BY external_id IS NULL, external_id, name",
        policy_id
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            // A catalogue rule is named by its number, which survives the set
            // being removed and installed again. A custom rule has no number
            // and can only be named by its row.
            let (value, label) = match r.external_id {
                Some(ext) => (format!("e:{ext}"), format!("{ext} — {}", r.name)),
                None      => (format!("r:{}", r.id), format!("{} (custom)", r.name)),
            };
            Candidate { value, label, set: r.rule_set.unwrap_or_default() }
        })
        .collect())
}

// ─── get_site_exclusions ─────────────────────────────────

pub async fn get_site_exclusions(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Path(name): Path<String>,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {

    let Some((site_id, policy_id)) = site_and_policy(&state, &name).await? else {
        return Ok(Redirect::to("/sites").into_response());
    };

    let policy_name: Option<String> = match policy_id {
        Some(id) => sqlx::query_scalar!("SELECT name FROM policies WHERE id = ?", id)
            .fetch_optional(&state.db)
            .await?,
        None => None,
    };

    let mut ctx = Context::new();
    ctx.insert("username",    &session.username);
    ctx.insert("title",       "Rule Exclusions");
    ctx.insert("url",         "/sites");
    ctx.insert("site_name",   &name);
    ctx.insert("policy_name", &policy_name.unwrap_or_default());
    ctx.insert("exclusions",  &load(&state, site_id, policy_id).await?);
    ctx.insert("candidates",  &candidates(&state, policy_id).await?);
    ctx.insert("result",      &flash.result.unwrap_or_default());
    ctx.insert("msg",         &flash.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("site_exclusions.html", &ctx)?)).into_response())
}

// ─── post_exclusion_add ──────────────────────────────────

pub async fn post_exclusion_add(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path(name): Path<String>,
    Form(form): Form<ExclusionForm>,
) -> Result<Response> {

    let back = format!("/sites/{name}/exclusions");

    let Some((site_id, _)) = site_and_policy(&state, &name).await? else {
        return Ok(Redirect::to("/sites").into_response());
    };

    let (external_id, rule_id) = match parse_rule_ref(&form.rule) {
        Some(pair) => pair,
        None => return flash_redirect(&back, "failed", "Select a rule to exclude."),
    };

    // Normalised so "/dav" and "/dav " are the same exclusion rather than two
    // that look identical in the list. A prefix that does not start with "/"
    // would match nothing, since a request path always does.
    let prefix = form.path_prefix.trim();
    if !prefix.is_empty() && !prefix.starts_with('/') {
        return flash_redirect(
            &back,
            "failed",
            "A path prefix must start with \"/\" — leave it empty to cover the whole site.",
        );
    }
    // Parsed before storing, not after. A block the engine cannot read would
    // be dropped at match time and the exclusion would silently cover nobody —
    // or, had it defaulted the other way, everybody.
    let client = form.client_cidr.trim();
    if !client.is_empty() && crate::forwarded::Cidr::parse(client).is_none() {
        return flash_redirect(
            &back,
            "failed",
            &format!("\"{client}\" is not an address or CIDR block. Use 203.0.113.9, \
                      203.0.113.0/24, or leave it empty for every client."),
        );
    }
    let client_opt = if client.is_empty() { None } else { Some(client) };
    let note = form.note.trim();

    let inserted = sqlx::query!(
        "INSERT INTO site_rule_exclusions
         (site_id, external_id, rule_id, path_prefix, client_cidr, note)
         VALUES (?, ?, ?, ?, ?, ?)",
        site_id, external_id, rule_id, prefix, client_opt, note
    )
    .execute(&state.db)
    .await;

    match inserted {
        Ok(_) => {
            tracing::info!(site = %name, rule = %form.rule, prefix, "Rule excluded for a site");
            let where_ = match (prefix.is_empty(), client_opt) {
                (true,  None)    => "the whole site".to_string(),
                (false, None)    => format!("paths under {prefix}"),
                (true,  Some(c)) => format!("client {c}"),
                (false, Some(c)) => format!("paths under {prefix} from {c}"),
            };
            flash_redirect(
                &back,
                "success",
                &format!("Rule excluded for {where_}. It no longer runs, and no longer scores."),
            )
        }
        // The unique index. Reported as the harmless thing it is rather than
        // as a database error, because pressing Add twice is not a fault.
        Err(e) if e.to_string().contains("UNIQUE") => {
            flash_redirect(&back, "failed", "That rule is already excluded for that path.")
        }
        Err(e) => flash_redirect(&back, "failed", &format!("Could not save the exclusion: {e}")),
    }
}

// ─── policy_exclusions ───────────────────────────────────

/// One exclusion as the policy-wide list shows it.
#[derive(Debug, Serialize)]
pub struct PolicyExclusion {
    pub id:          i64,
    pub site_name:   String,
    /// Which policy the site uses, so the unfiltered list can be read.
    pub policy_name: String,
    pub rule_label:  String,
    pub external_id: Option<i64>,
    pub path_prefix: String,
    pub client_cidr: String,
    pub note:        String,
    pub created_at:  String,
}

/// Every exclusion, or only those affecting one policy's rules.
///
/// Exclusions are stored per site, because a site is what an exclusion is
/// about. They are *read* per policy here because that is how someone thinks
/// about them afterwards: a policy is the set of rules, and "which of my rules
/// are not actually running, and where" is a question about the policy rather
/// than about any one site.
pub async fn list_for_policy(
    state: &AppState,
    policy_id: Option<i64>,
) -> Result<Vec<PolicyExclusion>> {
    // `policy_id IS NULL` in the bind makes the filter optional without a
    // second query: with no policy given, every row passes and the rule name
    // is resolved through whichever policy the site actually uses.
    let rows = sqlx::query!(
        r#"SELECT e.id          as "id!",
                  s.server_name as "site_name!",
                  COALESCE(p.name, '(no policy)') as "policy_name!",
                  e.external_id,
                  e.rule_id,
                  e.path_prefix as "path_prefix!",
                  e.client_cidr,
                  e.note        as "note!",
                  e.created_at  as "created_at!",
                  r.name        as "rule_name?"
           FROM   site_rule_exclusions e
           JOIN   sites s ON s.id = e.site_id
           LEFT   JOIN policies p ON p.id = s.waf_policy_id
           LEFT   JOIN waf_rules r
                  ON  r.policy_id = s.waf_policy_id
                  AND (   (e.external_id IS NOT NULL AND r.external_id = e.external_id)
                       OR (e.rule_id     IS NOT NULL AND r.id          = e.rule_id))
           WHERE  (? IS NULL OR s.waf_policy_id = ?)
           ORDER  BY p.name, s.server_name, e.id DESC"#,
        policy_id, policy_id
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| PolicyExclusion {
            id:          r.id,
            site_name:   r.site_name,
            policy_name: r.policy_name,
            rule_label: match (r.rule_name, r.external_id, r.rule_id) {
                (Some(n), _, _)       => n,
                (None, Some(ext), _)  => format!("rule {ext} (not in this policy)"),
                (None, _, Some(id))   => format!("custom rule #{id} (deleted)"),
                _                     => "unknown rule".to_string(),
            },
            external_id: r.external_id,
            path_prefix: r.path_prefix,
            client_cidr: r.client_cidr.unwrap_or_default(),
            note:        r.note,
            created_at:  r.created_at,
        })
        .collect())
}

// ─── post_exclusion_remove ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RemoveForm {
    /// The filter that was in view, so removing one does not lose the list.
    pub policy: Option<String>,
}

/// Remove an exclusion, from wherever it was listed.
pub async fn post_exclusion_remove(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path(id): Path<i64>,
    Form(form): Form<RemoveForm>,
) -> Result<Response> {

    let back = match form.policy.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => format!("/exclusions?policy={}", urlencoding::encode(p)),
        None    => "/exclusions".to_string(),
    };

    let done = sqlx::query!("DELETE FROM site_rule_exclusions WHERE id = ?", id)
        .execute(&state.db)
        .await?;

    if done.rows_affected() == 0 {
        return flash_redirect(&back, "failed", "That exclusion no longer exists.");
    }

    tracing::info!(exclusion = id, "Rule exclusion removed");
    flash_redirect(&back, "success",
                   "Exclusion removed — the rule applies again from the next request.")
}

// ─── get_exclusions ──────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ExclusionsQuery {
    /// Narrow to one policy. Absent means every exclusion in the installation.
    pub policy: Option<String>,
    pub result: Option<String>,
    pub msg:    Option<String>,
}

/// Every rule that is not running, anywhere — optionally narrowed to a policy.
///
/// One page rather than one per policy. A menu entry needs a single URL, and
/// the question people actually ask is "what is not running", not "what is not
/// running under this particular policy" — that is the narrowing, not the
/// question. The per-policy links pass `?policy=`.
pub async fn get_exclusions(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(q): Query<ExclusionsQuery>,
) -> Result<Response> {

    let wanted = q.policy.clone().unwrap_or_default();
    let policy_id: Option<i64> = if wanted.is_empty() {
        None
    } else {
        sqlx::query_scalar!("SELECT id FROM policies WHERE name = ?", wanted)
            .fetch_optional(&state.db)
            .await?
            .flatten()
    };

    let policies = sqlx::query_scalar!("SELECT name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;

    let mut ctx = Context::new();
    ctx.insert("username",   &session.username);
    ctx.insert("title",      "Rule Exclusions");
    ctx.insert("url",        "/exclusions");
    ctx.insert("policies",   &policies);
    ctx.insert("sel_policy", &wanted);
    ctx.insert("exclusions", &list_for_policy(&state, policy_id).await?);
    ctx.insert("result",     &q.result.unwrap_or_default());
    ctx.insert("msg",        &q.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("policy_exclusions.html", &ctx)?)).into_response())
}

// ─── post_exclusion_from_traffic ─────────────────────────

/// Form behind the Traffic Monitor's "exclude for this IP" button.
#[derive(Debug, Deserialize)]
pub struct FromTrafficForm {
    /// The traffic row this came from, so the message can name it back.
    pub host:      String,
    pub client_ip: String,
    /// Catalogue number of the rule that matched.
    pub rule:      i64,
    pub rule_name: String,
    /// Where to return to, preserving whatever filter was applied.
    pub back:      Option<String>,
}

/// Exclude one rule for one client, from the row that showed the block.
///
/// The whole point of the Traffic Monitor showing which rules produced a
/// verdict is that the fix should be reachable from there. Diagnosing a false
/// positive and then retyping the site, the rule number and the address into
/// another page is where the diagnosis gets abandoned.
///
/// Deliberately the narrowest exclusion available: this rule, this client,
/// every path. Not the site, not the rule everywhere — those are a decision
/// someone can still make on the exclusions page, having seen this one first.
pub async fn post_exclusion_from_traffic(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Form(form): Form<FromTrafficForm>,
) -> Result<Response> {

    let back = form.back.clone().unwrap_or_else(|| "/traffic".to_string());

    // The address comes from a traffic row, so it is already an address the
    // proxy resolved — but it is parsed again rather than trusted, because it
    // arrives here through a form field like any other.
    let client = form.client_ip.trim();
    if crate::forwarded::Cidr::parse(client).is_none() {
        return flash_redirect(&back, "failed",
            &format!("\"{client}\" is not an address this can exclude."));
    }

    let site = sqlx::query!(
        "SELECT id as \"id!\", server_name FROM sites WHERE server_name = ?",
        form.host
    )
    .fetch_optional(&state.db)
    .await?;

    let Some(site) = site else {
        return flash_redirect(&back, "failed",
            &format!("No site named {} — it may have been deleted.", form.host));
    };

    let note = format!("Excluded from Traffic Monitor: {} was blocked for {}",
                       client, form.rule_name);

    let done = sqlx::query!(
        "INSERT INTO site_rule_exclusions
         (site_id, external_id, rule_id, path_prefix, client_cidr, note)
         VALUES (?, ?, NULL, '', ?, ?)",
        site.id, form.rule, client, note
    )
    .execute(&state.db)
    .await;

    match done {
        Ok(_) => {
            tracing::info!(site = %site.server_name, rule = form.rule, client,
                           "Rule excluded for a client from Traffic Monitor");
            flash_redirect(&back, "success", &format!(
                "Rule {} no longer runs for {} on {}. Every other client is still \
                 checked by it.", form.rule, client, site.server_name))
        }
        Err(e) if e.to_string().contains("UNIQUE") => flash_redirect(&back, "failed",
            &format!("Rule {} is already excluded for {} on {}.",
                     form.rule, client, site.server_name)),
        Err(e) => flash_redirect(&back, "failed", &format!("Could not save it: {e}")),
    }
}

// ─── post_exclusion_delete ───────────────────────────────

pub async fn post_exclusion_delete(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path((name, id)): Path<(String, i64)>,
) -> Result<Response> {

    let back = format!("/sites/{name}/exclusions");

    let Some((site_id, _)) = site_and_policy(&state, &name).await? else {
        return Ok(Redirect::to("/sites").into_response());
    };

    // Scoped to the site, so an id from one site's page cannot delete another
    // site's exclusion.
    let done = sqlx::query!(
        "DELETE FROM site_rule_exclusions WHERE id = ? AND site_id = ?",
        id, site_id
    )
    .execute(&state.db)
    .await?;

    if done.rows_affected() == 0 {
        return flash_redirect(&back, "failed", "That exclusion no longer exists.");
    }

    tracing::info!(site = %name, exclusion = id, "Rule exclusion removed");
    flash_redirect(&back, "success", "Exclusion removed — the rule applies to this site again.")
}

// ─── Helpers ─────────────────────────────────────────────

/// Read the form's single rule field into the two columns that store it.
///
/// Returns `(external_id, rule_id)`, exactly one of which is `Some` — the
/// shape the table's CHECK constraint requires.
fn parse_rule_ref(raw: &str) -> Option<(Option<i64>, Option<i64>)> {
    let (kind, num) = raw.split_once(':')?;
    let num: i64 = num.trim().parse().ok()?;
    match kind {
        "e" => Some((Some(num), None)),
        "r" => Some((None, Some(num))),
        _   => None,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_catalogue_rule_parses_into_the_external_id_column() {
        assert_eq!(parse_rule_ref("e:913015"), Some((Some(913015), None)));
    }

    #[test]
    fn a_custom_rule_parses_into_the_row_id_column() {
        assert_eq!(parse_rule_ref("r:42"), Some((None, Some(42))));
    }

    #[test]
    fn exactly_one_column_is_ever_set() {
        // The table's CHECK enforces this too. Asserted here as well because
        // the CHECK reports a constraint failure, and this is where the shape
        // is actually decided.
        for raw in ["e:1", "r:1", "e:913015", "r:999"] {
            let (ext, id) = parse_rule_ref(raw).expect("should parse");
            assert!(ext.is_some() ^ id.is_some(), "{raw} set both or neither");
        }
    }

    #[test]
    fn anything_else_is_refused_rather_than_guessed() {
        for raw in ["", "913015", "x:1", "e:", "e:abc", "e:1.5", ":1"] {
            assert_eq!(parse_rule_ref(raw), None, "{raw:?} should not parse");
        }
    }
}

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

use crate::{auth::get_session, error::Result, AppState};
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
    Path(name): Path<String>,
    Query(flash): Query<FlashQuery>,
) -> Result<Response> {
    let session = match get_session(&jar) {
        Some(s) => s,
        None    => return Ok(Redirect::to("/login").into_response()),
    };

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
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(form): Form<ExclusionForm>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

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
    let note = form.note.trim();

    let inserted = sqlx::query!(
        "INSERT INTO site_rule_exclusions (site_id, external_id, rule_id, path_prefix, note)
         VALUES (?, ?, ?, ?, ?)",
        site_id, external_id, rule_id, prefix, note
    )
    .execute(&state.db)
    .await;

    match inserted {
        Ok(_) => {
            tracing::info!(site = %name, rule = %form.rule, prefix, "Rule excluded for a site");
            let where_ = if prefix.is_empty() {
                "the whole site".to_string()
            } else {
                format!("paths under {prefix}")
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

// ─── post_exclusion_delete ───────────────────────────────

pub async fn post_exclusion_delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path((name, id)): Path<(String, i64)>,
) -> Result<Response> {
    if get_session(&jar).is_none() {
        return Ok(Redirect::to("/login").into_response());
    }

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

fn flash_redirect(path: &str, result: &str, msg: &str) -> Result<Response> {
    let msg_enc = urlencoding::encode(msg).into_owned();
    Ok(Redirect::to(&format!("{}?result={}&msg={}", path, result, msg_enc)).into_response())
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

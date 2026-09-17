// =========================================================
// routes/exclusions.rs — EasyWAF
// Rules a policy does not apply — where, and for whom.
//
// A rule can be right in general and wrong in one place: an
// application whose uploads look like an injection, a client
// whose tooling trips a scanner rule. An exclusion is the
// answer that leaves the rule running everywhere else, and it
// is deliberately small: one named rule, optionally confined
// to a path prefix and to a client address or block, with a
// note saying why.
//
// Exclusions belong to a policy since 0.12.1, like every
// other decision about what a request meets. Sites that face
// different things get different policies — the public
// websites one, each hosted application its own — so a policy
// is already the group an exclusion is decided for. Because
// one exclusion then covers every site on its policy, every
// place one is made says how many sites that is.
//
// It turns a rule off, so everything here is written to make
// what is off obvious: the policy's list, the rule editor,
// and the Traffic Monitor all show it.
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

// ─── Models ──────────────────────────────────────────────

/// One exclusion, as the list shows it.
#[derive(Debug, Serialize)]
pub struct Exclusion {
    pub id:          i64,
    pub policy_name: String,
    /// The rule's name, resolved through the policy at read time. A rule the
    /// policy no longer holds is labelled as such rather than hidden; see
    /// `list`.
    pub rule_label:  String,
    pub external_id: Option<i64>,
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
    /// The policy, by name, as the page's filter holds it.
    pub policy:      String,
    /// Either "e:913015" (catalogue number) or "r:42" (custom rule row).
    /// One field rather than two, because the form offers one list.
    pub rule:        String,
    pub path_prefix: String,
    /// An address or CIDR block, or empty for every client.
    pub client_cidr: String,
    pub note:        String,
}

#[derive(Debug, Deserialize)]
pub struct RemoveForm {
    /// The filter that was in view, so removing one does not lose the list.
    pub policy: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExclusionsQuery {
    /// Narrow to one policy. Absent means every exclusion in the installation.
    pub policy: Option<String>,
    pub result: Option<String>,
    pub msg:    Option<String>,
}

/// Form behind the Traffic Monitor's "exclude for this IP" button.
#[derive(Debug, Deserialize)]
pub struct FromTrafficForm {
    /// The traffic row's host, which leads to its site and so its policy.
    pub host:      String,
    pub client_ip: String,
    /// Catalogue number of the rule that matched.
    pub rule:      i64,
    pub rule_name: String,
    /// Where to return to, preserving whatever filter was applied.
    pub back:      Option<String>,
}

// ─── Queries ─────────────────────────────────────────────

async fn policy_id(state: &AppState, name: &str) -> Result<Option<i64>> {
    Ok(sqlx::query_scalar!("SELECT id FROM policies WHERE name = ?", name)
        .fetch_optional(&state.db)
        .await?
        .flatten())
}

/// The sites a policy covers, which is what an exclusion on it covers.
pub async fn sites_using(state: &AppState, policy_id: i64) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar!(
        "SELECT server_name FROM sites WHERE waf_policy_id = ? ORDER BY server_name",
        policy_id
    )
    .fetch_all(&state.db)
    .await?)
}

/// "every site using websites (4 sites)", or the one site's name — what an
/// exclusion on this policy reaches, said the same way everywhere.
pub fn reach(policy: &str, sites: &[String]) -> String {
    match sites {
        []  => format!("policy {policy}, which no site uses yet"),
        [s] => format!("{s}, the only site using {policy}"),
        _   => format!("every site using {policy} ({} sites)", sites.len()),
    }
}

/// Every exclusion, or one policy's, grouped by policy.
///
/// The rule name is resolved through the policy at read time rather than
/// copied in at write time: a copied name goes stale when an update renames the
/// rule, and the name is the only part of this a person reads. A rule the
/// policy no longer holds is labelled rather than removed — the set can be
/// reinstalled, and an exclusion that quietly removed itself in between would
/// come back as a false positive nobody remembers the cause of.
pub async fn list(state: &AppState, policy_id: Option<i64>) -> Result<Vec<Exclusion>> {
    let rows = sqlx::query!(
        r#"SELECT e.id          as "id!",
                  p.name        as "policy_name!",
                  e.external_id,
                  e.rule_id,
                  e.path_prefix as "path_prefix!",
                  e.client_cidr,
                  e.note        as "note!",
                  e.created_at  as "created_at!",
                  r.name        as "rule_name?"
           FROM   policy_rule_exclusions e
           JOIN   policies p ON p.id = e.policy_id
           LEFT   JOIN waf_rules r
                  ON  r.policy_id = e.policy_id
                  AND (   (e.external_id IS NOT NULL AND r.external_id = e.external_id)
                       OR (e.rule_id     IS NOT NULL AND r.id          = e.rule_id))
           WHERE  (? IS NULL OR e.policy_id = ?)
           ORDER  BY p.name, e.id DESC"#,
        policy_id, policy_id
    )
    .fetch_all(&state.db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Exclusion {
            id:          r.id,
            policy_name: r.policy_name,
            rule_label: match (r.rule_name, r.external_id, r.rule_id) {
                (Some(n), _, _)      => n,
                (None, Some(ext), _) => format!("rule {ext} (not in this policy)"),
                (None, _, Some(id))  => format!("custom rule #{id} (deleted)"),
                _                    => "unknown rule".to_string(),
            },
            external_id: r.external_id,
            path_prefix: r.path_prefix,
            client_cidr: r.client_cidr.unwrap_or_default(),
            note:        r.note,
            created_at:  r.created_at,
        })
        .collect())
}

/// The rules a policy holds, as choices for the add form.
///
/// Only enabled rules. A disabled rule is already not running, so offering it
/// here would be offering to turn off something that is off.
async fn candidates(state: &AppState, policy_id: i64) -> Result<Vec<Candidate>> {
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

fn page(policy: &str) -> String {
    if policy.is_empty() {
        "/exclusions".to_string()
    } else {
        format!("/exclusions?policy={}", urlencoding::encode(policy))
    }
}

// ─── get_exclusions ──────────────────────────────────────

/// Every rule that is not running, optionally narrowed to one policy — which
/// is also where one is added.
pub async fn get_exclusions(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Viewer(session): Viewer,
    Query(q): Query<ExclusionsQuery>,
) -> Result<Response> {

    let wanted = q.policy.clone().unwrap_or_default();
    let selected = if wanted.is_empty() { None } else { policy_id(&state, &wanted).await? };

    let policies = sqlx::query_scalar!("SELECT name FROM policies ORDER BY name")
        .fetch_all(&state.db)
        .await?;

    let (candidates, sites) = match selected {
        Some(id) => (candidates(&state, id).await?, sites_using(&state, id).await?),
        None     => (Vec::new(), Vec::new()),
    };

    let mut ctx = Context::new();
    crate::routes::who_context(&mut ctx, &session);
    ctx.insert("title",      "Rule Exclusions");
    ctx.insert("url",        "/exclusions");
    ctx.insert("policies",   &policies);
    ctx.insert("sel_policy", &if selected.is_some() { wanted.clone() } else { String::new() });
    ctx.insert("exclusions", &list(&state, selected).await?);
    ctx.insert("candidates", &candidates);
    ctx.insert("sites",      &sites);
    ctx.insert("reach",      &reach(&wanted, &sites));
    ctx.insert("result",     &q.result.unwrap_or_default());
    ctx.insert("msg",        &q.msg.unwrap_or_default());

    Ok((jar, Html(state.tera.render("policy_exclusions.html", &ctx)?)).into_response())
}

// ─── post_exclusion_add ──────────────────────────────────

pub async fn post_exclusion_add(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Form(form): Form<ExclusionForm>,
) -> Result<Response> {

    let back = page(&form.policy);
    let Some(policy) = policy_id(&state, &form.policy).await? else {
        return flash_redirect("/exclusions", "failed", "Select a policy first.");
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
            "A path prefix must start with \"/\" — leave it empty to cover every path.",
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
        "INSERT INTO policy_rule_exclusions
         (policy_id, external_id, rule_id, path_prefix, client_cidr, note)
         VALUES (?, ?, ?, ?, ?, ?)",
        policy, external_id, rule_id, prefix, client_opt, note
    )
    .execute(&state.db)
    .await;

    match inserted {
        Ok(_) => {
            tracing::info!(policy = %form.policy, rule = %form.rule, prefix, "Rule excluded for a policy");
            let sites = sites_using(&state, policy).await?;
            flash_redirect(&back, "success", &format!(
                "Rule excluded {} on {}. It no longer runs there, and no longer scores.",
                scope(prefix, client_opt), reach(&form.policy, &sites)
            ))
        }
        // The unique index. Reported as the harmless thing it is rather than
        // as a database error, because pressing Add twice is not a fault.
        Err(e) if e.to_string().contains("UNIQUE") => flash_redirect(
            &back, "failed", "That rule is already excluded for that path and those clients."),
        Err(e) => flash_redirect(&back, "failed", &format!("Could not save the exclusion: {e}")),
    }
}

/// "for every path and client", "under /dav", "for 203.0.113.9", or both.
fn scope(prefix: &str, client: Option<&str>) -> String {
    match (prefix.is_empty(), client) {
        (true,  None)    => "for every path and client".to_string(),
        (false, None)    => format!("under {prefix}"),
        (true,  Some(c)) => format!("for {c}"),
        (false, Some(c)) => format!("under {prefix} for {c}"),
    }
}

// ─── post_exclusion_remove ───────────────────────────────

/// Remove an exclusion, from wherever it was listed.
pub async fn post_exclusion_remove(
    State(state): State<AppState>,
    _jar: SignedCookieJar,
    _: Admin,
    Path(id): Path<i64>,
    Form(form): Form<RemoveForm>,
) -> Result<Response> {

    let back = page(form.policy.as_deref().unwrap_or(""));

    let done = sqlx::query!("DELETE FROM policy_rule_exclusions WHERE id = ?", id)
        .execute(&state.db)
        .await?;

    if done.rows_affected() == 0 {
        return flash_redirect(&back, "failed", "That exclusion no longer exists.");
    }

    tracing::info!(exclusion = id, "Rule exclusion removed");
    flash_redirect(&back, "success",
                   "Exclusion removed — the rule applies again from the next request.")
}

// ─── post_exclusion_from_traffic ─────────────────────────

/// Exclude one rule for one client, from the row that showed the block.
///
/// The whole point of the Traffic Monitor showing which rules produced a
/// verdict is that the fix should be reachable from there. Diagnosing a false
/// positive and then retyping the rule number and the address into another
/// page is where the diagnosis gets abandoned.
///
/// Deliberately the narrowest exclusion available: this rule, this client,
/// every path, on the policy of the site the request reached. The message says
/// how many sites that policy covers, because that is what was just excluded.
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
        "SELECT s.server_name, s.waf_policy_id, p.name as \"policy_name?\"
         FROM   sites s LEFT JOIN policies p ON p.id = s.waf_policy_id
         WHERE  s.server_name = ?",
        form.host
    )
    .fetch_optional(&state.db)
    .await?;

    let Some(site) = site else {
        return flash_redirect(&back, "failed",
            &format!("No site named {} — it may have been deleted.", form.host));
    };
    let (Some(policy), Some(policy_name)) = (site.waf_policy_id, site.policy_name) else {
        return flash_redirect(&back, "failed", &format!(
            "{} has no policy, so no rules run on it and there is nothing to exclude.",
            site.server_name));
    };

    let note = format!("Excluded from Traffic Monitor: {} was blocked for {} on {}",
                       client, form.rule_name, site.server_name);

    let done = sqlx::query!(
        "INSERT INTO policy_rule_exclusions
         (policy_id, external_id, rule_id, path_prefix, client_cidr, note)
         VALUES (?, ?, NULL, '', ?, ?)",
        policy, form.rule, client, note
    )
    .execute(&state.db)
    .await;

    let sites = sites_using(&state, policy).await?;
    match done {
        Ok(_) => {
            tracing::info!(policy = %policy_name, rule = form.rule, client,
                           "Rule excluded for a client from Traffic Monitor");
            flash_redirect(&back, "success", &format!(
                "Rule {} no longer runs for {} on {}. Every other client is still \
                 checked by it.", form.rule, client, reach(&policy_name, &sites)))
        }
        Err(e) if e.to_string().contains("UNIQUE") => flash_redirect(&back, "failed",
            &format!("Rule {} is already excluded for {} on {}.",
                     form.rule, client, reach(&policy_name, &sites))),
        Err(e) => flash_redirect(&back, "failed", &format!("Could not save it: {e}")),
    }
}

// ─── get_site_exclusions ─────────────────────────────────

/// The per-site page that existed until 0.12.1, kept as a redirect so a
/// bookmark lands on the policy that now holds the site's exclusions.
pub async fn get_site_exclusions(
    State(state): State<AppState>,
    _: Viewer,
    Path(name): Path<String>,
) -> Result<Response> {
    let policy: Option<String> = sqlx::query_scalar!(
        "SELECT p.name FROM sites s JOIN policies p ON p.id = s.waf_policy_id
         WHERE s.server_name = ?",
        name
    )
    .fetch_optional(&state.db)
    .await?;
    Ok(Redirect::to(&page(policy.as_deref().unwrap_or(""))).into_response())
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

    #[test]
    fn the_reach_of_an_exclusion_is_said_plainly() {
        // Whoever makes an exclusion has to see how far it goes: on a policy
        // several sites share, it goes to all of them.
        let one = vec!["cloud.example".to_string()];
        let many = vec!["a.example".to_string(), "b.example".to_string()];
        assert_eq!(reach("nextcloud", &one), "cloud.example, the only site using nextcloud");
        assert_eq!(reach("websites", &many), "every site using websites (2 sites)");
        assert!(reach("spare", &[]).contains("no site uses"));
    }
}

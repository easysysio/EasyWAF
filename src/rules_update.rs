// =========================================================
// rules_update.rs — EasyWAF
// Noticing that a newer rule set has been published.
//
// This module only *looks*. It fetches the channel manifest,
// caches it, and compares each policy's installed version
// against what is offered. Applying an update is a separate,
// deliberate action — an auto-applied bad rule is an outage
// across every site using that policy, and 0.5.4 is the
// evidence that a bad rule blocks real traffic.
//
// The cached manifest is treated as *unverified*: it says
// what versions exist, which is enough to raise a notice.
// Anything that changes what traffic is refused re-fetches
// and verifies before touching a rule.
// =========================================================

use crate::error::Result;
use serde::Serialize;
use sqlx::SqlitePool;
use std::time::Duration;

/// How often to look. Rule updates are not urgent — the point is that an
/// administrator finds out within a day, not within a minute.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Settings keys.
pub const KEY_URL:      &str = "rule_update_url";
pub const KEY_ENABLED:  &str = "rule_update_check";
const KEY_MANIFEST:     &str = "rule_manifest_cache";
const KEY_FETCHED:      &str = "rule_manifest_fetched";
const KEY_ERROR:        &str = "rule_manifest_error";

pub const DEFAULT_URL: &str = "https://repo.easysys.io/easywaf/rules";

// ─── Manifest ────────────────────────────────────────────

/// One set as the channel offers it.
#[derive(Debug, Clone, Serialize)]
pub struct OfferedSet {
    pub id:      String,
    pub name:    String,
    pub version: i64,
    pub tier:    String,
}

/// Parse the manifest. Hand-rolled rather than via a TOML struct because the
/// manifest is written by a different repository on its own schedule: an
/// unknown key it gains later must not stop an installation reading the
/// versions it does understand.
pub fn parse_manifest(text: &str) -> Vec<OfferedSet> {
    let mut out = Vec::new();
    for block in text.split("[[sets]]").skip(1) {
        let value = |key: &str| -> Option<String> {
            for line in block.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix(key) {
                    let rest = rest.trim_start();
                    if let Some(v) = rest.strip_prefix('=') {
                        return Some(v.trim().trim_matches('"').to_string());
                    }
                }
            }
            None
        };
        let (Some(id), Some(version)) = (value("id"), value("version")) else {
            continue;
        };
        let Ok(version) = version.parse::<i64>() else { continue };
        out.push(OfferedSet {
            name: value("name").unwrap_or_else(|| id.clone()),
            tier: value("tier").unwrap_or_else(|| "basic".into()),
            id,
            version,
        });
    }
    out
}

// ─── Available updates ───────────────────────────────────

/// A set a policy holds at an older version than the channel offers.
#[derive(Debug, Serialize)]
pub struct AvailableUpdate {
    pub policy_id:   i64,
    pub policy_name: String,
    pub set_id:      String,
    pub set_name:    String,
    pub have:        i64,
    pub offered:     i64,
}

/// Everything out of date, one row per policy and set.
///
/// A set is only reported for a policy that actually holds it. An update to a
/// set nobody has installed is not news, and reporting it would train people to
/// ignore the notice.
pub async fn available(db: &SqlitePool) -> Result<Vec<AvailableUpdate>> {
    let Some(text) = cached_manifest(db).await else {
        return Ok(Vec::new());
    };
    let offered = parse_manifest(&text);
    if offered.is_empty() {
        return Ok(Vec::new());
    }

    let held = sqlx::query!(
        r#"SELECT prs.policy_id as "policy_id!", p.name as "policy_name!",
                  prs.set_id as "set_id!", prs.version as "version!"
           FROM   policy_rule_sets prs
           JOIN   policies p ON p.id = prs.policy_id"#
    )
    .fetch_all(db)
    .await?;

    let mut out = Vec::new();
    for h in held {
        if let Some(o) = offered.iter().find(|o| o.id == h.set_id)
            && o.version > h.version
        {
            out.push(AvailableUpdate {
                policy_id:   h.policy_id,
                policy_name: h.policy_name,
                set_id:      h.set_id,
                set_name:    o.name.clone(),
                have:        h.version,
                offered:     o.version,
            });
        }
    }
    out.sort_by(|a, b| (&a.policy_name, &a.set_id).cmp(&(&b.policy_name, &b.set_id)));
    Ok(out)
}

// ─── Checking ────────────────────────────────────────────

/// Fetch the manifest and cache it.
///
/// Failure is stored, not shouted. A WAF is often on a network with no
/// outbound access at all, and a proxy that logged an error every few hours
/// because a repository is unreachable would train its operator to ignore its
/// log — which is the one thing a security appliance cannot afford.
pub async fn check(db: &SqlitePool) {
    if !enabled(db).await {
        return;
    }

    let base = url(db).await;
    let target = format!("{}/sets.toml", base.trim_end_matches('/'));

    let result = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build();
    let Ok(client) = result else { return };

    match client.get(&target).send().await {
        Ok(r) if r.status().is_success() => match r.text().await {
            Ok(body) => {
                let sets = parse_manifest(&body);
                if sets.is_empty() {
                    set(db, KEY_ERROR, "the manifest could not be parsed").await;
                    return;
                }
                let previous = cached_manifest(db).await.unwrap_or_default();
                set(db, KEY_MANIFEST, &body).await;
                set(db, KEY_FETCHED, &chrono::Utc::now().to_rfc3339()).await;
                set(db, KEY_ERROR, "").await;

                // Logged only when it changes, so a working installation is
                // silent rather than repeating itself every six hours.
                if previous != body {
                    tracing::info!(sets = sets.len(), "Rule channel manifest updated");
                }
            }
            Err(e) => set(db, KEY_ERROR, &format!("could not read the manifest: {e}")).await,
        },
        Ok(r)  => set(db, KEY_ERROR, &format!("channel returned HTTP {}", r.status())).await,
        Err(e) => set(db, KEY_ERROR, &format!("channel unreachable: {e}")).await,
    }
}

/// Check at startup and every few hours after.
pub fn spawn_check_task(db: SqlitePool) {
    tokio::spawn(async move {
        loop {
            check(&db).await;
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

// ─── Settings ────────────────────────────────────────────

pub async fn enabled(db: &SqlitePool) -> bool {
    match get(db, KEY_ENABLED).await {
        Some(v) => !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"),
        None    => true,
    }
}

pub async fn url(db: &SqlitePool) -> String {
    match get(db, KEY_URL).await {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _                               => DEFAULT_URL.to_string(),
    }
}

/// When the manifest was last fetched, and what went wrong if anything.
pub async fn status(db: &SqlitePool) -> (Option<String>, Option<String>) {
    let fetched = get(db, KEY_FETCHED).await.filter(|v| !v.trim().is_empty());
    let error   = get(db, KEY_ERROR).await.filter(|v| !v.trim().is_empty());
    (fetched, error)
}

async fn cached_manifest(db: &SqlitePool) -> Option<String> {
    get(db, KEY_MANIFEST).await.filter(|v| !v.trim().is_empty())
}

async fn get(db: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_scalar!("SELECT value FROM settings WHERE key = ?", key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

async fn set(db: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query!(
        "INSERT INTO settings (key, value, updated_at)
         VALUES (?, ?, datetime('now'))
         ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                        updated_at = excluded.updated_at",
        key, value
    )
    .execute(db)
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
generated = "2026-09-06T00:00:00Z"

[[sets]]
id      = "owasp-sqli"
name    = "SQL injection"
band    = 942
version = 3
file    = "sets/942-sqli.rules.toml"
sha256  = "abc"
tier    = "basic"

[[sets]]
id      = "wordpress"
name    = "WordPress"
band    = 955
version = 1
file    = "sets/955-wordpress.rules.toml"
tier    = "optional"
"#;

    #[test]
    fn reads_ids_and_versions() {
        let sets = parse_manifest(MANIFEST);
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0].id, "owasp-sqli");
        assert_eq!(sets[0].version, 3);
        assert_eq!(sets[0].tier, "basic");
        assert_eq!(sets[1].tier, "optional");
    }

    #[test]
    fn an_unknown_key_does_not_stop_it_reading_the_rest() {
        // The manifest is written by another repository on its own schedule.
        // A field added there later must not blind an installation to the
        // versions it does understand.
        let with_extra = MANIFEST.replace(
            "band    = 942",
            "band    = 942\nsomething_new = \"added later\"\nnested = { a = 1 }",
        );
        let sets = parse_manifest(&with_extra);
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[0].version, 3);
    }

    #[test]
    fn a_set_without_a_version_is_skipped_not_guessed() {
        let broken = MANIFEST.replace("version = 3", "");
        let sets = parse_manifest(&broken);
        assert_eq!(sets.len(), 1, "the unusable entry is dropped, the other kept");
        assert_eq!(sets[0].id, "wordpress");
    }

    #[test]
    fn nonsense_yields_nothing_rather_than_a_panic() {
        assert!(parse_manifest("").is_empty());
        assert!(parse_manifest("<html>404</html>").is_empty());
    }
}

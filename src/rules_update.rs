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
const KEY_MIRROR_ERROR: &str = "rule_mirror_error";

pub const DEFAULT_URL: &str = "https://repo.easysys.io/easywaf/rules";

// ─── Manifest ────────────────────────────────────────────

/// One set as the channel offers it.
#[derive(Debug, Clone, Serialize)]
pub struct OfferedSet {
    pub id:          String,
    pub name:        String,
    pub version:     i64,
    pub tier:        String,
    /// Empty when the channel does not carry one. Older channels do not, and a
    /// missing description is a set that reads plainly, not one that fails.
    pub description: String,
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
            name:        value("name").unwrap_or_else(|| id.clone()),
            tier:        value("tier").unwrap_or_else(|| "basic".into()),
            description: value("description").unwrap_or_default(),
            id,
            version,
        });
    }
    out
}

/// One set as the catalogue shows it, for a particular policy.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogSet {
    pub id:          String,
    pub name:        String,
    pub description: String,
    pub tier:        String,
    /// What the channel offers. `None` for a set this policy holds that the
    /// channel has stopped publishing — worth showing rather than hiding, since
    /// the rules are still enforcing.
    pub offered:     Option<i64>,
    /// What this policy holds, if anything.
    pub held:        Option<i64>,
    /// `new`, `current`, `update`, or `withdrawn`. Decided here so the template
    /// does not have to compare two optional numbers, which is where a display
    /// that quietly says the wrong thing comes from.
    pub status:      String,
    pub rules:       i64,
}

/// Every set the channel offers, plus any this policy holds that it no longer
/// does, in one list.
///
/// This is what makes an optional set installable. `available()` reports only
/// sets a policy already has, because an update to something nobody installed
/// is not news — but that same rule meant a set you had never installed could
/// never be found either, and `tier = "optional"` had nothing that could act
/// on it.
pub async fn catalog(db: &SqlitePool, policy_id: i64) -> Result<Vec<CatalogSet>> {
    let offered = match cached_manifest(db).await {
        Some(text) => parse_manifest(&text),
        None       => Vec::new(),
    };

    let held = sqlx::query!(
        r#"SELECT set_id as "set_id!", version as "version!", name as "name!"
           FROM   policy_rule_sets WHERE policy_id = ?"#,
        policy_id
    )
    .fetch_all(db)
    .await?;

    // How many rules of each set this policy actually has, so the page can say
    // what installing one brought rather than only that it happened.
    let counts = sqlx::query!(
        r#"SELECT rule_set as "set_id!", COUNT(*) as "n!: i64"
           FROM   waf_rules
           WHERE  policy_id = ? AND rule_set IS NOT NULL AND external_id IS NOT NULL
           GROUP  BY rule_set"#,
        policy_id
    )
    .fetch_all(db)
    .await?;
    let count_of = |id: &str| -> i64 {
        counts.iter().find(|c| c.set_id == id).map(|c| c.n).unwrap_or(0)
    };

    let mut out: Vec<CatalogSet> = offered
        .iter()
        .map(|o| {
            let have = held.iter().find(|h| h.set_id == o.id).map(|h| h.version);
            let status = match have {
                None                        => "new",
                Some(v) if o.version > v    => "update",
                Some(_)                     => "current",
            };
            CatalogSet {
                id:          o.id.clone(),
                name:        o.name.clone(),
                description: o.description.clone(),
                tier:        o.tier.clone(),
                offered:     Some(o.version),
                held:        have,
                status:      status.to_string(),
                rules:       count_of(&o.id),
            }
        })
        .collect();

    // Installed but no longer published. Still enforcing, so still shown.
    for h in &held {
        if !offered.iter().any(|o| o.id == h.set_id) {
            out.push(CatalogSet {
                id:          h.set_id.clone(),
                name:        h.name.clone(),
                description: String::new(),
                tier:        String::new(),
                offered:     None,
                held:        Some(h.version),
                status:      "withdrawn".to_string(),
                rules:       count_of(&h.set_id),
            });
        }
    }

    // Installed first, then what can be added, each alphabetically: the sets
    // already enforcing are the ones an operator is usually looking for.
    out.sort_by(|a, b| {
        let rank = |c: &CatalogSet| match c.status.as_str() {
            "update" => 0,
            "current" => 1,
            "withdrawn" => 2,
            _ => 3,
        };
        (rank(a), a.name.clone()).cmp(&(rank(b), b.name.clone()))
    });
    Ok(out)
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

            // Mirror after checking, on the same schedule and behind the same
            // switch. A failure is stored the way a failed check is: an
            // appliance with no outbound access is the ordinary case, and one
            // that filled its log every six hours about a repository it cannot
            // reach would teach its operator to stop reading the log.
            if enabled(&db).await {
                match sync_cache(&db).await {
                    Ok(_)  => set(&db, KEY_MIRROR_ERROR, "").await,
                    Err(e) => set(&db, KEY_MIRROR_ERROR, &e).await,
                }
            }

            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

// ─── Applying ────────────────────────────────────────────

/// The trust anchor: the key the channel is signed with.
///
/// Read from `rules/key.gpg`, which ships beside the bundled sets and is
/// fetched by `scripts/fetch-rules.sh` — so the key arrives with the binary,
/// reviewed by whoever cut the release, rather than from the same connection
/// as the thing it is meant to vouch for. Fetching the key from the channel at
/// run time would verify the channel against itself.
fn trusted_key() -> std::result::Result<String, String> {
    std::fs::read_to_string("rules/key.gpg").map_err(|_| {
        "No signing key at rules/key.gpg, so nothing can be verified. It ships \
         with EasyWAF; if this installation was built without one, take the \
         update as a file instead."
            .to_string()
    })
}

/// Fetch one set, verified, and install it into a policy.
///
/// Order matters: the manifest is fetched and its signature checked *before*
/// anything is read from it, and the set is checked against the hash in that
/// verified manifest before a single rule is written. Nothing touches the
/// database until both hold.
pub async fn apply(db: &SqlitePool, policy_id: i64, set_id: &str) -> std::result::Result<String, String> {
    let key = trusted_key()?;

    // The mirror first. It holds the manifest, its signature and the sets, and
    // is verified here exactly as the network copy would be — reading from disk
    // changes where the bytes come from, not what has to be proved about them.
    // A mirror that is missing, incomplete or stale falls through to the
    // network rather than failing.
    if let Some(result) = apply_from_cache(db, policy_id, set_id, &key).await {
        return result;
    }

    let base = url(db).await;
    let base = base.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("{e}"))?;

    let fetch = |u: String| {
        let c = client.clone();
        async move {
            let r = c.get(&u).send().await.map_err(|e| format!("{u}: {e}"))?;
            if !r.status().is_success() {
                return Err(format!("{u}: HTTP {}", r.status()));
            }
            r.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("{u}: {e}"))
        }
    };

    let manifest = fetch(format!("{base}/sets.toml")).await?;
    let signature = fetch(format!("{base}/sets.toml.asc")).await?;
    let signature = String::from_utf8(signature).map_err(|_| "the signature is not text".to_string())?;

    let signer = crate::pgp_verify::verify_detached(&key, &manifest, &signature)?;
    let manifest = String::from_utf8(manifest).map_err(|_| "the manifest is not text".to_string())?;

    // Everything below is read from a manifest whose signature has been
    // checked, so the file name and hash are as trustworthy as the versions.
    let entry = manifest_entry(&manifest, set_id)
        .ok_or_else(|| format!("the channel does not offer a set called '{set_id}'"))?;

    let body = fetch(format!("{base}/{}", entry.file)).await?;
    let digest = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    if digest != entry.sha256 {
        return Err(format!(
            "{} does not match the signed manifest: {} rather than {}",
            entry.file, &digest[..12], &entry.sha256.chars().take(12).collect::<String>()
        ));
    }

    let text = String::from_utf8(body).map_err(|_| "the rule set is not text".to_string())?;
    let count = crate::routes::rules::install_set(db, policy_id, set_id, entry.version, &text)
        .await
        .map_err(|e| format!("{e}"))?;

    tracing::info!(policy_id, set_id, version = entry.version, rules = count,
                   "Applied a rule set update, signed by {}", signer);
    Ok(format!("{} updated to v{} — {} rules, signed by {}", set_id, entry.version, count, signer))
}

/// One set's entry in the manifest, including what the versions alone omit.
struct ManifestEntry {
    file:    String,
    sha256:  String,
    version: i64,
}

fn manifest_entry(manifest: &str, set_id: &str) -> Option<ManifestEntry> {
    for block in manifest.split("[[sets]]").skip(1) {
        let value = |key: &str| -> Option<String> {
            block.lines().find_map(|l| {
                let l = l.trim();
                l.strip_prefix(key)
                    .and_then(|r| r.trim_start().strip_prefix('='))
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
        };
        if value("id").as_deref() != Some(set_id) {
            continue;
        }
        return Some(ManifestEntry {
            file:    value("file")?,
            sha256:  value("sha256")?,
            version: value("version")?.parse().ok()?,
        });
    }
    None
}

/// Install a set from the on-disk mirror, or `None` if it cannot serve this one.
///
/// `None` means "not here, try the network" and is not a failure: a first run
/// has no mirror, and a set published since the last sync is not in it yet.
/// `Some(Err(..))` is a real refusal — the mirror exists and does not verify,
/// which is worth reporting rather than silently reaching past.
async fn apply_from_cache(
    db: &SqlitePool,
    policy_id: i64,
    set_id: &str,
    key: &str,
) -> Option<std::result::Result<String, String>> {
    let dir = cache_dir();
    let manifest = std::fs::read(dir.join("sets.toml")).ok()?;
    let signature = std::fs::read_to_string(dir.join("sets.toml.asc")).ok()?;

    let signer = match crate::pgp_verify::verify_detached(key, &manifest, &signature) {
        Ok(s)  => s,
        Err(e) => return Some(Err(format!("the mirrored manifest does not verify: {e}"))),
    };
    let manifest = String::from_utf8(manifest).ok()?;
    let entry = manifest_entry(&manifest, set_id)?;

    let name = std::path::Path::new(&entry.file).file_name()?;
    let body = std::fs::read(dir.join("sets").join(name)).ok()?;

    let digest: String = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect()
    };
    if digest != entry.sha256 {
        // Not a fall-through. The file is here and is not what the signed
        // manifest describes, which is exactly the case worth refusing loudly.
        return Some(Err(format!(
            "the mirrored copy of {} does not match the signed manifest: {} rather than {}",
            entry.file,
            &digest[..12.min(digest.len())],
            &entry.sha256[..12.min(entry.sha256.len())]
        )));
    }

    let text = match String::from_utf8(body) {
        Ok(t)  => t,
        Err(_) => return Some(Err(format!("{} is not valid UTF-8", entry.file))),
    };

    let count = match crate::routes::rules::install_set(db, policy_id, set_id, entry.version, &text)
        .await
    {
        Ok(c)  => c,
        Err(e) => return Some(Err(format!("{e}"))),
    };

    Some(Ok(format!(
        "{set_id} updated to v{} — {count} rules, signed by {signer}, from the local mirror",
        entry.version
    )))
}

// ─── Local cache ─────────────────────────────────────────

/// Where the channel is mirrored on disk.
///
/// Beside the database, never inside `rules/`. That directory is shipped by the
/// .deb and .rpm, so a process writing there would have every package upgrade
/// either clobber the mirror or leave dpkg asking about modified files. The
/// database's directory is already the one place an installation owns and a
/// package does not.
pub fn cache_dir() -> std::path::PathBuf {
    let url = crate::config::database_url();
    let path = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .unwrap_or(&url);
    let parent = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    parent.join("rules-cache")
}

/// The one directory anything reads rule sets from at runtime.
///
/// There is deliberately only one. The package ships `rules/`, that seeds this
/// on first run, the channel refreshes it, and every reader looks here. The
/// alternative — a bundle and a mirror, each authoritative for different
/// callers — needed a rule per caller about which to use, and rules like that
/// are learned by being caught out by them.
///
/// Falls back to the bundle if seeding never managed to run, so a broken or
/// read-only data directory degrades to the old behaviour instead of leaving
/// the GUI with no rules to show.
pub fn rules_source() -> std::path::PathBuf {
    let cache = cache_dir().join("sets");
    let usable = std::fs::read_dir(&cache)
        .map(|mut d| {
            d.any(|e| {
                e.ok().is_some_and(|e| {
                    e.file_name().to_str().is_some_and(|n| n.ends_with(".rules.toml"))
                })
            })
        })
        .unwrap_or(false);
    if usable { cache } else { std::path::PathBuf::from("rules") }
}

/// Copy the packaged sets into the mirror, once, when it is empty.
///
/// This is what makes one directory enough. A first run has no network and
/// therefore no mirror; without a seed every reader would have to fall back to
/// the bundle, which is the two-source design again with extra steps.
///
/// No signature is written. The bundle is trusted because it arrived inside a
/// package that was itself verified, not because of anything in the directory —
/// and a seeded mirror therefore cannot satisfy `apply_from_cache`, which wants
/// a signature. That is correct rather than unfortunate: content that came with
/// the binary is fine to *import*, and a channel *update* should still be proved
/// before it overwrites a rule.
pub fn seed_cache_from_bundle() {
    let cache = cache_dir();
    let sets = cache.join("sets");
    let already = std::fs::read_dir(&sets)
        .map(|mut d| d.any(|e| e.is_ok()))
        .unwrap_or(false);
    if already {
        return;
    }

    let bundle = std::path::Path::new("rules");
    let Ok(entries) = std::fs::read_dir(bundle) else { return };

    if std::fs::create_dir_all(&sets).is_err() {
        tracing::warn!(dir = %sets.display(), "Could not create the rule directory");
        return;
    }

    let mut copied = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(n) = name.to_str() else { continue };
        if !n.ends_with(".rules.toml") {
            continue;
        }
        if std::fs::copy(entry.path(), sets.join(n)).is_ok() {
            copied += 1;
        }
    }

    // The bundle's own manifest, which is what lets Import tell basic from
    // optional. Absent on an installation built before the bundle carried one;
    // Import then falls back to taking everything, which for a bundle that only
    // ever held basic sets is the same answer.
    let _ = std::fs::copy(bundle.join("sets.toml"), cache.join("sets.toml"));

    if copied > 0 {
        tracing::info!(sets = copied, dir = %sets.display(), "Seeded the rule directory from the packaged sets");
    }
}

/// Which sets the manifest beside the rules marks as `basic`.
///
/// `None` when there is no manifest to read — an older bundle, or a directory
/// that has never synced. Callers take that to mean "no filter", which is right
/// for a bundle that only ever contained basic sets.
pub fn basic_set_ids() -> Option<std::collections::HashSet<String>> {
    let manifest = std::fs::read_to_string(cache_dir().join("sets.toml"))
        .or_else(|_| std::fs::read_to_string("rules/sets.toml"))
        .ok()?;
    let ids: std::collections::HashSet<String> = parse_manifest(&manifest)
        .into_iter()
        .filter(|s| s.tier == "basic")
        .map(|s| s.id)
        .collect();
    if ids.is_empty() { None } else { Some(ids) }
}

/// Mirror the channel to disk: the manifest, its signature, and every set.
///
/// The signature and the manifest are stored **beside** the sets rather than
/// checked once and thrown away. Verifying at download and trusting the disk
/// afterwards would make this directory a way to install rules — and on a WAF,
/// installing rules is how you switch protection off. Applying still verifies;
/// it simply reads what it verifies from here instead of the network.
///
/// Written to a staging directory and renamed into place, so a mirror is never
/// half a version: an interrupted sync leaves the previous one intact.
pub async fn sync_cache(db: &SqlitePool) -> std::result::Result<usize, String> {
    let key = trusted_key()?;
    let base = url(db).await;
    let base = base.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("{e}"))?;
    let fetch = |u: String| {
        let c = client.clone();
        async move {
            let r = c.get(&u).send().await.map_err(|e| format!("{u}: {e}"))?;
            if !r.status().is_success() {
                return Err(format!("{u}: HTTP {}", r.status()));
            }
            r.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("{u}: {e}"))
        }
    };

    let manifest = fetch(format!("{base}/sets.toml")).await?;
    let signature = fetch(format!("{base}/sets.toml.asc")).await?;
    let signature_text =
        String::from_utf8(signature).map_err(|_| "the signature is not text".to_string())?;

    // Verified before anything is written, so a channel that cannot prove
    // itself never reaches the disk at all.
    crate::pgp_verify::verify_detached(&key, &manifest, &signature_text)?;
    let manifest_text =
        String::from_utf8(manifest.clone()).map_err(|_| "the manifest is not text".to_string())?;

    let dir = cache_dir();
    let stage = dir.with_extension("new");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(stage.join("sets")).map_err(|e| format!("{}: {e}", stage.display()))?;

    let mut written = 0usize;
    for set in parse_manifest(&manifest_text) {
        let Some(entry) = manifest_entry(&manifest_text, &set.id) else { continue };
        let body = fetch(format!("{base}/{}", entry.file)).await?;

        let digest: String = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect()
        };
        if digest != entry.sha256 {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(format!(
                "{} does not match the signed manifest: {} rather than {}",
                entry.file,
                &digest[..12.min(digest.len())],
                &entry.sha256[..12.min(entry.sha256.len())]
            ));
        }

        let name = std::path::Path::new(&entry.file)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("{}.rules.toml", set.id));
        std::fs::write(stage.join("sets").join(&name), &body)
            .map_err(|e| format!("{name}: {e}"))?;
        written += 1;
    }

    std::fs::write(stage.join("sets.toml"), &manifest).map_err(|e| format!("sets.toml: {e}"))?;
    std::fs::write(stage.join("sets.toml.asc"), signature_text.as_bytes())
        .map_err(|e| format!("sets.toml.asc: {e}"))?;

    // Both under the same parent, so these are renames rather than copies.
    let old = dir.with_extension("old");
    let _ = std::fs::remove_dir_all(&old);
    if dir.exists() {
        std::fs::rename(&dir, &old).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    if let Err(e) = std::fs::rename(&stage, &dir) {
        let _ = std::fs::rename(&old, &dir);
        return Err(format!("{}: {e}", dir.display()));
    }
    let _ = std::fs::remove_dir_all(&old);

    tracing::info!(sets = written, dir = %dir.display(), "Mirrored the rule channel to disk");
    Ok(written)
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

/// What went wrong mirroring the channel to disk, if anything.
pub async fn mirror_status(db: &SqlitePool) -> (usize, Option<String>) {
    let sets = std::fs::read_dir(cache_dir().join("sets"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".rules.toml"))
                .count()
        })
        .unwrap_or(0);
    let error = get(db, KEY_MIRROR_ERROR).await.filter(|v| !v.trim().is_empty());
    (sets, error)
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

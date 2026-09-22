// =========================================================
// iplist_feeds.rs — EasyWAF
// Published IP lists: fetched on a schedule, verified, and
// applied only as far as an operator has said.
//
// The data updates itself; the response does not. A list is
// fetched from the signed channel, checked the way a rule set
// is, and mirrored to disk whether or not anyone uses it —
// fresh data harms nobody while nothing is switched on. What
// a list *does* is a choice each policy makes in the database:
// off, challenge or block. Nothing a list says has any effect
// until somebody has said what it should mean for that policy.
//
// The ranges never touch the database. They arrive as whole
// files, carry licence text their sources require to stay
// with them, and are replaced wholesale every day; a few
// hundred thousand rows deleted and reinserted daily is a
// cost with no benefit. The mirror is the store, and like
// the rule mirror it is not trusted for being local: every
// load checks the signature and every file's hash again.
// =========================================================

use crate::iplist::{self, FeedData, Response};
use serde::Serialize;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

/// Lists are rebuilt daily upstream. Looking four times a day means a fresh one
/// arrives within hours, with no installation polling anybody every minute.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Settings keys.
pub const KEY_URL: &str = "ip_list_url";
const KEY_FETCHED:  &str = "ip_list_fetched";
const KEY_ERROR:    &str = "ip_list_error";

pub const DEFAULT_URL: &str = "https://repo.easysys.io/easywaf/lists";

const MANIFEST:  &str = "lists.toml";
const SIGNATURE: &str = "lists.toml.asc";
const FILES:     &str = "lists";

// ─── Manifest ────────────────────────────────────────────

/// One list as the channel offers it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct OfferedList {
    pub id:          String,
    pub name:        String,
    pub description: String,
    /// Shown beside the list. The sources' terms are why lists are never
    /// merged: each keeps its own licence and its own credit line.
    pub licence:     String,
    pub attribution: String,
    /// A serial set by the daily job, not a number anybody chooses.
    pub version:     String,
    pub entries:     i64,
    /// What the publisher suggests. It pre-selects the choice on the page and
    /// changes nothing by itself.
    pub suggested:   String,
    file:            String,
    sha256:          String,
}

/// Parse the manifest.
///
/// Hand-rolled for the reason `rules_update::parse_manifest` is: the manifest
/// is written by another repository on its own schedule, and a key it gains
/// later must not stop an installation reading the lists it does understand.
pub fn parse_manifest(text: &str) -> Vec<OfferedList> {
    let mut out = Vec::new();
    for block in text.split("[[lists]]").skip(1) {
        let value = |key: &str| -> Option<String> {
            block.lines().find_map(|line| {
                let rest = line.trim().strip_prefix(key)?.trim_start();
                let v = rest.strip_prefix('=')?;
                Some(v.trim().trim_matches('"').to_string())
            })
        };
        let (Some(id), Some(file), Some(sha256)) = (value("id"), value("file"), value("sha256"))
        else {
            continue;
        };
        // The id names a file on disk and a row in the database. Anything but
        // a plain slug is skipped rather than escaped.
        if !is_slug(&id) {
            continue;
        }
        out.push(OfferedList {
            name:        value("name").unwrap_or_else(|| id.clone()),
            description: value("description").unwrap_or_default(),
            licence:     value("licence").unwrap_or_default(),
            attribution: value("attribution").unwrap_or_default(),
            version:     value("version").unwrap_or_default(),
            entries:     value("entries").and_then(|v| v.parse().ok()).unwrap_or(0),
            suggested:   value("response")
                            .filter(|r| Response::parse(r).is_some())
                            .unwrap_or_else(|| Response::Challenge.as_str().to_string()),
            sha256:      sha256.to_ascii_lowercase(),
            file,
            id,
        });
    }
    out
}

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether a manifest's file path may be appended to the channel URL.
///
/// The manifest is signed, so this is not the line of defence — but a signed
/// manifest naming `../../something` is still not something to follow.
fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

fn short(digest: &str) -> &str {
    &digest[..12.min(digest.len())]
}

// ─── The mirror ──────────────────────────────────────────

/// Where the channel is mirrored: beside the rule mirror, for the reasons
/// `rules_update::cache_dir` gives.
pub fn cache_dir() -> PathBuf {
    crate::rules_update::cache_dir().with_file_name("lists-cache")
}

/// Where one list's file sits. Named by its id, never by the path the manifest
/// gives, so nothing a channel says can choose where a file is written.
fn local_file(dir: &Path, id: &str) -> PathBuf {
    dir.join(FILES).join(format!("{id}.txt"))
}

/// The signed manifest, read from the mirror and proved.
fn verified_manifest(dir: &Path, key: &str) -> Result<Vec<OfferedList>, String> {
    let manifest = std::fs::read(dir.join(MANIFEST))
        .map_err(|_| "nothing has been fetched from the channel yet".to_string())?;
    let signature = std::fs::read_to_string(dir.join(SIGNATURE))
        .map_err(|_| "the mirror has no signature for its manifest".to_string())?;
    crate::pgp_verify::verify_detached(key, &manifest, &signature)?;
    let text = String::from_utf8(manifest).map_err(|_| "the manifest is not text".to_string())?;
    Ok(parse_manifest(&text))
}

/// One list's file, read from the mirror and checked against the manifest.
fn verified_file(dir: &Path, list: &OfferedList) -> Result<String, String> {
    let body = std::fs::read(local_file(dir, &list.id))
        .map_err(|_| "its file is missing from the mirror".to_string())?;
    let digest = sha256_hex(&body);
    if digest != list.sha256 {
        return Err(format!(
            "its file does not match the signed manifest ({} rather than {})",
            short(&digest),
            short(&list.sha256)
        ));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Fetch the channel and replace the mirror with it.
///
/// All or nothing. The manifest is verified before anything is written, every
/// file is checked against it, and the new mirror is staged and renamed into
/// place — so an interrupted or refused sync leaves yesterday's lists, which
/// are still better than none.
pub async fn sync(db: &SqlitePool) -> Result<usize, String> {
    let key = crate::rules_update::trusted_key();
    let base = url(db).await;
    let base = base.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
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

    let manifest = fetch(format!("{base}/{MANIFEST}")).await?;
    let signature = fetch(format!("{base}/{SIGNATURE}")).await?;
    let signature =
        String::from_utf8(signature).map_err(|_| "the signature is not text".to_string())?;
    crate::pgp_verify::verify_detached(&key, &manifest, &signature)?;
    let text =
        String::from_utf8(manifest.clone()).map_err(|_| "the manifest is not text".to_string())?;

    let offered = parse_manifest(&text);
    if offered.is_empty() {
        return Err("the channel's manifest offers no lists".to_string());
    }

    // Every file in hand before anything is written, so the mirror is built
    // the same way whether the bundle arrived over HTTP or was carried in.
    let mut files: HashMap<String, Vec<u8>> = HashMap::new();
    for list in &offered {
        if !safe_relative(&list.file) {
            return Err(format!("{}: refusing the file path {:?}", list.id, list.file));
        }
        files.insert(list.id.clone(), fetch(format!("{base}/{}", list.file)).await?);
    }

    // Applied as it arrives unless this installation says otherwise. A list's
    // value is its freshness, so that is the default; an installation with
    // change control that forbids it turns the switch off and applies by hand.
    if crate::routes::updates::auto(db, crate::routes::updates::KEY_AUTO_LISTS).await {
        let written = install_bundle(&manifest, &signature, &files)?;
        tracing::info!(lists = written, "Mirrored the IP list channel");
        return Ok(written);
    }

    let held = cache_dir().with_extension("held");
    let _ = std::fs::remove_dir_all(&held);
    std::fs::create_dir_all(held.join(FILES)).map_err(|e| format!("{}: {e}", held.display()))?;
    for list in &offered {
        if let Some(body) = files.get(&list.id) {
            // Checked before it is written, even though it is not in force: a
            // held bundle that cannot verify is not worth keeping.
            if sha256_hex(body) != list.sha256 {
                let _ = std::fs::remove_dir_all(&held);
                return Err(format!("{} does not match the signed manifest", list.file));
            }
            std::fs::write(local_file(&held, &list.id), body)
                .map_err(|e| format!("{}: {e}", list.id))?;
        }
    }
    std::fs::write(held.join(MANIFEST), &manifest).map_err(|e| format!("{MANIFEST}: {e}"))?;
    std::fs::write(held.join(SIGNATURE), signature.as_bytes())
        .map_err(|e| format!("{SIGNATURE}: {e}"))?;

    tracing::info!(lists = offered.len(),
                   "Fetched the IP list channel and held it — this installation applies lists by hand");
    Ok(offered.len())
}

/// A bundle that was fetched and not put in force, because this installation
/// applies lists by hand.
///
/// It sits beside the mirror rather than in it: what is serving traffic must
/// not change because something was fetched.
pub fn held_bundle() -> Option<std::path::PathBuf> {
    let held = cache_dir().with_extension("held");
    held.join(MANIFEST).exists().then_some(held)
}

/// Put a held bundle in force.
pub fn apply_held() -> Result<usize, String> {
    let Some(held) = held_bundle() else {
        return Err("nothing has been fetched that is waiting to be applied".to_string());
    };
    let manifest = std::fs::read(held.join(MANIFEST)).map_err(|e| format!("{MANIFEST}: {e}"))?;
    let signature = std::fs::read_to_string(held.join(SIGNATURE))
        .map_err(|e| format!("{SIGNATURE}: {e}"))?;

    // Read back through the same door it came in by: verified again here, so
    // anything that changed the held copy on disk is caught before it serves.
    let mut files = HashMap::new();
    for list in parse_manifest(&String::from_utf8_lossy(&manifest)) {
        if let Ok(body) = std::fs::read(local_file(&held, &list.id)) {
            files.insert(list.id.clone(), body);
        }
    }
    let n = install_bundle(&manifest, &signature, &files)?;
    let _ = std::fs::remove_dir_all(&held);
    reload();
    Ok(n)
}

/// Build the list mirror from a manifest, its signature and the files it
/// names, whether they were fetched or uploaded.
///
/// All or nothing, and the same bar either way: the signature is checked
/// before anything is written, every file against the hash the signed manifest
/// gives for it, and the new mirror is staged and renamed into place — so a
/// refused bundle leaves yesterday's lists, which are better than none.
///
/// Files are keyed by list id rather than by the path the manifest gives:
/// nothing a channel or an uploader says may decide where a file is written.
pub fn install_bundle(
    manifest:  &[u8],
    signature: &str,
    files:     &HashMap<String, Vec<u8>>,
) -> Result<usize, String> {
    let key = crate::rules_update::trusted_key();
    crate::pgp_verify::verify_detached(&key, manifest, signature)?;
    let text = String::from_utf8(manifest.to_vec())
        .map_err(|_| "the manifest is not text".to_string())?;

    let offered = parse_manifest(&text);
    if offered.is_empty() {
        return Err("that manifest offers no lists".to_string());
    }

    let dir = cache_dir();
    let stage = dir.with_extension("new");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(stage.join(FILES))
        .map_err(|e| format!("{}: {e}", stage.display()))?;

    let staged: Result<(), String> = (|| {
        for list in &offered {
            if !safe_relative(&list.file) {
                return Err(format!("{}: refusing the file path {:?}", list.id, list.file));
            }
            let Some(body) = files.get(&list.id) else {
                return Err(format!(
                    "{} is named in the manifest and is not in the bundle", list.file));
            };
            let digest = sha256_hex(body);
            if digest != list.sha256 {
                return Err(format!(
                    "{} does not match the signed manifest: {} rather than {}",
                    list.file,
                    short(&digest),
                    short(&list.sha256)
                ));
            }
            std::fs::write(local_file(&stage, &list.id), body)
                .map_err(|e| format!("{}: {e}", list.id))?;
        }
        std::fs::write(stage.join(MANIFEST), manifest)
            .map_err(|e| format!("{MANIFEST}: {e}"))?;
        std::fs::write(stage.join(SIGNATURE), signature.as_bytes())
            .map_err(|e| format!("{SIGNATURE}: {e}"))
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
    }

    // Under the same parent, so these are renames rather than copies.
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

    Ok(offered.len())
}

// ─── Loading ─────────────────────────────────────────────

/// How a switched-on list fared when it was last loaded.
#[derive(Debug, Clone, Default)]
struct LoadStatus {
    ranges:     usize,
    unreadable: usize,
    error:      Option<String>,
}

static STATUS: OnceLock<RwLock<HashMap<String, LoadStatus>>> = OnceLock::new();

fn status_map() -> &'static RwLock<HashMap<String, LoadStatus>> {
    STATUS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Whose lists these are.
///
/// A decision belongs to one policy, or to every policy — the second reaching
/// the policies that exist and the ones made later, which is the only way to
/// say "never here, wherever here turns out to be" once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Policy(i64),
    Everywhere,
}

impl Scope {
    /// The stored `policy_id`: NULL for every policy.
    pub fn id(self) -> Option<i64> {
        match self {
            Scope::Policy(id)  => Some(id),
            Scope::Everywhere  => None,
        }
    }
}

/// What an operator has decided about one list.
struct Choice {
    enabled:  bool,
    response: Response,
}

async fn choices(db: &SqlitePool, scope: Scope) -> HashMap<String, Choice> {
    // `IS` rather than `=`, so the every-policy rows — the ones with no
    // policy_id — can be asked for with the same query.
    let policy_id = scope.id();
    sqlx::query!(
        r#"SELECT id as "id!", enabled as "enabled!", response as "response!"
           FROM ip_list_feeds WHERE policy_id IS ?"#,
        policy_id
    )
        .fetch_all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            (r.id, Choice {
                enabled:  r.enabled != 0,
                // The column's CHECK makes anything else unreachable. Were it
                // reached, challenge is the answer that cannot lock anyone out.
                response: Response::parse(&r.response).unwrap_or(Response::Challenge),
            })
        })
        .collect()
}

/// Load every list the mirror offers into memory, for every policy to use.
///
/// Called at startup and after every sync. Which policies use a list, and how,
/// is read by the matcher itself when it rebuilds; loading every offered list
/// rather than only those some policy has switched on keeps a newly switched-on
/// list from waiting for the next sync. A few thousand ranges each, parsed once.
///
/// A mirror that cannot prove itself loads nothing. That lets through what the
/// lists would have stopped — and every list says so on the page — rather than
/// enforcing data nobody can vouch for. The manual lists are not touched.
pub fn reload() -> usize {
    let dir = cache_dir();
    let mut status = HashMap::new();
    let mut loaded = HashMap::new();
    let failed = |e: String| LoadStatus { error: Some(e), ..LoadStatus::default() };

    match verified_manifest(&dir, &crate::rules_update::trusted_key()) {
        Err(e) => {
            // Quiet when nothing was ever fetched: that is every installation
            // with no outbound access, and the page already says it.
            if dir.join(MANIFEST).exists() {
                tracing::warn!("Published IP lists not loaded: {e}");
            }
        }
        Ok(offered) => {
            for list in &offered {
                match verified_file(&dir, list) {
                    Err(e) => {
                        tracing::warn!(list = %list.id, "Published IP list not loaded: {e}");
                        status.insert(list.id.clone(), failed(e));
                    }
                    Ok(text) => {
                        let (blocks, unreadable) = iplist::parse_feed(&text);
                        let data = FeedData::new(&list.id, &list.name, &blocks);
                        status.insert(list.id.clone(), LoadStatus {
                            ranges: data.len(),
                            unreadable,
                            error: None,
                        });
                        loaded.insert(list.id.clone(), Arc::new(data));
                    }
                }
            }
        }
    }

    let lists = loaded.len();
    let ranges: usize = loaded.values().map(|d| d.len()).sum();
    iplist::set_feed_data(loaded);
    if let Ok(mut w) = status_map().write() {
        *w = status;
    }
    if lists > 0 {
        tracing::info!(lists, ranges, "Published IP lists loaded");
    }
    ranges
}

/// Sync if the channel may be reached, record how it went, and reload.
pub async fn check_now(db: &SqlitePool) -> Result<usize, String> {
    let result = sync(db).await;
    match &result {
        Ok(_) => {
            set(db, KEY_FETCHED, &chrono::Utc::now().to_rfc3339()).await;
            set(db, KEY_ERROR, "").await;
        }
        // Stored rather than logged, like the rule channel: an appliance with
        // no outbound access is ordinary, and a log full of it teaches its
        // operator to stop reading the log.
        Err(e) => set(db, KEY_ERROR, e).await,
    }
    // Either way: a list switched on while the channel is unreachable still
    // loads from what was mirrored before.
    reload();
    result
}

/// Check at startup and every few hours after.
pub fn spawn_task(db: SqlitePool) {
    tokio::spawn(async move {
        loop {
            if crate::rules_update::enabled(&db).await {
                let _ = check_now(&db).await;
            } else {
                reload();
            }
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

// ─── The page ────────────────────────────────────────────

/// One list as the IP Lists page shows it.
#[derive(Debug, Serialize)]
pub struct ListView {
    pub id:          String,
    pub name:        String,
    pub description: String,
    pub licence:     String,
    pub attribution: String,
    pub version:     String,
    pub entries:     i64,
    pub enabled:     bool,
    /// The saved choice, or the publisher's suggestion for a list nobody has
    /// decided about yet.
    pub response:    String,
    /// From the last load: ranges after merging, lines that were not
    /// addresses, and why it did not load, if it did not.
    pub ranges:      usize,
    pub unreadable:  usize,
    pub error:       Option<String>,
    /// False for a list that is switched on and no longer published — shown,
    /// because it is switched on and doing nothing.
    pub offered:     bool,
    /// This policy has said nothing about the list and is following what was
    /// decided for every policy. Always false in the every-policy view, where
    /// there is nothing wider to follow.
    pub from_all:    bool,
    /// What every policy does about this list — `off`, `challenge` or `block`
    /// — when anything was decided there. None means nothing was, so there is
    /// nothing to follow and nothing being overruled.
    pub all_choice:  Option<String>,
    /// How many policies answer for this list themselves. Only counted in the
    /// every-policy view, which is where a choice can be quietly overruled and
    /// the reader has no other way to find out.
    pub overrides:   i64,
}

/// Every list the verified mirror offers, as one policy has decided about it,
/// plus any that policy switched on and the mirror no longer offers — and why
/// the mirror could not be read, if it could not.
pub async fn catalogue(db: &SqlitePool, scope: Scope) -> (Vec<ListView>, Option<String>) {
    let (offered, manifest_error) =
        match verified_manifest(&cache_dir(), &crate::rules_update::trusted_key()) {
            Ok(o)  => (o, None),
            Err(e) => (Vec::new(), Some(e)),
        };
    let decided = choices(db, scope).await;
    // What was decided for every policy, which a policy follows until it says
    // something of its own — including saying off, which is a decision.
    let wider = match scope {
        Scope::Everywhere => HashMap::new(),
        Scope::Policy(_)  => choices(db, Scope::Everywhere).await,
    };
    // Who answers for themselves. Asked only in the every-policy view: that is
    // the one place a decision reaches policies that may not be taking it.
    let overridden: HashMap<String, i64> = match scope {
        Scope::Policy(_)  => HashMap::new(),
        Scope::Everywhere => sqlx::query!(
            r#"SELECT id as "id!", COUNT(*) as "n!: i64"
               FROM ip_list_feeds WHERE policy_id IS NOT NULL GROUP BY id"#
        )
        .fetch_all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.id, r.n))
        .collect(),
    };

    let status = status_map().read().map(|s| s.clone()).unwrap_or_default();

    let mut out: Vec<ListView> = offered
        .iter()
        .map(|l| {
            let from_all = !decided.contains_key(&l.id) && wider.contains_key(&l.id);
            let all_choice = wider.get(&l.id).map(|c| {
                if c.enabled { c.response.as_str().to_string() } else { "off".to_string() }
            });
            let choice = decided.get(&l.id).or_else(|| wider.get(&l.id));
            let loaded = status.get(&l.id).cloned().unwrap_or_default();
            ListView {
                id:          l.id.clone(),
                name:        l.name.clone(),
                description: l.description.clone(),
                licence:     l.licence.clone(),
                attribution: l.attribution.clone(),
                version:     l.version.clone(),
                entries:     l.entries,
                enabled:     choice.is_some_and(|c| c.enabled),
                response:    choice
                                 .map(|c| c.response.as_str().to_string())
                                 .unwrap_or_else(|| l.suggested.clone()),
                ranges:      loaded.ranges,
                unreadable:  loaded.unreadable,
                error:       loaded.error,
                offered:     true,
                from_all,
                all_choice,
                overrides:   overridden.get(&l.id).copied().unwrap_or(0),
            }
        })
        .collect();

    let mut withdrawn: Vec<_> = decided
        .iter()
        .filter(|(id, c)| c.enabled && !offered.iter().any(|l| &&l.id == id))
        .collect();
    withdrawn.sort_by(|a, b| a.0.cmp(b.0));
    for (id, c) in withdrawn {
        out.push(ListView {
            id:          id.clone(),
            name:        id.clone(),
            description: String::new(),
            licence:     String::new(),
            attribution: String::new(),
            version:     String::new(),
            entries:     0,
            enabled:     true,
            response:    c.response.as_str().to_string(),
            ranges:      0,
            unreadable:  0,
            error:       status.get(id).and_then(|s| s.error.clone()),
            offered:     false,
            from_all:    false,
            all_choice:  None,
            overrides:   overridden.get(id).copied().unwrap_or(0),
        });
    }

    (out, manifest_error)
}

/// Record what an operator decided about a list for one policy.
///
/// Nothing is reloaded here: the write moves the configuration generation, and
/// the matcher rebuilds from that on the next request.
pub async fn save(
    db: &SqlitePool,
    scope: Scope,
    id: &str,
    enabled: bool,
    response: Response,
    by: &str,
) -> Result<(), String> {
    if !is_slug(id) {
        return Err(format!("\"{id}\" is not a list"));
    }
    let (on, response) = (enabled as i64, response.as_str());

    // Two statements for one write, because the row is kept unique by two
    // partial indexes — one for the rows that name a policy and one for the
    // rows that do not — and an upsert has to name the index it means.
    match scope {
        Scope::Policy(policy_id) => sqlx::query!(
            "INSERT INTO ip_list_feeds (policy_id, id, enabled, response, changed_by, updated_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(policy_id, id) WHERE policy_id IS NOT NULL
             DO UPDATE SET enabled    = excluded.enabled,
                           response   = excluded.response,
                           changed_by = excluded.changed_by,
                           updated_at = excluded.updated_at",
            policy_id, id, on, response, by
        )
        .execute(db)
        .await,
        Scope::Everywhere => sqlx::query!(
            "INSERT INTO ip_list_feeds (policy_id, id, enabled, response, changed_by, updated_at)
             VALUES (NULL, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(id) WHERE policy_id IS NULL
             DO UPDATE SET enabled    = excluded.enabled,
                           response   = excluded.response,
                           changed_by = excluded.changed_by,
                           updated_at = excluded.updated_at",
            id, on, response, by
        )
        .execute(db)
        .await,
    }
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Forget a policy's own decision about a list, so it follows what was decided
/// for every policy again.
pub async fn follow_everywhere(db: &SqlitePool, policy_id: i64, id: &str) -> Result<(), String> {
    sqlx::query!(
        "DELETE FROM ip_list_feeds WHERE policy_id = ? AND id = ?",
        policy_id, id
    )
    .execute(db)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ─── Settings ────────────────────────────────────────────

pub async fn url(db: &SqlitePool) -> String {
    match get(db, KEY_URL).await {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _                               => DEFAULT_URL.to_string(),
    }
}

/// When the channel was last fetched, and what went wrong if anything.
pub async fn status(db: &SqlitePool) -> (Option<String>, Option<String>) {
    let fetched = get(db, KEY_FETCHED).await.filter(|v| !v.trim().is_empty());
    let error   = get(db, KEY_ERROR).await.filter(|v| !v.trim().is_empty());
    (fetched, error)
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

    const MANIFEST_TEXT: &str = r#"
generated = "2026-09-16T06:00:00Z"

[[lists]]
id          = "spamhaus-drop"
name        = "Spamhaus DROP"
description = "Hijacked and criminal netblocks."
licence     = "Free for use in a product, with attribution"
attribution = "The Spamhaus Project SLU"
version     = "2026091601"
entries     = 1432
response    = "block"
file        = "lists/spamhaus-drop.txt"
sha256      = "ABCDEF0123"
added_later = "an unknown key is ignored"

[[lists]]
id       = "tor-exits"
name     = "Tor exit nodes"
file     = "lists/tor-exits.txt"
sha256   = "00"
response = "blackhole"

[[lists]]
id     = "../escape"
file   = "lists/x.txt"
sha256 = "00"

[[lists]]
id   = "no-hash"
file = "lists/no-hash.txt"
"#;

    #[test]
    fn the_manifest_is_read_tolerantly_and_strictly_where_it_matters() {
        let lists = parse_manifest(MANIFEST_TEXT);
        let ids: Vec<&str> = lists.iter().map(|l| l.id.as_str()).collect();
        // A path-shaped id and a list with no hash are skipped, not guessed at.
        assert_eq!(ids, ["spamhaus-drop", "tor-exits"]);

        let drop = &lists[0];
        assert_eq!(drop.entries, 1432);
        assert_eq!(drop.suggested, "block");
        assert_eq!(drop.attribution, "The Spamhaus Project SLU");
        assert_eq!(drop.sha256, "abcdef0123", "hashes compare in lowercase");

        // A suggestion this version does not understand falls back to the one
        // that cannot lock anybody out.
        assert_eq!(lists[1].suggested, "challenge");
        assert_eq!(lists[1].entries, 0);
    }

    #[test]
    fn only_plain_relative_paths_are_followed() {
        assert!(safe_relative("lists/spamhaus-drop.txt"));
        assert!(safe_relative("drop.txt"));
        for bad in ["", "/etc/passwd", "../x", "lists/../../x", "lists//x", "./x",
                    "https://elsewhere/x", "lists/x?y", "lists\\x"] {
            assert!(!safe_relative(bad), "{bad:?} must be refused");
        }
    }

    fn fixture_key() -> Option<String> {
        std::fs::read_to_string("tests/fixtures/pgp_key.asc").ok()
    }

    /// A private copy of the signed fixture mirror, to tamper with.
    fn mirror_copy(name: &str) -> Option<PathBuf> {
        let src = Path::new("tests/fixtures/lists");
        if !src.join(MANIFEST).exists() {
            eprintln!("fixtures absent — run tests/fixtures/make.sh");
            return None;
        }
        let dst = std::env::temp_dir()
            .join(format!("easywaf-lists-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst);
        std::fs::create_dir_all(dst.join(FILES)).unwrap();
        for f in [MANIFEST, SIGNATURE] {
            std::fs::copy(src.join(f), dst.join(f)).unwrap();
        }
        for e in std::fs::read_dir(src.join(FILES)).unwrap().flatten() {
            std::fs::copy(e.path(), dst.join(FILES).join(e.file_name())).unwrap();
        }
        Some(dst)
    }

    #[test]
    fn a_signed_mirror_loads() {
        let (Some(key), Some(dir)) = (fixture_key(), mirror_copy("good")) else { return };
        let offered = verified_manifest(&dir, &key).expect("the fixture mirror verifies");
        assert_eq!(offered.len(), 1);
        let text = verified_file(&dir, &offered[0]).expect("its file matches");
        let (blocks, unreadable) = iplist::parse_feed(&text);
        assert_eq!((blocks.len(), unreadable), (3, 0));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_edited_list_file_is_refused() {
        let (Some(key), Some(dir)) = (fixture_key(), mirror_copy("file")) else { return };
        // Editing the mirror is not a way to change what is blocked — or, more
        // to the point, what is not.
        let offered = verified_manifest(&dir, &key).unwrap();
        let path = local_file(&dir, &offered[0].id);
        let mut body = std::fs::read(&path).unwrap();
        body.extend_from_slice(b"198.51.100.0/24\n");
        std::fs::write(&path, body).unwrap();
        let err = verified_file(&dir, &offered[0]).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_edited_manifest_is_refused() {
        let (Some(key), Some(dir)) = (fixture_key(), mirror_copy("manifest")) else { return };
        let path = dir.join(MANIFEST);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("block", "challenge")).unwrap();
        assert!(verified_manifest(&dir, &key).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_mirror_with_no_signature_is_refused() {
        let (Some(key), Some(dir)) = (fixture_key(), mirror_copy("unsigned")) else { return };
        std::fs::remove_file(dir.join(SIGNATURE)).unwrap();
        assert!(verified_manifest(&dir, &key).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}

// =========================================================
// export.rs — EasyWAF
// The configuration as a readable document.
//
// The other half of 0.14.0 from a snapshot, and a different
// file for a different job. A snapshot is the database,
// exactly, for when the host is gone. This is a description
// of what the appliance is configured to do — for cloning an
// installation, reviewing a change, keeping it in git, or
// sending it to somebody who is helping — and it leaves out
// everything that is not configuration.
//
// Objects are named, never numbered. A row id means nothing
// on another host, so a site names its policy and its
// certificate, a policy names the rule sets it holds and the
// catalogue numbers of the rules it switched off, and nothing
// in the file is a primary key.
//
// A rule from an installed set travels as a reference — the
// set and its version — because it cannot have been edited:
// changing one makes a copy (0.6.0). Only what is genuinely
// this installation's own travels in full: rules written
// here, and catalogue rules taken one at a time.
//
// Private keys and accounts are out unless asked for, each
// by its own switch, and a file that carries either says so
// in its header. The session key, the ACME account key and
// traffic history never travel at all.
//
// The types here are also what an import reads, and they
// refuse a key they do not know rather than skip it: a
// setting silently dropped on import leaves an appliance
// that looks right and enforces less.
// =========================================================

use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::collections::BTreeMap;

/// The format this version writes and reads. Raised when a change could not
/// be read correctly by the version before it; a new optional field is not
/// such a change, since a missing field reads as its default.
pub const FORMAT: u32 = 1;

// ─── What the file says ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub easywaf: Header,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, String>,
    #[serde(default)]
    pub everywhere: Everywhere,
    #[serde(default, rename = "policy", skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<Policy>,
    #[serde(default, rename = "certificate", skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Certificate>,
    #[serde(default, rename = "site", skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<Site>,
    #[serde(default, rename = "account", skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<Account>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub format:   u32,
    /// The EasyWAF that wrote it.
    pub version:  String,
    /// When, in UTC.
    pub exported: String,
    /// What beyond configuration is in the file: "private-keys", "accounts".
    /// Said here as well as in the comment above it, because a comment is
    /// lost the first time somebody reformats the file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contains: Vec<String>,
}

/// What applies to every policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Everywhere {
    #[serde(default = "off")]
    pub countries_mode: String,
    #[serde(default)]
    pub countries: Vec<String>,
    #[serde(default, rename = "address", skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<Address>,
    #[serde(default, rename = "list", skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<ListChoice>,
}

impl Default for Everywhere {
    fn default() -> Self {
        Everywhere { countries_mode: off(), countries: Vec::new(), addresses: Vec::new(), lists: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    /// "On", "DetectionOnly" or "Off".
    pub mode: String,
    pub score_threshold: i64,
    #[serde(default)]
    pub challenge_threshold: i64,
    #[serde(default = "off")]
    pub countries_mode: String,
    #[serde(default)]
    pub countries: Vec<String>,
    /// Catalogue numbers of rules from installed sets that are switched off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_off: Vec<i64>,
    #[serde(default, rename = "rule_set", skip_serializing_if = "Vec::is_empty")]
    pub rule_sets: Vec<RuleSetRef>,
    /// Rules held in full: written here, or taken from the catalogue one at a
    /// time rather than as part of a set.
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// Exclusions of rules from installed sets, by catalogue number. An
    /// exclusion of a rule held in full sits under that rule instead, so
    /// nothing has to be matched by name.
    #[serde(default, rename = "exclusion", skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<Exclusion>,
    #[serde(default, rename = "address", skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<Address>,
    #[serde(default, rename = "list", skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<ListChoice>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleSetRef {
    pub id: String,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub zone: String,
    pub pattern: String,
    pub score: i64,
    pub action: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// For a catalogue rule taken on its own: its number, and the set it came
    /// from. Absent for a rule written here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_set: Option<String>,
    /// For a copy of a catalogue rule, what it was copied from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloned_from_external_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloned_from_version: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloned_from_set: Option<String>,
    #[serde(default, rename = "exclusion", skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<Exclusion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    /// The catalogue number of the rule — only at policy level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<i64>,
    /// Empty means every path.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path_prefix: String,
    /// Empty means every client.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
#[serde(deny_unknown_fields)]
pub struct Address {
    pub address: String,
    /// "allow" or "block".
    pub list: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
#[serde(deny_unknown_fields)]
pub struct ListChoice {
    pub id: String,
    pub enabled: bool,
    pub response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// Set when the certificate is issued and renewed through ACME.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_domain: Option<String>,
    /// The public certificate chain, PEM.
    pub certificate: String,
    /// The private key, PEM — only in a file exported with private keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub name: String,
    pub host: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    pub listen_port: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_port: Option<i64>,
    #[serde(default)]
    pub tls_redirect: bool,
    #[serde(default)]
    pub acme: bool,
    #[serde(default)]
    pub affinity: bool,
    #[serde(default)]
    pub hsts: bool,
    #[serde(default)]
    pub x_frame: bool,
    #[serde(default = "sameorigin")]
    pub x_frame_value: String,
    #[serde(default)]
    pub x_content_type: bool,
    #[serde(default)]
    pub xss_protection: bool,
    #[serde(default, rename = "upstream", skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<Upstream>,
    /// Ports beyond listen_port and tls_port.
    #[serde(default, rename = "port", skip_serializing_if = "Vec::is_empty")]
    pub extra_ports: Vec<Port>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub url: String,
    #[serde(default = "one")]
    pub weight: i64,
    #[serde(default = "yes")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
#[serde(deny_unknown_fields)]
pub struct Port {
    pub port: i64,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub username: String,
    pub role: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// bcrypt. The password itself is never stored anywhere.
    pub password_hash: String,
}

fn off() -> String { "off".to_string() }
fn yes() -> bool { true }
fn one() -> i64 { 1 }
fn sameorigin() -> String { "SAMEORIGIN".to_string() }

// ─── Settings: what travels ──────────────────────────────
//
// Every settings key is in exactly one of these two lists, and a test fails
// for a key in neither. That is the whole mechanism: a setting added later
// cannot reach an export by accident — which is how a credential would leak —
// nor be left out of one by accident, which is how an import would quietly
// reset it. Somebody has to decide, and the test makes them.

/// How this installation behaves. Travels.
pub const EXPORTED_SETTINGS: &[&str] = &[
    "auto_apply_geo",
    "auto_apply_lists",
    "auto_apply_rules",
    "backup_keep",
    "backup_scheduled",
    "geo_url",
    "ip_list_url",
    "maintenance_message",
    "request_body_inspect_kb",
    "rule_update_check",
    "rule_update_url",
    "syslog_enabled",
    "syslog_host",
    "syslog_port",
    "tls_ciphers",
    "tls_profile",
    "traffic_retention_days",
    "trusted_proxies",
];

/// Never travels: a credential, this host's own identity or role, or state
/// the appliance keeps about itself rather than configuration anybody chose.
pub const LOCAL_SETTINGS: &[&str] = &[
    // A credential.
    "cookie_secret",
    // This host's own: which certificate its management page uses, and
    // whether this node is the one that renews certificates.
    "management_cert",
    "acme_renew_here",
    // State.
    "backup_error",
    "backup_last",
    "geo_error",
    "geo_fetched",
    "geo_version",
    "ip_list_error",
    "ip_list_fetched",
    "restore_at",
    "restore_message",
    "restore_outcome",
    "rule_manifest_cache",
    "rule_manifest_error",
    "rule_manifest_fetched",
    "rule_mirror_error",
    "schema_written_by",
];

// ─── Building one ────────────────────────────────────────

/// What to put in beyond configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub private_keys: bool,
    pub accounts:     bool,
}

pub(crate) fn split_countries(raw: &str) -> Vec<String> {
    let mut v: Vec<String> = raw.split(',')
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| !c.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

async fn addresses(db: &SqlitePool, policy: Option<i64>) -> Result<Vec<Address>, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT ip, list_type, COALESCE(reason, '') AS reason FROM ip_rules
          WHERE policy_id IS ? ORDER BY ip")
        .bind(policy).fetch_all(db).await?
        .into_iter().map(|r| Address {
            address: r.get("ip"), list: r.get("list_type"), reason: r.get("reason"),
        }).collect())
}

async fn lists(db: &SqlitePool, policy: Option<i64>) -> Result<Vec<ListChoice>, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT id, enabled, response FROM ip_list_feeds WHERE policy_id IS ? ORDER BY id")
        .bind(policy).fetch_all(db).await?
        .into_iter().map(|r| ListChoice {
            id: r.get("id"), enabled: r.get::<i64, _>("enabled") != 0, response: r.get("response"),
        }).collect())
}

/// Read the configuration into a document. Everything is sorted by its name,
/// so two exports of the same configuration are the same file apart from the
/// time in the header, and a diff between two shows what changed.
pub async fn build(db: &SqlitePool, opts: Options) -> Result<Document, sqlx::Error> {
    let mut contains = Vec::new();
    if opts.private_keys { contains.push("private-keys".to_string()); }
    if opts.accounts     { contains.push("accounts".to_string()); }

    // ── Settings ──
    let mut settings = BTreeMap::new();
    for row in sqlx::query("SELECT key, value FROM settings ORDER BY key").fetch_all(db).await? {
        let key: String = row.get("key");
        if EXPORTED_SETTINGS.contains(&key.as_str()) {
            settings.insert(key, row.get::<String, _>("value"));
        }
    }

    // ── Names for ids, since the file never carries an id ──
    let policy_names: BTreeMap<i64, String> = sqlx::query("SELECT id, name FROM policies")
        .fetch_all(db).await?
        .into_iter().map(|r| (r.get("id"), r.get("name"))).collect();
    let cert_names: BTreeMap<i64, String> = sqlx::query("SELECT id, name FROM certs")
        .fetch_all(db).await?
        .into_iter().map(|r| (r.get("id"), r.get("name"))).collect();

    // ── Every policy ──
    let (mode, countries) = sqlx::query(
        "SELECT mode, COALESCE(countries, '') AS countries FROM geoip_everywhere LIMIT 1")
        .fetch_optional(db).await?
        .map(|r| (r.get::<String, _>("mode"), r.get::<String, _>("countries")))
        .unwrap_or_else(|| ("off".into(), String::new()));
    let everywhere = Everywhere {
        countries_mode: mode,
        countries: split_countries(&countries),
        addresses: addresses(db, None).await?,
        lists: lists(db, None).await?,
    };

    // ── Policies ──
    let mut policies = Vec::new();
    for p in sqlx::query(
        "SELECT id, name, rule_engine, score_threshold, challenge_threshold,
                COALESCE(geoip_mode, 'off') AS geoip_mode, COALESCE(geoip_countries, '') AS geoip_countries
           FROM policies ORDER BY name")
        .fetch_all(db).await?
    {
        let id: i64 = p.get("id");

        let rule_sets: Vec<RuleSetRef> = sqlx::query(
            "SELECT set_id, version FROM policy_rule_sets WHERE policy_id = ? ORDER BY set_id")
            .bind(id).fetch_all(db).await?
            .into_iter().map(|r| RuleSetRef { id: r.get("set_id"), version: r.get("version") })
            .collect();
        let held: std::collections::HashSet<String> =
            rule_sets.iter().map(|s| s.id.clone()).collect();

        // A rule is the set's when it carries a catalogue number and names a
        // set this policy holds. Those travel as the set reference plus the
        // numbers switched off; every other rule travels in full.
        let mut rules_off = Vec::new();
        let mut rules = Vec::new();
        let mut row_ids: BTreeMap<i64, usize> = BTreeMap::new();
        for r in sqlx::query(
            "SELECT id, name, COALESCE(description, '') AS description, zone, pattern, score, action,
                    enabled, external_id, rule_set,
                    cloned_from_external_id, cloned_from_version, cloned_from_set
               FROM waf_rules WHERE policy_id = ?
              ORDER BY external_id IS NULL, external_id, name, id")
            .bind(id).fetch_all(db).await?
        {
            let external: Option<i64> = r.get("external_id");
            let set: Option<String> = r.get("rule_set");
            let enabled = r.get::<i64, _>("enabled") != 0;
            let of_held_set = external.is_some()
                && set.as_ref().map(|s| held.contains(s)).unwrap_or(false);
            if of_held_set {
                if !enabled {
                    rules_off.push(external.unwrap_or_default());
                }
                continue;
            }
            row_ids.insert(r.get("id"), rules.len());
            rules.push(Rule {
                name: r.get("name"),
                description: r.get("description"),
                zone: r.get("zone"),
                pattern: r.get("pattern"),
                score: r.get("score"),
                action: r.get("action"),
                enabled,
                external_id: external,
                rule_set: set,
                cloned_from_external_id: r.get("cloned_from_external_id"),
                cloned_from_version: r.get("cloned_from_version"),
                cloned_from_set: r.get("cloned_from_set"),
                exclusions: Vec::new(),
            });
        }
        rules_off.sort();

        // Exclusions: by catalogue number at policy level, or under the rule
        // held in full that they apply to.
        let mut exclusions = Vec::new();
        for e in sqlx::query(
            "SELECT external_id, rule_id, path_prefix, COALESCE(client_cidr, '') AS client,
                    COALESCE(note, '') AS note
               FROM policy_rule_exclusions WHERE policy_id = ?")
            .bind(id).fetch_all(db).await?
        {
            let base = Exclusion {
                rule: None,
                path_prefix: e.get("path_prefix"),
                client: e.get("client"),
                note: e.get("note"),
            };
            let external: Option<i64> = e.get("external_id");
            let row: Option<i64> = e.get("rule_id");
            if let Some(n) = external {
                // A catalogue rule held in full carries its own; otherwise it
                // is a set's rule, named by number.
                if let Some(i) = rules.iter().position(|r| r.external_id == Some(n)) {
                    rules[i].exclusions.push(base);
                } else {
                    exclusions.push(Exclusion { rule: Some(n), ..base });
                }
            } else if let Some(i) = row.and_then(|r| row_ids.get(&r).copied()) {
                rules[i].exclusions.push(base);
            }
        }
        exclusions.sort();
        for r in &mut rules {
            r.exclusions.sort();
        }

        policies.push(Policy {
            name: p.get("name"),
            mode: p.get("rule_engine"),
            score_threshold: p.get("score_threshold"),
            challenge_threshold: p.get("challenge_threshold"),
            countries_mode: p.get("geoip_mode"),
            countries: split_countries(&p.get::<String, _>("geoip_countries")),
            rules_off,
            rule_sets,
            rules,
            exclusions,
            addresses: addresses(db, Some(id)).await?,
            lists: lists(db, Some(id)).await?,
        });
    }

    // ── Certificates ──
    //
    // The management page's own certificate is this host's identity, like the
    // setting that names it, and stays behind — unless a site serves with it,
    // in which case it is that site's configuration and has to travel.
    let management = crate::routes::settings::get_management_cert(db).await;
    let used_by_sites: std::collections::HashSet<String> = sqlx::query_scalar(
        "SELECT c.name FROM sites s JOIN certs c ON c.id = s.cert_id")
        .fetch_all(db).await?.into_iter().collect();
    let mut certificates = Vec::new();
    for c in sqlx::query(
        "SELECT name, COALESCE(domain, '') AS domain, acme_domain, cert_pem, key_pem
           FROM certs ORDER BY name")
        .fetch_all(db).await?
    {
        let name: String = c.get("name");
        if name == management && !used_by_sites.contains(&name) {
            continue;
        }
        certificates.push(Certificate {
            name,
            domain: c.get("domain"),
            acme_domain: c.get::<Option<String>, _>("acme_domain").filter(|d| !d.is_empty()),
            certificate: c.get("cert_pem"),
            private_key: if opts.private_keys { Some(c.get("key_pem")) } else { None },
        });
    }

    // ── Sites ──
    let mut sites = Vec::new();
    for s in sqlx::query(
        "SELECT id, name, server_name, enabled, cert_id, acme_enabled, waf_policy_id, hsts,
                x_frame, x_frame_value, x_content_type, xss_protection, listen_port, tls_port,
                tls_redirect, affinity
           FROM sites ORDER BY name")
        .fetch_all(db).await?
    {
        let id: i64 = s.get("id");
        let aliases: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM site_aliases WHERE site_id = ? ORDER BY name")
            .bind(id).fetch_all(db).await?;
        let upstreams = sqlx::query(
            "SELECT url, weight, enabled FROM upstreams WHERE site_id = ? ORDER BY id")
            .bind(id).fetch_all(db).await?
            .into_iter().map(|u| Upstream {
                url: u.get("url"), weight: u.get("weight"),
                enabled: u.get::<i64, _>("enabled") != 0,
            }).collect();
        let mut extra_ports: Vec<Port> = sqlx::query(
            "SELECT port, tls FROM site_ports WHERE site_id = ?")
            .bind(id).fetch_all(db).await?
            .into_iter().map(|p| Port { port: p.get("port"), tls: p.get::<i64, _>("tls") != 0 })
            .collect();
        extra_ports.sort();
        let flag = |c: &str| s.get::<i64, _>(c) != 0;

        sites.push(Site {
            name: s.get("name"),
            host: s.get("server_name"),
            enabled: flag("enabled"),
            aliases,
            policy: s.get::<Option<i64>, _>("waf_policy_id").and_then(|p| policy_names.get(&p).cloned()),
            certificate: s.get::<Option<i64>, _>("cert_id").and_then(|c| cert_names.get(&c).cloned()),
            listen_port: s.get("listen_port"),
            tls_port: s.get("tls_port"),
            tls_redirect: flag("tls_redirect"),
            acme: flag("acme_enabled"),
            affinity: flag("affinity"),
            hsts: flag("hsts"),
            x_frame: flag("x_frame"),
            x_frame_value: s.get("x_frame_value"),
            x_content_type: flag("x_content_type"),
            xss_protection: flag("xss_protection"),
            upstreams,
            extra_ports,
        });
    }

    // ── Accounts, only when asked for ──
    let accounts = if opts.accounts {
        sqlx::query("SELECT username, role, enabled, COALESCE(password_hash, '') AS password_hash
                       FROM users ORDER BY username")
            .fetch_all(db).await?
            .into_iter().map(|u| Account {
                username: u.get("username"), role: u.get("role"),
                enabled: u.get::<i64, _>("enabled") != 0, password_hash: u.get("password_hash"),
            }).collect()
    } else {
        Vec::new()
    };

    Ok(Document {
        easywaf: Header {
            format: FORMAT,
            version: env!("CARGO_PKG_VERSION").to_string(),
            exported: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            contains,
        },
        settings,
        everywhere,
        policies,
        certificates,
        sites,
        accounts,
    })
}

/// The document as the file somebody reads, with a header saying what it is
/// and — loudly, when it applies — what it must not be treated as.
pub fn to_toml(doc: &Document) -> Result<String, String> {
    let body = toml::to_string_pretty(doc)
        .map_err(|e| format!("the export could not be written: {e}"))?;

    let mut head = String::from(
        "# EasyWAF configuration export.\n\
         #\n\
         # A description of what this appliance is configured to do: policies, rules,\n\
         # sites, certificates and settings. Objects are named rather than numbered, so\n\
         # it can be imported into another installation, compared with another export,\n\
         # or kept in version control. It is not a backup: it leaves out traffic history\n\
         # and everything else that is not configuration. For recovery, keep snapshots.\n");
    if doc.easywaf.contains.iter().any(|c| c == "private-keys") {
        head.push_str(
            "#\n\
             # !!! THIS FILE CONTAINS PRIVATE KEYS. !!!\n\
             # Anybody holding it can impersonate every site it names. Do not commit it,\n\
             # attach it to a ticket or send it unencrypted.\n");
    }
    if doc.easywaf.contains.iter().any(|c| c == "accounts") {
        head.push_str(
            "#\n\
             # This file contains accounts and their password hashes. A hash is not the\n\
             # password, but it is what an attacker works on offline. Treat it as secret.\n");
    }
    head.push('\n');
    Ok(head + &body)
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Every settings key the code defines is decided one way or the other.
    /// The failure names the key and says what to do, because the person who
    /// sees it is the one adding a setting, not the one who wrote this.
    #[test]
    fn every_setting_is_either_exported_or_deliberately_not() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut keys = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() { stack.push(path); continue; }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") { continue; }
                let text = std::fs::read_to_string(&path).unwrap();
                for line in text.lines() {
                    let l = line.trim();
                    let Some(rest) = l.strip_prefix("pub const KEY_").or_else(|| l.strip_prefix("const KEY_"))
                        else { continue };
                    let Some(value) = rest.split('"').nth(1) else { continue };
                    // A path, not a settings key (the rule key's override file).
                    if value.contains('/') || value.contains('.') { continue; }
                    keys.push((value.to_string(), path.file_name().unwrap().to_string_lossy().to_string()));
                }
            }
        }
        assert!(keys.len() > 20, "found only {} keys — the scan is broken, not the lists", keys.len());
        for (key, file) in keys {
            let exported = EXPORTED_SETTINGS.contains(&key.as_str());
            let local = LOCAL_SETTINGS.contains(&key.as_str());
            assert!(exported || local,
                "settings key \"{key}\" (defined in {file}) is in neither EXPORTED_SETTINGS nor \
                 LOCAL_SETTINGS in export.rs. Decide: does it describe how the appliance behaves \
                 (export it), or is it a credential, this host's own, or state (keep it local)?");
            assert!(!(exported && local), "settings key \"{key}\" is in both lists");
        }
    }

    #[test]
    fn a_credential_is_never_exported() {
        assert!(!EXPORTED_SETTINGS.contains(&"cookie_secret"), "the session key would be exported");
    }

    /// An estate with one of each awkward thing, built through SQL so the
    /// test does not depend on a channel or a mirror.
    pub(crate) async fn estate(tag: &str) -> SqlitePool {
        let path = std::env::temp_dir().join(format!("easywaf-export-{tag}-{}.db", std::process::id()));
        for sfx in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", path.display()));
        }
        let db = crate::db::init(&format!("sqlite://{}", path.display())).await;
        sqlx::raw_sql(r#"
            INSERT INTO policies (name, rule_engine, score_threshold, challenge_threshold, geoip_mode, geoip_countries)
                 VALUES ('websites', 'On', 10, 5, 'block', 'RU,CN');
            INSERT INTO policy_rule_sets (policy_id, set_id, name, version) VALUES (1, 'owasp-sqli', 'SQLi', 2);
            -- Two rules of the held set, one switched off.
            INSERT INTO waf_rules (policy_id, name, zone, pattern, score, action, enabled, external_id, rule_set)
                 VALUES (1, 'SQLi one', 'ARGS', 'union', 5, 'score', 1, 942001, 'owasp-sqli'),
                        (1, 'SQLi two', 'ARGS', 'select', 5, 'score', 0, 942002, 'owasp-sqli');
            -- A rule written here, and a catalogue rule taken on its own.
            INSERT INTO waf_rules (policy_id, name, description, zone, pattern, score, action, enabled)
                 VALUES (1, 'Block the old admin', 'written here', 'URI', '^/old-admin', 10, 'block', 1);
            INSERT INTO waf_rules (policy_id, name, zone, pattern, score, action, enabled, external_id, rule_set)
                 VALUES (1, 'XSS script tag', 'ARGS', '<script', 5, 'score', 1, 941001, 'owasp-xss');
            -- An exclusion of the set's rule, by number, and one of the rule written here.
            INSERT INTO policy_rule_exclusions (policy_id, external_id, path_prefix, client_cidr, note)
                 VALUES (1, 942001, '/api/search', NULL, 'search takes SQL-ish text');
            INSERT INTO policy_rule_exclusions (policy_id, rule_id, path_prefix, client_cidr, note)
                 VALUES (1, 3, '', '10.0.0.0/8', 'the office');
            INSERT INTO ip_rules (policy_id, ip, list_type, reason) VALUES (1, '203.0.113.7', 'block', 'scanner');
            INSERT INTO ip_rules (policy_id, ip, list_type, reason) VALUES (NULL, '198.51.100.0/24', 'allow', 'monitoring');
            INSERT INTO ip_list_feeds (policy_id, id, enabled, response) VALUES (NULL, 'spamhaus-drop', 1, 'block');
            INSERT INTO certs (name, domain, not_before, not_after, cert_pem, key_pem)
                 VALUES ('example', 'example.com', '2026-01-01', '2027-01-01',
                         '-----BEGIN CERTIFICATE-----' || char(10) || 'AAAA' || char(10) || '-----END CERTIFICATE-----',
                         '-----BEGIN PRIVATE KEY-----' || char(10) || 'SECRET' || char(10) || '-----END PRIVATE KEY-----');
            INSERT INTO sites (name, server_name, enabled, cert_id, waf_policy_id, listen_port, tls_port, tls_redirect, hsts)
                 VALUES ('shop', 'shop.example.com', 1, 1, 1, 80, 443, 1, 1);
            INSERT INTO site_aliases (site_id, name) VALUES (1, 'www.shop.example.com');
            INSERT INTO upstreams (site_id, url, weight, enabled) VALUES (1, 'http://10.0.0.8:3000', 3, 1),
                                                                       (1, 'http://10.0.0.9:3000', 1, 0);
            INSERT OR REPLACE INTO settings (key, value) VALUES ('traffic_retention_days', '30');
            INSERT OR REPLACE INTO settings (key, value) VALUES ('syslog_host', 'logs.example.com');
        "#).execute(&db).await.expect("estate");
        db
    }

    #[tokio::test]
    async fn an_export_reads_back_as_exactly_what_was_written() {
        let db = estate("roundtrip").await;
        let doc = build(&db, Options::default()).await.unwrap();
        let text = to_toml(&doc).unwrap();
        let back: Document = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("an export did not read back: {e}\n\n{text}"));
        assert_eq!(back, doc, "reading an export back changed it");

        let p = &doc.policies[0];
        assert_eq!(p.rule_sets, [RuleSetRef { id: "owasp-sqli".into(), version: 2 }]);
        assert_eq!(p.rules_off, [942002], "the set rule switched off was not recorded");
        assert_eq!(p.countries, ["CN", "RU"]);
        // The set's rules travel as the set; the other two in full.
        let names: Vec<&str> = p.rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["XSS script tag", "Block the old admin"],
                   "a rule of an installed set travelled in full, or a rule of this installation's own did not");
        assert_eq!(p.exclusions.len(), 1);
        assert_eq!(p.exclusions[0].rule, Some(942001));
        let own = p.rules.iter().find(|r| r.name == "Block the old admin").unwrap();
        assert_eq!(own.exclusions[0].client, "10.0.0.0/8",
                   "an exclusion of a rule written here was not carried with that rule");

        let site = &doc.sites[0];
        assert_eq!((site.policy.as_deref(), site.certificate.as_deref()), (Some("websites"), Some("example")),
                   "a site referred to its policy or certificate by something other than its name");
        assert_eq!(site.upstreams.len(), 2);
        assert!(!site.upstreams[1].enabled);
        assert_eq!(doc.everywhere.addresses[0].address, "198.51.100.0/24");
        assert_eq!(doc.settings.get("syslog_host").map(String::as_str), Some("logs.example.com"));

        // The management page's own certificate stays behind unless a site uses it.
        sqlx::raw_sql("INSERT INTO certs (name, domain, not_before, not_after, cert_pem, key_pem)
                        VALUES ('easywaf', 'easywaf', '2026-01-01', '2036-01-01', 'PEM', 'KEY')")
            .execute(&db).await.unwrap();
        let names = |d: &Document| d.certificates.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&build(&db, Options::default()).await.unwrap()), ["example"],
                   "this host's own management certificate was exported");
        sqlx::raw_sql("UPDATE sites SET cert_id = (SELECT id FROM certs WHERE name = 'easywaf')")
            .execute(&db).await.unwrap();
        assert!(names(&build(&db, Options::default()).await.unwrap()).contains(&"easywaf".to_string()),
                "a certificate a site serves with was left out because it is also the management one");
        db.close().await;
    }

    #[tokio::test]
    async fn keys_and_accounts_are_in_only_when_asked_for_and_then_announced() {
        let db = estate("secrets").await;
        sqlx::query("INSERT INTO settings (key, value) VALUES ('cookie_secret', 'do-not-leak') \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .execute(&db).await.unwrap();

        let plain = to_toml(&build(&db, Options::default()).await.unwrap()).unwrap();
        assert!(!plain.contains("SECRET"), "a private key was exported without being asked for");
        assert!(!plain.contains("password_hash"), "accounts were exported without being asked for");
        assert!(!plain.contains("do-not-leak"), "the session key was exported");
        assert!(!plain.contains("PRIVATE KEYS"), "a file with no keys says it has them");

        let loud = to_toml(&build(&db, Options { private_keys: true, accounts: true }).await.unwrap()).unwrap();
        assert!(loud.contains("SECRET"));
        assert!(loud.contains("THIS FILE CONTAINS PRIVATE KEYS"), "a file with keys does not say so");
        let header = toml::from_str::<Document>(&loud).unwrap().easywaf;
        assert_eq!(header.contains, ["private-keys", "accounts"],
                   "the header does not record what the file carries");
        assert!(!loud.contains("do-not-leak"), "the session key was exported with the secrets");
        db.close().await;
    }

    #[test]
    fn a_key_nobody_knows_is_refused_not_skipped() {
        let text = "[easywaf]\nformat = 1\nversion = \"0.14.0\"\nexported = \"x\"\n\n\
                    [[policy]]\nname = \"p\"\nmode = \"On\"\nscore_threshold = 10\nsccore = 99\n";
        let e = toml::from_str::<Document>(text).unwrap_err().to_string();
        assert!(e.contains("sccore"), "a misspelt key was accepted and ignored: {e}");
    }

    #[test]
    fn countries_read_as_a_sorted_list() {
        assert_eq!(split_countries("ru, CN,,cn "), ["CN", "RU"]);
        assert!(split_countries("").is_empty());
    }
}

// =========================================================
// import.rs — EasyWAF
// Make this installation match an exported configuration.
//
// Replace, not merge — Yariv's decision of 2026-09-27. A
// file is imported by making this installation match it:
// what the file has is created or changed, and what only
// this installation has is removed. Merge was not offered,
// because a restore that quietly does the other one loses
// data, and the two are different features.
//
// Three stages, and nothing is written in the first two:
//
//   parse  — strict. A key nobody knows is an error that
//            names it, and one from a newer EasyWAF says to
//            upgrade, rather than being dropped: a setting
//            dropped on import is an appliance that looks
//            right and enforces less.
//   plan   — every creation, change and removal, listed, and
//            every reason the import cannot go ahead. This is
//            the preview an administrator reads before
//            pressing anything.
//   apply  — onto a copy of the database, never the live
//            one. The copy is then swapped in by the same
//            restart a snapshot restore uses, which brings
//            three things for free: a failure half-way leaves
//            nothing changed, a result that will not start is
//            put back by the next start, and the restart
//            re-binds every listener and reloads every cache
//            — the step the design note warns is easiest to
//            miss when done piece by piece.
//
// Two things are never replaced, whatever the file says.
// Accounts are merged — created and updated, never deleted —
// and the account doing the import is never disabled or
// demoted by it: an import must not be able to lock out the
// person running it. And this host's own management
// certificate is never removed.
// =========================================================

use crate::export::{self, Document};
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const ZONES: &[&str] = &["ANY", "ARGS", "BODY", "HEADERS", "URL"];
const ACTIONS: &[&str] = &["score", "block"];
const MODES: &[&str] = &["On", "DetectionOnly", "Off"];
const COUNTRY_MODES: &[&str] = &["off", "block", "allow"];

// ─── Parse ───────────────────────────────────────────────

/// Read a file as an export, strictly.
pub fn parse(text: &str) -> Result<Document, String> {
    let here = env!("CARGO_PKG_VERSION");

    // The header first, loosely, so a file from a newer EasyWAF is told so by
    // name before the strict read complains about a field it has added.
    let loose: toml::Value = toml::from_str(text)
        .map_err(|e| format!("it is not valid TOML: {e}"))?;
    let head = loose.get("easywaf")
        .ok_or("it has no [easywaf] header — it is not an EasyWAF configuration export")?;
    let format = head.get("format").and_then(|v| v.as_integer())
        .ok_or("its header does not say which format it is in")?;
    let version = head.get("version").and_then(|v| v.as_str()).unwrap_or("?").to_string();
    let newer = matches!((crate::backup::version(&version), crate::backup::version(here)),
                         (Some(theirs), Some(ours)) if theirs > ours);

    if format > export::FORMAT as i64 {
        return Err(format!(
            "it is in format {format}, written by EasyWAF {version}; this EasyWAF {here} reads \
             format {}. Upgrade this installation first", export::FORMAT));
    }
    toml::from_str::<Document>(text).map_err(|e| {
        let e = e.to_string().lines().next().unwrap_or("").trim().to_string();
        if newer {
            format!("it was written by EasyWAF {version}, which is newer than this {here}, and \
                     uses something this version does not know ({e}). Upgrade this installation \
                     first")
        } else {
            format!("it does not read as an EasyWAF export: {e}")
        }
    })
}

// ─── Plan ────────────────────────────────────────────────

/// Everything an import would do, and everything that stops it.
#[derive(Debug, Serialize, Default)]
pub struct Plan {
    pub version:  String,
    pub exported: String,
    pub contains: Vec<String>,
    /// Any of these, and the import is refused.
    pub blockers: Vec<String>,
    /// Worth knowing, and not a reason to stop.
    pub warnings: Vec<String>,
    pub groups:   Vec<Group>,
    pub changes:  usize,
}

#[derive(Debug, Serialize)]
pub struct Group {
    pub title: &'static str,
    pub items: Vec<Item>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Item {
    /// "create", "change", "remove" or "keep".
    pub action:  &'static str,
    pub name:    String,
    pub details: Vec<String>,
}

fn item(action: &'static str, name: &str, details: Vec<String>) -> Item {
    Item { action, name: name.to_string(), details }
}

/// "a, b and c", for saying which things.
fn listing<I: IntoIterator<Item = String>>(it: I) -> String {
    let v: Vec<String> = it.into_iter().collect();
    match v.len() {
        0 => String::new(),
        1 => v[0].clone(),
        n => format!("{} and {}", v[..n - 1].join(", "), v[n - 1]),
    }
}

fn countries(v: &[String]) -> String {
    if v.is_empty() { "none".into() } else { v.join(",") }
}

fn valid_network(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
        || s.split_once('/').is_some_and(|(ip, len)|
            ip.parse::<std::net::IpAddr>().is_ok()
            && len.parse::<u8>().is_ok_and(|l| l <= if ip.contains(':') { 128 } else { 32 }))
}

/// Compare the file with this installation and check it can be applied.
pub async fn plan(db: &SqlitePool, doc: &Document, gui_ports: &[u16], importer: &str) -> Plan {
    let mut p = Plan {
        version:  doc.easywaf.version.clone(),
        exported: doc.easywaf.exported.clone(),
        contains: doc.easywaf.contains.clone(),
        ..Default::default()
    };
    let current = match export::build(db, export::Options { private_keys: false, accounts: true }).await {
        Ok(c)  => c,
        Err(e) => { p.blockers.push(format!("this installation's configuration could not be read: {e}")); return p; }
    };

    check(db, doc, gui_ports, &mut p).await;

    p.groups = vec![
        Group { title: "Settings",          items: diff_settings(&current, doc) },
        Group { title: "Every policy",      items: diff_everywhere(&current, doc) },
        Group { title: "Policies",          items: diff_policies(&current, doc) },
        Group { title: "Certificates",      items: diff_certificates(db, &current, doc).await },
        Group { title: "Sites",             items: diff_sites(&current, doc) },
        Group { title: "Accounts",          items: diff_accounts(&current, doc, importer) },
    ];
    p.groups.retain(|g| !g.items.is_empty());
    p.changes = p.groups.iter()
        .flat_map(|g| &g.items)
        .filter(|i| i.action != "keep")
        .count();
    p
}

/// Every reason the file cannot be applied, and every caution.
async fn check(db: &SqlitePool, doc: &Document, gui_ports: &[u16], p: &mut Plan) {
    let b = &mut p.blockers;
    let w = &mut p.warnings;

    // ── Settings ──
    for (key, value) in &doc.settings {
        if export::LOCAL_SETTINGS.contains(&key.as_str()) {
            b.push(format!("Setting {key} is this installation's own — a credential, its identity \
                            or its state — and cannot be imported. Remove it from the file"));
        } else if !export::EXPORTED_SETTINGS.contains(&key.as_str()) {
            b.push(format!("Setting {key} is not one this EasyWAF knows"));
        }
        let number = |lo: i64, hi: i64| value.trim().parse::<i64>().is_ok_and(|n| (lo..=hi).contains(&n));
        let ok = match key.as_str() {
            "traffic_retention_days"  => number(0, 3650),
            "request_body_inspect_kb" => number(0, 32 * 1024),
            "syslog_port"             => value.trim().is_empty() || number(1, 65535),
            "backup_keep"             => number(1, 365),
            "tls_profile"             => ["modern", "compatible"].contains(&value.trim()),
            _ => true,
        };
        if !ok {
            b.push(format!("Setting {key} = {value:?} is not a value it can take"));
        }
    }

    // ── Rule sets this installation can install ──
    let offered: HashMap<String, i64> = crate::rules_update::offered(db).await
        .into_iter().map(|s| (s.id, s.version)).collect();
    let defs = crate::routes::rules::catalogue_sets();

    // ── Countries, addresses, lists — shared by policies and "every policy" ──
    let check_scope = |who: &str, mode: &str, cs: &[String], addrs: &[export::Address],
                       lists: &[export::ListChoice], b: &mut Vec<String>, w: &mut Vec<String>| {
        if !COUNTRY_MODES.contains(&mode) {
            b.push(format!("{who}: country mode {mode:?} is not off, block or allow"));
        }
        for c in cs {
            if c.len() != 2 || !c.bytes().all(|x| x.is_ascii_uppercase()) {
                b.push(format!("{who}: {c:?} is not a two-letter country code"));
            }
        }
        let mut seen = HashSet::new();
        for a in addrs {
            if !valid_network(&a.address) {
                b.push(format!("{who}: {:?} is not an address or a network", a.address));
            }
            if a.list != "allow" && a.list != "block" {
                b.push(format!("{who}: {} is on list {:?}, which is not allow or block", a.address, a.list));
            }
            if !seen.insert(&a.address) {
                b.push(format!("{who}: {} is listed twice", a.address));
            }
        }
        for l in lists {
            if crate::iplist::Response::parse(&l.response).is_none() {
                b.push(format!("{who}: list {} answers {:?}, which is not block or challenge", l.id, l.response));
            }
        }
        let _ = w;
    };
    let e = &doc.everywhere;
    check_scope("Every policy", &e.countries_mode, &e.countries, &e.addresses, &e.lists, b, w);

    // ── Policies ──
    let mut names = HashSet::new();
    for pol in &doc.policies {
        let who = format!("Policy {}", pol.name);
        if pol.name.trim().is_empty() { b.push("A policy has no name".into()); }
        if !names.insert(pol.name.as_str()) { b.push(format!("{who} appears twice")); }
        if !MODES.contains(&pol.mode.as_str()) {
            b.push(format!("{who}: mode {:?} is not On, DetectionOnly or Off", pol.mode));
        }
        if pol.score_threshold < 1 { b.push(format!("{who}: the score threshold must be at least 1")); }
        if pol.challenge_threshold < 0 { b.push(format!("{who}: the challenge threshold cannot be negative")); }
        check_scope(&who, &pol.countries_mode, &pol.countries, &pol.addresses, &pol.lists, b, w);

        let mut held = HashSet::new();
        for s in &pol.rule_sets {
            held.insert(s.id.as_str());
            match offered.get(&s.id) {
                None => b.push(format!(
                    "{who} holds rule set {}, which the rule channel this installation reads does \
                     not offer. Check Settings → Updates, or remove it from the file", s.id)),
                Some(v) if *v != s.version => w.push(format!(
                    "{who}: rule set {} was exported at v{}; this installation will install v{v}, \
                     which is what its channel offers", s.id, s.version)),
                _ => {}
            }
        }
        let of_held = |n: i64| defs.get(&n).is_some_and(|s| held.contains(s.as_str()));
        let strays: Vec<String> = pol.rules_off.iter().filter(|n| !of_held(**n))
            .map(|n| n.to_string()).collect();
        if !strays.is_empty() {
            w.push(format!("{who}: rules {} are listed as switched off but are not in any set it \
                            holds; ignored", listing(strays)));
        }
        for x in &pol.exclusions {
            if !x.rule.is_some_and(of_held) {
                w.push(format!("{who}: an exclusion names rule {}, which is not in any set it holds; \
                                ignored", x.rule.map(|n| n.to_string()).unwrap_or_else(|| "(none)".into())));
            }
        }
        for r in &pol.rules {
            let rw = format!("{who}, rule {:?}", r.name);
            if !ZONES.contains(&r.zone.as_str()) {
                b.push(format!("{rw}: zone {:?} is not ANY, ARGS, BODY, HEADERS or URL — the engine \
                                would read it as ANY and inspect more than was meant", r.zone));
            }
            if !ACTIONS.contains(&r.action.as_str()) {
                b.push(format!("{rw}: action {:?} is not score or block", r.action));
            }
            if let Err(e) = regex::Regex::new(&r.pattern) {
                b.push(format!("{rw}: the pattern does not compile ({}) — the engine would skip it \
                                silently", e.to_string().lines().last().unwrap_or("").trim()));
            }
            if r.external_id.is_some_and(of_held) {
                b.push(format!("{rw} is catalogue rule {} held in full, but the policy also holds \
                                its set", r.external_id.unwrap_or_default()));
            }
            for x in &r.exclusions {
                if !x.client.is_empty() && !valid_network(&x.client) {
                    b.push(format!("{rw}: exclusion client {:?} is not an address or a network", x.client));
                }
            }
        }
        for x in &pol.exclusions {
            if !x.client.is_empty() && !valid_network(&x.client) {
                b.push(format!("{who}: exclusion client {:?} is not an address or a network", x.client));
            }
        }
    }

    // ── Certificates ──
    let management = crate::routes::settings::get_management_cert(db).await;
    let local_certs: HashMap<String, String> = sqlx::query("SELECT name, cert_pem FROM certs")
        .fetch_all(db).await.unwrap_or_default()
        .into_iter().map(|r| (r.get("name"), r.get("cert_pem"))).collect();
    let mut usable: HashSet<String> = HashSet::new();
    let mut cert_names = HashSet::new();
    for c in &doc.certificates {
        if !cert_names.insert(c.name.as_str()) { b.push(format!("Certificate {} appears twice", c.name)); }
        match &c.private_key {
            Some(key) => match crate::tls::validate_pem(&c.certificate, key) {
                Ok(()) => { usable.insert(c.name.clone()); }
                Err(e) => b.push(format!("Certificate {}: {e}", c.name)),
            },
            None if local_certs.contains_key(&c.name) => { usable.insert(c.name.clone()); }
            None => {}
        }
    }
    // The management certificate stays wherever the file is silent about it.
    usable.insert(management.clone());

    // ── Sites ──
    let policy_names: HashSet<&str> = doc.policies.iter().map(|p| p.name.as_str()).collect();
    let mut site_names = HashSet::new();
    let mut hosts: HashMap<String, String> = HashMap::new();
    for s in &doc.sites {
        let who = format!("Site {}", s.name);
        if !site_names.insert(s.name.as_str()) { b.push(format!("{who} appears twice")); }
        for h in std::iter::once(&s.host).chain(&s.aliases) {
            let n = crate::routes::sites::normalize_server_name(h);
            if n.is_empty() { b.push(format!("{who}: {h:?} is not a hostname")); continue; }
            if let Some(other) = hosts.insert(n.clone(), s.name.clone())
                && other != s.name
            {
                b.push(format!("{who} and site {other} both answer for {n}"));
            }
        }
        if let Some(pol) = &s.policy {
            if !policy_names.contains(pol.as_str()) {
                b.push(format!("{who} uses policy {pol}, which the file does not have — an import \
                                makes this installation match the file, so it would not exist"));
            }
        } else {
            w.push(format!("{who} has no policy: its traffic is proxied without inspection"));
        }
        match &s.certificate {
            Some(c) if !usable.contains(c) => b.push(format!(
                "{who} serves with certificate {c}, which the file has without its private key and \
                 this installation does not have. Export with private keys, or add the certificate \
                 here first")),
            None if s.tls_port.is_some() => b.push(format!(
                "{who} has an HTTPS port but no certificate to serve it with")),
            _ => {}
        }
        let ports = std::iter::once(s.listen_port)
            .chain(s.tls_port)
            .chain(s.extra_ports.iter().map(|p| p.port));
        for port in ports {
            if !(1..=65535).contains(&port) {
                b.push(format!("{who}: {port} is not a port"));
            } else if gui_ports.contains(&(port as u16)) {
                b.push(format!("{who}: port {port} is the management interface's own"));
            }
        }
        if !s.upstreams.iter().any(|u| u.enabled) {
            b.push(format!("{who} has no upstream switched on — it would have nothing to forward to"));
        }
        for u in &s.upstreams {
            let ok = reqwest::Url::parse(&u.url)
                .is_ok_and(|x| (x.scheme() == "http" || x.scheme() == "https") && x.host().is_some());
            if !ok { b.push(format!("{who}: upstream {:?} is not an http:// or https:// address", u.url)); }
            if u.weight < 1 { b.push(format!("{who}: upstream {} has a weight below 1", u.url)); }
        }
    }

    // ── Accounts ──
    let mut users = HashSet::new();
    for a in &doc.accounts {
        if !users.insert(a.username.as_str()) { b.push(format!("Account {} appears twice", a.username)); }
        if a.role != "admin" && a.role != "viewer" {
            b.push(format!("Account {}: role {:?} is not admin or viewer", a.username, a.role));
        }
        if !a.password_hash.starts_with("$2") {
            b.push(format!("Account {}: the password hash is not a bcrypt hash", a.username));
        }
    }
}

// ─── The diff ────────────────────────────────────────────

/// Created, changed or removed, by name.
fn by_name<'a, T, N, D>(current: &'a [T], wanted: &'a [T], name: N, describe: D) -> Vec<Item>
where
    N: Fn(&T) -> &str,
    D: Fn(&T, &T) -> Vec<String>,
{
    let have: BTreeMap<&str, &T> = current.iter().map(|t| (name(t), t)).collect();
    let want: BTreeMap<&str, &T> = wanted.iter().map(|t| (name(t), t)).collect();
    let mut out = Vec::new();
    for (n, w) in &want {
        match have.get(n) {
            None => out.push(item("create", n, Vec::new())),
            Some(h) => {
                let d = describe(h, w);
                if !d.is_empty() { out.push(item("change", n, d)); }
            }
        }
    }
    for n in have.keys() {
        if !want.contains_key(n) { out.push(item("remove", n, Vec::new())); }
    }
    out
}

/// "was → will be", when they differ.
fn field<T: PartialEq + std::fmt::Display>(out: &mut Vec<String>, what: &str, was: T, now: T) {
    if was != now { out.push(format!("{what}: {was} → {now}")); }
}

/// Added and removed members of two lists, said as counts with the names.
fn set_change<T: Ord + Clone, F: Fn(&T) -> String>(out: &mut Vec<String>, what: &str, was: &[T], now: &[T], show: F) {
    let a: BTreeSet<&T> = was.iter().collect();
    let b: BTreeSet<&T> = now.iter().collect();
    let added: Vec<String> = b.difference(&a).map(|t| show(t)).collect();
    let gone: Vec<String> = a.difference(&b).map(|t| show(t)).collect();
    if !added.is_empty() { out.push(format!("{what} added: {}", listing(added))); }
    if !gone.is_empty()  { out.push(format!("{what} removed: {}", listing(gone))); }
}

fn diff_settings(current: &Document, doc: &Document) -> Vec<Item> {
    let mut out = Vec::new();
    for key in export::EXPORTED_SETTINGS {
        match (current.settings.get(*key), doc.settings.get(*key)) {
            (None, Some(v))              => out.push(item("create", key, vec![format!("set to {v:?}")])),
            (Some(a), Some(v)) if a != v => out.push(item("change", key, vec![format!("{a:?} → {v:?}")])),
            (Some(a), None)              => out.push(item("remove", key, vec![format!("{a:?} → the default")])),
            _ => {}
        }
    }
    out
}

fn diff_everywhere(current: &Document, doc: &Document) -> Vec<Item> {
    let (a, b) = (&current.everywhere, &doc.everywhere);
    let mut d = Vec::new();
    field(&mut d, "country mode", a.countries_mode.as_str(), b.countries_mode.as_str());
    field(&mut d, "countries", countries(&a.countries).as_str(), countries(&b.countries).as_str());
    set_change(&mut d, "addresses", &a.addresses, &b.addresses, |x| format!("{} ({})", x.address, x.list));
    set_change(&mut d, "published lists", &a.lists, &b.lists,
               |x| format!("{} ({}, {})", x.id, if x.enabled { "on" } else { "off" }, x.response));
    if d.is_empty() { Vec::new() } else { vec![item("change", "what applies to every policy", d)] }
}

fn diff_policies(current: &Document, doc: &Document) -> Vec<Item> {
    by_name(&current.policies, &doc.policies, |p| &p.name, |a, b| {
        let mut d = Vec::new();
        field(&mut d, "mode", a.mode.as_str(), b.mode.as_str());
        field(&mut d, "score threshold", a.score_threshold, b.score_threshold);
        field(&mut d, "challenge threshold", a.challenge_threshold, b.challenge_threshold);
        field(&mut d, "country mode", a.countries_mode.as_str(), b.countries_mode.as_str());
        field(&mut d, "countries", countries(&a.countries).as_str(), countries(&b.countries).as_str());
        let on_off = |on: bool| if on { "on" } else { "off" };
        field(&mut d, "Smart Protect", on_off(a.smart_protect), on_off(b.smart_protect));
        let sets = |p: &export::Policy| p.rule_sets.iter().map(|s| (s.id.clone(), s.version)).collect::<Vec<_>>();
        set_change(&mut d, "rule sets", &sets(a), &sets(b), |(id, v)| format!("{id} v{v}"));
        set_change(&mut d, "rules switched off", &a.rules_off, &b.rules_off, |n| n.to_string());
        let own = |p: &export::Policy| p.rules.iter().map(|r| format!("{} [{}]", r.name, r.pattern)).collect::<Vec<_>>();
        set_change(&mut d, "own rules", &own(a), &own(b), |s| s.split(" [").next().unwrap_or("").to_string());
        set_change(&mut d, "exclusions", &a.exclusions, &b.exclusions,
                   |x| format!("rule {} {}", x.rule.unwrap_or_default(),
                               if x.path_prefix.is_empty() { "everywhere".into() } else { format!("on {}", x.path_prefix) }));
        set_change(&mut d, "addresses", &a.addresses, &b.addresses, |x| format!("{} ({})", x.address, x.list));
        set_change(&mut d, "published lists", &a.lists, &b.lists,
                   |x| format!("{} ({}, {})", x.id, if x.enabled { "on" } else { "off" }, x.response));
        d
    })
}

async fn diff_certificates(db: &SqlitePool, current: &Document, doc: &Document) -> Vec<Item> {
    let management = crate::routes::settings::get_management_cert(db).await;
    let mut out = Vec::new();
    let have: BTreeMap<&str, &export::Certificate> = current.certificates.iter().map(|c| (c.name.as_str(), c)).collect();
    for c in &doc.certificates {
        match (have.get(c.name.as_str()), &c.private_key) {
            (None, Some(_)) => out.push(item("create", &c.name, vec![c.domain.clone()])),
            (None, None) => out.push(item("keep", &c.name, vec![
                "not imported: the file has no private key for it and this installation does not have it".into()])),
            (Some(h), Some(_)) if h.certificate != c.certificate =>
                out.push(item("change", &c.name, vec!["replaced by the file's certificate and key".into()])),
            (Some(h), None) if h.certificate != c.certificate => out.push(item("keep", &c.name, vec![
                "this installation's certificate is kept — the file's is different, and has no private key".into()])),
            _ => {}
        }
    }
    let wanted: HashSet<&str> = doc.certificates.iter().map(|c| c.name.as_str()).collect();
    for name in have.keys() {
        if !wanted.contains(name) && *name != management.as_str() {
            out.push(item("remove", name, Vec::new()));
        }
    }
    out
}

fn diff_sites(current: &Document, doc: &Document) -> Vec<Item> {
    by_name(&current.sites, &doc.sites, |s| &s.name, |a, b| {
        let mut d = Vec::new();
        let opt = |o: &Option<String>| o.clone().unwrap_or_else(|| "none".into());
        let port = |o: &Option<i64>| o.map(|p| p.to_string()).unwrap_or_else(|| "none".into());
        field(&mut d, "host", a.host.as_str(), b.host.as_str());
        set_change(&mut d, "aliases", &a.aliases, &b.aliases, |x| x.clone());
        field(&mut d, "enabled", a.enabled, b.enabled);
        field(&mut d, "policy", opt(&a.policy).as_str(), opt(&b.policy).as_str());
        field(&mut d, "certificate", opt(&a.certificate).as_str(), opt(&b.certificate).as_str());
        field(&mut d, "port", a.listen_port, b.listen_port);
        field(&mut d, "HTTPS port", port(&a.tls_port).as_str(), port(&b.tls_port).as_str());
        field(&mut d, "redirect to HTTPS", a.tls_redirect, b.tls_redirect);
        field(&mut d, "ACME", a.acme, b.acme);
        field(&mut d, "session affinity", a.affinity, b.affinity);
        field(&mut d, "backend certificate unverified",
              a.backend_certificate_unverified, b.backend_certificate_unverified);
        field(&mut d, "HSTS", a.hsts, b.hsts);
        field(&mut d, "X-Frame-Options", a.x_frame, b.x_frame);
        field(&mut d, "X-Frame-Options value", a.x_frame_value.as_str(), b.x_frame_value.as_str());
        field(&mut d, "X-Content-Type-Options", a.x_content_type, b.x_content_type);
        field(&mut d, "X-XSS-Protection", a.xss_protection, b.xss_protection);
        let ups = |s: &export::Site| s.upstreams.iter()
            .map(|u| format!("{} weight {}{}", u.url, u.weight, if u.enabled { "" } else { " (off)" }))
            .collect::<Vec<_>>();
        set_change(&mut d, "upstreams", &ups(a), &ups(b), |x| x.clone());
        set_change(&mut d, "extra ports", &a.extra_ports, &b.extra_ports,
                   |p| format!("{}{}", p.port, if p.tls { " (HTTPS)" } else { "" }));
        d
    })
}

fn diff_accounts(current: &Document, doc: &Document, importer: &str) -> Vec<Item> {
    let have: BTreeMap<&str, &export::Account> = current.accounts.iter().map(|a| (a.username.as_str(), a)).collect();
    let mut out = Vec::new();
    for a in &doc.accounts {
        match have.get(a.username.as_str()) {
            None => out.push(item("create", &a.username, vec![format!("{}{}", a.role,
                                  if a.enabled { "" } else { ", disabled" })])),
            Some(h) => {
                let mut d = Vec::new();
                if a.username == importer && (a.role != "admin" || !a.enabled) {
                    out.push(item("keep", &a.username, vec![
                        "your own account — an import never disables or demotes the account running it".into()]));
                    continue;
                }
                field(&mut d, "role", h.role.as_str(), a.role.as_str());
                field(&mut d, "enabled", h.enabled, a.enabled);
                if h.password_hash != a.password_hash { d.push("password changed to the file's".into()); }
                if !d.is_empty() { out.push(item("change", &a.username, d)); }
            }
        }
    }
    if !doc.accounts.is_empty() {
        let wanted: HashSet<&str> = doc.accounts.iter().map(|a| a.username.as_str()).collect();
        let kept: Vec<String> = have.keys().filter(|n| !wanted.contains(*n)).map(|n| n.to_string()).collect();
        if !kept.is_empty() {
            out.push(item("keep", &listing(kept), vec![
                "not in the file, and kept: an import never deletes accounts".into()]));
        }
    }
    out
}

// ─── Apply ───────────────────────────────────────────────

/// Apply a document to `work` — a copy of the live database, which is what
/// gets swapped in afterwards. Everything is replaced to match the file,
/// except accounts, which are merged, and this host's management certificate.
pub async fn apply(work: &SqlitePool, doc: &Document, importer: &str) -> Result<(), String> {
    let by = format!("import by {importer}");
    let err = |e: sqlx::Error| e.to_string();

    // ── Settings: the file's, and the defaults for any it leaves out ──
    for key in export::EXPORTED_SETTINGS {
        match doc.settings.get(*key) {
            Some(v) => { sqlx::query(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
                .bind(key).bind(v).execute(work).await.map_err(err)?; }
            None => { sqlx::query("DELETE FROM settings WHERE key = ?")
                .bind(key).execute(work).await.map_err(err)?; }
        }
    }

    // ── Every policy ──
    let e = &doc.everywhere;
    sqlx::query("UPDATE geoip_everywhere SET mode = ?, countries = ?, changed_by = ?, updated_at = datetime('now')")
        .bind(&e.countries_mode).bind(e.countries.join(",")).bind(&by)
        .execute(work).await.map_err(err)?;
    sqlx::query("DELETE FROM ip_rules WHERE policy_id IS NULL").execute(work).await.map_err(err)?;
    sqlx::query("DELETE FROM ip_list_feeds WHERE policy_id IS NULL").execute(work).await.map_err(err)?;
    put_scope(work, None, &e.addresses, &e.lists, &by).await?;

    // ── Policies: the file's, and none that it does not name ──
    let wanted: Vec<&str> = doc.policies.iter().map(|p| p.name.as_str()).collect();
    for (id, name) in sqlx::query("SELECT id, name FROM policies").fetch_all(work).await.map_err(err)?
        .into_iter().map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("name")))
    {
        if !wanted.contains(&name.as_str()) {
            sqlx::query("DELETE FROM policies WHERE id = ?").bind(id).execute(work).await.map_err(err)?;
        }
    }
    let defs = crate::routes::rules::catalogue_sets();
    for p in &doc.policies {
        sqlx::query(
            "INSERT INTO policies (name, rule_engine, score_threshold, challenge_threshold, geoip_mode, geoip_countries,
                                   smart_protect)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(name) DO UPDATE SET rule_engine = excluded.rule_engine,
                 score_threshold = excluded.score_threshold, challenge_threshold = excluded.challenge_threshold,
                 geoip_mode = excluded.geoip_mode, geoip_countries = excluded.geoip_countries,
                 smart_protect = excluded.smart_protect")
            .bind(&p.name).bind(&p.mode).bind(p.score_threshold).bind(p.challenge_threshold)
            .bind(&p.countries_mode).bind(p.countries.join(",")).bind(p.smart_protect)
            .execute(work).await.map_err(err)?;
        let id: i64 = sqlx::query_scalar("SELECT id FROM policies WHERE name = ?")
            .bind(&p.name).fetch_one(work).await.map_err(err)?;

        // Emptied, then filled from the file: the policy is what the file
        // says, not what the file says added to what was here.
        for table in ["policy_rule_exclusions", "waf_rules", "policy_rule_sets",
                      "policy_rule_set_previous", "ip_rules", "ip_list_feeds"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE policy_id = ?"))
                .bind(id).execute(work).await.map_err(err)?;
        }

        // Sets through the verified path the Rule Sets page uses.
        for s in &p.rule_sets {
            crate::rules_update::apply(work, id, &s.id).await
                .map_err(|e| format!("policy {}: rule set {} could not be installed: {e}", p.name, s.id))?;
        }
        let held: HashSet<&str> = p.rule_sets.iter().map(|s| s.id.as_str()).collect();
        let of_held = |n: &i64| defs.get(n).is_some_and(|s| held.contains(s.as_str()));
        let off: HashSet<i64> = p.rules_off.iter().filter(|n| of_held(n)).copied().collect();
        crate::routes::rules::switch_off_by_external_ids(work, id, &off).await.map_err(|e| e.to_string())?;
        for x in p.exclusions.iter().filter(|x| x.rule.as_ref().is_some_and(of_held)) {
            put_exclusion(work, id, x.rule, None, x).await?;
        }

        for r in &p.rules {
            let row: i64 = sqlx::query(
                "INSERT INTO waf_rules (policy_id, name, description, zone, pattern, score, action, enabled,
                                        external_id, rule_set, cloned_from_external_id, cloned_from_version, cloned_from_set)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(id).bind(&r.name).bind(&r.description).bind(&r.zone).bind(&r.pattern)
                .bind(r.score).bind(&r.action).bind(r.enabled)
                .bind(r.external_id).bind(&r.rule_set)
                .bind(r.cloned_from_external_id).bind(r.cloned_from_version).bind(&r.cloned_from_set)
                .execute(work).await.map_err(err)?
                .last_insert_rowid();
            for x in &r.exclusions {
                // A catalogue rule's exclusion is kept by its number, as the
                // Exclusions page records it; a rule written here, by its row.
                match r.external_id {
                    Some(n) => put_exclusion(work, id, Some(n), None, x).await?,
                    None    => put_exclusion(work, id, None, Some(row), x).await?,
                }
            }
        }
        put_scope(work, Some(id), &p.addresses, &p.lists, &by).await?;
    }

    // ── Certificates the file brings with their keys ──
    for c in doc.certificates.iter().filter(|c| c.private_key.is_some()) {
        let (_, not_before, not_after) = crate::routes::certs::parse_cert_pem(&c.certificate);
        sqlx::query(
            "INSERT INTO certs (name, domain, not_before, not_after, cert_pem, key_pem, acme_domain)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(name) DO UPDATE SET domain = excluded.domain, not_before = excluded.not_before,
                 not_after = excluded.not_after, cert_pem = excluded.cert_pem, key_pem = excluded.key_pem,
                 acme_domain = excluded.acme_domain")
            .bind(&c.name).bind(&c.domain).bind(not_before.unwrap_or_default())
            .bind(not_after.unwrap_or_default()).bind(&c.certificate).bind(&c.private_key)
            .bind(&c.acme_domain)
            .execute(work).await.map_err(err)?;
    }
    let cert_ids: HashMap<String, i64> = sqlx::query("SELECT id, name FROM certs")
        .fetch_all(work).await.map_err(err)?
        .into_iter().map(|r| (r.get("name"), r.get("id"))).collect();
    let policy_ids: HashMap<String, i64> = sqlx::query("SELECT id, name FROM policies")
        .fetch_all(work).await.map_err(err)?
        .into_iter().map(|r| (r.get("name"), r.get("id"))).collect();

    // ── Sites ──
    let wanted: Vec<&str> = doc.sites.iter().map(|s| s.name.as_str()).collect();
    for (id, name) in sqlx::query("SELECT id, name FROM sites").fetch_all(work).await.map_err(err)?
        .into_iter().map(|r| (r.get::<i64, _>("id"), r.get::<String, _>("name")))
    {
        if !wanted.contains(&name.as_str()) {
            sqlx::query("DELETE FROM sites WHERE id = ?").bind(id).execute(work).await.map_err(err)?;
        }
    }
    for s in &doc.sites {
        let host = crate::routes::sites::normalize_server_name(&s.host);
        let policy = s.policy.as_ref().and_then(|p| policy_ids.get(p)).copied();
        let cert = s.certificate.as_ref().and_then(|c| cert_ids.get(c)).copied();
        sqlx::query(
            "INSERT INTO sites (name, server_name, enabled, cert_id, acme_enabled, waf_policy_id, hsts,
                                x_frame, x_frame_value, x_content_type, xss_protection, listen_port,
                                tls_port, tls_redirect, affinity, backend_tls_insecure)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(name) DO UPDATE SET server_name = excluded.server_name, enabled = excluded.enabled,
                 cert_id = excluded.cert_id, acme_enabled = excluded.acme_enabled,
                 waf_policy_id = excluded.waf_policy_id, hsts = excluded.hsts, x_frame = excluded.x_frame,
                 x_frame_value = excluded.x_frame_value, x_content_type = excluded.x_content_type,
                 xss_protection = excluded.xss_protection, listen_port = excluded.listen_port,
                 tls_port = excluded.tls_port, tls_redirect = excluded.tls_redirect,
                 affinity = excluded.affinity, backend_tls_insecure = excluded.backend_tls_insecure,
                 updated_at = datetime('now')")
            .bind(&s.name).bind(&host).bind(s.enabled).bind(cert).bind(s.acme).bind(policy)
            .bind(s.hsts).bind(s.x_frame).bind(&s.x_frame_value).bind(s.x_content_type)
            .bind(s.xss_protection).bind(s.listen_port).bind(s.tls_port).bind(s.tls_redirect)
            .bind(s.affinity).bind(s.backend_certificate_unverified)
            .execute(work).await.map_err(err)?;
        let id: i64 = sqlx::query_scalar("SELECT id FROM sites WHERE name = ?")
            .bind(&s.name).fetch_one(work).await.map_err(err)?;
        for table in ["site_aliases", "upstreams", "site_ports"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE site_id = ?"))
                .bind(id).execute(work).await.map_err(err)?;
        }
        for a in &s.aliases {
            sqlx::query("INSERT INTO site_aliases (site_id, name) VALUES (?, ?)")
                .bind(id).bind(crate::routes::sites::normalize_server_name(a))
                .execute(work).await.map_err(err)?;
        }
        for u in &s.upstreams {
            sqlx::query("INSERT INTO upstreams (site_id, url, weight, enabled) VALUES (?, ?, ?, ?)")
                .bind(id).bind(&u.url).bind(u.weight).bind(u.enabled)
                .execute(work).await.map_err(err)?;
        }
        for p in &s.extra_ports {
            sqlx::query("INSERT INTO site_ports (site_id, port, tls) VALUES (?, ?, ?)")
                .bind(id).bind(p.port).bind(p.tls)
                .execute(work).await.map_err(err)?;
        }
    }

    // ── Certificates the file does not name, once no site needs them ──
    let management = crate::routes::settings::get_management_cert(work).await;
    let named: HashSet<&str> = doc.certificates.iter().map(|c| c.name.as_str()).collect();
    for (name, id) in &cert_ids {
        if !named.contains(name.as_str()) && *name != management {
            sqlx::query("DELETE FROM certs WHERE id = ?").bind(id).execute(work).await.map_err(err)?;
        }
    }

    // ── Accounts: merged, and never against the person importing ──
    for a in &doc.accounts {
        if a.username == importer {
            // Only the password travels to one's own account; role and
            // whether it is enabled stay as they are.
            sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
                .bind(&a.password_hash).bind(&a.username).execute(work).await.map_err(err)?;
            continue;
        }
        sqlx::query(
            "INSERT INTO users (username, password_hash, role, enabled) VALUES (?, ?, ?, ?)
             ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash,
                 role = excluded.role, enabled = excluded.enabled")
            .bind(&a.username).bind(&a.password_hash).bind(&a.role).bind(a.enabled)
            .execute(work).await.map_err(err)?;
    }

    // What the copy now is must be a database, whole, before it is swapped in.
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(work).await.map_err(err)?;
    if integrity != "ok" {
        return Err(format!("the imported database failed its own check: {integrity}"));
    }
    let dangling: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
        .fetch_one(work).await.map_err(err)?;
    if dangling > 0 {
        return Err(format!("the imported database has {dangling} reference(s) to things that do not exist"));
    }
    Ok(())
}

async fn put_scope(work: &SqlitePool, policy: Option<i64>, addrs: &[export::Address],
                   lists: &[export::ListChoice], by: &str) -> Result<(), String> {
    for a in addrs {
        sqlx::query("INSERT INTO ip_rules (policy_id, ip, list_type, reason, added_by) VALUES (?, ?, ?, ?, ?)")
            .bind(policy).bind(&a.address).bind(&a.list)
            .bind(if a.reason.is_empty() { None } else { Some(&a.reason) }).bind(by)
            .execute(work).await.map_err(|e| e.to_string())?;
    }
    for l in lists {
        sqlx::query("INSERT INTO ip_list_feeds (policy_id, id, enabled, response, changed_by) VALUES (?, ?, ?, ?, ?)")
            .bind(policy).bind(&l.id).bind(l.enabled).bind(&l.response).bind(by)
            .execute(work).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn put_exclusion(work: &SqlitePool, policy: i64, external: Option<i64>, row: Option<i64>,
                       x: &export::Exclusion) -> Result<(), String> {
    sqlx::query(
        "INSERT INTO policy_rule_exclusions (policy_id, external_id, rule_id, path_prefix, client_cidr, note)
         VALUES (?, ?, ?, ?, ?, ?)")
        .bind(policy).bind(external).bind(row).bind(&x.path_prefix)
        .bind(if x.client.is_empty() { None } else { Some(&x.client) })
        .bind(if x.note.is_empty() { None } else { Some(&x.note) })
        .execute(work).await.map_err(|e| e.to_string())?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const GUI: &[u16] = &[8080, 8443];

    async fn fresh(tag: &str) -> SqlitePool {
        let path = std::env::temp_dir().join(format!("easywaf-import-{tag}-{}.db", std::process::id()));
        for sfx in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sfx}", path.display()));
        }
        crate::db::init(&format!("sqlite://{}", path.display())).await
    }

    /// Export estate A, import it into installation B — which has things of
    /// its own that must go — then export B. The two must be the same
    /// configuration. This is the property the whole feature promises.
    #[tokio::test]
    async fn an_export_imported_elsewhere_reproduces_the_configuration() {
        let a = crate::export::tests::estate("import-a").await;
        // Rule sets need a channel; the round trip here is everything else.
        sqlx::raw_sql("DELETE FROM policy_rule_sets").execute(&a).await.unwrap();
        // A real certificate, since an import checks the key fits it.
        let ck = rcgen::generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
        sqlx::query("UPDATE certs SET cert_pem = ?, key_pem = ? WHERE name = 'example'")
            .bind(ck.cert.pem()).bind(ck.key_pair.serialize_pem()).execute(&a).await.unwrap();
        sqlx::raw_sql("INSERT INTO users (username, password_hash, role) VALUES
                       ('alice', '$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'viewer')")
            .execute(&a).await.unwrap();

        let opts = export::Options { private_keys: true, accounts: true };
        let text = export::to_toml(&export::build(&a, opts).await.unwrap()).unwrap();

        let b = fresh("import-b").await;
        sqlx::raw_sql("INSERT INTO policies (name) VALUES ('only-on-b');
                       INSERT INTO sites (name, server_name, listen_port, enabled) VALUES ('old-site', 'old.example.com', 8090, 1);
                       INSERT INTO upstreams (site_id, url) VALUES (1, 'http://10.9.9.9');")
            .execute(&b).await.unwrap();

        let doc = parse(&text).expect("an export does not parse as an import");
        let p = plan(&b, &doc, GUI, "someone").await;
        assert!(p.blockers.is_empty(), "a clean export was refused: {:?}", p.blockers);
        let removed: Vec<&str> = p.groups.iter().flat_map(|g| &g.items)
            .filter(|i| i.action == "remove").map(|i| i.name.as_str()).collect();
        assert!(removed.contains(&"only-on-b") && removed.contains(&"old-site"),
                "the preview does not say what the import removes: {removed:?}");

        apply(&b, &doc, "someone").await.expect("apply");

        let (x, y) = (export::build(&a, opts).await.unwrap(), export::build(&b, opts).await.unwrap());
        assert_eq!(y.settings, x.settings, "settings differ after the round trip");
        assert_eq!(y.everywhere, x.everywhere, "what applies to every policy differs");
        assert_eq!(y.policies, x.policies, "policies differ after the round trip");
        assert_eq!(y.certificates, x.certificates, "certificates differ");
        assert_eq!(y.sites, x.sites, "sites differ");
        assert_eq!(y.accounts, x.accounts, "accounts differ");
        a.close().await;
        b.close().await;
    }

    #[test]
    fn smart_protect_travels_with_its_policy() {
        let on = "[easywaf]\nformat = 1\nversion = \"0.15.0\"\nexported = \"x\"\n\
                  [[policy]]\nname = \"p\"\nmode = \"On\"\nscore_threshold = 10\nsmart_protect = true\n";
        assert!(parse(on).unwrap().policies[0].smart_protect);
        // A file that does not mention it — from before the switch existed, or
        // from an installation that does not use it — leaves it off.
        let silent = "[easywaf]\nformat = 1\nversion = \"0.14.4\"\nexported = \"x\"\n\
                      [[policy]]\nname = \"p\"\nmode = \"On\"\nscore_threshold = 10\n";
        assert!(!parse(silent).unwrap().policies[0].smart_protect);
    }

    #[test]
    fn a_file_from_a_newer_easywaf_says_to_upgrade() {
        let newer_field = "[easywaf]\nformat = 1\nversion = \"99.0.0\"\nexported = \"x\"\n\
                           [[policy]]\nname = \"p\"\nmode = \"On\"\nscore_threshold = 10\nnot_invented_yet = true\n";
        let e = parse(newer_field).unwrap_err();
        assert!(e.contains("99.0.0") && e.contains("Upgrade"), "{e}");

        let newer_format = "[easywaf]\nformat = 2\nversion = \"99.0.0\"\nexported = \"x\"\n";
        assert!(parse(newer_format).unwrap_err().contains("format 2"));

        assert!(parse("[something]\nelse = 1\n").unwrap_err().contains("not an EasyWAF"));
        assert!(parse("this is = = not toml").unwrap_err().contains("not valid TOML"));
    }

    #[tokio::test]
    async fn what_cannot_be_applied_is_refused_with_the_reason() {
        let db = fresh("blockers").await;
        let text = r#"
[easywaf]
format = 1
version = "0.14.0"
exported = "2026-09-27T00:00:00Z"

[settings]
cookie_secret = "stolen"

[[policy]]
name = "p"
mode = "On"
score_threshold = 10

[[policy.rule]]
name = "bad pattern"
zone = "ARGS"
pattern = "(unclosed"
score = 5
action = "score"

[[policy.rule]]
name = "unknown zone"
zone = "URI"
pattern = "x"
score = 5
action = "score"

[[site]]
name = "s"
host = "s.example.com"
policy = "not-in-the-file"
certificate = "nobody-has-it"
listen_port = 8443
tls_port = 443

[[site.upstream]]
url = "ftp://nope"

[[site]]
name = "idle"
host = "idle.example.com"
policy = "p"
listen_port = 8081

[[site.upstream]]
url = "http://10.0.0.1"
enabled = false
"#;
        let doc = parse(text).expect("parse");
        let p = plan(&db, &doc, GUI, "someone").await;
        let all = p.blockers.join("\n");
        for (needle, why) in [
            ("cookie_secret",        "a credential in the file was not refused"),
            ("does not compile",     "a pattern the engine would skip was accepted"),
            ("\"URI\"",              "a zone the engine would widen to ANY was accepted"),
            ("not-in-the-file",      "a site using a policy the import would not create was accepted"),
            ("nobody-has-it",        "a site with a certificate nobody has was accepted"),
            ("management interface", "a site on the management port was accepted"),
            ("ftp://nope",           "an upstream that is not http was accepted"),
            ("nothing to forward",   "a site with no upstream switched on was accepted"),
        ] {
            assert!(all.contains(needle), "{why}. Blockers were:\n{all}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn an_import_never_locks_out_the_person_running_it_or_deletes_accounts() {
        let db = fresh("accounts").await;
        sqlx::raw_sql("INSERT INTO users (username, password_hash, role) VALUES
                         ('me', '$2b$12$mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm', 'admin'),
                         ('bob', '$2b$12$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'admin')")
            .execute(&db).await.unwrap();
        // A file that would demote and disable me, and does not mention bob.
        let text = r#"
[easywaf]
format = 1
version = "0.14.0"
exported = "2026-09-27T00:00:00Z"
contains = ["accounts"]

[[account]]
username = "me"
role = "viewer"
enabled = false
password_hash = "$2b$12$nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"
"#;
        let doc = parse(text).unwrap();
        apply(&db, &doc, "me").await.unwrap();
        let (role, enabled): (String, i64) = sqlx::query_as("SELECT role, enabled FROM users WHERE username = 'me'")
            .fetch_one(&db).await.unwrap();
        assert_eq!((role.as_str(), enabled), ("admin", 1), "the import demoted or disabled the person running it");
        let bob: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = 'bob'")
            .fetch_one(&db).await.unwrap();
        assert_eq!(bob, 1, "an account the file did not mention was deleted");
        db.close().await;
    }
}

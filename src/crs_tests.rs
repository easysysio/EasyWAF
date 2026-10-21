// =========================================================
// crs_tests.rs — EasyWAF
// `easywaf test-crs`: a rule set converted from OWASP CRS,
// checked against CRS's own regression tests in this
// engine.
//
//   easywaf test-crs <set.rules.toml> <coreruleset>/tests/regression/tests
//
// CRS ships a test per rule: requests, each with the rule
// ids it must and must not set off (go-ftw's format). A
// converted rule is matched against every request whose
// assertions name it, through the same matching a proxied
// request goes through. A rule that fires where CRS says it
// must not, or stays silent where CRS says it must, is
// reported as failing:
//
//   FAIL <id> <crs id> <test> expected|unexpected
//
// followed by one summary line. The exit status is 0 when
// every rule passed, 1 when any failed, and 2 when the
// files could not be read. A job building sets from CRS
// drops the failing rules and publishes the rest.
// =========================================================

use crate::modules::targets::{Compiled, CompiledCondition, Parts};
use crate::modules::waf::Whole;
use crate::modules::RequestContext;
use std::collections::{BTreeMap, BTreeSet};
use yaml_rust2::Yaml;
use std::path::Path;

struct Rule {
    id:    i64,
    crs:   i64,
    conds: Compiled,
}

/// One request a CRS test sends, and what it says about which rules fire.
struct Case {
    name:      String,
    ctx:       RequestContext,
    expect:    BTreeSet<i64>,
    no_expect: BTreeSet<i64>,
}

/// Run the command. `args` are what followed `test-crs`.
pub fn run(args: &[String]) -> i32 {
    let [set, tests] = args else {
        eprintln!("usage: easywaf test-crs <set.rules.toml> <coreruleset>/tests/regression/tests");
        return 2;
    };
    let rules = match rules(Path::new(set)) {
        Ok(r) => r,
        Err(e) => { eprintln!("{set}: {e}"); return 2; }
    };
    let mut cases = Vec::new();
    if let Err(e) = collect(Path::new(tests), &mut cases) {
        eprintln!("{tests}: {e}");
        return 2;
    }
    if cases.is_empty() {
        eprintln!("{tests}: no CRS tests found there");
        return 2;
    }

    // rule id → (assertions checked, failures)
    let mut checked: BTreeMap<i64, (usize, Vec<String>)> = BTreeMap::new();
    for case in &cases {
        let (whole, parts) = (Whole::of(&case.ctx, &case.ctx.body), Parts::new(&case.ctx, &case.ctx.body));
        for rule in &rules {
            let wants = if case.expect.contains(&rule.crs) {
                true
            } else if case.no_expect.contains(&rule.crs) {
                false
            } else {
                continue;
            };
            let fired = crate::modules::targets::all_hold(&rule.conds, &whole, &parts);
            let entry = checked.entry(rule.id).or_default();
            entry.0 += 1;
            if fired != wants {
                let how = if wants { "expected" } else { "unexpected" };
                println!("FAIL {} {} {} {how}", rule.id, rule.crs, case.name);
                entry.1.push(case.name.clone());
            }
        }
    }

    let failing = checked.values().filter(|(_, f)| !f.is_empty()).count();
    let untested = rules.iter().filter(|r| !checked.contains_key(&r.id)).count();
    println!(
        "{} rules, {} passed, {failing} failed, {untested} with no CRS test; {} requests from CRS's tests",
        rules.len(),
        checked.len() - failing,
        cases.len()
    );
    if failing > 0 { 1 } else { 0 }
}

/// The set's rules converted from CRS — those whose description names the CRS
/// rule they came from. Others, written for EasyWAF, have no CRS test.
fn rules(path: &Path) -> Result<Vec<Rule>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let table: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
    let crs_id = regex::Regex::new(r"ModSecurity rule (\d+)").expect("a fixed pattern");
    let mut out = Vec::new();
    for r in table.get("rules").and_then(|r| r.as_array()).into_iter().flatten() {
        let id = r.get("id").and_then(|v| v.as_integer()).ok_or("a rule without an id")?;
        let description = r.get("description").and_then(|v| v.as_str()).unwrap_or("");
        let Some(crs) = crs_id.captures(description).and_then(|c| c[1].parse().ok()) else { continue };
        let table = r.as_table().ok_or(format!("rule {id} is not a table"))?;
        // One that cannot run is said so and left out, as check-set does,
        // rather than keeping every other rule from being tested.
        match crate::modules::targets::table_conditions(table)
            .and_then(|list| list.iter().map(CompiledCondition::new).collect::<Result<Compiled, String>>())
        {
            Ok(conds) => out.push(Rule { id, crs, conds }),
            Err(why) => println!("BROKEN {id} {crs} {why}"),
        }
    }
    Ok(out)
}

/// Every test file under `dir`, as cases.
fn collect(dir: &Path, out: &mut Vec<Case>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else if path.extension().is_some_and(|x| x == "yaml" || x == "yml") {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let docs = yaml_rust2::YamlLoader::load_from_str(&text)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            for doc in &docs {
                cases(doc, &path, out);
            }
        }
    }
    Ok(())
}

/// The requests one file sends. A stage sent as raw bytes (`encoded_request`)
/// or with no assertion about rule ids is not one this can check.
fn cases(doc: &Yaml, path: &Path, out: &mut Vec<Case>) {
    let file = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
    for test in doc["tests"].as_vec().into_iter().flatten() {
        let test_id = yaml_text(&test["test_id"]).unwrap_or_else(|| "?".into());
        for (n, stage) in test["stages"].as_vec().into_iter().flatten().enumerate() {
            let stage = if stage["stage"].is_badvalue() { stage } else { &stage["stage"] };
            let (input, log) = (&stage["input"], &stage["output"]["log"]);
            if input.is_badvalue() || log.is_badvalue() || !input["encoded_request"].is_badvalue() {
                continue;
            }
            let ids = |key: &str| -> BTreeSet<i64> {
                log[key].as_vec().into_iter().flatten().filter_map(Yaml::as_i64).collect()
            };
            let (expect, no_expect) = (ids("expect_ids"), ids("no_expect_ids"));
            if expect.is_empty() && no_expect.is_empty() {
                continue;
            }
            let Some(ctx) = request(input) else { continue };
            out.push(Case { name: format!("{file}-{test_id}.{}", n + 1), ctx, expect, no_expect });
        }
    }
}

/// A test's request as the engine is given one. `None` when it cannot be
/// built — a header value no HTTP stack would accept, for one.
fn request(input: &Yaml) -> Option<RequestContext> {
    let text = |key: &str| input[key].as_str().map(str::to_string);
    let uri = text("uri").unwrap_or_else(|| "/".into());
    let (path, query) = match uri.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (uri, None),
    };
    // A version no HTTP stack would hand on — `HTTP/1.11`, `HTTP/x` — is
    // one only a test sends raw.
    let version = match text("version").as_deref() {
        None | Some("HTTP/1.1") => axum::http::Version::HTTP_11,
        Some("HTTP/1.0")        => axum::http::Version::HTTP_10,
        Some("HTTP/0.9")        => axum::http::Version::HTTP_09,
        Some("HTTP/2" | "HTTP/2.0") => axum::http::Version::HTTP_2,
        Some("HTTP/3" | "HTTP/3.0") => axum::http::Version::HTTP_3,
        Some(_) => return None,
    };
    let mut headers = axum::http::HeaderMap::new();
    if let Some(map) = input["headers"].as_hash() {
        for (k, v) in map {
            let (Some(k), Some(v)) = (k.as_str(), yaml_text(v)) else { continue };
            let name = axum::http::HeaderName::from_bytes(k.as_bytes()).ok()?;
            let value = axum::http::HeaderValue::from_bytes(v.as_bytes()).ok()?;
            headers.append(name, value);
        }
    }
    let body = match &input["data"] {
        Yaml::Array(lines) => lines.iter().filter_map(yaml_text).collect::<Vec<_>>().join("\r\n"),
        v => yaml_text(v).unwrap_or_default(),
    };
    // go-ftw, which CRS's tests are written for, completes a request's headers
    // unless told not to: a body sent without a Content-Type is sent as a form,
    // and the rules are tested reading it that way; and one is sent with its
    // Content-Length, which the rules on a GET with a body read.
    let autocomplete = input["autocomplete_headers"].as_bool().unwrap_or(true);
    if autocomplete && !body.is_empty() && !headers.contains_key(axum::http::header::CONTENT_TYPE) {
        headers.insert(axum::http::header::CONTENT_TYPE,
                       axum::http::HeaderValue::from_static("application/x-www-form-urlencoded"));
    }
    if autocomplete && !body.is_empty() && !headers.contains_key(axum::http::header::CONTENT_LENGTH) {
        headers.insert(axum::http::header::CONTENT_LENGTH, axum::http::HeaderValue::from(body.len()));
    }
    // A body with neither a length nor a transfer coding is one no HTTP/1.1
    // server reads, and none reaches the rules behind it.
    let body = if headers.contains_key(axum::http::header::CONTENT_LENGTH)
        || headers.contains_key(axum::http::header::TRANSFER_ENCODING) { body } else { String::new() };
    Some(RequestContext {
        site_id: 0,
        site_name: "crs".into(),
        client_ip: "203.0.113.9".parse().ok()?,
        method: text("method").unwrap_or_else(|| "GET".into()),
        path,
        query,
        version,
        headers,
        body: bytes::Bytes::from(body),
    })
}

fn yaml_text(v: &Yaml) -> Option<String> {
    match v {
        Yaml::String(s) | Yaml::Real(s) => Some(s.clone()),
        Yaml::Integer(n) => Some(n.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

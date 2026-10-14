// =========================================================
// set_check.rs — EasyWAF
// `easywaf check-set`: a rule set loaded as installing it
// would load it, and run against requests it must leave
// alone.
//
//   easywaf check-set <set.rules.toml> [<ordinary.cases>]
//
// Every condition of every rule is compiled: a zone this
// version does not read, or a pattern Rust's regex will not
// take, is reported as
//
//   BROKEN <id> <why>
//
// With a cases file — the `pass` lines of the set-case
// format — every request in it is matched, and a rule that
// fires on one is reported as
//
//   FP <id> <line>
//
// followed by one summary line. Exit status 0 when nothing
// is reported, 1 when something is, 2 when the files could
// not be read. A job building sets from another project's
// rules drops what this reports and publishes the rest.
// =========================================================

use crate::modules::targets::{parse_zone, table_conditions, Parts, Target};
use crate::modules::waf::{reads, Whole};
use crate::modules::RequestContext;
use std::collections::BTreeSet;

pub fn run(args: &[String]) -> i32 {
    let (set, cases) = match args {
        [set] => (set, None),
        [set, cases] => (set, Some(cases)),
        _ => {
            eprintln!("usage: easywaf check-set <set.rules.toml> [<ordinary.cases>]");
            return 2;
        }
    };
    let text = match std::fs::read_to_string(set) {
        Ok(t) => t,
        Err(e) => { eprintln!("{set}: {e}"); return 2; }
    };
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => { eprintln!("{set}: {e}"); return 2; }
    };

    let mut rules: Vec<(i64, Vec<(Vec<Target>, regex::Regex, bool)>)> = Vec::new();
    let mut broken = 0;
    for r in table.get("rules").and_then(|r| r.as_array()).into_iter().flatten() {
        let id = r.get("id").and_then(|v| v.as_integer()).unwrap_or(0);
        let loaded = r.as_table().ok_or_else(|| "not a table".to_string()).and_then(|t| {
            table_conditions(t)?.into_iter().map(|(zone, pattern, negate)| {
                let targets = parse_zone(&zone).ok_or(format!("the zone {zone:?} is not one this version reads"))?;
                let re = regex::Regex::new(&pattern)
                    .map_err(|e| format!("a pattern does not compile: {}", e.to_string().lines().last().unwrap_or("").trim()))?;
                Ok((targets, re, negate))
            }).collect::<Result<Vec<_>, String>>()
        });
        match loaded {
            Ok(conds) => rules.push((id, conds)),
            Err(why) => { println!("BROKEN {id} {why}"); broken += 1; }
        }
    }

    let mut fired: BTreeSet<i64> = BTreeSet::new();
    let mut requests = 0;
    if let Some(cases) = cases {
        let text = match std::fs::read_to_string(cases) {
            Ok(t) => t,
            Err(e) => { eprintln!("{cases}: {e}"); return 2; }
        };
        for (n, line) in text.lines().enumerate() {
            let parts: Vec<&str> = line.splitn(3, '\t').collect();
            let [expect, arrives, sample] = parts[..] else { continue };
            if expect != "pass" || line.starts_with('#') {
                continue;
            }
            let ctx = match case_request(arrives, sample) {
                Ok(c) => c,
                Err(e) => { eprintln!("{cases}:{}: {e}", n + 1); return 2; }
            };
            requests += 1;
            let (whole, parts) = (Whole::of(&ctx, &ctx.body), Parts::new(&ctx, &ctx.body));
            for (id, conds) in &rules {
                if conds.iter().all(|(t, re, negate)| reads(t, &whole, &parts, re) != *negate) {
                    println!("FP {id} {}", n + 1);
                    fired.insert(*id);
                }
            }
        }
    }

    println!("{} rules, {broken} broken, {} firing on the {requests} ordinary requests", rules.len() + broken, fired.len());
    if broken > 0 || !fired.is_empty() { 1 } else { 0 }
}

/// The request a case describes. `URL` is a path and query; `BODY` a body,
/// sent as JSON when it starts like JSON and as a form otherwise; `HEADERS`
/// a header value, under a name no rule reads; `HEADER:Name` that header;
/// `COOKIE` a Cookie header; `METHOD` the method.
pub(crate) fn case_request(arrives: &str, text: &str) -> Result<RequestContext, String> {
    let mut headers = axum::http::HeaderMap::new();
    let mut bad = None;
    let mut put = |name: &str, value: &str| {
        match (axum::http::HeaderName::from_bytes(name.as_bytes()), axum::http::HeaderValue::from_str(value)) {
            (Ok(n), Ok(v)) => { headers.append(n, v); }
            _ => bad = Some(format!("{name}: {value:?} is not a header")),
        }
    };
    let (mut path, mut query, mut body, mut method) = ("/".to_string(), None, String::new(), "GET".to_string());
    match arrives {
        "URL" => {
            let (p, q) = text.split_once('?').map_or((text, None), |(p, q)| (p, Some(q)));
            path = p.to_string();
            query = q.map(str::to_string);
        }
        "BODY" => {
            let json = text.trim_start().starts_with(['{', '[']);
            put("content-type", if json { "application/json" } else { "application/x-www-form-urlencoded" });
            body = text.to_string();
            method = "POST".into();
        }
        "HEADERS" => put("x-case", text),
        "COOKIE" => put("cookie", text),
        "METHOD" => method = text.to_string(),
        other => match other.strip_prefix("HEADER:") {
            Some(name) => put(name, text),
            None => return Err(format!("{other:?} is not a way a case arrives")),
        },
    }
    if let Some(e) = bad {
        return Err(e);
    }
    Ok(RequestContext {
        site_id: 1,
        site_name: "cases".into(),
        client_ip: "203.0.113.9".parse().unwrap(),
        method,
        path,
        query,
        headers,
        body: bytes::Bytes::from(body),
    })
}

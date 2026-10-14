// =========================================================
// modules/targets.rs — EasyWAF
// Targeted zones: what a rule reads, one value at a time.
//
// The five zones a rule has always named — URL, ARGS, BODY,
// HEADERS, ANY — are each one block of text, built in
// waf.rs. The zones here name one part of a request, and a
// rule on them is matched against each value of that part
// on its own, so `^` and `$` mean the start and end of a
// value, as the rules written for ModSecurity assume.
//
// See docs/design/targeted-zones.md.
// =========================================================

use super::waf::{normalised_paths, percent_decode, zone_text};
use super::RequestContext;
use std::cell::OnceCell;

/// The most arguments, and separately the most cookies, read from one request.
/// Beyond it a value is not read on its own; it is still in the whole-text
/// zones, so a rule there sees it.
pub const MAX_VALUES: usize = 1024;

/// The longest name a targeted zone accepts after its colon.
const MAX_NAME: usize = 128;

/// A condition a rule adds to its first: a zone and a pattern, and whether it
/// holds when the pattern matches nothing instead. As a set file and the
/// database's `conditions` column write it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub zone:    String,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub negate:  bool,
}

/// The conditions stored in a rule's `conditions` column. `None` for text that
/// is not a list of them, which a rule is not run with.
pub fn read_conditions(json: &str) -> Option<Vec<Condition>> {
    if json.trim().is_empty() {
        return Some(Vec::new());
    }
    serde_json::from_str(json).ok()
}

/// A rule's conditions from a set file's TOML table — its zone and pattern
/// first, then each of `and` — as (zone, pattern, negate). `Err` names what is
/// missing.
pub fn table_conditions(rule: &toml::Table) -> Result<Vec<(String, String, bool)>, String> {
    let text = |t: &toml::Table, k: &str| t.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let flag = |t: &toml::Table| t.get("negate").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut out = vec![(
        text(rule, "zone").unwrap_or_else(|| "ANY".into()),
        text(rule, "pattern").ok_or("a rule without a pattern")?,
        flag(rule),
    )];
    for c in rule.get("and").and_then(|v| v.as_array()).into_iter().flatten() {
        let c = c.as_table().ok_or("a condition that is not a table")?;
        out.push((
            text(c, "zone").ok_or("a condition without a zone")?,
            text(c, "pattern").ok_or("a condition without a pattern")?,
            flag(c),
        ));
    }
    Ok(out)
}

/// One part of a request a rule reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    // The five whole-text zones.
    Url,
    Args,
    Body,
    Headers,
    Any,
    // One value at a time.
    Path,
    /// Argument values; with a name, those of arguments called that. Names
    /// are held lowercased and compared that way.
    Arg(Option<String>),
    ArgName,
    Header(Option<String>),
    HeaderName,
    Cookie(Option<String>),
    CookieName,
    Method,
}

/// A zone as a rule writes it — one zone, or several joined by `|` — as the
/// parts it reads. `None` when any part is not a zone this version reads: a
/// rule written for a newer EasyWAF is not run rather than read as `ANY`.
pub fn parse_zone(zone: &str) -> Option<Vec<Target>> {
    let mut out: Vec<Target> = Vec::new();
    for part in zone.split('|') {
        let part = part.trim();
        let (kind, name) = match part.split_once(':') {
            Some((kind, name)) => (kind.trim(), Some(name.trim())),
            None => (part, None),
        };
        let kind = kind.to_ascii_uppercase();
        let target = match (kind.as_str(), name) {
            ("URL", None)         => Target::Url,
            ("ARGS", None)        => Target::Args,
            ("BODY", None)        => Target::Body,
            ("HEADERS", None)     => Target::Headers,
            ("ANY", None)         => Target::Any,
            ("PATH", None)        => Target::Path,
            ("ARG_NAME", None)    => Target::ArgName,
            ("HEADER_NAME", None) => Target::HeaderName,
            ("COOKIE_NAME", None) => Target::CookieName,
            ("METHOD", None)      => Target::Method,
            ("ARG", name)         => Target::Arg(named(name, false)?),
            ("HEADER", name)      => Target::Header(named(name, true)?),
            ("COOKIE", name)      => Target::Cookie(named(name, false)?),
            _ => return None,
        };
        if !out.contains(&target) {
            out.push(target);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The name after a zone's colon, lowercased; `Some(None)` for no colon, and
/// `None` for a name that cannot be one. A header's name has to be an HTTP
/// token; an argument's or a cookie's anything without spaces or a `|`.
fn named(name: Option<&str>, header: bool) -> Option<Option<String>> {
    let Some(name) = name else { return Some(None) };
    let fits = !name.is_empty()
        && name.chars().count() <= MAX_NAME
        && !name.chars().any(|c| c.is_whitespace() || c.is_control() || c == '|')
        && (!header || axum::http::HeaderName::from_bytes(name.as_bytes()).is_ok());
    fits.then(|| Some(name.to_lowercase()))
}

/// A zone written the way the interface and an export show it: kinds in
/// capitals, a name as it was typed. `None` for one that is not a zone.
pub fn canonical(zone: &str) -> Option<String> {
    parse_zone(zone)?;
    Some(
        zone.split('|')
            .map(|part| match part.trim().split_once(':') {
                Some((kind, name)) => format!("{}:{}", kind.trim().to_ascii_uppercase(), name.trim()),
                None => part.trim().to_ascii_uppercase(),
            })
            .collect::<Vec<_>>()
            .join("|"),
    )
}

// ─── A request, a value at a time ───────────────────────

/// A name, and the forms its value is matched in.
struct Value {
    /// Decoded and lowercased, for comparing with a zone's name.
    key:   String,
    /// The name's own forms, for `*_NAME` zones.
    name:  Vec<String>,
    value: Vec<String>,
}

/// The parts of one request the targeted zones read, each built the first
/// time a rule asks for it and not again. A policy whose rules read none of
/// them builds none.
pub struct Parts<'a> {
    ctx:     &'a RequestContext,
    /// The body as inspected: inflated when it arrived compressed.
    body:    &'a [u8],
    path:    OnceCell<Vec<String>>,
    args:    OnceCell<Vec<Value>>,
    headers: OnceCell<Vec<Value>>,
    cookies: OnceCell<Vec<Value>>,
}

impl<'a> Parts<'a> {
    pub fn new(ctx: &'a RequestContext, body: &'a [u8]) -> Self {
        Parts {
            ctx,
            body,
            path: OnceCell::new(),
            args: OnceCell::new(),
            headers: OnceCell::new(),
            cookies: OnceCell::new(),
        }
    }

    /// Whether `is_match` holds for any form of any value `target` reads.
    /// Only for the targeted zones; the whole-text ones are the caller's.
    pub fn any(&self, target: &Target, is_match: &dyn Fn(&str) -> bool) -> bool {
        let values = |list: &[Value], name: &Option<String>| {
            list.iter()
                .filter(|v| name.as_ref().is_none_or(|n| &v.key == n))
                .any(|v| v.value.iter().any(|f| is_match(f)))
        };
        let names = |list: &[Value]| list.iter().any(|v| v.name.iter().any(|f| is_match(f)));
        match target {
            Target::Path        => self.path().iter().any(|f| is_match(f)),
            Target::Arg(name)   => values(self.args(), name),
            Target::ArgName     => names(self.args()),
            Target::Header(name) => values(self.headers(), name),
            Target::HeaderName  => names(self.headers()),
            Target::Cookie(name) => values(self.cookies(), name),
            Target::CookieName  => names(self.cookies()),
            Target::Method      => is_match(&self.ctx.method),
            Target::Url | Target::Args | Target::Body | Target::Headers | Target::Any => false,
        }
    }

    /// The path alone, raw and decoded, and as a backend reads it. `+` is a
    /// literal in a path, not a space.
    fn path(&self) -> &[String] {
        self.path.get_or_init(|| {
            let mut forms = zone_text(&self.ctx.path, false);
            for read in normalised_paths(&self.ctx.path) {
                for form in zone_text(&read, false) {
                    if !forms.contains(&form) {
                        forms.push(form);
                    }
                }
            }
            forms
        })
    }

    /// The arguments: the query string's, then a form or JSON body's.
    fn args(&self) -> &[Value] {
        self.args.get_or_init(|| {
            let mut out = Vec::new();
            if let Some(q) = self.ctx.query.as_deref() {
                pairs(q, &mut out);
            }
            match body_kind(&self.ctx.headers) {
                Some(BodyKind::Form) => pairs(&String::from_utf8_lossy(self.body), &mut out),
                Some(BodyKind::Json) => json(self.body, &mut out),
                None => {}
            }
            out
        })
    }

    /// Every header, each value on its own. Names come lowercased from the
    /// header map, which is how HTTP compares them.
    fn headers(&self) -> &[Value] {
        self.headers.get_or_init(|| {
            self.ctx.headers.iter()
                .map(|(name, value)| Value {
                    key:   name.as_str().to_string(),
                    name:  vec![name.as_str().to_string()],
                    value: zone_text(&String::from_utf8_lossy(value.as_bytes()), false),
                })
                .collect()
        })
    }

    /// The cookies, from every `Cookie` header, split on `;` and then on the
    /// first `=`. A cookie's value is often percent-encoded, and is decoded
    /// as a value; `+` stays a `+`.
    fn cookies(&self) -> &[Value] {
        self.cookies.get_or_init(|| {
            let mut out = Vec::new();
            for header in self.ctx.headers.get_all(axum::http::header::COOKIE) {
                for pair in String::from_utf8_lossy(header.as_bytes()).split(';') {
                    if out.len() >= MAX_VALUES {
                        return out;
                    }
                    let pair = pair.trim();
                    if pair.is_empty() {
                        continue;
                    }
                    let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                    out.push(Value {
                        key:   percent_decode(name.trim()).to_lowercase(),
                        name:  zone_text(name.trim(), false),
                        value: zone_text(value.trim(), false),
                    });
                }
            }
            out
        })
    }
}

enum BodyKind {
    Form,
    Json,
}

/// How a body's arguments are written, by its `Content-Type`. Anything else —
/// multipart, XML, plain text, none at all — has no arguments here, and is
/// read as a whole by `BODY`.
fn body_kind(headers: &axum::http::HeaderMap) -> Option<BodyKind> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE)?.to_str().ok()?;
    let mime = ct.split(';').next()?.trim().to_ascii_lowercase();
    if mime == "application/x-www-form-urlencoded" {
        Some(BodyKind::Form)
    } else if mime == "application/json" || mime.ends_with("+json") {
        Some(BodyKind::Json)
    } else {
        None
    }
}

/// `a=1&b=2` into arguments. Split on `&` and the first `=` before anything is
/// decoded, so an encoded `&` or `=` inside a value stays in it.
fn pairs(text: &str, out: &mut Vec<Value>) {
    for pair in text.split('&') {
        if out.len() >= MAX_VALUES {
            return;
        }
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.push(Value {
            key:   percent_decode(&name.replace('+', " ")).to_lowercase(),
            name:  zone_text(name, true),
            value: zone_text(value, true),
        });
    }
}

/// A JSON body's leaves as arguments, each named by its own key; an array's
/// elements by the array's. Keys are names too. A body that does not parse —
/// cut off at the inspection limit, or not JSON at all — gives none.
fn json(body: &[u8], out: &mut Vec<Value>) {
    use serde_json::Value as J;
    let Ok(root) = serde_json::from_slice::<J>(body) else { return };
    let mut stack: Vec<(String, &J)> = vec![(String::new(), &root)];
    while let Some((key, node)) = stack.pop() {
        if out.len() >= MAX_VALUES {
            return;
        }
        let leaf = |text: String| Value {
            key:   key.to_lowercase(),
            name:  zone_text(&key, false),
            value: zone_text(&text, false),
        };
        match node {
            J::Object(map) => {
                // Pushed in reverse so they come off the stack in order.
                for (k, v) in map.iter().rev() {
                    stack.push((k.clone(), v));
                }
                // A key holding an object or an array is a name with no value
                // of its own; its leaves are named by their own keys.
                for (k, v) in map {
                    if v.is_object() || v.is_array() {
                        out.push(Value { key: k.to_lowercase(), name: zone_text(k, false), value: Vec::new() });
                    }
                }
            }
            J::Array(items) => {
                for v in items.iter().rev() {
                    stack.push((key.clone(), v));
                }
            }
            J::String(s) => out.push(leaf(s.clone())),
            J::Number(n) => out.push(leaf(n.to_string())),
            J::Bool(b)   => out.push(leaf(b.to_string())),
            J::Null      => {}
        }
    }
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(path: &str, query: Option<&str>, headers: &[(&str, &str)], body: &str) -> RequestContext {
        let mut map = axum::http::HeaderMap::new();
        for (k, v) in headers {
            map.append(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        RequestContext {
            site_id: 1,
            site_name: "t".into(),
            client_ip: "203.0.113.9".parse().unwrap(),
            method: "POST".into(),
            path: path.into(),
            query: query.map(str::to_string),
            headers: map,
            body: bytes::Bytes::from(body.to_string()),
        }
    }

    fn hits(parts: &Parts, zone: &str, pattern: &str) -> bool {
        let re = regex::Regex::new(pattern).unwrap();
        parse_zone(zone).unwrap().iter().any(|t| parts.any(t, &|s| re.is_match(s)))
    }

    #[test]
    fn the_five_zones_parse_as_before_and_the_new_ones_alongside() {
        assert_eq!(parse_zone("ANY"), Some(vec![Target::Any]));
        assert_eq!(parse_zone("headers"), Some(vec![Target::Headers]));
        assert_eq!(parse_zone("HEADER:User-Agent"), Some(vec![Target::Header(Some("user-agent".into()))]));
        assert_eq!(parse_zone("ARG|ARG_NAME|COOKIE"),
                   Some(vec![Target::Arg(None), Target::ArgName, Target::Cookie(None)]));
        assert_eq!(parse_zone("ARG:id|ARG:ID"), Some(vec![Target::Arg(Some("id".into()))]));
        assert_eq!(canonical("arg:id | header:X-Token"), Some("ARG:id|HEADER:X-Token".into()));
    }

    /// A zone this version does not read is refused, not read as ANY.
    #[test]
    fn a_zone_this_version_does_not_know_is_refused() {
        for z in ["", "QUERY", "XML:/*", "HEADER:", "HEADER:bad name", "ARG:a|b", "URL:x", "ANY|FILES", "ARG:x y"] {
            assert_eq!(parse_zone(z), None, "{z:?} should not parse");
        }
    }

    #[test]
    fn an_anchor_is_the_start_of_one_value() {
        let c = ctx("/x", Some("a=1&url=http%3A%2F%2Fevil%2Fx%3F"), &[], "");
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "ARG", r"^https?://.*\?$"));
        assert!(hits(&p, "ARG:url", r"^https?://"));
        assert!(!hits(&p, "ARG:a", r"^https?://"));
        assert!(hits(&p, "ARG_NAME", r"^url$"));
    }

    #[test]
    fn an_encoded_ampersand_stays_inside_its_value() {
        let c = ctx("/x", Some("q=a%26b%3Dc"), &[], "");
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "ARG:q", r"^a&b=c$"));
        assert!(!hits(&p, "ARG_NAME", r"^b$"));
    }

    #[test]
    fn a_form_body_and_a_json_body_have_arguments_too() {
        let form = ctx("/x", None, &[("content-type", "application/x-www-form-urlencoded; charset=utf-8")],
                       "user=alice&comment=hello+world");
        let p = Parts::new(&form, form.body.as_ref());
        assert!(hits(&p, "ARG:comment", r"^hello world$"));

        let body = r#"{"user": {"Password": "x' OR 1=1"}, "tags": ["a", "<script>"], "n": 5, "ok": true}"#;
        let j = ctx("/x", None, &[("content-type", "application/vnd.api+json")], body);
        let p = Parts::new(&j, j.body.as_ref());
        assert!(hits(&p, "ARG:password", r"OR 1=1"), "a nested key is the argument's name, without regard to case");
        assert!(hits(&p, "ARG:tags", r"^<script>$"), "an array's elements are named by its key");
        assert!(hits(&p, "ARG:n", r"^5$") && hits(&p, "ARG:ok", r"^true$"));
        assert!(hits(&p, "ARG_NAME", r"^user$"));
    }

    #[test]
    fn a_body_of_another_kind_or_cut_short_has_no_arguments() {
        for (ct, body) in [("multipart/form-data; boundary=x", "a=1"), ("text/plain", "a=1"),
                           ("application/json", r#"{"a": "1"#)] {
            let c = ctx("/x", None, &[("content-type", ct)], body);
            let p = Parts::new(&c, c.body.as_ref());
            assert!(!hits(&p, "ARG", "1"), "{ct}: {body}");
        }
    }

    #[test]
    fn one_header_is_read_without_the_others() {
        let c = ctx("/x", None, &[("user-agent", "Mozilla/5.0"), ("referer", "https://x/?q=sqlmap")], "");
        let p = Parts::new(&c, b"");
        assert!(!hits(&p, "HEADER:User-Agent", "sqlmap"));
        assert!(hits(&p, "HEADER:referer", "sqlmap"));
        assert!(hits(&p, "HEADER", "^Mozilla"));
        assert!(hits(&p, "HEADER_NAME", "^referer$"));
    }

    #[test]
    fn cookies_are_split_into_names_and_values() {
        let c = ctx("/x", None, &[("cookie", "session=abc; Theme=dark%20blue"), ("cookie", "x=1")], "");
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "COOKIE:theme", "^dark blue$"));
        assert!(hits(&p, "COOKIE:x", "^1$"));
        assert!(hits(&p, "COOKIE_NAME", "^session$"));
        assert!(!hits(&p, "COOKIE:session", "dark"));
    }

    #[test]
    fn the_path_is_read_without_its_query_and_as_a_backend_reads_it() {
        let c = ctx("/a/b/../../.env", Some("x=1"), &[], "");
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "PATH", r"^/\.env$"));
        assert!(!hits(&p, "PATH", "x=1"));
        assert!(hits(&p, "METHOD", "^POST$"));
    }

    #[test]
    fn no_more_than_the_limit_of_arguments_is_read() {
        let query: String = (0..MAX_VALUES + 10).map(|i| format!("a{i}=v{i}&")).collect();
        let c = ctx("/x", Some(&query), &[], "");
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "ARG", &format!("^v{}$", MAX_VALUES - 1)));
        assert!(!hits(&p, "ARG", &format!("^v{}$", MAX_VALUES)));
    }
}

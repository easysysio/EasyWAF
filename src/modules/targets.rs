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

use super::transforms::{apply_all, parse_list, Transform};
use super::waf::{normalised_paths, percent_decode, reads, zone_text, Whole};
use super::RequestContext;
use std::cell::{OnceCell, RefCell};
use std::rc::Rc;

/// The most arguments, and separately the most cookies, read from one request.
/// Beyond it a value is not read on its own; it is still in the whole-text
/// zones, so a rule there sees it.
pub const MAX_VALUES: usize = 1024;

/// The longest name a targeted zone accepts after its colon.
const MAX_NAME: usize = 128;

/// A condition: a zone and a pattern, whether it holds when the pattern
/// matches nothing instead, and the decodings its values are matched after.
/// As a set file and the database's `conditions` column write it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub zone:    String,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub negate:  bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transforms: Vec<String>,
}

/// Decodings as the database's `transforms` column holds them: names joined
/// with commas, none for the empty string.
pub fn transforms_from_column(text: &str) -> Vec<String> {
    text.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
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
/// first, then each of `and`. `Err` names what is missing.
pub fn table_conditions(rule: &toml::Table) -> Result<Vec<Condition>, String> {
    let text = |t: &toml::Table, k: &str| t.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let flag = |t: &toml::Table| t.get("negate").and_then(|v| v.as_bool()).unwrap_or(false);
    let decodings = |t: &toml::Table| -> Result<Vec<String>, String> {
        match t.get("transforms") {
            None => Ok(Vec::new()),
            Some(v) => v.as_array()
                .and_then(|a| a.iter().map(|n| n.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
                .ok_or_else(|| "transforms that are not a list of names".to_string()),
        }
    };
    let mut out = vec![Condition {
        zone:       text(rule, "zone").unwrap_or_else(|| "ANY".into()),
        pattern:    text(rule, "pattern").ok_or("a rule without a pattern")?,
        negate:     flag(rule),
        transforms: decodings(rule)?,
    }];
    for c in rule.get("and").and_then(|v| v.as_array()).into_iter().flatten() {
        let c = c.as_table().ok_or("a condition that is not a table")?;
        out.push(Condition {
            zone:       text(c, "zone").ok_or("a condition without a zone")?,
            pattern:    text(c, "pattern").ok_or("a condition without a pattern")?,
            negate:     flag(c),
            transforms: decodings(c)?,
        });
    }
    Ok(out)
}

/// A condition ready to match: what it reads, its pattern, whether it is
/// negated, and the decodings applied first.
pub struct CompiledCondition {
    pub targets: Vec<Target>,
    pub re:      regex::Regex,
    pub negate:  bool,
    pub chain:   Vec<Transform>,
}

impl CompiledCondition {
    /// `Err` says why the condition cannot be run by this version. A list the
    /// pattern names is read as its default; see `with_values`.
    pub fn new(c: &Condition) -> Result<Self, String> {
        Self::with_values(c, &super::values::defaults())
    }

    /// As `new`, with the lists a policy sets.
    pub fn with_values(c: &Condition, values: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let targets = parse_zone(&c.zone).ok_or(format!("the zone {:?} is not one this version reads", c.zone))?;
        let chain = parse_list(&c.transforms)
            .map_err(|name| format!("the decoding {name:?} is not one this version applies"))?;
        let pattern = super::values::substitute(&c.pattern, values)
            .map_err(|name| format!("the list {name:?} is not one this version knows"))?;
        let re = regex::Regex::new(&pattern)
            .map_err(|e| format!("a pattern does not compile: {}", e.to_string().lines().last().unwrap_or("").trim()))?;
        Ok(CompiledCondition { targets, re, negate: c.negate, chain })
    }

    pub fn holds(&self, whole: &Whole, parts: &Parts) -> bool {
        reads(&self.targets, whole, parts, &self.re, &self.chain) != self.negate
    }
}

/// A rule's conditions, each compiled.
pub type Compiled = Vec<CompiledCondition>;

/// One part of a request a rule reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// An XML body's text, as XPath's `/*` reads it: the whole document's.
    Xml,
    /// Each attribute's value in an XML body.
    XmlAttr,
    /// Each file's name in a `multipart/form-data` upload.
    FileName,
    /// The headers as one block of lines, `Name: value\r\n` each.
    HeaderBlock,
    /// `GET /path?query HTTP/1.1`, without its line break.
    RequestLine,
    /// `HTTP/1.1`.
    Protocol,
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
            ("XML", None)         => Target::Xml,
            ("XML_ATTR", None)    => Target::XmlAttr,
            ("FILE_NAME", None)   => Target::FileName,
            ("HEADER_BLOCK", None) => Target::HeaderBlock,
            ("REQUEST_LINE", None) => Target::RequestLine,
            ("PROTOCOL", None)    => Target::Protocol,
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
#[derive(Clone)]
struct Value {
    /// Decoded and lowercased, for comparing with a zone's name.
    key:   String,
    /// The name's own forms, for `*_NAME` zones.
    name:  Vec<String>,
    value: Vec<String>,
}

/// A zone, a chain of decodings, and the forms the zone is read in with them
/// applied.
type Decoded = (Target, Vec<Transform>, Rc<Vec<String>>);

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
    /// An XML body's text, and its attributes' values.
    xml:     OnceCell<(Vec<String>, Vec<Value>)>,
    /// A multipart body's fields, and its files' names.
    parts:   OnceCell<(Vec<Value>, Vec<Value>)>,
    block:   OnceCell<Vec<String>>,
    line:    OnceCell<Vec<String>>,
    /// The forms a zone is read in with a chain of decodings applied, made
    /// once for each zone and chain however many rules ask. A list: a request
    /// meets a few dozen pairs, and comparing in place costs no allocation.
    decoded: RefCell<Vec<Decoded>>,
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
            xml: OnceCell::new(),
            parts: OnceCell::new(),
            block: OnceCell::new(),
            line: OnceCell::new(),
            decoded: RefCell::new(Vec::new()),
        }
    }

    /// Each of `forms` — what `target` is read in — with `chain` applied,
    /// from the cache when a rule has asked for the pair already.
    pub fn decoded(&self, target: &Target, chain: &[Transform], forms: impl FnOnce() -> Vec<String>) -> Rc<Vec<String>> {
        if let Some((_, _, found)) = self.decoded.borrow().iter().find(|(t, c, _)| t == target && c == chain) {
            return found.clone();
        }
        let made: Rc<Vec<String>> = Rc::new(forms().iter().flat_map(|f| apply_all(chain, f)).collect());
        self.decoded.borrow_mut().push((target.clone(), chain.to_vec(), made.clone()));
        made
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
            Target::Xml         => self.xml().0.iter().any(|f| is_match(f)),
            Target::XmlAttr     => values(&self.xml().1, &None),
            Target::FileName    => values(&self.multipart().1, &None),
            Target::HeaderBlock => self.header_block().iter().any(|f| is_match(f)),
            Target::RequestLine => self.request_line().iter().any(|f| is_match(f)),
            Target::Protocol    => is_match(protocol(self.ctx.version)),
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
                Some(BodyKind::Json) => {
                    if !json(self.body, &mut out) {
                        whole_body(self.body, &mut out);
                    }
                }
                Some(BodyKind::Multipart(_)) => {
                    for field in &self.multipart().0 {
                        if out.len() >= MAX_VALUES {
                            break;
                        }
                        out.push(field.clone());
                    }
                }
                Some(BodyKind::Xml) | None => {}
            }
            out
        })
    }

    /// An XML body as XPath reads it: the document's text, and each attribute's
    /// value. A body that says it is XML and does not parse — cut off at the
    /// inspection limit, or written so that a parser gives up — is read whole as
    /// its text, so a malformed document cannot hide what is in it.
    fn xml(&self) -> &(Vec<String>, Vec<Value>) {
        self.xml.get_or_init(|| {
            if !matches!(body_kind(&self.ctx.headers), Some(BodyKind::Xml)) {
                return (Vec::new(), Vec::new());
            }
            let text = String::from_utf8_lossy(self.body);
            let options = roxmltree::ParsingOptions { allow_dtd: true, nodes_limit: 100_000, ..Default::default() };
            match roxmltree::Document::parse_with_options(&text, options) {
                Ok(doc) => {
                    let all: String = doc.descendants().filter(|n| n.is_text()).filter_map(|n| n.text()).collect();
                    let mut attrs = Vec::new();
                    for node in doc.descendants().filter(|n| n.is_element()) {
                        for a in node.attributes() {
                            if attrs.len() >= MAX_VALUES {
                                break;
                            }
                            attrs.push(Value {
                                key:   a.name().to_lowercase(),
                                name:  vec![a.name().to_string()],
                                value: zone_text(a.value(), false),
                            });
                        }
                    }
                    (zone_text(&all, false), attrs)
                }
                Err(_) => (zone_text(&text, false), Vec::new()),
            }
        })
    }

    /// A `multipart/form-data` body's fields, as arguments, and its files'
    /// names. One whose parts cannot be found is read whole, as one field.
    fn multipart(&self) -> &(Vec<Value>, Vec<Value>) {
        self.parts.get_or_init(|| {
            let Some(BodyKind::Multipart(boundary)) = body_kind(&self.ctx.headers) else {
                return (Vec::new(), Vec::new());
            };
            match multipart(self.body, &boundary) {
                Some(found) => found,
                None => {
                    let mut whole = Vec::new();
                    whole_body(self.body, &mut whole);
                    (whole, Vec::new())
                }
            }
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

    /// The headers as the lines of a request's header block, in the order
    /// their names first arrived; a repeated header has a line for each value,
    /// together after its first. The header map holds names
    /// lowercased, as HTTP/2 sends them; they are written as HTTP/1.1 clients
    /// do, `User-Agent`, which is how the rules written for header blocks
    /// spell them. The block has no blank line at its end.
    fn header_block(&self) -> &[String] {
        self.block.get_or_init(|| {
            let mut block = String::new();
            for (name, value) in self.ctx.headers.iter() {
                block.push_str(&header_case(name.as_str()));
                block.push_str(": ");
                block.push_str(&String::from_utf8_lossy(value.as_bytes()));
                block.push_str("\r\n");
            }
            zone_text(&block, false)
        })
    }

    /// The request line: the method, the path and query as they arrived, and
    /// the protocol. A request over HTTP/2 or HTTP/3 has none on the wire; it
    /// is written as HTTP/1.1 would have sent it.
    fn request_line(&self) -> &[String] {
        self.line.get_or_init(|| {
            let ctx = self.ctx;
            let query = ctx.query.as_deref().map(|q| format!("?{q}")).unwrap_or_default();
            zone_text(&format!("{} {}{query} {}", ctx.method, ctx.path, protocol(ctx.version)), false)
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

/// A protocol as a request line names it.
fn protocol(version: axum::http::Version) -> &'static str {
    use axum::http::Version;
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2  => "HTTP/2.0",
        Version::HTTP_3  => "HTTP/3.0",
        _                => "HTTP/1.1",
    }
}

/// A header's name with each word capitalised: `user-agent` as `User-Agent`.
fn header_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut start = true;
    for c in name.chars() {
        out.push(if start { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() });
        start = c == '-';
    }
    out
}

enum BodyKind {
    Form,
    Json,
    Xml,
    /// With its boundary.
    Multipart(String),
}

/// How a body is written, by its `Content-Type`. Anything else — plain text,
/// none at all — has no arguments here, and is read as a whole by `BODY`.
fn body_kind(headers: &axum::http::HeaderMap) -> Option<BodyKind> {
    let ct = headers.get(axum::http::header::CONTENT_TYPE)?.to_str().ok()?;
    let mime = ct.split(';').next()?.trim().to_ascii_lowercase();
    if mime == "application/x-www-form-urlencoded" {
        Some(BodyKind::Form)
    } else if mime == "application/json" || mime.ends_with("+json") {
        Some(BodyKind::Json)
    } else if mime.ends_with("/xml") || mime.ends_with("+xml") {
        Some(BodyKind::Xml)
    } else if mime == "multipart/form-data" {
        // A multipart body without a boundary cannot be split; read whole.
        let boundary = ct.split(';').skip(1)
            .filter_map(|p| p.trim().split_once('='))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("boundary"))
            .map(|(_, v)| v.trim().trim_matches('"').to_string())
            .unwrap_or_default();
        Some(BodyKind::Multipart(boundary))
    } else {
        None
    }
}

/// A body read whole, as one argument with no name: what the rules are shown
/// of a body that says how it is written and cannot be read that way.
fn whole_body(body: &[u8], out: &mut Vec<Value>) {
    if !body.is_empty() {
        out.push(Value { key: String::new(), name: Vec::new(), value: zone_text(&String::from_utf8_lossy(body), true) });
    }
}

/// A multipart body's parts: each field's name and value, and each file's
/// field name and file name, from its `Content-Disposition`. `None` when the
/// boundary is not in the body. A file's content is not a value here; `BODY`
/// reads it as it arrived.
fn multipart(body: &[u8], boundary: &str) -> Option<(Vec<Value>, Vec<Value>)> {
    if boundary.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(body);
    let delimiter = format!("--{boundary}");
    let mut sections = text.split(delimiter.as_str());
    sections.next()?;                      // the preamble, before the first
    let (mut fields, mut files) = (Vec::new(), Vec::new());
    let mut found = false;
    for section in sections {
        if section.starts_with("--") {
            break;                         // the closing delimiter
        }
        found = true;
        let section = section.strip_prefix("\r\n").or_else(|| section.strip_prefix('\n')).unwrap_or(section);
        let (head, content) = section.split_once("\r\n\r\n")
            .or_else(|| section.split_once("\n\n"))
            .unwrap_or((section, ""));
        let content = content.strip_suffix("\r\n").or_else(|| content.strip_suffix('\n')).unwrap_or(content);
        let disposition = head.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-disposition:"))
            .unwrap_or("");
        let param = |want: &str| -> Option<String> {
            disposition.split(';').skip(1).find_map(|p| {
                let (k, v) = p.trim().split_once('=')?;
                k.trim().eq_ignore_ascii_case(want).then(|| v.trim().trim_matches('"').to_string())
            })
        };
        let name = param("name").unwrap_or_default();
        match param("filename") {
            Some(file) => {
                if files.len() < MAX_VALUES {
                    files.push(Value { key: name.to_lowercase(), name: zone_text(&name, false), value: zone_text(&file, false) });
                }
                // A file's field is an argument's name, without a value.
                if fields.len() < MAX_VALUES {
                    fields.push(Value { key: name.to_lowercase(), name: zone_text(&name, false), value: Vec::new() });
                }
            }
            None => {
                if fields.len() < MAX_VALUES {
                    fields.push(Value { key: name.to_lowercase(), name: zone_text(&name, false), value: zone_text(content, false) });
                }
            }
        }
    }
    found.then_some((fields, files))
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
/// elements by the array's. Keys are names too. False for a body that does not
/// parse — cut off at the inspection limit, or not JSON at all — which the
/// caller reads whole instead.
fn json(body: &[u8], out: &mut Vec<Value>) -> bool {
    use serde_json::Value as J;
    let Ok(root) = serde_json::from_slice::<J>(body) else { return false };
    let mut stack: Vec<(String, &J)> = vec![(String::new(), &root)];
    while let Some((key, node)) = stack.pop() {
        if out.len() >= MAX_VALUES {
            return true;
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
    true
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
            version: axum::http::Version::HTTP_11,
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

    #[test]
    fn the_header_block_is_its_lines_with_names_as_clients_write_them() {
        let c = ctx("/", None, &[("user-agent", "curl/8.5"), ("x-forwarded-for", "10.0.0.1"),
                                 ("accept", "*/*"), ("x-forwarded-for", "10.0.0.2")], "");
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "header_block", "^User-Agent: curl/8\\.5\r\nX-Forwarded-For: 10\\.0\\.0\\.1\r\nX-Forwarded-For: 10\\.0\\.0\\.2\r\nAccept: \\*/\\*\r\n$"));
        assert!(hits(&p, "HEADER_BLOCK", "(?m)^Accept: "));
        assert!(!hits(&p, "HEADER_BLOCK", "user-agent"));
    }

    /// A condition naming decodings is matched against each value with them
    /// applied, and not against the value as it is.
    #[test]
    fn a_condition_is_matched_after_its_decodings() {
        let c = ctx("/run", Some("cmd=c%27a%27t+/etc/pass%22%22wd&q=UNION/**/SELECT"), &[], "");
        let (whole, parts) = (Whole::of(&c, b""), Parts::new(&c, b""));
        let cond = |zone: &str, pattern: &str, negate: bool, transforms: &[&str]| {
            CompiledCondition::new(&Condition {
                zone: zone.into(), pattern: pattern.into(), negate,
                transforms: transforms.iter().map(|t| t.to_string()).collect(),
            }).unwrap().holds(&whole, &parts)
        };
        assert!(cond("ARG", "cat/etc/passwd", false, &["cmdLine"]));
        assert!(!cond("ARG", "cat/etc/passwd", false, &[]), "matched without the decoding");
        assert!(cond("ARGS", "cat/etc/passwd", false, &["cmdLine"]), "a whole-text zone is decoded too");
        assert!(cond("ARG:q", "^UNION SELECT$", false, &["replaceComments"]));
        assert!(!cond("ARG:q", "\\*", false, &["replaceComments"]), "a decoded form still has the comment");
        assert!(cond("ARG:q", "\\*", true, &["replaceComments"]), "negated: no decoded form matches");
        assert!(CompiledCondition::new(&Condition {
            zone: "ARG".into(), pattern: "x".into(), negate: false, transforms: vec!["rot13".into()],
        }).is_err(), "an unknown decoding compiled");
    }

    #[test]
    fn the_request_line_is_as_it_arrived_and_the_protocol_on_its_own() {
        let mut c = ctx("/api/../keys", Some("x=%3b"), &[], "");
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "REQUEST_LINE", "^POST /api/\\.\\./keys\\?x=%3b HTTP/1\\.1$"));
        assert!(hits(&p, "REQUEST_LINE", "\\?x=; "));
        assert!(hits(&p, "PROTOCOL", "^HTTP/1\\.1$"));
        c.version = axum::http::Version::HTTP_2;
        c.query = None;
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "REQUEST_LINE", "^POST /api/\\.\\./keys HTTP/2\\.0$"));
        assert!(hits(&p, "protocol", "^HTTP/2\\.0$"));
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
    fn a_body_of_no_kind_that_has_arguments_has_none() {
        for (ct, body) in [("text/plain", "a=1"), ("application/octet-stream", "a=1")] {
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

    fn body(ct: &str, body: &str) -> RequestContext {
        ctx("/x", None, &[("content-type", ct)], body)
    }

    #[test]
    fn an_xml_body_is_read_as_its_text_and_its_attributes() {
        let c = body("application/soap+xml; charset=utf-8",
                     r#"<?xml version="1.0"?><e:Envelope xmlns:e="x"><user id="1' OR '1'='1">alice</user><q>UNION SELECT</q></e:Envelope>"#);
        let p = Parts::new(&c, c.body.as_ref());
        assert!(hits(&p, "XML", "aliceUNION SELECT"), "the document's text, as XPath's /* reads it");
        assert!(hits(&p, "XML_ATTR", "^1' OR '1'='1$"));
        assert!(!hits(&p, "XML_ATTR", "alice"));
        assert!(!hits(&p, "ARG", "UNION"), "XML is not arguments, as ModSecurity's is not");
    }

    #[test]
    fn an_xml_body_with_a_dtd_is_read_without_fetching_or_exploding_it() {
        // An internal entity is expanded, as a parser behind would.
        let c = body("text/xml", r#"<!DOCTYPE a [<!ENTITY x "UNION SELECT">]><a>&x;</a>"#);
        let p = Parts::new(&c, c.body.as_ref());
        assert!(hits(&p, "XML", "^UNION SELECT$"));
        // An external one is not fetched, and a billion laughs is refused:
        // either way the body is read whole, payload and all.
        for xxe in [r#"<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>"#,
                    r#"<!DOCTYPE a [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;"><!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;">]><a>&e;</a>"#] {
            let c = body("application/xml", xxe);
            let p = Parts::new(&c, c.body.as_ref());
            assert!(hits(&p, "XML", "<!ENTITY"), "{xxe}");
        }
    }

    #[test]
    fn a_body_that_does_not_parse_is_read_whole() {
        let c = body("application/xml", "<a><b>UNION SELECT</a>");
        let p = Parts::new(&c, c.body.as_ref());
        assert!(hits(&p, "XML", "UNION SELECT"), "a malformed document hid its text");
        let c = body("application/json", r#"{"q": "UNION SELECT", "#);
        let p = Parts::new(&c, c.body.as_ref());
        assert!(hits(&p, "ARG", "UNION SELECT"), "JSON cut short hid its values");
        let c = body("multipart/form-data; boundary=zz", "no parts here: UNION SELECT");
        let p = Parts::new(&c, c.body.as_ref());
        assert!(hits(&p, "ARG", "UNION SELECT"), "a multipart body without its boundary hid it");
    }

    #[test]
    fn a_multipart_bodys_fields_are_arguments_and_its_files_have_names() {
        let upload = "--XyZ\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n<script>alert(1)</script>\r\n\
                      --XyZ\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"shell.php\"\r\nContent-Type: image/png\r\n\r\nPNG-bytes\r\n\
                      --XyZ--\r\n";
        let c = body("multipart/form-data; boundary=\"XyZ\"", upload);
        let p = Parts::new(&c, c.body.as_ref());
        assert!(hits(&p, "ARG:comment", "^<script>alert\\(1\\)</script>$"));
        assert!(hits(&p, "FILE_NAME", r"^shell\.php$"));
        assert!(hits(&p, "ARG_NAME", "^avatar$"), "a file's field is an argument's name");
        assert!(!hits(&p, "ARG", "PNG"), "a file's content is not an argument");
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

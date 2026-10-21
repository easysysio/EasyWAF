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
use super::waf::{normalised_paths, percent_decode, zone_text, Whole};
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

}

/// A rule's conditions, each compiled.
pub type Compiled = Vec<CompiledCondition>;

/// Whether every one of a rule's conditions holds, in order.
pub fn all_hold(conds: &Compiled, whole: &Whole, parts: &Parts) -> bool {
    let list: Vec<(&[Target], &regex::Regex, bool, &[Transform])> = conds.iter()
        .map(|c| (c.targets.as_slice(), &c.re, c.negate, c.chain.as_slice()))
        .collect();
    super::waf::all_hold(&list, whole, parts)
}

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
    /// Argument values; with a name, those of arguments called that, or whose
    /// name matches `/a pattern/`. Names are compared without regard to case.
    Arg(Option<Name>),
    ArgName(Option<Name>),
    Header(Option<Name>),
    HeaderName(Option<Name>),
    Cookie(Option<Name>),
    CookieName(Option<Name>),
    /// Not read: `!HEADER:Cookie` in `HEADER|!HEADER:Cookie` takes that
    /// header out of what the others read.
    Except(Box<Target>),
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
    /// The body, unless it is JSON, XML or multipart, which are read as their
    /// parts: what ModSecurity holds as `REQUEST_BODY`.
    BodyUnparsed,
    /// Each header as a line of its own, `Name: value`, without its line break.
    HeaderLine,
    /// The path's last segment: `index.php` in `/app/index.php`.
    Basename,
    /// The request as one text: its request line, its header block, a blank
    /// line, and its body as inspected.
    Request,
    /// `&HEADER:Host`: how many values a zone has, less its exceptions, as
    /// one value — a number a pattern compares.
    Count(Box<Target>),
    /// The values the condition before matched, after its decodings: what a
    /// second look at the same value reads. Negated, it holds when one of them
    /// does not match, as ModSecurity's negated operator does on MATCHED_VARS.
    Matched,
}

/// The name a zone narrows to: one name, or each name matching a pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Name {
    /// Lowercased.
    Is(String),
    Matches(NamePattern),
}

impl Target {
    /// The name a named zone narrows to.
    pub fn name(&self) -> Option<&Name> {
        match self {
            Target::Arg(n) | Target::ArgName(n) | Target::Header(n) | Target::HeaderName(n)
            | Target::Cookie(n) | Target::CookieName(n) => n.as_ref(),
            _ => None,
        }
    }
}

impl Name {
    /// Whether a name, lowercased, is this one.
    pub fn fits(&self, key: &str) -> bool {
        match self {
            Name::Is(n) => n == key,
            Name::Matches(p) => p.0.is_match(key),
        }
    }
}

/// A pattern names are matched against, compiled once, without regard to case.
/// Compared by its text.
#[derive(Debug, Clone)]
pub struct NamePattern(regex::Regex);

impl PartialEq for NamePattern {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}
impl Eq for NamePattern {}
impl std::hash::Hash for NamePattern {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        self.0.as_str().hash(h)
    }
}

/// A zone as a rule writes it — one zone, or several joined by `|` — as the
/// parts it reads. `None` when any part is not a zone this version reads: a
/// rule written for a newer EasyWAF is not run rather than read as `ANY`.
pub fn parse_zone(zone: &str) -> Option<Vec<Target>> {
    let mut out: Vec<Target> = Vec::new();
    if zone.trim().eq_ignore_ascii_case("MATCHED") {
        return Some(vec![Target::Matched]);
    }
    for part in zone.split('|') {
        let part = part.trim();
        // A count of what a zone reads: one of the zones read a value at a time.
        if let Some(rest) = part.strip_prefix('&') {
            let inner = parse_zone(rest)?.pop()?;
            if rest.contains('|') || matches!(inner, Target::Url | Target::Args | Target::Body | Target::Headers
                | Target::Any | Target::Except(_) | Target::Count(_) | Target::Matched)
            {
                return None;
            }
            let target = Target::Count(Box::new(inner));
            if !out.contains(&target) {
                out.push(target);
            }
            continue;
        }
        // An exception: a named zone, taken out of what the rest read.
        if let Some(rest) = part.strip_prefix('!') {
            let except = parse_zone(rest)?.pop()?;
            let named = matches!(&except, Target::Arg(Some(_)) | Target::ArgName(Some(_)) | Target::Header(Some(_))
                | Target::HeaderName(Some(_)) | Target::Cookie(Some(_)) | Target::CookieName(Some(_)));
            if !named || rest.contains('|') {
                return None;
            }
            let target = Target::Except(Box::new(except));
            if !out.contains(&target) {
                out.push(target);
            }
            continue;
        }
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
            ("METHOD", None)      => Target::Method,
            ("XML", None)         => Target::Xml,
            ("XML_ATTR", None)    => Target::XmlAttr,
            ("FILE_NAME", None)   => Target::FileName,
            ("HEADER_BLOCK", None) => Target::HeaderBlock,
            ("REQUEST_LINE", None) => Target::RequestLine,
            ("PROTOCOL", None)    => Target::Protocol,
            ("BODY_UNPARSED", None) => Target::BodyUnparsed,
            ("HEADER_LINE", None) => Target::HeaderLine,
            ("BASENAME", None)    => Target::Basename,
            ("REQUEST", None)     => Target::Request,
            ("ARG", name)         => Target::Arg(named(name, false)?),
            ("ARG_NAME", name)    => Target::ArgName(named(name, false)?),
            ("HEADER", name)      => Target::Header(named(name, true)?),
            ("HEADER_NAME", name) => Target::HeaderName(named(name, true)?),
            ("COOKIE", name)      => Target::Cookie(named(name, false)?),
            ("COOKIE_NAME", name) => Target::CookieName(named(name, false)?),
            _ => return None,
        };
        if !out.contains(&target) {
            out.push(target);
        }
    }
    // Something has to be read for an exception to be taken out of.
    out.iter().any(|t| !matches!(t, Target::Except(_))).then_some(out)
}

/// The name after a zone's colon; `Some(None)` for no colon, and `None` for a
/// name that cannot be one. `/a pattern/` matches names; anything else is one
/// name, lowercased. A header's name has to be an HTTP token; an argument's or
/// a cookie's anything without spaces or a `|`.
fn named(name: Option<&str>, header: bool) -> Option<Option<Name>> {
    let Some(name) = name else { return Some(None) };
    if name.chars().count() > MAX_NAME || name.contains('|') {
        return None;
    }
    if let Some(pattern) = name.strip_prefix('/').and_then(|n| n.strip_suffix('/')).filter(|p| !p.is_empty()) {
        let re = regex::RegexBuilder::new(pattern).case_insensitive(true).size_limit(1 << 20).build().ok()?;
        return Some(Some(Name::Matches(NamePattern(re))));
    }
    let fits = !name.is_empty()
        && !name.chars().any(|c| c.is_whitespace() || c.is_control())
        && (!header || axum::http::HeaderName::from_bytes(name.as_bytes()).is_ok());
    fits.then(|| Some(Name::Is(name.to_lowercase())))
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
    /// The name and value as ModSecurity's parsers hand them to a rule: a
    /// query's or a form's decoded once, `+` a space; every other as it was
    /// written. What a rule whose decodings begin with `none` is matched
    /// against. No value for a name that has none.
    parsed_name: String,
    parsed:      Option<String>,
}

/// A zone, the exceptions it is read less, a chain of decodings, and the forms
/// the zone is read in with them applied.
type Decoded = (Target, Vec<Target>, Vec<Transform>, Rc<Vec<String>>);

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
    unparsed: OnceCell<Vec<String>>,
    lines:   OnceCell<Vec<Vec<String>>>,
    request: OnceCell<Vec<String>>,
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
            unparsed: OnceCell::new(),
            lines: OnceCell::new(),
            request: OnceCell::new(),
            decoded: RefCell::new(Vec::new()),
        }
    }

    /// Each of `forms` — what `target` is read in — with `chain` applied,
    /// from the cache when a rule has asked for the pair already.
    pub fn decoded(&self, target: &Target, except: &[Target], chain: &[Transform],
                   forms: impl FnOnce() -> Vec<String>) -> Rc<Vec<String>> {
        if let Some((_, _, _, found)) = self.decoded.borrow().iter()
            .find(|(t, x, c, _)| t == target && x == except && c == chain)
        {
            return found.clone();
        }
        let made: Rc<Vec<String>> = Rc::new(forms().iter().flat_map(|f| apply_all(chain, f)).collect());
        self.decoded.borrow_mut().push((target.clone(), except.to_vec(), chain.to_vec(), made.clone()));
        made
    }

    /// Whether `is_match` holds for any form of any value `target` reads, less
    /// the values `except` takes out of it. With `parsed`, each value once, as
    /// ModSecurity's parsers hand it over, rather than in every form. Only for
    /// the targeted zones; the whole-text ones are the caller's.
    pub fn any(&self, target: &Target, except: &[Target], parsed: bool, is_match: &dyn Fn(&str) -> bool) -> bool {
        // Taken out: an exception of the same kind naming this one.
        let excepted = |v: &Value| except.iter().any(|e| match e {
            Target::Except(inner) if std::mem::discriminant(&**inner) == std::mem::discriminant(target) => {
                inner.name().is_some_and(|n| n.fits(&v.key))
            }
            _ => false,
        });
        let chosen = |v: &Value, name: &Option<Name>| name.as_ref().is_none_or(|n| n.fits(&v.key)) && !excepted(v);
        let values = |list: &[Value], name: &Option<Name>| {
            list.iter().filter(|v| chosen(v, name)).any(|v| if parsed {
                v.parsed.as_deref().is_some_and(is_match)
            } else {
                v.value.iter().any(|f| is_match(f))
            })
        };
        let names = |list: &[Value], name: &Option<Name>| {
            list.iter().filter(|v| chosen(v, name)).any(|v| if parsed {
                is_match(&v.parsed_name)
            } else {
                v.name.iter().any(|f| is_match(f))
            })
        };
        // A text read whole: as it is, or in every form.
        let text = |forms: &[String]| if parsed {
            forms.first().is_some_and(|f| is_match(f))
        } else {
            forms.iter().any(|f| is_match(f))
        };
        match target {
            // The path as the server behind ModSecurity hands it over:
            // decoded once, `+` a `+`.
            Target::Path        => if parsed { is_match(&percent_decode(&self.ctx.path)) } else { text(self.path()) },
            Target::Arg(name)   => values(self.args(), name),
            Target::ArgName(name) => names(self.args(), name),
            Target::Header(name) => values(self.headers(), name),
            Target::HeaderName(name) => names(self.headers(), name),
            Target::Cookie(name) => values(self.cookies(), name),
            Target::CookieName(name) => names(self.cookies(), name),
            Target::Method      => is_match(&self.ctx.method),
            Target::Xml         => text(&self.xml().0),
            Target::XmlAttr     => values(&self.xml().1, &None),
            Target::FileName    => values(&self.multipart().1, &None),
            Target::HeaderBlock => text(self.header_block()),
            Target::RequestLine => text(self.request_line()),
            Target::Protocol    => is_match(protocol(self.ctx.version)),
            Target::BodyUnparsed => text(self.unparsed_body()),
            Target::HeaderLine  => self.header_lines().iter().any(|forms| text(forms)),
            Target::Basename    => {
                let last = |p: &str| p.rsplit('/').next().unwrap_or("").to_string();
                if parsed {
                    is_match(&last(&percent_decode(&self.ctx.path)))
                } else {
                    zone_text(&last(&self.ctx.path), false).iter().any(|f| is_match(f))
                }
            }
            Target::Request     => text(self.raw_request()),
            Target::Count(inner) => {
                let n = std::cell::Cell::new(0usize);
                self.any(inner, except, true, &|_| {
                    n.set(n.get() + 1);
                    false
                });
                is_match(&n.get().to_string())
            }
            Target::Matched     => false,
            Target::Except(_) | Target::Url | Target::Args | Target::Body | Target::Headers | Target::Any => false,
        }
    }

    /// Each header as its own line, in the forms a value is read in; the
    /// header block's lines, one at a time.
    fn header_lines(&self) -> &[Vec<String>] {
        self.lines.get_or_init(|| {
            self.ctx.headers.iter()
                .map(|(name, value)| zone_text(
                    &format!("{}: {}", header_case(name.as_str()), String::from_utf8_lossy(value.as_bytes())), false))
                .collect()
        })
    }

    /// The request as one text, as it would have crossed the wire over
    /// HTTP/1.1: the request line, the header block, a blank line, the body.
    fn raw_request(&self) -> &[String] {
        self.request.get_or_init(|| {
            let line = self.request_line().first().cloned().unwrap_or_default();
            let block = self.header_block().first().cloned().unwrap_or_default();
            zone_text(&format!("{line}\r\n{block}\r\n{}", String::from_utf8_lossy(self.body)), false)
        })
    }

    /// The body in its forms when it is not one read as its parts — JSON,
    /// XML, multipart — and nothing when it is.
    fn unparsed_body(&self) -> &[String] {
        self.unparsed.get_or_init(|| match body_kind(&self.ctx.headers) {
            Some(BodyKind::Json | BodyKind::Xml | BodyKind::Multipart(_)) => Vec::new(),
            _ if self.body.is_empty() => Vec::new(),
            _ => zone_text(&String::from_utf8_lossy(self.body), true),
        })
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
                                parsed_name: a.name().to_string(),
                                parsed: Some(a.value().to_string()),
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
                .map(|(name, value)| {
                    let text = String::from_utf8_lossy(value.as_bytes()).into_owned();
                    Value {
                        key:   name.as_str().to_string(),
                        name:  vec![name.as_str().to_string()],
                        value: zone_text(&text, false),
                        parsed_name: name.as_str().to_string(),
                        parsed: Some(text),
                    }
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
                        parsed_name: name.trim().to_string(),
                        parsed: Some(value.trim().to_string()),
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
    } else if mime == "application/json" || mime.ends_with("+json") || mime.starts_with("application/x-amz-json-1.") {
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
        let text = String::from_utf8_lossy(body).into_owned();
        out.push(Value { key: String::new(), name: Vec::new(), value: zone_text(&text, true),
                         parsed_name: String::new(), parsed: Some(text) });
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
                    files.push(Value { key: name.to_lowercase(), name: zone_text(&name, false), value: zone_text(&file, false),
                                       parsed_name: name.clone(), parsed: Some(file.clone()) });
                }
                // A file's field is an argument's name, without a value.
                if fields.len() < MAX_VALUES {
                    fields.push(Value { key: name.to_lowercase(), name: zone_text(&name, false), value: Vec::new(),
                                        parsed_name: name.clone(), parsed: None });
                }
            }
            None => {
                if fields.len() < MAX_VALUES {
                    fields.push(Value { key: name.to_lowercase(), name: zone_text(&name, false), value: zone_text(content, false),
                                        parsed_name: name.clone(), parsed: Some(content.to_string()) });
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
        let parsed_name = percent_decode(&name.replace('+', " "));
        out.push(Value {
            key:   parsed_name.to_lowercase(),
            name:  zone_text(name, true),
            value: zone_text(value, true),
            parsed_name,
            parsed: Some(percent_decode(&value.replace('+', " "))),
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
            parsed_name: key.clone(),
            parsed: Some(text),
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
                        out.push(Value { key: k.to_lowercase(), name: zone_text(k, false), value: Vec::new(),
                                         parsed_name: k.clone(), parsed: None });
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
        hits_as(parts, zone, pattern, false)
    }

    /// As the engine reads a zone: less its exceptions, and with `parsed`
    /// each value once as parsed.
    fn hits_as(parts: &Parts, zone: &str, pattern: &str, parsed: bool) -> bool {
        let re = regex::Regex::new(pattern).unwrap();
        let targets = parse_zone(zone).unwrap();
        let (except, read): (Vec<Target>, Vec<Target>) = targets.into_iter().partition(|t| matches!(t, Target::Except(_)));
        read.iter().any(|t| parts.any(t, &except, parsed, &|s| re.is_match(s)))
    }

    #[test]
    fn a_zone_names_by_pattern_and_takes_exceptions_out() {
        let c = ctx("/", Some("json.a=1&keep=evil"), &[("cookie", "$Version=1; MyVersion=1"), ("referer", "evil"),
                                                       ("user-agent", "fine")], "");
        let p = Parts::new(&c, b"");
        assert!(hits(&p, "HEADER", "evil"));
        assert!(!hits(&p, "HEADER|!HEADER:Referer", "evil"), "the excepted header was read");
        assert!(hits(&p, "HEADER|!HEADER:Referer", "fine"));
        assert!(hits(&p, "COOKIE:/^\\$version$/", "^1$"));
        assert!(!hits(&p, "COOKIE_NAME:/^\\$version$/", "^MyVersion$"), "a pattern took a name it does not match");
        assert!(!hits(&p, "ARG_NAME|!ARG_NAME:/^json\\./", "^json"), "an excepted name by pattern was read");
        assert!(hits(&p, "ARG_NAME|!ARG_NAME:/^json\\./", "^keep$"));
        assert_eq!(parse_zone("!HEADER:Referer"), None, "a zone of exceptions alone reads nothing");
        assert_eq!(parse_zone("HEADER|!PATH"), None, "an exception names one value");
        assert_eq!(canonical("header|!header:cookie"), Some("HEADER|!HEADER:cookie".into()));
    }

    #[test]
    fn a_parsed_value_is_decoded_once_where_modsecurity_decodes_it() {
        let c = ctx("/a%20b", Some("q=%26lt%3B+x"), &[("cookie", "c=%41")], "");
        let p = Parts::new(&c, b"");
        assert!(hits_as(&p, "ARG:q", "^&lt; x$", true), "a query argument is decoded once, + a space");
        assert!(!hits_as(&p, "ARG:q", "<", true), "a parsed value was HTML-decoded too");
        assert!(hits(&p, "ARG:q", "<"), "a rule matched in every form sees it HTML-decoded");
        assert!(hits_as(&p, "COOKIE:c", "^%41$", true), "a cookie is read as written");
        assert!(hits_as(&p, "PATH", "^/a b$", true), "the path is decoded once, as a server hands it over");
    }

    #[test]
    fn a_header_line_is_one_header_and_the_request_is_all_of_it() {
        let c = ctx("/x", Some("a=1"), &[("user-agent", "curl/8"), ("x-token", "abc")], "body=1");
        let p = Parts::new(&c, c.body.as_ref());
        assert!(hits(&p, "HEADER_LINE", "^X-Token: abc$"));
        let b = ctx("/post/1234%20OR%201=1", None, &[], "");
        let bp = Parts::new(&b, b"");
        assert!(hits_as(&bp, "BASENAME", "^1234 OR 1=1$", true) && !hits_as(&bp, "BASENAME", "post", true));
        assert!(!hits(&p, "HEADER_LINE", "curl/8\r\nX-Token"), "a line ran into the next");
        assert!(hits(&p, "REQUEST", "^POST /x\\?a=1 HTTP/1\\.1\r\nUser-Agent: curl/8\r\nX-Token: abc\r\n\r\nbody=1$"));
    }

    /// A count is one value, the number; MATCHED reads what the condition
    /// before matched, and narrows it.
    #[test]
    fn a_count_is_a_number_and_matched_reads_the_value_before() {
        let c = ctx("/", Some("a=x/y+z&b=x/y&c=plain"), &[("content-type", "a"), ("content-type", "b")], "");
        let (whole, parts) = (Whole::of(&c, b""), Parts::new(&c, b""));
        let cond = |zone: &str, pattern: &str, negate: bool| CompiledCondition::new(&Condition {
            zone: zone.into(), pattern: pattern.into(), negate, transforms: vec!["none".into()],
        }).unwrap();
        let holds = |list: Vec<CompiledCondition>| all_hold(&list, &whole, &parts);
        assert!(holds(vec![cond("&HEADER:Content-Type", "^2$", false)]));
        assert!(holds(vec![cond("&HEADER:Host", "^0$", false)]), "a header absent is a count of nought");
        assert!(holds(vec![cond("&ARG|!ARG:c", "^2$", false)]), "a count is less its exceptions");
        // One value with a slash and a space: a's.
        assert!(holds(vec![cond("ARG", "/", false), cond("MATCHED", " ", false)]));
        assert!(!holds(vec![cond("ARG:b", "/", false), cond("MATCHED", " ", false)]),
                "MATCHED read a value the condition before did not match");
        // Negated: one of the values matched does not match.
        assert!(holds(vec![cond("ARG", "/", false), cond("MATCHED", " ", true)]), "b has no space");
        assert!(!holds(vec![cond("ARG:a", "/", false), cond("MATCHED", " ", true)]));
        assert!(!holds(vec![cond("MATCHED", ".", false)]), "MATCHED with nothing before it held");
        assert_eq!(parse_zone("&URL"), None, "a whole text has no values to count");
        assert_eq!(parse_zone("MATCHED|ARG"), None);
    }

    #[test]
    fn the_unparsed_body_is_one_modsecurity_holds_as_request_body() {
        for (ct, read) in [("application/x-www-form-urlencoded", true), ("text/plain", true),
                           ("application/json", false), ("application/xml", false), ("multipart/form-data; boundary=x", false)] {
            let c = ctx("/", None, &[("content-type", ct)], "java.lang.Runtime");
            let p = Parts::new(&c, c.body.as_ref());
            assert_eq!(hits(&p, "BODY_UNPARSED", "java"), read, "{ct}");
        }
    }

    #[test]
    fn the_five_zones_parse_as_before_and_the_new_ones_alongside() {
        assert_eq!(parse_zone("ANY"), Some(vec![Target::Any]));
        assert_eq!(parse_zone("headers"), Some(vec![Target::Headers]));
        assert_eq!(parse_zone("HEADER:User-Agent"), Some(vec![Target::Header(Some(Name::Is("user-agent".into())))]));
        assert_eq!(parse_zone("ARG|ARG_NAME|COOKIE"),
                   Some(vec![Target::Arg(None), Target::ArgName(None), Target::Cookie(None)]));
        assert_eq!(parse_zone("ARG:id|ARG:ID"), Some(vec![Target::Arg(Some(Name::Is("id".into())))]));
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
            let compiled = CompiledCondition::new(&Condition {
                zone: zone.into(), pattern: pattern.into(), negate,
                transforms: transforms.iter().map(|t| t.to_string()).collect(),
            }).unwrap();
            all_hold(&vec![compiled], &whole, &parts)
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

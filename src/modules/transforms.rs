// =========================================================
// modules/transforms.rs — EasyWAF
// The decodings a rule names for itself.
//
// Every value is matched in the forms waf.rs makes of it:
// as it arrived, percent-decoded, with HTML, JavaScript and
// CSS escapes undone, a path normalised. A rule written
// against text decoded further — a shell command with its
// quotes taken out, SQL with its comments replaced — names
// those decodings, and its pattern is matched against each
// of those forms with them applied in order, not against
// the forms themselves.
//
// Each follows libmodsecurity's, which CRS's rules are
// written against, except base64Runs and dotPrefix, which
// stand for Suricata's base64_data and dotprefix.
// `multiMatch` is not a decoding: named among them, the
// pattern is matched against each form before the first and
// after every one, as ModSecurity's multiMatch action does.
// Nor is `none`: first in a chain, it says the chain starts
// from each value as ModSecurity's parsers hand it over —
// once, rather than in every form — as `t:none` does.
// `length` is a value's length in bytes, as a number a
// pattern compares; `detectSQLi` and `detectXSS` are
// libinjection's verdict on it — the injection's fingerprint,
// or nothing — so the pattern `.` is ModSecurity's operator.
// =========================================================

use super::waf::{css_decode, html_entity_decode, js_decode, normalize_path, normalize_path_win,
                 percent_decode, remove_nulls, url_decode_uni};

/// One decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transform {
    CmdLine,
    RemoveWhitespace,
    CompressWhitespace,
    ReplaceComments,
    RemoveCommentsChar,
    Base64Decode,
    Base64Runs,
    EscapeSeqDecode,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    RemoveNulls,
    NormalizePath,
    NormalizePathWin,
    Lowercase,
    Trim,
    DotPrefix,
    Utf8ToUnicode,
    Length,
    DetectSqli,
    DetectXss,
    MultiMatch,
    /// `none`: the chain starts from each value as parsed.
    Parsed,
}

use Transform::*;

/// Each decoding by the name a rule gives it.
const NAMES: &[(&str, Transform)] = &[
    ("cmdLine", CmdLine),
    ("removeWhitespace", RemoveWhitespace),
    ("compressWhitespace", CompressWhitespace),
    ("replaceComments", ReplaceComments),
    ("removeCommentsChar", RemoveCommentsChar),
    ("base64Decode", Base64Decode),
    ("base64Runs", Base64Runs),
    ("escapeSeqDecode", EscapeSeqDecode),
    ("urlDecode", UrlDecode),
    ("urlDecodeUni", UrlDecodeUni),
    ("htmlEntityDecode", HtmlEntityDecode),
    ("jsDecode", JsDecode),
    ("cssDecode", CssDecode),
    ("removeNulls", RemoveNulls),
    ("normalizePath", NormalizePath),
    ("normalizePathWin", NormalizePathWin),
    ("lowercase", Lowercase),
    ("trim", Trim),
    ("dotPrefix", DotPrefix),
    ("utf8toUnicode", Utf8ToUnicode),
    ("length", Length),
    ("detectSQLi", DetectSqli),
    ("detectXSS", DetectXss),
    ("multiMatch", MultiMatch),
    ("none", Parsed),
];

impl Transform {
    /// A decoding by its name, in any case. `None` for one this version does
    /// not apply.
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        NAMES.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, t)| *t)
    }

    pub fn name(self) -> &'static str {
        NAMES.iter().find(|(_, t)| *t == self).map(|(n, _)| *n).unwrap_or("?")
    }

    pub fn apply(self, s: &str) -> String {
        match self {
            CmdLine            => cmd_line(s),
            RemoveWhitespace   => s.chars().filter(|c| !is_space(*c)).collect(),
            CompressWhitespace => compress_whitespace(s),
            ReplaceComments    => replace_comments(s),
            RemoveCommentsChar => remove_comments_char(s),
            Base64Decode       => base64_decode(s),
            Base64Runs         => base64_runs(s),
            EscapeSeqDecode    => escape_seq_decode(s),
            // Both read `+` as a space, as libmodsecurity's do.
            UrlDecode          => percent_decode(&s.replace('+', " ")),
            UrlDecodeUni       => url_decode_uni(&s.replace('+', " ")),
            HtmlEntityDecode   => html_entity_decode(s),
            JsDecode           => js_decode(s),
            CssDecode          => css_decode(s),
            RemoveNulls        => remove_nulls(s),
            NormalizePath      => normalize_path(s),
            NormalizePathWin   => normalize_path_win(s),
            Lowercase          => s.to_lowercase(),
            Trim               => s.trim_matches(is_space).to_string(),
            DotPrefix          => format!(".{s}"),
            Utf8ToUnicode      => utf8_to_unicode(s),
            Length             => s.len().to_string(),
            DetectSqli         => {
                let found = libinjectionrs::detect_sqli(s.as_bytes());
                match found.fingerprint {
                    Some(fp) if found.is_injection() => fp.to_string(),
                    _ => String::new(),
                }
            }
            DetectXss          => if libinjectionrs::detect_xss(s.as_bytes()).is_injection() {
                "xss".to_string()
            } else {
                String::new()
            },
            MultiMatch | Parsed => s.to_string(),
        }
    }
}

/// Decodings by name, in order. `Err` names the first this version does not
/// apply.
pub fn parse_list(names: &[String]) -> Result<Vec<Transform>, String> {
    names.iter().map(|n| Transform::parse(n).ok_or_else(|| n.clone())).collect()
}

/// What a pattern is matched against for `s`: `s` with each of `chain`
/// applied, in order — and with `multiMatch` in the chain, `s` itself and
/// what each decoding leaves too.
pub fn apply_all(chain: &[Transform], s: &str) -> Vec<String> {
    let every = chain.contains(&MultiMatch);
    // A measure at the end of a chain — a length, libinjection's verdict — is
    // of each value the multiMatch decodings leave, not one more of them.
    if every && matches!(chain.last(), Some(Length | DetectSqli | DetectXss)) {
        let (measure, rest) = chain.split_last().map(|(m, r)| (*m, r)).unwrap_or((Parsed, &[]));
        return apply_all(rest, s).iter().map(|v| measure.apply(v)).collect();
    }
    let mut out = if every { vec![s.to_string()] } else { Vec::new() };
    let mut text = s.to_string();
    for t in chain.iter().filter(|t| !matches!(t, MultiMatch | Parsed)) {
        text = t.apply(&text);
        if every && !out.contains(&text) {
            out.push(text.clone());
        }
    }
    if !every {
        out.push(text);
    }
    out
}

/// `utf8toUnicode`: each character beyond ASCII as `%uHHHH`, which
/// `urlDecodeUni` then reads, folding a full-width `＜` to `<`. One beyond the
/// first 65,536 is left as it is.
fn utf8_to_unicode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c as u32 {
            0..=0x7f => out.push(c),
            code @ 0x80..=0xffff => out.push_str(&format!("%u{code:04x}")),
            _ => out.push(c),
        }
    }
    out
}

/// Whitespace as C's `isspace` reads it, and the no-break space, which
/// libmodsecurity counts too.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\u{a0}')
}

/// `cmdLine`: a command as a shell runs it, whatever was put in to break up
/// the words a rule looks for. Quotes, backslashes and carets are dropped;
/// spaces, commas and semicolons become one space; a space before `/` or `(`
/// goes; everything is lowercased. `c\a"t /e't'c/pass''wd` is `cat/etc/passwd`.
fn cmd_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = false;
    for c in s.chars() {
        match c {
            '"' | '\'' | '\\' | '^' => {}
            ' ' | ',' | ';' | '\t' | '\r' | '\n' => {
                if !space {
                    out.push(' ');
                    space = true;
                }
            }
            '/' | '(' => {
                if space {
                    out.pop();
                }
                space = false;
                out.push(c);
            }
            _ => {
                out.push(c.to_ascii_lowercase());
                space = false;
            }
        }
    }
    out
}

fn compress_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = false;
    for c in s.chars() {
        if is_space(c) {
            if !space {
                out.push(' ');
            }
            space = true;
        } else {
            out.push(c);
            space = false;
        }
    }
    out
}

/// `replaceComments`: each `/* … */` is one space, and so is one left open
/// at the end, so `UNION/**/SELECT` is `UNION SELECT`.
fn replace_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        match rest.find("/*") {
            None => {
                out.push_str(rest);
                return out;
            }
            Some(open) => {
                out.push_str(&rest[..open]);
                out.push(' ');
                match rest[open + 2..].find("*/") {
                    Some(close) => rest = &rest[open + 2 + close + 2..],
                    None => return out,
                }
            }
        }
    }
}

/// `removeCommentsChar`: the comment markers themselves taken out — `/*`,
/// `*/`, `<!--`, `-->`, `--` and `#` — and what they enclosed kept.
fn remove_comments_char(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(c) = rest.chars().next() {
        match ["<!--", "-->", "/*", "*/", "--", "#"].into_iter().find(|m| rest.starts_with(m)) {
            Some(m) => rest = &rest[m.len()..],
            None => {
                out.push(c);
                rest = &rest[c.len_utf8()..];
            }
        }
    }
    out
}

fn base64_value(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as u32),
        b'a'..=b'z' => Some((b - b'a') as u32 + 26),
        b'0'..=b'9' => Some((b - b'0') as u32 + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Base64 digits, without padding, as the bytes they encode. A trailing digit
/// that encodes no whole byte is dropped.
fn decode_digits(digits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for d in digits.iter().filter_map(|b| base64_value(*b)) {
        acc = (acc << 6) | d;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// `base64Decode`: the value as base64, its line breaks ignored. A value that
/// is not base64 — a character outside the alphabet, padding before its end —
/// decodes to nothing, as libmodsecurity's does.
fn base64_decode(s: &str) -> String {
    let text: Vec<u8> = s.bytes().filter(|b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t')).collect();
    let digits = text.strip_suffix(b"==").or_else(|| text.strip_suffix(b"=")).unwrap_or(&text);
    let alphabet = |b: &u8| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/');
    if digits.len() % 4 == 1 || !digits.iter().all(alphabet) {
        return String::new();
    }
    String::from_utf8_lossy(&decode_digits(digits)).into_owned()
}

/// Each run of base64 in a value — standard or URL-safe, four digits or
/// more, its padding ending it — decoded, one to a line. What Suricata's
/// `base64_data` reads is base64 found after an earlier match; this decodes
/// every run, so a rule's content is looked for in each.
fn base64_runs(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if base64_value(b[i]).is_none() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && base64_value(b[i]).is_some() {
            i += 1;
        }
        if i - start >= 4 {
            if !out.is_empty() {
                out.push(b'\n');
            }
            out.extend(decode_digits(&b[start..i]));
        }
        while i < b.len() && b[i] == b'=' {
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `escapeSeqDecode`: C's escapes — `\n`, `\x41`, `\101` — as the bytes they
/// stand for. An escape that is none of them is the character after the
/// backslash.
fn escape_seq_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let simple = match b[i + 1] {
            b'a' => Some(0x07), b'b' => Some(0x08), b'f' => Some(0x0c), b'n' => Some(b'\n'),
            b'r' => Some(b'\r'), b't' => Some(b'\t'), b'v' => Some(0x0b),
            b'\\' | b'?' | b'\'' | b'"' => Some(b[i + 1]),
            _ => None,
        };
        if let Some(c) = simple {
            out.push(c);
            i += 2;
        } else if matches!(b[i + 1], b'x' | b'X') && i + 3 < b.len()
            && b[i + 2].is_ascii_hexdigit() && b[i + 3].is_ascii_hexdigit()
        {
            let hex = std::str::from_utf8(&b[i + 2..i + 4]).unwrap_or("0");
            out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
            i += 4;
        } else if (b'0'..=b'7').contains(&b[i + 1]) {
            let digits = b[i + 1..].iter().take(3).take_while(|d| (b'0'..=b'7').contains(*d)).count();
            let text = std::str::from_utf8(&b[i + 1..i + 1 + digits]).unwrap_or("0");
            out.push((u32::from_str_radix(text, 8).unwrap_or(0) & 0xff) as u8);
            i += 1 + digits;
        } else {
            out.push(b[i + 1]);
            i += 2;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn t(name: &str, s: &str) -> String {
        Transform::parse(name).unwrap_or_else(|| panic!("{name}")).apply(s)
    }

    #[test]
    fn names_are_read_in_any_case_and_an_unknown_one_is_named() {
        assert_eq!(Transform::parse("CMDLINE"), Some(CmdLine));
        assert_eq!(Transform::parse(" replaceComments "), Some(ReplaceComments));
        assert_eq!(parse_list(&["cmdLine".into(), "sqlHexDecode".into()]), Err("sqlHexDecode".into()));
        for (name, t) in NAMES {
            assert_eq!(Transform::parse(name), Some(*t));
            assert_eq!(t.name(), *name);
        }
    }

    #[test]
    fn cmd_line_reads_a_command_as_the_shell_would() {
        assert_eq!(t("cmdLine", "c\\a\"t /e't'c/pass''wd"), "cat/etc/passwd");
        assert_eq!(t("cmdLine", "PING,;  -c\t1 x"), "ping -c 1 x");
        assert_eq!(t("cmdLine", "echo (id)"), "echo(id)");
        assert_eq!(t("cmdLine", "w^h^o^a^m^i"), "whoami");
    }

    #[test]
    fn whitespace_is_removed_or_compressed() {
        assert_eq!(t("removeWhitespace", "un ion\t\nsel\u{a0}ect"), "unionselect");
        assert_eq!(t("compressWhitespace", "union  \t select\u{a0}\u{a0}1"), "union select 1");
        assert_eq!(t("trim", " \t x y \n"), "x y");
    }

    #[test]
    fn comments_are_replaced_or_their_markers_removed() {
        assert_eq!(t("replaceComments", "UNION/**/SELECT/*x*/1"), "UNION SELECT 1");
        assert_eq!(t("replaceComments", "a/*open"), "a ");
        assert_eq!(t("replaceComments", "a*/b"), "a*/b");
        assert_eq!(t("removeCommentsChar", "un/*x*/ion<!--y-->--#sel"), "unxionysel");
    }

    #[test]
    fn base64_decodes_a_value_or_the_runs_in_one() {
        assert_eq!(t("base64Decode", "PHNjcmlwdD4="), "<script>");
        assert_eq!(t("base64Decode", "PHNjcmlw\r\ndD4"), "<script>");
        assert_eq!(t("base64Decode", "not base64!"), "");
        // The name before `=` is a run of its own, so the value after it
        // decodes from its own start.
        assert!(t("base64Runs", "SAMLResponse=PHNhbWxwOlJlc3BvbnNlPg==").ends_with("\n<samlp:Response>"));
        // A JWT's header, URL-safe and unpadded.
        assert!(t("base64Runs", "Bearer eyJhbGciOiJub25lIn0.e30.").contains(r#"{"alg":"none"}"#));
        assert_eq!(t("base64Runs", "a b c"), "");
    }

    #[test]
    fn escape_sequences_are_the_bytes_they_stand_for() {
        assert_eq!(t("escapeSeqDecode", r"\x41\102\n\q\\"), "AB\nq\\");
        assert_eq!(t("escapeSeqDecode", r"\x4"), "x4");
        assert_eq!(t("escapeSeqDecode", "plain"), "plain");
    }

    #[test]
    fn libinjection_says_what_it_found_and_a_length_is_a_number() {
        assert!(!t("detectSQLi", "1' OR '1'='1").is_empty());
        assert_eq!(t("detectSQLi", "hello world"), "");
        assert_eq!(t("detectSQLi", "O'Reilly bought 3 books"), "", "an apostrophe in prose");
        assert_eq!(t("detectXSS", "<script>alert(1)</script>"), "xss");
        assert_eq!(t("detectXSS", "a < b and c > d"), "");
        assert_eq!(t("length", "héllo"), "6", "bytes, as ModSecurity counts");
        // With multiMatch, libinjection reads every step, and nothing else is matched.
        let steps = apply_all(&[Parsed, MultiMatch, UrlDecodeUni, DetectSqli], "1%27%20OR%20%271%27%3D%271");
        assert!(steps.iter().any(|f| !f.is_empty()) && steps.iter().all(|f| !f.contains('%')), "{steps:?}");
        assert!(apply_all(&[Parsed, MultiMatch, UrlDecodeUni, DetectSqli], "alice@example.com").iter().all(String::is_empty));
    }

    #[test]
    fn a_chain_applies_in_order() {
        let chain = [UrlDecodeUni, CmdLine];
        assert_eq!(apply_all(&chain, "c%27a%27t+/etc/passwd"), ["cat/etc/passwd"]);
        assert_eq!(apply_all(&[MultiMatch, UrlDecodeUni, CmdLine], "c%27a%27t+/etc/passwd"),
                   ["c%27a%27t+/etc/passwd", "c'a't /etc/passwd", "cat/etc/passwd"]);
        assert_eq!(t("dotPrefix", "evil.com"), ".evil.com");
        assert_eq!(apply_all(&[Parsed, Utf8ToUnicode, UrlDecodeUni], "＜script＞é"), ["<script>\u{fffd}"],
                   "é decodes to its low byte, as libmodsecurity's does, which alone is no character");
        assert_eq!(t("normalizePath", "/a/./b/../c\\..\\d"), "/a/c\\..\\d");
        assert_eq!(t("normalizePathWin", "/a/./b/../c\\..\\d"), "/a/d");
    }
}

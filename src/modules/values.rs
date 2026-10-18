// =========================================================
// modules/values.rs — EasyWAF
// The lists a policy sets, and the rules that read them.
//
// A pattern may name a list as `%{allowed_methods}`. When a
// policy's rules are loaded it is replaced by the policy's
// list as an alternation of its words, each matched as it
// is written: `^%{allowed_methods}$` is `^(?:GET|HEAD)$` on
// a policy allowing those two. A policy that sets none of a
// list has OWASP CRS's default, which is what CRS's rules
// on these lists were written for. A `*` in a word stands
// for any run of the characters a media type's name may
// hold (RFC 6838): `application/*+json`.
// =========================================================

use std::collections::HashMap;

/// A list a policy sets.
pub struct Value {
    pub name:    &'static str,
    pub label:   &'static str,
    pub help:    &'static str,
    /// OWASP CRS 4.30.0's, as words.
    pub default: &'static str,
}

pub const VALUES: &[Value] = &[
    Value {
        name: "allowed_methods",
        label: "Allowed methods",
        help: "Methods a request may use. WebDAV adds PUT DELETE PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK; a REST API PUT PATCH DELETE.",
        default: "GET HEAD POST OPTIONS",
    },
    Value {
        name: "allowed_content_types",
        label: "Allowed content types",
        help: "Types a request body may be sent as, without parameters; * stands for any run of a type name's characters. A file upload by PUT adds application/octet-stream.",
        // With what CRS's 901360 and 901370 add to its list on every request:
        // AWS's JSON types, and every +json type.
        default: "application/x-www-form-urlencoded multipart/form-data text/xml application/xml \
                  application/soap+xml application/json application/x-amz-json-1.0 \
                  application/x-amz-json-1.1 application/*+json",
    },
    Value {
        name: "allowed_charsets",
        label: "Allowed charsets",
        help: "Charsets a Content-Type may name.",
        default: "utf-8 iso-8859-1 iso-8859-15 windows-1252",
    },
    Value {
        name: "allowed_http_versions",
        label: "Allowed HTTP versions",
        help: "As the request line names them.",
        default: "HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0",
    },
    Value {
        name: "restricted_extensions",
        label: "Restricted file extensions",
        help: "Extensions, without the dot, a path may not end in: backups, configuration, keys, databases, scripts.",
        default: "ani asa asax ascx back backup bak bck bk bkp bat cdx cer cfg cmd cnf com compositefont \
                  config conf copy crt cs csproj csr dat db dbf dist dll dos dpkg-dist drv gadget hta htr \
                  htw ida idc idq inc inf ini jks jse key licx lnk log mdb msc ocx old pass pdb pfx pif pem \
                  pol prf printer pwd rdb rdp reg resources resx sav save scr sct sh shs sql sqlite sqlite3 \
                  swap swo swp sys temp tfstate tlb tmp vb vbe vbs vbproj vsdisco vxd webinfo ws wsc wsf wsh \
                  xsd xsx",
    },
    Value {
        name: "restricted_headers",
        label: "Restricted headers",
        help: "Headers a request may not carry, by name.",
        default: "content-encoding proxy lock-token content-range if x-http-method-override x-http-method \
                  x-method-override x-middleware-subrequest expect",
    },
];

/// A list by its name. `None` for one this version does not know.
pub fn find(name: &str) -> Option<&'static Value> {
    VALUES.iter().find(|v| v.name == name)
}

/// A list as it is stored and shown: its words, one space apart.
pub fn tidy(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every list's default, by name.
pub fn defaults() -> HashMap<String, String> {
    VALUES.iter().map(|v| (v.name.to_string(), tidy(v.default))).collect()
}

/// A policy's lists: what it set, and the default for every list it did not.
pub async fn of_policy(db: &sqlx::SqlitePool, policy_id: i64) -> HashMap<String, String> {
    let mut out = defaults();
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT name, value FROM policy_values WHERE policy_id = ?")
        .bind(policy_id)
        .fetch_all(db)
        .await
        .unwrap_or_default();
    for (name, value) in rows {
        if find(&name).is_some() {
            out.insert(name, tidy(&value));
        }
    }
    out
}

/// The names of the lists a pattern reads, in order, each once.
pub fn named_in(pattern: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = pattern;
    while let Some(at) = rest.find("%{") {
        let Some(end) = rest[at + 2..].find('}') else { break };
        let name = &rest[at + 2..at + 2 + end];
        if !out.contains(&name) {
            out.push(name);
        }
        rest = &rest[at + 2 + end + 1..];
    }
    out
}

/// `pattern` with each `%{name}` replaced by that list from `values` as an
/// alternation of its words, escaped, a `*` standing for any run of the
/// characters a media type's name may hold. A list with no words matches
/// nothing.
/// `Err` names a list this version does not know. A pattern naming none is
/// returned as it is.
pub fn substitute(pattern: &str, values: &HashMap<String, String>) -> Result<String, String> {
    if !pattern.contains("%{") {
        return Ok(pattern.to_string());
    }
    let mut out = pattern.to_string();
    for name in named_in(pattern) {
        if find(name).is_none() {
            return Err(name.to_string());
        }
        let words: Vec<String> = values.get(name).map(String::as_str).unwrap_or("")
            .split_whitespace().map(|w| regex::escape(w).replace("\\*", "[0-9A-Za-z!#$&^_.+-]*")).collect();
        let alternation = if words.is_empty() { "[^\\s\\S]".to_string() } else { format!("(?:{})", words.join("|")) };
        out = out.replace(&format!("%{{{name}}}"), &alternation);
    }
    Ok(out)
}

/// Whether a pattern compiles with the defaults of the lists it names. `Err`
/// says why not: a list this version does not know, or the regex's own error.
pub fn check(pattern: &str) -> Result<(), String> {
    let p = substitute(pattern, &defaults()).map_err(|name| format!("the list {name:?} is not one EasyWAF knows"))?;
    regex::Regex::new(&p).map(|_| ()).map_err(|e| e.to_string().lines().last().unwrap_or("").trim().to_string())
}

// ─── Tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_is_an_alternation_of_its_words_escaped() {
        let mut v = defaults();
        assert_eq!(substitute("^%{allowed_methods}$", &v).unwrap(), "^(?:GET|HEAD|POST|OPTIONS)$");
        v.insert("allowed_content_types".into(), "application/json  text/plain+x".into());
        assert_eq!(substitute("(?i)^%{allowed_content_types}(?:[;\\s]|$)", &v).unwrap(),
                   "(?i)^(?:application/json|text/plain\\+x)(?:[;\\s]|$)");
        v.insert("allowed_methods".into(), "".into());
        v.insert("allowed_content_types".into(), "application/*+json".into());
        let json = regex::Regex::new(&substitute("^%{allowed_content_types}$", &v).unwrap()).unwrap();
        assert!(json.is_match("application/cloudevents+json") && !json.is_match("application/json; x"));
        assert!(!json.is_match("application/a@b+json"), "* took a character a type's name cannot hold");
        let none = regex::Regex::new(&substitute("^%{allowed_methods}$", &v).unwrap()).unwrap();
        assert!(!none.is_match("GET") && !none.is_match(""), "an empty list matched");
        assert_eq!(substitute("^%{allowed_cheeses}$", &v), Err("allowed_cheeses".into()));
        assert_eq!(substitute("plain", &v).unwrap(), "plain");
    }

    #[test]
    fn every_default_compiles_and_names_are_found() {
        let d = defaults();
        for v in VALUES {
            let re = substitute(&format!("^%{{{}}}$", v.name), &d).unwrap();
            assert!(regex::Regex::new(&re).is_ok(), "{}", v.name);
        }
        assert_eq!(named_in("a%{x}b%{y}c%{x}"), ["x", "y"]);
        assert!(d["restricted_extensions"].split(' ').any(|w| w == "sqlite3"));
    }
}

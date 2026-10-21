#!/usr/bin/env python3
"""Convert ModSecurity SecRule directives into an EasyWAF rule set.

Not everything converts, and the point of this tool is to be exact about
which. A WAF rule that looks present but is bypassable is worse than one that
is missing: the missing rule is visible in a coverage report, the bypassable
one is visible only to whoever finds the bypass. So a rule that cannot be
represented faithfully is refused and listed, never approximated into silence.

What converts
    @rx, @pm and @pmFromFile rules, and the operators that are a pattern in
    other words (@streq, @beginsWith, @within…), in the request phases, whose
    variables map onto an EasyWAF zone, whose transformations EasyWAF already
    performs, and whose regex the Rust regex crate can compile. A chain is one
    rule with a condition for each link. A negated operator converts where its
    variable holds one value.

What does not, and why
    a configured     A link comparing with a configured value (%{tx...})
    value or a       other than the lists a policy sets, or with what an
    capture          earlier link captured (TX:1), has no condition to be.
                     @within one of those lists reads the policy's
                     (%{allowed_methods}), and CRS's rules capturing a value to
                     compare with one are written out in LIST_RULES.
                     MATCHED_VARS is the MATCHED zone, a count (&ARGS) a count
                     zone, @eq/@gt/@lt a pattern on the number, and
                     @detectSQLi/@detectXSS libinjection's decodings.
    TX variables     ModSecurity's own scoring machinery. EasyWAF scores in
                     the engine, so these are not needed rather than missing.
    RESPONSE_*       EasyWAF inspects requests.
    phase 3/4/5
    t:sqlHexDecode, t:removeComments, t:hexDecode and the others
    EasyWAF does not apply
                     A rule written against a decoded form is evadable by
                     using the encoding it was supposed to decode, so it is
                     refused rather than shipped looking intact. The forms
                     every value is matched in cover urlDecodeUni,
                     htmlEntityDecode, jsDecode, cssDecode, normalizePath and
                     removeNulls; from the first transformation they do not
                     cover, the rest are named in the rule's `transforms` —
                     cmdLine, replaceComments, removeWhitespace,
                     base64Decode, escapeSeqDecode and the others in
                     EASYWAF_TRANSFORM — and multiMatch with them.
    lookaround,      Rust's regex crate has no (?=) (?!) (?<=) (?<!),
    backreferences   no \\1, no (?>), no possessive quantifiers. There is no
                     rewrite that preserves meaning, so these are refused.

Matching
    Each rule is matched as ModSecurity matches it: its decodings begin with
    `none`, so they start from each value as ModSecurity's parsers hand it
    over, and every transformation it declares follows in order. An exception
    — REQUEST_HEADERS|!REQUEST_HEADERS:Cookie — is one in the zone, and a name
    by pattern — REQUEST_COOKIES:/__utm/ — is one too.

Widening
    A variable no zone holds apart from others — ARGS_GET, the query's
    arguments only — or an exception of a kind no zone takes can only be
    converted by widening what the rule inspects. That does not create a hole
    but does create false positives, so widened rules are left out unless
    --include-widened is given, and are marked in the output when they are
    included.

Scoring
    CRS scores CRITICAL 5 / ERROR 4 / WARNING 3 / NOTICE 2 against a default
    inbound threshold of 5, so one critical rule blocks. EasyWAF's default
    threshold is 10. The severities are carried across unchanged, so set the
    policy's threshold to 5 to get CRS's blocking behaviour; leaving it at 10
    means two critical hits are needed.

Rule ids
    CRS ids collide with EasyWAF's own bundled sets, which use the same OWASP
    numbering, and external_id is unique per policy — importing 930100 beside
    the bundled 930-lfi set would fail. Ids are therefore offset (see
    --id-base) and the original is recorded in each rule's description.
"""

import argparse
import os
import re
import sys
from collections import Counter

# ── Zones ────────────────────────────────────────────────
#
# Each variable as (zone, exact). A zone in the singular reads one value at a
# time, as ModSecurity does, so `^` and `$` mean the same in both and a named
# selector (REQUEST_HEADERS:User-Agent) keeps its name. `exact` is False where
# the zone holds more than the variable: ARGS_GET is the query string's
# arguments, ARG is the body's as well. Zones in the singular need EasyWAF
# 1.2.0; a set using them says so with `requires` in the channel's sets.toml.
ZONE_OF = {
    "REQUEST_URI": ("URL", True), "REQUEST_URI_RAW": ("URL", True),
    "REQUEST_FILENAME": ("PATH", True),
    # The last segment of the path.
    "REQUEST_BASENAME": ("BASENAME", True),
    "QUERY_STRING": ("ARGS", True),
    "ARGS": ("ARG", True), "ARGS_GET": ("ARG", False), "ARGS_POST": ("ARG", False),
    "ARGS_NAMES": ("ARG_NAME", True),
    "ARGS_GET_NAMES": ("ARG_NAME", False), "ARGS_POST_NAMES": ("ARG_NAME", False),
    # Held by ModSecurity for a form or a body of no type it parses, not for
    # JSON, XML or multipart, which it reads as their parts.
    "REQUEST_BODY": ("BODY_UNPARSED", True),
    # The body's length: the body, measured. See link_condition.
    "REQUEST_BODY_LENGTH": ("BODY", True),
    # XML by its XPath, below: /* is the document's text, //@* its attributes'
    # values. Any other path is a part of the document, which XML holds.
    "XML": ("XML", False),
    # An upload's file names, and the names of the fields that carry files —
    # among every argument's name.
    "FILES": ("FILE_NAME", True), "MULTIPART_FILENAME": ("FILE_NAME", True),
    "FILES_NAMES": ("ARG_NAME", False),
    "REQUEST_HEADERS": ("HEADER", True), "REQUEST_HEADERS_NAMES": ("HEADER_NAME", True),
    "REQUEST_COOKIES": ("COOKIE", True), "REQUEST_COOKIES_NAMES": ("COOKIE_NAME", True),
    "REQUEST_METHOD": ("METHOD", True),
    "USER_AGENT": ("HEADER:User-Agent", True),
    # "GET /x HTTP/1.1", and its last word. Both need EasyWAF 1.4.0.
    "REQUEST_LINE": ("REQUEST_LINE", True), "REQUEST_PROTOCOL": ("PROTOCOL", True),
}

def exact_var(var):
    """Whether a variable's zone holds only what the variable does — so that an
    anchor in its pattern means the same place in both."""
    name, _, selector = var.strip().partition(":")
    name = name.upper()
    if name == "XML":
        return selector in ("/*", "//@*", "/@*")
    return ZONE_OF.get(name, ("", True))[1]


# The variables a name after a colon narrows to one value of, and the zone
# that names it the same way; and their names', narrowed by name the same way.
# A name between slashes is a pattern names are matched against, as in
# ModSecurity. Narrowing names, and exceptions, need EasyWAF 1.6.0.
NAMED = {"ARGS": "ARG", "REQUEST_HEADERS": "HEADER", "REQUEST_COOKIES": "COOKIE"}
NAMES_OF = {"ARGS_NAMES": "ARG_NAME", "REQUEST_HEADERS_NAMES": "HEADER_NAME",
            "REQUEST_COOKIES_NAMES": "COOKIE_NAME"}

CASE_TRANSFORMS = {"lowercase", "uppercase"}
# The decodings EasyWAF applies, by ModSecurity's name lowercased. A rule is
# matched as ModSecurity matches it — `none`, each value as parsed, then every
# transformation it declares in order — so each has to be one of these. A
# chain beginning with `none` needs EasyWAF 1.6.0, and a set using one says so
# with `requires`.
EASYWAF_TRANSFORM = {
    "cmdline": "cmdLine", "removewhitespace": "removeWhitespace",
    "compresswhitespace": "compressWhitespace", "replacecomments": "replaceComments",
    "removecommentschar": "removeCommentsChar", "base64decode": "base64Decode",
    "escapeseqdecode": "escapeSeqDecode", "trim": "trim",
    "urldecode": "urlDecode", "urldecodeuni": "urlDecodeUni",
    "htmlentitydecode": "htmlEntityDecode", "jsdecode": "jsDecode", "cssdecode": "cssDecode",
    "removenulls": "removeNulls", "normalizepath": "normalizePath", "normalisepath": "normalizePath",
    "normalizepathwin": "normalizePathWin", "normalisepathwin": "normalizePathWin",
    "lowercase": "lowercase", "utf8tounicode": "utf8toUnicode", "length": "length",
}

SEVERITY_SCORE = {
    "CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2,
    "INFO": 1, "DEBUG": 1, "EMERGENCY": 5, "ALERT": 5,
}

# Constructs the Rust regex crate does not implement. Detected syntactically:
# each is unambiguous enough in a PCRE that a textual match is reliable, and
# the alternative — shipping a pattern that silently fails to compile — is the
# thing being avoided.
UNSUPPORTED_RE = [
    (re.compile(r"\(\?<?[=!]"),        "lookaround"),
    (re.compile(r"\(\?<[A-Za-z_]"),    "named group in PCRE syntax"),
    (re.compile(r"\(\?>"),             "atomic group"),
    (re.compile(r"\\[1-9]"),           "backreference"),
    (re.compile(r"\(\?P=|\\k<"),       "backreference"),
    (re.compile(r"\(\?R\)|\(\?[0-9]\)"), "recursion"),
    (re.compile(r"\\K"),               "\\K"),
    (re.compile(r"\(\?\("),            "conditional"),
    (re.compile(r"\\[hHvV]"),          "\\h/\\v class"),
    (re.compile(r"\(\?#"),             "inline comment group"),
    (re.compile(r"\\[GZ]"),            "\\G/\\Z anchor"),
]

UNSUPPORTED_VARS = {
    "TX", "RESPONSE_BODY", "RESPONSE_HEADERS", "RESPONSE_STATUS",
    "RESPONSE_CONTENT_TYPE", "RESPONSE_PROTOCOL", "GEO", "IP", "SESSION",
    "USER", "MATCHED_VAR", "MATCHED_VAR_NAME", "DURATION",
    "PERF_ALL", "HIGHEST_SEVERITY", "INBOUND_DATA_ERROR", "MULTIPART_STRICT_ERROR",
    "REQBODY_ERROR", "REQBODY_PROCESSOR", "WEBSERVER_ERROR_LOG", "ENV",
    "GLOBAL", "RESOURCE", "UNIQUE_ID", "MULTIPART_UNMATCHED_BOUNDARY",
    "OUTBOUND_DATA_ERROR", "FULL_REQUEST", "FULL_REQUEST_LENGTH",
    "MULTIPART_PART_HEADERS", "ARGS_COMBINED_SIZE", "FILES_COMBINED_SIZE",
}


def join_continuations(text):
    """Fold ModSecurity's backslash line continuations into single lines."""
    return re.sub(r"\\\s*\n\s*", " ", text)


def split_args(line):
    """Split a directive into its arguments, honouring double quotes.

    ModSecurity quotes the operator and the action list, and both routinely
    contain spaces and escaped quotes, so whitespace splitting is not enough.
    """
    out, buf, quoted, esc = [], "", False, False
    for ch in line:
        if esc:
            buf += ch
            esc = False
        elif ch == "\\":
            buf += ch
            esc = True
        elif ch == '"':
            quoted = not quoted
        elif ch.isspace() and not quoted:
            if buf:
                out.append(buf)
                buf = ""
        else:
            buf += ch
    if buf:
        out.append(buf)
    return out


def parse_actions(raw):
    """Parse the action list into a dict, keeping repeated keys as lists."""
    actions, buf, quoted = {}, "", False
    parts = []
    for ch in raw:
        if ch == "'":
            quoted = not quoted
            buf += ch
        elif ch == "," and not quoted:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    if buf:
        parts.append(buf)

    for p in parts:
        p = p.strip()
        if not p:
            continue
        if ":" in p:
            k, v = p.split(":", 1)
            v = v.strip().strip("'")
        else:
            k, v = p, True
        k = k.strip().lower()
        actions.setdefault(k, []).append(v)
    return actions


def parse_rules(text):
    """Yield (variables, operator, actions_dict) for each SecRule."""
    for line in join_continuations(text).split("\n"):
        line = line.strip()
        if not line.startswith("SecRule "):
            continue
        parts = split_args(line)
        if len(parts) < 3:
            continue
        variables, operator = parts[1], parts[2]
        actions = parse_actions(parts[3]) if len(parts) > 3 else {}
        yield variables, operator, actions


def classify_vars(variables):
    """Map a ModSecurity variable list onto the zones a rule names.

    Returns (zone, widened, reason). Several variables become several zones
    joined by `|`, which one rule reads and matches once, as ModSecurity does.
    `widened` marks a rule whose scope grew: a zone that holds more than its
    variable, a selector by regular expression, or an exclusion that cannot be
    expressed.
    """
    zones, widened = [], False
    for var in variables.split("|"):
        var = var.strip()
        if not var:
            continue
        if var.startswith("!"):
            # "Everything except this": a named header, argument or cookie, or
            # names matching a pattern, which an exception in the zone takes
            # out. Any other is kept by inspecting what CRS left out.
            name, _, selector = var[1:].partition(":")
            kind = NAMED.get(name.upper()) or NAMES_OF.get(name.upper())
            if kind and selector and "|" not in selector:
                zones.append(f"!{kind}:{selector}")
            else:
                widened = True
            continue
        if var.upper() == "MATCHED_VARS":
            # The values the link before matched: a zone of its own, read alone.
            if len([v for v in variables.split("|") if v.strip()]) > 1:
                return None, False, "MATCHED_VARS beside other variables, which no zone holds together"
            return "MATCHED", False, None
        if var.startswith("&"):
            # How many of a variable there are: the count of a zone read a
            # value at a time.
            zone, wide, why = classify_vars(var[1:])
            if zone is None or "|" in zone or not re.match(r"^(?:ARG|HEADER|COOKIE|FILE_NAME|XML_ATTR)", zone):
                return None, False, why or f"counts {var[1:]}, which no zone counts"
            widened |= wide
            if "&" + zone not in zones:
                zones.append("&" + zone)
            continue
        name, _, selector = var.partition(":")
        name = name.upper()
        if name in UNSUPPORTED_VARS:
            return None, False, f"variable {name} has no EasyWAF equivalent"
        if name not in ZONE_OF:
            return None, False, f"unknown variable {name}"
        zone, exact = ZONE_OF[name]
        if name == "XML" and selector == "/*":
            zone, exact = "XML", True
        elif name == "XML" and selector in ("//@*", "/@*"):
            zone, exact = "XML_ATTR", True
        elif name == "XML":
            pass
        elif selector and (name in NAMED or name in NAMES_OF) and "|" not in selector:
            # ARGS:foo — one named parameter, which ARG:foo reads; ARGS:/^id_/
            # those whose names match, which ARG:/^id_/ does.
            zone = f"{NAMED.get(name) or NAMES_OF[name]}:{selector}"
        elif selector:
            # ARGS:/^id_/ — names chosen by a pattern. The zone holds them all.
            widened = True
        widened |= not exact
        if zone not in zones:
            zones.append(zone)

    if not zones:
        return None, False, "no usable variable"
    return "|".join(zones), widened, None


def pm_to_regex(operator_arg, base_dir):
    """Turn @pm / @pmFromFile phrase lists into one alternation."""
    phrases = []
    if operator_arg.startswith("@pmFromFile"):
        fname = operator_arg.split(None, 1)[1].strip() if " " in operator_arg else ""
        for cand in (os.path.join(base_dir, fname),
                     os.path.join(base_dir, "..", fname),
                     os.path.join(base_dir, "..", "rules", fname)):
            if os.path.isfile(cand):
                with open(cand, encoding="utf-8", errors="replace") as fh:
                    phrases = [l.strip() for l in fh
                               if l.strip() and not l.startswith("#")]
                break
        else:
            return None, f"phrase file {fname or '?'} not found beside the rules"
    else:
        arg = operator_arg.split(None, 1)[1] if " " in operator_arg else ""
        phrases = [p for p in arg.split() if p]

    if not phrases:
        return None, "phrase list is empty"
    # @pm is a case-insensitive substring match over a phrase set.
    return "(?i)(?:" + "|".join(re.escape(p) for p in phrases) + ")", None


VALID_QUANTIFIER = re.compile(r"\{\d+(?:,\d*)?\}")


def escape_literal_braces(pattern):
    r"""Escape braces that PCRE reads as literal and Rust's regex rejects.

    PCRE treats `{` as an ordinary character when what follows is not a valid
    repetition count — `{{.*?}}` and `\(\s*\)\s+{` both rely on that. Rust's
    regex crate refuses them instead, so five CRS rules compiled under
    ModSecurity and would not have compiled here.

    This is a rewrite, but not an approximation: `\{` matches exactly what a
    literal `{` matched. Character classes are left alone, where a brace is
    already literal in both engines.
    """
    keep = set()
    for m in VALID_QUANTIFIER.finditer(pattern):
        keep.add(m.start())
        keep.add(m.end() - 1)
    # A policy's list, which EasyWAF puts in when it loads the rule.
    for m in re.finditer(r"%\{[a-z_]+\}", pattern):
        keep.add(m.start() + 1)
        keep.add(m.end() - 1)

    out, i, in_class = [], 0, False
    while i < len(pattern):
        ch = pattern[i]
        # `\x{e2}`, `\p{L}`: braces of an escape, which are no brace at all.
        if ch == "\\" and pattern[i + 1:i + 3] in ("x{", "p{", "P{") and "}" in pattern[i:]:
            end = pattern.index("}", i)
            out.append(pattern[i:end + 1])
            i = end + 1
            continue
        if ch == "\\" and i + 1 < len(pattern):
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        if ch in "{}" and not in_class and i not in keep:
            out.append("\\" + ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


# Strings no detection rule should match. Used as a backstop: whatever the
# action list said, a pattern that fires on all of these is not a detection,
# and would score every request on every site using the policy.
BENIGN = ["/index.html", "hello", "id", "1", "en-GB", "application/json"]


def matches_ordinary_traffic(pattern):
    """True when a pattern fires on everything benign thrown at it.

    Python's regex is not Rust's, but for the trivially-broad patterns this is
    meant to catch — `.`, `.*`, `^` — they agree, and a false alarm here costs
    one refused rule rather than a rule that scores every request.
    """
    try:
        rx = re.compile(pattern)
    except re.error:
        return False
    return all(rx.search(b) for b in BENIGN)


COUNTED = re.compile(r"\{\d+(?:,\d*)?\}")


def tokens(pattern):
    """The pattern's tokens outside escapes and classes, with their positions.

    An escape or a character class is skipped whole: a character that means
    something bare is literal behind a backslash or inside brackets.
    """
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            # \x{..}, \p{..} and \u{..} run to the brace.
            if i + 2 < n and pattern[i + 1] in "xpPu" and pattern[i + 2] == "{":
                close = pattern.find("}", i + 3)
                i = n if close < 0 else close + 1
            else:
                i += 2
            yield i, None
            continue
        if ch == "[":
            # A ']' first in a class, or after '^', is literal.
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            i = j + 1
            yield i, None
            continue
        yield i, ch
        i += 1


def is_anchored(pattern):
    """True when the pattern uses `^` or `$` as an anchor."""
    return any(ch is not None and ch in "^$" for _, ch in tokens(pattern))


def has_possessive(pattern):
    """True when a quantifier is made possessive by a `+` after it: `a++`,
    `a*+`, `a?+`, `a{2}+`.

    Read a token at a time, because a character that quantifies when bare is
    literal when escaped or inside a class. `\\?+` is one or more question
    marks and `[*+]` is a star or a plus; a scan for the two characters side by
    side refused both, and with them rules that use neither.
    """
    after_quantifier = False
    previous = None
    for i, ch in tokens(pattern):
        if ch is None:
            after_quantifier = False
        elif ch == "+" and after_quantifier:
            return True
        elif ch in "*+?":
            # `?` opening a group's flags is not a quantifier; after a
            # quantifier it makes it lazy, which Rust supports, and a `+`
            # after that is not possessive.
            after_quantifier = not ((ch == "?" and after_quantifier) or (ch == "?" and previous == "("))
        elif ch == "{" and COUNTED.match(pattern, i):
            after_quantifier = None   # until the closing brace
        elif ch == "}" and after_quantifier is None:
            after_quantifier = True
        elif after_quantifier is not None:
            after_quantifier = False
        previous = ch
    return False


def wide_classes(pattern):
    """A PCRE matching bytes, as one matching characters. A class range running
    to byte 0xff from ASCII — `[\\x7f-\\xff]`, any byte beyond ASCII — is every
    character beyond it. Any other byte beyond ASCII is one byte of a UTF-8
    character, which a pattern on characters never sees: `portable` refuses it."""
    return re.sub(r"(\\x(?:\{[0-7]?[0-9a-fA-F]\}|[0-7][0-9a-fA-F])|\\x\{?80\}?)-\\x(?:\{0*[fF]{2}\}|[fF]{2})",
                  r"\1-\\x{10FFFF}", pattern)


HIGH_BYTE = re.compile(r"\\x(?:\{0*[89a-fA-F][0-9a-fA-F]\}|[89a-fA-F][0-9a-fA-F])")


def portable(pattern):
    """Reject a PCRE the Rust regex crate cannot compile, or one that would
    compile and match something else."""
    if HIGH_BYTE.search(re.sub(r"\\x(?:\{[0-9a-fA-F]+\}|[0-9a-fA-F]{2})-\\x\{10FFFF\}", "", pattern)):
        return "a byte beyond ASCII, one byte of a UTF-8 character where EasyWAF reads characters"
    for rx, why in UNSUPPORTED_RE:
        if rx.search(pattern):
            return why
    if has_possessive(pattern):
        return "possessive quantifier"
    return None


def toml_string(value):
    """Emit a TOML string that survives a regex without re-escaping it."""
    if "'" not in value and "\n" not in value:
        return "'" + value + "'"
    if "'''" not in value and not value.endswith("'"):
        return "'''" + value + "'''"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped + '"'


def _refused(v, o, a, base_dir):
    try:
        link_condition(v, o, a, base_dir)
        return False
    except Refuse:
        return True


class Refuse(Exception):
    """A rule, or one link of a chain, that cannot be converted faithfully."""
    def __init__(self, key, why):
        super().__init__(why)
        self.key, self.why = key, why


# Zones that hold one value, where ModSecurity's negated operator — true for a
# variable whose value does not match — means what a negated condition does:
# no value matches. On a collection the two differ, and are refused.
SINGLE_VALUE = re.compile(r"^(?:METHOD|PATH|BASENAME|URL|ARGS|BODY|XML|REQUEST_LINE|PROTOCOL|MATCHED|&.+|(?:HEADER|ARG|COOKIE):.+)$")


# CRS's configured lists that an EasyWAF policy sets, by CRS's name and the
# policy's. A pattern names the policy's as `%{allowed_methods}`; EasyWAF puts
# in the policy's list when it loads the rule, and CRS's default where the
# policy sets none. They need EasyWAF 1.6.0.
POLICY_LISTS = {
    "allowed_methods": "allowed_methods",
    "allowed_request_content_type": "allowed_content_types",
    "allowed_request_content_type_charset": "allowed_charsets",
    "allowed_http_versions": "allowed_http_versions",
    "restricted_extensions": "restricted_extensions",
    "restricted_headers_basic": "restricted_headers",
}

# CRS's rules that capture a value into a variable and compare the variable
# with a configured list, each as the conditions it comes to — written out,
# since a capture is no condition. Each holds only for the links it was written
# against: a rule CRS has since changed is refused, not converted from the
# rule it was. As (links as (variables, operator), conditions as (zone,
# pattern, negated, and the decodings after `none` where there are any)).
LIST_RULES = {
    # The Content-Type's type, up to its parameters, is not an allowed one.
    "920420": ([("REQUEST_HEADERS:Content-Type", r"@rx ^[^;\s]+"),
                ("TX:content_type", "!@within %{tx.allowed_request_content_type}")],
               [("HEADER:Content-Type", r"^[^;\s]", False),
                ("HEADER:Content-Type", r"(?i)^%{allowed_content_types}(?:[;\s]|$)", True)]),
    # Its first charset is not an allowed one. What comes before the first is
    # text without "charset" in it, as a pattern without lookahead can say it:
    # each "c" that does not go on to spell the word.
    "920480": ([("REQUEST_HEADERS:Content-Type", r"""@rx charset\s*=\s*[\"']?([^;\"'\s]+)"""),
                ("TX:content_type_charset", "!@within %{tx.allowed_request_content_type_charset}")],
               [("HEADER:Content-Type", r"""(?i)charset\s*=\s*["']?[^;"'\s]""", False),
                ("HEADER:Content-Type",
                 r"""(?i)^(?:[^c]|c(?:(?:h(?:a(?:r(?:se?)?)?)?)?c)*(?:[^ch]|h[^ac]|ha[^rc]|har[^sc]|hars[^ec]|harse[^tc]))*"""
                 r"""(?:c(?:(?:h(?:a(?:r(?:se?)?)?)?)?c)*(?:h(?:a(?:r(?:se?)?)?)?)?)?"""
                 r"""charset\s*=\s*["']?%{allowed_charsets}(?:[;"'\s]|$)""", True)]),
    # The path's file extension is a restricted one.
    "920440": ([("REQUEST_BASENAME", r"@rx \.([^.]+)$"),
                ("TX:EXTENSION", "@within %{tx.restricted_extensions}")],
               [("PATH", r"(?i)\.%{restricted_extensions}$", False, ["urlDecodeUni"])]),
    # A header's name is a restricted one.
    "920450": ([("REQUEST_HEADERS_NAMES", "@rx ^.*$"),
                ("TX:/^header_name_920450_/", "@within %{tx.restricted_headers_basic}")],
               [("HEADER_NAME", "(?i)^%{restricted_headers}$", False)]),
}


# Conditions a CRS rule holds under that another rule sets, which a chain of
# its own does not show: 920539 removes 920540 when the body is read as JSON.
# Each holds where the header is absent, as the removal then does not happen.
EXTRA_CONDITIONS = {
    "920540": [("HEADER:Content-Type", r"(?i)^\s*(?:application/json|[^;\s]+\+json)\s*(?:;|$)", True)],
}


def list_rule(rid, links):
    """A LIST_RULES rule's conditions, or Refuse when its links are not the
    ones the conditions were written from."""
    expected, conds = LIST_RULES[rid]
    if [(v.strip(), o.strip()) for v, o, _ in links] != expected:
        raise Refuse("changed upstream", "compares a captured value with a configured list, and its "
                                         "links are not the ones EasyWAF's conditions were written for")
    return [{"zone": c[0], "pattern": c[1], "negate": c[2], "widened": False, "transforms": [],
             "chain": ["none"] + (c[3] if len(c) > 3 else [])}
            for c in conds]


def numeric_pattern(name, n):
    """A comparison with a whole number — @eq, @gt, @ge, @lt, @le — as a
    pattern on a value written in decimal, leading zeros allowed. A count, a
    length and a header holding a number are all written that way."""
    def above(k):
        # Every number greater than k: more digits, or as many and greater at
        # the first digit that differs.
        s = str(k)
        alts = [f"[1-9][0-9]{{{len(s)},}}"]
        for i, c in enumerate(s):
            if c != "9":
                d = int(c) + 1
                cls = "9" if d == 9 else f"[{d}-9]"
                alts.append(s[:i] + cls + (f"[0-9]{{{len(s) - i - 1}}}" if len(s) - i - 1 else ""))
        return alts

    def below(k):
        # Every number less than k, nought included.
        s = str(k)
        alts = [f"[0-9]{{1,{len(s) - 1}}}"] if len(s) > 1 else []
        for i, c in enumerate(s):
            if c != "0" and not (i == 0 and c == "1" and len(s) > 1):
                d = int(c) - 1
                lo = 1 if i == 0 and len(s) > 1 else 0
                cls = str(d) if d == lo else f"[{lo}-{d}]"
                alts.append(s[:i] + cls + (f"[0-9]{{{len(s) - i - 1}}}" if len(s) - i - 1 else ""))
        return alts

    exact = [str(n)]
    alts = {"@eq": exact, "@gt": above(n), "@ge": exact + above(n),
            "@lt": below(n), "@le": exact + below(n)}[name]
    if not alts:
        raise Refuse(f"operator {name}", f"{name} {n}, which no number is")
    return "^0*(?:" + "|".join(alts) + ")$"


def byte_range_pattern(arg):
    """@validateByteRange, which holds for a value with a byte outside the
    ranges, as a pattern finding one: a character class of the ASCII bytes it
    leaves out, and any character beyond ASCII unless it allows every byte
    beyond ASCII. One allowing some of those and not others cannot be said on
    characters, which are several bytes each there."""
    allowed = set()
    for part in arg.split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        if not lo.strip().isdigit() or (hi and not hi.strip().isdigit()):
            raise Refuse("operator @validateByteRange", f"@validateByteRange {arg}, a range this converter does not read")
        allowed |= set(range(int(lo), int(hi or lo) + 1))
    high = allowed & set(range(128, 256))
    if high and high != set(range(128, 256)):
        raise Refuse("operator @validateByteRange",
                     "@validateByteRange allowing some bytes beyond ASCII and not others, which a pattern on "
                     "characters cannot tell apart")
    left_out = [b for b in range(128) if b not in allowed]
    runs, start = [], None
    for b in range(129):
        if b < 128 and b in left_out:
            start = b if start is None else start
        elif start is not None:
            runs.append(f"\\x{start:02x}" if start == b - 1 else f"\\x{start:02x}-\\x{b - 1:02x}")
            start = None
    alternatives = (["[" + "".join(runs) + "]"] if runs else []) + ([] if high else ["[^\\x00-\\x7f]"])
    if not alternatives:
        raise Refuse("operator @validateByteRange", "@validateByteRange allowing every byte, which nothing fails")
    return "|".join(alternatives)


def operator_pattern(op, base_dir):
    """An operator — @rx, @pm, and those that are a pattern in other words —
    as a regex. Refused for one that is not."""
    name, _, arg = op.partition(" ")
    arg = arg.strip()
    listed = re.fullmatch(r"%\{tx\.(\w+)\}", arg)
    if name == "@within" and listed and listed.group(1).lower() in POLICY_LISTS:
        return "^%{" + POLICY_LISTS[listed.group(1).lower()] + "}$"
    if "%{" in arg:
        raise Refuse("a macro", f"{name} compares with a configured value (%{{...}}), which a "
                                "pattern cannot read")
    if name == "@rx":
        return arg
    if name in ("@pm", "@pmFromFile", "@pmf"):
        pattern, why = pm_to_regex(op, base_dir)
        if pattern is None:
            raise Refuse("phrase list", why)
        return pattern
    if name == "@streq":
        return f"^{re.escape(arg)}$"
    if name == "@beginsWith":
        return f"^{re.escape(arg)}"
    if name == "@endsWith":
        return f"{re.escape(arg)}$"
    if name == "@contains":
        return re.escape(arg)
    if name == "@containsWord":
        return rf"\b{re.escape(arg)}\b"
    if name == "@validateByteRange":
        return byte_range_pattern(arg)
    if name == "@within":
        # True when the value is found in the list. Read as one of its words —
        # what lists of methods, versions and types hold — which is stricter
        # than ModSecurity only for a value that is part of a word.
        words = [w for w in re.split(r"[\s|]+", arg) if w]
        if not words:
            raise Refuse("operator @within", "@within an empty list")
        return "^(?:" + "|".join(re.escape(w) for w in words) + ")$"
    if name in ("@eq", "@gt", "@ge", "@lt", "@le") and re.fullmatch(r"\d+", arg):
        return numeric_pattern(name, int(arg))
    if name in ("@detectSQLi", "@detectXSS"):
        # libinjection's verdict is a decoding; any fingerprint is a match.
        return "."
    raise Refuse(f"operator {name or '(none)'}", f"operator {name or '(none)'} has no EasyWAF equivalent")


def zone_string(zone):
    """A zone as TOML: double-quoted, as every zone was before a name could be
    a pattern, unless it holds what would need escaping there."""
    return f'"{zone}"' if not re.search(r'["\\]', zone) else toml_string(zone)


def toml_names(names):
    """A list of names as a TOML array."""
    return "[" + ", ".join(toml_string(n) for n in names) + "]"


def link_condition(variables, operator, actions, base_dir):
    """One SecRule — a rule, or one link of a chain — as the condition it is:
    {zone, pattern, negate, widened, transforms}. Raises Refuse."""
    op = operator.strip()
    negate = op.startswith("!")
    if negate:
        op = op[1:].strip()
    pattern = wide_classes(operator_pattern(op, base_dir))
    if not pattern:
        raise Refuse("empty pattern", "an empty pattern")

    transforms = [t.strip().lower() for t in actions.get("t", []) if t.strip()]
    # t:none clears what came before it.
    if "none" in transforms:
        transforms = transforms[len(transforms) - transforms[::-1].index("none"):]
    unknown = [t for t in transforms if t not in EASYWAF_TRANSFORM]
    if unknown:
        raise Refuse("transformation",
                     f"needs t:{','.join(sorted(set(unknown)))}, which EasyWAF does not "
                     f"apply — the rule would be evadable by that encoding")
    # Matched as ModSecurity matches it: each value as its parser hands it
    # over — `none` — with the rule's transformations applied in order, and
    # with multiMatch before each and after the last.
    chain = ["none"] + (["multiMatch"] if any(k.lower() == "multimatch" for k in actions) else []) \
        + [EASYWAF_TRANSFORM[t] for t in transforms]
    # libinjection reads the value its transformations leave; REQUEST_BODY_LENGTH
    # is the body's length.
    op_name = op.partition(" ")[0]
    if op_name == "@detectSQLi":
        chain.append("detectSQLi")
    elif op_name == "@detectXSS":
        chain.append("detectXSS")
    if variables.strip().upper() == "REQUEST_BODY_LENGTH":
        chain.append("length")

    why = portable(pattern)
    if why:
        raise Refuse(f"regex: {why}", f"regex uses {why}, unsupported by Rust's regex")

    zone, widened, reason = classify_vars(variables)
    if zone is None:
        raise Refuse("variables", reason)
    # A zone that holds more than the variable holds more than one value of
    # it, so an anchor falls somewhere else in it.
    loose = sorted({v.strip().split(":", 1)[0].upper() for v in variables.split("|")
                    if v.strip() and not v.strip().startswith("!") and not exact_var(v)})
    if loose and is_anchored(pattern):
        raise Refuse("anchored", f"anchored with ^ or $ to one value of {loose[0]}, which EasyWAF "
                                 "reads as part of a larger text — the anchor would fall elsewhere "
                                 "in it, and the rule would miss")
    if negate and not SINGLE_VALUE.match(zone):
        raise Refuse("negated on many values",
                     f"negated on {zone}, which holds many values: ModSecurity fires when any one "
                     f"of them fails to match, a negated condition when none matches")

    if any(t in CASE_TRANSFORMS for t in transforms) and not pattern.startswith("(?i)"):
        pattern = "(?i)" + pattern
    return {"zone": zone, "pattern": escape_literal_braces(pattern), "negate": negate,
            "widened": widened, "transforms": transforms, "chain": chain}


def convert(paths, id_base, include_widened, set_id, set_name, max_paranoia=1, score_scale=1, min_paranoia=1):
    rules, skipped, stats = [], [], Counter()
    seen_ids = set()

    for path in paths:
        base_dir = os.path.dirname(os.path.abspath(path))
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()

        pending = list(parse_rules(text))
        at = 0
        while at < len(pending):
            variables, operator, actions = pending[at]
            at += 1
            # A chain's continuations are the SecRules after it, each with no
            # id of their own, for as long as one says `chain` again.
            links = [(variables, operator, actions)]
            while "chain" in links[-1][2] and at < len(pending):
                links.append(pending[at])
                at += 1
            rid = (actions.get("id") or [None])[0]
            msg = (actions.get("msg") or [""])[0]
            label = f"{rid or '?'} {msg}".strip()
            if len(links) > 1:
                stats["chained"] += 1

            if not rid:
                stats["no id"] += 1
                continue

            # CRS paranoia level. Levels above 1 are opt-in upstream: CRS ships
            # at level 1 and an operator raises it deliberately, accepting more
            # false positives for more coverage. Converting them all made 53%
            # of the output always-on rules that CRS itself would not run —
            # which is a false-positive generator wearing a rule set's clothes.
            level = 1
            for tag in actions.get("tag", []):
                m = re.match(r"paranoia-level/(\d)", tag)
                if m:
                    level = int(m.group(1))
            if level > max_paranoia:
                stats[f"paranoia level {level}"] += 1
                skipped.append((label, f"CRS paranoia level {level}; this conversion "
                                       f"takes up to {max_paranoia}, which is what CRS "
                                       f"runs by default"))
                continue
            if level < min_paranoia:
                stats[f"paranoia level {level}"] += 1
                skipped.append((label, f"CRS paranoia level {level}; this conversion takes "
                                       f"{min_paranoia} and up, the lower levels being another set's"))
                continue

            phases = actions.get("phase") or ["2"]
            if str(phases[0]) not in ("1", "2", "request"):
                stats["response phase"] += 1
                skipped.append((label, f"phase {phases[0]} inspects the response"))
                continue

            # A rule that deliberately does not act is bookkeeping, not a
            # detection. CRS 921170 is `@rx .` with pass,nolog,setvar — it
            # matches every parameter name to count them, and the detection is
            # a later rule that reads the count. Converted naively it becomes a
            # rule that scores on every request that has a parameter at all.
            disruptive = {"block", "deny", "drop", "redirect", "proxy"}
            if "pass" in actions and not (disruptive & set(actions)):
                stats["bookkeeping (pass)"] += 1
                skipped.append((label, "pass/setvar bookkeeping, not a detection: it "
                                       "feeds a later rule rather than acting"))
                continue
            if "nolog" in actions and not (disruptive & set(actions)):
                stats["nolog"] += 1
                skipped.append((label, "nolog: not meant to be reported, so not a detection"))
                continue
            if not msg:
                stats["no msg"] += 1
                skipped.append((label, "no msg: nothing to name the rule, so nothing an "
                                       "operator could review it by"))
                continue

            # Each link a condition, all of which must hold — what a chain
            # means.
            try:
                if rid in LIST_RULES:
                    conds = list_rule(rid, links)
                else:
                    conds = [link_condition(v, o, a, base_dir) for v, o, a in links]
            except Refuse as e:
                stats[e.key] += 1
                where = f" (in link {next(n for n, (v, o, a) in enumerate(links, 1) if _refused(v, o, a, base_dir))} of a chain of {len(links)})" if len(links) > 1 else ""
                skipped.append((label, e.why + where))
                continue
            for z, p, n in EXTRA_CONDITIONS.get(rid, []):
                conds.append({"zone": z, "pattern": p, "negate": n, "widened": False, "transforms": [],
                              "chain": ["none"], "absent_holds": True})
            widened = any(c["widened"] for c in conds)
            if widened and not include_widened:
                stats["would widen"] += 1
                skipped.append((label, "would have to inspect more than the original "
                                       "(pass --include-widened to accept that)"))
                continue
            # ModSecurity does not evaluate a variable the request does not
            # have; a negated condition on a named header that is absent holds.
            # So such a link also requires its header to be there.
            for c in list(conds):
                if c["negate"] and not c.get("absent_holds") and re.match(r"^(?:HEADER|ARG|COOKIE):", c["zone"]):
                    conds.append({"zone": c["zone"], "pattern": "^", "negate": False,
                                  "widened": False, "transforms": [], "chain": [], "present": True})
            # A negated condition holds wherever its zone has nothing, so on
            # its own it must read something every request has — the method,
            # the path, the request line — or be paired with its header being present. A rule of
            # negations on a body would fire on every request without one.
            present = {c["zone"] for c in conds if c.get("present")}
            for c in conds:
                if c["negate"] and c["zone"] not in ("METHOD", "PATH", "URL", "REQUEST_LINE", "PROTOCOL") \
                        and not c["zone"].startswith("&") and c["zone"] not in present \
                        and not any(not d["negate"] for d in conds):
                    break
            else:
                c = None
            if c is not None:
                stats["only negated"] += 1
                skipped.append((label, f"only negated conditions, on {c['zone']}, which a request may "
                                       "not have: it would fire on every one that lacks it"))
                continue
            # A rule that fires on ordinary requests is not a detection. Judged
            # on the rule's own patterns as a whole: one link alone — a method —
            # matches ordinary traffic by design, and a negated one cannot be
            # judged on the strings below at all.
            # A rule on a policy's list is judged by the gate, with the lists'
            # defaults: its patterns alone do not say what it matches.
            # A count, a second look at a matched value and libinjection's
            # verdict are judged by the gate too.
            judged = [c for c in conds if not c["negate"] and not c.get("present")]
            special = any("%{" in c["pattern"] or c["zone"].startswith("&") or c["zone"] == "MATCHED"
                          or {"length", "detectSQLi", "detectXSS"} & set(c["chain"]) for c in conds)
            if judged and not special \
                    and all(matches_ordinary_traffic(c["pattern"]) for c in judged):
                stats["matches ordinary traffic"] += 1
                skipped.append((label, "pattern matches ordinary traffic — it would "
                                       "score every request"))
                continue

            severity = (actions.get("severity") or ["WARNING"])[0].upper()
            score = SEVERITY_SCORE.get(severity, 3) * score_scale

            new_id = id_base + int(rid)
            if new_id in seen_ids:
                stats["duplicate id"] += 1
                continue
            seen_ids.add(new_id)

            rules.append({
                "paranoia": level,
                # Without what ModSecurity puts in at logging time — the value
                # that matched — which a rule's name cannot hold.
                "id": new_id, "orig": rid,
                "name": re.sub(r"\s*\(?%\{[^}]*\}\)?", "", msg).strip() or f"ModSecurity {rid}",
                "conds": conds, "score": score,
                "severity": severity, "widened": widened,
                "transforms": sorted({t for c in conds for t in c["transforms"]}),
            })
            stats["converted"] += 1

    out = [
        f"# Converted from ModSecurity by scripts/modsec2easywaf.py.",
        f"#",
        f"# {stats['converted']} rules converted, {len(skipped)} refused. The refusals",
        f"# are not a bug: see the report for each one. A rule that cannot be",
        f"# represented faithfully is left out rather than approximated, because a",
        f"# rule that looks present and is bypassable is worse than a missing one.",
        f"#",
        *([f"# Scores are CRS severities (CRITICAL 5 / ERROR 4 / WARNING 3 / NOTICE 2)",
           f"# against CRS's own threshold of 5. EasyWAF's default is 10, so set this",
           f"# policy's Score Threshold to 5 to reproduce CRS blocking behaviour."]
          if score_scale == 1 else
          [f"# Scores are CRS severities times {score_scale} (CRITICAL {5 * score_scale} / ERROR "
           f"{4 * score_scale} / WARNING {3 * score_scale} / NOTICE {2 * score_scale}),",
           f"# so a policy's threshold of {5 * score_scale} blocks what CRS's threshold of 5 does."]),
        f"#",
        f"# Ids are offset by {id_base} because CRS numbering collides with EasyWAF's",
        f"# own bundled sets. Each rule's description carries its original id.",
        "",
        "[set]",
        f'id      = "{set_id}"',
        f'name    = "{set_name}"',
        "version = 1",
        "",
    ]
    for r in rules:
        note = (f"Converted from ModSecurity rule {r['orig']} "
                f"(severity {r['severity']}, CRS paranoia level {r['paranoia']})")
        if r["transforms"]:
            note += f"; original transforms t:{','.join(r['transforms'])}"
        if r["widened"]:
            note += "; WIDENED — inspects more than the original did"
        first, *more = r["conds"]
        out += [
            "[[rules]]",
            f"id          = {r['id']}",
            f"name        = {toml_string(r['name'][:120])}",
            f"description = {toml_string(note)}",
            f"zone        = {zone_string(first['zone'])}",
            f"pattern     = {toml_string(first['pattern'])}",
        ]
        if first["negate"]:
            out.append("negate      = true")
        if first["chain"]:
            out.append(f"transforms  = {toml_names(first['chain'])}")
        out += [f"score       = {r['score']}", 'action      = "score"', ""]
        for c in more:
            out += ["[[rules.and]]", f"zone    = {zone_string(c['zone'])}", f"pattern = {toml_string(c['pattern'])}"]
            if c["negate"]:
                out.append("negate  = true")
            if c["chain"]:
                out.append(f"transforms = {toml_names(c['chain'])}")
            out.append("")
    return "\n".join(out), skipped, stats


SELF_TEST_CONF = r"""
# Exact: single @rx on one zone.
SecRule REQUEST_URI "@rx (?i)/etc/passwd" \
    "id:100001,phase:2,block,t:none,msg:'LFI',severity:'CRITICAL'"

# Exact: chained — two conditions, both of which must hold.
SecRule ARGS "@rx foo" \
    "id:100002,phase:2,block,chain,msg:'Chained',severity:'ERROR'"
    SecRule REQUEST_HEADERS:User-Agent "@rx bar"

# Refused: a link re-testing the value the first matched.
SecRule ARGS "@rx foo" \
    "id:100016,phase:2,block,chain,msg:'Same value',severity:'ERROR'"
    SecRule MATCHED_VARS|REQUEST_HEADERS "@rx bar"

# Exact: a method not in a list, and a header that must be there and not say x.
SecRule REQUEST_METHOD "!@within GET HEAD POST" \
    "id:100017,phase:1,block,chain,msg:'Method',severity:'CRITICAL'"
    SecRule REQUEST_HEADERS:X-Mode "!@streq safe"

# Refused: negated on many values.
SecRule ARGS "!@rx ^[a-z]+$" \
    "id:100018,phase:2,block,msg:'Negated collection',severity:'ERROR'"

# A transformation EasyWAF applies on request: the rule names it.
SecRule ARGS "@rx /bin/sh" \
    "id:100003,phase:2,t:cmdLine,msg:'RCE',severity:'CRITICAL'"

# The decodings the forms cover, before one they do not, are left to the
# forms; one after it is named too.
SecRule ARGS "@rx union select" \
    "id:100020,phase:2,t:none,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,msg:'SQLi',severity:'CRITICAL'"
SecRule REQUEST_COOKIES "@rx <script" \
    "id:100021,phase:2,t:none,t:base64Decode,t:urlDecodeUni,msg:'XSS in base64',severity:'CRITICAL'"

# A byte range: what it leaves out, found.
SecRule ARGS "@validateByteRange 1-255" \
    "id:100023,phase:2,t:none,t:urlDecodeUni,msg:'Null byte',severity:'CRITICAL'"

# Refused: a transformation EasyWAF does not apply, which is what this case is
# here to check.
SecRule ARGS "@rx 0x41" \
    "id:100019,phase:2,t:none,t:sqlHexDecode,msg:'Hex',severity:'CRITICAL'"

# Refused: lookahead.
SecRule ARGS "@rx (?!safe)attack" \
    "id:100004,phase:2,t:none,msg:'Lookahead',severity:'WARNING'"

# Refused: response phase.
SecRule RESPONSE_BODY "@rx secret" \
    "id:100005,phase:4,t:none,msg:'Leak',severity:'ERROR'"

# libinjection, as a decoding whose fingerprint the pattern finds.
SecRule ARGS "@detectSQLi" \
    "id:100006,phase:2,t:none,t:urlDecodeUni,msg:'SQLi',severity:'CRITICAL'"

# A count, a length, and a second look at the matched value.
SecRule &REQUEST_HEADERS:Host "@eq 0" \
    "id:100024,phase:1,t:none,msg:'No Host',severity:'WARNING'"
SecRule REQUEST_HEADERS:Accept-Encoding "@gt 100" \
    "id:100025,phase:1,t:none,t:lowercase,t:length,msg:'Long Accept-Encoding',severity:'WARNING'"
SecRule ARGS "@rx evil" \
    "id:100026,phase:2,t:none,chain,msg:'Evil with a slash',severity:'CRITICAL'"
    SecRule MATCHED_VARS "@rx /" "t:none"

# Exact: one header, by name, with t:lowercase folded into a flag.
SecRule REQUEST_HEADERS:User-Agent "@rx sqlmap" \
    "id:100007,phase:2,t:lowercase,msg:'Scanner',severity:'NOTICE'"

# Exact: two variables, as one rule reading two zones.
SecRule ARGS|REQUEST_HEADERS "@rx evil" \
    "id:100008,phase:2,t:none,msg:'Two zones',severity:'WARNING'"

# Widened: the query string's arguments alone, which no zone holds apart from
# the body's.
SecRule ARGS_GET "@rx evil" \
    "id:100014,phase:2,t:none,msg:'Widened',severity:'WARNING'"

# Exact: headers chosen by a pattern, less one by name.
SecRule REQUEST_HEADERS:/^x-/|!REQUEST_HEADERS:X-Trace "@rx evil" \
    "id:100022,phase:2,t:none,msg:'Named by pattern',severity:'WARNING'"

# Literal brace: legal in PCRE, rejected by Rust's regex until escaped.
SecRule ARGS "@rx {{.*?}}" \
    "id:100009,phase:2,t:none,msg:'Template',severity:'ERROR'"

# Phrase list.
SecRule REQUEST_HEADERS "@pm nikto nmap" \
    "id:100010,phase:2,t:none,msg:'Tools',severity:'WARNING'"

# Refused: bookkeeping. This is CRS 921170's shape — it matches every
# parameter name to count them, and a later rule reads the count. Converted
# naively it scores on every request that has a parameter.
SecRule ARGS_NAMES "@rx ." \
    "id:100011,phase:2,pass,nolog,setvar:'tx.paramcounter_%{MATCHED_VAR_NAME}=+1'"

# Exact: anchored to one argument's value, which ARG reads. CRS 931120's shape.
SecRule ARGS "@rx ^(?i:https?).*?\?+$" \
    "id:100013,phase:2,block,t:none,msg:'Anchored',severity:'CRITICAL'"

# Refused: anchored to the query string's arguments, which ARG reads together
# with the body's — and widened besides.
SecRule ARGS_GET "@rx ^https?://" \
    "id:100015,phase:2,block,t:none,msg:'Anchored, inexact',severity:'CRITICAL'"

# Refused by the backstop even though it declares itself a detection.
SecRule ARGS "@rx .*" \
    "id:100012,phase:2,block,t:none,msg:'Far too broad',severity:'CRITICAL'"
"""


def self_test():
    """Check the refusals and the two documented rewrites still hold."""
    import tempfile
    failures = []

    def check(cond, what):
        if not cond:
            failures.append(what)

    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(SELF_TEST_CONF)
        path = fh.name
    try:
        toml, skipped, stats = convert([path], 2000000, False, "t", "t")
        refused = {lbl.split()[0] for lbl, _ in skipped}

        check(stats["converted"] == 17, f"expected 17 exact conversions, got {stats['converted']}")
        check("transforms  = ['none', 'urlDecodeUni', 'detectSQLi']" in toml, "@detectSQLi is libinjection's decoding")
        check('zone        = "&HEADER:Host"' in toml and "pattern     = '^0*(?:0)$'" in toml, "a count of nought")
        check("transforms  = ['none', 'lowercase', 'length']" in toml, "t:length is the length decoding")
        check('[[rules.and]]\nzone    = "MATCHED"' in toml, "MATCHED_VARS reads the values matched")
        check(byte_range_pattern("1-255") == r"[\x00]", byte_range_pattern("1-255"))
        check(byte_range_pattern("9,10,13,32-126,128-255") == r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]",
              byte_range_pattern("9,10,13,32-126,128-255"))
        check(byte_range_pattern("32-126") == r"[\x00-\x1f\x7f]|[^\x00-\x7f]", byte_range_pattern("32-126"))
        check("transforms  = ['none', 'cmdLine']" in toml, "t:cmdLine should be named, from the value as parsed")
        check("transforms  = ['none', 'urlDecodeUni', 'replaceComments', 'compressWhitespace']" in toml,
              "every transformation a rule declares should be named, in order")
        check("transforms  = ['none', 'base64Decode', 'urlDecodeUni']" in toml,
              "a decoding after base64Decode should be named")
        check('zone        = "HEADER:/^x-/|!HEADER:X-Trace"' in toml,
              "headers by a pattern, less one, should be one zone with an exception")
        check('[[rules.and]]\nzone    = "HEADER:User-Agent"' in toml, "a chain's second link should be a condition")
        check('negate      = true' in toml and 'pattern = \'^\'' in toml,
              "a negated named header should need the header present")
        check("^(?:GET|HEAD|POST)$" in toml, "@within should be a list of words")
        for rid, why in [("100016", "MATCHED_VARS beside others"), ("100018", "negated collection"),
                         ("100019", "transformation"), ("100004", "lookahead"), ("100005", "response phase"),
                         ("100014", "widening"),
                         ("100011", "pass/setvar bookkeeping"),
                         ("100012", "matches ordinary traffic"),
                         ("100015", "anchored in a zone holding more")]:
            check(rid in refused, f"{rid} ({why}) should have been refused")
        check('zone        = "HEADER:User-Agent"' in toml, "a named header should keep its name")
        check('zone        = "ARG|HEADER"' in toml, "two variables should become one rule reading both")
        check("id          = 2100013" in toml, "an anchor on one argument's value should convert")

        check("'(?i)/etc/passwd'" in toml, "exact pattern not carried through verbatim")
        check("score       = 5" in toml, "CRITICAL should score 5")
        check("id          = 2100001" in toml, "id should be offset by --id-base")
        check("zone        = \"URL\"" in toml, "REQUEST_URI should map to the URL zone")
        # Literal braces escaped so the Rust engine accepts them.
        check(r"\{\{.*?\}\}" in toml, "literal braces should be escaped")
        # @pm becomes one case-insensitive alternation.
        check("nikto|nmap" in toml, "@pm should become an alternation")

        # XML by its XPath: the document's text, and its attributes' values.
        zone_, wide_, _ = classify_vars("ARGS|XML:/*|XML://@*")
        check((zone_, wide_) == ("ARG|XML|XML_ATTR", False), f"XML's two paths should be exact, got {zone_} {wide_}")
        check(classify_vars("XML://book")[1], "another XPath should widen")
        check(classify_vars("FILES|MULTIPART_FILENAME")[0] == "FILE_NAME", "files should read their names")

        # With widening allowed, the pattern selector converts too, and says so.
        wide, _, wstats = convert([path], 2000000, True, "t", "t")
        check(wstats["converted"] == 18, f"expected 18 with widening, got {wstats['converted']}")
        check("WIDENED" in wide, "a widened rule must say so in its description")
        check('zone        = "HEADER"' in wide, "headers chosen by a pattern should widen to every header")
        # Scaled scores, for a policy at EasyWAF's threshold of 10.
        scaled, _, _ = convert([path], 2000000, False, "t", "t", 1, 2)
        check("score       = 10" in scaled, "CRITICAL should score 10 at a scale of 2")

        # t:lowercase becomes a regex flag rather than a lost transformation.
        check("'(?i)sqlmap'" in wide, "t:lowercase should fold into (?i)")

        # Possessive quantifiers are refused, and quantified literals are not:
        # CRS writes `\?+` for one or more question marks.
        for p in ["a++", "a*+", "(?:ab)?+", "x{2,3}+", "[a-z]++"]:
            check(has_possessive(p), f"{p!r} is possessive")
        for p in [r"\?+$", r"\*+", r"\$+", "[*+]", "[?+]+", "a+?", "a*?b+", r"\x{ff}+",
                  "(?i)a+", "a{2}", "a{,b}+"]:
            check(not has_possessive(p), f"{p!r} is not possessive")

        for p in ["^/admin", "x$", "(?:^|&)a=", "a|b$"]:
            check(is_anchored(p), f"{p!r} is anchored")
        for p in [r"\$+", "[^a-z]+", r"\^", "[$]", "a{2}"]:
            check(not is_anchored(p), f"{p!r} is not anchored")
    finally:
        os.unlink(path)

    for f in failures:
        print(f"FAIL: {f}", file=sys.stderr)
    print("self-test: " + ("FAILED" if failures else "passed"), file=sys.stderr)
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="ModSecurity .conf files")
    ap.add_argument("-o", "--out", help="write the rule set here (default: stdout)")
    ap.add_argument("--report", help="write the refusal report here")
    ap.add_argument("--set-id", default="modsec-imported")
    ap.add_argument("--set-name", default="Imported from ModSecurity")
    ap.add_argument("--id-base", type=int, default=2000000,
                    help="offset added to every rule id (default 2000000)")
    ap.add_argument("--include-widened", action="store_true",
                    help="also convert rules whose scope EasyWAF can only widen")
    ap.add_argument("--max-paranoia", type=int, default=1, metavar="N",
                    help="highest CRS paranoia level to convert (default 1, which "
                         "is what CRS itself runs unless told otherwise)")
    ap.add_argument("--min-paranoia", type=int, default=1, metavar="N",
                    help="lowest CRS paranoia level to convert (default 1), for a set holding "
                         "only a higher level's rules")
    ap.add_argument("--score-scale", type=int, default=1, metavar="N",
                    help="multiply CRS's severity scores by N; 2 makes EasyWAF's default "
                         "threshold of 10 block what CRS's 5 does")
    ap.add_argument("--self-test", action="store_true",
                    help="check the refusals and rewrites, then exit")
    args, _ = ap.parse_known_args()
    if args.self_test:
        return self_test()
    args = ap.parse_args()

    toml, skipped, stats = convert(args.files, args.id_base, args.include_widened,
                                   args.set_id, args.set_name, args.max_paranoia,
                                   args.score_scale, args.min_paranoia)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(toml)
    else:
        print(toml)

    lines = ["Rules refused, and why", "=" * 60, ""]
    for label, why in skipped:
        lines.append(f"  {label}\n      {why}\n")
    lines += ["", "Totals", "=" * 60]
    for k, v in stats.most_common():
        lines.append(f"  {v:5d}  {k}")
    lines.append(f"  {len(skipped):5d}  refused in total")
    report = "\n".join(lines)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(report)

    print(f"converted {stats['converted']}, refused {len(skipped)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

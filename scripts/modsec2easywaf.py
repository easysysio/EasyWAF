#!/usr/bin/env python3
"""Convert ModSecurity SecRule directives into an EasyWAF rule set.

Not everything converts, and the point of this tool is to be exact about
which. A WAF rule that looks present but is bypassable is worse than one that
is missing: the missing rule is visible in a coverage report, the bypassable
one is visible only to whoever finds the bypass. So a rule that cannot be
represented faithfully is refused and listed, never approximated into silence.

What converts
    Single (unchained) @rx, @pm and @pmFromFile rules, in the request phases,
    whose variables map onto an EasyWAF zone, whose transformations EasyWAF
    already performs, and whose regex the Rust regex crate can compile.

What does not, and why
    chain            EasyWAF has one pattern per rule. A chain is several
                     conditions that must all hold; keeping only the first
                     would fire on far more than the original.
    @detectSQLi      libinjection. A parser, not a pattern; nothing to port.
    @detectXSS
    TX variables     ModSecurity's own scoring machinery. EasyWAF scores in
                     the engine, so these are not needed rather than missing.
    RESPONSE_*       EasyWAF inspects requests.
    phase 3/4/5
    t:base64Decode, t:escapeSeqDecode, t:sqlHexDecode, t:cmdLine,
    t:replaceComments, t:removeComments, t:removeWhitespace,
    t:normalizePath
                     A rule written against a decoded form is evadable by
                     using the encoding it was supposed to decode, so it is
                     refused rather than shipped looking intact. EasyWAF
                     applies htmlEntityDecode, jsDecode, cssDecode,
                     urlDecodeUni and removeNulls itself, so rules naming
                     those convert.
    lookaround,      Rust's regex crate has no (?=) (?!) (?<=) (?<!),
    backreferences   no \\1, no (?>), no possessive quantifiers. There is no
                     rewrite that preserves meaning, so these are refused.

Widening
    ModSecurity can say "these variables except that one"; EasyWAF's zone is a
    single choice. A rule targeting several zones, or excluding one variable,
    can only be converted by widening what it inspects — which does not create
    a hole but does create false positives, and CRS excludes things like
    REQUEST_HEADERS:Referer precisely because they cause them. Widened rules
    are therefore left out unless --include-widened is given, and are marked
    in the output when they are included.

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
    # The last segment of the path. PATH holds it, and more.
    "REQUEST_BASENAME": ("PATH", False),
    "QUERY_STRING": ("ARGS", True),
    "ARGS": ("ARG", True), "ARGS_GET": ("ARG", False), "ARGS_POST": ("ARG", False),
    "ARGS_NAMES": ("ARG_NAME", True),
    "ARGS_GET_NAMES": ("ARG_NAME", False), "ARGS_POST_NAMES": ("ARG_NAME", False),
    "REQUEST_BODY": ("BODY", True),
    # XML is not parsed, nor is a multipart upload: the body holds them whole.
    "XML": ("BODY", False), "FILES": ("BODY", False),
    "FILES_NAMES": ("BODY", False), "MULTIPART_FILENAME": ("BODY", False),
    "REQUEST_HEADERS": ("HEADER", True), "REQUEST_HEADERS_NAMES": ("HEADER_NAME", True),
    "REQUEST_COOKIES": ("COOKIE", True), "REQUEST_COOKIES_NAMES": ("COOKIE_NAME", True),
    "REQUEST_METHOD": ("METHOD", True),
    "USER_AGENT": ("HEADER:User-Agent", True),
    # "GET /x HTTP/1.1" is no zone; the URL holds its middle.
    "REQUEST_LINE": ("URL", False),
}

# The variables a name after a colon narrows to one value of, and the zone
# that names it the same way.
NAMED = {"ARGS": "ARG", "REQUEST_HEADERS": "HEADER", "REQUEST_COOKIES": "COOKIE"}

# Transformations EasyWAF's own matching already covers, or that map onto a
# regex flag. Anything outside this set changes what the pattern is matched
# against, and is a refusal rather than a warning.
SAFE_TRANSFORMS = {
    "none", "urldecode", "urldecodeuni", "utf8tounicode",
    "removenulls", "compresswhitespace", "trim", "length_none",
    # zone_text applies these in the chains CRS declares, so a rule naming
    # them is matched against the text it was written against.
    "htmlentitydecode", "jsdecode", "cssdecode",
}
CASE_TRANSFORMS = {"lowercase", "uppercase"}

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
    "USER", "MATCHED_VAR", "MATCHED_VARS", "MATCHED_VAR_NAME", "DURATION",
    "PERF_ALL", "HIGHEST_SEVERITY", "INBOUND_DATA_ERROR", "MULTIPART_STRICT_ERROR",
    "REQBODY_ERROR", "REQBODY_PROCESSOR", "WEBSERVER_ERROR_LOG", "ENV",
    "GLOBAL", "RESOURCE", "UNIQUE_ID", "MULTIPART_UNMATCHED_BOUNDARY",
    "REQUEST_PROTOCOL",
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
            # "everything except this" — EasyWAF cannot exclude, so keeping the
            # rule means inspecting what CRS deliberately left out.
            widened = True
            continue
        if var.startswith("&"):
            return None, False, "counts a variable rather than matching it"
        name, _, selector = var.partition(":")
        name = name.upper()
        if name in UNSUPPORTED_VARS:
            return None, False, f"variable {name} has no EasyWAF equivalent"
        if name not in ZONE_OF:
            return None, False, f"unknown variable {name}"
        zone, exact = ZONE_OF[name]
        if selector and name in NAMED and not selector.startswith("/") and "|" not in selector:
            # ARGS:foo — one named parameter, which ARG:foo reads.
            zone = f"{NAMED[name]}:{selector}"
        elif selector and name != "XML":
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
    """Escape braces that PCRE reads as literal and Rust's regex rejects.

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

    out, i, in_class = [], 0, False
    while i < len(pattern):
        ch = pattern[i]
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


def portable(pattern):
    """Reject a PCRE the Rust regex crate cannot compile."""
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


def convert(paths, id_base, include_widened, set_id, set_name, max_paranoia=1):
    rules, skipped, stats = [], [], Counter()
    seen_ids = set()

    for path in paths:
        base_dir = os.path.dirname(os.path.abspath(path))
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()

        chain_depth = 0
        for variables, operator, actions in parse_rules(text):
            rid = (actions.get("id") or [None])[0]
            msg = (actions.get("msg") or [""])[0]
            label = f"{rid or '?'} {msg}".strip()

            # A chained rule's continuations are separate SecRule lines with no
            # id of their own. Swallow them with the rule that started the chain.
            if chain_depth > 0:
                chain_depth -= 1
                continue
            if "chain" in actions:
                chain_depth = 1
                stats["chain"] += 1
                skipped.append((label, "chained: several conditions must all hold"))
                continue

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

            op = operator.strip()
            if op.startswith("!"):
                stats["negated operator"] += 1
                skipped.append((label, "negated operator: fires when it does NOT match"))
                continue

            if op.startswith("@rx"):
                pattern = op[3:].strip()
            elif op.startswith("@pm"):
                pattern, why = pm_to_regex(op, base_dir)
                if pattern is None:
                    stats["phrase list"] += 1
                    skipped.append((label, why))
                    continue
            else:
                name = op.split(None, 1)[0] if op else "(none)"
                stats[f"operator {name}"] += 1
                skipped.append((label, f"operator {name} has no EasyWAF equivalent"))
                continue

            if not pattern:
                stats["empty pattern"] += 1
                continue

            transforms = [t.strip().lower() for t in actions.get("t", [])]
            unsafe = [t for t in transforms
                      if t and t not in SAFE_TRANSFORMS and t not in CASE_TRANSFORMS]
            if unsafe:
                stats["transformation"] += 1
                skipped.append((
                    label,
                    f"needs t:{','.join(sorted(set(unsafe)))}, which EasyWAF does not "
                    f"apply — the rule would be evadable by that encoding"))
                continue

            why = portable(pattern)
            if why:
                stats[f"regex: {why}"] += 1
                skipped.append((label, f"regex uses {why}, unsupported by Rust's regex"))
                continue

            zone, widened, reason = classify_vars(variables)
            if zone is None:
                stats["variables"] += 1
                skipped.append((label, reason))
                continue
            # A zone that holds more than the variable holds more than one
            # value of it, so an anchor falls somewhere else in it.
            loose = sorted({v.strip().split(":", 1)[0].upper() for v in variables.split("|")
                            if v.strip() and not v.strip().startswith("!")
                            and not ZONE_OF.get(v.strip().split(":", 1)[0].upper(), ("", True))[1]})
            if loose and is_anchored(pattern):
                stats["anchored"] += 1
                skipped.append((label, f"anchored with ^ or $ to one value of {loose[0]}, which EasyWAF "
                                       "reads as part of a larger text — the anchor would fall elsewhere "
                                       "in it, and the rule would miss"))
                continue
            if widened and not include_widened:
                stats["would widen"] += 1
                skipped.append((label, "would have to inspect more than the original "
                                       "(pass --include-widened to accept that)"))
                continue

            if any(t in CASE_TRANSFORMS for t in transforms) \
               and not pattern.startswith("(?i)"):
                pattern = "(?i)" + pattern

            if matches_ordinary_traffic(pattern):
                stats["matches ordinary traffic"] += 1
                skipped.append((label, "pattern matches ordinary traffic — it would "
                                       "score every request"))
                continue

            fixed = escape_literal_braces(pattern)
            if fixed != pattern:
                stats["brace escaped"] += 1
                pattern = fixed

            severity = (actions.get("severity") or ["WARNING"])[0].upper()
            score = SEVERITY_SCORE.get(severity, 3)

            new_id = id_base + int(rid)
            if new_id in seen_ids:
                stats["duplicate id"] += 1
                continue
            seen_ids.add(new_id)

            rules.append({
                "paranoia": level,
                "id": new_id, "orig": rid, "name": msg or f"ModSecurity {rid}",
                "zone": zone, "pattern": pattern, "score": score,
                "severity": severity, "widened": widened,
                "transforms": [t for t in transforms if t and t != "none"],
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
        f"# Scores are CRS severities (CRITICAL 5 / ERROR 4 / WARNING 3 / NOTICE 2)",
        f"# against CRS's own threshold of 5. EasyWAF's default is 10, so set this",
        f"# policy's Score Threshold to 5 to reproduce CRS blocking behaviour.",
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
        out += [
            "[[rules]]",
            f"id          = {r['id']}",
            f"name        = {toml_string(r['name'][:120])}",
            f"description = {toml_string(note)}",
            f'zone        = "{r["zone"]}"',
            f"pattern     = {toml_string(r['pattern'])}",
            f"score       = {r['score']}",
            'action      = "score"',
            "",
        ]
    return "\n".join(out), skipped, stats


SELF_TEST_CONF = r"""
# Exact: single @rx on one zone.
SecRule REQUEST_URI "@rx (?i)/etc/passwd" \
    "id:100001,phase:2,block,t:none,msg:'LFI',severity:'CRITICAL'"

# Refused: chained. The continuation below must be swallowed with it.
SecRule ARGS "@rx foo" \
    "id:100002,phase:2,chain,msg:'Chained',severity:'ERROR'"
    SecRule REQUEST_HEADERS:User-Agent "@rx bar"

# Refused: a transformation EasyWAF does not apply, which is what this case is
# here to check.
SecRule ARGS "@rx /bin/sh" \
    "id:100003,phase:2,t:cmdLine,msg:'RCE',severity:'CRITICAL'"

# Refused: lookahead.
SecRule ARGS "@rx (?!safe)attack" \
    "id:100004,phase:2,t:none,msg:'Lookahead',severity:'WARNING'"

# Refused: response phase.
SecRule RESPONSE_BODY "@rx secret" \
    "id:100005,phase:4,t:none,msg:'Leak',severity:'ERROR'"

# Refused: no pattern operator EasyWAF can use.
SecRule ARGS "@detectSQLi" \
    "id:100006,phase:2,t:none,msg:'SQLi',severity:'CRITICAL'"

# Exact: one header, by name, with t:lowercase folded into a flag.
SecRule REQUEST_HEADERS:User-Agent "@rx sqlmap" \
    "id:100007,phase:2,t:lowercase,msg:'Scanner',severity:'NOTICE'"

# Exact: two variables, as one rule reading two zones.
SecRule ARGS|REQUEST_HEADERS "@rx evil" \
    "id:100008,phase:2,t:none,msg:'Two zones',severity:'WARNING'"

# Widened: headers chosen by a pattern, which no zone names.
SecRule REQUEST_HEADERS:/^x-/ "@rx evil" \
    "id:100014,phase:2,t:none,msg:'Widened',severity:'WARNING'"

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

        check(stats["converted"] == 6, f"expected 6 exact conversions, got {stats['converted']}")
        for rid, why in [("100002", "chain"), ("100003", "transformation"),
                         ("100004", "lookahead"), ("100005", "response phase"),
                         ("100006", "@detectSQLi"), ("100014", "widening"),
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

        # With widening allowed, the pattern selector converts too, and says so.
        wide, _, wstats = convert([path], 2000000, True, "t", "t")
        check(wstats["converted"] == 7, f"expected 7 with widening, got {wstats['converted']}")
        check("WIDENED" in wide, "a widened rule must say so in its description")
        check('zone        = "HEADER"' in wide, "headers chosen by a pattern should widen to every header")
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
    ap.add_argument("--self-test", action="store_true",
                    help="check the refusals and rewrites, then exit")
    args, _ = ap.parse_known_args()
    if args.self_test:
        return self_test()
    args = ap.parse_args()

    toml, skipped, stats = convert(args.files, args.id_base, args.include_widened,
                                   args.set_id, args.set_name, args.max_paranoia)

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

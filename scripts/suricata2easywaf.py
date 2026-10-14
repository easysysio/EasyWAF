#!/usr/bin/env python3
"""Convert Suricata HTTP rules — ET Open's — into EasyWAF rule sets.

    suricata2easywaf.py emerging-web_server.rules [...] -o set.rules.toml \\
        --report refused.txt --set-id et-web-server --set-name "..." --since 2015

As with modsec2easywaf.py, the point is to be exact about what converts. A
rule that cannot be represented faithfully is refused and listed, never
approximated into one that looks present and is not.

What is taken
    Rules that alert on HTTP sent to a server (`flow:...to_server`, towards
    $HOME_NET or $HTTP_SERVERS), with Emerging Threats' own sids — 2000000 to
    2799999, which ET licenses under the BSD licence; the GPL and ET Pro ranges
    are left out — created in --since or later. A rule that does not say when it
    was created is taken to be old.

How a rule becomes conditions
    Each sticky buffer (http.uri, http.method, http.request_body, the named
    headers) maps onto an EasyWAF zone. Within a buffer, a content or pcre tied
    to the one before it by distance, within or pcre's R flag is one pattern
    with the gap between; one standing alone is a condition of its own. Every
    condition must hold, which is what Suricata means. A negated content is a
    negated condition. The content marked fast_pattern — the one Suricata looks
    for first, because it is rare — is the rule's first condition, so the
    engine stops at it on almost every request.

What is refused, and why
    flowbits, xbits   state across requests; one request cannot say it
    byte_*, base64_*  arithmetic on bytes, and decoding EasyWAF does not do
    detection_filter  alerts only after a count; a rule is not a counter
    dsize, isdataat, urilen, bsize, stream_size
                      lengths and positions; a condition is a pattern
    strip_whitespace and other transforms EasyWAF does not apply
    http.request_line, http.start, http.protocol, http.stat_code and the
    response buffers
                      no zone holds them
    a pcre on the raw header block, or a header content spanning lines
                      no zone holds header lines with their names
    bytes outside ASCII in a content
                      the engine reads text; such bytes are not there to match
    a pcre Rust's regex cannot compile, or one matching ordinary requests
"""

import argparse
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modsec2easywaf import escape_literal_braces, matches_ordinary_traffic, portable, toml_string  # noqa: E402

BSD_SIDS = range(2000000, 2800000)

# Sticky buffers and the zone each is read in.
BUFFERS = {
    "http.uri": "URL", "http.uri.raw": "URL", "http.method": "METHOD",
    "http.request_body": "BODY", "http.client_body": "BODY", "file.data": "BODY",
    "http.user_agent": "HEADER:User-Agent", "http.host": "HEADER:Host",
    "http.host.raw": "HEADER:Host", "http.cookie": "HEADER:Cookie",
    "http.referer": "HEADER:Referer", "http.content_type": "HEADER:Content-Type",
    "http.accept": "HEADER:Accept", "http.accept_enc": "HEADER:Accept-Encoding",
    "http.accept_lang": "HEADER:Accept-Language", "http.connection": "HEADER:Connection",
    "http.content_len": "HEADER:Content-Length",
    # Read content by content, below: "Name: value" names its header.
    "http.header": "HEADER-BLOCK", "http.header.raw": "HEADER-BLOCK",
    "http.request_header": "HEADER-LINE", "http.header_names": "HEADER-NAMES",
}
# The pre-sticky-buffer spelling, as a modifier after a content.
LEGACY = {
    "http_uri": "http.uri", "http_raw_uri": "http.uri.raw", "http_method": "http.method",
    "http_client_body": "http.request_body", "http_header": "http.header",
    "http_raw_header": "http.header.raw", "http_cookie": "http.cookie",
    "http_user_agent": "http.user_agent", "http_host": "http.host", "http_raw_host": "http.host.raw",
}
NO_ZONE = {"http.request_line", "http.start", "http.protocol", "http.stat_code", "http.stat_msg",
           "http.response_line", "http.response_body", "http.server", "http.location",
           "http.response_header"}
REFUSED = {
    "flowbits": "state across requests (flowbits)", "xbits": "state across requests (xbits)",
    "byte_test": "byte arithmetic", "byte_jump": "byte arithmetic", "byte_extract": "byte arithmetic",
    "byte_math": "byte arithmetic", "base64_decode": "base64 decoding", "base64_data": "base64 decoding",
    "detection_filter": "alerts only after a count", "dsize": "a packet's size", "isdataat": "a position",
    "stream_size": "a stream's size", "noalert": "sets state only",
    "lua": "a script", "luajit": "a script", "pcrexform": "a transform", "strip_whitespace": "a transform",
    "compress_whitespace": "a transform", "dotprefix": "a transform", "xor": "a transform",
    "http_stat_code": "a response", "ja3.hash": "TLS", "tls.sni": "TLS", "dns.query": "DNS",
    "entropy": "a statistic", "tag": "tags a session",
}
# Transforms the engine's forms already cover: every value is matched
# percent-decoded, and a lowercased buffer is a case-insensitive match.
COVERED_TRANSFORMS = {"url_decode", "to_lowercase", "header_lowercase", "strip_pseudo_headers"}
IGNORED = {"msg", "flow", "reference", "classtype", "sid", "rev", "metadata", "target", "priority",
           "threshold", "gid", "fast_pattern", "nocase", "depth", "offset", "distance", "within",
           "startswith", "endswith", "rawbytes", "bsize", "urilen"}

SCORE = {"critical": 10, "major": 10, "minor": 5}

# Rules ET writes to see traffic rather than to catch an attack: a search
# engine's crawler by name, a client library, a policy note. An IDS records
# them; a WAF that took them would score the crawlers a site wants.
NOT_ATTACKS = {"not-suspicious", "policy-violation", "protocol-command-decode", "unknown"}


def pcre_classes(pattern):
    """Escape what PCRE reads as literal inside a character class and Rust
    reads as syntax: a `[` (Rust nests classes), and `&&`, `--` and `~~`
    (Rust's set operations). Not an approximation — each escaped character
    matches what PCRE matched."""
    out, i, depth = [], 0, 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            out.append(pattern[i:i + 2]); i += 2; continue
        if depth == 0:
            if ch == "[":
                depth = 1
                out.append(ch); i += 1
                # A ']' first in a class, or after '^', is a literal.
                if i < len(pattern) and pattern[i] == "^":
                    out.append("^"); i += 1
                if i < len(pattern) and pattern[i] == "]":
                    out.append("\\]"); i += 1
                continue
            out.append(ch); i += 1; continue
        if ch == "[" and pattern[i:i + 2] != "[:":
            out.append("\\["); i += 1; continue
        if ch == "[" :
            end = pattern.find(":]", i)
            out.append(pattern[i:end + 2] if end > 0 else "\\["); i = end + 2 if end > 0 else i + 1; continue
        if ch in "&-~" and pattern[i + 1:i + 2] == ch:
            out.append("\\" + ch + "\\" + ch); i += 2; continue
        if ch == "]":
            depth = 0
        out.append(ch); i += 1
    return "".join(out)


class Refuse(Exception):
    pass


def split_options(body):
    r"""`a:b; c; d:"x;y";` into (key, value) pairs, respecting quotes and `\;`."""
    out, cur, quoted, i = [], [], False, 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            cur.append(body[i:i + 2]); i += 2; continue
        if ch == '"':
            quoted = not quoted
        if ch == ";" and not quoted:
            part = "".join(cur).strip()
            if part:
                k, _, v = part.partition(":")
                out.append((k.strip(), v.strip()))
            cur = []
        else:
            cur.append(ch)
        i += 1
    part = "".join(cur).strip()
    if part:
        k, _, v = part.partition(":")
        out.append((k.strip(), v.strip()))
    return out


def content_bytes(value):
    """A content's value — `"a|3a 20|b"`, maybe negated — as (bytes, negated)."""
    negated = value.startswith("!")
    value = value.lstrip("!").strip()
    if not (value.startswith('"') and value.endswith('"')):
        raise Refuse("a content that is not quoted")
    s, out, i, hexmode = value[1:-1], bytearray(), 0, False
    while i < len(s):
        ch = s[i]
        if ch == "|":
            hexmode = not hexmode; i += 1; continue
        if hexmode:
            if ch.isspace():
                i += 1; continue
            out.append(int(s[i:i + 2], 16)); i += 2; continue
        if ch == "\\" and i + 1 < len(s):
            out.append(ord(s[i + 1])); i += 2; continue
        out.append(ord(ch)); i += 1
    return bytes(out), negated


def literal(data):
    """Bytes as a Rust regex literal. Refused outside ASCII."""
    out = []
    for b in data:
        if b >= 0x80:
            raise Refuse("a content with bytes outside ASCII")
        c = chr(b)
        if c in "\\.+*?()|[]{}^$#&-~":
            out.append("\\" + c)
        elif 0x20 <= b < 0x7f:
            out.append(c)
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def pcre_parts(value):
    """`"/.../flags"`, maybe negated, as (pattern, flags, negated)."""
    negated = value.startswith("!")
    value = value.lstrip("!").strip()
    if not (value.startswith('"') and value.endswith('"')):
        raise Refuse("a pcre that is not quoted")
    s = value[1:-1].replace('\\"', '"').replace("\\;", ";")
    if not s.startswith("/") or s.rfind("/") == 0:
        raise Refuse("a pcre without delimiters")
    end = s.rfind("/")
    return s[1:end], s[end + 1:], negated


def gap(distance, within, length):
    """The gap a relative content allows before it, as a regex."""
    lo = distance or 0
    if lo < 0:
        raise Refuse("a negative distance")
    if within is not None:
        hi = lo + within - length
        if hi < lo:
            raise Refuse("a within shorter than its content")
        return f"(?s:.{{{lo},{hi}}})" if hi > 0 else ""
    return f"(?s:.{{{lo},}}?)" if lo else "(?s:.*?)"


class Piece:
    def __init__(self, regex, relative, negated, fast=False, length=1):
        self.regex, self.relative, self.negated, self.fast, self.length = regex, relative, negated, fast, length


def header_block(data, nocase):
    """A content on the raw header block — `User-Agent: x` — as (zone, regex).
    The block's lines are "Name: value\\r\\n"; a content naming one header
    reads that header's value from its start, and one inside a line reads
    every header's name and value."""
    text = data.decode("ascii")
    m = re.match(r"^(?:\r\n)?([A-Za-z0-9!#$%&'*+.^_`|~-]+):[ \t]?(.*)$", text, re.S)
    if m and "\r\n" not in m.group(2).rstrip("\r\n"):
        value = m.group(2)
        anchored_end = value.endswith("\r\n")
        value = value[:-2] if anchored_end else value
        regex = "^" + literal(value.encode()) + ("$" if anchored_end else "")
        return f"HEADER:{m.group(1)}", f"(?i:{regex})" if nocase else regex
    if "\r" in text or "\n" in text:
        raise Refuse("a header content spanning lines")
    regex = literal(data)
    return "HEADER|HEADER_NAME", f"(?i:{regex})" if nocase else regex


def inbound(head):
    """Whether a rule's header — `alert http SRC SPORT -> DST DPORT` — is about
    requests to this side's servers: towards $HOME_NET or $HTTP_SERVERS, or
    towards any address from anywhere but this side."""
    words = head.split()
    if len(words) < 7 or words[4] != "->":
        return False
    src, dst = words[2], words[5]
    if "$HOME_NET" in dst or "$HTTP_SERVERS" in dst:
        return True
    return dst == "any" and "$HOME_NET" not in src


def length(spec, what):
    """A length keyword's value — `12`, `>100`, `<8`, `4<>10` — as a pattern
    on a whole value."""
    spec = spec.strip()
    m = re.fullmatch(r"(\d+)", spec) or re.fullmatch(r"(\d+)\s*<>\s*(\d+)", spec)
    if m and len(m.groups()) == 1:
        return f"^(?s:.{{{int(m.group(1))}}})$"
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        return f"^(?s:.{{{lo + 1},{hi - 1}}})$"
    m = re.fullmatch(r"([<>])\s*(\d+)", spec)
    if m:
        n = int(m.group(2))
        return f"^(?s:.{{{n + 1},}})$" if m.group(1) == ">" else f"^(?s:.{{0,{max(n - 1, 0)}}})$"
    raise Refuse(f"{what}:{spec}, a length this converter does not read")


def convert_rule(line):
    """One rule line as (sid, rule dict) or raise Refuse."""
    head, _, rest = line.partition("(")
    words = head.split()
    if len(words) < 7 or words[0] != "alert" or words[1] != "http":
        raise Refuse("not an alert on HTTP")
    if not inbound(head):
        raise Refuse("not towards a server")
    opts = split_options(rest[:rest.rindex(")")])
    keys = [k for k, _ in opts]
    flow = dict(opts).get("flow", "")
    if "to_client" in flow or "from_server" in flow or ("to_server" not in flow and "from_client" not in flow):
        raise Refuse("not a request to a server")

    for k in keys:
        if k in REFUSED:
            raise Refuse(REFUSED[k])
        if k in NO_ZONE:
            raise Refuse(f"{k}, which no zone holds")
        if k not in IGNORED and k not in BUFFERS and k not in LEGACY and k not in COVERED_TRANSFORMS \
                and k not in ("content", "pcre"):
            raise Refuse(f"{k}, which this converter does not know")

    buffer, pieces = None, []          # pieces: [(buffer, Piece)]
    last = None                        # the last content's piece, for its modifiers
    mods = {}
    def finish():
        nonlocal last, mods
        if last is None:
            return
        buf, data, negated, fast = last
        if buf is None:
            raise Refuse("a content outside an HTTP buffer")
        nocase = "nocase" in mods
        relative = "distance" in mods or "within" in mods
        if relative and negated:
            raise Refuse("a negated relative content")
        zone = BUFFERS[buf]
        if zone == "HEADER-NAMES":
            name = data.decode("ascii").strip("\r\n")
            if not name or "\r" in name or "\n" in name:
                raise Refuse("a header-names content that is not one name")
            pieces.append(("HEADER_NAME", Piece(f"(?i)^{literal(name.lower().encode())}$", False, negated, fast)))
        elif zone in ("HEADER-BLOCK", "HEADER-LINE"):
            if relative:
                raise Refuse("a relative content on the header block")
            hz, regex = header_block(data if zone == "HEADER-BLOCK" else b"\r\n" + data, nocase)
            pieces.append((hz, Piece(regex, False, negated, fast)))
        else:
            regex = literal(data)
            if nocase:
                regex = f"(?i:{regex})"
            if relative:
                regex = gap(int(mods.get("distance", 0)), int(mods["within"]) if "within" in mods else None,
                            len(data)) + regex
            else:
                lo = int(mods.get("offset", 0))
                if "startswith" in mods:
                    regex = "^" + regex
                elif "depth" in mods:
                    hi = lo + int(mods["depth"]) - len(data)
                    if hi < lo:
                        raise Refuse("a depth shorter than its content")
                    regex = f"^(?s:.{{{lo},{hi}}})" + regex
                elif lo:
                    regex = f"^(?s:.{{{lo},}})" + regex
            if "endswith" in mods:
                regex += "$"
            pieces.append((zone, Piece(regex, relative, negated, fast, len(data))))
            # Suricata does not inspect a buffer the request does not have,
            # so a negated content on a named header holds only where the
            # header is there. In EasyWAF a negated condition on a header that
            # is absent holds; this one says it must be present.
            if negated and zone.startswith("HEADER:"):
                pieces.append((zone, Piece("^", False, False)))
        last, mods = None, {}

    for k, v in opts:
        if k in BUFFERS:
            finish(); buffer = k
        elif k in LEGACY:
            # The pre-sticky spelling modifies the content before it.
            if last is None:
                raise Refuse("a buffer modifier with no content")
            last = (LEGACY[k], last[1], last[2], last[3])
        elif k == "content":
            finish()
            data, negated = content_bytes(v)
            last = (buffer, data, negated, False)
        elif k == "fast_pattern" and last is not None:
            last = (last[0], last[1], last[2], True)
        elif k == "bsize":
            # The length of the whole buffer: a condition of its own.
            finish()
            if buffer is None or BUFFERS[buffer].startswith("HEADER-"):
                raise Refuse("a length on no buffer, or on the header block")
            pieces.append((BUFFERS[buffer], Piece(length(v, "bsize"), False, False)))
        elif k == "urilen":
            finish()
            pieces.append(("URL", Piece(length(v, "urilen"), False, False)))
        elif k in ("nocase", "depth", "offset", "distance", "within", "startswith", "endswith"):
            if last is None:
                raise Refuse(f"{k} with no content")
            mods[k] = v
        elif k == "pcre":
            finish()
            pattern, flags, negated = pcre_parts(v)
            buf = buffer
            for f, b in (("U", "http.uri"), ("I", "http.uri.raw"), ("P", "http.request_body"),
                         ("M", "http.method"), ("C", "http.cookie"), ("V", "http.user_agent"),
                         ("W", "http.host")):
                if f in flags:
                    buf = b
            if "H" in flags or "D" in flags or (buf and BUFFERS.get(buf, "").startswith("HEADER-")):
                raise Refuse("a pcre on the header block")
            unknown = set(flags) - set("ismxUIPMCVWRBGO")
            if unknown:
                raise Refuse(f"pcre flags {''.join(sorted(unknown))}")
            if buf is None:
                raise Refuse("a pcre outside an HTTP buffer")
            why = portable(pattern)
            if why:
                raise Refuse(f"a pcre using {why}")
            pattern = pcre_classes(escape_literal_braces(pattern))
            inline = "".join(f for f in "ismx" if f in flags)
            relative = "R" in flags
            if relative and negated:
                raise Refuse("a negated relative pcre")
            if relative:
                body = pattern[1:] if pattern.startswith("^") else "(?s:.*?)" + f"(?:{pattern})"
                regex = (f"(?{inline}:{body})" if inline else body)
            else:
                regex = f"(?{inline}:{pattern})" if inline else f"(?:{pattern})"
            pieces.append((BUFFERS[buf], Piece(regex, relative, negated)))
    finish()

    if not pieces:
        raise Refuse("nothing to match")
    # Pieces into conditions: a relative piece joins the chain before it in
    # the same zone.
    conds = []      # [zone, regex, negated, fast]
    for zone, p in pieces:
        if p.relative:
            if not conds or conds[-1][0] != zone or conds[-1][2]:
                raise Refuse("a relative match with nothing before it in its buffer")
            conds[-1][1] += p.regex
            conds[-1][3] = conds[-1][3] or p.fast
        elif [zone, p.regex, p.negated] not in [c[:3] for c in conds]:
            # Written once: several negated contents on one header each say
            # that header must be there.
            conds.append([zone, p.regex, p.negated, p.fast])
    for zone, regex, negated, _ in conds:
        why = portable(regex)
        if why:
            raise Refuse(f"a pattern using {why}")
        try:
            re.compile(regex.replace("(?s:", "(?:").replace("(?i:", "(?:"))
        except re.error:
            pass
    positive = [c for c in conds if not c[2]]
    if not positive:
        raise Refuse("only negated conditions")
    # A rule matching an ordinary request on its own conditions is not a
    # detection. Checked on the whole rule, as one condition alone — a method —
    # matches ordinary traffic by design.
    if all(matches_ordinary_traffic(c[1]) for c in positive):
        raise Refuse("matches ordinary traffic")
    # The fast pattern first, so a rule is stopped on almost every request by
    # one search for its rarest string; then the other positive conditions;
    # the negated last.
    conds.sort(key=lambda c: (c[2], not c[3], matches_ordinary_traffic(c[1])))

    meta = dict(opts).get("metadata", "")
    sev = re.search(r"signature_severity (\w+)", meta)
    classtype = dict(opts).get("classtype", "")
    if classtype in NOT_ATTACKS or (sev and sev.group(1).lower() == "informational"):
        raise Refuse(f"not an attack ({classtype or sev.group(1)}): a rule for seeing traffic")
    msg = dict(opts).get("msg", "").strip('"')
    sid = int(dict(opts)["sid"])
    rev = dict(opts).get("rev", "1")
    cves = sorted({v.split(",", 1)[1].strip() for k, v in opts if k == "reference" and v.startswith("cve,")})
    created = re.search(r"created_at (\d{4})", meta)
    return sid, {
        "id": sid,
        "name": msg[3:] if msg.startswith("ET ") else msg,
        "description": f"From ET Open rule {sid} rev {rev}" + (f", {', '.join('CVE-' + c for c in cves)}" if cves else ""),
        "score": SCORE.get(sev.group(1).lower() if sev else "", 5),
        "created": int(created.group(1)) if created else 0,
        "conds": conds,
    }


def convert(paths, since):
    rules, refused, stats = [], [], Counter()
    for path in paths:
        for line in open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line.startswith("alert http"):
                continue
            m = re.search(r"\bsid:\s*(\d+)", line)
            sid = int(m.group(1)) if m else 0
            if sid not in BSD_SIDS:
                stats["not ET's BSD range"] += 1
                continue
            if "to_client" in line or not inbound(line.split("(")[0]):
                stats["not a request to a server"] += 1
                continue
            try:
                sid, rule = convert_rule(line)
            except Refuse as e:
                refused.append((sid, str(e), line[:200]))
                stats[f"refused: {e}"] += 1
                continue
            except (ValueError, KeyError, IndexError) as e:
                refused.append((sid, f"could not be read ({e})", line[:200]))
                stats["refused: could not be read"] += 1
                continue
            if rule["created"] < since:
                stats[f"created before {since}"] += 1
                continue
            rules.append(rule)
            stats["converted"] += 1
    return rules, refused, stats


def write_set(rules, set_id, set_name):
    out = ["[set]", f'id      = "{set_id}"', f'name    = {toml_string(set_name)}', "version = 1", ""]
    for r in sorted(rules, key=lambda r: r["id"]):
        (zone, pattern, negated, _), *more = r["conds"]
        out += ["[[rules]]", f"id          = {r['id']}", f"name        = {toml_string(r['name'][:120])}",
                f"description = {toml_string(r['description'])}", f'zone        = "{zone}"',
                f"pattern     = {toml_string(pattern)}"]
        if negated:
            out.append("negate      = true")
        out += [f"score       = {r['score']}", 'action      = "score"', ""]
        for zone, pattern, negated, _ in more:
            out += ["[[rules.and]]", f'zone    = "{zone}"', f"pattern = {toml_string(pattern)}"]
            if negated:
                out.append("negate  = true")
            out.append("")
    return "\n".join(out)


SELF_TEST = r'''
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER pingback"; flow:established,to_server; http.method; content:"POST"; http.uri; content:"/xmlrpc.php"; nocase; http.request_body; content:"pingback.ping"; nocase; fast_pattern; metadata:created_at 2020_01_01, signature_severity Major; sid:2018277; rev:4;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT chained"; flow:to_server,established; http.uri; content:"/cgi-bin/"; startswith; content:".sh"; distance:0; within:40; pcre:"/\?cmd=[a-z]+/Ri"; reference:cve,2024-0001; metadata:created_at 2024_05_01, signature_severity Critical; sid:2050001; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER header"; flow:to_server; http.header; content:"X-Api-Version|3a 20|${jndi"; nocase; http.header_names; content:!"Referer"; metadata:created_at 2021_12_10, signature_severity Major; sid:2034647; rev:2;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET state"; flow:to_server; flowbits:set,x; http.uri; content:"/a"; metadata:created_at 2020_01_01; sid:2030000; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET old"; flow:to_server; http.uri; content:"/old.php"; metadata:created_at 2009_01_01; sid:2009000; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Bingbot"; flow:to_server; http.user_agent; content:"bingbot"; classtype:not-suspicious; metadata:created_at 2021_05_18, signature_severity Informational; sid:2032981; rev:2;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT cross origin"; flow:to_server; http.uri; content:"/api/admin"; http.referer; content:!"example.com"; metadata:created_at 2023_01_01, signature_severity Major; sid:2059000; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL no date"; flow:to_server; http.uri; content:"/x"; sid:2100001; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"GPL low sid"; flow:to_server; http.uri; content:"/y"; sid:2001; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET outbound"; flow:to_server; http.uri; content:"/beacon"; sid:2040000; rev:1;)
alert http any any -> [$HOME_NET,$HTTP_SERVERS] any (msg:"ET lengths"; flow:to_server; http.method; content:"GET"; http.uri; bsize:12; content:"/admin/x.cgi"; urilen:>8; metadata:created_at 2025_01_01, signature_severity Major; sid:2060001; rev:1;)
'''


def self_test():
    import tempfile
    fails = []
    def check(c, what):
        if not c:
            fails.append(what)
    with tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False) as fh:
        fh.write(SELF_TEST)
        path = fh.name
    try:
        rules, refused, stats = convert([path], 2015)
        by = {r["id"]: r for r in rules}
        check(set(by) == {2018277, 2050001, 2034647, 2060001, 2059000}, f"converted {sorted(by)}")
        co = by.get(2059000)
        check(co and ["HEADER:Referer", "^", False] in [c[:3] for c in co["conds"]],
              "a negated content on a named header should require the header")
        many = convert_rule('alert http any any -> $HOME_NET any (msg:"x"; flow:to_server; http.uri; '
                            'content:"/a"; http.user_agent; content:!"b"; content:!"c"; '
                            'metadata:created_at 2020_01_01, signature_severity Major; sid:2059001; rev:1;)')[1]
        check(sum(c[:3] == ["HEADER:User-Agent", "^", False] for c in many["conds"]) == 1,
              "the header's presence should be one condition, however many negated contents need it")

        ln = by.get(2060001)
        check(ln and any(c[1] == "^(?s:.{12})$" for c in ln["conds"]), "bsize should be a length condition")
        check(ln and any(c[0] == "URL" and c[1] == "^(?s:.{9,})$" for c in ln["conds"]), "urilen:>8")
        p = by.get(2018277)
        check(p and p["conds"][0][0] == "BODY", "the fast pattern should be the first condition")
        check(p and {c[0] for c in p["conds"]} == {"BODY", "URL", "METHOD"}, "three buffers, three conditions")
        ch = by.get(2050001)
        check(ch and len(ch["conds"]) == 1 and ch["conds"][0][1].startswith("^/cgi\\-bin/"),
              "relative contents and an R pcre should be one anchored pattern")
        check(ch and ch["score"] == 10 and "CVE-2024-0001" in ch["description"], "severity and CVE")
        h = by.get(2034647)
        check(h and any(c[0] == "HEADER:X-Api-Version" for c in h["conds"]), "a header content names its header")
        check(h and any(c[0] == "HEADER_NAME" and c[2] for c in h["conds"]), "a negated header name")
        check(h and not any(c[1] == "^" for c in h["conds"]),
              "a negated header-names content should not require a header")
        check(any(s == 2030000 and "flowbits" in why for s, why, _ in refused), "flowbits refused")
        check(any(s == 2032981 and "not an attack" in why for s, why, _ in refused), "a crawler-seeing rule refused")
        check(pcre_classes(r'[^\x22}*?[\x3b\x7c]') == r'[^\x22}*?\[\x3b\x7c]', pcre_classes(r'[^\x22}*?[\x3b\x7c]'))
        check(pcre_classes(r'[a&&b][[:alpha:]x]') == r'[a\&\&b][[:alpha:]x]', pcre_classes(r'[a&&b][[:alpha:]x]'))
        check(pcre_classes(r'[]a][^]b]') == r'[\]a][^\]b]', pcre_classes(r'[]a][^]b]'))
        # A rule without a creation date is taken to be old.
        check(stats["created before 2015"] == 2, "the 2009 and the undated rule should be left out by --since")
        check(stats["not ET's BSD range"] == 1, "a GPL-range sid should be left out")
        check(stats["not a request to a server"] == 1, "an outbound rule should be left out")
        text = write_set(rules, "t", "T")
        check("[[rules.and]]" in text and "negate  = true" in text, "conditions written")
    finally:
        os.unlink(path)
    for f in fails:
        print("FAIL:", f, file=sys.stderr)
    print("self-test: " + ("FAILED" if fails else "passed"), file=sys.stderr)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*")
    ap.add_argument("-o", "--out")
    ap.add_argument("--report")
    ap.add_argument("--set-id", default="et-imported")
    ap.add_argument("--set-name", default="Imported from ET Open")
    ap.add_argument("--since", type=int, default=0, help="only rules ET created in this year or later")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    rules, refused, stats = convert(args.files, args.since)
    text = write_set(rules, args.set_id, args.set_name)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text)
    else:
        print(text)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write("Rules refused, and why\n" + "=" * 60 + "\n\n")
            for sid, why, line in refused:
                fh.write(f"  {sid}\n      {why}\n")
    print(f"converted {stats['converted']}, refused {len(refused)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

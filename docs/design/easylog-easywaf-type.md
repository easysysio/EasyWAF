# Specification — the `easywaf` log type for EasyLog

**Producer:** EasyWAF 0.9.0 onwards.
**Consumer:** EasyLog, as a new log type alongside its existing ones.
**Status:** specification. EasyWAF's side is defined here and is the contract;
EasyLog implements against it.

This document is the whole handover. It defines the wire format, every field,
the parser's obligations, a storage schema and the dashboards worth building.
It is written so an EasyLog implementer needs nothing else.

---

## 1. Why a new type rather than an existing parser

EasyLog can already parse combined-access-log and JSON. Either would ingest
these lines and lose the point of them: **verdict, score, and which rules
fired**. Those three fields are the entire reason a WAF's log differs from a
web server's — "this request was refused, it scored 15, and 942100 and 932001
are why" is not expressible in an access-log line.

## 2. Transport

* **UDP syslog**, one datagram per proxied request, to a host and port
  configured in EasyWAF's `config.toml`.
* Fire and forget. EasyWAF drops lines rather than blocking its request path
  when the queue is full, and counts what it dropped. **EasyLog must not assume
  it receives every request**: gaps are expected under load or when the
  collector is unreachable, and a dashboard should never present a count as a
  complete tally of traffic.
* TCP may be added later for delivery guarantees. The payload will not change.

## 3. Wire format

RFC 3164 framing, `local0.info` (priority 134), then a logfmt payload:

```
<134>Sep  9 10:14:22 easywaf easywaf: ts=2026-09-09T10:14:22Z site=cloud host=cloud.hakim.family client=203.0.113.9 country=DE method=GET path=/index.php status=403 ms=4 verdict=blocked score=15 rules=942100,932001 reason="WAF score 15 ≥ block threshold 10"
```

The syslog header is standard and EasyLog presumably already strips it. Parsing
starts after `easywaf: `.

### Why logfmt

Chosen over JSON deliberately:

* a syslog datagram is size-limited, and logfmt carries less overhead per field;
* it stays readable to a person running `tcpdump` or `logger` during an
  incident, which is when this data is needed;
* fields can be added without breaking a parser that ignores unknown keys.

**EasyLog must ignore unknown keys** rather than reject the line. New fields
will be added — that is the compatibility contract in both directions.

### Escaping rules

* A value containing whitespace, `"` or `=` is wrapped in double quotes.
* Inside quotes, `\` becomes `\\` and `"` becomes `\"`.
* An empty value is emitted as `""`.
* Values are otherwise bare.

`path` and `reason` are **attacker-influenced** and are the fields most likely
to be quoted. A parser that splits naively on spaces will corrupt them and can
be made to forge fields. Split on whitespace *outside quotes*, honouring
backslash escapes.

### Clipping

`path` is clipped to 512 characters and `reason` to 256, each marked with a
trailing `…` (U+2026) when clipped. Clipping is visible on purpose: a truncated
value should not be mistaken for a short one.

---

## 4. Fields

Always present:

| Key | Type | Notes |
|---|---|---|
| `ts` | RFC 3339, UTC, second precision | When the request completed. Prefer this over arrival time; the two differ under load. |
| `site` | string | EasyWAF's own name for the site. Stable; a rename is rare and deliberate. |
| `host` | string | The `Host:` header as received. May differ from `site`. |
| `client` | IPv4 or IPv6 | The resolved client address. Already accounts for trusted proxies, so treat it as authoritative. |
| `method` | string | Uppercase HTTP method. |
| `path` | string | Path and query. Clipped at 512. **Quoted often.** |
| `status` | integer | Status returned *to the client* — 403 for a block, not the upstream's status. |
| `ms` | integer | Milliseconds from arrival to response. |
| `verdict` | enum | See below. The most important field. |

Present only when meaningful:

| Key | Type | Present when |
|---|---|---|
| `country` | ISO 3166-1 alpha-2 | The address resolved to one. Absent for private ranges. |
| `score` | integer | Any rule matched. Absent means no rule matched at all, which is different from a score of 0. |
| `rules` | comma-separated integers | Any rule with a catalogue number matched. Custom rules have no number and are omitted, so `rules` may be absent while `score` is present. |
| `reason` | string | The verdict has an explanation. Quoted. |

### `verdict`

Exactly one of:

| Value | Meaning |
|---|---|
| `passed` | Nothing matched. |
| `scored` | Rules matched, the total stayed under the block threshold, the request was served. **This is normal on an enforcing policy** and is where reconnaissance appears. |
| `challenged` | A CAPTCHA was shown. |
| `blocked` | Refused. `status` is 403. |
| `would_block` | Served, but an enforcing policy would have refused it. Only from a policy in DetectionOnly. |
| `would_challenge` | Served, but an enforcing policy would have challenged it. DetectionOnly only. |

**The distinction that matters for dashboards:** `blocked` is an attack stopped.
`would_block` is an attack **served** because the policy is not enforcing.
`scored` is an attack served because it did not reach the threshold. Presenting
the last two as "handled" would be wrong — they are the ones an operator most
needs to see.

---

## 5. Parser obligations

1. Strip the syslog header; parse from after `easywaf: `.
2. Split on whitespace outside double quotes, honouring `\\` and `\"`.
3. Split each token on the **first** `=` only — values contain `=`.
4. Unquote and unescape quoted values.
5. Ignore unknown keys; do not reject the line.
6. Treat a missing optional key as absent, **not** as zero or empty. `score`
   absent and `score=0` are different facts.
7. Reject a line with no `ts`, `verdict` or `client` as malformed and count it,
   rather than storing a partial row.

---

## 6. Suggested storage

```sql
CREATE TABLE easywaf_events (
    id          INTEGER PRIMARY KEY,
    received_at TIMESTAMP NOT NULL,   -- when EasyLog got it
    ts          TIMESTAMP NOT NULL,   -- when EasyWAF served it
    source_ip   TEXT NOT NULL,        -- which appliance sent it
    site        TEXT NOT NULL,
    host        TEXT,
    client      TEXT NOT NULL,
    country     TEXT,
    method      TEXT,
    path        TEXT,
    status      INTEGER,
    ms          INTEGER,
    verdict     TEXT NOT NULL,
    score       INTEGER,              -- NULL when no rule matched
    rules       TEXT,                 -- as received, comma-separated
    reason      TEXT
);

CREATE INDEX idx_easywaf_ts      ON easywaf_events(ts);
CREATE INDEX idx_easywaf_verdict ON easywaf_events(verdict, ts);
CREATE INDEX idx_easywaf_client  ON easywaf_events(client, ts);
CREATE INDEX idx_easywaf_site    ON easywaf_events(site, ts);
```

Keep `source_ip`: several appliances will send, and "which one refused this"
is a question a fleet asks immediately.

Storing `rules` as text is deliberate for a first implementation — a join table
is better for "top rules" but is a bigger change, and the string answers most
questions with a `LIKE`.

---

## 7. Dashboards worth building

In priority order, because the first two are the ones EasyWAF cannot show
itself.

1. **Verdicts over time**, stacked: passed / scored / challenged / blocked /
   would-block. The shape of an attack is visible here before anything else.
2. **Across appliances** — the same split grouped by `source_ip` and `site`.
   This is the thing a single EasyWAF cannot do and the main reason to ship
   logs at all.
3. **Top rules fired**, by count, filterable by verdict. A rule dominating the
   `scored` bucket against ordinary traffic is a tuning candidate; one
   dominating `blocked` is doing its job.
4. **Top clients**, by count and by blocked count, with country. Feeds the
   allow/block lists EasyWAF gains in 0.10.0.
5. **Top countries**, for policies considering country rules.
6. **Served-but-shouldn't-have**: a panel counting `would_block` +
   `would_challenge`. On a DetectionOnly policy this is the number that
   justifies enforcing; it should be prominent, not buried in a verdict split.

---

## 8. Testing

EasyWAF will emit a known corpus on request for parser tests. Until then, these
lines exercise every rule above and should round-trip exactly:

```
ts=2026-09-09T10:14:22Z site=cloud host=cloud.hakim.family client=203.0.113.9 country=DE method=GET path=/index.php status=200 ms=4 verdict=passed
ts=2026-09-09T10:14:23Z site=cloud host=cloud.hakim.family client=203.0.113.9 country=DE method=GET path=/admin status=200 ms=6 verdict=scored score=4 rules=913015
ts=2026-09-09T10:14:24Z site=api host=api.example client=198.51.100.7 method=POST path="/search?q=a b" status=403 ms=2 verdict=blocked score=15 rules=942100,932001 reason="WAF score 15 ≥ block threshold 10"
ts=2026-09-09T10:14:25Z site=api host=api.example client=198.51.100.7 method=GET path="/x=1&y=\"2\"" status=200 ms=3 verdict=would_block score=12 rules=930011 reason="WAF score 12 ≥ block threshold 10"
ts=2026-09-09T10:14:26Z site=web host=web.example client=2001:db8::1 method=GET path=/ status=200 ms=1 verdict=passed
```

Line 3 has a space inside `path` and an `=` inside `reason`. Line 4 has escaped
quotes inside `path` and is a DetectionOnly verdict. Line 5 is IPv6 with no
`country`, because the address is documentation range and resolves to none.

A parser that handles those five handles the format.

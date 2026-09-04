# Design note — IP allow/block lists, added from Traffic Monitor

Status: planned for **0.11.0** — see [roadmap.md](roadmap.md), after flow logs
(0.9.0) and node configuration sync (0.10.0).

## The case that motivated this

Diagnosing a real false positive in 0.3.1 took a debug-logging session and two
rule fixes. The fastest actual mitigation, the whole time, would have been:
see the blocked row in Traffic Monitor, click "always allow this IP", keep
protection on for everyone else while the rule gets fixed properly. That is
the feature: fix issues on the spot, from the place an admin is already
looking when they notice one.

## Scope: global, not per-policy or per-site

Country rules are per-policy, because "which countries a site trusts" is a
property of that site's security posture. An IP list is a different kind of
fact: a specific attacker's address, or a specific trusted address, is true
regardless of which site it hits or whether that site has a policy attached at
all.

That last part matters concretely: **WAF and country rules both require a
policy** — `WafModule` and `GeoIpModule` return `Pass` outright when
`sites.waf_policy_id` is `NULL`, so a plain reverse-proxy site gets no
protection from either today. An IP blocklist should not inherit that gap. So
both lists are installation-wide and checked unconditionally, independent of
policy assignment, applying to every site.

## The allowlist truly overrides everything

Confirmed requirement: an allowlisted IP bypasses WAF rules and country
blocking, not just the specific rule that happened to fire.

The pipeline's `ModuleDecision::Pass` today only means "this module does not
object" — later modules still run. Making the allowlist win would need a new
verdict that somehow outranks every module's `Drop`, present and future, which
is fragile: the next module added has to remember to respect it too.

Instead, the allowlist is checked **before `Pipeline::run` is called at all**,
in the proxy handler. An allowlisted request never reaches GeoIP or WAF, so the
override is structural rather than a rule the pipeline has to honour — true
regardless of what modules exist now or are added later. The same reasoning
extends to the CAPTCHA challenge: an allowlisted IP is never challenged either,
since it never enters the pipeline that decides that.

The blocklist is checked at the same point, for the policy-less-site reason
above — it needs to work whether or not `pipeline.run` would even do anything
for this site.

## Data model

One table, one row per IP, list membership determined by a type column:

```sql
CREATE TABLE ip_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL UNIQUE,   -- exact IPv4 or IPv6, not a range
    list_type  TEXT    NOT NULL,          -- 'allow' | 'block'
    reason     TEXT,                      -- free text, e.g. "false positive on 942007"
    added_by   TEXT,                      -- username, once 0.5.0 exists
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

`UNIQUE` on `ip` alone, not on `(ip, list_type)` — an address is on at most one
list. Clicking "Allow" on a currently-blocklisted IP moves it (`INSERT …
ON CONFLICT(ip) DO UPDATE`), rather than leaving both entries to disagree about
what should happen.

**v1 is exact addresses, not CIDR ranges.** Traffic Monitor shows exact client
IPs, so one-click matches what is on screen; a CIDR range needs the admin to
decide a prefix length, which is a second decision, not a click. Worth adding
later if a range is what people actually reach for, but it should not block
shipping the exact-match version, which already covers the motivating case.

## Hot path: must be an in-memory cache

Both lists are consulted on every proxied request, so — like the regex cache
and the compiled country database — this cannot be a database query per
request. A `HashSet<IpAddr>` per list (or one map keyed by IP to list type),
held behind the same kind of replaceable cell used for the country database in
0.3.0, rebuilt when an entry is added or removed from the GUI.

## GUI

**One click from Traffic Monitor.** Each row gains two small actions next to
the client IP — Block, Allow — posting the IP and a reason (defaulted to the
row's `block_reason` when blocking, editable). Blocking a live IP is
confirmed, the way disabling a site is; allowing is not, since it only ever
widens access for one address.

**A badge on the IP itself** when it is already on a list, so scanning the log
shows context at a glance rather than risking a duplicate add.

**A dedicated page** (Security Policy → IP Lists, alongside the country-rules
overview from 0.3.0) to view, search, and remove entries — the one-click path
adds them, but removing or auditing what has accumulated needs a real list
view, not just reactive clicks.

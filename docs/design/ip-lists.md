# Design note — IP allow/block lists, added from Traffic Monitor

Status: planned for **0.10.0** — see [roadmap.md](roadmap.md), after users and
roles (0.8.0) and flow logs (0.9.0).

Logging moved ahead of this on 2026-09-09. It costs this release nothing and
buys it something: an IP list refusing a request is exactly the kind of verdict
someone will want explained afterwards, and the flow log is where that
explanation lives.

## What 0.7.0 already did, and what is left

The case that originally motivated this note was a false positive in 0.3.1: the
fastest mitigation would have been to see the blocked row in Traffic Monitor
and click something, keeping protection on for everyone else while the rule got
fixed properly.

**0.7.0 delivered that, for the common instance of it.** A rule that misfires
for one client can be excluded from the row that shows the block — one named
rule, off, for that client, on that site. Most false positives are one rule
misbehaving for one caller, and those no longer need this feature.

What that left is not a smaller version of the same thing. It is four
capabilities an exclusion structurally cannot provide, and the note was
rewritten on 2026-09-08 to say so, so that this release is not built as though
0.7.0 had not happened.

**1. It works where there is no policy — the reason this moved earlier.**
`WafModule` and `GeoIpModule` both return `Pass` outright when
`sites.waf_policy_id` is `NULL`. Rule exclusions live *inside* the WAF module,
so they exist only where a policy exists. A site added as a plain reverse proxy
has no WAF, no country rules, and no way to refuse a single address — and
nothing in the GUI says so — 0.7.1 at least made it visible. That gap is live
in every installation today, and it is what moved this release ahead of load
balancing and export.

**2. Blocking does not exist at all.** An exclusion turns a rule *off*. Nothing
in EasyWAF refuses a client outright, at any scope. That half of this note is
untouched by 0.7.0.

**3. The allowlist bypasses the whole pipeline, structurally.** It is checked
before `Pipeline::run`, so GeoIP and the CAPTCHA challenge are skipped with it.
An exclusion cannot reach outside the module it lives in. Approximating "allow
this address" with exclusions would need one row per rule per site, and a rule
arriving in the next set update would not be covered — an allowlist that
develops holes quietly as the rules it was written against change.

**4. Scope is installation-wide.** A specific attacker's address is true
regardless of which site it hits. An exclusion is per site by design, because a
site is what a false positive is about.

## Scope: global, not per-policy or per-site

Country rules are per-policy, because "which countries a site trusts" is a
property of that site's security posture. An IP list is a different kind of
fact: a specific attacker's address, or a specific trusted address, is true
regardless of which site it hits or whether that site has a policy attached at
all.

That last part matters concretely, and is argued above as the reason this
release moved earlier: WAF and country rules both require a policy, so a plain
reverse-proxy site gets no protection from either. An IP list must not inherit
that gap. Both lists are therefore installation-wide and checked
unconditionally, independent of policy assignment, applying to every site —
including the ones a rule exclusion cannot reach.

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
    added_by   TEXT,                      -- username, once 0.8.0 exists
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

The Traffic Monitor row already carries an *exclude for this IP* control, added
in 0.7.0. This release adds *allow* and *block* beside it rather than inventing
a second place to act, and the row should make the difference legible: excluding
turns one rule off for one client on one site, allowing skips every check on
every site, and blocking refuses the client outright. The widest of the three
should not be the easiest to reach by accident.

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

# Design note — IP allow/block lists, added from Traffic Monitor

Status: the manual half **shipped in 0.10.0**. The published half is scheduled
for **0.12.0** — see [roadmap.md](roadmap.md). Its engine side was built
**2026-09-16** (see *What was built*); the lists repository and
`github2repo.sh --lists` are next.

An earlier version of this line said the published half was already built. A
session did build one before 0.11.0, and it was dropped rather than merged, so
0.12.0 started from the manual half.

The release was split on 2026-09-13, once the manual lists were working. The
matcher, the precedence rule and the enforcement point are shared, so the
published half is a fetch and a verification on top of something already
carrying traffic — and splitting got blocking into production while the channel
was still being designed.

**Published lists were added to this note on 2026-09-12** — see *Published
lists* below. What began as manual entry for an address you had just seen in
Traffic Monitor now also covers addresses you have not seen yet, fetched from a
signed channel. The two halves share one matcher and one precedence rule.

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

**Manual entry stays exact addresses, not CIDR ranges.** Traffic Monitor shows
exact client IPs, so one-click matches what is on screen; a CIDR range needs
the admin to decide a prefix length, which is a second decision, not a click.

**Published lists are ranges, and that is not optional** — every feed worth
carrying is CIDR-native. So the matcher handles ranges from the first release
even though the form does not offer them, and the note's original "exact
addresses only" applies to what an operator can type, not to what the engine
can hold. See *Hot path* below, which this supersedes.

Published entries are **not** rows in `ip_rules`. They arrive as whole files,
are replaced wholesale on every update, and carry a licence and an attribution
that a row cannot. Mixing them into the manual table would also make "remove
this entry" mean two different things — one permanent, one undone by the next
sync.

```sql
CREATE TABLE ip_list_feeds (
    id          TEXT    PRIMARY KEY,      -- 'tor-exits', 'spamhaus-drop', ...
    name        TEXT    NOT NULL,
    description TEXT,
    licence     TEXT,                     -- shown in the GUI, per source
    attribution TEXT,                     -- the credit line the source requires
    version     TEXT,                     -- serial from the manifest
    entries     INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 0,
    response    TEXT    NOT NULL DEFAULT 'challenge',  -- 'challenge' | 'block'
    fetched_at  TEXT,
    error       TEXT
);
```

The ranges themselves live in the mirrored channel files on disk, not in the
database: they are replaced whole, never queried individually, and a few hundred
thousand rows that are deleted and reinserted daily is a cost with no benefit.

## Hot path: must be an in-memory cache

Both lists are consulted on every proxied request, so — like the regex cache
and the compiled country database — this cannot be a database query per
request. Held behind the same kind of replaceable cell used for the country
database in 0.3.0, rebuilt when an entry is added or removed from the GUI and
when a published list is updated.

**A sorted array of ranges with a binary search, not a hash set.** An earlier
draft of this note said `HashSet<IpAddr>`, which is right for the manual lists
and wrong the moment a published list arrives: feeds are CIDR-native, and one
of them alone can carry hundreds of thousands of ranges. A hash set cannot
answer "is this address inside any of these ranges" at all without expanding
them, which for a `/12` is four hundred thousand entries standing in for one.

So: ranges normalised to `(start, end)` as `u128`, sorted and merged once at
load, found by bisection — one comparison per bit of index, independent of how
many lists are enabled. Overlapping and touching blocks are merged, so three
entries describing one `/24` cost one range.

**One array per family, not one mapped space.** An earlier draft of this
section folded IPv4 into v6 so a lookup would be a single search. That is the
opposite of the decision `Cidr::contains` already makes, and for a good reason:
`10.0.0.0/8` would quietly cover `::ffff:10.0.0.1`, which is a wider rule than
the one written down. Two arrays, and the address's own family picks one.

Manual entries go into the same structure as `/32` and `/128` ranges. One
matcher, one code path, and the exact-versus-range distinction stays where it
belongs: in what the form accepts.

## Published lists

Manual entry answers "this address is attacking me now". It cannot answer
"this address is a hijacked netblock that has never been anything else", which
is what a published list is for — the addresses you have not seen yet.

Several **named lists, each switched on or off independently**, each with its
own response. Not one aggregate blob, for reasons that are both practical and
legal:

| List | Source | Licence | Default |
|---|---|---|---|
| Tor exit nodes | Tor Project | CC0 | **Off** — using Tor is not an attack |
| Bad reputation | Spamhaus DROP | free for product use, with attribution | Block |
| Compromised hosts | Emerging Threats `compromised-ips` | GPL-2.0 | Challenge |

Tor is off by default and says why on the page. Blocking Tor is a policy
choice, not a security one, and a WAF that makes it quietly is making somebody
else's decision for them.

**Proxy and VPN addresses are the gap**, and it is a real one. Every credible
dataset is commercial; the free ones are scraped, churn hourly and carry no
terms at all. The nearest honest substitute is hosting and datacenter ranges —
"no human browses from a server" is a strong signal — but the cloud providers'
own published files may not be redistributed (see below), so that list has to
be *derived* from public BGP and RIR data rather than downloaded. That is a
build rather than a fetch, and it is deliberately not in the first release.

### One file per list, never merged

This is the shape the licences require, and it happens to be the shape the GUI
wants anyway.

Spamhaus asks that "the date and © text should remain with the file and data";
Emerging Threats' list is GPL-2.0 and must carry its licence. Merge them into
one blob and both obligations are stripped, producing something that cannot be
licensed to anyone. Kept separate, each file carries its own header:

```
; Spamhaus DROP List 2026/09/12 - (c) 2026 The Spamhaus Project SLU
; https://www.spamhaus.org/drop/drop.txt
```

So the manifest carries `licence` and `attribution` per entry, and the GUI shows
them beside each list — the same treatment DB-IP already gets for the country
database.

### What may and may not be mirrored

Checked on 2026-09-12. Recorded here so nobody researches it twice.

**Mirrorable:**

* **Spamhaus DROP** — free for all use including in a product, requiring credit
  to The Spamhaus Project and that the date and copyright text stay with the
  data. Do not auto-fetch more than once an hour; their own guidance is daily.
* **ET `compromised-ips`** — GPL-2.0, per Emerging Threats' own answer that the
  list is third-party sourced and "free to download and use via GPL 2.0".
* **Tor exit list** — CC0; the Tor Project has waived its rights in the data.

**Not mirrorable:**

* **AWS `ip-ranges.json`** (and, until shown otherwise, Azure and GCP) — the
  licence is explicitly "non-sublicensable, non-transferrable... solely in
  connection with your permitted use of the Services".
* **CINS Army** — download now requires registration and a token, behind a EULA.
* **blocklist.de** — "these files are as they are"; no grant to republish.
* **Team Cymru bogons** — no terms published at all. Silence is not permission;
  it is a question to ask them, and bogons can otherwise be derived from the
  public RIR delegated files.
* **FireHOL ipsets** — an aggregate that explicitly refers licensing back to
  each source. Useful as a map of what exists, not as something to mirror.

**Cannot mirror is not cannot use.** An installation fetching blocklist.de
itself is doing exactly what blocklist.de invites. That is a separate, later
feature — an operator-added feed URL — and it is where the sources with awkward
terms belong. It is not in this release.

### DROP's terms pull both ways

Worth recording rather than discovering again. Spamhaus states that DROP may be
used in a product with attribution, and separately that "nothing in these Terms
shall be construed as granting an assignment or licence of any intellectual
property rights in the DROP Lists", reserving the right to revoke.

Publishing DROP **unmodified, with its header intact, as its own file** is the
reading that satisfies both sentences. Deriving from it, merging it, or
stripping the header is the form that does not.

## The data updates itself; the response does not

Rule sets are never applied automatically, because a bad rule is an outage
across every site using the policy. A published IP list is the same kind of
risk pointed at a different target, and the resolution is to split the two
halves of "applying" it:

* **The data updates automatically.** It is fetched from our own signed
  channel, verified the way rule sets are, and replaced wholesale. Fresh data
  cannot hurt anybody while no list is enabled.
* **The response is a setting.** Off, challenge, or block, per list, chosen by
  the operator. Nothing a list says has any effect until somebody has said what
  it should mean here.

That split is what makes daily automatic updates defensible where automatic
rule application is not. It also matches where the challenge landed in
[auth-gateway.md](auth-gateway.md): a CAPTCHA works as a response to suspicion
because anyone human can pass it, so a misclassified address is a speed bump
rather than a wall. Challenge is the right default for everything except lists
conservative enough that a hit is not really a judgement call.

**The manual allowlist still wins, structurally.** It is checked before
`Pipeline::run` is reached, so an allowlisted address is never matched against
a published list either. An operator who has said "this address is fine" has
overruled every feed, permanently, and no sync can undo it.

**A stale list must say so.** The channel's last check is already shown for
rule updates; each list shows its own fetch time and error the same way. A feed
that silently stopped updating is worse than one that is plainly absent.

## Publishing: the channel and the daily job

The lists travel the road the rule sets already travel — signed manifest, a
SHA-256 per file, verified against a key compiled into EasyWAF — as a fourth
channel beside `debian/`, `redhat/` and `rules/`.

**Aggregation belongs in a lists repository with its own `publish.sh`,** not in
`github2repo.sh`. That script already argues the case for rule sets:

> The rule channel is deliberately built by the rules repository's own
> publish.sh rather than reimplemented here... a second copy of those rules
> living on the repo server is how the two quietly drift apart, and then only
> one of them is right.

So `github2repo.sh` gains a `--lists` mode that does what `--rules` does:
clone, run that repository's `publish.sh`, stage into `lists.new`, rename
atomically. Every reason already written into `publish_rules()` carries over
unchanged — the manifest and its detached signature must land as a matching
pair, and a fresh staging directory means a withdrawn list stops being served
rather than sitting there fetchable.

The lists repository's `publish.sh` owns the same two refusals as the rules
one: never publish unsigned, and never publish changed content whose version
stood still.

**Rebuilt whole every day, never appended.** IP reputation decays — an address
that was a botnet node in March is somebody's home connection by September. A
job that appends produces a list that only grows and quietly accumulates people
who have done nothing wrong. Regenerating from the sources each day makes
removal automatic and makes the entry count mean something.

`version` therefore becomes a serial or a date set by the job, rather than a
number a human chooses when correcting a rule.

**One signing key, and a nightly cron on the repo server.** A second key was
considered, on the grounds that automating a daily signature with the key that
also signs packages widens what a compromise reaches. It is unnecessary here:
`github2repo.sh` already runs on the repo server and already requires that
secret key, so a cron entry calling `--lists` on the same machine adds no
exposure that publishing a rule set by hand does not. A separate key becomes
the right answer only if the job ever moves to CI.

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

**The published lists are a second panel on that page**, one row each: name,
what it covers, how many ranges, when it was last fetched, its licence and
attribution, a switch, and the response it produces. A blocked request names
the list that did it, for the same reason a blocked request has named the rule
since 0.5.5 — a refusal nobody can explain is the one people turn the whole
feature off over.

## What was built

The engine side, 2026-09-16: `src/iplist_feeds.rs`, the matcher in
`src/iplist.rs`, and the second panel on the IP Lists page. Five departures from
the plan above.

**The table holds decisions, not metadata.** Migration 026 keeps `enabled`,
`response` and who changed them — nothing else. Name, description, licence,
attribution, version and entry count are read from the verified manifest in the
mirror. Copying them into rows would give them two sources, one always about to
be stale, and the manifest is already where the licence text has to live.

**Every load verifies, not only every download.** The mirror is not trusted for
being local: the signature and each file's hash are checked again whenever the
matcher is rebuilt, at startup included. A mirror that cannot prove itself loads
nothing, and every list that was switched on says why. That lets through what
the lists would have stopped — deliberately, because the alternative is
enforcing data nobody can vouch for, and the manual lists are untouched either
way. Files are stored under their list id, never under the path the manifest
names, so nothing a channel says chooses where a file is written.

**One update switch.** Settings' existing "check the channel" now covers both
channels. Its reason to be off — no outbound access — is true of both, and two
switches would let an installation that must not reach out forget the second.
The lists get their own URL field.

**Challenge only for a visitor who has not already answered one.** A
challenge-response list turns an otherwise clean verdict into the existing
CAPTCHA flow, after the pipeline, so a request the rules would block is still
blocked. A visitor holding a clearance cookie is left alone: they have shown
what the list asked, and converting their request would also drop whatever a
DetectionOnly policy found on it.

**Precedence is one function.** `Lists::check` decides manual allow, manual
block, published block, published challenge — in that order, whatever order the
lists loaded in — and the request path calls nothing else.

Checked live against a throwaway instance trusting the test key, with a local
channel and upstream: a listed address refused and named in its traffic row,
IPv6 ranges enforced, a challenge list serving the CAPTCHA, the manual allowlist
overruling a published block while the neighbouring address stays refused, a
switched-off list changing nothing, and a tampered mirror with the channel down
enforcing nothing and saying why.


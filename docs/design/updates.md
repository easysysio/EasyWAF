# Design note — updates: signatures, IP lists and the country database

Status: **shipped in 0.13.1**, 2026-09-22 — see *What was built* at the end,
including the one part that needs the publishing side before it does anything.
Yariv's shape, argued out over four turns the same day.

Most of this is not new design. Three of its four parts were specified in
[rule-repository.md](rule-repository.md) for 0.6.0 and never built:

> * **Keep the previous version on disk** so there is a way back.
> * **Offer file upload** for hosts with no outbound access at all.
> * *The country database in the same channel.*

What shipped instead was the half that mattered first — fetch, verify, install
per policy — and the rest was left. This note finishes it and puts the three
kinds of update in one place.

## The gap

**Updates are scattered and one of them is invisible.**

| Kind | Where it is configured today | Applied |
|---|---|---|
| Rule sets (signatures) | Settings → **Rule Updates** | Per policy, by hand |
| Published IP lists | the same panel, under a name that does not mention them | Data refreshes itself; a list is switched on per policy |
| Country database | nowhere — `geoip_db` in `config.toml`, or the copy compiled into the binary | Never |

So an operator looking for "where do updates come from" finds a panel named
after one of the three, and an operator wanting a fresher country database
finds nothing at all — although [geo.rs](../../src/geo.rs) was deliberately
written so the reader can be replaced without a restart, for exactly this.

**And an appliance with no outbound access has no way in.** The switch that
turns checking off is honest about not reaching out, and then there is no
second route: nothing in EasyWAF accepts a file.

## Shape

**One section, Settings → Updates**, with the same three parts in the same
words:

* **Rule sets** — the signed channel, what the mirror holds, when it was last
  checked, and which policies are behind.
* **IP lists** — the same channel, the lists it publishes, and when each was
  last fetched.
* **Country database** — what is in force (the bundled DB-IP Lite, a file from
  the channel, or one an administrator supplied) and its date.

**Data is applied as it arrives; logic waits for a person.** Yariv's rule,
settled 2026-09-22 after a turn of arguing both ways, and it is the split the
risk actually has:

* **IP lists and the country database are applied as soon as they are
  fetched.** Their value *is* freshness — Tor exits turn over in under an hour,
  and a list applied on Monday describes Monday's network by Friday. A refresh
  changes which addresses are on a list; it does not change any decision a
  policy made about what to do with them.
* **Rule sets wait for an administrator.** A new pattern can refuse traffic
  that was fine yesterday, across every site using the policy, and 0.3.1
  shipped two such rules. This is how it already works and it stays.

What guards the automatic half is upstream: every file is checked against the
SHA-256 in a manifest this installation's key signed, and `publish-lists.sh`
refuses to publish a list with fewer entries than its floor, because a source
serving an error page or an empty file is a thing that happens. A list nobody
switched on still does nothing, whatever it contains.

**Two stages, named.** They already exist and are already the right model; the
interface does not say so.

1. **Fetch** — the channel is read, the manifest's signature checked before
   anything is read from it, and each file checked against the SHA-256 that
   signed manifest gives. Verified files land in the mirror beside the
   database: `rules-cache/`, `lists-cache/`. Nothing that fails verification is
   written.
2. **Install** — a set is imported *into a policy*, which is why one policy can
   hold v2 while another has v3. A list is put in force for the installation,
   which is where its ranges are parsed and shared; which policies use it, and
   what they do about it, is theirs and is not touched by an update. The
   country database is one file for the host.

**The copy that was in force is kept, not deleted.** The mirror already stages
a download and renames it into place; keeping the one it replaced costs a
directory and buys the way back the 0.6.0 note asked for — for lists and for
the country database, nearly free. Sets are the harder case and are dealt with
below.

It is also what an operator who wants the automatic half switched off needs: a
fetch that is held rather than applied has to sit somewhere that is not in
force.

## Fetching by hand

**An Update now beside each kind**, because waiting six hours to find out
whether a channel is reachable is not a way to diagnose anything, and because
somebody who has just fixed a proxy or a firewall rule wants to know now.

Where each stands today:

| Kind | Fetch on demand |
|---|---|
| IP lists | **exists** — the button on the IP Lists page; it moves here |
| Rule sets | **the function exists and nothing calls it**: `sync_cache` fetches, verifies and mirrors the channel, and is reachable only from the six-hourly task. There is no route and no button |
| Country database | nothing to press, because there is nothing to press it for yet |

**It says what it found**, in the three words that differ: a newer version is
here, everything is already current, or the channel could not be read and why.
"Nothing happened" is the answer people re-press buttons over.

**It respects the switch.** Pressing Update now on an installation that has
turned checking off is refused rather than quietly overriding it — that switch
is how an installation says it must not reach out at all, and a button that
ignored it would make it a suggestion. The route for those installations is
upload, below, and the refusal should say so rather than just declining.

**What a hand fetch does not do is apply.** It fills the mirror; what happens
next is the split above — lists and the country database go into force, rule
sets wait for somebody. The button's message should not blur the two.

## Upload, for an appliance off the grid

**The same bundle, a different transport.** An operator downloads the channel's
files on a machine that has outbound access and uploads them here.

**Verification does not change.** The manifest's detached signature and every
file's hash are checked exactly as they are for a download — which is what
makes offline upload safe rather than a hole. An uploaded bundle that does not
verify is refused with the same message a bad channel gets.

* Rule sets and IP lists: the manifest, its `.asc`, and the files it names.
* Country database: a `.mmdb`, which is a different case — see below.

Nothing about upload lowers a bar, so nothing about it needs a warning beyond
naming what was verified.

### The country database is two different licences

Recorded in [rule-repository.md](rule-repository.md) and worth repeating,
because the two must not be blurred:

* **DB-IP Lite is CC BY 4.0 and may be mirrored**, so it can travel the signed
  channel like everything else, with the attribution EasyWAF already carries.
* **MaxMind GeoLite2 must not be mirrored.** Its licence forbids
  redistribution. It can only ever be a file an administrator fetches
  themselves and hands to EasyWAF — upload, or `geoip_db` as today.

So the country database has a signed path (DB-IP through the channel) and an
unsigned one (a file the operator chose). The second cannot be verified against
a signature EasyWAF holds, and the interface should say which of the two is in
force rather than implying both are equal.

**Where an uploaded database lives:** beside the database, with the mirrors —
`geo/` next to `easywaf.db` — not in `rules/`, which packages own. `geoip_db`
in `config.toml`, when set, stays the last word: it is a deliberate local
choice, and a file uploaded through the GUI must not silently override what an
operator wrote in a file.

## Status: what each kind says about itself

The page's first job is answering "what is in force here, and how old is it",
for all three, without opening anything. Most of the facts already exist and
are shown in three different places or not at all.

**Rule sets** — per set, and per policy because a set is held by a policy:

| Field | Where it comes from |
|---|---|
| Set, and what it covers | the signed manifest |
| Version in the mirror, and when that manifest was fetched | the manifest; `rule_update_checked` |
| Version each policy holds, and when it was installed | `policy_rule_sets.version`, `installed_at` |
| Behind by | the two compared — which `available()` already does |
| Rules in the set | counted from the file |

**IP lists** — already the richest, and already correct; it moves rather than
changes:

| Field | Where it comes from |
|---|---|
| List, source, licence, attribution | the manifest |
| Version, and entries the publisher counted | the manifest |
| Ranges in force after merging, and lines that would not parse | the load |
| Fetched at, and the error if the last fetch failed | `ip_list_fetched`, `ip_list_error` |
| Which policies use it, and what they do about it | `ip_list_feeds` |

**The country database** — nothing is shown today, and all of it is available:
an `.mmdb` carries its own metadata, which
[maxminddb](https://crates.io/crates/maxminddb) exposes as `database_type`,
`build_epoch`, `description`, `ip_version` and `node_count`.

| Field | Where it comes from |
|---|---|
| Which database — DB-IP Lite, GeoLite2, something else | `metadata.database_type` |
| When it was built | `metadata.build_epoch`, which is the date that matters: a country database is only as good as its last build |
| Where this one came from — compiled in, `geoip_db` in config.toml, fetched from the channel, or uploaded | EasyWAF's own record of which path loaded it |
| Whether it was verified | signed, for the channel; not signed, for a file an operator supplied |
| Addresses it covers | `metadata.ip_version`, `node_count` |

**Age is the fact, so say it as one.** A build date is a date; "built 2026-08-30
(23 days ago)" is the thing somebody is actually checking, and the same applies
to a list fetched three weeks ago on an appliance whose channel has been
unreachable since. Stale is not an error and must not be shouted at, but it
should be legible without arithmetic.

## The notification

**In the menu, because that is where somebody is when they are not looking for
it.** It counts what is waiting for a person, which is rule sets by default —
the two automatic kinds have nothing to wait for unless their switch is off.
Today `available()` computes exactly the right thing — a set is reported
only for a policy that actually holds it, because an update to a set nobody has
installed is not news and reporting it trains people to ignore the notice — and
it is shown on one page. It should carry a count in the navigation, covering
all three kinds: policies behind, lists with a newer version fetched, and a
newer country database.

**Quiet when offline**, as the 0.6.0 note insisted: a channel that cannot be
reached is not a badge, not a banner, and not a log line every six hours. The
badge counts updates that are *here and unapplied*, which is a different fact
from "we could not reach the channel", and the second belongs on the Updates
page where somebody has gone to look.

## Applying: from the policy, or from here

Per policy is where it happens now, and that stays: a set is installed into a
policy, and which policies are behind is a per-policy fact.

**What is missing is the view over all of them.** Settings → Updates should
list every policy that is behind, with what it holds and what is available, and
offer to apply — the same act as the policy's own page, reachable from the
place somebody goes when they are thinking about updates rather than about one
policy.

## Automatic apply, and what it needs first

Yariv asked for an option to apply to every policy automatically. It reverses a
decision this project has held since 0.6.0 — *notify, do not auto-apply* —
so the reasoning is worth writing down rather than quietly flipping.

**Data and logic are not the same risk.**

* **IP lists and the country database are data.** A refreshed list changes
  which addresses are on it; the policy's decision about what to do is
  untouched. This already refreshes automatically and should keep doing so.
* **Rule sets are logic.** A new pattern can refuse traffic that was fine
  yesterday. 0.3.1 shipped two such rules, and they were found by a site
  breaking.

**The missing piece is a way back.** `install_set` overwrites each rule in
place; only the enabled flag survives. There is no previous version anywhere,
so a bad update cannot be undone except by hand, rule by rule — which is
exactly the situation an automatic apply makes more likely and harder to spot.
The 0.6.0 note said *keep the previous version on disk so there is a way back*,
and that is still the prerequisite.

**One switch per kind, defaulting to the split above**, because the three are
not the same risk and an operator should be able to say which they want:

| Switch | Default | What it costs when it goes wrong |
|---|---|---|
| Apply IP lists automatically | **on** | Somebody else's list decides what this WAF refuses, the moment it is published |
| Apply the country database automatically | **on** | A reassignment moves a client into a blocked country |
| Apply rule sets automatically | **off** | A new pattern refuses traffic that was fine yesterday, on every site using the policy |

The first two are on because that is what they are for, and both can be turned
off by an installation with change control that forbids it. The third is off
for the reason this project has held since 0.6.0, and turning it on is the
operator taking responsibility — Yariv's words, 2026-09-22: *"for those that
take responsibility, maybe we can create a setting that will allow automatic
update (after a warning)"*.

**The warning is shown when the switch is turned on, not buried under it**, and
says what that switch costs. The interface's part is making sure somebody knows
what they took on.

**Rule sets keep their prerequisite even so.** `install_set` overwrites each
rule in place and only the enabled flag survives, so there is no previous
version to go back to. Rollback is what turns an automatic apply from a gamble
into a decision, and it is the next thing after this release. Until it exists
the switch for rule sets should say so plainly rather than pretending the three
carry the same risk.

**Proposed sequence:**

1. **0.13.1** — the section, the notification, upload, the country database,
   the central view, held-until-applied for lists, and the three switches,
   all off.
2. **Next** — keep the previous version of a set per policy, so an update can
   be reverted in one click and a diff can be shown before it is applied.
3. **Then** — whether the rule-set switch should also be settable per policy,
   so the applications can track automatically while the public sites do not.

## What 0.13.1 includes

* Settings → **Updates**, replacing Rule Updates, with the three parts.
* **A count in the menu** of updates fetched and not applied, quiet when the
  channel cannot be reached.
* **Three switches** — lists and the country database on, rule sets off — each
  with its warning at the moment it is turned on.
* **The copy that was replaced is kept**, so an applied update can be undone
  for lists and for the country database, and so a held fetch has somewhere to
  wait when the automatic half is switched off.
* **Update now** for each kind, including rule sets, whose fetch exists as a
  function with nothing calling it.
* **Upload** of a signed bundle — rule sets and IP lists — verified exactly as
  a download is.
* **The country database**: what is in force, an update from the signed channel
  where the licence allows it, and upload for a file the operator supplies.
* **The policies that are behind**, listed in one place, with apply.
* No change to what is verified, where mirrors live, or to per-policy install.

## What it does not include

* Automatic apply of rule sets as a default. The switch exists and starts off,
  and until rollback exists it says why.
* Rollback. It is the next thing, and it is what makes the point above
  possible.
* Any change to the publishing side: `github2repo.sh --rules` and `--lists`
  are unaffected, and an uploaded bundle is the same bundle they publish.

## What was built (0.13.1)

**The country database can account for itself.** An `.mmdb` carries its own
metadata and nothing read it, so the one question anybody asks — how old is
this — had no answer in the product. It now reports what it is, when it was
built and how many days ago, what it covers, which of the four paths loaded it,
and whether that path was verified. Where it came from is recorded beside the
file rather than inferred, because a `.mmdb` cannot say whether anybody checked
a signature over it. A database can be swapped in without a restart, which
0.3.0 made possible and nothing had used.

**One page, and the two stages named on it.** Settings → Updates replaced a
panel named after one of the three kinds it governed. The channels and their
switch moved with it, because a setting written from two forms is a setting one
of them resets.

**Update now for each kind**, including rule sets, whose fetch existed as a
function nothing called. It says what it found, and is refused — pointing at
upload — on an installation that has turned checking off.

**Upload takes the same path as a download.** Both channels build their mirror
through one function that takes a manifest, its signature and the files it
names, however they arrived. A bundle missing its signature, carrying a changed
file, or missing a file the manifest names is refused with the reason, and the
mirror is left as it was. The country database is the exception it has to be:
nobody signs those, so an uploaded one is checked for being a database and
recorded as unverified.

**The split holds.** Lists and the country database apply as they arrive; rule
sets wait. Each has a switch, and with lists set to apply by hand a fetch waits
beside the mirror — verified on the way in and again on the way out — while
what is serving traffic stays put. With rule sets set to apply automatically,
every policy holding an updated set is brought up to date on the next check and
each is logged by name.

**The count in the menu** is what has arrived and not been applied, held in
memory because every page draws the navigation, and recounted whenever anything
could have changed it. A channel that cannot be reached is not counted.

### Still to do

**The country database's channel is now published, and nothing fetches it
yet.** The publishing half was built after 0.13.2: `geo/sources.toml` and
`publish-geo.sh` in the rules repository, and a `--geo` mode in
`github2repo.sh`, putting a signed `geo.toml` + `geo/dbip-country-lite.mmdb`
at `https://repo.easysys.io/easywaf/geo` on the same key as everything else.
It refuses rather than mirrors a file that is not a country database, is older
than the one already published, or changed without its version moving — the
last two mattering more here than for lists, because a country database that
goes backwards reads to an installation as an update.

What is left is the client half: a fetch in `geo.rs` alongside
`rules_update` and `iplist_feeds`, verifying the manifest exactly as they do,
and *Update now* stopping saying *"not published to a channel yet: upload one,
or point geoip_db at a file"*. Until then, upload and `geoip_db` are still the
routes that work and the switch for applying it automatically governs nothing —
the difference is that there is now something for the fetch to fetch.

A second thing the channel exposes: **the database compiled into the binary is
built once, when the release is.** The copy in 0.13.x was built 2026-07-01,
which was fresh at 0.11.0 and is a quarter old now. That is an argument for the
client half rather than against the bundled copy — a fresh install should work
offline, and then take a current database at its first check.

**Rollback for rule sets — done in 0.13.2.** The version a policy held is kept
when an update overwrites it, and can be put back from the policy's Rule Sets
page: the rules as they were, what the newer version added deleted, the
recorded version restored. One step, consumed on use.

It does not make automatic apply a *default* — that remains off, and a switch
somebody turns on. What it changes is what turning it on means: an update that
refuses traffic it should not is now a click to undo rather than an evening
spent reconstructing eighteen patterns from memory.

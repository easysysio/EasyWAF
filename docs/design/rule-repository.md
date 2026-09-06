# Design note — rule sets, the update channel, and rule numbering

Status: planned for **0.6.0** — see [roadmap.md](roadmap.md). The numbering
scheme below is in force **now**, because rule ids become public identifiers
the moment a set is published.

## Shape

Rule sets are downloadable units, each covering one kind of protection — SQL
injection, WordPress, and so on — authored in the `EasyWAF-rules` repository and
published to a signed directory in the EasySYS repository alongside the
packages (see *One source of truth* and *Publishing*, below). EasyWAF checks for newer versions, shows a
notification, and applies an update when an administrator asks it to. The
country database travels the same channel.

## Rule numbering

**EasyWAF follows OWASP CRS numbering, and ids are globally unique across every
set.** That is the whole collision-avoidance mechanism: two sets must never
issue the same id, and the existing unique index on
`waf_rules(policy_id, external_id)` is correct precisely because of it.

Current allocation:

| Range | Set | File |
|---|---|---|
| 913xxx | Scanner and automated tool detection | `913-scanners.rules.toml` |
| 920xxx | Protocol enforcement | `920-protocol.rules.toml` |
| 930xxx | Local file inclusion | `930-lfi.rules.toml` |
| 931xxx | Remote file inclusion | `931-rfi.rules.toml` |
| 932xxx | Remote code execution | `932-rce.rules.toml` |
| 933xxx | PHP injection | `933-php.rules.toml` |
| 941xxx | Cross-site scripting | `941-xss.rules.toml` |
| 942xxx | SQL injection | `942-sqli.rules.toml` |

CRS itself occupies up to roughly 980000, so **EasyWAF-specific sets that have
no CRS counterpart — WordPress, and whatever follows — must be allocated a band
outside that**, recorded in this table before the set is written. A band chosen
at authoring time is a band that will eventually collide with CRS as CRS grows.

Two corrections were made while only this repository held the data:

* `931100` in `932-rce.rules.toml` became `932012`. An RCE rule carrying an RFI id.
* `990xxx` scanner rules became `913xxx`, CRS's actual scanner-detection
  category, and the file was renamed to match.

Both were cheap here and would not have been later: `external_id` is how an
update finds the rule it is replacing, so changing one after publication leaves
an orphan in every policy that imported the old id.

## Set membership is recorded, not derived

It is tempting to infer a rule's set from its range — `942xxx` means SQLi — and
that inference is already wrong in this repository's own history: rule `931100`
sat in the RCE file until it was corrected above. Someone copies a rule between
files, keeps the id, and the arithmetic quietly disagrees with reality.

So a `rule_set` column records the set a rule was imported from, populated at
import from the file's `[set] id`. It is a stored fact, not a namespacing
device: **no change to the unique index, no compound keys.** It exists so that
"the SQLi set has an update, here are its rules in this policy" can be answered
without encoding a range table in SQL.

## Imported rules are immutable; customizing means cloning

An imported rule (`external_id IS NOT NULL`) cannot have its `pattern`,
`score`, `action`, `zone` or `description` edited. Today it can:
[`post_rule_update_global`](../../src/routes/rules.rs) writes those fields to
any rule by id with no check on where it came from — a real gap independent of
whether update-checking ever ships, since the thing an update would need to
protect (a deliberate customization) already has no protection today.

Wanting to change an imported rule means **cloning** it: a new row is created
with the same content, `external_id` cleared, and the rule free to edit from
that point on exactly like a hand-written custom rule. The two are then
indistinguishable in the editor — a clone is not a special kind of rule, it is
an ordinary custom rule that happened to start from an imported one.

This makes drift structurally impossible instead of something to detect at
update time. There is no comparison to run, no "was this touched" question,
and no case where the detection itself could be wrong: an imported row cannot
diverge from what was imported, because nothing can write to its content but
the importer.

**`enabled` stays a free toggle regardless.** Turning a rule off is a
subscription decision, not a content edit —
[`post_rule_toggle_global`](../../src/routes/rules.rs) already touches only
that column and needs no change. An administrator who dislikes an imported
rule can disable it, clone and edit it, or both: disable the original and
enable their own version. All three are ordinary uses of controls that already
exist.

**A clone remembers where it came from, informationally.** Two columns record
the fork point:

```sql
ALTER TABLE waf_rules ADD COLUMN cloned_from_external_id INTEGER;
ALTER TABLE waf_rules ADD COLUMN cloned_from_version     INTEGER;
```

set only on a clone, to the source rule's `external_id` and the rule set's
version at the moment of cloning. `rule_set` (below) is copied onto the clone
too, so a custom rule still shows which set it descends from. None of this
feeds a merge — it exists only so an update notification can also say "your
custom rule was forked from SQLi v2; the set is now on v4", a nudge for a
human to look at, never an automatic action.

**Open question, not a blocker:** what happens to an imported rule a later set
version removes entirely — left in place as a harmless orphan, or flagged
retired in the UI. Worth deciding at implementation time.

## One source of truth: the rules repository

`EasyWAF-rules` is authoritative. The `rules/` directory shipped alongside the
binary is a **snapshot taken at release**, not a parallel copy anyone edits, and
`git` is what records why a pattern is the way it is.

This is settled first because the alternative has already gone wrong once. The
`Accept: */*` false positive lived in two copies of the same rule — the TOML
catalogue and a hard-coded list in `routes/rules.rs`. One was corrected when it
was found; the other was not, so which button an operator pressed decided
whether every request scored 3 for a header every HTTP client sends. It went
unnoticed for four releases. Introducing the repository makes a **third** place
the same rule could live, and three copies fail the same way two did, sooner.

So:

* **`EasyWAF-rules` holds the sets.** Edits happen there and nowhere else.
* **`EasyWAF/rules/*.toml` is generated**, copied in at release time from a
  pinned commit of the rules repository, and the release records which commit.
  A rule shipped in a binary can then always be traced to the change that wrote
  it.
* **`seed_default_rules` is deleted.** Those 22 hard-coded rules are the second
  copy that caused the problem; the Seed button becomes an import of the bundled
  snapshot, so seeding and importing can no longer disagree. Nothing else needs
  them: any installation that has imported the catalogue already has better
  versions of all 22.

**A corollary worth stating, because 0.5.4 had to work around it.** Import skips
any `external_id` already present, so a corrected rule never reaches an
installation that has already imported it. That is the right behaviour for
*adding* a set and the wrong behaviour for *updating* one, and 0.6.0 is where
the difference gets a mechanism instead of a migration. Until it exists, a rule
correction has to be shipped as SQL that rewrites the exact pattern EasyWAF
published, matching nothing an operator has edited — which is what migration 012
does, and which does not scale past a handful.

## Bundling: basic sets, taken from the channel

`sets.toml` marks each set `basic` or `optional`. Basic sets are bundled with
every build and installed by default — protections that assume nothing about
the application behind the proxy. Optional sets are published and updatable but
never bundled: a set that only matters to one application, WordPress being the
first, should not cost every deployment the matching.

`scripts/fetch-rules.sh` refreshes `rules/` from the published channel, taking
only the basic sets. It exists so the snapshot is never maintained by hand,
which is the failure that left one copy of a rule corrected and another broken
for four releases.

Three things it does deliberately:

* **Everything is fetched before anything is replaced.** A channel that fails
  halfway leaves the working copy untouched rather than half-updated — a WAF
  running half a rule set is worse than one running last week's.
* **The directory is replaced wholesale, not merged.** A set withdrawn upstream,
  because a rule in it was wrong, has to disappear here too rather than live on
  in every subsequent build.
* **`rules/SOURCE` records where the snapshot came from** and a SHA-256 per set,
  so a shipped binary can be tied to exactly what it carries.

**On currency versus reproducibility.** Taking the channel's current content
means a release always ships current rules, at the cost of the same tag
rebuilding into a different binary later. That trade is only safe because the
result is committed and reviewed: `git diff rules/` is the gate, and a rule
change is not one to wave through. Fetching at build time inside CI, with no
human between the channel and the release, would mean a bad rule pushed
upstream entering the next release unseen — and 0.5.4 is the evidence that a
bad rule can block real traffic.

## Publishing: private repository, public channel

The rules repository is private (Gitea); the update channel has to be public,
because an installation fetching a rule set cannot hold credentials for it.
Something must publish across that boundary, and packages already do exactly
this: `github2repo.sh` takes built artifacts and lays them out as signed APT and
YUM repositories under `repo.easysys.io/easywaf/…`.

Rule sets follow the same shape rather than inventing a second one:

* Published to `repo.easysys.io/easywaf/rules/<channel>/`, beside the packages
  and served by the same web server.
* **Signed with the same GPG key** the package repositories already use. An
  installation that trusts EasyWAF packages then trusts rule sets by the same
  mechanism, with no second key to distribute. A rule set is executable in every
  sense that matters — it decides what traffic is refused — so an unsigned one
  fetched over the network would be a straightforward supply-chain hole.
* **Signature verified before a set is applied, not after downloading.** A set
  that fails verification is discarded and reported, never imported "just this
  once".
* A `stable` and a `testing` channel, matching the packages, so a rule change
  can be exercised before it reaches everyone. Today's two corrections would
  both have gone to testing first.

The publishing script is the rules repository's own concern rather than
EasyWAF's, and belongs next to `github2repo.sh` on the repository server.

## Rule set files

Each file gains a header the current parser ignores, so it can be added before
anything consumes it:

```toml
[set]
id      = "owasp-sqli"      # stable; the filename may change, this may not
name    = "SQL Injection"
version = 3                 # increments on every published change
```

## The manifest

One signed index fetched per check, rather than probing each file:

```toml
[[sets]]
id       = "owasp-sqli"
name     = "SQL Injection"
version  = 3
sha256   = "…"
size     = 20480
requires = "0.6.0"          # minimum EasyWAF version
url      = "sets/owasp-sqli-3.toml"
```

`requires` is what stops a set written for a later EasyWAF — using a zone or
action this build does not understand — from importing as rules that silently
never match.

**The manifest must be signed.** A rule is close to executable content: a regex
run against every request on a machine whose job is security, where a corrupted
or tampered set can block all traffic or quietly disable protection. The
EasySYS repositories already GPG-sign the RPMs, `repomd.xml` and the APT
`Release`; the same key and the same tooling apply here, with a SHA-256 per file
verified before anything is applied.

## Installed means per-policy

Rules are imported *into a policy*, so a set has two independent states: the
version the repository offers, and the version each policy holds. Policy A may
be on 2 while policy B is on 3.

The notification is therefore not "an update is available" but "SQLi 3 is
available; Policy A has 2". Applying it reconciles one policy at a time: every
imported rule in that policy is overwritten with the new version — `pattern`,
`score`, `action`, `zone`, `description` — while `id`, `enabled` and
`policy_id` are preserved. This is safe unconditionally, not just usually: an
imported row cannot hold a customization, since making one means cloning the
rule into a separate, no-longer-imported row the update never touches.

## Applying updates

* **Notify, do not auto-apply.** An auto-applied bad rule is an outage across
  every site using that policy. Show what changed; apply on a click.
* **Keep the previous version on disk** so there is a way back.
* **Be quiet when offline.** A WAF is often air-gapped. No nagging, no error
  banner, no repeated log lines because the repository is unreachable — and an
  explicit opt-out for sites that forbid outbound connections.
* **Offer file upload** for hosts with no outbound access at all.

## The country database in the same channel

Publishing DB-IP Lite through the EasySYS repository gives it the same signing
and avoids depending on DB-IP's own URLs and rate limits.

**Licensing differs by source and must not be blurred:**

* **DB-IP Lite is CC BY 4.0 — redistributable.** It may be mirrored in the
  repository, with the attribution EasyWAF already carries.
* **MaxMind GeoLite2 must not be mirrored.** Its licence prohibits
  redistribution, so it can only ever be a file an administrator downloads
  themselves and points `geoip_db` at.

0.3.0 already made the reader replaceable, so a downloaded database can be
swapped in without restarting.

## Housekeeping this exposes

`seed_default_rules` inserts 22 hardcoded rules that duplicate content in the
`.toml` files and carry no `external_id`. This note called it "a second source
of truth which can never be updated" before it caused anything; in 0.5.4 it did
— the SQL-comment rule was corrected in the catalogue and left broken here, so
pressing Seed rather than Import gave a rule that scored every request. It is
deleted rather than maintained; see *One source of truth* above.

The `imported_pattern`, `imported_score` and `imported_action` columns added in
migration 008 (0.3.0/0.3.1) supported an earlier design: diffing a rule's
current values against what was imported, to detect that it had been edited.
Immutability makes that comparison unnecessary — an imported row cannot be
edited, so there is nothing to diff. They are left in place unused rather than
dropped; three nullable columns cost nothing, and removing a column in SQLite
means rebuilding the table, not worth it for this.

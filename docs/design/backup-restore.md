# Design note — backup, restore, and configuration export

Status: **built for 0.14.0** — see [roadmap.md](roadmap.md).

## Decided, 2026-09-27

Yariv's decisions, recorded before the code so the code can be checked
against them:

* **All of it in 0.14.0** — snapshot download and restore, a readable
  export, *and* importing that export. Not split across two releases.
* **Import replaces.** An imported file makes this instance match it — "make
  this instance match that file" rather than "add these to what is here" —
  and a preview lists every creation, change and removal before anything is
  written. Merge is not offered; a restore that silently did the other would
  lose data, which is the note's own warning below.
* **Scheduled snapshots exist and are off by default.** Daily, a number kept,
  in a directory beside the database. Switched on by an administrator.

Built in five phases, each tested before the next: snapshot download,
scheduled snapshots, snapshot restore, readable export, import with preview.

## How it was built

Recorded because three of these were choices, and the alternatives were real.

**An import is applied to a copy and swapped in by a restart** — the second of
the two options this note allows below ("one transaction, or a staged database
swapped in at the end"). The live database is snapshotted, the import applied
to the copy through the ordinary code paths — rule sets still arrive through
the signature-verified installer — and the copy is staged exactly as a snapshot
restore is. That buys three things this note asks for without writing them
twice: a failure half-way changes nothing; a result that will not start is put
back by the next start; and the restart re-binds every listener and reloads
every cache, which is the step the note warns is easiest to miss when done one
subsystem at a time. The cost is a few seconds without serving sites per import,
and the preview says so.

**A restore undoes itself.** The swap is ordered so that a power cut between
any two steps loses nothing: the current database is copied whole to
`<db>.before-restore`, a marker is written, the snapshot is renamed over the
database, and the marker is cleared only once the migrations have run. A start
that finds the marker with nothing staged knows the restored database never
came up, and puts the kept one back.

**Every settings key is classified.** `EXPORTED_SETTINGS` or `LOCAL_SETTINGS`
in `export.rs`, and a test that scans every `KEY_` constant fails, with
instructions, for a key in neither. This is how the note's requirement that the
format gain fields without being reworked is met for settings in particular: a
setting added by Smart Protect has to be decided on before the build is green.

Two exceptions to replace, both deliberate: accounts are merged — added and
updated, never deleted, and never the account running the import — and this
host's own management certificate is neither exported nor removed.

Unknown keys are refused, in both directions of the note's rule: one from a
newer EasyWAF is refused with the versions named and an instruction to
upgrade; one from the same or an older version is a misspelling, and is named
rather than dropped.

**One correction to what follows.** This note says the cookie `secret` lives in
`config.toml` and so travels in neither artefact. That stopped being true: the
signing key is generated on first run and stored **in the database**. So a
snapshot *does* carry it — restoring one brings back the old key, and anyone
signed in on the new host is signed out once. The restore says so. A readable
export does not carry it, and must not: it is a credential, not configuration.

## The problem

Everything EasyWAF knows lives in one SQLite file: sites, policies, rules,
certificates, users, GeoIP rules and settings. There is no export of any of it.

Three consequences, in rising order of how often they will actually bite:

* **Losing the host loses the configuration.** A tuned rule set is real work —
  the 0.3.1 false positives took a debugging session each to find — and none of
  it is reproducible from anything but the machine it lives on.
* **There is no way to move a configuration.** Standing up staging that matches
  production, or promoting a tested policy from staging to production, means
  retyping it through the GUI and hoping the two match.
* **None of it can be reviewed or version-controlled.** "What changed on the
  WAF last Tuesday" has no answer, and no change to it can be proposed, diffed
  or approved before it takes effect.

The support case is worth stating separately: one exported file beats twenty
screenshots.

## Two deliverables, deliberately different

They are often spoken of as one feature and should not be built as one.

**A snapshot** is the whole database, byte-exact, for disaster recovery. It is
schema-agnostic — it does not know what a site or a rule is — so it never needs
changing when a later release adds a table. It answers "the host is gone".

**A structured export** is a readable document (TOML or JSON) describing the
configuration: sites, policies, rules, settings. It is schema-*coupled* by
definition, so it must be revisited whenever a release adds something worth
exporting. It answers "clone this", "review this", "keep this in git".

A snapshot cannot do the second job — an opaque binary cannot be diffed or
merged — and an export should not be trusted for the first, because anything it
omits is silently gone at restore. Both are needed.

## The constraint that shapes everything: an export carries secrets

`certs` holds **`key_pem`** — the private keys for every certificate the
appliance serves. `users` holds bcrypt password hashes. An export is therefore
not a configuration file; it is a credential-bearing artefact, and the whole
point of the feature is that people will put it in git, email it to support and
copy it between machines.

This must be decided before the format is, not after:

* **Private keys are excluded by default.** An export is for configuration; a
  restore onto a new host re-uploads certificates or re-issues them via ACME
  (0.5.0). Including keys must be an explicit, separately named choice — not a
  flag someone sets once and forgets, and never the default that a support
  request casually produces.
* **An export that does include keys must say so, loudly, in the file itself
  and in the GUI at the moment it is produced.** A filename is not a warning.
* **Password hashes are configuration, not credentials to propagate.** Cloning
  production onto staging should not silently clone production's accounts.
  Exporting users at all is a separate decision from exporting sites, and
  probably wants to default to off.
* **A snapshot is a different matter** — it is the whole database including
  keys by definition, so it must be treated as a secret in its own right and
  the GUI should say that plainly rather than presenting it as "download a
  backup".

~~`config.toml`'s `secret` is *not* in the database, so it is in neither
artefact.~~ Superseded — see *Decided, 2026-09-27* above: the cookie key is in
the database, so a snapshot carries it and a readable export does not. Either
way a restore can sign people out, and that belongs in the restore's own
output rather than being discovered as a mysterious mass logout.

## Snapshots must not be a file copy

`cp easywaf.db backup.db` is wrong and will appear to work. EasyWAF runs SQLite
in WAL mode (`001_init.sql`), so committed data can live in `easywaf.db-wal`
rather than the main file; copying the one file while the service is running can
produce a database missing its most recent writes, or a torn one.

Use `VACUUM INTO` (or the online backup API), which takes a consistent snapshot
of a live database without stopping the service. It also compacts, so the
artefact is smaller than the running file.

## Restore is the half that is easy to get wrong

Producing an export is straightforward. Consuming one raises questions that
should be settled before coding:

**Replace or merge?** Both are legitimate — "make this instance match that
file" versus "add these sites to what is here" — and they are different
features with different failure modes. Pick one for 0.14.0 and say which; a
restore that silently does the other loses data.

**What identifies an object across instances?** Not `id`: autoincrement values
mean nothing on another host. Sites have unique `server_name`, rules already
carry `external_id` for exactly this reason (see
[rule-repository.md](rule-repository.md)), and policies have names. The export
should reference by those and never by primary key.

**Restore must re-bind and re-load, not require a restart.** Sites carry
`listen_port` and `tls_port`, and the running proxy binds listeners on demand
via `announce_site`; certificates are held in the in-memory SNI map rebuilt by
`tls::reload`. A restore that writes rows without triggering both leaves an
appliance whose database and behaviour disagree — the worst possible state to
hand back to an operator who has just recovered from an outage.

**A restore that fails must change nothing.** One transaction, or a staged
database swapped in at the end. A half-applied configuration on a security
appliance is worse than a failed restore, because it looks like success.

## Why 0.14.0

**After 0.6.0, because 0.6.0 decides what a rule *is*.** That release makes
vendor rules immutable and turns edits into clones held as custom rules. An
export written before it would encode the current model — every rule equally
editable — and then need reworking immediately. Exporting after it can record
the distinction that matters: which rules came from a vendor set at which
version, and which are genuinely this installation's own. Only the second kind
needs to travel in full; the first is a reference to a set that can be fetched.

**Before rate limiting and learning**, so those two are designed with an export
format already in place rather than retrofitted into one. That is also why it
should not go later: each of them adds exportable state.

IP lists moved ahead of this release on 2026-09-08, so their state is one the
export has to accommodate rather than one shaped around it. That is a smaller
cost than it sounds — an IP list is a flat table of addresses with a note and a
timestamp, which is the easiest kind of state to export.

**Smart Protect lands after this release, by Yariv's decision of 2026-09-22 —
so the format must be built to gain fields without being reworked.** A
versioned document whose reader ignores keys it does not know, and whose writer
never assumes the set of tables is closed. That is good practice anyway; here
it is a requirement with a date on it, because the release that needs it is the
next one. The same applies to everything after: rate limiting, learned URL
sets, and whatever a node-local state column turns out to hold.

What must *not* be inferred from this is that unknown keys are simply dropped
on restore. A restore that silently discards settings it does not understand is
worse than one that refuses: the appliance comes up looking right and enforcing
less. An unknown key from a **newer** version is a refusal with the versions
named; an unknown key from an older one is a default.

**It displaces flow logs by one release**, which is the cheapest thing to
displace — the logging work has a cross-repository dependency (see
[logging.md](logging.md)) that can proceed in parallel regardless of which
release it lands in.

It is not earlier than 0.6.0 mainly because of the rule-model point above. The
counter-argument is real and worth recording: every release it waits is another
release in which a lost host means a lost configuration. If that becomes urgent
before 0.14.0, **the snapshot half can be pulled forward on its own** — it is
schema-agnostic, so it neither depends on the rule model nor churns when the
schema changes. The structured export is the half that must wait.

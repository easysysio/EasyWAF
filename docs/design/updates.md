# Design note — updates: signatures, IP lists and the country database

Status: planned for **0.13.1** — see [roadmap.md](roadmap.md). Yariv's shape,
2026-09-22.

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

**Two stages, named.** They already exist and are already the right model; the
interface does not say so.

1. **Fetch** — the channel is read, the manifest's signature checked before
   anything is read from it, and each file checked against the SHA-256 that
   signed manifest gives. Verified files land in the mirror beside the
   database: `rules-cache/`, `lists-cache/`. Nothing that fails verification is
   written.
2. **Install** — a set is imported *into a policy*, which is why one policy can
   hold v2 while another has v3. IP lists and the country database have no
   second stage: switching a list on is a policy's own decision, and the
   database is one file for the host.

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

**Proposed sequence:**

1. **0.13.1** — the section, upload, the country database, and the central
   view of which policies are behind. Automatic apply for data (already true)
   and not for signatures.
2. **Next** — keep the previous version of a set per policy, so an update can
   be reverted in one click and a diff can be shown before it is applied.
3. **Then** — automatic apply for signatures, **per policy** rather than
   appliance-wide, so the applications can track automatically while the public
   sites do not, or the reverse. Paired with rollback, this is a defensible
   default rather than a gamble.

If it is wanted sooner than rollback, it should at least be per policy and
off by default, and the switch should say plainly what it costs.

## What 0.13.1 includes

* Settings → **Updates**, replacing Rule Updates, with the three parts.
* **Upload** of a signed bundle — rule sets and IP lists — verified exactly as
  a download is.
* **The country database**: what is in force, an update from the signed channel
  where the licence allows it, and upload for a file the operator supplies.
* **The policies that are behind**, listed in one place, with apply.
* No change to what is verified, where mirrors live, or to per-policy install.

## What it does not include

* Automatic apply of rule sets. See above.
* Rollback. It is the next thing, and it is what makes the point above
  possible.
* Any change to the publishing side: `github2repo.sh --rules` and `--lists`
  are unaffected, and an uploaded bundle is the same bundle they publish.

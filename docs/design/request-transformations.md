# Design note — the decoders the rules assume

Status: planned for **0.11.0** — see [roadmap.md](roadmap.md), alongside
[proxy-performance.md](proxy-performance.md). The two share a release because
they change the same code path in opposite directions, which is argued at the
end.

## What is missing

`zone_text` in [modules/waf.rs](../../src/modules/waf.rs) produces four candidate
forms of a request: raw, `+`-as-space, percent-decoded, and percent-decoded
twice. A rule matches if any one form matches. That is the whole pipeline.

ModSecurity applies a per-rule transformation pipeline instead, and CRS rules
are written assuming it. A rule declaring `t:htmlEntityDecode` is written
against the *decoded* text, so matching it against the raw text catches the
literal payload and misses every encoded variant.

`scripts/modsec2easywaf.py` therefore refuses such rules rather than converting
them, on the grounds that a rule which looks like protection and is evaded by
the encoding it was written to see through is worse than a missing rule. That
is the right refusal, and this release is what makes it unnecessary.

## What it costs to be missing

Against CRS `main`, counting only paranoia level 1 — the rules CRS itself runs
by default:

| | |
|---|---|
| Paranoia-1 rules refused for transformations | 49 |
| Need only `htmlEntityDecode` and/or `jsDecode` | **7** |
| Those plus `cssDecode` | **26** |
| Need something else entirely | 23 |

**Log4Shell is in the first group.** CRS 944150 is a paranoia-1 rule needing
`jsDecode` and `htmlEntityDecode`, so it is refused today, and
`sets/1030-java.rules.toml` says in its header that Log4Shell is not covered.
This is the change that lets that sentence be deleted.

## The change

Three decoders, each producing one more candidate form in `zone_text`:

* **`htmlEntityDecode`** — named (`&dollar;`, `&lbrace;`), decimal (`&#36;`)
  and hexadecimal (`&#x24;`) entities.
* **`jsDecode`** — `\xHH`, `\uHHHH`, `\0NN`, and the usual escapes.
* **`cssDecode`** — the backslash-hex form CSS allows.

No schema change, no per-rule metadata, and no change to how a rule is
expressed. The converter's `SAFE_TRANSFORMS` widens to accept them, and the 26
rules stop being refused.

**Adding a form can only add matches, never remove one**, because a rule
matches if any form matches. So the failure mode of getting a decoder slightly
wrong is a false positive, not a hole — the direction that is visible in
Traffic Monitor and fixable with an exclusion, rather than silent.

Per-rule transformations, as ModSecurity does them, are deliberately *not* the
design. They would mean a column on every rule, a converter that emits it, and
an engine that reads it, to save work that measurement says is not worth
saving — see below.

## Why this shares a release with proxy performance

The two pull the same lever in opposite directions, and doing them apart means
touching the matching path twice and measuring it twice.

Three more forms is roughly three more passes per rule. Matching costs about
0.21µs per rule across the eight forms an `ANY` rule sees today, so this is
perhaps +35% on the matching half. That is a large fraction of a small number:
at 138 rules, matching is 35µs against 431µs of per-request database work.

[proxy-performance.md](proxy-performance.md) removes most of that 431µs. Doing
both together means the release that makes rules more expensive to match is the
release that stops re-reading them from SQLite on every request, and the net
result is still several times faster than today. Doing the decoders alone would
make the engine slower with no offset; doing the caching alone would leave the
coverage gap open for another release.

It also means one measurement pass, against one before-and-after, rather than
two sets of numbers that have to be reconciled.

## What stays refused

`cmdLine`, `normalizePath`, `replaceComments` and `removeWhitespace` account
for most of the remaining 23. They are the same shape of work and can follow if
they turn out to matter.

`base64Decode` is different in kind and is deliberately excluded: decoding
base64 anywhere in a request changes what "the request" means, and a rule
matching decoded base64 will match ordinary encoded payloads — an image upload,
a JWT, a session blob. That deserves its own decision rather than arriving as
part of a batch.

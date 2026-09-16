# Design note — the decoders the rules assume

Status: **built, unreleased**, for 0.11.0 — see [roadmap.md](roadmap.md),
alongside [proxy-performance.md](proxy-performance.md). The two share a release
because they change the same code path in opposite directions, which is argued
at the end. *What was built* records where the implementation departs from the
plan below; the plan is left as it was written.

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

## What was built

Built **2026-09-16**, in `zone_text` and five decoders beside it in
[modules/waf.rs](../../src/modules/waf.rs). Four departures from the plan, each
found while implementing it.

**The decoders are applied in chains, not as three independent forms.** A CRS
rule does not declare one transformation; it declares a pipeline, and the
pattern is written against the end of it. 941110 is
`t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode` — an entity that
decodes to a backslash is then an escape to `jsDecode`. Three independent forms
would each undo one layer of an attack that uses two. So `zone_text` produces
the two chains CRS actually uses: the 941 order above, and
`urlDecodeUni,jsDecode,htmlEntityDecode` for the Log4Shell family.

The order has a consequence worth recording: `jsDecode` reads `\3c` as an octal
escape and consumes it before `cssDecode` sees it, so a CSS escape beginning
with an octal digit does not survive the first chain. libmodsecurity does the
same, and the rules were written against that, so this follows it rather than
improving on it.

**`htmlEntityDecode` knows five names, not HTML's several thousand.** The plan's
examples, `&dollar;` and `&lbrace;`, do not decode: libmodsecurity handles
`quot`, `amp`, `lt`, `gt` and `nbsp`, numerically-escaped entities, and nothing
else. It also truncates `&#256;` to one byte and accepts a missing semicolon.
Each of those is a quirk the patterns were tested against, so the decoders
follow libmodsecurity rather than the standards they are named after.

**`urlDecodeUni` had to come too.** `%uFF1C` is an escape percent-decoding
leaves alone, and rules declare `t:urlDecodeUni` on its own, so it is both the
head of each chain and a form in its own right. `removeNulls` ends the 941
chain for the same reason.

**The chains start from percent-decoded text.** The first implementation gated
them on the text as received, which is wrong for the ordinary case: an escape
arrives encoded, and `%26lt%3Bscript%26gt%3B` carries no literal `&` at all. A
test using the shipped 941001 rule caught it. Ordinary text still costs one
scan and one form — an `&` between query parameters is not an entity, and the
forms are de-duplicated, so `a=1&b=2` yields exactly one.

### What it cost

Measured with the harness in `waf.rs`, release build, against the numbers
[proxy-performance.md](proxy-performance.md) recorded before the decoders:

| Rules | WAF before decoders | WAF after | Reference: the database work removed |
|---|---|---|---|
| 138 | 29µs | 31µs | 438µs |
| 1,000 | 222µs | 230µs | 2,808µs |
| 5,000 | 1,111µs | 1,138µs | 14,314µs |

About +7%, where this note predicted +35%. The prediction assumed three more
passes over every form for every rule; the gate means text carrying no escape —
which is most traffic, including the benchmark's — pays one scan of the
decoded form and produces no extra forms at all.

### The converter

`SAFE_TRANSFORMS` in [modsec2easywaf.py](../../scripts/modsec2easywaf.py) now
accepts `htmlentitydecode`, `jsdecode` and `cssdecode`. Against the CRS 4.7.0
refusal list, that is **36 rules** refused for transformations alone that are
now convertible — more than the 26 estimated above, which counted paranoia
level 1 only — including all three Log4Shell rules, 921's header-injection
family, and the 941 XSS set.

The converter's self-test had a case asserting that a rule is refused for
naming `t:htmlEntityDecode`. It names `t:cmdLine` now, which is still refused.

Re-converting CRS and removing the Log4Shell disclaimer from
`sets/1030-java.rules.toml` happen in the EasyWAF-rules repository, and are not
part of this change.

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

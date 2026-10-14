# Design note — targeted zones

Status: **built for 1.2.0, not released** — see [roadmap.md](roadmap.md). Decided by
Yariv on 2026-10-14, after a review of CRS 4.30.0 for what could be imported.

## The gap

A rule reads one of five zones, and each is a block of text:

| Zone | What a rule reads |
|---|---|
| `URL` | path and query, raw, decoded and normalised |
| `ARGS` | the query string, whole |
| `BODY` | the body, whole, inflated if compressed |
| `HEADERS` | every header value joined with spaces, no names |
| `ANY` | all of the above |

CRS addresses one part of a request: `REQUEST_HEADERS:User-Agent`, each
argument's value, cookie names apart from cookie values, the path without its
query. Its patterns are written for that. Three things follow from the gap:

* **A rule meant for one header reads every header.** A User-Agent signature
  fires on a `Referer` that happens to contain it. Converting such a rule widens
  it, which is why 80 of the 86 CRS rules that convert at paranoia level 1 are
  marked widened and stay unpublished.
* **Anchors mean the wrong place.** CRS's `^` and `$` are the start and end of one
  value. Here they are the start and end of the zone, so `^https?://` on
  `ARGS` fires only when the whole query string begins with a URL — never, in
  practice — and the converter now refuses such rules rather than ship them
  silent.
* **A form or JSON body has no arguments.** `ARGS` is the query string only, so a
  rule written for arguments misses every POSTed field, and the rules here that
  care about fields read `ANY` and widen to headers too.

## What 1.2.0 adds

The five zones keep their meaning exactly. Every published set and every rule an
installation holds reads what it read before. The new zones are named in the
singular, because they read **one value at a time**: a rule matches when its
pattern matches any one value, in any of the forms `zone_text` makes of it.

| Zone | Each value is |
|---|---|
| `PATH` | the path, without the query — raw, decoded, and as a backend reads it |
| `ARG` | an argument's value: from the query string, and from a body sent as a form or as JSON |
| `ARG:name` | the value of each argument called *name* |
| `ARG_NAME` | an argument's name |
| `HEADER` | one header's value |
| `HEADER:Name` | each value of the header *Name* |
| `HEADER_NAME` | a header's name |
| `COOKIE` | one cookie's value |
| `COOKIE:name` | the value of the cookie *name* |
| `COOKIE_NAME` | a cookie's name |
| `METHOD` | the request method |

**A rule can name several, separated by `|`** — `ARG|ARG_NAME|COOKIE`. It reads
all of them and matches once, which is what a CRS rule with several variables
does. Without this, a rule that CRS points at arguments and cookies has to read
`ANY`, and two rules split from one would score a payload twice.

Names after the colon are compared without regard to case: HTTP header names
have none, and for arguments and cookies a rule that misses `ID=` because it
was written for `id=` is a rule an attacker reads around.

## Where arguments come from

* **The query string**, split on `&` and then on the first `=` *before* decoding,
  so an encoded `%26` inside a value does not split it.
* **A body sent as `application/x-www-form-urlencoded`**, the same way.
* **A body sent as JSON** (`application/json`, or any `+json` type): every
  leaf — string, number, `true`, `false` — is a value, named by its own key; an
  array's elements are named by the array's key. `{"user": {"password": "x"}}`
  gives `password` = `x`, so `ARG:password` means the same in a form and in
  JSON. Every key is also an `ARG_NAME`.

Bodies are read as far as they are inspected (128 KB by default) and after
inflating. JSON cut off at that limit does not parse, and gives no arguments;
`BODY` still reads it. A form cut off at the limit gives the fields before the
cut.

**At most 1,024 arguments** are taken from one request, query and body together.
One beyond that is not read as an argument. It is still in `ARGS`, `BODY`, `URL`
and `ANY`, so a rule on those zones sees it. A request carrying more than that
many is itself worth a rule, and CRS has one (920380), which conditions will let
EasyWAF express.

**Not in 1.2.0: multipart bodies.** A field in a `multipart/form-data` upload is
not an argument yet. `BODY` reads the upload as it arrived.

## A zone this version does not know

Until now a rule whose zone was not one of the five was read as `ANY` — silently
inspecting everything. A set written for a newer EasyWAF would have widened on
an older one, and nobody would have been told. From 1.2.0:

* **The engine does not run a rule whose zone it cannot read**, and says so in the
  journal, once.
* **Installing or updating a rule set that uses one is refused,** with the set
  named and the reason: it needs a newer EasyWAF.
* **The channel can say so first.** A set's entry in `sets.toml` may carry
  `requires = "1.2.0"`; an installation older than that is shown the set as
  needing an upgrade rather than as an update to apply.

What this cannot do is change an installation already older than 1.2.0. Such an
installation does not know `requires`, and reads an unknown zone as `ANY`. A set
it applies after its rules move to targeted zones inspects more than it should:
false positives, never a hole. So **the published sets keep the five zones until
1.2.0 has been out for a while**, and moving them is a separate step in the rules
repository, with `requires`, release notes that say to upgrade before applying,
and the set's description saying it too.

## Cost

Today every request builds all five zones whether a rule reads them or not. The
new zones are built **only when a rule in the site's policy reads them**, and each
at most once per request: parsing a JSON body is not free, and a policy of
basic sets that reads none of the new zones should cost exactly what it cost in
1.1.

## Everything else that knows a zone

* **The interface.** The zone list on the custom-rule and rule-edit pages gains
  the new zones, with a field for the name after the colon, and a rule's zone is
  shown as it is written.
* **Export and import.** An import checks a rule's zone with the same parser the
  engine uses, so a misspelt zone is refused, not read as everything.
* **The converter** maps ModSecurity's variables onto the new zones —
  `REQUEST_HEADERS:User-Agent` to `HEADER:User-Agent`, `ARGS` to `ARG`,
  `REQUEST_COOKIES_NAMES` to `COOKIE_NAME`, `REQUEST_FILENAME` to `PATH` — and a
  rule naming several becomes one rule naming several zones. Anchors are then
  right, and the anchored rules it now refuses convert.
* **The case harness** in the rules repository takes a request in the new forms,
  so a set's cases can say what arrives in which header, argument or cookie.

## Not in 1.2.0

* **Exclusions by target** — "this rule, but not on the argument `comment`".
  CRS's main tool against false positives, and only expressible once rules
  know which value they matched. The obvious next step.
* **Conditions** — counts, lengths, "matches unless", several conditions at
  once — and **libinjection**. Both read targeted values; neither is a zone.
* **Multipart parsing**, above.
* **XML bodies.** CRS points most of its attack rules at `XML:/*` as well as at
  arguments and cookies. With no XML parsing here, the converter maps that to
  `BODY` and marks the rule widened. Of CRS 4.30.0's request rules at paranoia
  level 1, the converter takes 16 exactly once the targeted zones exist (5
  before them); XML alone keeps about 60 more from being exact. Nearly all are
  in the SQL injection, XSS, RCE and PHP bands, which sets written for EasyWAF
  cover and which are not published from CRS, so this waits for a reason.

# Design note — learning and hardening modes (URL allowlisting)

Status: planned for **0.12.0** — see [roadmap.md](roadmap.md).

A positive security model: instead of describing what an attack looks like, as
every rule so far does, describe what the application legitimately exposes and
refuse everything else. **Learning** watches real traffic and records the URLs
a site actually serves; **hardening** then allows only those.

This is the strongest protection EasyWAF can offer against an unknown attack —
a zero-day against an endpoint the application does not have is simply not
reachable — and also the easiest to turn into an outage, which shapes most of
what follows.

## Scope: per-site, not per-policy

The mode was proposed as a policy setting, alongside `rule_engine` and
`geoip_mode`. It should live on the **site** instead, and so should the
learned data. `sites.waf_policy_id` is a foreign key, so several sites can
share one policy — and the URL set of one site has nothing to do with
another's. A shared policy holding a learned set would mean site A's
`/wp-admin` is allowed on site B, which is the exact opposite of what
hardening is for.

That is not merely a data-placement question. The **lifecycle** is per-site
too: the natural rollout is to learn one site for a fortnight, harden it,
watch it, then start the next. A mode on a shared policy cannot stagger that,
and staggering is the only safe way to deploy this.

This follows the reasoning already recorded for rate limiting
([rate-limiting.md](rate-limiting.md)): shared policies are right for shared
*threat* data — a country list, a SQLi pattern — and wrong for a property of
one site's own traffic.

## The mode has four states, not two

`sites.url_model`:

| State | Behaviour |
|---|---|
| `off` | Nothing recorded, nothing enforced. The default. |
| `learning` | Record URLs. Enforce nothing. |
| `hardening_alert` | Record nothing new. Log what *would* be blocked. |
| `hardening_block` | Refuse anything not in the learned set. |

`hardening_alert` is not optional politeness. 0.3.1 was two rules that blocked
real traffic because nothing let an operator see what a change would do before
it did it. A URL allowlist is far more dangerous than any single rule — a set
that is 95% complete rejects one request in twenty — so the step where you
watch it decide without acting on it has to be on the path, not an option
beside it.

## What counts as a URL

The make-or-break decision. Learned naively, `/products/1041` and
`/products/1042` are different URLs, a real site produces tens of thousands of
them, and hardening breaks the moment someone adds a product.

So learning stores a **normalised pattern**, not a raw path: segments that
look like identifiers collapse to a placeholder.

```
/products/1041/reviews   ->  /products/{n}/reviews
/user/3f9a-…-b7c2/avatar ->  /user/{uuid}/avatar
/assets/app.4f3d9b.css   ->  /assets/app.{hash}.css
```

Incoming requests are normalised the same way before lookup. Integers, UUIDs,
long hex strings and date-like segments are the obvious first set; the rule of
thumb is that a segment which varies per entity is an argument, not a route.

**Method is part of the key.** `GET /admin` and `POST /admin` are different
capabilities, and learning them separately means hardening rejects a POST to a
read-only endpoint — a genuine class of attack, free with this design.

Query strings are **not** part of v1. Which parameters an endpoint accepts is
a second allowlist with its own false-positive profile, and worth doing
properly later rather than bolted on here.

## Learning records whatever it sees, including attacks

The failure that matters: a scanner probes `/wp-admin/setup-config.php` during
the learning window, and hardening then allows it forever. Learning that
happily records its own attack surface is worse than no learning.

Two defences, both required:

* **Only learn from requests that survived the rest of the pipeline.** A
  request blocked or challenged by a WAF rule, a country rule, an IP block or
  a rate limit must never reach the recorder. Learning therefore happens
  *after* the verdict, not during inspection — the recorder sits at the end of
  the request, next to where `log_event` is already called.
* **The set is reviewable and prunable before hardening.** A screen listing
  learned URLs with first seen, last seen and hit count, where entries can be
  deleted or edited. One hit, once, three weeks ago is what a probe looks
  like; an endpoint the application actually serves does not look like that.

## Knowing when it is safe to harden

The question an operator cannot answer alone is "have I learned enough yet?".
The signal that answers it is **how long since anything new was learned** — a
site still discovering novel URLs daily is not ready; one that has seen
nothing new in ten days across a full business cycle probably is.

So the learning screen leads with that, not with a count: *learning for 14
days, 247 URLs, nothing new in 9 days*. A weekly or monthly cycle matters too
— a report that runs on the first of the month will not appear in a fortnight
of learning, and hardening on day 14 breaks it.

## traffic_events already holds the raw material

`traffic_events` records `site_id`, `method` and `path` for every proxied
request. Two consequences worth taking:

* **Hardening can be previewed before learning is ever switched on.** Running
  the normaliser over recent traffic answers "what would this site learn, and
  how many distinct URLs is that" from history that already exists.
* Learning still needs its **own table** rather than querying that one live:
  `traffic_events` is subject to retention pruning, and a deduplicated set
  with `first_seen` / `last_seen` / `hit_count` is a different shape from an
  append-only log. But it can be **seeded** from existing traffic, which turns
  a fortnight of waiting into a starting point.

## Mechanics

Roughly:

```sql
CREATE TABLE learned_urls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    method      TEXT    NOT NULL,
    path_pattern TEXT   NOT NULL,   -- normalised, e.g. /products/{n}/reviews
    first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
    hit_count   INTEGER NOT NULL DEFAULT 1,
    UNIQUE (site_id, method, path_pattern)
);
```

**Pipeline position is split**, unusually for a module:

* the **hardening check runs early** — a hash-set lookup is cheaper than
  compiling regexes, so a request for an unknown URL should be refused before
  the pattern rules run, for the same reason country rules already precede
  them;
* the **learning write happens last**, after the verdict, for the reason
  above.

**In memory, like everything else on this path.** The allowlist is consulted
per request, so it is cached and rebuilt on change — the pattern already used
for the regex cache, the country database, and the IP lists in 0.10.0.

**Bounded, and loud when it is not.** A site whose learned set keeps growing
past a sane cap is telling you the normaliser is missing a dynamic pattern,
not that the site has 90,000 endpoints. That is a warning worth surfacing
rather than a table worth growing.

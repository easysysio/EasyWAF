# Design note — per-site rate limiting

Status: planned for **0.10.0** — see [roadmap.md](roadmap.md), after IP
allow/block lists (0.9.0). The two are adjacent because they are both
identity/volume signals rather than payload inspection and share a pipeline
position, but they differ enough in shape — a set lookup versus a counter with
a time window — to stay separate releases, consistent with one feature per
minor.

## Scope: per-site, not per-policy or global

Country rules are per-policy because a country list is genuinely something an
operator wants to share across many sites. A numeric rate threshold is not:
what counts as normal traffic for a busy public API and for a small internal
tool differs by orders of magnitude, so forcing sites onto a shared policy's
single threshold would mean every site sharing it constantly needs an
override — defeating the point of sharing.

So rate-limit settings belong on `sites` directly, alongside the fields
already there per-site: `listen_port`, `target`, the security-header toggles.
Not a third policy concept next to WAF policies and the IP lists from 0.9.0 —
each of those is genuinely shared threat data; a rate limit is a property of
one site's own traffic shape.

## What v1 covers

* **Site-wide**, not per-path. A limit on every request to the site, not a
  separate one for `/login` versus static assets. Per-path limits — the
  classic brute-force-protection case — are valuable and worth a later
  extension, but v1 should ship the simpler, still-useful version rather than
  hold up on that decision.
* **One threshold, one action.** Requests per window, and what happens when a
  client's window is exceeded: `block` (429) or `challenge` (route through the
  existing CAPTCHA/clearance mechanism from the score-based challenge work,
  rather than building a second one). A two-tier design — challenge at a lower
  threshold, block at a higher one, mirroring the WAF policy's
  `score_threshold` / `challenge_threshold` pair — is a natural v2 if a single
  threshold proves too coarse.
* **A mode, exactly like a WAF policy's `rule_engine`.** `Off` / `DetectionOnly`
  / `On`. This is not optional: 0.3.1 was two false-positive rules that blocked
  real traffic before anyone could see it coming, entirely because there was
  no way to observe what a rule would do before it enforced. A rate limit
  defaulting straight to enforcement risks exactly that, and it is cheaper to
  build the safety in now than to patch around its absence later.

## Where it runs, and why

Right after the IP allow/block check (0.9.0) and before GeoIP and WAF pattern
matching — cheapest checks first. If a client is already over its limit,
nothing is gained by then compiling and matching every WAF rule against a
request that is going to be rejected anyway, the same reasoning already
written down for why GeoIP precedes WAF.

**It must respect the allowlist.** An allowlisted IP is checked before
`Pipeline::run` is even called (0.9.0's design), so it automatically never
reaches a rate limiter either — one more confirmation that keeping the
allowlist override structural, rather than a rule each module has to
individually honour, was the right call.

## State: in-memory, ephemeral, bounded

A rate limiter is a live counter per `(client_ip, site_id)`, checked on every
request — a database round trip here would defeat the purpose the same way it
would for the regex cache or the country lookup. This needs an in-memory
structure, and unlike the regex cache or the geo reader, it is not something
that needs to survive a restart: losing counters on restart is an acceptable,
ordinary trade-off for ephemeral rate-limit state, not a correctness problem.

It does need bounding — an attacker rotating source ports or scanning from
many addresses can otherwise grow the key space without limit — so whatever
structure holds this needs either a periodic sweep (the traffic-retention
sweep is the existing pattern to follow) or a crate that manages that expiry
itself.

**`governor`** (a maintained Rust crate implementing the GCRA algorithm with
per-key state and its own cleanup) is worth evaluating first rather than
hand-rolling a sliding-window counter — this is a well-trodden problem with a
purpose-built library, and reaching for `tower`'s built-in rate-limit layer
instead would be the wrong fit: it throttles a whole service, not per-client,
per-site traffic. This is a detail to settle at implementation time, not a
commitment made here.

## Interaction with the challenge / clearance system

When the configured action is `challenge`, a rate-limited visitor goes through
the same CAPTCHA and clearance-cookie mechanism the WAF's score-based
challenge already uses, rather than a second parallel challenge system.
Solving it should **not** reset the request counter — it grants clearance to
proceed while still being counted, so an attacker cannot simply keep solving
CAPTCHAs to sustain a flood. Only the "am I currently blocked" decision is
affected by clearance; the counter itself keeps ticking.

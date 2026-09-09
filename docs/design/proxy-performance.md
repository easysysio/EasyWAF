# Design note — proxy performance: streaming bodies, cached rules

Status: planned for **0.11.0** — see [roadmap.md](roadmap.md), after flow logs
(0.9.0) and IP allow/block lists (0.10.0), and deliberately *before* load
balancing (0.12.0).

Flow logs moved ahead of this on 2026-09-09, which suits it: this release
changes how a request is buffered and matched, and having the log already in
place is what makes the before-and-after legible rather than asserted.

## Why before load balancing

Load balancing rewrites the proxy's request path: choosing an upstream, health
checks, failover. Whether a request body is buffered whole or streamed is a
property of that path, and retrofitting streaming into a request path that has
just gained upstream selection means doing the harder half twice. Model changes
belong before the things built on them — the same reasoning that puts load
balancing before configuration export.

## What was measured

On 2026-09-08, release build, against the rule sets this project publishes and
a request with a percent-encoded query string and a JSON body.

Rule matching is linear and cheap, about 0.21µs per rule:

| Rules | Matching |
|---|---|
| 138 (the published sets) | 35µs |
| 1,000 | 207µs |
| 5,000 | 1.0ms |
| 10,000 | 2.1ms |

The database work is an order of magnitude larger:

| Rules | DB per request | of which loading rules |
|---|---|---|
| 138 | 431µs | 378µs |
| 1,000 | 2.69ms | 2.66ms |
| 5,000 | 13.3ms | 13.3ms |

**92% of the WAF's per-request cost, at a realistic rule count, is re-reading
rows that change only when an administrator clicks something.** Rule count is
not the limit; re-reading the rules per request is.

## 1. Request bodies are buffered whole

```rust
// proxy/mod.rs
let body_bytes = axum::body::to_bytes(body, 32 * 1024 * 1024).await
```

Every body is read into memory before anything is forwarded, and anything
larger than 32 MB is refused with a 400. This is the item that affects real
deployments rather than headroom: a Nextcloud sync or an Immich video upload
is exactly the shape this penalises, and above the cap it does not merely slow
down, it fails.

Three approaches, and the order matters:

**Skip buffering when nothing inspects the body.** If a site's policy holds no
rule in the `BODY` or `ANY` zone, the body is never examined, and reading it is
pure cost. Cheap to decide once the rules are cached (§2), and correct by
construction: nothing can be missed that nothing was looking for.

**Inspect a bounded prefix, stream the remainder.** Attacks live in the first
few kilobytes; the tail of a 4 GB video does not contain SQL injection. This is
what established proxies do, and it is what makes uploads streaming again in
the general case. The prefix size becomes a setting, and the honest statement
in the GUI is that bodies are inspected up to it.

**Raise the cap.** One line, and the worst of the three: memory becomes
`concurrent uploads × cap` and the latency is unchanged. Worth doing only as a
stopgap.

The first two together are the design. The first is a special case of the
second and can ship first.

## 2. Rules are re-read on every request

Cache the rows per policy, alongside the compiled-regex cache that already
exists — the patterns were given this treatment and the rows never were.

**Invalidation is the whole problem.** A missed invalidation means a rule an
administrator disabled keeps firing, or a rule they added never does, and
neither announces itself. For a security product "stale forever" is not an
acceptable failure mode.

So both mechanisms, deliberately belt and braces:

* An explicit version bump from every handler that writes rules, policies or
  exclusions, so a change takes effect on the next request.
* A short TTL — 30 seconds is enough — so that a bump someone forgot to add
  self-heals rather than persisting until restart.

Neither alone is right. The bump alone is fragile against a future handler that
forgets it; the TTL alone makes every rule change take up to 30 seconds, which
is wrong when the change is being made to stop blocking someone.

The same cache covers the policy row and the site's exclusions, taking three
queries per request to none in the common case.

## 3. RegexSet

`regex::RegexSet` matches many patterns in one pass and reports which of them
matched. The engine never uses capture groups, so nothing prevents it.

Built per zone per policy, alongside §2 — it only makes sense once there is
somewhere to keep it. It turns matching from N passes into approximately one,
which would make several thousand rules cost about what 138 costs today.

Worth being clear that this is the *least* valuable of the three at present
scale: 35µs of matching against 431µs of database work is not where the time
goes. It matters if rule counts grow by an order of magnitude, and it is close
to free once §2 exists.

## 4. Connection pool

`max_connections(5)`, with three queries per request, is a concurrency ceiling
reached well before CPU saturates. It is listed last on purpose: §2 removes
most of those queries, and tuning a pool before removing the load on it is
tuning the wrong thing.

## The other half of this release

[request-transformations.md](request-transformations.md) adds three decoders —
`htmlEntityDecode`, `jsDecode`, `cssDecode` — so that CRS rules written against
decoded text can be converted at all. Twenty-six paranoia-1 rules are refused
today for want of them, Log4Shell among them.

It shares this release because it pulls the same lever the other way: three
more candidate forms is roughly +35% on matching, against a caching change that
removes most of the 431µs this note is about. Together the release is still
several times faster; apart, one of them ships a slower engine with no offset
and the other leaves the coverage gap open for a release. It is also one
measurement pass instead of two.

## What this is not

Not a rewrite. Each item is independently shippable and independently
measurable, and the measurements above are the acceptance test: per-request
database work should fall to roughly zero at 138 rules, and an upload larger
than the inspection prefix should reach the upstream without being held whole
in memory first.

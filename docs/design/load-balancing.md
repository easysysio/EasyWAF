# Design note — load balancing and upstream health

Status: planned for **0.8.0** — see [roadmap.md](roadmap.md), after rule updates
(0.7.0) and deliberately *before* backup/export (0.9.0).

## The gap

A site has exactly one upstream: `sites.target`, a single URL, formatted
straight into the request in [proxy/mod.rs](../../src/proxy/mod.rs). If it is
unreachable the request gets a 502 and that is the end of it — every request,
for as long as the backend is down, with nowhere else to send them.

So EasyWAF cannot be the only thing in front of an application that runs more
than one copy of itself, which is most applications that matter enough to put a
WAF in front of. Anyone who needs it keeps a load balancer behind EasyWAF, which
means two hops, two places to configure a backend, and a WAF that reports every
upstream as one address.

## Scope

Several upstreams per site, a way to choose between them, and a way to notice
that one has stopped answering.

**Out of scope, and worth saying so:** EasyWAF is still not a load balancer for
*itself*. Distributing traffic across EasyWAF nodes is the job of whatever sits
in front of them — DNS, a hardware balancer, keepalived — and stays that way
(see [ha-config-sync.md](ha-config-sync.md)). This is about what happens behind
EasyWAF, not in front of it.

## The data model change, which is the real work

`sites.target TEXT NOT NULL` becomes a one-to-many. That is a change to what a
site *is*, not a column added beside it, and it touches the site form, the
proxy's request path, the export format and the traffic record.

An `upstreams` table keyed on site, carrying at least the URL, a weight, and an
enabled flag. The migration writes one row per existing site from its current
`target`, so nothing changes for anyone until they add a second.

**A site with one upstream must look exactly as it does now.** The overwhelming
majority will have one, and making everyone learn a pool, a policy and a health
check to point at a single container would be a poor trade for a feature they
are not using. One upstream: one field, as today. The rest appears when a second
is added.

## Choosing an upstream

**Round-robin, weighted.** Enough for almost everyone, and the weight covers the
common real case of backends on unequal hardware. Least-connections is the
tempting alternative and needs in-flight accounting per upstream; it is worth
having only once there is evidence round-robin is losing, which there is not
yet.

**Session affinity is a separate switch, and needed sooner than it looks.** Any
backend keeping state in memory — a PHP session, an in-process cache — breaks
under round-robin in ways that look like random logouts rather than like a load
balancer problem. Affinity by cookie rather than by client IP: NAT puts many
clients behind one address, and EasyWAF already sets and verifies signed cookies
for sessions and CAPTCHA clearance, so the machinery exists and the cookie
should be signed the same way. A client whose pinned upstream is down gets
re-pinned rather than an error.

## Health, without building a prober first

The instinct is a background job probing every upstream on a timer. Do the other
thing first.

**Passive checks, circuit-breaker shaped.** Count failures on real traffic; after
N consecutive failures take the upstream out of rotation for T seconds; then let
a single request through and restore it if that succeeds. This needs no new
scheduling machinery, sends no synthetic traffic at backends that may not want
it, and — the part that matters — measures the thing actually being asked, which
is whether *this proxy* can serve *this site* from *this backend*. A prober can
report a backend healthy while every real request to it fails.

Its weakness is recovery latency: nothing notices a backend is back until the
half-open probe. That is a tuning question, not a design flaw, and an active
prober can be added later for operators who want faster recovery.

**What a failure counts as needs defining precisely.** A connection refused or a
timeout is the upstream's fault. A 500 probably is. A 404 is not — that is the
application answering, and treating it as ill health would take a working
backend out of rotation because someone requested a missing page.

**When every upstream is down**, the answer is still 502 — but it should say
that all upstreams are down rather than repeating today's generic text, because
the two are different problems and the operator's next step differs.

## Interactions

**Traffic records must name the upstream that served the request.** Without it,
"this site is intermittently slow" cannot be traced to one bad backend, which is
the single most common thing load balancing is asked to help diagnose. This is a
column on `traffic_events` and should land with the feature rather than after
it.

**Health state is per node and must never sync.** When configuration sync
arrives (0.11.0), the *list* of upstreams is shared configuration; which of them
are currently in rotation is a local observation — node A may reach a backend
node B cannot, and copying that judgement between them would take a working
backend out of rotation everywhere because one node has a network problem. It
belongs in the per-node column of that note's table, next to rate-limit counters
and learned URL sets.

**The GUI should show rotation state**, since a silently ejected backend is
exactly the thing an operator needs to see and has no other way to learn.

## Why 0.8.0

**Before backup/export**, for the same reason export sits after rule updates: it
changes what a core object *is*. An export written while a site has one `target`
would encode that shape and need reworking the moment a site has a pool. Model
changes belong before the format that has to represent them.

**After rule updates**, which are more central to what EasyWAF is for. A WAF that
cannot refresh its rules is a worse WAF; a WAF that cannot balance across two
backends is a proxy with a gap that a separate load balancer already fills for
anyone who hit it.

It is scheduled rather than left as a candidate because the alternative — the
status quo — quietly requires a second load balancer behind EasyWAF for any
application with more than one instance, which undercuts the premise of a
self-contained appliance.

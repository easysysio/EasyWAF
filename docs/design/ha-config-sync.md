# Design note — configuration sync between EasyWAF nodes

Status: planned for **0.10.0** — see [roadmap.md](roadmap.md), after
backup/export (0.8.0) and flow logs (0.9.0), and deliberately *before* rate
limiting and learning mode.

## What this is, and what it is not

Two or more EasyWAF nodes serving the same sites, with the same configuration,
so that losing one does not lose the service. Something in front of them —
DNS round-robin, a load balancer, keepalived with a VIP — decides which node a
request reaches. EasyWAF's job is to make the nodes *identical*, not to
distribute the traffic.

**Traffic is not synchronised.** Each node records what it saw. Seeing it in
one place is EasyLog's job (0.9.0), which is the right split: aggregating logs
is a solved problem in a product that already exists, and replicating a
high-write append-only table between nodes would be the most expensive and
least valuable thing to build.

So this is **configuration replication**, and it is worth being explicit about
what stays per-node, because "HA" invites the assumption that everything is
shared:

| Shared | Per-node |
|---|---|
| Sites, policies, rules, GeoIP rules, IP lists | Traffic events |
| Certificates, settings | Login sessions |
| | CAPTCHA clearance |
| | Rate-limit counters |
| | Learned URL sets |

The right-hand column is not an oversight; each entry is a decision with a
consequence, and the ones that bite are below.

## Topology: one writable node

Two shapes are possible and only one is worth building.

**Primary/replica.** One node owns the configuration; the others pull from it
and serve their GUI read-only, with a banner naming the primary. Changes have
one source, so there is nothing to reconcile.

**Multi-master.** Both nodes accept edits and reconcile. This requires an
answer to "site X was edited on both nodes during a partition" for every table,
and the honest answers are last-writer-wins (silently discards an operator's
work) or a merge UI (a feature in its own right, larger than this one).

Take primary/replica. The failure it is designed for is a node dying, and a
dead primary means configuration is temporarily read-only — an inconvenience,
while the traffic keeps being served by the replica, which is the entire point.
Promoting a replica should be a deliberate, documented operator action rather
than something automatic; automatic promotion needs consensus to avoid two
nodes both believing they are primary, and that is a distributed-systems
problem this product should not take on to avoid an occasional manual step.

## It is 0.8.0's export, applied continuously

This is why it follows backup/export rather than preceding it. The question
"what constitutes this appliance's configuration, expressed portably, without
primary keys that mean nothing on another host" is exactly what
[backup-restore.md](backup-restore.md) has to answer. Sync is that document
plus a transport, a schedule and a conflict rule.

If the two are designed apart they will disagree — two definitions of what
configuration is, drifting. Built adjacently, sync is a consumer of the export
format, and the format gets a second real user, which is the best way to find
out whether it was right.

## The interactions that actually matter

**Rate limiting counts per node, so limits multiply.** With two nodes and a
limit of 100 requests a minute, a client spread across both gets 200. This is
not a bug to fix later; it is a semantic that has to be chosen when rate
limiting is designed — document the per-node meaning, divide the configured
limit by node count, or share counters through a store, which is a much larger
feature. **This is the main reason sync is scheduled before rate limiting
rather than after.**

**Learning mode on split traffic learns a partial set.** Each node sees roughly
half the requests, so each learns roughly half the URLs. Switching to hardening
on either node then blocks legitimate traffic the *other* node learned about.
Learning results must therefore either replicate, or learning must run on one
node while the others are drained — and that is a design decision belonging to
[url-learning.md](url-learning.md), which is why sync precedes it too.

**ACME must renew on exactly one node.** If every node renews independently
they duplicate issuance, and Let's Encrypt's rate limits punish exactly that.
The primary renews; the resulting certificate replicates like any other
configuration. Since ACME (0.6.0) lands well before this, its design should
avoid assuming it is alone — at minimum leaving room for a "this node renews"
flag rather than making it an implicit truth.

**Sessions do not survive a node change unless the nodes share `secret`.**
Session cookies are signed with the key derived from `config.toml`'s `secret`.
Two nodes with different secrets means a load balancer moving an administrator
between them logs them out, apparently at random. `secret` is host
configuration and lives outside the database, so **sync cannot fix this** — it
has to be documented as a deployment requirement, and the GUI should warn when
it detects a peer whose signing key disagrees.

## Private keys cross the network

Certificates must replicate — both nodes serve the same sites — so `key_pem`
travels between hosts. This is the same constraint that shapes the export
format, one step more exposed, because now it is on a wire rather than in a
file someone chose to create.

Consequences to settle before coding: the transport is TLS with **mutual**
authentication, not a bearer token over HTTPS — a replica must prove which node
it is, not merely know a shared string that leaks the moment it appears in
anyone's shell history. The primary should be able to enumerate and revoke
peers, a peer's first enrolment should be an explicit approval on the primary
rather than anything automatic, and every sync should be recorded in the audit
log (0.9.0) with what changed and which peer received it.

## Open questions

* **Pull or push?** A replica polling the primary keeps every connection
  outbound from the replica and needs no inbound port on it; a primary pushing
  propagates faster. Polling is likely right, with an interval, and the GUI
  showing each peer's last-sync time and drift.
* **All-or-nothing, or per-object?** A replica that applies half a
  configuration is the same hazard as a half-applied restore.
* **What happens to a replica that cannot reach the primary?** It should keep
  serving its last good configuration indefinitely and say so prominently,
  never degrade or stop.
* **Does the replica's GUI allow local override?** Recommendation: no, with one
  exception worth considering — the IP allow/block list, since 0.11.0's whole
  premise is fixing a problem on the spot, and requiring a round trip to the
  primary during an incident undermines it. If allowed, it must be visibly
  temporary and reconciled explicitly.

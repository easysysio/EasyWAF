# Design note — flow logs over syslog, audit log on disk

Status: **shipped in 0.9.0** — see [roadmap.md](roadmap.md). It follows TLS
(0.4.0), ACME (0.5.0), the update work (0.6.0) and users and roles (0.8.0) — the
audit log deliberately comes after roles, since a trail recording that "admin
did X" says little when every operator is `admin`.

Moved to the front of the unreleased work on 2026-09-09, ahead of IP lists
and the engine release as well as load balancing and export.

The argument is the same each time and it has only got stronger: logging
*observes* the objects, where the others reshape them — a site's upstream
becomes a pool, an export has to encode that shape, the engine changes how a
request is buffered and matched. Nothing logging does is invalidated by any of
them, and everything they do is easier to see having shipped it first. Node
sync (0.14.0) depends on it outright: the traffic half of high availability is
deliberately not built, each node instead recording what it saw for EasyLog to
aggregate, so the aggregation should exist before the nodes do.

There is a practical argument too. The two releases it now precedes are the
ones most likely to need explaining after the fact — an IP list that refuses a
request, and an engine that streams a body it used to buffer. Having the flow
log and the audit trail already in place is what makes either debuggable.
The EasyLog parser question below is cross-repository and can be settled in
parallel, well before then.

## What EasyWAF did before this

Everything went to stdout through `tracing`, which systemd captures into the
journal. There were no log files, no rotation, and **no audit trail at all** —
22 state-changing POST handlers, none of which recorded who performed the
action. A traffic event was written to the `traffic_events` table and nowhere
else.

## Decisions taken

* **Flow logs go to syslog only** — one line per proxied request, sent to a
  collector, off by default.
* **The audit log is a local file only** — not syslog, not the database.
* Operational logging stays on stdout / the journal, which is what a
  systemd-managed service should do and what `journalctl -u easywaf` already
  gives. EasyWAF's own chatter is never forwarded.

**There is deliberately no local flow file.** An earlier draft had one, on the
grounds that a proxy which can only say what it did while a collector is
reachable cannot be debugged during an outage. That argument is already
answered: every proxied request is written to `traffic_events` and shown in
Traffic Monitor with its verdict, score, and the rules that produced it. A
`flow.log` beside the database would be the same data in a worse format, aged
out on a different schedule. Syslog's job is to get the stream *off the box* —
to hold more history than an appliance should, and to chart several appliances
together — not to duplicate what is already local.

The audit log is the other way round, and stays a file. It is evidence about
the appliance itself, and evidence is least useful when it can only be read
from the machine it accuses; a local file survives the collector being
unreachable, which is precisely when it matters. Sending it as well is a
defensible future option; sending it *instead* is not.

## 1. Flow logs over syslog

One line per proxied request, emitted from the same place `log_event` is called
so the syslog line and the database row describe the same event.

**The request path must not wait for the network.** `log_event` is already
spawned so it never delays a response; the syslog sender must be at least as
careful:

* a bounded channel with a fixed capacity, written to with `try_send`
* **drop on full, and count what was dropped** — a proxy must not stall because
  a log collector is slow or gone. A periodic "dropped N flow lines" warning
  makes the loss visible rather than silent
* UDP first (fire and forget, matching what EasyLog ingests); TCP is a possible
  later addition for delivery guarantees
* reconnect/resolve failures are logged once, not per request

**Format.** EasyLog routes an incoming line to a parser by the sending host's
IP, so the format has to be one EasyLog understands. Two options, to settle
before implementation:

1. Emit a format EasyLog already parses (its combined-access-log or JSON
   parsers), which works today with no EasyLog change but loses the
   WAF-specific fields — verdict, rule name, score, country.
2. Add an `easywaf` log type to EasyLog with its own parser, storage and
   dashboard — blocked / challenged / passed over time, top rules fired, top
   countries, top client IPs.

Option 2 is the one worth building: those fields are the entire point of a WAF,
and EasyLog's log types are self-contained modules designed to be added. It is
cross-repository work and should be planned as such.

**Configuration.** The collector is a setting in the GUI, under Settings ›
Logging: enabled, host, port. It is a thing an operator changes — a collector
moves, a port changes — and changing it should not mean editing a file on the
appliance and restarting the proxy. The logger reads the address per line from
a shared cell, so a save takes effect on the next request.

What stays in `config.toml` is what has to be known before the database is
open, or set from outside a container image:

```toml
[logging]
dir       = "/var/log/easywaf"  # audit.log lives here
keep_days = 14                  # daily rotation, then delete
```

Both sinks share one bounded channel and one drop counter, for the same reason:
a slow disk must not stall the proxy any more than a slow collector may.

## 2. Audit log

`audit.log` in the log directory, one line per state-changing action, with the
account and the client address.

**Recorded by middleware on the management router, not by each handler.** Every
state-changing route is a POST behind the `Admin` extractor, so the router
knows the account, the path, the client address and the outcome without any
handler remembering to say so. That is the same reasoning that made
authorisation an extractor in 0.8.0: a trail that depends on thirty-seven
handlers each calling a function is a trail with holes in it, and the holes are
exactly where somebody did something they should not have.

Signing out is the one GET the layer treats as state-changing — it is a link
rather than a form, and a trail with sign-ins but no sign-outs leaves every
session looking open.

Signing in is the one case the layer cannot read on its own: the account is in
the request body, which it deliberately does not parse, and a refused attempt
answers 200 with the form again. The handler attaches the name and the outcome
to its response, and the layer prefers that when it is there. It is an escape
hatch for what the router cannot see, not the interface — everything else is
derived from the request and the response.

Refusals are recorded, not only successes: a viewer's POST to an
administrator's page is a line saying `result=refused`, which is the line
somebody reviewing the trail is looking for. A save the handler rejected
carries the reason it showed on screen, read back out of the flash redirect, so
the trail says *why* rather than showing a 303 that looks like a success.

What must appear:

* sign-ins, failed sign-ins, sign-outs
* site create / update / delete / enable / disable
* policy create / update / delete, including country-rule changes
* rule add / edit / toggle / delete / import
* certificate add / delete
* settings changes

Daily rotation, keeping `log_keep_days` files (default 14), so there is nothing
to configure in logrotate — matching EasyLog.

**Do not log the content of secrets.** Certificate private keys and the session
secret must never reach the file; record that the object changed, not what it
changed to.

If the directory cannot be written, log a warning and continue on stdout rather
than refusing to start: a source build running unprivileged should not fail
because `/var/log/easywaf` is root-owned.

## 3. Packaging and deployment

* **systemd**: add `LogsDirectory=easywaf` to the unit, which creates and owns
  `/var/log/easywaf`. This is the convention EasyLog already uses
  (`LogsDirectory=easylog`).
* **Docker**: `/var/log/easywaf` there too, so the path is the same wherever
  EasyWAF runs and there is one answer to "where is the audit log". It is
  inside the container and goes with it unless something is mounted there,
  which is why the directory stays configurable — an installation that wants
  the log on the `/data` volume points it there.

## Open questions

* Which of the two syslog formats above — and if the EasyLog parser, when is
  that work scheduled in the EasyLog repository?
* Should the audit log also be viewable in the GUI? A read-only page is cheap
  and useful, but an audit trail an administrator can read through the same
  session it records is weaker evidence than a file only root can read.
* Retention for the audit log is time-based here. Some environments require it
  to be shipped off-box and never rotated locally — worth confirming before
  choosing the default.

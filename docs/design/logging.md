# Design note — flow logs over syslog, audit log on disk

Status: planned for **0.10.0** — see [roadmap.md](roadmap.md). It follows TLS
(0.4.0), ACME (0.5.0), users and roles (0.6.0), the update work (0.7.0), load
balancing (0.8.0) and backup/export (0.9.0) — the audit log deliberately comes
after roles, since a trail recording that "admin did X" says little when every
operator is `admin`.
The EasyLog parser question below is cross-repository and can be settled in
parallel, well before then.

## What EasyWAF does today

Everything goes to stdout through `tracing`, which systemd captures into the
journal. There are no log files, no rotation, and **no audit trail at all** —
22 state-changing POST handlers, none of which record who performed the action.
A traffic event is written to the `traffic_events` table and nowhere else.

## Decisions taken

* **Syslog carries flow logs only** — one line per proxied request. EasyWAF's
  own operational chatter is not forwarded.
* **The audit log is a file** under `/var/log/easywaf/`, not syslog and not the
  database.
* Operational logging stays on stdout / the journal, which is what a
  systemd-managed service should do and what `journalctl -u easywaf` already
  gives.

The reasoning for the split: flow logs are a stream that belongs in a collector
— EasyLog exists to hold and chart exactly that. The audit log is evidence
about the appliance itself, and evidence is least useful when it can only be
read from the machine it accuses; keeping it as a local file means it survives
the collector being unreachable, which is precisely when it matters.

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

**Configuration** (`config.toml`, since it is needed before the GUI is up):

```toml
[syslog]
enabled  = false          # off by default; sending traffic off-box is opt-in
host     = ""             # collector address, e.g. "10.0.0.9"
port     = 514
protocol = "udp"
```

## 2. Audit log

`/var/log/easywaf/audit.log`, one line per state-changing action, with the
account and the client address. What must appear:

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
* **Docker**: `/var/log` inside a container is lost with the container, and the
  image already declares `/data` as its volume. The log directory must
  therefore be configurable rather than a fixed path, defaulting to
  `/var/log/easywaf` for packages and set to `/data/log` in the image's
  `config.toml`.

## Open questions

* Which of the two syslog formats above — and if the EasyLog parser, when is
  that work scheduled in the EasyLog repository?
* Should the audit log also be viewable in the GUI? A read-only page is cheap
  and useful, but an audit trail an administrator can read through the same
  session it records is weaker evidence than a file only root can read.
* Retention for the audit log is time-based here. Some environments require it
  to be shipped off-box and never rotated locally — worth confirming before
  choosing the default.

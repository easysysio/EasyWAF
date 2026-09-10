# Logging

EasyWAF writes three separate things, and keeps them separate on purpose.

| | Where | Switch |
|---|---|---|
| **Flow logs** — one line per proxied request | syslog, to a collector | Off by default |
| **Audit log** — every change made through the interface | `/var/log/easywaf/audit.log` | Always on |
| **Operational logging** — what the service itself is doing | stdout, so the journal | `journalctl -u easywaf` |

## Flow logs

One line per proxied request, sent to a syslog collector over UDP: the site, the
client, the method and full path, the verdict, and the score and rules behind it.

Turn it on under **Settings → Logging** with the collector's address and port.
The change applies to the running proxy — there is no restart and no file to
edit.

```
ts=2026-09-09T12:50:42Z site=cloud host=localhost client=127.0.0.1 method=GET
path="/etc/passwd?evil=%27+OR+1%3D1" status=403 ms=0 verdict=blocked score=10
rules=930001 reason="WAF score 10 ≥ block threshold 10"
```

The format is [logfmt](https://brandur.org/logfmt): `key=value`, quoted only when
a value could otherwise split the line. Values that arrive from the wire — the
path, the host — are escaped, so nothing a client sends can forge a field.

**Nothing is written locally.** Every request is already in
[Traffic Monitor](traffic.md) with the same detail, so a file beside the database
would be the same data in a worse format. Syslog exists to get the stream *off
the box* — into a collector that can hold more history than an appliance should,
and chart several appliances together.

Lines are sent without waiting. If the collector is slow or gone, lines are
dropped and the count is reported in the journal, rather than the proxy slowing
down behind them. A WAF that stalls because a log collector is unreachable has
turned its logging into an outage.

!!! tip "EasyLog"
    [EasyLog](https://easysys.io) parses this format natively, with dashboards
    for blocked and challenged traffic over time, top rules, top countries and
    top clients.

## Audit log

Every state-changing action through the management interface, written to
`/var/log/easywaf/audit.log`, one file per day.

```
ts=2026-09-09T13:09:16Z user=admin role=admin client=10.0.0.5 method=POST
path=/settings/update status=303 result=ok ms=12
```

It records the account, the client address, what was done and how it came out —
including sign-ins, failed sign-ins and sign-outs, and including **refusals**: a
viewer's attempt at an administrator's page is a line saying `result=refused`,
which is the line somebody reviewing the trail is looking for. A change the
appliance rejected carries the reason it showed on screen.

It records what was done, never what it was done with: method, path, account,
address and outcome — no bodies and no query strings, so a password or a private
key cannot reach the file by being an argument to something.

There is no switch for it. An appliance that cannot say who changed it is not one
to run, and it is a local file whose only cost is disk. It stays on the machine
rather than going to a collector: evidence about an appliance is least useful when
it can only be read from the machine it accuses.

Recording is done by a layer on the router rather than by each page, so a page
added later cannot forget to be in the trail.

## Rotation

A file per day, named `audit-YYYY-MM-DD.log`, with `audit.log` as a symlink to
today's — so `tail -F audit.log` keeps working across a rotation.

Files older than `keep_days` (14 by default) are deleted. There is nothing to set
up in logrotate.

## What is configured where

The collector is a setting in the interface, because it is a thing operators
change — a collector moves, a port changes — and that should not mean editing a
file on the appliance and restarting the proxy.

The directory and the retention are in `config.toml`, because the directory has
to be known before the database is open, and because a container needs to set it
from outside the image:

```toml
[logging]
dir       = "/var/log/easywaf"   # audit.log, one file per day
keep_days = 14                   # then deleted; 0 keeps everything
```

The systemd unit declares `LogsDirectory=easywaf`, so the directory is created
and owned before the service starts.

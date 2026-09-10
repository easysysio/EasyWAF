# What EasyWAF does not do

Called out so nothing here is a surprise in production. Split by whether it is
scheduled or decided.

Current as of **0.9.1**.

## As a reverse proxy

- **A WebSocket tunnel is not inspected.** The handshake is a normal request and
  goes through the rule engine like any other, but once the connection is
  upgraded EasyWAF relays opaque frames — the payload is no longer HTTP, so there
  is nothing for HTTP rules to match. The connection appears in Traffic Monitor
  as its handshake.
- **Upgrades to an `https://` upstream are refused.** Plain-HTTP upstreams tunnel
  fine; a TLS upstream would need a TLS client on the tunnelling path, which is
  not built.
- **No HTTP/2 to clients.** No ALPN is advertised, so connections are HTTP/1.1.
  Not scheduled.
- **Routing is by `Host:` only, matched exactly.** A site can answer for several
  hostnames, but there are no path prefixes and no wildcard hostnames like
  `*.example.com`. Two applications behind one hostname cannot be split. Not
  scheduled.
- **One upstream per site.** No load balancing, no health checks, no failover —
  an application running more than one instance needs a load balancer behind
  EasyWAF. Scheduled for **0.12.0**.
- **IPv6 literal hostnames do not route.** Host matching truncates at the first
  colon, so `[::1]:8080` does not match. Name-based hosts are unaffected.
- **No health or metrics endpoint.** Nothing to point a load balancer's health
  check at, and no Prometheus scrape target.

## As a WAF

- **Requests only — responses are not inspected.** Nothing detects what leaks
  *out*: stack traces, SQL errors, directory listings, card numbers. This is the
  half of a WAF that the OWASP Core Rule Set reserves its 950xxx band for. Not
  scheduled, and it has a real cost: responses stream today, and inspecting them
  means buffering.
- **Some rule transformations are not implemented.** Rules converted from the
  Core Rule Set assume decoding steps — HTML entity, JavaScript and CSS decoding
  — that EasyWAF does not yet perform, so an attack hidden behind one of those
  encodings can pass a rule written to catch it. Scheduled for **0.11.0**.
- **Traffic history holds no headers or bodies** — method, host, path, country
  and verdict only, and the path without its query string. A new rule cannot be
  replayed against past traffic to see what it would have matched. The
  [flow log](logging.md) carries the full path and query.
- **Request bodies are buffered to 32 MB** so rules can inspect them; anything
  larger is refused with 400.

## Managing it

- **ACME is HTTP-01 only.** No wildcards — those need DNS-01, which needs
  credentials for a DNS provider's API. Upload a wildcard certificate instead.
  Validation always arrives on port 80, so the host must be reachable there from
  the internet.
- **No backup, restore or configuration export.** Everything is in one SQLite
  file with no way to export it, clone it to staging, or keep it under version
  control. Scheduled for **0.13.0**; until then,
  [copy the file](configuration.md#backing-up) with the service stopped.
- **No high availability.** No configuration sync between nodes. Scheduled for
  **0.14.0**.
- **No IP allow or block lists** — nothing refuses a client outright, at any
  scope. Scheduled for **0.10.0**.
- **No rate limiting.** Scheduled for **0.15.0**.
- **No authentication in front of a site.** EasyWAF decides whether a request is
  an attack, not who is making it. Proposed, not scheduled.

## Decided, not missing

- **TLS version and cipher suites are appliance-wide, not per site.** rustls
  fixes both when a listener binds its port, before the client has said which
  site it wants, so sites sharing a port necessarily share them. Certificates
  *are* per site, chosen by SNI. Per-site and per-port policies were both
  considered and declined.
- **There is no local flow log file.** Every request is already in Traffic
  Monitor with the same detail; a file beside the database would be the same data
  in a worse format. Syslog exists to get the stream off the box.
- **There is no password recovery.** No mailer, no second account to reset from.
  A lost administrator password means editing the `users` table directly — which
  is the argument for keeping a second administrator account.
- **Traffic is not replicated and is not intended to be.** When node sync
  arrives, each node will keep its own traffic history and
  [EasyLog](https://easysys.io) will aggregate it.

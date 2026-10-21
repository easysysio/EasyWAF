# What EasyWAF does not do

Called out so nothing here is a surprise in production. Split by whether it is
scheduled or decided.

Current as of **1.5.0**.

## As a reverse proxy

- **A WebSocket tunnel is not inspected.** The handshake is a normal request and
  goes through the rule engine like any other, but once the connection is
  upgraded EasyWAF relays opaque frames — the payload is no longer HTTP, so there
  is nothing for HTTP rules to match. The connection appears in Traffic Monitor
  as its handshake.
- **Upgrades to an `https://` upstream are refused.** Plain-HTTP upstreams tunnel
  fine; a TLS upstream would need a TLS client on the tunnelling path, which is
  not built.
- **No HTTP/2 to clients.** No ALPN is advertised, so connections are HTTP/1.1,
  and a client that opens with HTTP/2 anyway is disconnected. Not scheduled.
- **Routing is by `Host:` only, matched exactly.** A site can answer for several
  hostnames, but there are no path prefixes and no wildcard hostnames like
  `*.example.com`. Two applications behind one hostname cannot be split. Not
  scheduled.
- **Upstream health is observed, not probed.** A backend is taken out of the
  rotation after three failed requests and tried again thirty seconds later, so
  nothing notices a backend is back until that request. There is no active
  health check, and no way to tune the thresholds yet.
  - **Session affinity needs a client that keeps cookies.** The pin is a
    signed cookie, since many clients share one address behind NAT; a client
    that discards cookies goes round the pool in turn. There is no
    address-based affinity.
- **Listens on IPv4 only.** Every port — the sites' and the management
  interface's — is bound on the host's IPv4 addresses. A client with only IPv6
  cannot connect unless something in front of EasyWAF accepts it.
- **IPv6 literal hostnames do not route.** Host matching truncates at the first
  colon, so `[::1]:8080` does not match. Name-based hosts are unaffected.
- **No health or metrics endpoint.** Nothing to point a load balancer's health
  check at, and no Prometheus scrape target.
- **The connection limits are fixed.** A connection has 30 seconds to send a
  request, the inspected start of a body may not stall for longer than that,
  and one address — or one IPv6 /64 — may hold 1,024 connections at once. None
  of them is a setting. A client behind another proxy is counted as that proxy unless the
  proxy is listed as trusted, which exempts it.

## As a WAF

- **Requests only — responses are not inspected.** Nothing detects what leaks
  *out*: stack traces, SQL errors, directory listings, card numbers. This is the
  half of a WAF that the OWASP Core Rule Set reserves its 950xxx band for. Not
  scheduled, and it has a real cost: responses stream today, and inspecting them
  means buffering.
- **At most 1,024 arguments, cookies, XML attributes and uploaded files** are
  read from one request; any beyond that are seen only by the zones that read
  whole text. An uploaded file's content is not an argument; `BODY` reads it
  as it arrived, up to the inspection limit.
- **`HEADER_BLOCK` is rebuilt, not the bytes that arrived.** Header names are
  written as `User-Agent` whatever case they came in, and a repeated header's
  lines sit together after its first, so a rule about the exact case or the
  interleaving of headers sees them as most clients send them.
- **A rule sees one request.** A condition can count what a request holds
  (`&ARG`) and compare a number, but nothing carries from one request to the
  next, so ET's rules that need state across requests are refused by the
  converter. So are CRS's rules comparing one captured value with another.
- **A rule's conditions are not edited in the interface.** They are shown on
  its page; one with several comes from a rule set or an import.
- **No exclusion by argument.** An exclusion silences a rule on a path or for a
  client, not on one argument, so a rich-text field that trips a rule is
  excluded with the whole path. Not scheduled; the obvious step after 1.2.0.
- **Some rule transformations are still not implemented.** Every value is
  matched HTML-entity, JavaScript, CSS and `%uHHHH` decoded and with its path
  normalised, and a rule can name `cmdLine`, `replaceComments`,
  `removeWhitespace`, `base64Decode`, `escapeSeqDecode` and the rest of
  [the decodings](policies.md#decoding-a-rule-names) to be matched after.
  `sqlHexDecode`, `removeComments`, `hexDecode` and Suricata's `xor` and
  `pcrexform` are not applied, so the rules assuming them are still refused by
  the converters rather than shipped broken. Base64 is decoded only for a rule
  that names it: decoding it everywhere would match ordinary payloads — an image
  upload, a JWT, a session blob.
- **A rule's decodings are not edited in the interface.** They are shown on its
  page, beside its conditions.
- **Traffic history holds no headers or bodies** — method, host, path, country
  and verdict only, and the path without its query string. A new rule cannot be
  replayed against past traffic to see what it would have matched. The
  [flow log](logging.md) carries the full path and query.
- **Under a flood, traffic rows can be dropped.** Rows are written in batches
  from a queue, and a request is never held up to record it: if the queue fills —
  tens of thousands of requests a second — the rows that do not fit are dropped,
  and the journal says how many.
- **Request bodies are inspected up to a limit** — 128 KB by default, under
  **Settings → Proxy**. The rest of a body is forwarded uninspected as it
  arrives, so a payload padded past the limit is not seen.
- **A body compressed with Brotli or Zstandard is not inspected.** gzip and
  deflate are inflated and read; the others are matched as the bytes they
  arrive as, which no rule recognises. Browsers do not compress request bodies,
  and few servers accept those two.

## Managing it

- **ACME is HTTP-01 only.** No wildcards — those need DNS-01, which needs
  credentials for a DNS provider's API. Upload a wildcard certificate instead.
  Validation always arrives on port 80, so the host must be reachable there from
  the internet.
- **No high availability.** No configuration sync between nodes. Scheduled for
  **1.7.0**.
- **No list of proxy, VPN or hosting addresses.** Every credible dataset is
  commercial, and the cloud providers' own address files may not be
  redistributed. The [published lists](ip-lists.md#published-lists) cover
  hijacked netblocks, compromised hosts and Tor exits only.
- **No feed of your own.** A published list comes from the signed channel; there
  is no way yet to point EasyWAF at another list's URL.
- **No rate limiting.** Scheduled for **1.8.0**. An address that attacks
  repeatedly is handled by [Smart Protect](smart-protect.md), which counts
  refusals, not requests.
- **Smart Protect blocks are per node and do not survive a restart.** They are
  held in memory, and a repeat offender is blocked for the same length each
  time rather than longer.
- **A sign-in is a name and a password, from EasyWAF's own accounts or LDAP.**
  No single sign-on from an identity provider (OIDC, SAML), no second factor
  and no passkeys. Not scheduled.
- **Somebody removed from a directory keeps a session they already have** until
  it runs out — an hour unused, eight at most, by default. The directory is
  asked at sign-in and not again; *Sign everyone out* ends it sooner.
- **Failed sign-ins are counted per node and forgotten on a restart**, as Smart
  Protect's blocks are.
- **No allowlist of an application's own URLs.** Every rule describes what an
  attack looks like; nothing yet learns what the application legitimately
  exposes and refuses the rest. Scheduled for **1.9.0**.

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

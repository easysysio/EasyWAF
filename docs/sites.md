# Sites

A site is a hostname, an upstream, and the ports EasyWAF answers on for it.
Everything about it is stored in the database and edited in the interface — there
is no file to edit and no reload to remember.

## Routing

Requests are matched on the `Host:` header, exactly, against enabled sites. A
request that matches nothing gets a 404.

The port suffix is stripped before matching, so a site's hostname is a bare name:
`example.com`, never `example.com:8443` and never a URL.

## Aliases

A site answers for its hostname plus any aliases you give it — one per line, or
comma separated. Every alias shares the site's upstream, policy, ports, headers
and certificate.

That is the point: two names for one application used to mean two sites carrying
the same settings, kept in step by hand, and any divergence was a bug that
appeared on only one of the names.

- A hostname belongs to **one site only**. Claiming one another site already has
  is refused, and the message names that site.
- **No wildcards.** The `Host:` header is matched exactly, and a wildcard
  certificate needs a DNS-01 challenge EasyWAF does not implement.
- Saving the form does **not** reissue a certificate. A name added to a live site
  is served immediately, but a browser reaching it gets a warning until the
  certificate covers it — [request one](tls.md#lets-encrypt) and every name on
  the site is included.

## Upstreams

A site starts with one backend — the **Upstream Target** field — and that is all
most sites ever need. Add a second under **Upstreams** on the site's page and
requests go round them **in turn**, a heavier **weight** taking a larger share,
which is what backends on unequal hardware are for.

**A backend that stops answering is taken out of the rotation** after three
failures in a row, and one request is let through thirty seconds later to find
out whether it is back. Unreachable counts as a failure and so does a `5xx` —
that is the backend saying it cannot answer. A `404` does not: that is the
application answering, and a missing page is no reason to stop using a working
backend.

**A request that can safely be sent again is retried on another backend**, so
one backend failing costs nothing. A request whose body is still arriving cannot
be retried — the body is a stream, and the first attempt consumes it — so a
large upload to a backend that dies mid-request gets a 502.

Two things the pool will not do:

- **A site is never left with nothing to forward to.** The last backend cannot
  be removed or switched off; disable the site itself instead.
- **A pool where every backend is out still gets asked.** All of them failing at
  once is what a deploy looks like. If none answers, the response says *all
  upstreams for this site are down*, which is a different problem from one
  unreachable backend.

The rotation state shown beside each backend — in rotation, failing, out — is
what **this node** has observed. It is never shared with another node: a backend
one node cannot reach may be perfectly reachable from another.

Each traffic record names the backend that served it, so a site that is
intermittently slow can be traced to one of them.

### Session affinity

Off by default. Switch it on — the checkbox under **Upstreams** — when a
backend keeps something in memory: a session, an in-process cache, an upload
being assembled. Without it a client's requests are spread across the pool, and
the symptom is a user logged out at random rather than anything that looks like
a proxy problem.

**A client is pinned by a signed cookie, not by its address.** Many clients
share one address behind NAT, and pinning by address would hold a whole office
to one backend. The cookie holds only which backend, is signed with this
installation's own key, and is rejected if it is tampered with — a client
cannot choose its own backend and aim traffic at one of them. It is a session
cookie, `HttpOnly`, and `Secure` on an HTTPS site.

**If the pinned backend goes out of rotation the client is pinned to another**,
not refused: a client that cannot be served until it clears its cookies is a
client that will never think to. It stays on the new backend afterwards.

A client that keeps no cookies — most API clients — cannot be pinned, and goes
round the pool in turn as usual.

## Ports

One or more HTTP ports, and optionally one or more HTTPS ports, comma separated.

- A port is bound as soon as you save. Adding a site on a new port does not need
  a restart.
- Ports are shared: several sites can listen on 443, each presenting its own
  certificate, chosen by SNI during the handshake.
- A site given an HTTPS port but no certificate **does not bind that port at
  all**. A port that is not listening is far easier to diagnose than one that
  fails every handshake.
- Removing a port from a site does not close the listener — other sites may be
  using it. It stops answering for that site immediately; the listener goes at
  the next restart.

## HTTPS

Setting an HTTPS port serves the site over TLS **as well as** plain HTTP.
Turning on **Redirect HTTP to HTTPS** sends the plain port to the TLS one, and it
is off by default — enabling HTTPS never silently takes away the port your
callers are already using.

The redirect names the site's HTTPS port, so a site on a non-standard port
redirects to that port rather than to 443.

Certificates are per site. The TLS version profile and the cipher suites are
appliance-wide — see [TLS and certificates](tls.md#profile-and-cipher-suites) for
why.

## Security headers

Toggled per site, applied to every response EasyWAF forwards:

| Header | Notes |
|---|---|
| `Strict-Transport-Security` | HSTS. A browser ignores it over plain HTTP, so it only does something once the site serves HTTPS |
| `X-Frame-Options` | `SAMEORIGIN` or `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | Legacy; modern browsers ignore it |

## What is sent upstream

EasyWAF adds the headers an application needs to know what the client actually
asked for:

```
X-Forwarded-For     the client address
X-Real-IP           the same
X-Forwarded-Proto   http or https, as the client connected
X-Forwarded-Host    the hostname the client asked for
```

Hop-by-hop headers are stripped, as a proxy must. WebSocket upgrades are
tunnelled: the handshake is inspected like any other request, and the connection
that follows is relayed as opaque frames.

Request bodies are inspected up to a limit — 128 KB by default, under
**Settings → Proxy** — and the rest streams to the site as it arrives. There is
no upload size limit, and a large upload is not held in memory first. Bytes
past the limit are not inspected.

## Disabling a site

Disabling stops EasyWAF proxying that hostname. Visitors get a **maintenance
page** — 503, with the message set under **Settings** — rather than a 404,
because the hostname is configured and expected back, and saying so is more use
than pretending it was never there.

Nothing else about the site is touched, so re-enabling restores it exactly as it
was. Its listener stays bound for the other sites sharing it.

## Behind another proxy

If something else sits in front of EasyWAF, list its addresses under **Settings →
Proxy → Trusted Proxies**. The client address is then taken from
`X-Forwarded-For` — but only for connections from a listed address, so a client
cannot claim to be someone else.

The list is empty by default, which means the header is ignored entirely and the
client is whoever connected.

!!! warning "Only list proxies you control"
    `X-Forwarded-For` is a header; anyone can send one. If EasyWAF believed it
    unconditionally, any client could claim any address and walk past country
    rules and CAPTCHA clearance. Getting it wrong the other way matters too:
    behind a proxy with nothing listed, every request looks like it came from
    that proxy, so one visitor solving a CAPTCHA clears it for everyone.

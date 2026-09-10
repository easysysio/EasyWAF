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

Request bodies are buffered up to 32 MB so rules can inspect them. Anything
larger is refused with 400.

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

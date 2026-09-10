# TLS and certificates

## Certificates

Under **Certificates** you can upload a certificate and its key, request one from
Let's Encrypt, or inspect what you already have.

Certificates are chosen **per site, by SNI**, during the handshake. Many sites
share one HTTPS port, each presenting its own.

Clicking a certificate shows what it says about itself: subject and issuer,
validity and days remaining, the names it covers, key type and size, chain
length, and its SHA-256 fingerprint. The private key is never shown and cannot
be exported from the interface — viewers can read this page, which is why.

## Let's Encrypt

Set a contact address under **Settings → TLS**, then request a certificate from
a site's page or from the Certificates page.

EasyWAF answers the **HTTP-01** challenge itself on port 80. There is no webroot
to configure and nothing to change on the backend. Port 80 is bound whatever
ports your sites use, precisely so validation always has somewhere to arrive.

For this to work, every name being requested must resolve to this host from the
public internet, and port 80 must be open to it.

**Requesting from a site's page asks for every hostname that site answers for** —
its own name and all its aliases — in one certificate. Each name is validated
separately and they all have to succeed: a name that does not resolve here means
no certificate at all, rather than one quietly missing that name.

### Renewal

Automatic, at 30 days remaining. Thirty leaves four weeks of retries before
anything expires, which makes a failing renewal something to look into rather
than an emergency.

The retry backoff is stored in the database, so restarting the service cannot
turn a failing renewal into a rate-limited account. Each certificate's page shows
when renewal was last attempted, whether it worked, what the CA said if it did
not, and when the next attempt is due.

A renewal re-requests **every name the certificate was issued for**.

!!! note "Start with the staging directory"
    Let's Encrypt's production rate limits punish retry loops. The staging
    directory issues untrusted certificates with far looser limits — get the
    validation working there first, then switch.

!!! info "No wildcards"
    A wildcard certificate requires the DNS-01 challenge, which needs credentials
    for a DNS provider's API. EasyWAF does not implement it. Upload a wildcard
    certificate issued elsewhere instead — nothing stops you serving one.

## The management certificate

On first start EasyWAF generates a self-signed certificate named `easywaf` and
serves the management interface with it, so the interface is never served over
plain HTTP.

To use your own: upload it under **Certificates**, select it as the **Management
Certificate** under **Settings → TLS**, and restart.

The generated one stays as a fallback. If the certificate you picked is later
removed or becomes unusable, EasyWAF starts on `easywaf` and logs why, rather
than leaving you with no way in.

A certificate that cannot serve TLS is refused when you save the setting, not at
the next restart — the interface is the only place this setting can be corrected,
so a bad value that only failed later would take away the means of fixing it.

## Profile and cipher suites

Two appliance-wide settings under **Settings → TLS**, covering the proxied sites
**and** the management interface. Both take effect on restart.

They are appliance-wide rather than per site because rustls fixes both when a
listener binds its port — before the client has said which site it wants. Sites
sharing a port necessarily share them. Certificates are the per-site part, and
those are chosen by SNI.

| Profile | Meaning |
|---|---|
| Compatible | TLS 1.2 and 1.3 |
| Modern | TLS 1.3 only |

The cipher suites are one editable line, pre-filled with everything this build
supports. Delete the ones your policy forbids. A name EasyWAF does not recognise
is refused when you save rather than dropped, so a restriction you believe is in
force always is — and Modern with no TLS 1.3 suite selected is refused too,
since no connection could be negotiated.

Nothing weak is on that line to begin with. All nine suites are AEAD, and the
TLS 1.2 ones are all ECDHE:

```
TLS13_AES_256_GCM_SHA384                  TLS13_AES_128_GCM_SHA256
TLS13_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

So a requirement to disable CBC — or RC4, 3DES, static-RSA key exchange, or
anything below TLS 1.2 — is met before any configuration: none of it is
implemented, so none of it can be selected. Restricting the line is for policies
that go further, such as AES-only or 256-bit-only.

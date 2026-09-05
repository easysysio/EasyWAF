# Design note — ACME / Let's Encrypt

Status: **released in 0.5.0** (2026-09-05) — see [roadmap.md](roadmap.md). Scoped to
**HTTP-01**; wildcards and DNS-01 are deliberately out (see the roadmap's
constraints section).

## What 0.1.0 already left in place

The schema anticipated this and needs no migration to begin:

* `acme_accounts` — `email`, `private_key`, `directory`, one row per installation
* `certs` — `acme_domain`, `acme_expires`
* `sites` — `acme_enabled`

An issued certificate is stored as an ordinary row in `certs`, and the site's
`cert_id` points at it like any uploaded one. Everything downstream — the SNI
map, the detail page, the deletion guard, per-site selection — then works
without knowing where the certificate came from.

## The challenge is served by the proxy, not from a directory

`config.toml` carries an `acme_webroot` placeholder from 0.1.0. It stays unused.
EasyWAF already owns the port the challenge arrives on, so it answers
`/.well-known/acme-challenge/<token>` itself. That needs no filesystem shared
with a backend, works while the upstream is down — which is exactly when someone
is most likely to be fixing certificates — and removes a class of
misconfiguration where the proxy and the backend disagree about which directory
is authoritative.

Three properties this path must have, each for a reason:

* **Before inspection.** The WAF must not score, challenge or block it. A token
  is opaque base64url and there is no reason a rule could not match one by
  accident; a certificate that fails to renew because a scanner rule matched its
  challenge token would be a genuinely awful outage to diagnose.
* **Independent of policy and of the upstream.** It must answer for a site with
  no policy attached, a disabled site, and a site whose backend is down.
* **Plain HTTP only, and never redirected.** HTTP-01 validation always arrives
  on port 80, and Let's Encrypt follows redirects — but a site with the
  HTTP-to-HTTPS redirect turned on and a broken certificate would bounce the
  validator into a connection it cannot complete. The challenge path is answered
  before the redirect is considered.

**The operational constraint this creates, which the GUI must state:** the site
has to be reachable from the internet on **port 80** for the name being issued.
A site listening only on 8080 behind something else cannot be validated this
way, and that is a property of HTTP-01 rather than of EasyWAF.

## Tokens live in memory

A `token -> key authorization` map, the same shape as the SNI certificate map:
written when an order is created, read by the proxy handler, removed when the
order finishes. Nothing is persisted — an interrupted order is simply retried,
and a token that outlived its order is worse than no token.

## Issuance

Account is created once per installation from the configured email and
directory, and its key is stored in `acme_accounts`. Certificates are **ECDSA
P-256** — smaller and faster than RSA, and universally supported by anything
that also speaks TLS 1.2 with an AEAD suite, which is the floor EasyWAF already
enforces.

**The directory URL is a setting, and staging is offered explicitly.** Let's
Encrypt's production limits punish the exact loop a first-time integration
produces — five failed validations per account, per hostname, per hour. Anyone
setting this up for the first time should be able to point at staging, watch it
work end to end, and switch. A GUI that only offers production teaches people to
debug against the rate-limited endpoint.

## Renewal is the half that fails silently

Issuance is visible: someone clicks a button and sees what happened. Renewal
happens sixty days later with nobody watching, and a renewal that fails quietly
is an outage scheduled for thirty days after that.

* **A periodic task**, following the traffic-retention sweep's pattern — at
  startup and on an interval.
* **Renew at 30 days remaining**, which leaves four weeks of retries before
  anything expires.
* **Backoff must be persisted, not in memory.** This is the detail most likely
  to be got wrong: an in-memory backoff resets on restart, so a service that
  crash-loops — or an operator restarting to "fix" a failing renewal — turns
  into something that hammers Let's Encrypt and gets the account rate-limited,
  making the original problem unfixable for an hour. The last attempt and its
  outcome belong in the database.
* **Never retry a permanent failure on a short timer.** A domain that no longer
  points at this host will fail identically forever; that is a notification, not
  a retry.
* **The GUI must show, per certificate: when it was last renewed, whether the
  last attempt succeeded, and when the next is due.** Without it there is no
  difference visible between "renewing quietly" and "failing quietly" until the
  certificate expires.

## Leave room for more than one node

Configuration sync (0.11.0) will replicate certificates between nodes, and if
every node renews independently they duplicate issuance and hit exactly the
rate limits above. This release does not implement that, but it must not
foreclose it: renewal should read a flag that says whether this node renews,
defaulting to yes, rather than assuming it is alone. Adding the flag later is
cheap; unpicking an assumption spread through the renewal path is not.

## What this release does not do

* **No wildcards, no DNS-01.** Upload a wildcard under Certificates instead.
* **No TLS-ALPN-01.** It would let validation work without port 80, but it
  requires the certificate resolver to serve a challenge certificate mid
  handshake, which is a materially different integration for a case HTTP-01
  already covers.
* **No revocation.** Deleting a certificate removes it locally; it is not
  revoked at the CA.

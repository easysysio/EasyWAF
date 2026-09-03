# Roadmap — 0.4.0 onwards

Agreed sequence. Each minor is one feature; fixes found while testing between
them ship as patch releases (`0.4.1`, `0.4.2`) rather than accumulating into the
next minor, so a release's notes stay about its feature.

| Release | Feature |
|---|---|
| 0.4.0 | TLS termination, certificate management, admin password change |
| 0.5.0 | ACME / Let's Encrypt |
| 0.6.0 | Updating the rule sets and the country database |
| 0.7.0 | Flow logs over syslog, audit log on disk |

## Why this order

**TLS is first because everything about the management plane is currently
exposed.** The GUI seeds `admin`/`admin`, is served over plain HTTP, and its
session and CAPTCHA clearance cookies travel in the clear with no way to set
`Secure` on them.

It also fixes a live bug: the per-site **HSTS toggle does nothing today**.
A user agent must ignore a `Strict-Transport-Security` header received over
insecure transport (RFC 6797 §8.1), so that checkbox has been inert since
0.1.0. TLS is what makes it real.

**ACME is separated from TLS** because it is the riskiest piece and the two are
independently useful. TLS with an uploaded or self-signed certificate is
shippable and testable on its own, while ACME needs the domain publicly
reachable, is governed by Let's Encrypt rate limits that punish retry loops,
and its hard part is not issuance but unattended renewal sixty days later.
Bundling them would hold working HTTPS behind the harder half.

**Rule and database updates come before flow logs** because 0.3.0 already laid
their groundwork — the replaceable country-database reader and the rule import
provenance — and that lineage is fresher than the logging work, which has a
cross-repository dependency (see [logging.md](logging.md)) that can proceed in
parallel meanwhile.

## What 0.1.0 already left in place

The schema anticipated most of 0.4.0 and 0.5.0:

* `certs` — `cert_pem`, `key_pem`, `domain`, `not_before`, `not_after`,
  `acme_domain`, `acme_expires`
* `acme_accounts` — account key and directory URL, one per installation
* `sites` — `cert_id` and `acme_enabled`

So the data model is largely there; what is missing is the serving and issuing.

## Constraints to settle before coding 0.4.0

**A port is TLS or plain, not both.** Listeners are bound per *port* and shared
by every site on that port ([proxy/mod.rs](../../src/proxy/mod.rs)), so TLS is
configured on the listener, not on the site. Site A cannot serve HTTP while
site B serves HTTPS on the same port. Several sites on 443 therefore need
certificate selection by **SNI** — a rustls certificate resolver keyed on
`server_name`. This may change how sites and ports relate, so it is worth
settling before writing code rather than discovering it halfway.

**The admin password belongs here.** There is currently no way to change it
outside the database. It is the same concern as TLS — protecting the management
plane — and the README presently tells operators to firewall port 8080 as a
workaround for its absence.

## Constraint to settle before coding 0.5.0

**Do not use `acme_webroot`.** It is a placeholder from 0.1.0, but EasyWAF
already owns port 80, so it should answer `/.well-known/acme-challenge/<token>`
from the proxy itself. That needs no filesystem shared with a backend, works
while the upstream is down, and removes a class of misconfiguration. The proxy
already special-cases a path for CAPTCHA verification, so the pattern exists.

Renewal deserves as much design as issuance: a periodic job (the traffic
retention sweep is the existing pattern), backoff that respects Let's Encrypt's
rate limits, and somewhere in the GUI that shows when a certificate last
renewed and when it will next be attempted — a renewal that fails silently is
an outage scheduled ninety days out.

# Roadmap — 0.4.0 onwards

Agreed sequence. Each minor is one feature; fixes found while testing between
them ship as patch releases (`0.4.1`, `0.4.2`) rather than accumulating into the
next minor, so a release's notes stay about its feature.

| Release | Feature |
|---|---|
| 0.4.0 | TLS termination, certificate management, self-service password change |
| 0.5.0 | User management and roles |
| 0.6.0 | ACME / Let's Encrypt |
| 0.7.0 | Updating the rule sets and the country database (see [rule-repository.md](rule-repository.md)) |
| 0.8.0 | Flow logs over syslog, audit log on disk |
| 0.9.0 | IP allow/block lists, addable with one click from Traffic Monitor (see [ip-lists.md](ip-lists.md)) |
| 0.10.0 | Per-site rate limiting (see [rate-limiting.md](rate-limiting.md)) |

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

**User management comes early, and specifically before everything except TLS,
because the authorization surface only grows.** There are 40 separate
`get_session(&jar)` checks across the handlers today, each a binary "is anyone
logged in". Roles turn every one into an authorization decision, which wants
centralising into an extractor rather than 40 hand-written checks — one of
which someone will eventually forget, and the forgotten one will be a POST
handler a read-only user can call. Certificates, ACME, updates and logging each
add routes, so every release taken first makes that retrofit larger.

It also shares a theme with 0.4.0: TLS protects the channel to the management
plane, users and roles protect access to it, and doing them adjacently keeps
that code open once. And it precedes the audit log deliberately — a trail
recording that "admin did X" says little when every operator is `admin`.

The cost is that ACME slips a release, and certificates expire on a schedule
nobody controls. That trade was taken knowingly: manual renewal is a calendar
reminder, while a missed authorization check is a vulnerability.

**Rule and database updates come before flow logs** because 0.3.0 already laid
their groundwork — the replaceable country-database reader and the rule import
provenance — and that lineage is fresher than the logging work, which has a
cross-repository dependency (see [logging.md](logging.md)) that can proceed in
parallel meanwhile.

**IP lists and rate limiting sit last, adjacent to each other, and each still
self-contained.** Both are identity/volume signals rather than payload
inspection, both share a pipeline position — checked early, before GeoIP and
WAF, and both must respect the allowlist override from 0.9.0 — and both are
easy slots to pull forward if an urgent need shows up, since neither assumes
anything from the releases ahead of it. They stay two releases rather than one
because they differ enough in shape: an IP list is a set lookup, rate limiting
is a counter with a time window and its own state-management questions.

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

**A self-service password change belongs here**, not deferred to 0.5.0 with the
rest of user management. There is currently no way to change the password
outside the database, and "change my own password" is not throwaway work — it
survives unchanged into a multi-user world, while closing the unchangeable
`admin`/`admin` gap now rather than two releases out. The README presently tells
operators to firewall port 8080 as a workaround for its absence.

## Constraints to settle before coding 0.5.0

**Which roles, minimally.** Two to begin with — `admin` (everything) and
`viewer` (dashboard, traffic, the read-only pages) — adding an `operator` tier
later only if it is actually wanted. Three roles invented up front usually
leaves one that is never used.

**Enforce centrally.** The 40 `get_session` call sites should become a
requirement a handler declares, not a check it remembers to make.

**The schema is bare.** `users` holds `id`, `username`, `password_hash`,
`created_at` — no role, no enabled flag, no email. `SessionData` carries
`user_id` and `username` but no role, so it must carry one or look it up per
request. Decide too what prevents the last remaining admin from deleting or
demoting themselves.

## Constraint to settle before coding 0.6.0

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

# Roadmap — 0.4.0 onwards

Agreed sequence. Each minor is one feature; fixes found while testing between
them ship as patch releases (`0.4.1`, `0.4.2`) rather than accumulating into the
next minor, so a release's notes stay about its feature.

| Release | Feature |
|---|---|
| 0.4.0 | TLS termination, certificate management, self-service password change — **released 2026-09-04** |
| 0.5.0 | User management and roles |
| 0.6.0 | ACME / Let's Encrypt |
| 0.7.0 | Updating the rule sets and the country database (see [rule-repository.md](rule-repository.md)) |
| 0.8.0 | Flow logs over syslog, audit log on disk |
| 0.9.0 | IP allow/block lists, addable with one click from Traffic Monitor (see [ip-lists.md](ip-lists.md)) |
| 0.10.0 | Per-site rate limiting (see [rate-limiting.md](rate-limiting.md)) |
| 0.11.0 | Learning and hardening modes — URL allowlisting (see [url-learning.md](url-learning.md)) |

## Candidates, not yet scheduled

Recorded so they are not lost. No version assigned — these are worth doing,
not yet ordered against each other.

**Rule attribution on the traffic event — "why was this blocked?"** The GUI
cannot currently answer that. Diagnosing the 0.3.1 false positives took SSH, a
systemd environment change, two restarts and `journalctl`, to learn something
the WAF knew at the moment it decided. Much of the plumbing already exists and
is inert: `traffic_events.waf_score` is threaded through `TrafficRecord` and
the INSERT but passed `None` at all four call sites in
[proxy/mod.rs](../../src/proxy/mod.rs), the same way `country` was before
0.3.0; and `PipelineVerdict` already collects `alerts: Vec<Alert>` and then
discards them. Recording the score and the matching rules, then showing them
when a Traffic Monitor row is opened, turns the product's most common failure
mode from an hour of shell work into a click — and leads naturally into
disabling the rule, cloning it to tune (0.7.0), or allowlisting the client
(0.9.0).

**Backup, restore, and configuration export.** Sites, policies, rules,
certificates, users and settings all live in one SQLite file with no export.
Losing the host loses all of it, there is no way to clone a working
configuration onto a staging instance, and none of it can be kept under
version control. An export/import as TOML or JSON, plus a consistent database
snapshot to download, also makes support easier: one exported file beats
twenty screenshots.

**Response inspection.** Everything today inspects requests; the other half of
a WAF catches what leaks out — stack traces, SQL errors, directory listings,
card numbers — which is what CRS reserves the 950xxx band for. The cost is
real and worth deciding deliberately rather than discovering: the proxy
currently streams responses back to the client (`Body::from_stream`), so
inspecting them means buffering, trading away the streaming behaviour it has
today.

**Rule dry-run — cheaper-sounding than it is.** "This pattern would have
matched N of the last 10,000 requests" would be an excellent guard against
shipping a rule like 0.3.1's. But `traffic_events` stores only method, host,
path and country — **no headers and no body** — and both 0.3.1 false positives
were header-zone matches, so a replay over stored history would have caught
neither. It would work for `URL` and `ARGS` zone rules only, unless a bounded
sample of complete requests is also retained for testing, which is a
substantially larger feature. Recorded here mainly so nobody later assumes it
is a small one.

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

**Learning and hardening come last** because they are the one feature that
inverts the model everything else follows — describing what the application
legitimately exposes rather than what an attack looks like — and because they
lean on almost everything before them: the traffic history that seeds a
learned set, the verdict pipeline that decides which requests are safe to
learn from, and the detect-before-enforce pattern that by then has been built
three times over. It is also the feature most able to cause an outage, which
is a reason to build it when the surrounding machinery is settled rather than
while it is still moving.

**IP lists and rate limiting sit before it, adjacent to each other, and each
still self-contained.** Both are identity/volume signals rather than payload
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

**Sessions cannot be revoked, and 0.4.0 left it that way.** They are stateless
signed cookies, so changing a password does not invalidate one already issued —
it stays valid for its remaining 8 hours, in any browser that holds it. Fixing
it needs a server-side check per request (a session epoch on the user row,
compared on every load), which means `get_session` becomes async and every one
of its call sites is touched. That is the same refactor this release needs for
roles, so the two belong together rather than being done twice. Until then the
honest statement — made on the account page — is that other sessions expire
rather than end.

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

# EasyWAF

A self-contained web application firewall and HTTP reverse proxy, in a single Rust binary.

EasyWAF sits in front of your web applications, routes requests to the right backend by
`Host:` header, inspects them against OWASP-style rules, and blocks, challenges or forwards
them. Everything — virtual hosts, WAF policies, rules, traffic history — is managed from a
built-in web GUI and stored in one SQLite file. There is no separate database server, no
runtime dependency beyond glibc, and nothing to wire together.

![The EasyWAF dashboard](docs/screenshots/dashboard.png)

*The dashboard: request volume over the last 24 hours split into passed, challenged and
blocked, with a per-site breakdown.*

---

## Status

Working today: reverse proxying, the rule engine, country rules, the CAPTCHA challenge,
traffic logging and retention, HTTPS for both the management GUI and proxied sites, and the
management GUI itself.

The largest gaps are **ACME** (certificates are uploaded by hand — it is the next release),
**WebSockets** (they do not proxy at all), and **backup/export** (there is none). Read
[What EasyWAF does not do](#what-easywaf-does-not-do) before deploying — it is short, and it
is the honest half of this page.

---

## How it works

```
                    ┌─────────────────────────────────────────┐
   client ────────► │ EasyWAF                                 │
                    │                                         │
                    │  1. match Host: against a site          │
                    │  2. pipeline: traffic log → WAF rules   │ ──► block  403
                    │  3. verdict: pass / challenge / block   │ ──► challenge (CAPTCHA)
                    │  4. forward, inject security headers    │
                    └──────────────────┬──────────────────────┘
                                       ▼
                                  upstream app
```

One process serves two things: the **management GUI** on `gui_tls_port` (8443 by default, over
TLS, with `gui_port` 8080 redirecting to it), and one
**proxy listener per distinct site port**. Saving a site on a new port binds it immediately —
no restart. A request whose `Host:` matches no enabled site gets a 404.

A site with no WAF policy attached is simply a reverse proxy: traffic is forwarded and logged,
and the per-site security headers still apply, but nothing is inspected.

---

## Features

* **Virtual hosts** — route by `Host:` header to any upstream URL, one listener per port,
  bound dynamically as sites are added.
* **Rule engine** — 99 bundled OWASP-style rules across SQLi, XSS, LFI, RFI, RCE, PHP,
  protocol and scanner categories. Rules match a request zone (`URL`, `ARGS`, `BODY`,
  `HEADERS`, or `ANY`) and either add to a score or block outright.
* **Three enforcement modes per policy** — `Off`, `DetectionOnly` (log what would happen,
  block nothing) and `On`.
* **Country rules** — block listed countries, or allow only listed ones, per policy. Uses the
  DB-IP Lite database compiled into the binary, so lookups are offline and there is nothing to
  download. Addresses with no country are never matched, so an allow list cannot lock out
  private-network traffic.
* **CAPTCHA challenge** — a middle ground between allow and block: suspicious-but-plausible
  traffic gets a self-hosted image CAPTCHA. Solving it sets a short-lived, IP-bound,
  HMAC-signed clearance cookie. No third-party service.
* **Traffic monitor** — every proxied request recorded with verdict, latency and status;
  filterable by site, verdict and time window, with a per-hour chart.
* **Dashboard** — request volume, a stacked passed/challenged/blocked chart over 24 hours,
  and a per-site breakdown.
* **Traffic retention** — bound the history from Settings; older events are pruned at startup
  and hourly.
* **HTTPS per site** — each site can serve plain HTTP, HTTPS, or both at once. Certificates
  are selected per site by SNI, so many sites share one HTTPS port, each presenting its own.
  An optional per-site redirect sends HTTP to HTTPS; it is off by default, so turning on
  HTTPS never silently stops the HTTP port working.
* **Certificate inspection** — click a certificate to see what it says about itself: subject
  and issuer (CN, organization, city, state, country), validity and days remaining, the names
  it is valid for, key type and size, chain length, and its SHA-256 fingerprint. The private
  key is never shown.
* **Per-site security headers** — HSTS, `X-Frame-Options`, `X-Content-Type-Options`,
  `X-XSS-Protection`, toggled individually.
* **Light / dark / auto theme.**
* **Packaged** — `.deb` and `.rpm` for x86_64 and arm64, with a systemd unit, and a
  multi-arch container image.

---

## Install

Packages are published for **x86_64** and **arm64**; your package manager picks the right one.

**Debian / Ubuntu**

```bash
curl -fsSL https://repo.easysys.io/easywaf/stable/debian/key.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/easysys.gpg
echo "deb [signed-by=/usr/share/keyrings/easysys.gpg] https://repo.easysys.io/easywaf/stable/debian ./" \
  | sudo tee /etc/apt/sources.list.d/easywaf.list
sudo apt update && sudo apt install easywaf
sudo systemctl enable --now easywaf
```

**RHEL / Fedora**

```bash
sudo tee /etc/yum.repos.d/easywaf.repo >/dev/null <<'EOF'
[easywaf]
name=EasyWAF
baseurl=https://repo.easysys.io/easywaf/stable/redhat
enabled=1
gpgcheck=1
gpgkey=https://repo.easysys.io/easywaf/stable/redhat/key.gpg
EOF
sudo dnf install easywaf
sudo systemctl enable --now easywaf
```

**openSUSE / SLES**

```bash
sudo zypper addrepo -fg https://repo.easysys.io/easywaf/stable/redhat easywaf
sudo zypper install easywaf
sudo systemctl enable --now easywaf
```

Or download a `.deb`/`.rpm` from the [releases page](https://github.com/easysysio/EasyWAF/releases).

The package installs the binary to `/usr/bin/easywaf` and its runtime files — templates,
static assets, bundled rule sets and `config.toml` — under `/opt/easywaf`, plus a systemd
unit. The database is created at `/opt/easywaf/easywaf.db` on first start. The service runs as
root so a site can bind a privileged port such as 80.

### Docker

```bash
docker run -d --name easywaf \
  -p 8443:8443 -p 8080:8080 -p 80:80 \
  -v easywaf-data:/data \
  easysysio/easywaf:latest
```

Multi-arch (amd64 and arm64). The database lives in `/data`, so mount a volume there or it
goes with the container. Publish whichever ports your sites listen on — 8443 is the GUI,
8080 redirects to it.

The image no longer carries a published signing key — that was removed in 0.4.2, and the key
is now generated into the database on first run. To change ports or point the database
elsewhere, mount your own config or set the environment variable:

```bash
docker run -d -v ./config.toml:/opt/easywaf/config.toml ... easysysio/easywaf:latest
```

The Docker Hub overview is [`docker/README.md`](docker/README.md), pushed by the release
workflow so it is versioned here rather than typed into a web form and left to rot.

---

## First run

Open `https://<host>:8443/`. On the first start EasyWAF has no account yet, so it asks
you to create one — pick a username and password there. Plain HTTP on 8080 redirects to
the TLS port, so the password is never typed over a cleartext connection.

There is nothing to recover that password with: EasyWAF has no mailer and no second
account to reset it from. Keep it somewhere safe.

Your browser will warn about the certificate. On first run EasyWAF generates a self-signed
one named `easywaf` and stores it under **Certificates** — it exists so the management
interface is never served over plain HTTP, not because it is trustworthy.

To use your own instead: upload it under **Certificates**, then select it as the
**Management Certificate** under **Settings → TLS** and restart. The generated one stays
as a fallback — if the certificate you pick is later removed or becomes unusable, EasyWAF
starts on `easywaf` and logs why rather than leaving you with no way in.

> **Upgrading from 0.4.0 or 0.4.1?** Those versions seeded an `admin`/`admin` account. It
> is untouched by the upgrade, so if you never changed it, change it now under
> **Account → Change Password**. EasyWAF says so on every start in the log and on the
> account page until you do. New installations have no default account at all.

Keeping the management ports off the public internet is still worth doing — bind them to a
management network or firewall 8443 and 8080 — but it is defence in depth rather than the
only thing standing between a stranger and your appliance.

### Add a site

**Sites → Add site**:

| Field | Value | Notes |
|---|---|---|
| Hostname | `example.com` | The `Host:` header to route on — bare name, no scheme, no port |
| Upstream Target | `http://127.0.0.1:3000` | Where to forward — full URL including scheme |
| Listen Port | `80` | Plain HTTP. Bound immediately; the previously bound port keeps listening until restart |
| HTTPS Port | `443` | Optional. Empty means HTTP only; setting it serves HTTPS *as well as* HTTP |
| Certificate | one you uploaded | Required for HTTPS. A site with an HTTPS port but no certificate does not bind that port at all, rather than binding it and failing every handshake |

### Attach a WAF policy

Under **Policies**, create a policy, choose its rule sets, and set the engine mode. A new
policy defaults to `DetectionOnly`, so nothing is blocked until you switch it to `On` — start
there, watch the Traffic Monitor, then enforce.

Each matching rule adds its **score**; when the total reaches the policy's score threshold
(10 by default) the request is blocked with 403. Six of the bundled rules are instant-block
regardless of score. If a challenge threshold is set, scores that reach it but stay under the
block threshold get a CAPTCHA instead.

Verify enforcement with a signature that always blocks:

```bash
curl -i "http://your-site/?q=xp_cmdshell"
# HTTP/1.1 403 Forbidden
# WAF block rule matched: SQLi: xp_cmdshell (MSSQL)
```

---

## Configuration

`config.toml` lives beside the binary's working directory — `/opt/easywaf/config.toml` for a
package install — and holds only what is needed before the database is open:

```toml
[proxy]
gui_port     = 8080      # plain HTTP; redirects to gui_tls_port
gui_tls_port = 8443      # the GUI itself, over TLS
```

Nothing security-sensitive is configured here. The key that signs session and CAPTCHA
clearance cookies is generated on first run and kept in the database, so no installation
can be left using a default that was published in this repository, and the administrator
account is created through the GUI at first start. Restart to apply any edit.

The database defaults to `easywaf.db` in the working directory. Override it with the
`DATABASE_URL` environment variable — an environment variable rather than a setting
because the case that needs it is a container, where `config.toml` is baked into the image
and the database has to sit on a mounted volume to survive at all.

Everything else — sites, their ports, policies, rules and retention — lives in the database
and is managed from the GUI, so adding a site never means editing a file.

The TLS version profile and the cipher suites are two appliance-wide settings under
**Settings**, rather than per site, because rustls fixes both when a listener binds its
port — before the client has said which site it wants. Certificates *are* per site; those
are chosen by SNI during the handshake. Both settings cover the management interface as
well as the proxied sites, and take effect on restart.

The profile is "compatible" (TLS 1.2 and 1.3) or "modern" (1.3 only). The cipher suites
are one editable line, pre-filled with everything supported; delete the ones your policy
forbids. A name EasyWAF does not recognise is refused on save rather than dropped, so a
restriction you believe is in force always is.

Nothing weak is on that line to begin with. All nine suites are AEAD, and the TLS 1.2 ones
are all ECDHE:

```
TLS13_AES_256_GCM_SHA384                  TLS13_AES_128_GCM_SHA256
TLS13_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

So a requirement to disable CBC — or RC4, 3DES, static-RSA key exchange, or anything below
TLS 1.2 — is met before any configuration: none of it is implemented, so none of it can be
selected. Restricting the line is for policies that go further, such as AES-only or
256-bit-only.

`geoip_db` optionally points at a MaxMind-format `.mmdb` to use instead of the bundled DB-IP
Lite database — a fresher DB-IP file, or MaxMind GeoLite2. Leave it empty for the bundled one.

The shipped file also carries `http_port` and `acme_webroot`. These are placeholders for
features that are not wired up and are ignored; the ports EasyWAF listens on come from the
sites you define.

---

## Build from source

Requires a stable Rust toolchain and `sqlite3`.

`sqlx`'s `query!` macros validate SQL against a real schema **at compile time**, so a database
must exist, and must be current, before you build. `.env` points `DATABASE_URL` at
`./easywaf.db`; bring it up to date with:

```bash
./scripts/dev-db.sh
```

That applies any migrations the database is missing, keeping whatever data is already in it,
and creates the database if it does not exist. On a database that is already current it does
nothing at all — it checks the version first and exits — so it is cheap to run before any
build, and it never drops anything.

**This is the usual cause of a confusing build failure.** Migrations are applied by the
*running* binary, so a development database that has not been run against a recent build
falls behind, and `cargo build` then fails with a wall of `no such column: …` errors that
look like faults in the code but are not — they are the compile-time query checks hitting an
old schema. Run the script and build again. Without any database at all the failure is
different: `unable to open database file` from inside the macro expansion.

Run it from the repository root, since templates, static assets and rules are resolved
relative to the working directory:

```bash
DATABASE_URL=sqlite://easywaf.db ./target/release/easywaf
```

---

## Project layout

```
src/
  main.rs           entry point: GUI router, proxy spawn, retention task
  config.rs         config.toml loader
  db.rs             pool setup and migrations
  auth.rs           session cookie key
  challenge.rs      CAPTCHA generation and clearance cookies
  proxy/mod.rs      the reverse proxy: routing, pipeline, forwarding
  modules/          inspection pipeline
    waf.rs          rule evaluation, scoring, compiled-pattern cache
    traffic.rs      request logging and retention pruning
  routes/           GUI pages (dashboard, sites, policy, rules, traffic, certs, settings)
migrations/         schema, applied in order at startup
rules/              bundled OWASP-style rule sets (TOML)
templates/          Tera templates
static/             CSS and JS
packaging/          systemd unit
```

---

## What EasyWAF does not do

Called out so nothing here is a surprise in production. Split by whether it is
scheduled or decided — the roadmap lives in [docs/design/roadmap.md](docs/design/roadmap.md).

### As a reverse proxy

* **WebSockets do not work.** `Connection` and `Upgrade` are stripped as hop-by-hop headers
  and there is no tunnelling path, so an upgrade never reaches the upstream. Anything with
  live updates — chat, hot reload, streaming dashboards — breaks. Not scheduled.
* **No HTTP/2 to clients.** No ALPN is advertised, so connections are HTTP/1.1. Not scheduled.
* **Routing is by `Host:` only, matched exactly.** No path prefixes, no wildcard hostnames
  like `*.example.com`. Two applications behind one hostname cannot be split. Not scheduled.
* **One upstream per site.** No load balancing, no health checks, no failover to a second
  backend — an application running more than one instance needs a load balancer behind
  EasyWAF. Scheduled for **0.8.0**.
* **IPv6 literal hostnames do not route.** Host matching truncates at the first colon, so
  `[::1]:8080` does not match. Name-based hosts are unaffected.
* **No health or metrics endpoint.** Nothing to point a load balancer's health check at, and
  no Prometheus scrape target.

### As a WAF

* **Requests only — responses are not inspected.** Nothing detects what leaks *out*: stack
  traces, SQL errors, directory listings, card numbers. This is the half of a WAF that CRS
  reserves its 950xxx band for. Not scheduled, and it has a real cost: responses stream
  today, and inspecting them means buffering.
* **The GUI cannot tell you why a request was blocked.** Traffic Monitor records that a
  request was blocked, not which rule did it or what the score was — diagnosing a false
  positive means debug logging and reading the journal. Unscheduled but wanted; most of the
  plumbing already exists and is inert.
* **Traffic history holds no headers or bodies** — method, host, path, country and verdict
  only. So a new rule cannot be replayed against past traffic to see what it would have
  matched.
* **Request bodies are buffered to 32 MB** so rules can inspect them; anything larger is
  rejected with 400.

### Managing it

* **Certificates are uploaded by hand — no ACME yet.** Renewal is a calendar reminder.
  Scheduled for **0.5.0**, and the next release.
* **One account, and everyone who has it is an administrator.** No second user, no roles, no
  read-only access. Scheduled for **0.6.0**.
* **Sessions cannot be revoked.** They are stateless signed cookies, so changing a password
  does not invalidate one already issued — it expires on its own within 8 hours. Scheduled
  with roles in **0.6.0**, which needs the same refactor.
* **No audit log.** Nothing records who changed what. Scheduled for **0.10.0** — deliberately
  after roles, since a trail saying "admin did X" says little when every operator is `admin`.
* **No backup, restore or configuration export.** Everything lives in one SQLite file with no
  way to export it, clone it to staging, or keep it under version control. Scheduled for
  **0.9.0**; until then, copy the database file with the service stopped.
* **No high availability.** No configuration sync between nodes. Scheduled for **0.11.0**.
* **No IP allow/block lists** (**0.12.0**) and **no rate limiting** (**0.13.0**).
* **`http_port` and `acme_webroot` in `config.toml` are ignored.** They are placeholders from
  0.1.0; listening ports come from the sites you define.

### Decided, not missing

* **TLS version and cipher suites are appliance-wide, not per site.** rustls fixes both when a
  listener binds its port, before the client has said which site it wants, so sites sharing a
  port necessarily share them. Certificates *are* per site, chosen by SNI. Per-site and
  per-port policies were both considered and declined.
* **There is no password recovery.** No mailer, no second account to reset from. A lost
  administrator password means editing the `users` table directly.
* **Traffic is not replicated and is not intended to be.** When node sync arrives, each node
  will keep its own traffic history and [EasyLog](https://easysys.io) aggregates it.

## Releasing

Tagging `v*` triggers `.github/workflows/release.yml`, which builds `.deb` and `.rpm` for both
architectures and publishes a GitHub Release with the notes from the matching `CHANGELOG.md`
section. Running the workflow manually builds packages only, versioned
`X.Y.Z+ci<run>.git<sha>` for the testing channel. Packages are pulled into the public
repositories by `github2repo.sh` in the EasyWAF-repo project.

---

## Bundled data

IP geolocation by [DB-IP](https://db-ip.com) — the DB-IP Lite country database, licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

## License

GPL-3.0. Documentation at [easysys.io/easywaf](https://easysys.io/easywaf/).

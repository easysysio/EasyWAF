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
management GUI itself. Not yet implemented: **ACME** — certificates are uploaded manually. See
[Not implemented yet](#not-implemented-yet) before deploying.

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

The image ships a config with the same placeholder secret as the packages, which is published
for anyone to read, so replace it before production by mounting your own:

```bash
docker run -d -v ./config.toml:/opt/easywaf/config.toml ... easysysio/easywaf:latest
```

---

## First run

Open `https://<host>:8443/` and sign in with **admin** / **admin**. Plain HTTP on 8080
redirects there.

Your browser will warn about the certificate. On first run EasyWAF generates a self-signed
one named `easywaf` and stores it under **Certificates** — it exists so the management
interface is never served over plain HTTP, not because it is trustworthy. Replace it with
your own certificate to make the warning go away.

> **Keep the management port private.** The first start seeds an `admin`/`admin` account and
> there is no password-change screen yet. Firewall ports 8443 and 8080, or bind them to a management
> network until that lands.

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
secret       = "change-this-to-a-random-secret-before-production"
database_url = "sqlite://easywaf.db"

[proxy]
gui_port     = 8080      # plain HTTP; redirects to gui_tls_port
gui_tls_port = 8443      # the GUI itself, over TLS
```

`secret` signs GUI session cookies and CAPTCHA clearance cookies — change it before
production. Restart to apply any edit.

Everything else — sites, their ports, policies, rules and retention — lives in the database
and is managed from the GUI, so adding a site never means editing a file.

The TLS version profile is one appliance-wide setting under **Settings** — "compatible"
(TLS 1.2 and 1.3) or "modern" (1.3 only) — rather than per site, because rustls fixes the
version and cipher suites when a listener binds its port, before the client has said which
site it wants. Certificates *are* per site; those are chosen by SNI during the handshake.
There is no weak-cipher option: nothing below TLS 1.2, and no RC4, 3DES or CBC-SHA1, is
implemented at all.

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

## Not implemented yet

Called out so nothing here is a surprise in production:

* **TLS / HTTPS** — the proxy serves plain HTTP. Certificates can be stored in the GUI but are
  not used to terminate TLS. Put EasyWAF behind a TLS terminator if you need HTTPS.
* **ACME** — no automatic certificate issuance.
* **WebSockets** — the `Upgrade` header is stripped as hop-by-hop, so upgrades do not proxy.
* **Password change** — the admin password can only be changed in the database.
* **IPv6 literal hostnames** — host matching truncates at the first colon.

Request bodies are buffered up to 32 MB so rules can inspect them; larger requests are
rejected with 400. Responses are streamed.

---

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

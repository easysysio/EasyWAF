# Changelog

All notable changes to EasyWAF are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version bumps and tags are created only after explicit approval.

---

## [0.4.3] — 2026-09-05

Certificate details, and one fewer external dependency at runtime. Nothing to
do on upgrade.

### Added
- **Certificate details.** Clicking a certificate under Certificates opens what
  it actually says about itself: subject and issuer distinguished names (common
  name, organization, unit, city, state, country, email), validity with days
  remaining, every subject alternative name, key type and size, signature
  algorithm, serial, chain length and the SHA-256 fingerprint. Read from the
  stored PEM on each load rather than from the `certs` columns, which are a
  three-field snapshot taken at upload and can only drift.

  The private key is never displayed or exported — the page reports only
  whether one is stored, since a certificate without its key cannot terminate
  TLS and that is worth seeing.

  It also answers questions the list could not: whether a certificate is
  self-signed, whether it is about to expire, whether the file contains
  intermediates or only the leaf, and which names it is actually valid for —
  the usual reason a browser rejects a certificate EasyWAF is serving happily.

### Fixed
- **A certificate that is in use can no longer be deleted.** Deleting one
  assigned to a site silently unset that site's certificate — `sites.cert_id`
  is `ON DELETE SET NULL` and foreign keys are enforced — and a site with an
  HTTPS port but no certificate stops binding that port. The site kept working
  over plain HTTP, so nothing looked wrong until someone tried the HTTPS one.
  Deletion is now refused, naming the sites that would break.

  **The management interface's own `easywaf` certificate cannot be deleted at
  all.** Removing it left the GUI running on a certificate that existed nowhere,
  and the next start generated a replacement with a different fingerprint — so
  every browser that had accepted the old one met a fresh warning, which is
  hard to tell apart from being locked out. There is no reason to delete it:
  a start with it missing simply makes another.

  Both are shown in the list rather than only enforced on submit — the delete
  control is disabled with the reason on hover, and a new **In use by** column
  says which sites hold each certificate.
- Deleting a certificate now rebuilds the SNI map. It previously stayed in
  memory, so a deleted certificate went on being served for the life of the
  process.
- **Reading a certificate no longer shells out to the `openssl` binary.**
  Extracting the domain and dates on upload ran `openssl x509` as a
  subprocess, making an undeclared external program a requirement for a
  certificate to display its own details, and failing silently to blank fields
  when it was missing. The container image installs `ca-certificates` with
  `--no-install-recommends`, so that binary cannot be assumed present. Parsing
  is now in-process via `x509-parser`, which has no build script and so adds no
  C build to the aarch64 cross-compile.
- **The README's limitations section had been wrong since 0.4.0.** It still said
  the proxy served plain HTTP and that the admin password could only be changed
  in the database — both fixed by that release, in the same commits that failed
  to update this section. Rewritten as *What EasyWAF does not do*, covering what
  is actually missing across the proxy, the WAF and management, and separating
  what is scheduled (with its release number) from what is a decision. A
  limitations list that is out of date is worse than none: it is the section a
  reader trusts precisely because they expect it to be unflattering.

## [0.4.2] — 2026-09-04

Closes the last two credentials that shipped with known values.

### Upgrading from 0.4.x

**Nothing breaks and nothing needs editing.** An existing `config.toml` still
parses; `secret` and `database_url` are read, ignored, and named in a warning at
startup so the lines can be deleted at leisure.

Two things worth doing:

* If you never changed the seeded `admin`/`admin` account, change it now under
  **Account → Change Password**. The upgrade does not touch existing accounts,
  so an installation carrying that password keeps carrying it.
* **Containers must set `DATABASE_URL`.** The published image does this itself
  (`sqlite:///data/easywaf.db`). A container running a *custom* `config.toml`
  that relied on `database_url` to place the database on a mounted volume will
  otherwise write it inside the container and lose it on the next `docker run`.

Existing sessions survive the upgrade: the signing key is generated only when
none is stored, and an installation that had one keeps it.

### Fixed
- The account page's default-password banner claimed the password "ships with
  every copy of EasyWAF". That stopped being true in this release. It only ever
  appears on an installation upgraded from 0.4.0 or 0.4.1 — nothing seeds that
  password now, and the GUI will not accept one that short — so it says that
  instead. The banner is kept rather than removed: the installations that can
  still see it are exactly the ones that need the warning.

### Changed
- **The administrator account is created at first run instead of being seeded
  as `admin`/`admin`.** The first start serves a setup form asking for a
  username and password, and serves nothing else until one exists. A default
  credential is only as good as the operator's memory to change it, and the
  ones never changed are the ones nobody was told about — asking at first run
  means an installation cannot be in that state at all. The form closes the
  moment an account exists, checked again inside the insert so two simultaneous
  requests cannot both create one.

  It is safe to ask for a password there because 0.4.0 put the GUI behind TLS:
  on the plain-HTTP port there is only a redirect, so the password is never
  typed over a cleartext connection.
- **`secret` is gone from `config.toml`**; the cookie signing key is generated
  on first run and stored in the database, the same way the management
  certificate already was. It shipped as a literal value in a public
  repository, so every installation that did not edit it signed session and
  CAPTCHA-clearance cookies with a key anyone could read — and nothing about a
  working system revealed that. A generated key has no such failure mode:
  there is no value to leave unchanged. The container image was the worst case,
  since its config was baked in and identical for every user.
- **`database_url` is gone from `config.toml`**, replaced by the `DATABASE_URL`
  environment variable, defaulting to `easywaf.db` in the working directory. An
  environment variable because the case that needs to override it is a
  container, where the config file is inside the image and the database has to
  live on a mounted volume to survive at all.

## [0.4.1] — 2026-09-04

A dependency-hygiene release. No behaviour changes and nothing to do on
upgrade.

### Changed
- **`rustls-pemfile` is gone** (RUSTSEC-2025-0134, unmaintained). Its job moved
  into `rustls-pki-types`, which rustls already re-exports, so certificate and
  key parsing goes through `PemObject` instead. Dropping EasyWAF's own use was
  not enough on its own — `axum-server` 0.7 pulled the crate in too — so
  **axum-server is upgraded to 0.8**, whose `tls-rustls-no-provider` feature
  depends on `rustls-pki-types` as well. The crate is now absent from the
  dependency tree entirely rather than merely unused by EasyWAF's own code, and
  `cargo audit` reports nothing.

  It was an unmaintained-crate warning rather than a vulnerability, so 0.4.0 is
  not unsafe to run — this closes the warning rather than fixing an exposure.

## [0.4.0] — 2026-09-04

The TLS release: the management interface and proxied sites both serve HTTPS,
certificates are managed from the GUI, and the seeded password can finally be
changed from the GUI too.

### Upgrading from 0.3.x — read this first

**The management GUI has moved to `https://<host>:8443/`.** Port 8080 still
answers, but now does nothing except redirect there.

0.3.1's README told operators to firewall port 8080 as the way to keep the GUI
private. If you did that and opened nothing else, **you will not be able to
reach the GUI after upgrading** — 8080 will redirect you to a port your own
firewall is blocking. Open 8443 to whatever can currently reach 8080 *before*
you upgrade.

Your browser will warn about the certificate on first load. EasyWAF generates a
self-signed one named `easywaf`; replace it under **Certificates**.

Nothing else needs doing: the new `gui_tls_port` key is defaulted, so a
`config.toml` written before TLS existed keeps parsing, and site ports are
unchanged.

### Added
- **Self-service password change** (Account → Change Password). EasyWAF seeds an
  `admin`/`admin` account on first run, and until now the only way to change it
  was editing the `users` table with `sqlite3` — a default credential that
  shipped with every copy and could not practically be replaced. Changing it
  requires the current password even though the session already proves identity,
  so an unattended browser cannot be used to take the account over, and rejects
  a new password under 8 characters or over bcrypt's 72-byte limit rather than
  letting bcrypt silently ignore the tail.

  EasyWAF now also says so while the default is still in place: a warning on
  **every** start rather than only the one where the account was created, and a
  banner on the account page itself.

  This is deliberately "change my own password" and not user administration —
  it is all a single-account appliance needs, and it survives unchanged into
  0.5.0's roles rather than being thrown away by them. One limitation worth
  knowing: sessions are stateless signed cookies, so a change does not revoke
  one already issued; it expires on its own within 8 hours. Revocation needs a
  per-request server-side check, which is scheduled with 0.5.0's session work.
- `scripts/dev-db.sh` — applies any migrations a development database is
  missing, keeping existing data, and does nothing at all when the database is
  already current. sqlx checks every query against a real schema at compile
  time, but migrations are applied by the running binary, so a database that
  has not been run against a recent build falls behind and `cargo build` fails
  with `no such column` errors that read as faults in the code rather than a
  stale schema.

- **Configurable cipher suites** (Settings): one editable line naming the suites
  every HTTPS listener offers, pre-filled with all nine this build supports, for
  policies that permit only a subset. Names are validated on save — an
  unrecognised one is refused rather than silently dropped, since dropping it
  would leave an operator believing a restriction was in force that was not —
  and a selection that could negotiate nothing (TLS 1.2 suites only under the
  "modern" profile) is refused too, rather than being stored to take the GUI
  down at the next restart along with everything else. Applies to the management
  interface as well as to proxied sites, which now build their TLS configuration
  the same way: a policy restricting ciphers means the administrative interface
  too.

  Worth stating plainly for compliance work: **there are no CBC suites to
  disable.** All nine are AEAD (GCM or ChaCha20-Poly1305) and every TLS 1.2 one
  is ECDHE, so requirements forbidding CBC, RC4, 3DES, static-RSA key exchange
  or anything below TLS 1.2 are already met before the line is touched. A unit
  test asserts this rather than leaving it as a claim in the documentation.

- **HTTPS for proxied sites.** A site can now serve plain HTTP, HTTPS, or both
  at once: `listen_port` keeps serving HTTP and a new `tls_port` serves HTTPS,
  bound independently so enabling one never switches the other off.
  Certificates are chosen per site by **SNI** during the handshake, so many
  sites share one HTTPS port, each presenting its own — and a client naming a
  site with no certificate is refused rather than served somebody else's.
  A site configured with an HTTPS port but no certificate does not bind that
  port at all, since binding it would fail every handshake and be far harder to
  diagnose than a port that simply is not listening.
- **Optional per-site HTTP-to-HTTPS redirect**, off by default. The request was
  for both secure and insecure access to work, so turning on HTTPS must not
  silently stop the HTTP port serving.
- **TLS profile** (Settings): "compatible" (TLS 1.2 and 1.3) or "modern"
  (1.3 only). Appliance-wide rather than per site, because rustls fixes the
  version and cipher suites when a listener binds its port — before the client
  has said which site it wants — so sites sharing a port necessarily share
  them. There is no weak-cipher option to expose: nothing below TLS 1.2, and no
  RC4, 3DES or CBC-SHA1, is implemented at all. An unrecognised value falls
  back to "compatible", so a bad setting cannot start refusing clients that
  were working.
- **The management interface is served over TLS.** On first run EasyWAF
  generates a self-signed certificate named `easywaf` and stores it under
  Certificates, so the GUI is never served over plain HTTP — not even on a
  fresh install, where there is otherwise nothing for an administrator to
  prepare. It is a default, not a recommendation: browsers will warn, and
  replacing it with a real certificate is the point of certificate management.
  Later starts reuse the stored certificate rather than generating a new one,
  since an operator who has accepted a fingerprint should not be asked to
  accept another after a restart.
- **`gui_tls_port`** (default 8443) serves the GUI; `gui_port` (8080) now does
  nothing but redirect there, preserving path and query. The redirect is a 307
  rather than a permanent one, because the TLS port is configurable and a
  permanently cached redirect would keep sending browsers to a port that no
  longer listens. The key is defaulted rather than required, so a `config.toml`
  written before TLS existed keeps parsing across the upgrade.

### Changed
- The session cookie is now marked `Secure`, so a browser will not send it in
  cleartext to the plain-HTTP redirect port on its way to the TLS one.

### Fixed
- A TLS listener logged "listening" *before* it actually bound the port —
  `bind_rustls` defers the bind into `serve()` — so a port already in use
  produced a log claiming the GUI was up followed by a panic. Both the
  management and proxy TLS listeners now bind first and report a clear,
  actionable error naming the port instead of panicking.

## [0.3.1] — 2026-09-03

### Fixed
- **A multi-encoding-form fix from earlier this release introduced a second,
  broader false positive.** Zones with more than one candidate form (raw plus
  percent-decoded) were joined into a single string with `\n` before matching.
  Any header carrying a `%` that decodes to something different — a
  percent-encoded cookie is the common case — produced a string containing a
  real newline character that no client sent, which then matched
  `Protocol: host header injection` (`[\r\n\x0b\x0c]`, zone `HEADERS`): the
  rule built to catch CRLF injection was triggering on a character the WAF's
  own code inserted. Combined with the `SQLi: SQL comment stripping` false
  positive above (8 + 3 = 11 against a default block threshold of 10), this
  was enough on its own to block ordinary browser traffic.

  Fixed structurally rather than by picking a different separator: rules are
  now matched against each candidate form independently — never concatenated —
  so no synthetic character can exist for a rule to accidentally match. This
  removes the entire class of bug, not just this instance of it; a rule
  written after this change to detect some other whitespace or control
  character is safe by construction rather than by the separator happening not
  to collide with it.

  Verified against a live instance: a percent-encoded cookie that previously
  triggered the CRLF rule no longer does, the original reproduction (curl with
  a percent-encoded cookie, scoring 11 before this fix) is now clean, and the
  full attack battery (`scripts/waf-test.sh`) still passes 16/16 — including
  the encoding-defeat cases the earlier fix in this release addressed.
- **`SQLi: SQL comment stripping` (942007) false-positived on almost all
  traffic.** Its pattern accepted a lone `/\*` or `\*/` as a match, and the
  `Accept: */*` header sent by curl, wget and many other clients contains
  exactly that — so the rule scored 3 points against essentially every request
  regardless of what a client actually sent, silently pushing otherwise benign
  traffic toward the block threshold. The pattern now requires the markers as a
  pair (`/\*.*?\*/`), which still catches real SQL comments — including the
  empty-comment whitespace bypass `UNION/**/SELECT` — without matching a MIME
  wildcard. Confirmed against a live instance: a plain `curl` request and a
  realistic Chrome `Accept` header both pass clean; `UNION/**/SELECT` still
  blocks.

### Changed
- **Rule ids now match their OWASP CRS category.** Scanner detection moved from
  `990xxx` to `913xxx`, CRS's actual category for it, and the file was renamed
  to `913-scanners.toml`; one RCE rule carrying an RFI id (`931100`) became
  `932012`. Rule ids are how an update identifies the rule it replaces, so they
  become public identifiers once sets are published — corrected now, while this
  repository is the only place the data exists. A policy that already imported
  the old ids keeps them as orphaned rules; re-importing adds the corrected
  ones.

## [0.3.0] — 2026-09-03

### Added
- **Groundwork for updating rules and the country database** (the feature
  itself comes later). Two pieces that are far cheaper to put in now:
  - The country database is held behind a lock rather than written once, so
    `geo::init` can be called again to swap in a newer file without restarting.
  - Rules imported from the bundled files now record what they looked like on
    import (`imported_pattern`, `imported_score`, `imported_action`, migration
    008). A rule update has to tell an untouched rule from one an administrator
    deliberately changed, and that comparison needs the imported values — which
    cannot be recovered afterwards, because the row itself is what changed.
    Recording them from 0.3.0 means every rule imported from now on can be
    reconciled safely. Hand-written rules keep NULL: they are owned by their
    author and are never candidates for automatic updates.
- **Country rules on the policy.** A policy can now block a list of countries,
  or allow only that list and deny everything else. The rules follow the
  policy's Rule Engine setting, so `DetectionOnly` records what an allow list
  would have cost before it is enforced, and they run before the pattern rules —
  a denied country needs no payload scoring. Configured under Policy settings;
  `/geoip` now lists what each policy does instead of being a placeholder.
- **IP geolocation, offline.** The DB-IP Lite country database is compiled into
  the binary, so country rules work on a fresh install with nothing to download
  and no lookup leaving the host. `geoip_db` in `config.toml`, previously an
  unread placeholder, now points at another MaxMind-format `.mmdb` to override
  it. Every proxied request also records its country, filling the
  `traffic_events.country` column that has existed unused since 0.1.0.
- **Container image** — `easysysio/easywaf`, multi-arch amd64 and arm64,
  published to Docker Hub by the release workflow on a version tag. Built from
  the binaries the release matrix already produces, so the image contains
  exactly the binary that was released and arm64 needs no emulation. The
  database lives in `/data`, declared as a volume.

### Safety
- A country rule never fires on an address with no country — a private range,
  or one the database does not cover — so an allow list cannot deny traffic on
  a failed lookup. An empty country list matches nothing in either mode, so
  turning a mode on before choosing countries cannot lock a site out.

## [0.2.4] — 2026-09-03

### Added
- **Favicon.** The GUI had none, so browsers showed a blank tab icon. Adds a
  mark in the EasySYS family style — the same rounded hexagon badge and indigo
  as the EasySYS logo, carrying a shield in the GUI's accent blue. Shipped as an
  SVG with a 32px PNG fallback and a 180px apple-touch icon, declared on both
  the application and login layouts.
- **Enable / disable a site from Site Management.** The status column is now the
  control: clicking it stops or starts proxying for that hostname, with a
  confirmation before taking a live site down. Disabling leaves everything else
  about the site untouched, so re-enabling restores it as it was, and it does
  not close the TCP listener — ports are shared between sites and closing one
  would take the others down with it. Enabling signals the proxy to bind the
  port, which matters when the site is the only one using it: listeners are
  bound from the enabled sites at startup, so the port may not be listening yet.
- **Maintenance message** (Settings). A disabled site used to answer 404, the
  same as a hostname nobody had configured — indistinguishable from a mistake.
  It now serves a self-contained page carrying this text with
  `503 Service Unavailable` and a `Retry-After`, so visitors and crawlers alike
  are told the site is expected back. Unknown hostnames still get the 404.
- README: a screenshot of the dashboard, so the project shows what it looks like
  rather than only describing it.

## [0.2.3] — 2026-09-02

### Fixed
- **Percent-encoded payloads bypassed most WAF rules.** Rules were matched
  against the raw request, so `?q=DROP%20TABLE%20users` — or the `+` form a
  browser produces — defeated every pattern containing `\s`, while the identical
  payload in a request body blocked instantly. Query strings, paths, bodies and
  headers are now matched in both their raw and percent-decoded forms, decoded
  twice so double-encoded payloads reduce to plain text. The raw form is kept
  rather than replaced, since several rules deliberately match the encoding
  itself (`%252e%252e`, `%00`, the double-URL-encoding rule); text containing no
  encoding is passed through untouched, so an ordinary request pays only the
  scan for `%`.
- **Upgrading the package left the old service running.** Neither the `.deb`
  nor the `.rpm` carried a post-install step, so an upgrade replaced
  `/usr/bin/easywaf` and the systemd unit on disk while the running service kept
  the old binary — the GUI went on reporting the previous version, and systemd
  warned that the unit file had changed on disk. Both packages now run
  `systemctl daemon-reload` and `systemctl try-restart easywaf.service` after
  install. `try-restart` leaves a stopped service stopped, so a first install
  still does not start EasyWAF before any site is configured.
- **Removing the package left the service running.** With no `prerm`/`preun`,
  uninstalling removed the binary but left EasyWAF running and enabled — still
  holding port 80, and set to start again at the next boot from a unit whose
  binary was gone. Both packages now stop and disable the service on removal,
  guarded so an upgrade does not stop the service the post-install step is about
  to restart.

### Added
- `scripts/waf-test.sh` — fires representative attacks at a site and reports
  what the WAF did with each: instant-block rules, score accumulation, scanner
  User-Agents, encoded payloads, and benign traffic that must *not* be blocked.
- **README.** The repository had none. Covers what EasyWAF is and how requests
  flow through it, installation from the EasySYS repositories, first-run setup,
  configuring sites and policies, the `config.toml` keys that are actually read,
  the project layout, and how releases are cut. Includes a "Not implemented yet"
  section — TLS termination, GeoIP, ACME, WebSocket upgrades, password change —
  so the gaps are stated up front rather than discovered in production, and
  documents the `DATABASE_URL` a source build needs for sqlx's compile-time
  query macros.

## [0.2.2] — 2026-09-01

### Added
- **Dashboard charts.** A stacked *Requests per Hour* bar chart covering the
  last 24 hours — passed, challenged and blocked — beside a *Verdicts* doughnut
  of the same totals, and a proportion bar in each row of the per-site table so
  the mix is readable at a glance rather than only as numbers. Hours with no
  traffic are drawn as empty buckets, so a quiet night is visible instead of
  being compressed out of the axis.
- **Settings section** (`/settings`) — a new sidebar entry for installation-wide
  options that belong in the GUI rather than in `config.toml`, which is read
  before the database is open and cannot be edited from the web UI. Values live
  in a new `settings` key/value table (migration 006), so adding a setting later
  needs no schema change.
- **Traffic retention.** EasyWAF writes one row per proxied request and, until
  now, never deleted any of them — the table grew for as long as the proxy ran.
  Settings now carries a retention window in days; events older than it are
  deleted at startup and hourly after that, and the page shows how many events
  are currently stored. The default is **0 — keep everything**, so existing
  installations behave exactly as before until the setting is changed. The
  window is re-read on every sweep, so a change applies without a restart.

### Changed
- **WAF rule patterns are compiled once instead of per request.** Every rule's
  regex was rebuilt on every request — with the bundled rule set loaded, ~100
  `Regex::new` calls per request, which dominated the cost of actually matching
  them. Patterns are now compiled on first use and cached on the module. In a
  local benchmark against a policy holding all 99 bundled rules, mean
  proxy-request latency fell from **36.2 ms to 0.8 ms** (p95 39.0 ms → 0.8 ms).
  A pattern that fails to compile is cached as a failure too, so a broken rule
  logs once for the life of the process rather than on every request.

### Fixed
- **The Traffic Monitor's per-hour chart never rendered.** Its data was
  interpolated with `{{ chart | json_encode }}`, and Tera autoescapes `.html`
  templates, so the JSON reached the browser as `[{&quot;hour&quot;:...}]` —
  a syntax error inside `<script>`. Both that chart and the new dashboard ones
  now pipe through `| safe`.
- Dashboard panels shared no time window: the summary counted a rolling 24
  hours while the chart bucketed 23, so the card, the doughnut and the bar chart
  could disagree. All panels now derive from one window truncated to the top of
  the hour, and the totals match by construction.
## [0.2.1] — 2026-09-01

### Security
- **`cargo audit` is clean.** Updated the advisory-affected dependencies in
  `Cargo.lock` — h2 0.4.14 → 0.4.19 (unbounded empty DATA frames,
  RUSTSEC-2026-0258), crossbeam-epoch 0.9.18 → 0.9.20 (RUSTSEC-2026-0204),
  quinn-proto 0.11.14 → 0.11.17 (RUSTSEC-2026-0185), plus anyhow, event-listener
  and spin, which cleared the two unsoundness warnings and one yanked crate.
  All are lockfile-only bumps; no version requirement in `Cargo.toml` changed.
- Added `.cargo/audit.toml` ignoring RUSTSEC-2023-0071 (Marvin Attack in `rsa`),
  which has had no fixed release since 2023. `rsa` is pulled in only by
  `sqlx-mysql`: Cargo.lock lists every optional dependency regardless of the
  features enabled, but EasyWAF builds sqlx with `sqlite` alone, so it is never
  compiled. The reasoning is recorded in the file so the exemption can be
  re-checked rather than inherited blindly.

### Fixed
- **About modal showed the wrong version.** The version was hard-coded in
  `layout_default.html` alongside the real one in `Cargo.toml`, so the two had
  to be bumped together — and they drifted: the `v0.2.0` tag was cut before the
  template was corrected, so the released 0.2.0 packages ship a modal reading
  0.1.0. The modal now renders `{{ version() }}`, a Tera function backed by
  `CARGO_PKG_VERSION`, leaving `Cargo.toml` as the single source of truth.
- About modal: the website link now points at `https://easysys.io/easywaf/`.
  Without the trailing slash the site answers 301 and downgrades the redirect to
  plain `http://`, so the link left HTTPS on the way to the same page.

### Added
- **Dashboard: traffic per site.** A new table breaks the last 24 hours down by
  site — requests, passed, challenged, blocked, and blocked share — with each
  site linking through to its filtered view in the Traffic Monitor. Sites with
  no traffic are listed with zeros rather than omitted, so a configured but idle
  site is visible. Challenges are counted in their own column and excluded from
  "passed", since a visitor shown a CAPTCHA was neither cleanly allowed nor
  blocked.
- Dashboard: a fourth summary card showing total requests over the last 24
  hours. The count was already being computed for the page but never displayed.

### Fixed
- **Site hostname is now normalised on save.** The Hostname field is matched
  against the request's `Host:` header, which never carries a scheme, a path or
  (once the proxy has stripped it) a port — so pasting a URL such as
  `http://example.com` silently matched nothing and the site answered
  "No site configured for this host" with no hint as to why. Create and update
  now reduce the value to a bare host: `https://Example.com:8080/app/` is stored
  as `example.com`. A trailing DNS root dot is dropped too, and a hostname that
  normalises to empty is rejected on update as it already was on create.

### Changed
- Site forms: the Hostname and Upstream Target fields now say what shape they
  expect (bare host vs. full URL) and the settings form carries the same hints
  and placeholders as the create form, which previously had them alone.
- Site forms: corrected the Listen Port hint. A new port is bound immediately
  without a restart; it is the *previously* bound port that keeps listening
  until the proxy restarts.
- Repository moved to `https://github.com/easysysio/EasyWAF` (the easysysio
  org). Added `repository`/`homepage` to `Cargo.toml`; git remote updated.
  Author and package maintainer remain "Yariv Hakim".
- About modal: website link now points to `https://easysys.io/easywaf`
  (was easywaf.org); version updated to 0.2.0 and copyright to 2025–2026.

### Added
- **CAPTCHA challenge** — suspicious-but-maybe-legit requests can now be shown
  a self-hosted image CAPTCHA instead of being hard-blocked, cutting false
  positives while still costing bots:
  - New `challenge` rule action and a per-policy **`challenge_threshold`**
    (migration 005): score ≥ challenge_threshold but < block_threshold ⇒
    challenge; block_threshold still hard-blocks. `DetectionOnly` only alerts.
  - New pipeline outcome `Challenge`; the proxy serves a standalone CAPTCHA
    page (pure-Rust `captcha` crate, no third party) when challenged and the
    visitor has no clearance.
  - Solving it sets a short-lived (30 min), IP-bound, HMAC-signed
    `easywaf_clearance` cookie; subsequent requests skip the challenge.
    In-flight challenges are kept in memory (~3 min TTL); the cookie itself is
    stateless. Verification handled at the internal `/__easywaf/verify` path.
  - Challenges are recorded in `traffic_events`; rule lists show a CAPTCHA
    badge; `challenge` added to the rule action dropdowns and a Challenge
    Threshold field to policy create/settings.

## [0.2.0] — 2026-06-07

### Added
- **Release CI pipeline** (`.github/workflows/release.yml`) — triggered by
  pushing a `v*` tag:
  - Builds the release binary for **x86_64** and **arm64 (aarch64)**
    (cross-compiled with the aarch64 GCC toolchain; sqlx schema built in CI
    from the migration files)
  - Packages each architecture as both **`.deb`** and **`.rpm`**
    (cargo-deb / cargo-generate-rpm) — binary to `/usr/bin/easywaf`, runtime
    assets to `/opt/easywaf`, plus a systemd unit
  - Creates a **GitHub Release** with all four packages attached and the
    body taken from the matching `CHANGELOG.md` section (falls back to
    `[Unreleased]`)
- Packaging metadata in `Cargo.toml` (`[package.metadata.deb]` /
  `[package.metadata.generate-rpm]`) and a `packaging/easywaf.service`
  systemd unit (WorkingDirectory `/opt/easywaf`, `CAP_NET_BIND_SERVICE`)

### Added
- **Auto theme mode** — the navbar theme button now cycles
  **Auto → Light → Dark**. "Auto" (the new default) follows the operating
  system's light/dark setting via `prefers-color-scheme`, and updates live
  if you change your OS theme while a page is open. The button icon reflects
  the current preference (half-circle = Auto, sun = Light, moon = Dark).
  Preference persisted in `localStorage`; resolved before paint in the
  `<head>` so there is no flash. Asset version bumped to `v=3`.

### Fixed
- **Theme toggle appeared not to work due to stale browser cache** — the
  `/static` files were served without a `Cache-Control` header, so browsers
  heuristically cached the old dark-only `easywaf.css`/`easywaf.js` (which had
  no `toggleTheme`), making the new toggle do nothing. Fixed by:
  - Serving `/static` with `Cache-Control: no-cache` (always revalidate;
    cheap 304 when unchanged, fresh assets when they change) via a
    `SetResponseHeaderLayer` — prevents stale assets going forward
  - Adding a `?v=2` cache-busting query to the CSS/JS includes so already-
    cached copies are bypassed immediately
  - Added `tower` dependency and the `set-header` tower-http feature

### Added
- **Light / Dark mode** — a theme toggle (sun/moon icon) in the navbar:
  - Choice persisted in `localStorage`; applied before paint via an inline
    `<head>` script so there is no flash of the wrong theme on load
  - Works on both the app layout and the login page

### Changed
- **GUI stylesheet rewritten to be theme-driven** — all neutral surfaces,
  borders, text, navbar/sidebar/dropdown/modal backgrounds, inputs, tables,
  scrollbars and the page background now come from CSS variables that flip
  between a light and a dark palette; accent colours stay constant
  - Light theme: clean white glass surfaces on a soft slate-blue background
  - Dark theme: the existing obsidian glassmorphism look
  - Labels, badges, alerts and `code` get theme-appropriate text contrast
  - Loads Inter/Outfit web fonts the stylesheet already referenced

### Added
- **Create custom rules from the Rule Editor** — an "Add Custom Rule" button
  on the Rule Editor page opens a form (`/rules/new`) to define a rule and
  choose which policy it belongs to:
  - Fields: target policy (dropdown), name, description, zone, pattern,
    score, action, with a live regex tester
  - Server-side regex validation; rejects invalid patterns back to the form
  - Created rules have no `external_id`, so they appear in the
    "Custom / Manual" group of the Rule Editor
  - Friendly warning + link when no policies exist yet
  - `GET /rules/new` and `POST /rules/create` routes

### Changed
- **Rule Editor is now grouped by category** (collapsible panels, like the
  policy-creation page) instead of one flat table:
  - Rules are bucketed by category via their `external_id` (SQL Injection,
    XSS, LFI, RFI, RCE, PHP, Protocol, Scanners); hand-written rules with no
    external_id go into a "Custom / Manual" group at the end
  - Each panel header shows the category, code, and "N enabled / M rules"
  - Panels collapsed by default; click to expand; Expand all / Collapse all
  - Search filters rows across all groups and auto-expands while typing
  - `get_all_rules` now returns `EditorGroup`/`EditorRule` grouped data

### Added
- **Rule Editor** — a new top-level page under Security Policy (sidebar:
  Security Policy → Rule Editor, `/rules`) that lists every WAF rule across
  all policies and lets each one be edited:
  - Global table (DataTables) with policy, name, zone, pattern, score, status
  - **Per-rule edit form** (`/rules/{id}/edit`) — the first place rule fields
    (name, description, zone, pattern, score, action, enabled) can be changed;
    includes a live regex tester and server-side regex validation on save
  - Toggle enable/disable and delete directly from the list or the edit form
  - `RuleForm` gained an optional `enabled` field (used only by the edit form)

### Changed
- **Create Policy rule selection is now collapsible** — only the category
  groups are shown by default; clicking a group header expands its rules.
  - Chevron icon indicates open/closed state
  - The category's master checkbox still works without toggling the panel
  - Searching auto-expands all categories so matches are visible, and
    collapses them again when the search box is cleared

### Added
- **Select rules during policy creation** — the Create Policy form now embeds
  the full Rule Library below the policy fields:
  - All rules grouped by category with checkboxes, per-category select-all,
    global select/clear, live counters, and a search filter
  - On submit, the chosen rules are inserted into the newly-created policy in
    one step; the success message reports how many rules were added
  - Refactored `rules.rs`: `read_catalog_categories()` (pure file I/O) and
    `add_rules_by_external_ids()` are now public and reused by both the
    catalog sync and the policy-creation flow; `CatalogRule`/`CatalogCategory`
    made public

### Added
- **Policy Manager now shows rules per policy** — the `/policy` list gained:
  - A **Rules** column: a clickable badge ("99 rules · 88 enabled") linking
    straight to the rules page, or a "Select rules" button for empty policies
  - A **Threshold** column showing each policy's score threshold
  - Rule Engine mode rendered as a coloured label (Enforcing / Detection only / Off)
  - A quick "Manage Rules" list icon in the Actions column
  - `fetch_policies` now LEFT JOINs `waf_rules` to compute per-policy
    rule_count and enabled_count

### Added
- **Rule Library selection GUI** (`/policy/{name}/rules/catalog`) — browse every
  rule from the `rules/` directory and pick the ones applicable to you:
  - Rules grouped into category panels (SQL Injection, XSS, LFI, RFI, RCE,
    PHP, Protocol, Scanners) with a per-category "select all" checkbox
  - Rules already in the policy are pre-checked, so the catalog reflects
    your current selection
  - Live "X of Y selected" counters (global and per-category) and a search
    filter to narrow the list
  - **Save = sync**: checked rules are added, unchecked catalog rules are
    removed. Manually-created rules (no external_id) are never touched
  - "Select from Rule Library" button added to the Rules Manager page
  - `GET/POST /policy/{name}/rules/catalog` routes; selection submitted as a
    single comma-separated field (same serde_urlencoded-safe pattern as bulk)

### Fixed
- **2 OWASP rule files failed to import silently** — `932-rce.toml` and
  `933-php.toml` had `[''"]` regex char classes inside TOML single-quoted
  literal strings, where `''` terminates the string early and causes a TOML
  parse error. The importer logged a warning and skipped the whole file,
  so 24 rules never loaded. Switched the 4 affected patterns to TOML
  multi-line literal strings (`'''...'''`) which allow both quote types.
- **Empty policy gave no guidance** — the rules page showed a bare empty
  table when a policy had no rules, making it look like selection was broken.
  Added an empty-state message pointing to Import / Seed / Add Rule.

### Fixed
- **Bulk rule selection not working** — two bugs:
  1. `BulkForm.ids` was `Vec<i64>` but `serde_urlencoded` (used by axum's
     `Form` extractor) does not map repeated keys into a Vec; changed to
     a single comma-separated `String` populated by JS before submit
  2. DataTables was reinitialising the DOM on sort/search, detaching the
     event listeners attached before initialisation; fixed by using jQuery
     event delegation on `tbody` and setting `paging: false` so all rows
     are always in the DOM (no cross-page checkbox state issue)

### Added
- **Bulk rule selection** on the Rules Manager page:
  - Checkbox column on every row + "select all" header checkbox
  - Bulk action bar appears when one or more rules are selected,
    showing the count and three buttons: Enable, Disable, Delete
  - `POST /policy/{name}/rules/bulk` route accepts a list of rule IDs
    and a `bulk_action` (enable / disable / delete)
  - Delete action requires a JS confirmation before submitting
  - Per-row toggle and delete buttons kept alongside for quick single-rule edits

### Fixed
- `policy_create.html` — removed stale "No OWASP CRS rule files found"
  message left over from the Perl era; replaced with a clean form that
  matches `policy_settings.html` (name, rule engine mode, score threshold)

### Added
- **OWASP rule files** — `rules/` directory with 7 TOML files covering 93 rules
  based on OWASP ModSecurity Core Rule Set v3.x patterns:
  - `920-protocol.toml` — protocol enforcement (double encoding, CRLF, XXE, SSRF, cloud metadata)
  - `930-lfi.toml` — local file inclusion (path traversal, /etc/passwd, null byte, SSH keys)
  - `931-rfi.toml` — remote file inclusion (HTTP/FTP URL params, PHP stream wrappers)
  - `932-rce.toml` — remote code execution (shell chaining, reverse shells, template injection)
  - `933-php.toml` — PHP injection (eval, exec, include, unserialize, preg_replace /e)
  - `941-xss.toml` — cross-site scripting (script tags, event handlers, VBScript, data URIs)
  - `942-sqli.toml` — SQL injection (UNION, blind time/boolean, xp_cmdshell, INTO OUTFILE)
  - `990-scanners.toml` — scanner/bot detection (sqlmap, Nikto, Burp, ZAP, Metasploit, etc.)
- **Import route** `POST /policy/{name}/rules/import` — reads all `*.toml` files from
  `rules/` at runtime, inserts unseen rules (idempotent via `external_id`); repeated
  imports safely skip already-loaded rules
- Migration 004 — `external_id INTEGER` column on `waf_rules` + unique index on
  `(policy_id, external_id)` to enforce one copy per rule per policy
- "Import OWASP rules" button on the Rules Manager page

### Added
- **WAF rules engine** — full per-policy pattern-based inspection:
  - `waf_rules` table (migration 003): id, policy_id, name, description,
    zone, pattern, score, action, enabled
  - `modules/waf.rs`: new `WafModule` in the pipeline; evaluates every
    enabled rule for the site's policy; instant-blocks on `action=block`;
    accumulates scores and blocks when total ≥ `score_threshold`
  - Respects `rule_engine` mode: `Off` skips all checks, `DetectionOnly`
    raises Alert instead of Drop, `On` fully enforces
  - Invalid regex patterns are logged and skipped — a broken rule cannot
    crash the WAF
- **Rules manager UI** (`/policy/{name}/rules`):
  - List all rules with zone, pattern, score, action, and enabled status
  - Enable / disable individual rules without deleting them
  - Delete rules with confirmation
  - Stats cards: total / enabled / disabled / threshold
- **Add Rule form** (`/policy/{name}/rules/new`):
  - Fields: name, description, zone, pattern (regex), score, action
  - Client-side live pattern tester (JS regex preview)
  - Common-patterns reference sidebar
  - Server-side regex validation before saving
- **Built-in default rule set** (24 rules across 5 categories):
  - SQL Injection (7 rules): UNION SELECT, blind SLEEP, boolean injection,
    stacked queries, DROP/TRUNCATE (instant block), comment stripping
  - XSS (5 rules): script tag, javascript: URI, event handlers, iframe/embed, SVG
  - Path Traversal (4 rules): `../`, encoded `%2e%2e`, /etc/passwd (instant block),
    Windows system32 (instant block)
  - Remote Code Execution (4 rules): PHP exec/eval family, shell pipe injection,
    template injection `${}`, PHP stream wrappers
  - Scanners (2 rules): known tool User-Agents (sqlmap/nikto/etc.), admin path brute-force
  - Seeded via "Seed default rules" button or automatically on demand
- **Policy settings** cleaned up: removed stale OWASP CRS file-based UI;
  added "Manage WAF Rules" button; score_threshold now editable inline

### Added
- **Dynamic port binding** — adding or editing a site with a new `listen_port`
  now opens that TCP listener immediately without restarting EasyWAF.
  - `AppState` gains a `port_tx: mpsc::Sender<u16>` channel to the proxy
  - `proxy::start()` accepts `mpsc::Receiver<u16>` and loops on it forever;
    each received port is bound if not already in the `bound` HashSet
  - `post_site_create` and `post_site_update` send the port after saving to DB
  - Bind failures log an error instead of panicking, so a bad port number
    cannot crash the whole process

### Changed
- Fixed all 8 compiler warnings — build is now warning-free:
  - `certs.rs`: removed unused `AppError` import
  - `error.rs`: added `#[allow(dead_code)]` to `Internal` and `Unauthorized`
    variants (kept for future auth middleware / route error handling)
  - `modules/mod.rs`: added `#[allow(dead_code)]` to `RequestContext`,
    `ModuleDecision`, `Alert`, and `PipelineVerdict` — all are scaffolding
    for the upcoming GeoIP and WAF-rules modules
  - `modules/traffic.rs`: removed unused `db` field from `TrafficLogger`;
    logging is done by the proxy via `log_event()`, not inside the module

### Fixed
- `traffic.html` — `tojson` filter does not exist in Tera 1.20.1; replaced
  with the correct built-in filter name `json_encode` (caused "Failed to
  render 'traffic.html'" on every visit to the Traffic Monitor page)

### Added
- **Per-site `listen_port`** — each virtual host now has its own TCP port
  configured in Site Settings (default 80). The proxy binds one listener
  per unique port found across all enabled sites at startup.
  Multiple sites can share the same port (routing is still by Host header).
- `listen_port` column shown in the Sites list table as a `:80` badge.
- Migration 002 (`002_listen_port.sql`) adds the column to existing databases
  safely via a PRAGMA table_info check — no data is lost on upgrade.

### Changed
- `proxy::start()` no longer takes a global `http_port` argument; it reads
  ports directly from the `sites` table at startup.
- `config.toml` `http_port` is now unused by the proxy (kept for reference
  only; will be removed in a future cleanup).

### Added
- **Traffic Monitor** (`GET /traffic`) — live view of every proxied request with:
  - Filter bar: site, blocked/allowed/all, time window (1 h – 30 d)
  - Four stat cards: total requests, blocked, allowed, average response time
  - Stacked bar chart (Chart.js) showing allowed vs blocked requests per hour
  - DataTables event log (up to 1000 rows) with method colour-coding,
    status-code colour-coding, country, and block-reason tooltip
  - Live-refresh toggle (auto-reloads every 5 s)
- Traffic Monitor link added to the sidebar navigation

### Fixed
- `sites.html` — removed stale `site.port` and `site.waf_policy` references
  that caused a template render error; replaced with `site.waf_policy_id`
  badge and `site.enabled` status badge

---

## [0.1.0] — 2025-05-25 (initial Rust rewrite)

### Added
- Self-contained HTTP reverse proxy (no nginx dependency)
- Virtual hosting routed by `Host:` header
- Management GUI on a separate port (Axum + Tera)
- SQLite database with WAL mode, auto-created on first run
- Module pipeline: async inspection modules (Pass / Alert / Block)
- TrafficLogger module — every proxied request written to `traffic_events`
- Site management: create, edit, delete virtual hosts
- Certificate management: PEM stored in DB
- WAF policy management
- GeoIP rules UI
- Dashboard with 24 h traffic summary
- Default `admin/admin` account seeded on first run

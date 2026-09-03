# Changelog

All notable changes to EasyWAF are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version bumps and tags are created only after explicit approval.

---

## [Unreleased]

### Added
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

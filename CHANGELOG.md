# Changelog

All notable changes to EasyWAF are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version bumps and tags are created only after explicit approval.

---

## [Unreleased]

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

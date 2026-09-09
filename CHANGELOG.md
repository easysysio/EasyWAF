# Changelog

All notable changes to EasyWAF are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version bumps and tags are created only after explicit approval.

---

## [Unreleased]

### Added
- Flow logs over syslog: one line per proxied request, sent to a collector with the site, client, method, path, verdict, score and rules. Off by default.
- Settings › Logging: the syslog collector's address and port, applied to the running proxy on save rather than at the next restart.
- Logging configuration in `config.toml`: the directory the audit log is written to — `/var/log/easywaf` on every installation, created by the systemd unit — and how many days of files are kept.
- Audit log: every change made through the management interface is written to `/var/log/easywaf/audit.log` with the account, the client address, the outcome and — when a save was refused — the reason.
- Sign-ins, failed sign-ins and sign-outs appear in the audit log, a failed one naming the account that was tried.
- `docs/design/easylog-easywaf-type.md` — the wire format EasyWAF emits, specified for EasyLog to implement a parser against.

### Fixed
- `scripts/modsec2easywaf.py` converted CRS rules of every paranoia level. CRS runs level 1 by default and higher levels are opt-in, so 53% of the output was rules CRS itself would not run. It now takes `--max-paranoia`, default 1.

## [0.8.1] — 2026-09-09

### Fixed
- Signing in after a session ended looped between the login page and the dashboard until the browser gave up with ERR_TOO_MANY_REDIRECTS. The login page decided "already signed in" from the cookie alone while every other page checked the database.
- Logging out did not always remove the session cookie: the removal did not name the path the cookie was set with, so the browser kept it.

## [0.8.0] — 2026-09-09

### Added
- Accounts have roles: `admin` sees and changes everything, `viewer` sees the
  dashboard, traffic, sites, policies, rules, exclusions and certificates but
  changes nothing. Every account existing before the upgrade becomes an admin.
- Account management under Settings › Accounts: create, change role, reset a
  password, sign out everywhere, suspend, delete.
- Accounts can be suspended rather than deleted, keeping their history, and
  their last sign-in is recorded.
- Sessions can be ended. A password change, role change, suspension or "sign
  out everywhere" invalidates that account's sessions immediately, instead of
  leaving them valid for up to eight hours.
- The interface reflects the role: controls a viewer cannot use are not offered,
  and the header shows a `viewer` badge.

### Changed
- Authorisation is declared per route rather than checked by each handler, so a
  page that needs an administrator cannot be written without saying so.
- Settings is administrator-only. Certificates are readable by viewers —
  private keys are never rendered — but uploading, requesting and deleting are
  not.

### Security
- A session no longer outlives the password that created it.
- No action can leave the installation without an enabled administrator: the
  last one cannot be demoted, suspended or deleted, and no account can suspend
  or delete itself.

## [0.7.3] — 2026-09-08

### Added
- Clicking a chart filters the traffic it stands for: a Traffic Monitor bar narrows to that hour, and a dashboard bar or verdict slice opens Traffic Monitor already narrowed.

### Changed
- A sub-threshold match is labelled SCORED rather than DETECTED, and shows its score — the old word read as though an enforcing policy had stopped enforcing.

## [0.7.2] — 2026-09-08

### Fixed
- Rule Exclusions now appears in the Security Policy menu, as one page across all policies with a filter.

## [0.7.1] — 2026-09-08

### Added
- A site with no policy attached now says so, on the dashboard, in the sites list and beside the policy selector. It is the one state in which nothing is inspected.

### Fixed
- Excluding a rule from Traffic Monitor failed with "invalid digit found in string". The exclusion was saved; only the confirmation was lost.

## [0.7.0] — 2026-09-08

### Added
- A rule exclusion can name the clients it applies to, so one client's false positive no longer needs the rule weakened for everyone.
- Traffic Monitor rows carry an "exclude for this IP" button, and mark a rule already excluded for that client.
- A Rule Exclusions page per policy lists every rule not running, with the client and path each covers, and removes them.

## [0.6.12] — 2026-09-08

### Added
- A policy's custom rules can be copied into another policy, skipping any rule the target already holds by pattern.
- `scripts/modsec2easywaf.py` converts ModSecurity rules, refusing with a reason the ones it cannot convert faithfully.

### Changed
- A cloned rule is a custom rule and no longer sits in the set it came from, while still recording where it came from.

### Fixed
- The Traffic Monitor graph ignored the verdict filter, so the table filtered while the graph showed everything. It also gained a Detected series.

## [0.6.11] — 2026-09-08

### Changed
- The rule-signing key is compiled into the binary, so an installation cannot be missing the thing it verifies updates against. A key on disk still wins, and says so in the log.

### Fixed
- DetectionOnly reported nothing it detected: traffic records now say what the WAF would have done.
- A request that matched rules but stayed under the threshold left no trace, in every mode. Those are now recorded with their score and rules.
- `assets::tera()` returned an instance that could not render, because the layout's `version()` function was registered separately.

## [0.6.10] — 2026-09-07

### Added
- A site can exclude a rule, optionally under a path prefix, so a false positive on one site does not weaken the rule for every site sharing the policy.
- `scripts/prune-debris.sh` finds and removes rule rows left behind before 0.6.6 that inflate a request's score.

### Changed
- The Create Policy page asks for the policy first, and for sets and rules as one question instead of two.
- The site form takes a list of ports per protocol ("80, 8080") instead of a primary port plus a separate extras field.

## [0.6.9] — 2026-09-07

### Added
- Rule sets are read from one directory: the package seeds it, the channel refreshes it, and every reader looks there.
- The rule channel is mirrored to disk, so installing a set no longer needs the network.
- Rule sets can be chosen while creating a policy, rather than only afterwards.

### Fixed
- A rule taken singly from the Rule Library recorded no set, so it was never offered updates.
- Deleting a policy silently removed WAF protection from every site using it. It is now refused while a site holds it.

## [0.6.8] — 2026-09-07

### Fixed
- The Rule Editor filed correctly-installed rules under "Custom / Manual".

## [0.6.7] — 2026-09-07

### Fixed
- The Rule Editor's group headers counted rows rather than rules.

## [0.6.6] — 2026-09-07

### Added
- The Rule Editor warns about custom rules that duplicate an installed one, since both match and both add their score.

### Removed
- The "Seed defaults" button and the hardcoded rules behind it, which duplicated the published sets.

## [0.6.5] — 2026-09-07

### Added
- A site can answer on more than two ports.

### Fixed
- A rule saved from the rule editor appeared to vanish.

## [0.6.4] — 2026-09-07

### Added
- Rule sets imported before 0.6.0 are adopted automatically, so those policies start being offered updates.

## [0.6.3] — 2026-09-07

### Fixed
- The Rule Sets page was almost unreachable, having no entry point unless an update was already pending.
- Uploading a certificate under an existing name detached it from every site using it.
- A slow certificate authority was reported as a failed validation; the ACME timeout is now 120 seconds.
- The certificate authority's own explanation of a failure is now reported first.

## [0.6.2] — 2026-09-06

### Changed
- Templates and static assets are compiled into the binary, so EasyWAF is one executable.

### Fixed
- `rules/key.gpg` was missing from the .deb and .rpm, so 0.6.0 and 0.6.1 could not apply any rule update.

## [0.6.1] — 2026-09-06

### Added
- A Rule Sets page: browse what the channel publishes, and install or update per policy.

### Changed
- Port 80 is bound whether or not a site asks for it, because HTTP-01 validation always arrives there.
- `proxy.http_port` and `proxy.acme_webroot` are accepted but ignored, with a warning.

### Fixed
- A certificate request that timed out now says what timed out.

## [0.6.0] — 2026-09-06

### Added
- EasyWAF notices when a newer rule set is published, and can apply it — verified by signature and hash before anything is written.
- A new site can request its certificate from the create form.

### Changed
- Settings is organised into tabs.
- The rule channel is configurable and the update check can be turned off.
- Imported rules are read-only; customising one means cloning it, so an update cannot silently revert an edit.
- Rule sets describe themselves, and EasyWAF records which set and version each policy holds.

### Fixed
- Requesting a certificate reported neither success nor failure.

## [0.5.6] — 2026-09-06

### Changed
- `scripts/fetch-rules.sh` refreshes `rules/` from the published channel, verifying the signature.
- Rule set files are named `<band>-<slug>.rules.toml`.

### Fixed
- Migration 012 never reached the installations that had EasyWAF longest.
- Rule 913015 scored an application's own admin pages.
- The URL zone ran the path into the query, so a rule anchored to the end of a path never matched when a query was present.
- Stray empty boxes beside the table pagination on four pages.

## [0.5.5] — 2026-09-05

### Added
- Traffic Monitor says which rules produced a verdict, and what each contributed.

## [0.5.4] — 2026-09-05

### Fixed
- Rule 932012 blocked ordinary traffic from any application whose cookies contain a semicolon.
- Rule 920002 treated ordinary URL encoding as a double-encoding attack.

## [0.5.3] — 2026-09-05

### Changed
- `X-Frame-Options` is a choice per site rather than always `DENY`.

## [0.5.2] — 2026-09-05

### Fixed
- Only the last of any repeated response header reached the client, which broke cookie-based logins upstream.

## [0.5.1] — 2026-09-05

### Added
- Forwarding headers are sent to the upstream: `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`.
- WebSockets are proxied.

### Fixed
- An uploaded certificate is now checked against its key.

## [0.5.0] — 2026-09-05

### Added
- Let's Encrypt certificates, issued and renewed by EasyWAF.
- `X-Forwarded-For` support behind a trusted-proxy list, so a client IP is believed only from an address you name.
- A Docker Hub overview (`docker/README.md`).

### Fixed
- Uploading a certificate never worked: the form posted field names the handler did not read.

### Upgrading
- Nothing to do. A migration adds renewal-tracking columns; existing certificates are untouched.

## [0.4.3] — 2026-09-05

### Added
- Certificate details: subject, issuer, validity, SANs, fingerprint and chain length.
- The management interface's certificate is chosen in Settings.

### Fixed
- A certificate in use can no longer be deleted.
- Deleting a certificate now rebuilds the SNI map.
- Reading a certificate no longer shells out to the `openssl` binary.

## [0.4.2] — 2026-09-05

### Changed
- The administrator account is created at first run instead of being seeded as `admin`/`admin`.
- `secret` is gone from `config.toml`; the cookie signing key is generated and stored on first run.
- `database_url` is gone from `config.toml`, replaced by the `DATABASE_URL` environment variable.

### Fixed
- The account page's default-password banner described the wrong thing.

### Upgrading
- Nothing breaks and nothing needs editing. An existing `config.toml` still parses; removed keys are ignored with a warning.

## [0.4.1] — 2026-09-04

### Changed
- `rustls-pemfile` removed (RUSTSEC-2025-0134, unmaintained).

## [0.4.0] — 2026-09-04

### Added
- The management interface is served over TLS, with a self-signed certificate generated on first run.
- HTTPS for proxied sites, with an optional per-site HTTP-to-HTTPS redirect.
- TLS profile and configurable cipher suites in Settings.
- Self-service password change.
- `gui_tls_port` (default 8443) serves the GUI; `gui_port` (8080) redirects to it.
- `scripts/dev-db.sh`.

### Changed
- The session cookie is marked `Secure`.

### Fixed
- A TLS listener logged "listening" before it had bound the port.

### Upgrading from 0.3.x
- The GUI moves to HTTPS on port 8443. The browser will warn about the self-signed certificate on first visit.

## [0.3.1] — 2026-09-04

### Changed
- Rule ids match their OWASP CRS category.

### Fixed
- `SQLi: SQL comment stripping` (942007) false-positived on almost all traffic.
- A multi-encoding-form fix introduced a second false positive on percent-encoded headers.

## [0.3.0] — 2026-09-04

### Added
- Country rules on a policy: block a list of countries, or allow only those named.
- Offline IP geolocation, using the DB-IP Lite country database compiled into the binary.
- Container image `easysysio/easywaf`, multi-arch amd64 and arm64.
- Groundwork for updating rules and the country database.

### Security
- A country rule never fires on an address with no country, such as a private range.

## [0.2.4] — 2026-09-03

### Added
- Enable and disable a site from Site Management.
- A configurable maintenance message for disabled sites.
- Favicon, and a dashboard screenshot in the README.

## [0.2.3] — 2026-09-03

### Added
- `scripts/waf-test.sh` fires representative attacks at a site and reports what was blocked.
- README.

### Fixed
- Percent-encoded payloads bypassed most WAF rules.
- Upgrading or removing the package left the old service running.

## [0.2.2] — 2026-09-03

### Added
- Dashboard charts: requests per hour and a verdict split.
- A Settings section for installation-wide options.
- Traffic retention, so the events table does not grow without bound.

### Changed
- WAF rule patterns are compiled once instead of per request.

### Fixed
- The Traffic Monitor's per-hour chart never rendered.
- Dashboard panels disagreed about their time window.

## [0.2.1] — 2026-09-02

### Added
- CAPTCHA challenge for suspicious-but-plausible requests.
- Dashboard: traffic per site, and a total-requests card.

### Changed
- Site forms say what shape each field expects.
- Repository moved to `https://github.com/easysysio/EasyWAF`.

### Fixed
- The About modal showed a hard-coded version.
- Site hostnames are normalised on save.

### Security
- `cargo audit` is clean.

## [0.2.0] — 2026-09-02

### Added
- WAF rules engine: per-policy pattern inspection across URL, args, body and headers, with scoring and thresholds.
- Rule Editor, custom rules, bulk selection, and rule selection during policy creation.
- OWASP rule files in `rules/`, importable per policy.
- Traffic Monitor: every proxied request, with filters.
- Per-site listen port, bound dynamically without a restart.
- Light and dark themes, following the OS setting by default.
- Release CI producing .deb and .rpm for x86_64 and arm64.

### Fixed
- Two OWASP rule files failed to import silently.
- Bulk rule selection did not work.

## [0.1.0] — 2026-09-01

### Added
- Self-contained HTTP reverse proxy, virtual-hosted by `Host:` header.
- Management GUI on a separate port, with sites, certificates, policies and GeoIP rules.
- SQLite storage, created on first run.
- Module pipeline for async inspection, and a traffic logger writing every request.
- Dashboard with a 24-hour traffic summary.

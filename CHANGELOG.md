# Changelog

All notable changes to EasyWAF are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version bumps and tags are created only after explicit approval.

---

## [1.0.1] — unreleased

### Added
- **A new optional rule set on the channel, *Exploit probes*:** the exact requests scanners send to every address for one known hole each — PHPUnit, Laravel Ignition, ThinkPHP, PHP-CGI, Drupalgeddon, Shellshock, Exchange ProxyShell, router and VPN-appliance firmware. Every rule blocks, so Smart Protect refuses a scanner a few requests into its list. It needs no upgrade: tick it on a policy's Rules tab once it is published.
- The *Java and Tomcat* set (version 4) blocks the Spring Boot actuator endpoints that return the environment or a heap dump.
- **An optional set for Node.js and document databases, *Node.js and NoSQL*:** a query operator where a password or token was expected (`password[$ne]=x`), operators that run code (`$where`), prototype pollution (`__proto__`), constructor sandbox escapes, node-serialize and EJS option injection. Operators on ordinary fields are left alone, since Strapi, Feathers and similar frameworks use them as their query language.
- **Three more optional sets.** *Web shells*: the request made after getting in — a shell by its known name, a script under `.well-known` or an uploads directory, and the dialects of WSO, China Chopper and AntSword. *IIS and ASP.NET*: `web.config` backups, `trace.axd` and `elmah.axd`, short-name enumeration, `::$DATA`, .NET deserialization gadgets and SharePoint ToolShell. *Bad bots*: SEO crawlers, site copiers, address harvesters and internet scanners by what they call themselves, each a rule to untick.
- **Two more optional sets, which are a policy rather than a protection.** *AI crawlers* refuses the crawlers that collect content to train models, and — as a rule of its own, to untick if you want to stay in their results — those that index it for AI search. *AI assistants and agents* refuses pages fetched because a person asked an assistant, and is separate so that refusing crawlers does not refuse readers.
- A rule set that is not bundled can be tested through the engine itself: `cargo test a_set_does_what_its_cases_say`, given a set file and a file of cases.

---

## [1.0.0] — 2026-10-02

### Security
- **A few hundred slow connections could take every site down.** A connection that never finished its headers, or never sent anything, was held open for ever, each holding a file descriptor; at the limit, every site and the management interface stopped answering. A connection now has 30 seconds to send a request, a kept-alive one 30 seconds between requests, and the inspected start of a body may not go 30 seconds without a byte arriving — on the sites' ports and the interface's alike.
- One address — or one IPv6 /64 — may hold at most 1,024 connections at once, so a single machine cannot use up the descriptors by opening them faster than they time out. A trusted proxy is exempt.
- **A connection that opens as HTTP/2 is disconnected.** None is advertised, but one opened that way was served anyway, without any of the limits above — it could be held open for ever — and without being routable, since such a request carries no `Host` header.
- The service's descriptor limit is raised from the default 1,024 to 65,536.
- **The packaged service no longer runs as root.** It runs as its own account, `easywaf`, with the one extra right it needs — binding ports below 1024 — and with `/usr`, `/etc`, home directories and devices out of its reach. The package creates the account and hands it `/opt/easywaf` and `/var/log/easywaf`.
- **The management interface loads nothing from outside.** Bootstrap, jQuery, DataTables, metisMenu, Chart.js, Font Awesome and the two fonts came from six other hosts, unchecked; they are now compiled into the binary, so the interface works on a host with no internet access and no outside host can change what runs in an administrator's browser.
- The interface sends a content security policy that allows scripts, styles, fonts and requests only from itself.
- **A blocked request is no longer told which rule matched.** The 403 named the rule, or the score and the threshold — directions for getting under it next time. It is now a page saying the request was blocked, with the time and the visitor's address as a reference; the rule, score and reason are in Traffic Monitor as before.
- A form's return path cannot lead off the appliance: `/\host`, which a browser reads as another site, was accepted from a signed-in administrator's own form.

### Added
- **A site can reach an HTTPS backend that has a self-signed or private-CA certificate.** Tick *Do not verify the backend's certificate* on the site; it is off by default, and other sites are unaffected. Such a backend used to answer 502 with no way round it.
- **A tutorial that sets a site up, one step at a time.** Six steps, each a short form that does the thing: the site, a check that it answers, HTTPS from Let's Encrypt in one press, a policy in DetectionOnly put on the site, daily snapshots, and what to do over the following days.
- On a new installation the tutorial opens when an administrator signs in, until one finishes it or presses **Don't show this again**; it stays under **Tutorial** in the menu. An installation that is upgraded is not shown it at sign-in.
- The documentation has the same route at more length, as a tutorial page.

### Fixed
- When a backend cannot be reached, the log says why — refused, timed out, or *invalid peer certificate* — rather than only "error sending request".
- The Traffic Monitor chart no longer asks for a tick at every whole number, which Chart.js had to cap on a busy hour.
- Deleting a policy lifts its Smart Protect blocks, which stayed on the Smart Protect page until each ran out.
- Creating a policy under a name already in use says so, where it answered with an error page.
- A site's hostname must be a hostname, as its aliases already had to be. One containing a space or a quote was saved, and could never match a request.

### Changed
- The versions after this one are renumbered: a sign-in in front of a site is 1.1.0, configuration sync between nodes 1.2.0, rate limiting 1.3.0 and URL allowlisting 1.4.0.
- The README, the documentation's home page and *What EasyWAF does not do* describe the product as it is: Smart Protect, load balancing, IP lists, backup and export were missing from the first two, and the README's own list of limits had fallen behind the documentation's, which it now points to.

### Upgrading
- The package creates the `easywaf` account if it is not already there — on a first install and on an upgrade alike — and gives it `/opt/easywaf` and `/var/log/easywaf`; nothing needs doing on a standard installation. If your database is somewhere else (`DATABASE_URL`), make that place writable by `easywaf` before upgrading.
- During the upgrade a running service is stopped, its files are handed to the account, and it is started again — in that order, so the old service, still running as root, cannot create a file the account then cannot open. If the account cannot be created the upgrade says so and leaves the service running as it was.
- Commands run by hand against the database should now be run as the account — `sudo -u easywaf sqlite3 /opt/easywaf/easywaf.db` — or the files they create belong to root and the service cannot open them. `sudo /usr/lib/easywaf/service-account` puts that right: it is what the package runs, and can be run by hand.
- Anything that read the text of a 403 from EasyWAF — a monitoring check matching "WAF block rule matched", say — should look at the status code instead; the body is now HTML and says only that the request was blocked.
- To go back to running as root, `sudo systemctl edit easywaf` and set `User=root` and `Group=root` under `[Service]`.

---

## [0.15.0] — 2026-10-01

### Added
- **Smart Protect: an address a policy's rules keep refusing is refused outright for a while.** Every request was judged alone, so a scanner firing two hundred probes got two hundred separate refusals and carried on. By default, three refusals within a minute block the address for ten minutes.
- **Enable Smart Protect** is a checkbox on each security policy, off by default. In DetectionOnly it records what it would have refused and refuses nothing; with the policy Off it does nothing.
- **Settings → Smart Protect** holds the numbers — how many refusals, within how many seconds, for how many minutes — set once for every policy, and in force as soon as they are saved.
- The same page lists every address blocked right now, with the policy, the refusal that completed the count and the time left, and an **Unblock** button.
- **A preview from your own traffic.** The same page replays a policy's recorded traffic through any numbers you try and says how many addresses they would have blocked — and how many of the requests refused that way had in fact been served successfully, which is what a false positive looks like. It changes nothing, and is offered for every policy, on or off.
- Only refusals by the rules count: not a rule that matched on a request that was served, a CAPTCHA, or a country refusal. A block lasts exactly as long as it says; requests made while blocked do not extend it.
- An address on a policy's allow list is never blocked, and neither is a trusted proxy. An IPv6 client is counted and blocked by its /64.
- Blocks are kept in memory on the node that made them, never written to an IP list, and cleared by a restart. The switch and the numbers travel in a configuration export.

### Removed
- The **Updates** tab on Settings → General, which held nothing but a note pointing to Settings → Updates; the menu already names that page.

### Upgrading
- Nothing changes until you tick **Enable Smart Protect** on a policy: it is off for every existing one. Try the preview on **Settings → Smart Protect** against your own traffic first.

---

## [0.14.4] — 2026-09-29

### Security
- **A client could pass itself off as another address behind a proxy that adds its own `X-Forwarded-For` line.** Only the first line was read — the one the client wrote — so behind HAProxy's `option forwardfor`, for one, a forged address was taken as the client's, and IP lists, country rules and challenge clearance all went by it. Every line is now read, in order, as the one list HTTP says they are. Only installations with trusted proxies configured were affected.
- **A rule excluded for a path was also skipped for requests that only looked as if they were under it.** `/files/../admin` counted as under `/files`, and so did the encoded `%2e%2e` form — and the request reached the application as `/admin`, with the rule off. A prefix also covered longer names: `/files` covered `/filesystem`. An exclusion's path is now compared with the path the application receives, a whole segment at a time.
- **WebSocket handshakes were forwarded with the client's headers as they arrived.** An `X-Forwarded-For` the client wrote reached the application unchecked, `X-Real-IP` and `X-Forwarded-Proto` were not sent, and `Host` was replaced with the backend's address, which an application comparing `Origin` with `Host` refuses. A handshake now carries the same forwarding headers as any other request, the browser's `Host`, and every value of a repeated header.
- **After solving a challenge, a crafted link could send the visitor to another site.** The return path had only to start with `/`, and `//evil.example/` does. It must now be a single-slash path on the same site.
- **Sign-in had no limit on attempts.** An address is now refused for the rest of a 15-minute window after 10 failed sign-ins in it. Counted per address, not per account, so nobody can lock an administrator out.
- **How long a refused sign-in took said whether the account existed** — about 2 ms for an unknown name against 230 for a known one. Both now take the same time.
- **A session's eight hours are enforced by the server**, not only by the cookie's lifetime in the browser, so a copied cookie stops working when the session would have ended. Cookies issued before this release carry no start time, so everyone signs in once more after upgrading.
- The challenge clearance cookie is marked `Secure` over HTTPS.

### Fixed
- Waiting challenges are capped at 10,000. Each draws an image and is kept for three minutes, so a flood of requests crossing a challenge threshold cost memory and CPU without limit; past the cap a visitor is asked to try again in a minute, before any image is drawn.

### Changed
- Code that described things it no longer did was corrected or removed: comments claiming a new port needs a restart, that alerts and blocks were "not yet produced", and a 32 MB body limit; a pipeline module that did nothing; and fields and an error variant nothing used. The proxy's request handler, one function of about 570 lines, is split into its steps — each a function of its own, named for what it does — so it reads top to bottom as the list of what happens to a request.
- Comments say what the code does and why; how it used to behave is left to this changelog and the git history. A version is still named where code exists to handle what an older release left behind, such as a cookie with no role or a config file with keys since removed.

### Upgrading
- Everyone signs in once more: sessions issued before this release carry no start time, so the server refuses them.
- An exclusion's path now covers whole path segments: `/api/upload` no longer covers `/api/uploads`. Add an exclusion for each path it was meant to reach.
- If the management interface is reached through a proxy — EasyWAF itself or another — list that proxy under **Settings → Proxy**, or every sign-in counts against the proxy's one address.

---

## [0.14.3] — 2026-09-29

### Fixed
- **The charts on the Dashboard and in Traffic Monitor follow the window when it gets wider, not only narrower.** Each kept its aspect ratio, and Chart.js caps a growing chart at its container's current height — which, in a panel exactly as tall as the chart, meant a chart could shrink and never grow back. Each chart now has a box of its own with a set height, and fills its width at any size.

---

## [0.14.2] — 2026-09-28

### Changed
- **The proxy holds every site in memory instead of looking each request's site up in the database.** That query was about half of what a request cost. A saved change to a site, its backends, its aliases or its certificate reaches the proxy within a second, as rule changes already did.
- A traffic row no longer reads the site's name back from the database after it is written, and the syslog line is built only when syslog is on.
- **Traffic rows are written by one task, in batches, from a bounded queue.** Every request used to start its own insert, and several at once fought over SQLite's single write lock: with a backlog, rows went in at about 2,850 a second and the backlog grew without limit. With both changes, 100,000 blocked requests are served at 38,000 a second — 68,000 over kept-alive connections — against 7,400 on 0.14.1, all in Traffic Monitor by the time the last one is answered, at under 100 µs of CPU each including the write where 0.14.1 took about 225. A flood that fills the queue drops rows rather than slowing the proxy, and the journal reports how many, as syslog lines already did.
- A status the background tasks keep — when a channel was last fetched, the last scheduled snapshot, the outcome of a restore — is reported in the journal if it cannot be saved, instead of being dropped without a word.

### Removed
- **The *Import OWASP rules* button on a policy's rules page.** It added only the rules a policy did not have, but recorded each set at the newest version — so a policy that had not applied an update was marked as having it, the update left the Updates page, and the policy went on running the old rules. The *Rule Sets* page installs and updates sets correctly, and keeps the version it replaced so it can be put back.

### Fixed
- The message 0.14.1 gives for an EC key that spells its curve out now shows for every such key. About one `EC PRIVATE KEY` in ten still got "failed to parse private key as RSA, ECDSA, or EdDSA", because the check searched for a byte that the random private key could also contain.

---

## [0.14.1] — 2026-09-27

### Security
- **Changes to the management interface can only come from the interface itself.** The session cookie's `SameSite=Lax` kept it off requests from other sites, but a sibling subdomain is the same site — so with the interface at waf.example.com, a script on app.example.com, perhaps an application EasyWAF proxies, could have sent a restore or an import with an administrator's session. A change the browser says came from another page is now refused; pages can still be linked to from anywhere.
- The management interface can no longer be framed by another page, and does not send its URLs to the libraries it loads.

### Fixed
- **A site could be saved with an HTTPS port and no certificate, and then nobody could reach it.** Its HTTPS port refused every handshake, and with "redirect to HTTPS" on, plain HTTP sent every visitor there — while the sites list said the site was active and protected. The form now refuses the combination, as the import already did; a site that still ends up that way, after a certificate request that failed, keeps serving plain HTTP rather than redirecting to a port that cannot answer, and the sites list says *HTTPS — no certificate*.
- A site's security headers — HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection — are sent on every response for that site, including EasyWAF's own block page, challenge page and gateway errors, not only on what the upstream returns. A visitor whose first response was one of those never received the HSTS the site's settings promised.
- HSTS is sent only over HTTPS, as RFC 6797 requires.
- An EC key that spells its curve out rather than naming it is refused with a message saying so and how to make one that works, instead of "failed to parse private key as RSA, ECDSA, or EdDSA" for a key that is ECDSA. The `openssl` on a Mac makes keys this way by default.
- The documentation said a site with an HTTPS port and no certificate did not bind the port; it did, once saved while EasyWAF ran.

### Changed
- Five signatures with no innocent reading — `UNION SELECT`, `WAITFOR DELAY`, `INTO OUTFILE`/`DUMPFILE`, `LOAD_FILE` and double-encoded `%252e%252e` — now block on their own at the default threshold, where before each needed a second rule to match beside it. `UNION SELECT` no longer matches words that contain it, as in "reunion selection". These arrive through the rule channel as SQL injection v3 and Local file inclusion v4, and take effect when an administrator applies the update.
- The rule sets bundled for a first start without network are refreshed to the published channel — scanners v4, local file inclusion v4, remote file inclusion v2, SQL injection v3 — so a new installation no longer starts on the ones from 2026-09-07 and waits for its first update to catch up.

---

## [0.14.0] — 2026-09-27

### Added
- **Settings → Backup**, for administrators only. **Download a snapshot**: the whole database, taken while EasyWAF runs and consistent without stopping it — including writes not yet folded into the main file, which a copy of the file would miss. The page says plainly that a snapshot is a secret: it holds every private key, every password hash and the key that signs sessions. It is sent uncacheable, written readable by its owner only, and not kept on the appliance after the download.
- **Scheduled snapshots**, off until an administrator switches them on: one a day, the newest few kept (seven unless you say otherwise), in `backups/` beside the database, readable by EasyWAF's own account only. Checked hourly against the newest snapshot rather than timed from the last start, so an appliance that restarts every day still takes one, and a restart never takes a second. **Take one now** proves it works without waiting a day; each kept snapshot can be downloaded; lowering the number kept prunes at once; and a failure — usually a full disk — is shown on the page. They guard against a bad change or a damaged database, and the page says plainly that they do not guard against losing the host unless that directory is copied off it.
- **Restore a snapshot** from the same page. An upload is checked before anything else happens — that it is SQLite, undamaged by SQLite's own integrity check, an EasyWAF database, and not from a newer EasyWAF than this one — and then **held**, with the page showing what it holds: the version that last ran it, its sites, policies, rules, certificates, accounts and newest traffic. Nothing is replaced until a second button says so, because the likeliest mistake is the wrong file.
- A restore replaces the whole database, so it is applied by a restart: EasyWAF stops cleanly and exits with a code that systemd's `Restart=on-failure` answers, and the next start swaps the snapshot in before anything opens the database. The page in between waits for the service to come back. Sites are not served for those few seconds, and you sign in afterwards with the snapshot's own accounts.
- **A restore either works or undoes itself.** The database it replaces is kept whole first, and a marker is written before the swap; a start that finds the marker still there knows the restored database never came up, puts the previous one back, and says so on the page. The swap is ordered so a power cut between any two steps loses nothing. The replaced database stays downloadable, one generation back.
- **Export the configuration** as a readable TOML file: policies with the rule sets they hold and the rules they switched off, rules written here in full, exclusions, sites with their upstreams, aliases and ports, certificates, IP entries, published-list choices, country rules and settings. Objects are named, never numbered, and everything is sorted, so two exports of the same configuration differ only in their timestamp and a diff between two shows what changed. A rule from an installed set travels as a reference to the set, since it cannot have been edited; only what is this installation's own travels in full.
- An export leaves out, always, traffic history, the session key, the ACME account key, this host's own management certificate and every piece of state the appliance keeps about itself. **Private keys** and **accounts** are each in only when their own box is ticked, and a file carrying either says so at the top, in its header, and in a confirmation before it downloads.
- **Import a configuration**: an exported file makes this installation match it. What the file has is created or changed, and what only this installation has is removed — except accounts, which are only ever added or updated and never the account running the import, and this appliance's own management certificate. An upload is read strictly and held, and a **preview** lists every addition, change and removal and every reason it cannot go ahead, before anything is written.
- An import refuses what it cannot apply faithfully, by name: a key it does not know (a misspelling is not silently ignored; a file from a newer EasyWAF says to upgrade), a setting that belongs to one host such as the session key, a rule pattern that does not compile or a zone the engine would read as *any*, a site whose policy is not in the file or whose certificate nobody has the key for, a site with nothing to forward to, and a port the management interface already uses.
- An import is applied to a copy of the database and swapped in by the same restart a restore uses, so it gains the same guarantees: a failure changes nothing, a result that will not start is put back, and every listener and cache comes back matching the new configuration. Rule sets are installed from this installation's own channel, verified as always; the preview says when that will be a different version from the one exported. Sessions carry on.
- A **Backup and restore** page in the documentation, covering all of the above.
- Every settings key is classified as travelling or staying local, and a test fails for one that is neither — so a setting added later cannot leak into exports, or silently drop out of them, without somebody deciding.
- Every start records which version the database was last run by, so a snapshot says where it came from and a restore can refuse one from a newer EasyWAF.

### Security
- **rustls 0.23.45** (from 0.23.40), for RUSTSEC-2026-0285: earlier releases accepted TLS 1.3 handshake messages across encryption-level boundaries. One copy of rustls serves the management interface, every site's HTTPS, the upstream client and ACME, so all of them take the fix; the minimum is raised in `Cargo.toml` as well, so nothing can resolve back below it.

- `.gitignore` covers what a run from the source checkout writes beside the database: the database a restore replaced and the one it is swapping in — both whole copies, with every private key and password hash — as well as `backups/` and the country database in `geo/`.

### Changed
- The README and the limitations page no longer list backup and export as missing, and the README no longer lists load balancing, which arrived in 0.13.0.

---

## [0.13.5] — 2026-09-25

### Fixed
- **Times are shown in your own time zone.** The interface printed times as it stores them, in UTC — some labelled, most not — so at 12:51 in Israel the dashboard's latest hour read 09:00, and a Traffic Monitor row, an account's creation, an exclusion or a certificate attempt each read three hours behind the clock beside it. Every page now shows times in the browser's time zone, the dashboard names that zone, and each time keeps its UTC value in a tooltip for matching against logs, which stay in UTC. With scripts off the page shows UTC and says so.
- Clicking an hour on the dashboard still opens exactly that hour in Traffic Monitor, now labelled in the same zone as the bar that was clicked.

---

## [0.13.4] — 2026-09-24

### Fixed
- **A policy could report holding rule sets it had not one rule of.** The Rule Library page applied a selection by inserting the ticked rules and deleting the unticked ones, and never recorded which sets were installed — so a policy's Rule Sets page could say a set was *up to date at v2* while the policy inspected none of those requests, the update check compared a version nobody was running, and rollback offered to put back a version that was not there. Starting up now forgets a holding with no rules behind it. A set whose rules are merely switched off is untouched: off is a decision, and it survives.
- **Unticking a rule in the Rule Library deleted it** instead of switching it off, so the next update of its set inserted it again and it started matching with nobody told. It now switches off, as the other two pages that carry the same picker already did.
- Ticking a set's heading in the Rule Library installs it *as a set* — recorded, verified, and offered an update when the channel publishes a newer version — rather than copying its rules in loose.

- **Four pages offered a viewer a form they could not submit.** Creating a site, a policy, a policy rule or a custom rule each rendered for a viewer and refused on click; they now need an administrator to open, as requesting a certificate already did. Nothing linked to them from a viewer's screen, which is why it went unnoticed.

### Changed
- **The sites list says what a site is getting rather than that a policy exists.** *Protected* meant only that a policy was attached — so a policy switched off, a policy set to detection only, and a policy with no rules switched on all read as protection while a SQL injection went straight through. Each now says which it is, and *Protected* carries the number of rules standing behind the claim.
- The Rule Library is now the same picker as the policy's own pages rather than a second implementation of it, so it gains what that one learned: the set headings that follow their rules, **Basic sets**, and a message naming everything that happened rather than only what was added.

---

## [0.13.3] — 2026-09-23

### Added
- The country database is fetched from its own signed channel, the last of the three to get one: the manifest is verified against the key this installation pins, the database checked against the hash that manifest gives, and it takes effect on the next request rather than at the next restart. *Update now* stops saying there is nothing to fetch, because now there is.
- The country database channel can be pointed elsewhere, beside the other two, and lowers no bar when it is: same signature, same hashes.
- With *applied as it arrives* turned off for the country database, a fetch waits instead — named on the page with what it is and when it was built, counted in the Settings badge, and put in force by one button. What is answering lookups does not change until then.

### Fixed
- Stopping EasyWAF now leaves a database that stands on its own. The process handled no signals, so `systemctl stop`, `systemctl restart` and Ctrl-C all killed it where it stood and SQLite's write-ahead log was never checkpointed — while the documented backup is to stop the service and copy `easywaf.db`. A backup taken that way could be almost empty, with the data sitting in the `-wal` file beside it. SIGTERM and Ctrl-C are now caught, the log checkpointed and the pool closed before exit.

### Changed
- The backup instructions lead with `sqlite3 easywaf.db ".backup"`, which is safe while EasyWAF is running, and say which versions a plain `cp` with the service stopped is safe for.
- README and the limitations page no longer claim less than the product does: roles arrived in 0.8.0, the audit log in 0.9.0, and Traffic Monitor has named the rule that blocked a request since 0.5.5.

---

## [0.13.2] — 2026-09-22

### Added
- The version of a rule set that an update replaced is kept, per policy, and *put back vN* on the policy's Rule Sets page restores those rules exactly and deletes anything the newer version added. One step back — what the last update replaced — leaving alone the two things no version owns: whether a rule is switched on, and any rule cloned from the set.

## [0.13.1] — 2026-09-22

### Added
- **Settings → Updates**: rule sets, published IP lists and the country database in one page, each saying what it holds, when it last arrived and what is waiting to be applied — replacing a panel named after one of the three, and showing the country database, which nothing in the interface reported before.
- The country database now says what it is, when it was built and how long ago, what it covers, where it came from, and whether that path was signature-verified.
- **Update now** for each kind, including rule sets, whose fetch existed with nothing calling it. It says what it found, and is refused — with the way in named — on an installation that has turned checking off.
- **Upload**, for an appliance with no outbound access: a rule set or IP list bundle — the manifest, its signature and the files it names — is checked exactly as a download is, so a bundle whose signature does not verify or whose files do not match their hashes is refused and the mirror is left as it was. A country database can be uploaded too, and is marked as what it is: nobody signs those, so it is checked for being a database and recorded as unverified.
- The country database an update replaced is kept, and can be put back from the page — the only way back there is, since rule sets are overwritten in place.
- Every policy that is behind is listed in one place, with the same apply as its own page, and applying from there returns there.

- A count in the Settings menu of what has arrived and not been applied — rule sets a policy holds at an older version than the mirror offers, and a list bundle fetched on an installation that applies lists by hand. A channel that cannot be reached is not counted: that is a different fact and it appears on the page.
- With IP lists set to apply by hand, a fetched bundle is held and what is serving traffic does not change until it is applied; with rule sets set to apply automatically, every policy holding an updated set is brought up to date on the next check, and each one is logged by name.

### Changed
- The update channels and the switch that governs them moved from Settings → General to Settings → Updates, which now owns them; the three kinds each have their own "apply as it arrives" switch, on for lists and the country database and off for rule sets.

## [0.13.0] — 2026-09-21

### Added
- A site's upstream is now a row rather than a column, so a site can have more than one: requests go round the pool in turn, weighted for backends on unequal hardware. A site with one upstream behaves exactly as before, and every traffic record names the upstream that served it.
- A site is created and edited through the same fields: the Upstream field takes one backend or several, one per line, each with an optional weight after the URL (`http://10.0.0.8:3000 3`) and `off` to park one, with session affinity beside it. On an existing site it arrives filled in with the whole pool, so editing that text is how a backend is added, removed, reweighted or parked — and the message afterwards names what changed.
- Under the Upstream field, a line says what each backend is doing now — in rotation, failing, switched off, or out and when it will be tried again — which is what this node has seen and is not shared between nodes. A site can never be left with nothing to forward to.
- **Session affinity**, per site and off by default: a client stays on the backend that first served it, pinned by a cookie this installation signs rather than by its address, since many clients share one address behind NAT. A client whose backend goes out of rotation is pinned to another rather than refused.
- A backend that stops answering is taken out of the rotation after three failures in a row and let back in by a single request thirty seconds later, and a request that can safely be sent again is retried on another backend rather than failing — so one dead backend of several costs nothing. When every backend is down the answer says so, instead of repeating the message for one unreachable upstream.

### Changed
- Security Policy → IP Lists → All policies now lists every entry in the installation, each with the policy whose list it is on — or *all policies* for the ones that belong to all of them — so an address can be found without opening each policy in turn; the search box matches the policy name too, and a published list that some policies answer for themselves says how many.

## [0.12.3] — 2026-09-19

### Added
- IP lists have a second scope: **All policies**, under Security Policy → IP Lists. An address or a published list set there applies on every policy — the ones that exist and the ones made later — without being copied into any of them, and a policy's own page shows what reaches it from there.
- A policy can still decide a published list for itself, which overrules the every-policy choice, and *Follow all policies* beside the list gives that decision back.
- Country rules have the same second scope: one rule under Security Policy → GeoLocation Rules applies on every policy, old and new, on top of each policy's own — a request refused by either is refused, and the policy pages say what is already in force from there.

## [0.12.2] — 2026-09-19

### Added
- Creating a policy now sets up everything it holds — country rules, IP lists and published lists alongside the rule sets — arranged in tabs, instead of leaving three more pages to visit afterwards.
- A new policy can be started from an existing one, copying its rules, installed sets, exclusions, IP entries, published-list choices and country rules; the two are independent afterwards.
- The tick beside a rule in a policy's rule list now says whether that rule applies: untick one the policy holds to switch it off — it stays in the policy, matches nothing, and stays off through every later update of its set — and tick it again to switch it back on, so one rule of a set can go without the set; delete beside it removes the rule outright, which the set's next install or update undoes.
- A policy's own page carries everything it holds in the same tabs — rules, country rules, IP lists and exclusions — instead of a settings form with links elsewhere; the IP list and exclusion panels there are the same ones those pages show.

### Changed
- Ticking every rule of a set now ticks the set itself, so it is installed as a set and offered an update when a newer version is published, instead of leaving copies that nothing will ever correct; unticking any one of them releases the set again.
- A set's heading follows the rules under it both ways: rules the policy already holds count towards it, so a policy holding all of a set's rules one by one is offered the set itself, and it lets go the moment one rule is unticked — a set the policy holds as a set included, which used to be shown ticked and frozen. Unticking a heading switches its whole set off.

## [0.12.1] — 2026-09-17

### Added
- The GNU GPL v3 licence text is now in the repository and installed by the .deb and .rpm packages, and the licence is stated precisely as GPL-3.0-or-later.

### Changed
- IP lists — your own allow and block lists and the published lists — now belong to a security policy and apply on the sites using it, so the public websites can block Tor exits while an application on its own policy does not; a site with no policy has no IP lists, and upgrading copies every existing entry and list choice into every policy.
- IP lists follow their policy's mode: in DetectionOnly a listed address is served and recorded as would block or would challenge, and with the policy Off the lists do nothing.
- Rule exclusions belong to a policy instead of a site, still narrowable to a path and a client, and are added under Security Policy → Rule Exclusions; the per-site exclusions page redirects there.
- Blocking, allowing and excluding from Traffic Monitor act on the row's site's policy and say how many sites that covers before you confirm.

### Security
- Upgrading moves each rule exclusion to its site's policy, so one made for a site that shares its policy now applies on all of that policy's sites; the start-up log names every exclusion that widened, and every one dropped because its site had no policy.

### Upgrading
- A site with no policy loses the IP lists it had; the start-up log names each one. Attach a policy to keep them.

## [0.12.0] — 2026-09-16

### Added
- Published IP lists — hijacked netblocks, compromised hosts and Tor exit nodes — fetched from the signed channel and refreshed daily, each switched on separately under Security Policy → IP Lists and set to challenge or block; none does anything until switched on, a refused request names the list that refused it, and your own allow list overrules all of them.

### Changed
- The update switch under Settings → Rule Updates now covers the published IP lists as well as rule sets, and a new field there sets where the lists are fetched from.

## [0.11.0] — 2026-09-16

### Added
- Rules now see through the escapes the Core Rule Set assumes have been undone before matching — HTML entities (`&lt;`, `&#60;`, `&#x3c;`), JavaScript escapes (`\x3c`, `\u003c`, octal), CSS escapes (`\3c`) and IIS-style `%u003c` — so an attack hidden behind one of them is caught by the rule written to catch it rather than passing as ordinary text.

### Changed
- Inspection no longer reads each site's policy, rules and exclusions from the database on every request, which makes it about fifteen times faster at 138 rules; a change to a rule, policy or exclusion now takes effect within a second rather than on the very next request.
- Request bodies are no longer read whole before being forwarded: the rules inspect the first 128 KB, set under Settings → Proxy, and the rest streams to the site as it arrives. The 32 MB upload limit is gone, and a 200 MB upload now costs a few MB of memory where a 30 MB one used to take 400 MB.
- The documentation site has the easysys.io and easylog.easysys.io design: a landing page for EasyWAF, with the existing overview moved to its own page and every documentation page themed to match in light and dark.

### Security
- Bytes of a request body past the inspection limit are forwarded without being inspected, so a payload padded past it is not seen. Raise the limit under Settings → Proxy if every site takes only small, structured request bodies.

## [0.10.2] — 2026-09-15

### Security
- A request could get past every rule that needs decoded text by adding one escape that does not decode to UTF-8, such as `%FF`, anywhere in the same field — EasyWAF stopped decoding that field, while the application behind it decoded the rest and received the attack. Affects every release before 0.10.2; upgrade.

## [0.10.1] — 2026-09-15

### Fixed
- Downloads and media streams taking longer than thirty seconds were cut off mid-transfer, after the response had already started with a 200, leaving a truncated file; upstream connections now time out only when they stop moving.

## [0.10.0] — 2026-09-13

### Added
- IP allow and block lists, installation-wide: a blocked address is refused before any rule runs — including on a site with no policy, where the WAF would do nothing — and an allowed one skips the WAF, the country rules and the CAPTCHA alike.
- Block and Allow on every Traffic Monitor row, beside the client address, with a badge instead when it is already on a list.
- Security Policy → IP Lists, to search what has accumulated, see who added each entry and why, and take entries off again.
- Entries are ranges as well as addresses, so a whole CIDR block can be refused with one row.

### Changed
- The site settings page follows the same order as the create-site form, field for field, with the Let's Encrypt request beside the certificate picker instead of in a section at the bottom of the page.

## [0.9.2] — 2026-09-10

### Added
- A documentation site, built with MkDocs from `docs/` in this repository: overview, installation, first run, sites, TLS, policies, traffic, accounts, logging, configuration, troubleshooting, and a current list of what EasyWAF does not do.

### Changed
- Creating a policy starts with nothing selected, and a **Basic sets** button ticks the eight that assume nothing about the application behind the proxy. They used to be ticked on arrival, so every new policy carried them whether or not anyone had decided to.
- Creating a policy with no rules says so on the form and in the message afterwards, rather than reporting that it was created with 0 rules.
- The create-site form asks whether to request a Let's Encrypt certificate before offering the list of existing ones, and says why that list goes inert when it does.
- The create-site form's Let's Encrypt checkbox says it covers the site's aliases as well, which it has done since 0.9.1.

## [0.9.1] — 2026-09-10

### Added
- A site can answer for more than one hostname: aliases share its upstream, policy, ports and headers, so two names for one application no longer means two sites kept in step by hand.
- A certificate requested for a site now covers every hostname it answers for, and renewal re-requests all of them.

## [0.9.0] — 2026-09-09

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
- An `admin` account that 0.4.0 or 0.4.1 seeded keeps its password `admin` through the upgrade. If you never changed it, change it now under **Account → Change Password**.

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
- If you firewalled 8080 to keep the interface private and opened nothing else, open 8443 to the same callers before upgrading: 8080 now only redirects there.

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

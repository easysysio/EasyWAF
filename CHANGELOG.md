# Changelog

All notable changes to EasyWAF are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version bumps and tags are created only after explicit approval.

---

## [Unreleased]

### Fixed
- **Excluding a rule from Traffic Monitor failed with "invalid digit found in
  string".** The exclusion was saved; it was the redirect back that broke, so
  the page which would have confirmed it never rendered.

  The button returns to `/traffic?site=…&blocked=…&hours=24` so the filter you
  were looking at survives. `flash_redirect` then appended its message with a
  `?` unconditionally, producing a second one, so `hours` arrived as
  `24?result=success&msg=…` and axum rejected the request before any handler
  ran.

  The helper existed as **seven identical private copies**, one per route
  module, and every one of them assumed the path had no query string. They are
  now one implementation that picks the separator by looking, with the
  Traffic Monitor URL as a test case.

  If you pressed the button before this fix, the exclusions are there — check
  the policy's Rule Exclusions page rather than adding them again.

### Added
- **A site with no policy attached now says so** — on the dashboard, in the
  sites list, and next to the control that causes it.

  It is the one state in which EasyWAF inspects nothing at all: `WafModule` and
  `GeoIpModule` both return `Pass` outright when `sites.waf_policy_id` is
  `NULL`, so such a site is proxied straight through with no WAF rules and no
  country rules. Requests are still logged, so Traffic Monitor shows them —
  every one allowed — which makes the site look healthy rather than
  uninspected.

  Nothing in the GUI said this. The sites list rendered it as a muted "None",
  which reads as a neutral absence rather than as the only configuration in
  which the product does nothing. It now reads **Not inspected**, the dashboard
  names every active site in that state, and the site settings page explains it
  beside the policy selector.

  Found while re-scoping IP allow/block lists, where the same gap is the reason
  that release moved from 0.13.0 to 0.9.0: rule exclusions cannot close it,
  because they live inside the WAF module and so exist only where a policy
  does.

## [0.7.0] — 2026-09-08

### Added
- **A rule exclusion can name the clients it applies to**, and the usual way to
  create one is now a button on the Traffic Monitor row that showed the block.

  Exclusions were scoped by site and optionally by path. That answers "this
  rule is wrong for this application", but not the case that actually turns up
  most often: the rule is right, and one client trips it — an office range, a
  monitoring probe, a colleague whose password manager sends something that
  looks like an injection. Narrowing by client is the smallest exclusion that
  fixes such a case; the rule keeps protecting the site from everyone else,
  which a site-wide or even a path-wide exclusion does not.

  An address or a CIDR block, parsed by the same code that reads the trusted
  proxy list, so `203.0.113.9`, `203.0.113.0/24`, `::1` and `fd00::/8` all
  work. No block means every client, which is what every existing exclusion
  means and what the engine did before the column existed.

  **From Traffic Monitor**, each rule listed against a request now carries an
  *exclude for this IP* button. The point of showing which rules produced a
  verdict is that the fix should be reachable from there; retyping the site,
  the rule number and the address into another page is where diagnosing a
  false positive gets abandoned. It creates the narrowest exclusion available —
  this rule, this client, every path — and a rule that is *already* excluded
  for that client is marked as such instead of being offered again.

  **Under Security Policy**, a new Rule Exclusions page lists every rule not
  running across the sites using that policy, with the client and path each
  covers and a button to remove it. Exclusions are stored per site, because a
  site is what one is about; they are listed per policy because that is the
  question worth asking afterwards — which of my rules are not actually in
  force, and where. Exclusions that name *every client* or *the whole site* are
  labelled, since those are the widest forms.

## [0.6.12] — 2026-09-08

### Fixed
- **The Traffic Monitor's graph now follows the verdict filter.** It took the
  site and the time window but not the verdict, so choosing *Blocked Only*
  changed the table while the graph above it carried on showing everything —
  two answers to one question on one page.

  The graph also gained a **Detected** series. Without one, filtering to
  *Detected (allowed)* drew those hours green as ordinary traffic, which is the
  opposite of what selecting that filter is asking to see. The three series are
  disjoint and sum to each hour's total, matching the dashboard's verdict
  split.

### Changed
- **A cloned rule is a custom rule, and no longer sits in the set it came
  from.** It used to inherit the origin's set id, which made it a member of
  that set for everything that reads the column: it grouped under the set in
  the rule list rather than under Custom, and it kept pointing at the set even
  after the set was uninstalled — so a policy could show rules belonging to
  something it no longer held.

  `rule_set` was doing two jobs, membership and provenance. Provenance now has
  its own column, so a clone belongs to no set while still recording which set
  and which version it was forked from — the rule editor still says when that
  set has moved on since. Existing clones are moved across by the migration;
  the set id is not lost, it moves to the column that means what it actually
  was.

### Added
- **A policy's custom rules can be copied into another policy** — the panel at
  the top of the policy's rules page.

  Custom rules belong to one policy, because every rule does, and someone who
  has written or cloned a few usually wants them on their other policies.
  Copying is how a set already reaches a policy: installing one writes its
  rules in, and the copies then diverge freely, which is the point of having
  separate policies.

  A rule is skipped when the target already holds one with the same zone and
  pattern. That is exactly when both would match a request and both would add
  their score, so pressing the button twice copies nothing the second time.
  Copies keep their provenance, so a rule that began as a clone still says what
  it was forked from, and stay custom in the target — no update will overwrite
  them.

- **`scripts/modsec2easywaf.py` converts ModSecurity rules into an EasyWAF rule
  set** — and refuses, loudly and itemised, the ones it cannot convert
  faithfully.

  Against OWASP CRS 4.7.0's 585 request rules it converts 119 and refuses 313
  (the rest are `SecAction`/marker directives with no id). The refusals are the
  honest part: 158 are CRS's own anomaly-scoring comparisons (`@lt`, `@eq`,
  `@ge`), which EasyWAF does not need because it scores in the engine; 72 need
  transformations EasyWAF does not apply, such as `t:htmlEntityDecode` and
  `t:jsDecode`; 57 are chained rules, where several conditions must all hold
  and EasyWAF has one pattern per rule; the remainder are response-phase rules,
  `@detectSQLi`/`@detectXSS` (libinjection — a parser, not a pattern), and one
  possessive quantifier Rust's regex cannot compile.

  A rule that cannot be represented is left out rather than approximated,
  because a rule that looks present and is bypassable is worse than one that is
  missing: the missing rule shows up in a coverage report, the bypassable one
  shows up only to whoever finds the bypass.

  Of the 119 converted, 97 patterns are byte-identical to CRS. Eleven differ
  only by a leading `(?i)` folded in from `t:lowercase`, five by escaping
  literal braces that PCRE accepts and Rust's regex rejects, and six are built
  from `@pm` phrase lists. Nothing else differs.

  ModSecurity can target several variables at once and exclude one of them;
  EasyWAF's zone is a single choice, so such a rule can only be converted by
  widening what it inspects. That creates false positives rather than holes —
  CRS excludes things like `REQUEST_HEADERS:Referer` precisely because they
  cause them — so widened rules are left out unless `--include-widened` is
  given, and are marked in the output when they are.

  CRS ids are offset (`--id-base`, default 2000000) because CRS numbering
  collides with EasyWAF's own bundled sets, which use the same OWASP numbers
  under a unique index. Scores carry CRS severities across unchanged, so the
  policy's Score Threshold should be set to 5 to reproduce CRS blocking
  behaviour; EasyWAF's default of 10 needs two critical hits.

  Rules that only exist to feed a later rule are refused too. CRS 921170 is
  `@rx .` against every parameter name with `pass,nolog,setvar` — it counts
  parameters, and a different rule reads the count. Converted as a detection it
  scores on every request carrying a parameter at all. A pattern that matches
  ordinary traffic is refused as a backstop regardless of what its actions
  claimed, so a misread action list cannot produce a rule that scores
  everything.

  `--self-test` checks the refusals and both rewrites without needing a copy of
  CRS.

## [0.6.11] — 2026-09-08

### Fixed
- **DetectionOnly now reports what it detected.** It previously reported
  nothing at all, which left the mode close to useless.

  The WAF did the work: it matched rules, summed the score, decided the request
  would have been blocked, and raised an alert saying so. The proxy then threw
  that away and wrote a traffic record identical to clean traffic — no score,
  no rules, no reason. `Alert` had carried a comment since it was written
  saying it would be stored "once the alerting pipeline is wired up", and it
  never was. In DetectionOnly every request is allowed, so the Traffic
  Monitor's blocked/allowed filter could not find an attack either, and the
  dashboard's Blocked figure stayed at zero however hard a site was probed.

  Traffic records now carry what the WAF would have done: **would block**,
  **would challenge**, or **detected** — the last meaning rules matched and the
  request was allowed on its merits. The Traffic Monitor shows each as its own
  verdict, colours a would-block row, and gains two filters for them. The
  dashboard counts detections separately from passes, gives them their own
  slice of the verdict chart, and says plainly when requests were served that
  an enforcing policy would have refused.

- **A request that matched rules but stayed under the threshold left no trace,
  in every mode** — not just DetectionOnly. The WAF returned early and dropped
  the hits and the score on the floor. That is where reconnaissance lives, and
  where the request scoring 9 against a threshold of 10 lives: a policy could
  sit one point away from blocking real traffic with nothing recorded to show
  it. Those requests are now logged as **detected**, with their score and the
  rules that matched, and remain allowed exactly as before.

  Nothing about which requests are blocked changes. This is only about what is
  recorded on the ones that are not.

- **`assets::tera()` now returns a Tera instance that can actually render.**
  The `version()` function the shared layout calls was registered by `main.rs`
  afterwards, so the instance the function handed back was incomplete, and any
  other caller got templates that failed at render time — on a page, not at
  startup. It is registered where the instance is built.

### Changed
- **The rule-signing key is compiled into the binary**, so an installation can
  no longer be missing the thing it verifies updates against.

  It was a loose file, read from `rules/key.gpg` relative to the working
  directory, with no fallback. That made the trust anchor something a build or
  a package could simply omit — not a theoretical worry: 0.6.0 and 0.6.1
  shipped without it and could not apply a single rule update. A missing key is
  now a compile error, which is the right end of the process to find it.

  Nothing about *what* is trusted changes. The key still arrives with the
  binary, reviewed by whoever cut the release, rather than over the same
  connection as the thing it vouches for — fetching it from the channel at run
  time would verify the channel against itself.

  A key placed at `rules/key.gpg` still wins, so an operator pointing EasyWAF
  at a channel of their own can sign it with their own key without rebuilding.
  The packages no longer install that file, so its presence is now always
  somebody's decision — and using it is logged every time, because a
  substituted trust anchor is exactly the thing that should not be silent.

  Consequently **`rules/` is no longer required at run time.** What the
  appliance enforces has been read from the local mirror since 0.6.9; the
  directory now holds only `SOURCE` and the sets that seed that
  mirror on a first run with no network. Deleting it on a working installation
  no longer breaks rule updates. The packages still ship the seed, and still
  recreate the directory on upgrade.

## [0.6.10] — 2026-09-07

### Added
- **A site can exclude a rule** — Sites → *(a site)* → Rule Exclusions.

  A policy is shared on purpose: several sites use one, and a rule update
  reaches all of them at once. That left nowhere to say "this rule is wrong for
  this one site". The answers available were to weaken the rule for every site
  using the policy, or to give the site a policy of its own and lose the shared
  updates — both worse than the false positive being answered. This is the
  third answer.

  An exclusion names one rule, optionally confines it to a path prefix, and
  records why. An excluded rule does not run on that site: it adds no score and
  cannot block. Everywhere else the rule is untouched.

  A prefix rather than a pattern, because an exclusion turns a rule *off* — a
  mistake in it is a hole, and a prefix is something you can read and be sure
  about. Leaving it empty covers the whole site.

  Rules from a set are remembered by catalogue number, not by database row.
  Removing a set and installing it again deletes every row and writes new ones
  with new ids, so an exclusion keyed on the row would have stopped applying at
  the moment the rule came back — silently, and only in production. Custom
  rules have no catalogue number and are keyed on the row, which cascades: the
  rule goes, the exclusion goes with it.

  Because a rule that is enabled and yet silent on one host is the sort of
  thing found *during* an incident, the rule editor now says which sites
  exclude it and under what path, and the site settings page says how many
  exclusions the site has next to the policy it shares.

  An exclusion naming a rule the policy no longer holds is shown as unknown and
  kept, not deleted. The set can be reinstalled or the policy changed back, and
  one that quietly removed itself in between would return as a false positive
  with nothing left to explain it.

- **`scripts/prune-debris.sh`** finds and removes rule rows left behind by two
  things that happened before 0.6.6: catalogue numbers renumbered by an early
  commit, whose old rows stayed enabled beside their replacements, and copies
  written by the old "Seed defaults" button, removed in 0.6.6 without its rows
  being removed with it. Both mean two rules match one request and both add
  their score — how a 4-point request came to score 17.

  The debris is derived from the database and the installed rule files, not
  from a list of ids: a list taken from one snapshot stops being true the
  moment a set is reinstalled. Clones are never touched, since a clone is
  deliberate. The script shows what it found, backs the database up, and
  deletes nothing until you type yes.

### Changed
- **The Create Policy page asks for the policy first, and for rule sets and
  rules as one question instead of two.**

  It used to open with a list of rule sets, put the policy's own settings —
  name, mode, thresholds — below that, and then list every rule again
  underneath, so a set could be chosen twice through two different controls
  that did not know about each other. Naming the thing being created is the
  first step, so it is now the first panel.

  Below it, one list. Ticking a heading takes the whole set: it is installed as
  a set, recorded, and offered an update when the channel publishes a newer
  version. Opening a heading and ticking rules individually takes copies, which
  are never updated. Both were always true; the page previously expressed the
  first through a separate panel and the second through this one, which is why
  it read as two questions.

  A heading is now an independent choice rather than a summary of the boxes
  under it, so a set taken whole no longer also sends its rules as individual
  copies — which would have installed the same rules twice, by two mechanisms,
  with only one of them updatable. While a set is taken whole its rule boxes
  are disabled rather than hidden, since the rules are still worth reading.

  Basic sets start ticked. Optional sets are listed and labelled, and are no
  longer only reachable after the policy exists.

- **The site form takes a list of ports per protocol** — "80, 8080" — instead
  of a single port plus a separate "additional ports" field beside it.

  0.6.5 added extra ports by bolting a second field onto each of the existing
  single-port ones, which made an implementation detail into something the form
  asked about: there is a primary port because the HTTP-to-HTTPS redirect has
  to name one, and that is a storage concern, not a question for whoever is
  filling in the form. One field per protocol is what someone means when they
  say a site answers on 80 and 8080.

  The first port listed is still the primary, and is still what a redirect
  points at. Existing sites read back as one field each, primary first, and
  nothing about how ports are stored or bound has changed.

  A port repeated within one field collapses; the same port in **both** fields
  is refused, because that is a contradiction rather than a repetition. Ports
  are also now checked across both lists at once, which the previous shape
  could not do — a port named as both the primary and an extra was two fields
  agreeing with each other.

## [0.6.9] — 2026-09-07

**Rule sets live in one directory, and installing one no longer needs the
network.**

The channel is mirrored to disk on the same six-hourly schedule as the update
check, and installing or updating a set reads from there — which matters
because a WAF is often on a segment with no outbound access, and that is
exactly where the one action worth taking should not require a round trip.

**The mirror is a cache, not a trust boundary.** The manifest, its signature
and the sets are stored together, and both the signature and the per-set hash
are checked when a set is installed, exactly as they would be over the network.
Editing a mirrored file does not install anything; it makes the install refuse.

And there is now **one** directory anything reads rule sets from. The package
seeds it on first run, the channel refreshes it, and Import, the Rule Library,
policy creation and the pre-0.6.0 adoption all read it. Before this there were
two, each authoritative for different callers.

Also: rule sets can be chosen while creating a policy — including the optional
ones, which the create page could never show — and deleting a policy a site is
using is refused rather than silently removing that site's protection.

**Upgrading is enough.** The mirror appears on the first start and fills on the
first sync.

### Added
- **There is now one directory rule sets are read from.** The package seeds it,
  the channel refreshes it, and every reader looks there: Import, the Rule
  Library, policy creation, the pre-0.6.0 adoption, and installing a set.

  Before this there were two — the packaged `rules/` and the runtime mirror —
  each authoritative for different callers, with a rule per caller about which
  to use. Rules like that are learned by being caught out by them, and one of
  them was subtle enough to be a bug in the first draft of the mirror: pointing
  Import at the mirror would have installed WordPress and Apache onto every
  policy, because Import installs every set file in the directory it reads.

  What makes one directory safe is that **Import now filters by tier**, using
  the manifest that sits beside the sets. The packaged bundle carries one for
  the first time, written by `scripts/fetch-rules.sh` and filtered to what it
  bundled; before, the bundle had no manifest, which is exactly why Import could
  only mean "every file present".

  `key.gpg` stays in the package. The trust anchor must not live where the sync
  can write.

- **The rule channel is mirrored to disk, and installs read from the mirror.**
  Every set the channel publishes is copied locally on the same six-hourly
  schedule as the update check. Installing or updating a set then reads from
  disk, so it works with the channel unreachable — which for a WAF is the
  ordinary case, not the exception.

  **The mirror is a cache, not a trust boundary.** The manifest, its signature
  and the sets are stored together, and the signature and per-set hash are
  checked *when a set is installed*, exactly as they would be over the network.
  Verifying at download and trusting the disk afterwards would make that
  directory a way to install rules — and on a WAF, installing rules is how you
  switch protection off. Editing a mirrored file does not install anything; it
  makes the install refuse.

  It lives beside the database, never in `rules/`. That directory is shipped by
  the packages, so a process writing there would have every upgrade either
  clobber the mirror or leave dpkg asking about modified files.

  A set the mirror does not have — published since the last sync — is still
  fetched over the network. A missing or incomplete mirror falls through
  rather than failing.

- **Rule sets can be chosen while creating a policy.** The Create Policy page
  listed rules from the `rules/` directory on disk, and optional sets are never
  bundled there — so WordPress and Apache could not appear at all, and the only
  way to get them was to create the policy and then go somewhere else. Choosing
  what a policy contains is exactly when someone wants them.

  The sets come from the channel manifest, basic ones pre-ticked. Each is
  installed after the policy exists, through the same verified path the Rule
  Sets page uses — signature before anything is read, hash before anything is
  written. A set that fails to install is named and the policy still exists,
  because discarding it would throw away the sets that did install.

### Fixed
- **A rule taken singly from the Rule Library recorded no set.** It had an
  `external_id` and no `rule_set`, which is the exact signature of a leftover
  from a renumbering — so hand-picked rules were indistinguishable from real
  debris to anything looking for it.

  The set is now recorded as provenance. It deliberately does **not** create a
  `policy_rule_sets` row: a policy that took three rules out of eighteen chose
  three, and an update must not arrive and install the other fifteen.

- **Deleting a policy that sites were using silently removed their
  protection.** `sites.waf_policy_id` is `ON DELETE SET NULL`, so the delete
  succeeded and every site holding that policy simply stopped being inspected.
  Nothing failed, nothing returned an error, no page looked any different — the
  WAF was just gone.

  That is the worst shape a mistake can take here, because having no protection
  is indistinguishable from having protection that nothing has attacked yet.

  It is now refused while any site holds it, naming them, the way deleting a
  certificate in use has been refused since 0.4.3. Deleting a policy nothing
  uses is unchanged, and deleting one that does not exist now says so instead
  of reporting success.

## [0.6.8] — 2026-09-07

### Fixed
- **The Rule Editor filed correctly-installed rules under "Custom / Manual".**
  Its categories were built from the `.rules.toml` files on disk, which are a
  **build-time snapshot** — `scripts/fetch-rules.sh` writes them when EasyWAF is
  built, and nothing writes them again. Applying an update from the channel
  writes to the database and never touches them, so the moment a set is updated
  the snapshot is behind, and a rule added in the newer version was not in it.
  The rule enforced correctly; only its group was wrong.

  Grouping now comes from the set each rule records, which the database holds as
  of the last install or update. Group names come from `policy_rule_sets`, and
  the order from the lowest rule id in each group — so the familiar 913 → 942
  band order survives even with no files present at all.

  The files are still consulted, but only as a fallback for a rule with no set
  recorded: an installation upgraded from before 0.6.0 whose policy the 0.6.4
  adoption declined to claim. Those keep the grouping they had rather than
  collapsing into Custom.

## [0.6.7] — 2026-09-07

### Fixed
- **The Rule Editor's group headers counted rows, not rules.** A rule is a row
  per policy, so two policies holding one set produce two rows for every rule in
  it — and the header read "36 rules" for a set of 18. It now says *"36 rows
  across 2 policies"* when more than one is in play, and is unchanged for the
  ordinary single-policy case.

  Nothing about the rules was wrong, only the number describing them. Each
  policy's copy is genuinely independent: its own row, its own enabled state,
  its own edits — disabling a rule in one policy leaves the other untouched,
  which is the point of policies. The Policy column is what tells the rows
  apart.

## [0.6.6] — 2026-09-07

**"Seed defaults" was quietly halving your block threshold.**

The button inserted 22 rules written directly into the Rust source — a second
copy of protections the rule sets already carry. It did not merely drift, which
would have been the usual cost of a second copy. A seeded rule and its set
counterpart **both matched the same request, and both added their score**, so a
request scoring 8 against a threshold of 10 — which should pass — scored 16 and
was blocked. Every rule present in both halved the threshold for its pattern.

**Upgrading is enough to stop it getting worse**, but the duplicates already in
your database are not removed: a custom rule is yours, and deleting one because
it resembles a shipped rule is not a decision to make on your behalf. The Rule
Editor now lists them so you can.

### Removed
- **The "Seed defaults" button and the hardcoded rules behind it.** Rule sets
  are how a policy gets rules: import them, or install them from the channel,
  where they carry an id, a version, and a way to be corrected later. The seeded
  list had none of that and could never be updated.

### Added
- **The Rule Editor warns about custom rules that duplicate an installed one**,
  matched on the pattern rather than the name — the names had drifted apart
  while the patterns stayed identical, which is exactly how this went unnoticed.

  Each is labelled. **custom** is most likely seeded and safe to delete, since
  the set version stays and is the one that receives updates. **clone** is a rule
  you made whose pattern is still identical to its original — either change it,
  or disable the rule it came from so the clone replaces rather than doubles it.

## [0.6.5] — 2026-09-07

**A site can be served on as many ports as you like, and a rule you save stops
disappearing.**

A site had exactly two ports — one plain, one optional HTTPS — and
`server_name` is `UNIQUE`, so adding the same hostname twice was not a way
around it. Site settings now take additional HTTP and HTTPS ports.

The rule list buckets rules by the set they came from, and a clone has none by
design, so it left the category its original sat in and appeared in *Custom /
Manual* at the bottom — collapsed, like every group, with no message confirming
the save. Saving now says what it saved and opens the page on that rule.

**Upgrading is enough.** A migration adds the table for the extra ports; every
site keeps the ports it had.

### Added
- **A site can answer on more than two ports.** It had exactly two: a required
  plain-HTTP port and an optional HTTPS one, and `server_name` is `UNIQUE` so
  the same hostname could not be added twice to work around it. Site settings
  now take **Additional HTTP Ports** and **Additional HTTPS Ports**, comma
  separated.

  Every extra port behaves exactly like the primary: same upstream, same
  policy, same certificate. Nothing about routing changed — `lookup_site`
  matches on `server_name` alone and never looked at the port, so an extra
  listener reaches the same site by the same path. The primary pair stays
  primary because the HTTP-to-HTTPS redirect has to name one port, so one of
  them has to be the answer.

  A port added binds immediately, as the primary always did. A port **removed**
  stops being served but its listener stays bound until a restart — a bound
  socket cannot be handed back mid-process — and the field says so.

  An extra HTTPS port is not bound unless the site has a certificate, for the
  same reason the primary is not: binding with nothing to present fails every
  handshake, which reads as a working configuration. Ports that clash with the
  site's own primary, with the management interface, or with each other are
  refused with the reason, and refused before anything is written.

### Fixed
- **A rule you had just saved appeared to vanish.** Saving from the rule editor
  redirected to the rule list with no message, and the list has no alert markup
  to show one — so there was no confirmation that anything had happened.

  Worse for a **clone**. The list buckets rules into category panels derived
  from `external_id`, and a clone deliberately has none, so it leaves the
  category its original sits in and lands in *Custom / Manual* — rendered last,
  and collapsed like every other group. Clone a rule, change it, save, and you
  were returned to a page where it was nowhere to be seen.

  Saving now says what it saved, and opens the page on that rule: its group is
  expanded, the row scrolled to and briefly highlighted. Nothing about where
  clones are filed has changed — the list simply takes you to it.

## [0.6.4] — 2026-09-06

**Policies that predate 0.6.0 now claim the rule sets they already hold.**

0.6.3 shipped with this as a known gap. Migration 015 added the tracking for
which set a rule came from and backfilled none of it, so an installation
upgraded from 0.5.x had rules but no record of their origin — and was therefore
**never offered a rule update**, because the check compares against sets a
policy is recorded as holding. The Rule Sets page offered to install sets whose
rules were already there, and had no Remove button because it believed nothing
was installed. The whole 0.6.0 mechanism was inert on exactly the installations
that had been running longest.

**Upgrading is enough** — the adoption runs at startup and reports what it did.

### Added
- **Rule sets imported before 0.6.0 are adopted automatically**, and
  deliberately only when it is safe to do so. A set is claimed **only if the
  policy holds all of it, unchanged**:

  - *All of it*, because the rule catalogue lets an operator take individual
    rules. A policy holding 5 of 18 chose 5, and claiming the set would let the
    next update install the other 13 and change what is enforced.
  - *Unchanged*, because imported rules were editable before 0.6.0. An edited
    rule may be someone's deliberate correction, and claiming it would let an
    update overwrite that edit silently — the exact drift this design exists to
    prevent.

  Anything else is left alone and logged, naming the policy and the set. It can
  still be adopted from the Rule Sets page with **Install**, which is an
  explicit act with a confirmation on it. The migration never makes that
  decision for you.

  It runs on every start rather than once behind a flag: claimed rules no longer
  match, so it is naturally idempotent, and an installation put right later
  heals on its next restart instead of having missed its one chance.

## [0.6.3] — 2026-09-06

**Five fixes, all found by using 0.6.2 rather than by reading it.**

The one to upgrade for: **uploading a certificate under a name that already
existed silently detached it from every site using it**, because the row was
replaced rather than updated and `sites.cert_id` is `ON DELETE SET NULL`. That
is the manual-renewal path — what you do when a purchased certificate is about
to expire, which is the worst possible moment for a site to quietly stop
serving HTTPS. The upload also never rebuilt the SNI map, so a replacement was
not served until a restart.

Certificate requests no longer fail on a slow CA: the poll gave up after 30
seconds, and Let's Encrypt under load takes longer. And when one does fail, the
CA's own explanation is reported instead of a guess — a timeout used to claim
the CA had "not accepted the answer", which a timeout cannot know.

The **Rule Sets** page added in 0.6.1 is now reachable from the Policy Manager.
It previously had one durable entry point buried inside a policy's rules page.

**Upgrading is enough.**

### Known gap

An installation upgraded from 0.5.x or earlier has rules but no record of which
*sets* they came from — migration 015 added the tracking without backfilling
it. Such a policy shows every set as installable and is never offered an
update. Pressing **Install** once per set adopts the rules already there
(no duplicates, disabled rules stay disabled) and puts updates back in play.
A migration to do this automatically has not been written yet.

### Fixed
- **The Rule Sets page was almost unreachable.** It had two entry points: a
  button on a policy's rules page, and a link on the Policy Manager that
  appeared *only while an update was pending*. So the way to find the page was
  to already have an update waiting for you, and the way to get an update
  offered is to have used the page. The Policy Manager now links to it from
  every policy row, next to Manage Rules.

- **Uploading a certificate under an existing name detached it from every site
  using it.** The upload used `INSERT OR REPLACE`, which deletes the
  conflicting row and inserts a new one with a new id. `sites.cert_id` is
  `ON DELETE SET NULL`, so the site's certificate was silently cleared — and
  the only symptom was HTTPS quietly not being served after the next restart,
  long after the upload had reported success.

  This is the manual-renewal path: exactly what someone does when a purchased
  certificate is about to expire. It now updates the row in place, keeping its
  id, so sites stay attached. (Requesting one over ACME was always correct —
  it already upserted on the name.)

  **The upload also never rebuilt the SNI map.** A replaced certificate went on
  being served for the life of the process. Uploading now reloads, so the new
  certificate is served immediately — verified by watching the served expiry
  date change without a restart.

  **And an upload over an ACME-managed name now stops automatic renewal**,
  saying so. That was already the effect, by accident: `INSERT OR REPLACE`
  dropped `acme_domain` because the column was not listed. Keeping the row
  would have preserved it and let the renewal task overwrite the upload weeks
  later, so it is now cleared deliberately.

- **A slow certificate authority was reported as a failed validation.** The
  ACME poll used `instant-acme`'s default retry policy, which **gives up after
  30 seconds**. Let's Encrypt validates from several network vantage points and
  under load takes longer than that, so an ordinary slow validation was
  reported as an error — and the order frequently completed moments after
  EasyWAF had stopped looking. The budget is now 120 seconds, for the
  certificate as well as the validation.

- **The CA's own explanation is now reported.** Let's Encrypt records a precise
  reason on the failed challenge — the address it connected to and what it got
  back — and EasyWAF discarded all of it and substituted a guess. The
  authorization is now re-read after a failure and whatever the CA said is put
  in front of anything EasyWAF infers.

  This is the difference between "timed out" and *"Fetching
  http://name/.well-known/acme-challenge/…: Timeout during connect"* naming an
  address you did not expect — which is how an AAAA record pointing somewhere
  else is diagnosed in one step instead of several.

- **And the message blamed the wrong thing.** A timeout said the CA "did not
  accept the answer", which a timeout cannot know: an order the CA has refused
  reaches a settled state, while a timeout is the absence of a decision. The
  two now read differently, and the timeout says to try again — because if the
  authorization completed in the meantime, the retry finishes immediately.

  This one is worth naming as a lesson. The diagnosis added in 0.6.1 was meant
  to replace a bare "timeout" with a cause; it replaced it with a **confident
  and wrong** cause, which sent someone to check DNS on a host whose DNS was
  fine. A diagnosis that guesses is worse than one that says it does not know.

## [0.6.2] — 2026-09-06

**Rule set updates work on a package install again, and the binary is finally
self-contained.**

`rules/key.gpg` — the key every rule update is verified against — was added in
0.6.0 and never listed as a package asset. A `.deb` or `.rpm` installation
therefore had no key, and refused every update with "No signing key at
rules/key.gpg". The Rule Sets page listed and checked normally, so the fault
only appeared at the moment of installing something. **Container images were
never affected.**

**Upgrade if you installed from the package repositories** and want rule
updates. Nothing to do by hand: the key ships with this build.

Templates and static assets are now compiled into the binary, so only `rules/`
and `config.toml` are read from the working directory. A wrong working
directory used to produce a panic or a GUI with no stylesheet rather than a
clear failure at startup.

### Changed
- **Templates and static assets are compiled into the binary.** EasyWAF is
  meant to be one executable, and it also needed `templates/` and `static/`
  beside it in the right working directory. Getting that wrong did not fail at
  startup — it failed on the first page load, as a panic or a GUI with no
  stylesheet.

  Only `rules/` and `config.toml` are read from the working directory now.
  Rule sets stay on disk deliberately: they are data an operator can read, a
  build refreshes them from the published channel, and `rules/key.gpg` — the
  key every update is checked against — belongs somewhere it can be inspected.

  A **debug** build still reads both from disk, so editing a template needs a
  restart rather than a rebuild. Release builds embed them.

  The packages no longer ship copies. That would have been worse than
  redundant: editing an installed template would have had no effect and given
  no error.

### Fixed
- **`rules/key.gpg` was missing from the .deb and .rpm.** It was added in 0.6.0
  and never listed as a package asset, so an installation from the package
  repositories had no key to verify against and **every rule set update was
  refused** — "No signing key at rules/key.gpg". The container image was
  unaffected; it copies the whole directory.

  This means 0.6.0 and 0.6.1 packages cannot apply rule updates. Upgrading to a
  build with this fix is enough; nothing needs to be done by hand.

## [0.6.1] — 2026-09-06

**Two faults found by using 0.6.0 in production, and the page that finishes
what it started.**

A certificate request could sit and then fail with nothing but a timeout.
The cause was that **port 80 was bound only when some site happened to use
it** — HTTP-01 validation always arrives there, so a certificate could be
requested for a name nothing on the host would ever answer for. Port 80 is now
bound always, and a validation that does fail says which of three unrelated
things went wrong instead of saying "timeout".

**Upgrading is enough**, and it is worth doing if you use Let's Encrypt.
Nothing to configure: port 80 is bound on start. If something else on the host
already holds it, EasyWAF says so at startup and carries on serving everything
else.

0.6.0 could update a rule set but not install one, so `tier = "optional"` —
sets published without being bundled — had nothing that could act on it. Each
policy now has a **Rule Sets** page listing everything the channel publishes,
where a set can be installed, updated, reinstalled or removed. Installing goes
through the same signature and hash checks as an update.

### Added
- **A Rule Sets page: browse everything the channel publishes, and install
  it.** Each policy gets one, listing every set on the channel with what that
  policy holds of it — install a set it does not have, update one that is
  behind, or reinstall one at the same version.

  **This is what makes `tier = "optional"` mean anything.** Sets that are
  published but not bundled — the WordPress case the tier was designed for —
  had no way to be installed at all: `available()` reports only sets a policy
  already holds, because an update to something nobody installed is not news,
  and that same rule made a set you had never installed impossible to find.
  Adding rules in bulk otherwise meant putting a `.rules.toml` on the appliance
  by hand and pressing Import.

  Installing goes through exactly the path an update does — signature checked
  before the manifest is read, each set checked against the SHA-256 that signed
  manifest gives for it — so nothing is trusted more for being new.

  A set the channel has **stopped** publishing is still listed, marked *not in
  the channel*, because its rules are still installed and still refusing
  traffic. Hiding it would make rules that are enforcing invisible.

  **A set can also be removed.** Its rules are deleted and the policy stops
  holding it, so it appears as installable again. Two things survive: rules you
  cloned from it, because a clone is your own rule that happens to record where
  it came from, and their provenance — reinstall the set later and they resume
  telling you when the original has moved on. Rules you had disabled go with
  the set; disabling one is a decision about a set you are keeping.

  The message says how many rules went and how many of yours were kept.
  "Removed" alone would leave you wondering whether your custom rules went too.

  The update notice on the Policy Manager now links here rather than applying
  in place. Installing, updating and seeing what a policy holds were three
  different places; the notice was an action that existed only on whichever
  page happened to spot it.

### Changed
- **Port 80 is now bound whether or not a site asks for it.** HTTP-01
  validation always arrives there and cannot be pointed elsewhere, so binding
  only the ports sites happened to declare meant a certificate could be
  requested for a name nothing on the host would ever answer for. The CA's
  connection was refused by the operating system before EasyWAF saw it, and the
  only symptom was a timeout.

  The listener adds an ACME responder, not a new way in: a request to port 80
  for a hostname no site claims is answered exactly as on any other port — 404,
  or the maintenance page for a site that is switched off.

  **A bind failure is not fatal.** Something else may already hold port 80, or
  the process may lack `CAP_NET_BIND_SERVICE`. Sites on other ports carry on,
  and the error says what stops working — issuance and renewal — because that
  consequence otherwise shows up much later and looks like a certificate fault
  rather than a bind one.

  The GUI no longer warns that a site not on port 80 cannot be validated. It
  was true, and is not any more.

- **`proxy.http_port` and `proxy.acme_webroot` are accepted but ignored**, with
  a warning at startup naming each. Neither had been read for some time:
  a site is served on its own Listen Port, and ACME challenges are answered
  from memory in the proxy with no directory involved. `acme_webroot` in
  particular is the setting someone reaches for when a certificate request
  fails, and it did nothing.

### Fixed
- **A certificate request that timed out now says what timed out.** HTTP-01
  validation failing produced `instant-acme`'s bare timeout, which sends people
  to check DNS — usually not the cause.

  EasyWAF knows two things the message never used: whether it served the
  challenge token, and whether its own port 80 listener actually came up.

  The three cases now read differently — the listener never bound, it is up but
  was never asked, and the token was served and refused anyway. They have
  unrelated causes and used to share one word.

## [0.6.0] — 2026-09-06

**EasyWAF can now be told a rule set has been corrected, and apply it.** Until
this release, fixing a rule meant shipping a migration that rewrote patterns in
your database by hand — which is how one rule sat corrected in the repository
and broken in every installation for four releases.

Rule sets are now versioned and published to a signed channel. EasyWAF checks
it, the Policy Manager shows which policies are behind, and applying is a
button someone presses. **Nothing is ever applied on its own**: a bad rule
applied automatically is an outage across every site using that policy, and
0.5.4 is the evidence that a bad rule blocks real traffic.

Applying keeps the decisions you made about a set. A rule you disabled because
it blocked your traffic stays disabled through the update; rules you cloned are
untouched. Nothing reaches the database until the manifest's signature and the
set's hash both check out.

**Upgrading is enough.** A migration adds the version tracking; policies keep
the rules they hold and are simply told when a newer set exists.

The channel is live at `repo.easysys.io/easywaf/rules`, signed with the same
key that signs the EasySYS package repositories — fingerprint
`82A1 264F 11C2 F278 61CF  A36E D700 3226 8BEE 7767`. That key ships with
EasyWAF as `rules/key.gpg` and is what every update is checked against, so
there is no second key to distribute and nothing to trust on first use.

Also in this release: a fix for certificate requests that reported neither
success nor failure, a new site being able to request its certificate while
being created, and Settings organised into tabs.

### Added
- **EasyWAF notices when a newer rule set is published.** It fetches the
  channel manifest at startup and every six hours, and the Policy Manager shows
  what is out of date — per policy, because a set is installed into a policy:
  "SQLi 3 is available; this policy has 2", while another policy may already be
  current.

  **Nothing is applied automatically.** An auto-applied bad rule is an outage
  across every site using that policy, and 0.5.4 is the evidence that a bad rule
  blocks real traffic.

  **It is quiet when it cannot reach the channel.** A WAF is often on a network
  with no outbound access, so a failure is stored and shown on the page rather
  than logged every six hours — a proxy that fills its log with a repository it
  cannot reach teaches its operator to ignore the log. The last manifest is
  cached, so the notice still works offline, and the check can be turned off.

- **An update can be applied, and nothing is trusted on the way in.** The
  Policy Manager's update notice now carries a button that fetches the set and
  installs it into that policy.

  **The order is the security property.** The manifest is fetched and its
  OpenPGP signature verified *before* anything is read from it; the set file is
  then checked against the sha256 in that verified manifest; only if both hold
  does a single rule reach the database. A channel that serves a modified set
  under a valid manifest is refused by the hash, and one that serves a modified
  manifest is refused by the signature. Verification is done in-process with
  [`pgp`](https://crates.io/crates/pgp) — pure Rust, so it holds on an
  installation with no `gpg` binary, which a container generally is.

  **`rules/key.gpg` is the trust anchor and it ships with EasyWAF.** It is a
  file in the repository rather than something fetched alongside the update,
  because a key taken from the same server that serves what it signs proves
  only that the server is self-consistent. `scripts/fetch-rules.sh` now pins it
  the same way: it verifies against that file alone rather than the build
  host's keyring, so a signature from any other key the builder happens to
  trust is still a failure. On a first run against a new channel it takes the
  key and prints the fingerprint to be confirmed once, by a person.

  **Applying preserves the decisions you made about the set.** Rules are
  overwritten in place, keeping each rule's `enabled` state and its place in the
  policy — a rule you disabled because it blocked your traffic stays disabled
  through the update, which is the whole reason disabling it was worth doing.
  Clones are untouched. A rule dropped from the set is left alone rather than
  deleted, since removing something that is currently enforcing is not a
  decision an update should make silently.

- **A new site can request its certificate on the way in.** The create form
  offers "Request a Let's Encrypt certificate", so a site that needs one no
  longer has to be saved, found again and edited before it can ask.

  **The site is created either way.** Issuing talks to a CA over the network
  and fails for reasons that have nothing to do with what was typed — DNS not
  pointing here yet, port 80 closed, a rate limit — and losing the site to that
  would mean filling the form in again to retry something the site's own page
  already has a button for. A failure says the site was created and what went
  wrong.

  The form does not offer the checkbox when no ACME contact is set; it says
  what to set instead, because a checkbox whose only possible outcome is an
  error is worse than no checkbox. Ticking it disables the certificate picker,
  since the issued certificate is what gets assigned.

### Fixed
- **Requesting a certificate said nothing, either way.** The site page's
  Request Certificate button redirected back to the site page with a message
  attached — and that page never read it or displayed it. The same was true of
  the certificate upload form: a rejected key pair sent you back to a blank
  form with no explanation.

  So a certificate request that the CA refused was indistinguishable from a
  button that did nothing. Issuing works until it doesn't — a rate limit, a
  hostname that stopped resolving here, a port 80 that closed — and at that
  point EasyWAF simply stopped producing certificates without saying why.
  Both pages now show the result, success or failure, including what the CA
  actually said.

  **And a failed issuance is now logged.** It previously existed only as a
  flash message, so a page that dropped one turned the whole attempt into
  silence — nothing on screen and nothing in the log to look up afterwards.

### Changed
- **Settings is organised into tabs** — General, TLS, Proxy, Rule Updates —
  rather than six panels down one page. Rule Updates made the sixth, and a
  page you have to scroll to find out what is on it is a page nobody reads to
  the bottom of.

  It stays **one form with one Save**: the handler writes every setting on each
  save, so a form per tab would clear whatever the other tabs hold. A hidden
  tab is still in the document and still submits what it contains.

  Two things that a naive split would have broken. The tab you were on is
  remembered, because saving redirects and being returned to the first tab
  after a rejected value hides the field the message is about. And a field the
  browser rejects pulls its own tab forward: a `required` field in a hidden tab
  cannot be focused to complain about, so the browser gives up and **Save does
  nothing at all, silently**.

- **The rule channel is configurable, and the check can actually be turned
  off.** Settings gains a Rule Updates panel: whether to check at all, which
  channel to check, and when the last check happened or why it failed.

  The switch existed in the code from the start of this work but was reachable
  only by editing the database, which is not a setting — it is a note in a
  changelog that nobody can act on. An installation with no outbound access
  needs to stop it looking, and that has to be a checkbox.

  **Pointing the channel elsewhere does not lower the bar.** The signature and
  hash checks are the same wherever the manifest came from, so a private mirror
  is a supported thing to run and a hostile one is refused exactly as the
  default would be. The URL is validated when saved rather than six hours later
  in a background task, where the only symptom would be a last-check time that
  never advances.

  An empty channel field means the default, not "no channel" — turning the
  check off is the checkbox. Conflating the two would leave a ticked box that
  quietly does nothing.

- **Imported rules are read-only; customising means cloning.** A rule that came
  from a rule set can no longer have its pattern, score, action, zone,
  description or name edited. Applying a set update overwrites every imported
  rule it owns, so an edit made in place would have been reverted by the next
  update without saying so — the editor previously accepted such changes and
  saved them.

  **Clone to customise** copies the rule into an ordinary custom rule that
  updates never touch. It is not a special kind of rule: `external_id` is
  cleared and the editor treats it like any hand-written one. The original is
  left enabled, since disabling it is a separate decision and a button labelled
  "clone" should not quietly change what a policy enforces — disable it
  alongside if you want yours to replace rather than add.

  This makes drift structurally impossible rather than something to detect at
  update time: an imported row cannot diverge from what was imported, so
  applying an update needs no comparison and has no case where the comparison
  could be wrong.

  A clone records where it forked from and at which version, and the rule's own
  page says so: "forked from 913015 at version 1 — owasp-scanners is now at
  version 2, so any correction made to the original since then is not in this
  copy." Nothing merges; it is a nudge for a person, shown where that person
  already is rather than left as two numbers on two pages to compare by hand.

- **Rule sets describe themselves, and EasyWAF records what it holds.** Each
  `.rules.toml` now carries a `[set]` header with its id and version, and
  importing records both which set every rule came from and which version of
  each set a policy holds.

  This is the foundation the update mechanism needs: a policy that does not know
  it holds SQLi v2 cannot be told v3 exists, which is exactly why correcting a
  rule has so far meant shipping a migration that rewrote patterns by hand.

  A set's version is tracked **per policy**, because sets are imported into
  policies: policy A may hold v2 while policy B holds v3. The notification will
  therefore be "SQLi 3 is available; this policy has 2", not "an update is
  available".

  The set is stored rather than derived from the rule's id range. That inference
  is already wrong in this project's history — rule `931100` sat in the RCE file
  for several releases, so `931xxx` did not mean RFI.

## [0.5.6] — 2026-09-06

Three rule and matching faults found by running production traffic, one of them
a fix that never reached the installations it was written for.

**Upgrading is enough** — a migration corrects the affected rules in your
database. It matches the exact patterns EasyWAF published, so a rule you have
edited is left alone.

Also carries the groundwork for 0.6.0's rule updates: the sets now live in the
`EasyWAF-rules` repository and are published to a signed channel. Nothing in
this release consumes that channel at runtime; it is a build-time script and a
file rename, and is listed here because it is in the code, not because there is
anything to do about it.

### Changed
- **`scripts/fetch-rules.sh`** refreshes `rules/` from the published rule
  channel at `repo.easysys.io/easywaf/rules`, taking only the sets marked
  `basic`. The channel's manifest is **GPG-signed with the same key that signs
  the EasySYS packages**, and the script refuses an unsigned or unverifiable
  one — a rule set decides what traffic is refused, so fetching one over a
  network without checking it is a supply-chain hole. Each set is then checked
  against the SHA-256 in the signed manifest, so the signature covers the
  content and not merely the index. Every set carries a version, recorded in
  `rules/SOURCE`, which is how an installation will know an update exists. The bundled rules are a snapshot of that channel rather than a copy
  maintained by hand — which is what left one version of a rule corrected and
  another broken for four releases. `rules/SOURCE` records where a snapshot came
  from and a SHA-256 per set.
- Rule set files are named `<band>-<slug>.rules.toml` rather than
  `<band>-<slug>.toml`, and only files with that suffix are loaded. `.rules`
  says what the file is — which matters once sets are published and downloaded
  on their own — while `.toml` keeps editors highlighting and validating them,
  which matters when the content is regular expressions edited by hand. A
  stray `.toml` in the rules directory is now ignored instead of being parsed
  as a rule set.

  The sets themselves now live in the `EasyWAF-rules` repository, which is the
  source of truth; what ships here is a snapshot of it.

### Fixed
- **Migration 012 never reached installations that had EasyWAF longest.** It
  corrected the two false-positive rules by `external_id`, but the catalogue was
  renumbered into OWASP bands at 0.3.x — `990xxx` became `913xxx`, and the
  command-chaining rule moved from `931100` to `932012`. A database imported
  before that keeps the old ids, so the fix skipped exactly the installations
  that had been running the broken rule the longest. Migration 014 matches on
  the pattern instead, which reaches both, and still leaves a rule an operator
  has edited alone.
- **Rule 913015 scored an application's own admin pages.** `/(admin|…)` was
  unanchored, so Nextcloud's `/index.php/settings/admin` matched every time an
  administrator opened it. Anchored to the path root — a scanner probes these at
  the root, an application nests them — while `.env`, `.git` and the rest stay
  unanchored, since nothing legitimately serves those at any depth.
- **The URL zone ran the path into the query.** It was built as
  `path + query` with no `?`, so `/admin?c=1` became `/adminc=1`. Any rule
  anchored to the end of a path stopped matching as soon as a request carried a
  query, and the join could manufacture a string that appeared in neither the
  path nor the query — a false match with no source in what the client sent.

- **Stray empty boxes beside the table pagination**, on Sites, Certificates,
  Policies and Traffic Monitor. With DataTables' Bootstrap integration
  `paginate_button` is the class on the `<li>` and the label lives in a child
  `<a>`; the stylesheet painted its box on the `<li>`, and Bootstrap floats the
  `<a>` out of it — so each button rendered twice, once as the real labelled
  button and once as a small empty bordered box beside it. Measured before and
  after in a browser: four 22×29 boxes with borders, now 0×0 with none.
- `responsive: true` was passed to DataTables on four pages without the
  Responsive extension ever being loaded, so it did nothing. Removed rather
  than satisfied — nothing depends on it. The identically-named Chart.js option
  on the dashboard is a different thing and is untouched.

## [0.5.5] — 2026-09-06

Nothing to do on upgrade. A migration adds one column; events recorded before
it simply show nothing in the new column.

### Added
- **Traffic Monitor says which rules produced a verdict.** A blocked or
  challenged row now shows the total score and every rule that contributed —
  catalogue number, name and points — so a false positive can be read off the
  page instead of reconstructed.

  This was the product's most frequently hit gap. `traffic_events.waf_score`
  had existed since 0.1.0 and was written as `NULL` at every call site, and the
  pipeline collected the matching rules and then discarded them, so the GUI
  could say a request scored 14 but never what produced it. Diagnosing the
  false positives in 0.3.1 and 0.5.4 meant enabling debug logging on a live
  proxy and reproducing the request — three occasions, each of which a row
  reading `932012 (8) + 920002 (6) = 14` would have answered immediately.

  Matches are stored as one JSON column on the event rather than a row per
  match in a second table: `traffic_events` is the highest-write table in the
  schema and already what makes the dashboard slow at scale, so multiplying its
  writes to make a rarely-read detail queryable would be the wrong trade.
  Nothing is stored when nothing matched.

  Rules in `DetectionOnly` mode report what they would have done, which is the
  whole reason for running a policy that way.

## [0.5.4] — 2026-09-06

Two bundled rules scored ordinary traffic heavily enough to block real
requests. Both are corrected **in existing databases too**: rules live in the
database and importing skips anything already present, so fixing the shipped
files would otherwise have reached nobody who had already imported them.

A migration rewrites only the exact patterns EasyWAF shipped. A rule you have
edited yourself does not match and is left alone.

### Fixed
- **Rule 932012 blocked ordinary traffic from any application whose cookies
  start with a command name.** `[;|`]\s*(…|nc|netcat)` had no word boundary, so
  `nc` matched the `nc` of `nc_token` and `id` the `id` of `identity` — and a
  `Cookie` header is semicolon-separated by definition. `; nc_token=…` therefore
  read as "semicolon, then netcat" and scored **8 of the default threshold of
  10** on every single request, before anything an attacker sent was weighed.
  Two points of headroom left, so any second match — a `--` inside a random
  session value, say — tipped it over, and Nextcloud broke seemingly at random.
  A word boundary fixes it; every real chaining attack is still caught, which
  the tests now assert both ways.
- **Rule 920002 treated ordinary URL encoding as a double-encoding attack.**
  Its own description says "`%%XX` or `%25XX`", but the pattern's first
  alternative was `(%[0-9a-fA-F]{2}){2,}` — *any two adjacent percent-escapes*.
  That is not double encoding: it is what every character outside ASCII looks
  like (`é` is `%C3%A9`, a Hebrew or emoji filename is several escapes in a
  row), and what any base64 token containing an encoded `=`, `/` or `:` looks
  like. Nextcloud's CSRF token is one, so signing out scored 6, and any
  non-English filename scored 6 on every request touching it.

  Double encoding is a percent that has itself been encoded. The rule now
  matches that — and `%%XX`, which the old pattern missed despite the
  description claiming it.
- **The rule list behind the Seed button still had the `Accept: */*` bug.** The
  catalog copy of the SQL-comment rule was corrected long ago; this second,
  hard-coded copy in `rules.rs` was missed, so anyone who pressed Seed rather
  than Import got a rule that scored every request 3 for the `*/` in a header
  every HTTP client sends.

## [0.5.3] — 2026-09-05

Nothing to do on upgrade, but **one thing to check**: sites that already had
`X-Frame-Options` enabled keep sending `DENY`. If an application frames its own
pages — Nextcloud, Collabora, Grafana — switch it to `SAMEORIGIN` under
Sites → Settings.

### Changed
- **`X-Frame-Options` is now a choice per site, not always `DENY`.** The header
  was hard-coded, and `DENY` forbids framing by *anything* — including the site
  itself. Applications that frame their own pages break quietly under it;
  Nextcloud reports the header as misconfigured and says some features may not
  work, which is what found this.

  `SAMEORIGIN` is what actually defends against clickjacking, since framing by
  another origin is the threat and framing by yourself is not. It is the default
  for new sites. **Existing sites are set to `DENY` by the migration**, so the
  upgrade changes nothing for anyone — those it was breaking can now choose, and
  those relying on it keep it.

  The configured value replaces whatever the application sent, so the setting
  says what is served rather than sometimes deferring to the upstream.

## [0.5.2] — 2026-09-05

A single fix, released on its own because it breaks logging in to any
application that sets more than one cookie. Nothing to do on upgrade.

### Fixed
- **Only the last of any repeated response header reached the client, which
  broke logins.** Headers were copied from the upstream with `insert`, and a
  `HeaderMap` yields one pair per value — so a response carrying four
  `Set-Cookie` headers arrived with one. Applications that set a session cookie
  alongside others could not establish a session at all: the login POST
  succeeded, the session cookie was discarded in the proxy, and the browser came
  back to the login page with no error anywhere. Nextcloud is the case that
  found it; its mobile app was unaffected because it authenticates with a token
  rather than a browser session, which made it look like a Nextcloud problem.
  Verified against the previous build: four cookies in, one out.

  The same mistake was present in the request direction, where a client sending
  `Cookie` more than once would have had all but the last dropped before the
  upstream saw them.

## [0.5.1] — 2026-09-05

Everything here came out of migrating a real installation onto EasyWAF, which
is why a patch release carries two features: each was something that stopped an
application working, found by pointing it at production traffic rather than at
a test. Nothing to do on upgrade — no migration, no configuration change.

### Added
- **Forwarding headers are sent to the upstream**: `X-Forwarded-For`,
  `X-Real-IP`, `X-Forwarded-Proto` and `X-Forwarded-Host`. EasyWAF previously
  sent none, so an application behind it could not tell it was behind anything
  — it saw a plain HTTP request from a local address and built `http://` URLs,
  redirected to them, and marked session cookies as not needing a secure
  connection. Applications that generate absolute URLs, Nextcloud among them,
  fail to log in for exactly that reason, while an API-driven front end on the
  same proxy works and makes it look like the application's fault.

  `X-Forwarded-Proto` reports the scheme the *client* used, not the scheme of
  the hop to the upstream, since that is what an application needs to link back
  to itself. `X-Forwarded-Host` keeps its port, which an application on a
  non-standard port needs to build a working URL.

  A client's own `X-Forwarded-For` is replaced rather than extended. Sending
  one is a claim about its address, and if this proxy did not believe it — it
  only does for peers listed under Trusted Proxies — passing it on would hand
  the upstream a forgery. Behind a trusted proxy the chain is preserved and
  this hop appended.

- **WebSockets are proxied.** An upgrade request is forwarded to the upstream
  with its `Connection` and `Upgrade` headers intact, and if the upstream
  answers `101 Switching Protocols` the connection is tunnelled in both
  directions until either end closes. Terminals, chat, hot reload and streaming
  dashboards work through EasyWAF; previously the upgrade headers were stripped
  as hop-by-hop — correct for ordinary traffic — so the upstream never saw the
  request and every client reported that WebSockets were unavailable.

  The handshake is a normal request and goes through the rule engine like any
  other, and is recorded in Traffic Monitor as a `101`. **The tunnel itself is
  not inspected**: once upgraded the payload is no longer HTTP, so there is
  nothing for HTTP rules to match. That is inherent to proxying WebSockets
  rather than a shortcut, and it is worth knowing before putting one behind a
  WAF.

  Upgrades to an `https://` upstream are refused with a clear message rather
  than attempted — the tunnelling path has no TLS client — so the failure names
  itself instead of arriving as a protocol error.

### Fixed
- **An uploaded certificate is now checked against its key.** Nothing was
  validated on upload beyond the name being non-empty, so a mismatched pair was
  stored happily and the failure surfaced later — and in the worst shape. Two
  individually valid halves from different pairs bind the port and then fail
  *every* handshake with a signature error that points at nothing, which looks
  like a working configuration. The public keys are now compared before storing,
  along with rejecting unreadable PEM, swapped fields, and X.509 v1
  certificates, which TLS does not accept.

## [0.5.0] — 2026-09-05

**Let's Encrypt.** EasyWAF obtains and renews its own certificates, so HTTPS
stops being a thing to remember every ninety days.

### Upgrading from 0.4.x

Nothing to do. A migration adds renewal-tracking columns to `certs` and is
applied on start; existing certificates are untouched, and nothing renews a
certificate EasyWAF did not issue — renewal only considers rows with an
`acme_domain`, which only issuance sets.

To use it: set a contact address under **Settings → Let's Encrypt**, start with
the **staging** directory, and request a certificate from **Certificates** or
from a site. Switch to production once staging succeeds.

Validation is HTTP-01, so the name must resolve to this host from the public
internet and the host must be reachable on **port 80**. If something else holds
port 80, it has to forward `/.well-known/acme-challenge/` to EasyWAF.

### Added
- **`X-Forwarded-For` support, behind a trusted-proxy list.** When EasyWAF runs
  behind another proxy, list that proxy's addresses under **Settings → Trusted
  Proxies** and the client address is taken from the header instead of the
  connection. Single addresses and CIDR blocks, IPv4 and IPv6.

  Believed **only** for connections that arrive from a listed address, and the
  header is walked from the right so a client cannot win by prepending a forged
  hop. Empty by default, which ignores the header entirely and is exactly the
  behaviour EasyWAF had before. An unparseable entry is refused rather than
  skipped: a silently ignored range is one an operator would believe was
  covered.

  This matters for more than the logs. The client address decides country
  rules, the Traffic Monitor, and **CAPTCHA clearance** — behind a proxy with
  nothing configured, every request appears to come from that proxy, so one
  visitor solving a challenge would clear it for everyone arriving through it.

- **Let's Encrypt certificates, issued by EasyWAF.** Set a contact address and
  a directory under **Settings**, then request one either from **Certificates →
  Request from Let's Encrypt** (any domain, stored but not attached) or with
  **Request Certificate** on a site (issued and assigned in one step). Uploading
  and requesting are separate pages, reached by their own buttons, since they
  are separate things to do.
  EasyWAF answers the HTTP-01 challenge on port 80 itself — no webroot, nothing
  to configure on the backend — and stores the result as an ordinary row in
  `certs`, assigned to the site. Everything downstream treats it exactly like an
  uploaded certificate.

  **Staging is the default and is offered explicitly.** Production allows only
  five failed validations per hostname per hour, which a first attempt burns
  through easily; staging proves the whole exchange works without spending that.
  Changing the contact or the directory re-registers the account, since staging
  and production are separate registries.

- **Automatic renewal.** Certificates issued over ACME renew themselves once 30
  days remain, checked hourly. That margin leaves four weeks of retries before
  anything expires, so a failure is something to look into rather than an
  emergency.

  **The backoff is persisted, not held in memory.** This is the part that would
  otherwise be got wrong: an in-memory backoff resets on restart, so a
  crash-looping service — or an operator restarting to "fix" a failing renewal —
  becomes one that hammers the CA and gets the account rate-limited, making the
  original problem unfixable for an hour. Retries double from one hour to a cap
  of a day, and restarts do not reset the count or bring an attempt forward.

  The certificate page shows what renewal is doing: when it was last attempted,
  whether that succeeded, the error if it did not, and when the next attempt is
  due. Without that there is nothing to tell a certificate renewing quietly from
  one failing quietly, until it expires.

  A per-node flag decides whether this node renews, defaulting to yes. There is
  no GUI for it — it exists so configuration sync can set it when there is more
  than one node, rather than the renewal path having to be unpicked later from
  an assumption that it is alone.

- **A Docker Hub overview** (`docker/README.md`): what EasyWAF is, quick start,
  what each port is for, why `/data` must be mounted, a compose file, adding a
  site — including the trap that an upstream on the Docker host is not
  `127.0.0.1` from inside the container — and the honest list of what it does
  not do. The release workflow pushes it, so it is versioned and reviewed here
  rather than typed into a web form once and left to rot. That step is
  non-fatal: Docker Hub's description API has historically wanted an account
  password rather than a token, and an image that published successfully must
  not be reported as a failed release because its overview did not update.

### Fixed
- **Uploading a certificate never worked.** The form posted `cert` and `key`
  while the handler expected `cert_pem` and `key_pem`, so every upload was
  rejected with a 422 before it reached any of the code that stores one. The
  field names now match. This was the path the documentation pointed at for
  replacing the management certificate and for wildcard certificates, neither of
  which was therefore possible from the GUI.

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

### Added
- **The management interface's certificate is now chosen in Settings.** Upload
  your own under Certificates, select it as the **Management Certificate** under
  **Settings → TLS**, and restart. Previously the GUI always used the generated
  `easywaf` certificate — the name was hard-coded — so the only way to serve
  your own was to delete that one and upload a replacement under the same name,
  which the deletion guard above now correctly prevents. Selecting it is the
  supported path, and the generated certificate becomes deletable once nothing
  uses it.

  A choice that cannot serve TLS is refused when saved rather than at the next
  start, and if the selected certificate is later removed or becomes unusable
  EasyWAF starts on `easywaf` and logs why. The management interface is the only
  place this setting can be corrected, so it has to come up: a GUI that refuses
  to start because of its own certificate setting is a locked door with the key
  inside. Settings then says the selection is missing rather than quietly
  showing a different one.

### Fixed
- **A certificate that is in use can no longer be deleted.** Deleting one
  assigned to a site silently unset that site's certificate — `sites.cert_id`
  is `ON DELETE SET NULL` and foreign keys are enforced — and a site with an
  HTTPS port but no certificate stops binding that port. The site kept working
  over plain HTTP, so nothing looked wrong until someone tried the HTTPS one.
  Deletion is now refused, naming the sites that would break.

  **The certificate the management interface is serving cannot be deleted
  either** — whichever one is selected, not a fixed name. Removing it left the GUI running on a certificate that existed nowhere,
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

# Policies and rules

A **policy** is a set of rules, a mode, and two thresholds. Sites point at a
policy; several sites can share one.

A site with no policy is a plain reverse proxy — forwarded and recorded, but not
inspected. The Sites page says so, since a site nobody meant to leave
uninspected is worth noticing.

## Modes

| Mode | Behaviour |
|---|---|
| `Off` | No inspection at all |
| `DetectionOnly` | Rules run and matches are recorded; nothing is blocked or challenged. **The default for a new policy** |
| `On` | Enforced — matching traffic is blocked or challenged |

DetectionOnly is how you find out what a policy would do to your traffic before
it does it. Traffic Monitor marks what *would* have happened — `WOULD BLOCK`,
`WOULD CHALLENGE` — so the mode is not silent.

## Scoring

Each matching rule adds its **score**. When the total reaches the policy's
**score threshold** — 10 by default — the request is blocked with 403. Some
rules block outright regardless of score.

If a **challenge threshold** is set, a score that reaches it but stays under the
block threshold gets a [CAPTCHA](#the-captcha-challenge) instead of a hard
block. Set it to 0 to disable score-based challenges.

A request that matched something but stayed under both thresholds is recorded as
**SCORED**, with its score and the rules that produced it. It is not a block and
not a clean request, and it is usually the first sign of both a real probe and a
rule that is about to become a false positive.

## Rule sets

Rules arrive as **sets**, versioned and published to a signed channel.

**Basic sets** are bundled with every build and installed by default. They assume
nothing about the application behind the proxy:

| Band | Set |
|---|---|
| 913 | Scanner and automated tool detection |
| 920 | Protocol enforcement |
| 930 | Local file inclusion and path traversal |
| 931 | Remote file inclusion |
| 932 | Remote code execution and command injection |
| 933 | PHP injection |
| 941 | Cross-site scripting |
| 942 | SQL injection |

**Optional sets** are published but never bundled. They only make sense in front
of the thing they name — WordPress, Apache httpd, Java and Tomcat, protocol
attacks, and credential and secret file exposure. A set for a stack you do not
run cannot detect anything, and can only match something legitimate.

Take a whole set by ticking its heading: it is recorded as a set and offered an
update when the channel publishes a newer version. Open the heading and tick
rules individually to take only those — single rules are copies, and nothing will
ever correct them.

## Updates

EasyWAF checks the channel on start and every six hours. The **Policy Manager**
shows which policies are behind — per policy, because a set is imported *into* a
policy: one may hold version 2 while another already has 3.

**Nothing is applied on its own.** Applying is a button somebody presses, because
a bad rule applied automatically is an outage across every site using that
policy.

When you apply one:

- The manifest's signature is checked **before anything is read from it**, and
  each set is checked against the SHA-256 the signed manifest gives for it. A
  channel serving something else is refused, and nothing reaches the database.
- Rules already installed are overwritten in place, **keeping each rule's enabled
  state**. A rule you disabled because it blocked your traffic stays disabled
  through the update.
- Rules you cloned are untouched, and a rule dropped from the set is left rather
  than deleted.

Under **Settings → Rule Updates** you can turn the check off — an appliance with
no outbound access should not keep trying — or point it at a different channel.
Pointing it elsewhere relaxes nothing: the signature and hash checks are the same
wherever the manifest came from, and the trusted key ships with EasyWAF.

## Customising a rule

Imported rules cannot be edited, because an update would overwrite the change
without saying so. Use **Clone**: you get an ordinary custom rule that updates
never touch, and its page tells you when the set it was forked from has moved on.

The original stays enabled unless you disable it, so a clone *adds* to what the
policy enforces rather than replacing it.

## False positives

When a rule blocks traffic that should have been allowed, you have three answers,
from narrowest to widest.

**Exclude it for the client that was blocked.** From the Traffic Monitor row that
shows the block, one click excludes that rule for that site — optionally narrowed
to a path prefix, or to the single address or CIDR block that was refused. The
rule goes on protecting everyone else.

**Disable the rule for the policy.** Wider: the rule stops running everywhere that
policy is used. The disabled state survives rule updates.

**Clone and tune it.** Where the rule is right in principle and wrong in detail.

Every rule that is not running anywhere — disabled or excluded — is listed on one
page, so a temporary exclusion cannot quietly become permanent.

## Country rules

Per policy: block listed countries, or allow only listed ones.

Lookups use a geolocation database compiled into the binary, so they are offline
and there is nothing to download. Addresses with no country — private ranges,
anything the database does not know — are never matched, so an allow list cannot
lock out traffic from your own network.

## The CAPTCHA challenge

The middle ground between allowing and blocking: suspicious-but-plausible traffic
gets a self-hosted image CAPTCHA rather than a 403. No third-party service is
involved.

Solving it sets a short-lived, HMAC-signed clearance cookie bound to the client
address, and requests carrying a valid one skip the challenge for 30 minutes.

!!! warning "Clearance is per client address"
    Behind a NAT — including hairpin NAT on your own network, where internal
    clients arrive as the router's address — one visitor solving a challenge
    clears it for everyone sharing that address. It is a reason to be careful
    with the challenge threshold on sites reached from inside a NAT, and a
    reason to get [trusted proxies](sites.md#behind-another-proxy) right when
    something sits in front.

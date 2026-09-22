# Design note — Smart Protect

Status: planned for **0.15.0** — see [roadmap.md](roadmap.md). Yariv's idea,
2026-09-22: *"if a specific IP has been attacking 3 times in 1 minute, the IP
will be blocked for 10 minutes."*

## The gap

**Every request is judged alone.** A scanner that fires two hundred probes gets
two hundred independent verdicts, each one correct and none of them noticing
that it is the same client, doing the same thing, for the twentieth time. The
rules refuse each probe on its merits and the scanner is free to carry on until
it finds something that is not refused.

Nothing in EasyWAF looks at a client's behaviour over time. IP lists are
decisions a person made; the CAPTCHA challenge asks whether there is a human
behind one request; upstream health counts failures but that is about backends.
This is the missing one: what a single address has been doing lately.

## The rule

**Three refusals within a minute, and that address is refused for ten.**

## Switched on per policy, configured once

Yariv's shape, 2026-09-22: **a policy decides whether Smart Protect applies to
it; the numbers are set once, under Settings.**

* **Per policy**: a switch, like the policy's mode and its country rules. The
  public websites can have it while an internal application does not, which is
  the reason policies exist.
* **Global**: how many refusals, in what window, and for how long the address
  is then refused. These are tuning, not policy, and three numbers repeated on
  every policy page is three numbers to keep in step.

**Stored so a per-policy override is not a rework.** The numbers live as
settings keys now. If it later turns out that the applications want a different
window from the websites — which is exactly the argument that moved IP lists
and country rules under a policy — that is nullable columns on `policies` with
NULL meaning "use the global ones", and no change to how the counter works.
Designing for that now costs nothing; discovering it later would cost a
migration and a page.

## Deciding the numbers from traffic that already happened

Yariv, same conversation: *"maybe we can also scan the traffic and decide based
on past traffic."* This is the most useful part of the feature and it is
cheaper here than it would be anywhere else, because the data is already on
disk and it is exactly the right data.

`traffic_events` records, for every request: the client address, the timestamp,
whether it was blocked, and — since 0.10.0 — what a watching policy *would*
have done. That is the whole input. **Replaying it is the same simulation the
feature performs live**, run over history instead of arrivals, and it answers
the question nobody can answer by guessing:

> With 3 refusals in 60 seconds and a 10 minute block, **last week would have
> blocked 412 addresses**. Of those, **2 later made a request that was served**
> — which is what a false positive looks like here.

That second number is the one that matters. An address that was refused three
times and never seen again was a scanner; an address that was blocked and then
went on to use the site normally is a customer who tripped something.

**It previews, it does not act.** Nothing is blocked by looking, and the page
says what the simulation cannot know:

* **It sees only what was recorded.** Traffic history is pruned on a retention
  setting — fourteen days by default — so a preview over a longer window is
  answering with less than it appears to.
* **It cannot know what a blocked address would have done next**, only what it
  did do when it was not blocked. A block that prevents an attack looks
  identical to one that prevented nothing.
* **It is per policy**, because a refusal belongs to the site's policy and the
  numbers mean different things in front of a public website and an API.

**What it is not: thresholds that tune themselves.** An appliance that quietly
moves its own numbers is one whose behaviour cannot be explained after an
incident, and one an attacker can walk upwards by keeping just under the line
while it adapts. The simulation recommends; a person decides; the numbers are
then what the page says they are.

## What counts as an offence

**A refusal, not a rule match.** The pipeline already draws that line:
`ModuleDecision::Drop`, and `Detection::WouldBlock` for a policy that is only
watching. Plenty of legitimate requests trip a rule and score under the
threshold, and counting those would ban real users for visiting a page whose
query string happens to look like SQL.

* **Refused, or would have been** — counts. This is the whole of it.
* **A rule matched and the request was served** — does not. That is the WAF
  working as intended.
* **A CAPTCHA challenge, passed or failed** — does not. Yariv, 2026-09-22: a
  failed challenge is itself a refusal, so it is already the answer rather than
  evidence towards a different one. A visitor who cannot read the picture is
  the other person it happens to, and neither of them should accumulate towards
  a ten-minute ban.

  **This is already true mechanically, which is the best kind of rule.** A
  challenged request is logged with `blocked = false` and no detection — it is
  a 200 with a puzzle in it — so both the live counter and the history preview
  exclude it without a special case for challenges existing anywhere. A failed
  answer is not recorded as an event at all: the verify path re-renders the
  page. Counting failures would mean first inventing the record, which is a
  second reason not to.

## Where the state lives

**In memory, per node, and never written to an operator's lists.** An IP list
entry is a decision somebody made and expects to find later; a Smart Protect
block is an observation that expires. Mixing them would mean an operator's
block list slowly filling with rows nobody chose, and a `DELETE` on every
expiry.

**Never synced between nodes**, for the reason the HA note reserves a per-node
column: node A may see a scanner that node B never receives a packet from, and
copying a judgement about traffic that only one node saw is how a working
client gets refused everywhere. A temporary block belongs beside upstream
health and rate-limit counters.

**Visible, with a way out.** A page listing what is blocked right now, why,
which policy did it, and how long is left — with an unblock button. A block
nobody can see or lift is the thing operators dislike most about tools of this
kind, and the information already exists.

## Three rules it must not break

**The allow list wins, always.** An address an operator has allowed must never
be auto-blocked, whatever it does. Otherwise the first thing Smart Protect does
in an incident is refuse the monitoring, the office, and whoever is trying to
fix it.

**A trusted proxy is never blocked.** EasyWAF resolves the real client from
forwarded headers, with trusted proxies configured under Settings. If that is
misconfigured, every request appears to come from one address — and Smart
Protect would block it, taking out every client behind it at once. The block
list is therefore checked against the trusted-proxy list first, and an address
that is a trusted proxy is refused as a candidate rather than relied on being
absent. The page says so.

**A policy's mode decides, as everywhere else.** In DetectionOnly the block is
recorded and not enforced, so a policy can be trialled with Smart Protect on;
with the policy Off it does nothing at all.

## IPv6 is a /64, not an address

A single IPv6 address costs an attacker nothing — most allocations hand out a
/64 or larger, so blocking one address blocks one of billions they hold. The
unit is the /64 for IPv6 and the single address for IPv4, which is what every
other tool that has had to learn this does.

## What it shares with rate limiting

Rate limiting (0.17.0) counts events per client in a sliding window, evicts
what has aged out, and bounds its own memory. So does this. **The counter is
built here, for the concrete case, and rate limiting uses it** rather than a
second one being written beside it.

The memory bound matters in the case this feature is for: a spray from a
botnet is thousands of distinct addresses in a minute. A fixed ceiling with
oldest-first eviction, and a block table that is small because only offenders
are in it.

## Deliberately not in 0.15.0

**Escalation** — a repeat offender blocked for longer each time. It is an
obvious second step and it is not free: it needs history that outlives the
window, which is a different kind of state from a sliding count. Worth having
once the simple version has been watched in production.

**Thresholds that adapt on their own.** See above — the simulation is there to
inform a decision, not to replace one.

**Sharing offenders between installations.** A reputation feed built from what
several EasyWAF installations have seen is a different product with different
consent questions, and nothing here should quietly become the first half of it.

**Blocking on anything but refusals.** Response codes, request rates, payload
sizes and failed challenges are all either rate limiting's business or already
an answer of their own. Mixing them in would make "attacking" mean whatever the
last person to edit the definition thought, and the definition is the feature.

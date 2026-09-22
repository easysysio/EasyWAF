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

**Three refusals within a minute, and that address is refused for ten.** Those
three numbers are per policy, with those defaults, so the hosted applications
can be stricter than the public websites — which is the reason policies exist.

## What counts as an offence

**A refusal, not a rule match.** The pipeline already draws that line:
`ModuleDecision::Drop`, and `Detection::WouldBlock` for a policy that is only
watching. Plenty of legitimate requests trip a rule and score under the
threshold, and counting those would ban real users for visiting a page whose
query string happens to look like SQL.

* **Refused, or would have been** — counts. This is the whole of it.
* **A rule matched and the request was served** — does not. That is the WAF
  working as intended.
* **A CAPTCHA challenge** — does not, by default. A challenge means "maybe a
  person", and a person who is asked is not an attacker. A *failed* challenge
  is a reasonable signal and can be offered as a switch; the default is off,
  because failing a CAPTCHA is also what a person does when the picture is
  unreadable.

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

**Sharing offenders between installations.** A reputation feed built from what
several EasyWAF installations have seen is a different product with different
consent questions, and nothing here should quietly become the first half of it.

**Blocking on anything but refusals.** Response codes, request rates and
payload sizes are rate limiting's business, and mixing them in here would make
"attacking" mean whatever the last person to edit the definition thought.

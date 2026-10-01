# Smart Protect

Every request is judged alone. A scanner that fires two hundred probes gets two
hundred separate refusals, each one correct and none of them noticing that it is
the same client doing the same thing — so it carries on until it finds something
that is not refused.

Smart Protect notices. **An address a policy's rules keep refusing is refused
outright for a while**: by default, three refusals within a minute, and that
address is refused for ten.

## Switching it on

It is a checkbox on each policy — **Security Policy → the policy → Enable Smart
Protect** — and on the page that creates one. It is off by default, so nothing
is blocked that nobody decided to block. A policy that has it on is labelled
**Smart Protect** in the policy list.

It follows the policy's mode, like everything else a policy does:

| Mode | What Smart Protect does |
|---|---|
| `On` | Blocks, and refuses the blocked address with a 403 |
| `DetectionOnly` | Counts, and records each request it *would* have refused as `WOULD BLOCK`; nothing is refused |
| `Off` | Nothing |

A block belongs to the policy that made it. An address blocked on one policy is
judged as usual on another.

## The numbers

**Settings → Smart Protect** holds them, set once for every policy that has it
on:

| Number | Default | Accepts |
|---|---|---|
| Refusals | 3 | 2 to 100 |
| Within | 60 seconds | 10 to 3,600 seconds |
| Refused for | 10 minutes | 1 to 1,440 minutes |

They are in force as soon as they are saved. A block already in force keeps the
length it was made with.

## What counts, and what does not

Only a **refusal by the rules** counts — a request the policy's rules blocked, or
would have blocked in `DetectionOnly`.

These do not:

- **A rule that matched on a request that was served.** That is the WAF working
  as intended, and counting it would block real users for visiting a page whose
  query string happens to look like SQL.
- **A CAPTCHA**, passed or failed.
- **A country refusal**, or a refusal by an IP list. Those addresses are refused
  every time anyway.
- **A request made while blocked.** A block lasts exactly as long as it says;
  an address that keeps trying is let back in when its time is up, and judged
  afresh.

## Who is never blocked

- **An address on the policy's allow list.** Otherwise the first thing Smart
  Protect does in an incident is refuse the monitoring, the office, and whoever
  is trying to fix it.
- **A trusted proxy.** If forwarded headers are misconfigured, every request
  appears to come from the proxy's address, and blocking that would refuse every
  client behind it at once.

An **IPv6** client is counted and blocked by its /64 rather than its single
address, since one address there costs an attacker nothing.

## Seeing and lifting blocks

**Settings → Smart Protect** lists every address blocked right now: the policy,
when it was blocked, the time left, and the refusal that completed the count.
**Unblock** lifts one immediately, and its count starts again from nothing.

In Traffic Monitor a request refused this way is a `BLOCKED` row whose reason
begins *Smart Protect*.

Blocks are held in memory on the node that made them. They are never written to
your IP lists — a block list is decisions somebody made, and these are
observations that expire — and a restart clears them. Unticking the checkbox on
a policy forgets that policy's blocks at once.

## Choosing the numbers from your own traffic

The page can replay a policy's recorded traffic through any numbers you try, and
say what they would have done:

> Over the last 7 days, on **websites**, these numbers would have blocked **412**
> addresses and refused **3,980** further requests from them. **6 of those
> requests were in fact served successfully**, from 2 addresses.

The second number is the one that matters. An address that was refused three
times and never served was a scanner; one that would have been blocked and went
on to use the site normally is a customer who tripped something. Those are
listed first, so you can look them up in Traffic Monitor, then raise the count or
fix the rule that tripped them before switching Smart Protect on.

The preview changes nothing, and it has two limits it says on the page:

- It sees only what was recorded, and traffic history is kept for as long as
  **Settings → General** says.
- It cannot know what a blocked address would have done next, only what it did
  when nothing was blocking it.

It is offered for every policy, not only those with Smart Protect on: seeing
what it would do is how you decide.

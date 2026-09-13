# IP lists

Two lists, applying to the whole installation: addresses refused outright, and
addresses waved past every check.

They are installation-wide on purpose. A specific attacker's address is true
regardless of which site it reaches, and so is one you have decided to trust —
unlike a [rule exclusion](policies.md#false-positives), which is about one rule
on one site.

| List | Effect |
|---|---|
| **Block** | Refused before any rule runs — including on a site with no policy, where the WAF would do nothing at all |
| **Allow** | Skips the WAF, the country rules and the CAPTCHA alike |

**Allow is wide, deliberately.** It is checked before the inspection pipeline is
entered at all, so it cannot be undone by a rule added later — which is what
makes it trustworthy, and why it should be used sparingly.

An address is on at most one list. Putting it on the other one moves it.

## Adding one

**From Traffic Monitor**, beside the client address on any row — which is where
you are standing when you decide an address should never be seen again. Blocking
asks for confirmation; allowing does not, since it only widens access for one
address.

A row whose client is already listed shows a badge instead of the buttons, so
you cannot add it twice or silently move somebody else's entry.

**From Security Policy → IP Lists**, for an address that arrives in a report
rather than in your own traffic.

Entries take effect on the **next request**. There is no restart and nothing to
reload by hand.

## Ranges

Both lists hold CIDR blocks as well as single addresses — `203.0.113.0/24` as
readily as `203.0.113.9` — for either family. A block costs one entry however
large it is.

The Traffic Monitor buttons always add the exact address they are next to,
since that is what is on screen. Type a range by hand on the IP Lists page.

## Reviewing them

**Security Policy → IP Lists** shows every entry with its reason, who added it
and when, searchable by address or reason.

Worth doing periodically. A block added during an incident is easy to add and
easy to forget, and an address is rarely hostile forever — the machine behind it
gets rebuilt, or the address is reassigned to somebody else entirely.

## What it does not do yet

Curated lists synced from a signed channel — Tor exits, hijacked netblocks,
compromised hosts — are the next piece of this work. Today the lists hold what
you put in them.

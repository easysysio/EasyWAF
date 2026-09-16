# IP lists

Two lists of your own, applying to the whole installation — addresses refused
outright, and addresses waved past every check — and
[published lists](#published-lists) kept by other people, which you switch on
one at a time.

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

## Published lists

Addresses you have not seen yet: hijacked netblocks, compromised hosts, Tor exit
nodes. Each is a separate list on **Security Policy → IP Lists**, with its
source, licence and size beside it.

| List | Source | Suggested |
|---|---|---|
| Hijacked netblocks | Spamhaus DROP | Block |
| Compromised hosts | Emerging Threats | Challenge |
| Tor exit nodes | The Tor Project | Off — using Tor is not an attack |

**The data updates itself; what it does does not.** Every list is fetched and
refreshed daily whether or not you use it, but none has any effect until you
switch it on and choose a response:

- **Challenge** — a CAPTCHA, which anyone human can pass. A wrongly listed
  address is a speed bump rather than a wall, which is why it is the right
  answer for anything less certain than a hijacked netblock.
- **Block** — refused before any rule runs, on every site, including those with
  no policy.

A refused or challenged request names the list in Traffic Monitor, so a refusal
can always be explained.

**Your own lists come first.** An address on your allow list skips every
published list, and no update can undo that. An address on your block list is
reported as yours, not as the published list that happens to agree.

### Where they come from

From the same signed channel as rule sets, on the same schedule, and only if
**Settings → Rule Updates** allows checking the update channels. Nothing is
loaded unless the manifest carries a valid signature from the key that ships
with EasyWAF and each file matches the hash that manifest gives for it — on
every load, not only on download. A list whose copy on disk has been altered is
not enforced, and its row says why.

If the channel cannot be reached, the lists from the last update that worked
stay in force. **Update now** on the IP Lists page fetches them without waiting
for the next check.

The lists are never merged into one: each keeps the licence and credit line its
source requires, and the page shows both.

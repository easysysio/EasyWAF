# IP lists

A security policy's own two lists — addresses refused outright, and addresses
waved past every check — and the [published lists](#published-lists) kept by
other people, which a policy switches on one at a time.

They **belong to the policy**, like its rules, country rules and
[exclusions](policies.md#false-positives), and apply on every site using it.
Sites that face the same traffic share a policy and so share its lists: the
public websites can block Tor exits while Nextcloud, on a policy of its own,
does not; an office address can be allowed on the applications and nowhere
else. **A site with no policy has no IP lists.**

| List | Effect |
|---|---|
| **Block** | Refused before any rule runs |
| **Allow** | Skips the WAF, the country rules, the published lists and the CAPTCHA alike |

**Allow is wide, deliberately.** It is checked before the inspection pipeline is
entered at all, so it cannot be undone by a rule added later — which is what
makes it trustworthy, and why it should be used sparingly.

An address is on at most one of a policy's lists. Putting it on the other one
moves it. The same address can be on different lists in different policies.

## All policies

Some addresses are not one policy's business: an office that must never be
refused anywhere, a netblock with no honest reason to reach this appliance at
all. **Security Policy → IP Lists → All policies** is the second scope, and an
entry there applies on **every policy — the ones that exist and the ones made
later**. Nothing is copied into the policies, so there is nothing to keep in
step and nothing to remember when the next policy is created.

A policy's own page lists what reaches it from here, marked `all policies` and
read-only; it is changed in the All policies view.

**The All policies view is also the overview.** Its table is every entry in the
installation, each with the policy whose list it is on — or `all policies` for
the ones that belong to all of them — because "why is this address refused" is
not a question one policy's page can answer. The search box matches the policy
name as well as the address and the reason, and a published list that some
policies answer for themselves says how many.

**Allow wins wherever it was written.** An address allowed for every policy
cannot be blocked by one policy, and one blocked for every policy is let through
by a policy that allows it. Which page an entry was typed on decides nothing
else, so there is one rule to remember rather than two.

**A site with no policy is still not inspected**, and still gets no IP lists.
All policies means every policy, not every site.

## The policy's mode

The lists follow the policy's mode, as its rules do:

- **On** — enforced.
- **DetectionOnly** — nothing is refused or challenged. A listed address is
  served, and Traffic Monitor records it as *would block* or *would challenge*
  with the list that said so, so a policy can be trialled with its lists too.
- **Off** — the lists do nothing.

An allowed address skips inspection in both On and DetectionOnly.

## Adding one

**From Traffic Monitor**, beside the client address on any row — which is where
you are standing when you decide an address should never be seen again. The
address goes on the lists of that row's site's policy, and the confirmation says
how many sites that covers. Blocking asks for confirmation; allowing does not,
since it only widens access for one address. A row whose site has no policy
offers neither.

A row whose client is already listed shows a badge instead of the buttons, so
you cannot add it twice or silently move somebody else's entry.

**From Security Policy → IP Lists**, choosing the policy at the top — or
**All policies**, for an address that no policy should see — for an address
that arrives in a report rather than in your own traffic. The policy list links
straight to each policy's IP lists too. Traffic Monitor always adds to the
row's own policy; an entry for every policy is made here, deliberately, since
it reaches sites the row says nothing about.

Entries take effect on the **next request**. There is no restart and nothing to
reload by hand.

## Ranges

Both lists hold CIDR blocks as well as single addresses — `203.0.113.0/24` as
readily as `203.0.113.9` — for either family. A block costs one entry however
large it is.

The Traffic Monitor buttons always add the exact address they are next to,
since that is what is on screen. Type a range by hand on the IP Lists page.

## Reviewing them

**Security Policy → IP Lists** shows a policy's entries with their reason, who
added them and when, searchable by address or reason, and names the sites they
apply to.

Worth doing periodically. A block added during an incident is easy to add and
easy to forget, and an address is rarely hostile forever — the machine behind it
gets rebuilt, or the address is reassigned to somebody else entirely.

## Published lists

Addresses you have not seen yet: hijacked netblocks, compromised hosts, Tor exit
nodes. Each is a separate list on **Security Policy → IP Lists**, with its
source, licence and size beside it.

A list can be switched on for one policy or, under **All policies**, for every
policy at once. A policy that has decided about that list itself keeps its own
answer — including *off*, which is a decision — and its row says what every
policy does and that it is being overruled. **Follow all policies**, beside the
row, drops the policy's own answer and lets it follow again.

| List | Source | Suggested |
|---|---|---|
| Hijacked netblocks | Spamhaus DROP | Block |
| Compromised hosts | Emerging Threats | Challenge |
| Tor exit nodes | The Tor Project | Off — using Tor is not an attack |

**The data updates itself; what it does does not.** Every list is fetched and
refreshed daily whether or not any policy uses it, but none has any effect on a
policy until that policy switches it on and chooses a response:

- **Challenge** — a CAPTCHA, which anyone human can pass. A wrongly listed
  address is a speed bump rather than a wall, which is why it is the right
  answer for anything less certain than a hijacked netblock.
- **Block** — refused before any rule runs, on every site using the policy.

A refused or challenged request names the list in Traffic Monitor, so a refusal
can always be explained.

**The policy's own lists come first.** An address on its allow list skips
every published list, and no update can undo that. An address on its block list
is reported as such, not as the published list that happens to agree.

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

## Upgrading from 0.12.0

Until 0.12.1 the lists applied to the whole installation. The upgrade copies
every entry, and every published-list choice, into every policy, so each site
with a policy is treated as before. A site with **no** policy loses its lists;
the start-up log names each such site. Attach a policy to keep them.


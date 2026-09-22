# Updates

Three things arrive from outside: **rule sets**, **published IP lists** and the
**country database**. All of them are managed on one page —
**Settings → Updates** — which says what is in force, how old it is, and what
is waiting.

## Two stages

**Fetching** reads a channel, checks the signature over its manifest before
reading anything from it, checks every file against the SHA-256 that signed
manifest gives for it, and puts what survives in a mirror beside the database.
Nothing that fails verification is written.

**Applying** is what puts something in force. The two are separate on purpose,
and the page never blurs them: a fetch changes what is available, not what is
protecting your sites.

## What applies itself, and what waits

| | Applied as it arrives | Why |
|---|---|---|
| **IP lists** | yes | Their value *is* freshness. A refresh changes which addresses are on a list, not what any policy decided to do about them |
| **Country database** | yes | A stale one mis-locates clients, quietly |
| **Rule sets** | **no — they wait for you** | A new pattern can refuse traffic that was fine yesterday, on every site using the policy |

Each has a switch, so an installation with change control can hold the first
two, and one that wants rule sets applied for it can say so. **Turning the rule
set switch on applies updates to every policy holding the set, without asking.**

**There is a way back.** The version a policy held is kept when an update
overwrites it, and *put back vN* on that policy's **Rule Sets** page restores
those rules exactly, removes what the newer version added, and puts the
recorded version back. One step — what the last update replaced, not a history
— and it leaves alone the two things no version owns: whether a rule is
switched on, and any rule you cloned from the set.

When lists are set to apply by hand, a fetched bundle is **held**: what is
serving traffic does not change until you press *Apply them*.

## The count in the menu

**Settings** carries a count of what has arrived and not been applied — rule
sets a policy holds at an older version than the mirror offers, and a held list
bundle. A channel that cannot be reached is *not* counted: that is a different
fact, it appears on this page, and a badge that meant "something is wrong
somewhere" would be ignored within a week.

## Update now

Each kind has one, for when waiting up to six hours to find out whether a
channel is reachable is not good enough. It says what it found: a newer version
is here, everything is current, or why the channel could not be read.

**It is refused when channel checking is switched off**, rather than quietly
overriding that switch — an installation that says it must not reach out means
it. Use upload instead.

## Upload, for an appliance with no outbound access

Download the channel's files on a machine that has access, carry them over, and
upload them here. **The bar is identical**: the manifest's signature and every
file's hash are checked exactly as they are for a download, and a bundle that
does not verify is refused with the mirror left as it was.

- **Rule sets** — `sets.toml`, `sets.toml.asc`, and the set files.
- **IP lists** — `lists.toml`, `lists.toml.asc`, and the list files.

**The country database is the exception.** DB-IP and MaxMind do not sign
theirs, so an uploaded `.mmdb` is checked for being a database and nothing
more, and the page records it as *not signed* rather than showing it beside the
verified kinds.

Licensing differs by source, and the two must not be blurred: **DB-IP Lite is
CC BY 4.0** and may be redistributed, which is why one ships with EasyWAF;
**MaxMind GeoLite2 must not be redistributed**, so it can only ever be a file
you fetch yourself and upload, or point `geoip_db` at.

## What is in force

The country database reports what it is, when it was built and how long ago,
what it covers, where it came from, and whether that path was verified. A
database named by `geoip_db` in `config.toml` is always the one used — a
deliberate local choice is not overridden from a web page.

Rule sets show what the mirror offers and what each policy holds; lists show
the publisher's version and entry count, the ranges actually in force after
merging, any lines that could not be read, and how many policies use each one.

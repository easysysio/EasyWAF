# Design note — rules with several conditions

Status: **built for 1.3.0, not released** — see [roadmap.md](roadmap.md). Decided by
Yariv on 2026-10-14, to make ET Open's rules convertible.

## The gap

A rule is one pattern on one or more zones. What it cannot say:

* **"This and that."** ET Open's rules nearly all combine several things: the
  method is `POST`, *and* the URI names `/xmlrpc.php`, *and* the body holds
  `pingback.ping`. CRS writes the same thing as a chain.
* **"These strings, in any order."** A rule that needs `&c=`, `&p1=` and
  `&p2=` in a body, wherever each is, is three conditions. A regular expression
  can only say it by spelling out every order, and Rust's has no lookahead to
  do it otherwise.
* **"Not this."** CRS refuses a method that is not in an allowed list; ET a
  request whose `Content-Type` is missing. A pattern only says what matches.

Of ET Open's 7,092 BSD-licensed rules for requests to a server, about 9% fit
one pattern; about 95% fit a list of conditions.

## What 1.3.0 adds

A rule keeps its zone and pattern — its first condition — and can carry more,
each a zone and a pattern of its own. **It matches when every condition does.**
Any condition, the first included, can be negated: it holds when its pattern
matches no form of any value its zone reads, so a negated condition on a header
the request does not have holds.

```toml
[[rules]]
id      = 2018277
name    = "WordPress pingback"
zone    = "URL"
pattern = '(?i)/xmlrpc\.php'
score   = 10
action  = "score"

[[rules.and]]
zone    = "METHOD"
pattern = '^POST$'

[[rules.and]]
zone    = "BODY"
pattern = '(?i)pingback\.ping'
```

A rule without `and` and without `negate` is what it was. Every rule an
installation holds, and every published set, reads exactly as before.

In the database the first condition stays in `zone` and `pattern`; `negate`
and the further conditions are columns beside them. A rule's conditions travel
everywhere its pattern does: installing and updating a set, putting a version
back, the rule picker, clones, sharing to another policy, export and import,
the set-case harness and `easywaf test-crs`.

## Cost

Conditions are checked in order and the rule stops at the first that fails,
so a rule costs what its first condition costs on the requests that condition
refuses — which, written well, is nearly all of them. A converter puts the
cheapest and rarest condition first: for ET, the literal the rule names as its
fast pattern.

Thousands of rules per request still cost per rule. If ET's sets make that
show, the step after this is a pre-check: the literals rules require, found in
one pass over the request, so a rule whose literal is absent is never run. It
is not built until a measurement says it is needed.

## Forward compatibility

A rule set using conditions is refused by an EasyWAF that does not read them,
the way a zone it does not read is: installing a set with a key in a rule this
version does not know is refused, naming the key. 1.2.x refuses such a set by
`requires = "1.3.0"` in the channel. Older ones would ignore `and` and match the
first condition alone — more matches, not fewer — which is why the sets that
use conditions are published with `requires` and only as optional sets.

## Not in 1.3.0

* **Editing conditions in the interface.** A rule's conditions are shown on its
  page. A custom rule with several conditions is written as a set or imported.
* **Counting** — "more than 255 arguments", "a header twice". A condition is a
  pattern; a number is not one. CRS's rules that count stay refused.
* **The pre-check**, above.

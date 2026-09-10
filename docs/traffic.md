# Traffic

## Dashboard

Request volume, a stacked passed / challenged / blocked chart over the last 24
hours, and a per-site breakdown of each site's mix.

The charts are filters. Clicking a bar or a slice opens Traffic Monitor already
narrowed to what the chart was drawn from — the reader's next question after
seeing a spike is "show me those", and it used to mean rebuilding the filter by
hand.

## Traffic Monitor

Every proxied request, with:

- the site, the client address and its country
- the method and path
- the verdict, and for anything the rules touched, the **score** and **every rule
  that contributed to it**
- the response status and how long it took

Filter by site, verdict and time window. The per-hour chart narrows to the same
filter, so a bar and the rows under it can never disagree.

### Verdicts

| Verdict | Meaning |
|---|---|
| `PASSED` | Nothing matched, or nothing that scored |
| `SCORED` | Something matched but stayed under both thresholds. Forwarded |
| `CHALLENGED` | Sent a CAPTCHA |
| `BLOCKED` | Refused with 403 |
| `WOULD BLOCK` | The policy is in DetectionOnly; this would have been blocked |
| `WOULD CHALLENGE` | The policy is in DetectionOnly; this would have been challenged |

`SCORED` is deliberately not called "detected". Detected reads as *stopped*, and
these requests were forwarded to your application exactly as they were.

### Acting on a row

A blocked row carries the rule that blocked it, and a button that excludes that
rule for the site — optionally for just that client or path. That is the fastest
honest answer to a false positive: keep the rule for everyone else, and stop it
refusing the caller it was wrong about.

## Retention

Traffic history is kept forever by default. Set a window under **Settings →
General** and older events are pruned at startup and hourly.

The Settings page shows how many events are stored, so the setting's effect is
concrete rather than theoretical.

## What is not recorded

Traffic history holds the method, host, path, country and verdict — **no headers
and no bodies**. That keeps the database bounded and keeps request contents out
of it, but it means a new rule cannot be replayed against past traffic to see
what it would have matched.

The path is stored without its query string. The [flow log](logging.md) sends the
full path and query to a collector, so that is where to look when the query
string is what you need.

## Beyond the appliance

Traffic Monitor is bounded by what an appliance should hold. For longer history,
several appliances charted together, or alerting, send [flow logs](logging.md)
over syslog to a collector such as [EasyLog](https://easysys.io) — one line per
request, with the same verdict, score and rules.

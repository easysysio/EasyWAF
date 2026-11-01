# Rate limiting

A rate limit caps how many requests one client may make to a site: say, 600 a
minute. A person in a browser never comes near a sensible limit. A script
hammering a login form, a scraper copying the site, or a client stuck in a loop
does, and is held back before it reaches the application.

It is set **per site**, on the site's page under **Rate limit**. What counts as
normal differs too much between sites to share one number: a busy API and a
small internal tool are orders of magnitude apart.

## Setting a limit

| Field | What it is |
|---|---|
| Mode | `Off`, `DetectionOnly` or `On`, as a policy's |
| Requests | How many one client may make within the window, from 1 to 1,000,000 |
| Within | 10 seconds, a minute, 5 minutes or an hour |
| Then | **Refuse (429)** or **Show a CAPTCHA** |

It is off on every site until you switch it on. Start in **DetectionOnly**: nothing
is refused, and each request that would have been is served and marked `WOULD BLOCK`
(or `WOULD CHALLENGE`) in [Traffic Monitor](traffic.md), with the count that put it
over. Switch to `On` once nothing you want is in those rows.

### Choosing the number

**Preview**, beside the fields, replays the site's recorded traffic through the
numbers typed, saved or not, and changes nothing. It shows how many requests
would have been over the limit, how many of those the site in fact served
successfully, and the busiest addresses with the most each made within one
window. The limit has to sit above what your real clients do.

!!! warning "A page is many requests, and a sync client is many more"
    A browser loading one page fetches its images, scripts and styles as
    separate requests: dozens at once is ordinary. A Nextcloud or Immich client
    syncing a folder makes hundreds a minute and keeps going. Preview a busy
    day before enforcing anything on a site like that.

## What happens over the limit

**Refuse** answers `429 Too Many Requests`, with a `Retry-After` header giving
the seconds until one more request would be within the limit. Well-behaved
clients and libraries wait that long by themselves.

**Show a CAPTCHA** shows the challenge page to a page load, and a person who
answers it carries on. A few things are refused with 429 instead:

- **A request that is not a page load**, such as an image, a script or an API
  call. Nobody would see a CAPTCHA served to those.
- **A client past twice the limit.** That is not a person waiting at a
  CAPTCHA, and drawing one for every request would do the flood's work for it.

Answering the CAPTCHA does not reset the count. The visitor is let through for
as long as the clearance lasts (30 minutes), still counted, so solving
CAPTCHAs cannot keep a flood going.

**Every request counts, refused ones included.** A client that keeps sending
while over the limit stays over. One that stops is let back in within about a
window.

## Who is counted

A client is its address, or for IPv6 its /64, as with
[Smart Protect](smart-protect.md). Two are never counted:

- **An address on the policy's allow list.** Your monitoring and your office
  are never limited.
- **A trusted proxy** (Settings → Proxy → Trusted Proxies). If forwarded headers
  are misconfigured, every request appears to come from the proxy, and
  limiting it would limit everyone behind it.

A request refused by an IP list or by Smart Protect is refused before it is
counted.

## How it counts

The count is over a sliding window: the requests in the current window, plus
those of the previous window in proportion to how much of it still falls in the
last *window* seconds. It costs a few bytes per client however high the limit,
which is why a limit in the thousands is no more expensive than one of ten.

Counts are kept in memory, on each node. A restart starts every client's count
afresh, and **with several nodes each counts its own traffic**: a client whose
requests a load balancer spreads over two nodes can make up to twice the limit.
Most balancers keep a client on one node; if yours does not, set the limit for
one node's share.

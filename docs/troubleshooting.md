# Troubleshooting

The journal is the first place to look for anything the appliance says about
itself:

```bash
journalctl -u easywaf -f
```

## A request gets 404 from EasyWAF

The `Host:` header matched no **enabled** site.

- The hostname is matched exactly. `www.example.com` is not `example.com` unless
  it is listed as an [alias](sites.md#aliases).
- A disabled site serves a 503 maintenance page, not a 404 — so a 404 means
  nothing matched at all.
- Check you are talking to a port that site actually listens on.

## The site answers, but not through the port I expected

Ports are bound as sites are saved, and a removed port keeps listening until the
next restart because other sites may share it. If a port answers that you thought
you had removed, restart the service.

## A legitimate request is blocked

Open [Traffic Monitor](traffic.md), find the row, and read the rule that blocked
it and the score. Then, narrowest first:

1. **Exclude the rule for that client or path** from the row itself. The
   exclusion goes on the site's policy, so it covers every site using it.
2. **Disable the rule** for the policy, if it is wrong for this application
   generally.
3. **Clone and tune it**, if it is right in principle and wrong in detail.

Every rule not currently running is listed on one page, so a temporary exclusion
does not quietly become permanent.

## Nothing appears in Traffic Monitor

- The site may have no policy attached — it is then a plain reverse proxy.
  Requests are still recorded, but nothing is inspected.
- The policy may be `Off`. In `DetectionOnly`, matches **are** recorded, marked
  `WOULD BLOCK` and `WOULD CHALLENGE`.
- Retention may be pruning faster than you expect. Check **Settings → General**.
- Under a flood, rows can be dropped rather than slow the proxy down. The journal
  says so every five minutes while it happens: *Traffic rows were dropped:
  requests arrived faster than they could be recorded*.

## Let's Encrypt fails

The certificate's page shows the last attempt, what the CA said, and when the
next attempt is due. The common causes, in order:

- **The name does not resolve to this host from the internet.** Validation comes
  from the CA's network, not from yours — split-horizon DNS that answers
  differently inside will not help it.
- **Port 80 is not reachable.** HTTP-01 validation always arrives there. EasyWAF
  binds it whatever ports your sites use, so this is usually a firewall or a NAT
  rule.
- **One name of several failed.** A request from a site's page covers every alias,
  and all of them must validate. The error names the CA's own explanation for
  each.
- **Rate limits.** Use the staging directory while you get validation working.

## Every internal client shows the same address

Hairpin NAT: traffic from inside your network that leaves and comes back arrives
with the router's address, so every internal visitor looks like one client.

That matters in three places — country rules, CAPTCHA clearance (one visitor
solving it clears everyone behind that address) and traffic history.

The fix is **split-horizon DNS**: resolve the site's name to EasyWAF's internal
address from inside, so internal traffic never leaves the network and arrives
with its real source address.

!!! danger "Do not fix this with trusted proxies"
    Listing the router under trusted proxies makes EasyWAF believe
    `X-Forwarded-For` from it. The router does not set that header, and anything
    that can reach EasyWAF through it could then claim any address it likes.

## The browser warns about the management certificate

Expected on a new installation: the generated `easywaf` certificate is
self-signed. [Replace it](tls.md#the-management-certificate) with your own under
**Settings → TLS**.

## A certificate is refused: "spells its curve out"

The key gives its elliptic curve by spelling out the curve's parameters rather
than by name. TLS clients, browsers included, accept only named curves, so the
certificate could never be served. OpenSSL and LibreSSL — the `openssl` on a
Mac — write keys this way unless told not to. Make a new key with
`-pkeyopt ec_param_enc:named_curve` and issue the certificate again from it; the
certificate carries the same spelled-out curve, so converting only the key
leaves the two not matching.

## A change is refused: "this request came from another page"

EasyWAF refuses a change that the browser says came from a page other than the
management interface itself — which is how a script on another site, or on a
sibling subdomain of the interface's own, could otherwise act with your
session. Make the change from the interface. If it happens there, something in
between — an extension, or a proxy rewriting requests — is presenting it as
coming from elsewhere.

## Sign-in says "Too many failed sign-ins from this address"

Ten wrong passwords from one address within 15 minutes, and that address is
refused for the rest of the 15 minutes. Wait it out. Below the limit, a
successful sign-in clears the count.

If everyone is refused at once, the interface is probably behind a proxy — EasyWAF
itself, or another — that is not listed as a trusted proxy under **Settings → Proxy**, so
every sign-in appears to come from that proxy's one address. List it, and each
person is counted by their own.

## Locked out of the interface

There is no password recovery — no mailer, and no second account to reset from.
If no administrator can sign in, the password has to be changed in the database
directly, with the service stopped. This is the reason to keep a second
administrator account.

## A build from source fails with `no such column`

The development database is behind the code. Migrations are applied by the
*running* binary, and `sqlx` validates queries against the schema at compile
time. Run `./scripts/dev-db.sh` and build again — see
[Installation](install.md#from-source).

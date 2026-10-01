# Tutorial: protect a site, start to finish

One worked example, in the order you would really do it: put a site behind
EasyWAF, give it HTTPS, watch what a policy would do to its traffic, deal with
the first false positive, and only then enforce. It takes about half an hour of
your time, spread over the few days you leave the policy watching.

The example is a shop at `shop.example.com`, whose application listens on
`http://10.0.0.20:3000`. Substitute your own names throughout.

Each step links to the page that covers it properly. This page is the route;
those are the map.

The interface has a quick version of this under **Tutorial** in the menu: six
steps, each a short form that does the thing, which gets a site as far as step 5
here in a few minutes. On a new installation it opens when you sign in, until
you finish it or tell it not to. This page is the same route by hand, on the
full pages, with the reasons.

## Before you start

- A Linux host for EasyWAF, x86_64 or arm64, that can reach the application.
- Ports **80** and **443** on that host open to your visitors, and **8443** open
  to you and nobody else — that is the management interface.
- The ability to change where `shop.example.com` points. You will not need to
  until step 3.

## 1. Install it and create the account

On Debian or Ubuntu:

```bash
curl -fsSL https://repo.easysys.io/easywaf/stable/debian/key.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/easysys.gpg
echo "deb [signed-by=/usr/share/keyrings/easysys.gpg] https://repo.easysys.io/easywaf/stable/debian ./" \
  | sudo tee /etc/apt/sources.list.d/easywaf.list
sudo apt update && sudo apt install easywaf
sudo systemctl enable --now easywaf
```

Other distributions and Docker are on the [Installation](install.md) page.

Open `https://<host>:8443/`. Your browser warns about the certificate, because
EasyWAF generated a self-signed one so the interface is never served in the
clear; accept it for now. There is no account yet, so the first page asks you to
create one.

!!! warning "Keep that password"
    There is no password recovery. See [First run](first-run.md#create-the-account).

## 2. Put the site behind EasyWAF

**Sites → Site Management → Create Site**:

| Field | Value |
|---|---|
| Site Name | `shop` |
| Hostname | `shop.example.com` |
| Upstream | `http://10.0.0.20:3000` |
| HTTP Ports | `80` |
| WAF Policy | none, for now |

Leave HTTPS empty; it comes in step 4. Save, and the port is bound at once.

The site is now a plain reverse proxy: forwarded and recorded, not inspected.
DNS still points at the application, so nobody is using it yet — which is the
moment to check it. Ask EasyWAF for the site by name without touching DNS:

```bash
curl -i --resolve shop.example.com:80:<easywaf-host-address> http://shop.example.com/
```

You should get your application's own page. If you get **404** from EasyWAF, the
hostname on the site does not match what you asked for; if **502**, EasyWAF
cannot reach the upstream. Both are in
[Troubleshooting](troubleshooting.md).

Open **Traffic Monitor** and the request you just made is there, marked
`PASSED`.

## 3. Send the traffic through it

Point `shop.example.com` at the EasyWAF host — the DNS record, or the port
forward on your router. From here every visitor arrives through EasyWAF, and
your application sees EasyWAF's address as the caller; the visitor's own address
is passed on in `X-Forwarded-For` and `X-Real-IP`
([what is sent upstream](sites.md#what-is-sent-upstream)).

Watch **Dashboard** for a few minutes. Requests should be arriving and passing.

## 4. Turn on HTTPS

Let's Encrypt validates over port 80, which is why the DNS change came first.

1. **Settings → TLS**: set the ACME contact address.
2. Open the site from **Site Management** and press **Request Certificate**.
   EasyWAF answers the challenge itself; nothing changes on the application.
3. On the same page set **HTTPS Ports** to `443` and choose the new certificate.
4. Check `https://shop.example.com/` in a browser.
5. Only then tick **Redirect HTTP to HTTPS**. It is separate, and off by
   default, so that turning HTTPS on never takes plain HTTP away from callers
   still using it.

Renewal is automatic. If you already have a certificate, upload it under
**Certificates → Certificate Manager** instead and skip the first two steps. See
[TLS and certificates](tls.md).

## 5. Create a policy that only watches

**Security Policy → Policy Manager → Create Policy**:

| Field | Value |
|---|---|
| Policy Name | `websites` |
| Rule Engine Mode | `DetectionOnly` |
| Score Threshold | `10` |
| Rule sets | the basic sets, already ticked |

Leave everything else alone and press **Create Policy**. Then open the `shop`
site and choose `websites` under **WAF Policy**.

In `DetectionOnly` the rules run on every request and nothing is refused. That
is the whole point of this step: you are about to find out what the policy
*would* do before it does it.

Prove it is looking. This request carries a signature that blocks on its own:

```bash
curl -i "https://shop.example.com/?q=xp_cmdshell"
```

It reaches your application as usual. In **Traffic Monitor** its row says
`WOULD BLOCK`, with the rule that matched and the score.

## 6. Leave it, then read what it found

Give it a few days of ordinary use — long enough to include whatever your site
does weekly: the newsletter going out, the stock import, the editor publishing a
page.

Then open **Traffic Monitor**, choose the site and a window that covers those
days, and filter to what would have been blocked. Every row is one of two
things:

- **An attack.** A scanner asking for `/.env`, a path with `../../etc/passwd` in
  it, a query string with `union select`. You will have some; everything on the
  internet does. These are what you want refused.
- **Your own traffic.** A real user, or a real integration, doing something that
  looks like an attack to a rule. These are false positives, and each one would
  have been an outage for that user had the policy been enforcing.

`SCORED` rows are worth a glance as well: something matched but stayed under the
threshold. They are usually the first sign of both a probe and a rule about to
become a false positive. The verdicts are explained under
[Traffic](traffic.md#verdicts).

## 7. Deal with a false positive

Suppose the shop's editor saves a product description containing HTML, and a
rule from the cross-site scripting set calls it an attack. The row is a `POST`
to `/admin/products`, from the office's address, marked `WOULD BLOCK`.

You have three answers, narrowest first:

1. **For that caller.** Press **exclude for this IP** on the row. That rule stops
   running for that address; everyone else is still checked by it.
2. **For that path.** Under **Security Policy → Rule Exclusions**, exclude the
   rule for the path prefix `/admin`. Right when the editor works from more than
   one address.
3. **For the whole policy.** Untick the rule on the policy's **Rules** tab. Right
   only when the rule is wrong for this application altogether.

Take the narrowest that fixes it. An exclusion belongs to the policy, so it
applies on every site using that policy, and the confirmation says how many.

When it is the *caller* that is trustworthy rather than the rule that is wrong —
your monitoring, a partner's integration — use **Allow** on the row instead. It
puts the address on the policy's allow list, which skips every check for it.

Repeat until the only rows that would have been blocked are ones you are happy
to block. [Policies and rules](policies.md#false-positives) covers each option.

## 8. Enforce

Open the policy, set **Rule Engine Mode** to `On`, and save. Then:

```bash
curl -i "https://shop.example.com/?q=xp_cmdshell"
```

```http
HTTP/1.1 403 Forbidden
```

The page that comes back says the request was blocked and gives a reference —
the time and your address — and nothing about which rule matched. That is on the
row in Traffic Monitor, now marked `BLOCKED`. When a visitor writes in to say
they were blocked by mistake, the reference is how you find their row, and step
7 is what you do about it.

Keep an eye on Traffic Monitor for the first day. Enforcing changes nothing
about what matches, only what happens next, so there should be no surprises —
but this is the day you would see one.

## 9. Stop the ones that keep trying

A scanner refused once tries again, two hundred times. **Smart Protect** blocks
an address the rules keep refusing: by default, three refusals within a minute
and it is refused for ten.

Before switching it on, open **Settings → Smart Protect**, choose the `websites`
policy in the preview, and read what the numbers would have done to the traffic
you have already recorded. The line that matters is how many of the requests it
would have refused were in fact served successfully — those are real users. If
there are any, look them up and fix the rule that tripped them first.

Then tick **Enable Smart Protect** on the policy. Blocked addresses are listed on
the same Settings page, each with an **Unblock** button. See
[Smart Protect](smart-protect.md).

## 10. Refuse known-bad addresses outright

**Security Policy → IP Lists** carries published lists that update themselves
daily. For the `websites` policy:

| List | Set it to |
|---|---|
| Hijacked netblocks | Block |
| Compromised hosts | Challenge |
| Tor exit nodes | Off, unless you have a reason |

*Challenge* shows a CAPTCHA, so a wrongly listed address is slowed down rather
than shut out. See [IP lists](ip-lists.md#published-lists).

## 11. Make sure you can get it back

Everything you have just set up is in one database file.

- **Settings → Backup**: switch on scheduled snapshots, and press **Take one
  now** to see it work. Have your host's own backup copy the `backups/`
  directory somewhere else — a snapshot on the same disk does not survive losing
  the host.
- **Export the configuration** on the same page gives you a readable file of
  sites, policies and settings, which imports with a preview on another host.

A snapshot contains every private key and password hash; treat it as one. See
[Backup and restore](backup.md).

## Where you are now

The shop is served over HTTPS with a certificate that renews itself, inspected
by a policy you have watched on its own traffic, with repeat offenders and
known-bad addresses refused, and a way back if something goes wrong.

For the next site, most of this is already done: create the site, give it the
same policy if it faces the same traffic, and request its certificate. Give it a
policy of its own — **Start from an existing policy** copies one — when it needs
exceptions the others should not have.

From here:

- [Add accounts](accounts.md) for people who should look but not change.
- [Send flow logs to a collector](logging.md) for history beyond the appliance.
- [Run several backends](sites.md#upstreams) behind one site.
- Read [What EasyWAF does not do](limitations.md).

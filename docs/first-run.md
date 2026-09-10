# First run

## Create the account

Open `https://<host>:8443/`.

There is no account yet, so EasyWAF asks you to create one. Plain HTTP on 8080
redirects to the TLS port, so the password is never typed over a cleartext
connection.

!!! warning "There is no password recovery"
    EasyWAF has no mailer and no second account to reset from. A lost
    administrator password means editing the `users` table in the database by
    hand. Keep it somewhere safe.

Your browser will warn about the certificate. On first start EasyWAF generates a
self-signed one named `easywaf` and stores it under **Certificates** — it is
there so the management interface is never served over plain HTTP, not because
it is trustworthy. [Replace it](tls.md#the-management-certificate) with your own
to clear the warning.

## Add a site

**Sites → Add site**:

| Field | Example | Notes |
|---|---|---|
| Site name | `shop` | A label for you. It names the site in the interface and in the logs |
| Hostname | `example.com` | The `Host:` header to route on — bare name, no scheme, no port |
| Aliases | `www.example.com` | Optional. Other hostnames the same site answers for, one per line |
| Upstream target | `http://127.0.0.1:3000` | Where requests are forwarded — a full URL including the scheme |
| HTTP ports | `80` | One or more, comma separated. Bound as soon as you save |
| HTTPS ports | `443` | Optional. Empty means plain HTTP only |
| Certificate | one you uploaded | Required to serve HTTPS |

The listener is bound the moment you save, so adding a site on a new port does
not need a restart. Requests whose `Host:` matches no enabled site get a 404.

At this point the site is already being proxied. It has no policy yet, so
nothing is inspected — it is a plain reverse proxy, with the per-site security
headers applied and every request recorded.

See [Sites](sites.md) for aliases, ports, headers and what happens when you
disable one.

## Attach a policy

Under **Policies**, create a policy and choose the rule sets it should load. A
new policy defaults to **DetectionOnly**: rules run, matches are recorded, and
nothing is blocked.

Then assign it to the site under **Sites → Settings**.

Leave it in DetectionOnly for a while and watch [Traffic](traffic.md). That is
the safe way to find out what a policy would do to your traffic before it does
it. When the only things scoring are things you are happy to block, switch the
policy to **On**.

## Check that it is working

With the policy set to `On`, send a request carrying a signature that blocks on
its own, regardless of score:

```bash
curl -i "http://your-site/?q=xp_cmdshell"
```

```http
HTTP/1.1 403 Forbidden
content-type: text/plain; charset=utf-8

WAF block rule matched: SQLi: xp_cmdshell (MSSQL)
```

In DetectionOnly the same request reaches your application as usual and appears
in Traffic Monitor marked as what would have happened — which is the point of
the mode.

## What to do next

- [Get a real certificate](tls.md#lets-encrypt) — EasyWAF answers the Let's
  Encrypt challenge itself, so there is nothing to configure on the backend.
- [Send flow logs to a collector](logging.md) if you want history beyond what
  the appliance keeps.
- [Add accounts](accounts.md) for anyone who needs to look but not touch.
- Read [What EasyWAF does not do](limitations.md).

# EasyWAF

**A self-contained web application firewall and HTTP reverse proxy, in a single Rust binary.**

EasyWAF sits in front of your web applications, inspects every request against a rule
engine, and blocks SQL injection, XSS, path traversal, command injection and scanner
traffic before it reaches your backend. Sites, rules, policies and certificates are all
managed from a web GUI — there is no configuration language to learn and no file to edit to
add a site.

* [Source and full documentation](https://github.com/easysysio/EasyWAF)
* [Docs site](https://easysys.io/easywaf/)

---

## Quick start

```bash
docker run -d --name easywaf \
  -p 8443:8443 -p 8080:8080 -p 80:80 \
  -v easywaf-data:/data \
  easysysio/easywaf:latest
```

Then open **https://localhost:8443/**.

On the first start there is no account yet, so EasyWAF asks you to create one — pick a
username and password there. Nothing is seeded, and there is no default password to change
afterwards.

Your browser will warn about the certificate. EasyWAF generates a self-signed one on first
run so the management interface is never served over plain HTTP; replace it with your own
under **Certificates**, then select it under **Settings → TLS**.

> **There is no password recovery.** No mailer, no second account. Keep the password you set.

---

## Ports

| Port | What it is |
|---|---|
| `8443` | Management GUI, over HTTPS |
| `8080` | Redirects to 8443. Publishing it is optional |
| `80`, `443`, … | Whatever ports you give your sites — publish those you use |

Proxy listeners are bound from the sites you define in the GUI, not from configuration, so
publish the container ports your sites will listen on.

---

## Data

The database holds everything: sites, policies, rules, certificates, users and settings.

```
-v easywaf-data:/data
```

**Mount it, or you lose your configuration when the container is replaced.** The image sets
`DATABASE_URL=sqlite:///data/easywaf.db`; point it elsewhere with `-e DATABASE_URL=...` if
you mount the volume somewhere else.

There is no backup or export yet — to take a copy, stop the container and copy the file out
of the volume.

---

## docker compose

```yaml
services:
  easywaf:
    image: easysysio/easywaf:latest
    container_name: easywaf
    restart: unless-stopped
    ports:
      - "8443:8443"   # management GUI
      - "8080:8080"   # redirects to 8443
      - "80:80"       # a site listening on 80
    volumes:
      - easywaf-data:/data
volumes:
  easywaf-data:
```

---

## Adding a site

In the GUI, **Sites → Add site**:

* **Server name** — the `Host:` header to route on, e.g. `example.com`
* **Target** — the upstream, e.g. `http://10.0.0.5:3000`
* **Listen port** — the port EasyWAF accepts that site's traffic on

The listener binds as soon as you save; no restart. A site with no WAF policy attached is
simply a reverse proxy — traffic is forwarded and logged.

To serve it over HTTPS, add a **TLS port** and pick a certificate. Certificates are chosen
per site by SNI, so many sites can share one HTTPS port.

**Reaching your backends:** an upstream on the Docker host is not `127.0.0.1` from inside
the container — that is the container itself. Use `host.docker.internal` on Docker Desktop,
the host's LAN address, or put EasyWAF on the same Docker network as the backend and use
its service name.

---

## Configuration

Everything operational lives in the database and is managed from the GUI. `config.toml`
holds only what must be known before the database is open — the ports above — and can be
overridden:

```bash
docker run -d -v ./config.toml:/opt/easywaf/config.toml ... easysysio/easywaf:latest
```

Nothing security-sensitive is configured in it. The key that signs session cookies is
generated on first run and stored in the database, so no installation runs with a value
published in the image.

---

## Tags

* `latest` — the most recent release
* `X.Y.Z` — a specific version, e.g. `0.4.3`

Multi-arch: `linux/amd64` and `linux/arm64`.

---

## What it does not do

Worth knowing before you deploy:

* **WebSockets do not proxy** — upgrades are not tunnelled, so anything with live updates
  breaks
* **No HTTP/2 to clients**, and routing is by `Host:` only — no path prefixes or wildcards
* **One upstream per site** — no load balancing or health checks yet
* **Requests only** — responses are not inspected
* **No ACME yet** — certificates are uploaded by hand
* **One account, no roles**, and no backup or configuration export

The [full list](https://github.com/easysysio/EasyWAF#what-easywaf-does-not-do) is kept
current in the repository, along with which release each is scheduled for.

---

Licensed under GPL-3.0.

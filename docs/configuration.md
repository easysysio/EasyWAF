# Configuration

Almost everything lives in the database and is managed from the interface. The
file holds only what has to be known **before** the database is open.

## config.toml

`/opt/easywaf/config.toml` for a package installation. The path is resolved
relative to the service's working directory, so keep the file where the package
put it. Restart to apply an edit.

```toml
[proxy]
gui_port     = 8080      # management interface: plain HTTP, redirects to gui_tls_port
gui_tls_port = 8443      # management interface: served here, over TLS
geoip_db     = ""        # external MaxMind-format .mmdb; empty = the bundled database

[logging]
dir       = "/var/log/easywaf"   # audit.log, one file per day
keep_days = 14                   # then deleted; 0 keeps everything
```

Nothing security-sensitive is configured here. The key that signs session and
CAPTCHA clearance cookies is generated on first run and kept in the database, so
no installation can be left using a default that was published in a public
repository, and the administrator account is created through the interface at
first start.

`geoip_db` optionally points at a MaxMind-format `.mmdb` to use instead of the
bundled DB-IP Lite country database — a fresher DB-IP file, or MaxMind GeoLite2.
Leave it empty for the bundled one.

!!! note "`http_port` and `acme_webroot` are ignored"
    They are placeholders from 0.1.0, left so an old file still parses. The ports
    EasyWAF listens on come from the sites you define, and ACME needs no webroot.

## DATABASE_URL

The database defaults to `easywaf.db` in the working directory. Override it with
the environment variable:

```bash
DATABASE_URL=sqlite:///data/easywaf.db
```

An environment variable rather than a setting because the case that needs it is a
container, where `config.toml` is baked into the image and the database has to
sit on a mounted volume to survive at all.

## Settings in the interface

| Section | Holds |
|---|---|
| **General** | Traffic retention, and the maintenance message shown for a disabled site |
| **TLS** | Version profile, cipher suites, the management certificate, the ACME contact address and directory |
| **Proxy** | Trusted proxies — whose `X-Forwarded-For` is believed |
| **Logging** | The syslog collector for flow logs |
| **Rule Updates** | Whether to check the channel, and which channel |
| **Accounts** | Accounts and roles |

Sites, policies, rules, exclusions and certificates have pages of their own.

## Where things live

| Path | What |
|---|---|
| `/usr/bin/easywaf` | the binary — templates, static assets and the bundled rule sets are compiled in |
| `/opt/easywaf/config.toml` | the file above |
| `/opt/easywaf/easywaf.db` | everything else: sites, policies, rules, certificates, accounts, traffic |
| `/opt/easywaf/rules-cache/` | the mirror of the rule channel |
| `/var/log/easywaf/` | the audit log |

## Backing up

There is no export yet ([0.13.0](limitations.md#managing-it)). Everything is in
the one SQLite file, so with the service stopped:

```bash
sudo systemctl stop easywaf
sudo cp /opt/easywaf/easywaf.db /somewhere/safe/easywaf-$(date +%F).db
sudo systemctl start easywaf
```

That file contains the private keys of every certificate stored in EasyWAF.
Treat the copy accordingly.

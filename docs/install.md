# Installation

EasyWAF ships as a single binary with a systemd unit. Packages are published for
**x86_64** and **arm64**; your package manager picks the right one.

## From the package repository

=== "Debian / Ubuntu"

    ```bash
    curl -fsSL https://repo.easysys.io/easywaf/stable/debian/key.gpg \
      | sudo gpg --dearmor -o /usr/share/keyrings/easysys.gpg
    echo "deb [signed-by=/usr/share/keyrings/easysys.gpg] https://repo.easysys.io/easywaf/stable/debian ./" \
      | sudo tee /etc/apt/sources.list.d/easywaf.list

    sudo apt update
    sudo apt install easywaf
    sudo systemctl enable --now easywaf
    ```

=== "RHEL / Fedora"

    ```bash
    sudo tee /etc/yum.repos.d/easywaf.repo >/dev/null <<'EOF'
    [easywaf]
    name=EasyWAF
    baseurl=https://repo.easysys.io/easywaf/stable/redhat
    enabled=1
    gpgcheck=1
    gpgkey=https://repo.easysys.io/easywaf/stable/redhat/key.gpg
    EOF

    sudo dnf install easywaf
    sudo systemctl enable --now easywaf
    ```

=== "openSUSE / SLES"

    ```bash
    sudo zypper addrepo -fg https://repo.easysys.io/easywaf/stable/redhat easywaf
    sudo zypper install easywaf
    sudo systemctl enable --now easywaf
    ```

=== "Manual download"

    For hosts with no access to the repository, take the `.deb` or `.rpm` for
    your architecture from the
    [releases page](https://github.com/easysysio/EasyWAF/releases):

    ```bash
    sudo dpkg -i easywaf_*_amd64.deb     # or _arm64.deb
    sudo rpm  -i easywaf-*.x86_64.rpm    # or .aarch64.rpm
    sudo systemctl enable --now easywaf
    ```

    Upgrades then mean fetching the next package by hand. Where the host has
    network access, the repository is the easier path.

### What the package installs

| Path | What it is |
|---|---|
| `/usr/bin/easywaf` | the binary |
| `/opt/easywaf/` | working directory: `config.toml`, the bundled rule sets, and the database |
| `/opt/easywaf/easywaf.db` | the database, created on first start |
| `/var/log/easywaf/` | the audit log, created and owned by the systemd unit |
| `/etc/systemd/system/easywaf.service` (or the packaged unit path) | the service |

Templates and static assets are compiled into the binary, so there is nothing to
serve from disk and nothing to keep in step with an upgrade.

The service runs as root, so a site can bind a privileged port such as 80.

## Container

```bash
docker run -d --name easywaf \
  -p 8443:8443 -p 8080:8080 -p 80:80 \
  -v easywaf-data:/data \
  easysysio/easywaf:latest
```

Multi-arch (amd64 and arm64). The database lives in `/data`, so mount a volume
there or it goes with the container. Publish whichever ports your sites listen
on — 8443 is the management interface and 8080 redirects to it.

To change ports or put the database elsewhere, mount your own configuration file
or set the environment variable:

```bash
docker run -d \
  -v ./config.toml:/opt/easywaf/config.toml \
  -e DATABASE_URL=sqlite:///data/easywaf.db \
  ... easysysio/easywaf:latest
```

## Ports

| Port | What answers there |
|---|---|
| 8443 | the management interface, over TLS |
| 8080 | plain HTTP, redirecting to 8443 |
| 80 | bound unconditionally, because Let's Encrypt HTTP-01 validation always arrives there |
| whatever your sites use | the proxied sites themselves |

!!! warning "Keep the management ports off the public internet"
    Bind 8443 and 8080 to a management network, or firewall them. The interface
    requires an account and is served over TLS, so this is defence in depth
    rather than the only thing protecting the appliance — but it is worth doing.

## From source

Requires a stable Rust toolchain and `sqlite3`.

`sqlx`'s query macros validate SQL against a real schema **at compile time**, so
a database must exist and be current before you build:

```bash
./scripts/dev-db.sh
cargo build --release
DATABASE_URL=sqlite://easywaf.db ./target/release/easywaf
```

`dev-db.sh` applies any migrations the database is missing, keeping whatever data
is in it, and creates it if it does not exist. On a database that is already
current it does nothing.

!!! note "The usual confusing build failure"
    Migrations are applied by the *running* binary, so a development database
    that has not been run against a recent build falls behind — and `cargo build`
    then fails with a wall of `no such column: …` errors that look like faults in
    the code. Run `./scripts/dev-db.sh` and build again. With no database at all
    the failure is different: `unable to open database file`, from inside the
    macro expansion.

Run the binary from the repository root: rule sets are resolved relative to the
working directory.

## Upgrading

Upgrade through the package manager. Migrations run at startup, so there is no
separate step, and the database keeps everything in it.

```bash
sudo apt update && sudo apt install --only-upgrade easywaf   # Debian / Ubuntu
sudo dnf upgrade easywaf                                     # RHEL / Fedora
```

Each release's notes list anything an upgrade needs from you. Two older ones
still matter:

!!! danger "Upgrading from 0.4.0 or 0.4.1 — check your administrator password"
    Those versions seeded an `admin` / `admin` account, and an upgrade does not
    touch existing accounts. If you never changed it, change it now under
    **Account → Change Password**. Installations from 0.4.2 onwards have no
    default account at all.

!!! danger "Upgrading from 0.3.x — the interface has moved"
    It is now on **8443 over HTTPS**, and 8080 does nothing but redirect there.
    If you firewalled 8080 to keep the interface private and opened nothing
    else, **open 8443 to the same callers before upgrading** — otherwise 8080
    will redirect you to a port your own firewall is blocking.

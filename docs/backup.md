# Backup and restore

**Settings → Backup**, for administrators. It deals in two different files, for
two different jobs:

| | A **snapshot** | An **export** |
|---|---|---|
| What it is | The whole database, exactly | A readable description of the configuration |
| For | Recovering when the host is gone | Cloning an installation, reviewing a change, version control, support |
| Format | SQLite `.db` | TOML `.toml` |
| Holds traffic history | Yes | No |
| Holds private keys and password hashes | **Always** | Only if you tick the box |
| Put back with | Restore | Import |

For recovery, trust a snapshot. An export leaves out whatever is not
configuration, and anything it leaves out is gone after an import.

## Snapshots

**Download a snapshot** takes one while EasyWAF runs, without stopping
anything, and sends it to your browser. SQLite copies the database through its
own consistent view, including writes it has not yet folded into the main
file — which a copy of the file itself would miss.

!!! warning "A snapshot is a secret"
    It holds the private key of every certificate the appliance serves, every
    account's password hash, and the key that signs sessions. Keep it where
    you would keep those: not in a ticket, not in a shared folder, not in git.

### Scheduled snapshots

Off until you switch them on. Once on, EasyWAF takes one a day and keeps the
newest few — seven unless you say otherwise — in `backups/` beside the
database, readable by EasyWAF's own account only. **Take one now** proves it
works without waiting a day, and each kept snapshot can be downloaded from the
list.

They guard against a bad change or a damaged database. **They do not guard
against losing the host** unless something copies that directory somewhere
else — have your own backup do so. Each file is a complete, consistent
database, so anything that copies files can take it.

## Restoring a snapshot

Upload the `.db` file. It is checked before anything else happens — that it is
a SQLite database, undamaged, an EasyWAF database, and not from a newer
version of EasyWAF than this one — and then **held**. The page shows what it
holds: the version that last ran it, its sites, policies, rules,
certificates, accounts and newest traffic. Nothing is replaced until you press
**Restore it**.

A restore replaces the whole database, so it is applied by a restart. EasyWAF
stops cleanly and starts again by itself, swapping the snapshot in as it
starts — a few seconds without serving sites. Afterwards you sign in with the
**snapshot's** accounts: it carries its own, and its own session key.

**A restore either works or undoes itself.** The database it replaces is kept,
whole, before anything moves. If the snapshot will not start — it will not
open, or this version cannot bring its schema up to date — the next start puts
the previous database back and the page says so. The replaced database stays
downloadable, one generation back.

A snapshot from an older EasyWAF is fine: it is brought up to date as it
starts. One from a newer EasyWAF is refused, and the message names the version
to upgrade to first.

!!! note "Restarting needs a service manager"
    EasyWAF stops itself with an exit code that systemd's `Restart=on-failure`
    answers, which is how the packaged unit runs it. Run another way, start it
    again yourself after pressing Restore — the snapshot is applied as it
    starts.

## Exporting the configuration

**Export** writes a TOML file of what the appliance is configured to do:
policies, the rule sets they hold and the rules they switched off, rules
written here, exclusions, sites with their upstreams, aliases and ports,
certificates, IP entries, published-list choices, country rules and settings.

- **Objects are named, never numbered.** A site names its policy and its
  certificate; nothing in the file is a database id, which would mean nothing
  on another host.
- **A rule from an installed set travels as the set.** It cannot have been
  edited — editing one makes a copy — so the set's name and version are the
  whole truth, plus the numbers of any you switched off. Rules written here
  travel in full.
- **Everything is sorted**, so exporting an unchanged configuration twice gives
  the same file apart from its timestamp, and a diff between two exports shows
  what changed and nothing else.

Never in an export: traffic history, the session key, the ACME account key,
this appliance's own management certificate (unless a site serves with it),
and anything the appliance keeps about itself rather than configuration you
chose.

**Private keys** and **accounts** are each in only when you tick their box.
A file that carries either says so in its first lines and in its header, and
the page asks you to confirm before the download.

## Importing a configuration

**An import makes this installation match the file.** What the file has is
created or changed; what only this installation has is removed. Two
exceptions: accounts are only ever added or updated — never deleted, and never
the account running the import — and this appliance's own management
certificate stays.

Upload the `.toml` file and a **preview** lists every addition, change and
removal, and every reason the import cannot go ahead. Nothing changes until
you press **Import it**. Among the reasons it will refuse:

- a key it does not know — a misspelling is named, not silently ignored, and a
  file from a newer EasyWAF says to upgrade;
- a setting that belongs to one host — the session key, which certificate the
  management page uses;
- a rule whose pattern does not compile, or whose zone the engine would read
  as *any*, inspecting more than was meant;
- a site whose policy is not in the file, whose certificate the file carries
  without its key and this installation does not have, that has no upstream
  switched on, or that would take the management interface's own port.

Rule sets are installed from **this** installation's rule channel, verified as
any installation is. If the file was exported at a different version of a set,
the preview says which version will be installed.

Like a restore, an import is applied to a copy of the database and swapped in
by a restart — a few seconds without serving sites. If the result will not
start, the current configuration is put back. Your session carries on: an
import keeps this installation's session key.

### Moving a configuration to a new host

Without private keys, a certificate travels as its public half. On the new
host, either export with keys, or upload the certificate there first — the
preview names any site that would be left without one, and refuses until it
has one.

## From the command line

A snapshot can also be taken without the interface, while EasyWAF runs:

```bash
sudo sqlite3 /opt/easywaf/easywaf.db ".backup '/somewhere/safe/easywaf-$(date +%F).db'"
```

With the service stopped, copying `easywaf.db` alone is enough — stopping
folds the write-ahead log into it.

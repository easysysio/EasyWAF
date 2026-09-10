# Accounts and roles

## Roles

| Role | Can |
|---|---|
| `admin` | See and change everything |
| `viewer` | See the dashboard, traffic, sites, policies, rules, exclusions and certificates. Change nothing |

The interface reflects the role: controls a viewer cannot use are not offered,
and the header shows a `viewer` badge. A viewer who reaches an administrator's
page by URL gets a 403 that says why, rather than being bounced to a login form
they have already completed.

Authorisation is declared per route rather than checked by each handler, so a
page that needs an administrator cannot be written without saying so.

A viewer can see a certificate's details — subject, issuer, validity, the names
it covers, its fingerprint — because that page shows only what the certificate
says about itself in public. The private key is never rendered and cannot be
exported.

## Managing accounts

**Settings → Accounts**: create an account, change a role, reset a password, sign
an account out everywhere, suspend it, or delete it.

**Suspending** keeps the account and its history and refuses it a session.
Deleting removes it. Each account's last sign-in is recorded, so a dormant
account is visible — which is usually the reason to suspend one.

EasyWAF refuses to leave itself without an administrator: the last enabled admin
cannot be demoted, suspended or deleted.

## Sessions

A session lasts 8 hours, and each request checks the account behind the cookie
rather than trusting the cookie alone. That is what makes the following take
effect immediately rather than within 8 hours:

- changing a password
- changing a role — a demoted administrator is a viewer on their next request
- suspending or deleting an account
- **sign out everywhere**

Everyone changing their own password does so under **Account → Change Password**,
which is available to viewers as well: an account changing its own password is
not an administrative act.

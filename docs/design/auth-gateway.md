# Design note — authentication gateway

Status: **proposed 2026-09-10**, not yet scheduled — see [roadmap.md](roadmap.md).

First cut agreed the same day: **local accounts and LDAP**, turned on per site
and scopeable to a path prefix. OIDC is a second release. SAML is argued
against below rather than deferred.

## What this adds

EasyWAF currently asks two questions about a request. The rules ask *what is
this* — a pattern, a score, a threshold. The CAPTCHA challenge asks *is there a
person here*. Both are properties of the request.

This adds a third, and it is a different kind: *who is this*. Nothing else in
the product identifies a caller, and identity is not a property of a request —
it is established once and carried, which is why this needs a session and the
other two do not.

The effect is that a site behind EasyWAF can require a sign-in before the
application behind it is reachable at all. The application need not know: an
admin panel with no authentication of its own, a staging site, an internal
tool, or an application whose own login is fine but whose `/admin` should not
be reachable from the internet by anyone who has not already proved who they
are.

## What it reuses, and the three places it must not

The CAPTCHA challenge is already this shape. It interrupts a request, serves a
page on a reserved path (`/__easywaf/verify`), and on success sets an
HMAC-signed clearance cookie that lets subsequent requests through for thirty
minutes. The gateway is the same mechanism with a different proof and a longer
clearance, and `challenge.rs` is the model to follow.

Three things must differ, and each is a security property rather than a
preference:

**1. The session must not be bound to the client address.**
`challenge::make_clearance` signs the client IP into the cookie, which is
correct for a thirty-minute CAPTCHA and wrong for a sign-in: a phone moving
from wifi to cellular would be signed out mid-session. Worse on an estate
behind hairpin NAT, where every internal client already appears as the router's
address — an address-bound session would mean one person signs in and everyone
inside the network is signed in as them.

**2. It must not use the `users` table.**
Those are management accounts; they open the WAF's own GUI. A site visitor who
is also a row in `users` is one configuration mistake away from being an
administrator of the appliance in front of the site. Site identities live in
their own tables, in their own namespace, and the two are never joined.

**3. Inbound identity headers must be stripped.**
The gateway tells the application who the user is by setting a header. If a
client can set that header itself, the gateway is an authentication bypass with
extra steps. Stripping is unconditional on a protected site, before anything is
set, and is not a configurable behaviour.

## Scope: per site, and per path within it

A site, optionally narrowed to path prefixes, with a bypass list that is never
challenged.

Path scoping is not a refinement; it is what makes the feature usable at all in
front of the applications people actually run. **A browser-redirect gateway in
front of Nextcloud or Immich breaks them immediately.** The desktop sync
client, the mobile apps, WebDAV, CalDAV and CardDAV do not follow an HTML
redirect to a login form — they receive a login page where they expect a `401`
and fail, quietly and confusingly, with the user's files or photos silently no
longer syncing. The same is true of anything with an API, a webhook receiver or
a mobile client.

So the useful configuration in front of a real application is not "protect the
site" but "protect `/settings` and `/admin`", and the GUI should make that the
obvious thing to do rather than a thing to discover afterwards.

Two supports for the same problem:

* **Bypass prefixes** — never challenged, whatever the protected paths say.
  `/remote.php`, `/api`, `/.well-known` are the shapes that will appear.
* **HTTP Basic as an alternative proof.** On a protected path, a request
  carrying `Authorization: Basic` is checked against the same realm and let
  through without a cookie. It is the same credential check without the
  interstitial, it makes `curl` and scripts work, and it costs little because
  the backends are already there. TLS only — never accepted on the plain-HTTP
  listener.

## Where it runs

After the pipeline, immediately before the request is proxied upstream.

The alternative — authenticating first, so unauthenticated traffic never
reaches the rules — is cheaper and worse. Attack traffic aimed at a protected
site would then appear in Traffic Monitor as "sent to a login page" rather than
as what it was, and visibility of what is being attempted is most of what this
product is for. Running the rules first also means the challenge fires *before*
the login form, which is the right order in front of a credential-stuffing
attempt: filter the bots, then offer the form.

One exemption, and it needs stating because it is a hole deliberately made:
**the gateway's own login POST is not body-inspected.** The body is a password,
and passwords are high-entropy strings full of quotes, semicolons and
backslashes — exactly what an SQL injection rule matches. A false positive
there does not block a request, it locks every user out of the site, and the
person who could fix it cannot sign in to do so. The path and headers are still
inspected, and the lockout below still applies.

## The session

A signed cookie, stateless, verified by HMAC the way the clearance cookie is:

```
v1.<realm>.<subject>.<issued>.<expires>.<epoch>.<signature>
```

signed over all fields plus the site id, so a cookie for one site cannot be
presented to another. `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`.

* **Absolute lifetime** — the "certain time" this is for. Default 8 hours.
* **Idle timeout** — default 1 hour, implemented by re-minting the cookie as it
  is used, so it slides without a database write.
* **Epoch** — a counter on the realm and, for local accounts, on the user.
  Bumping it invalidates every session at once, which is what "sign everyone
  out" means and what disabling an account has to do. This is exactly the
  mechanism 0.8.0 added for management sessions, for the same reason.

**LDAP revocation is bounded by the session lifetime, not by LDAP.** An account
disabled in the directory keeps its EasyWAF session until it expires, because
nothing re-checks mid-session. That is a real limitation, it belongs in the GUI
next to the lifetime field rather than being discovered, and the answer for an
installation that cares is a short lifetime. A periodic revalidation interval
is a later refinement.

## Backends

**Local.** Accounts in EasyWAF's own tables, bcrypt-hashed, per realm. The
whole feature for a home lab or a single admin panel, and the way to test the
gateway without a directory to point at.

**LDAP.** `ldap3`: bind as a service account, search for the user, bind as the
user to check the password. LDAPS and StartTLS, with certificate verification
on by default. An optional group filter, which is the only authorization this
release has — membership decides who gets in, and beyond that everyone in the
realm is equal.

**OIDC — the second release, not this one.** Well supported in Rust
(`openidconnect`), and it is what most people mean in 2026: Entra, Okta,
Google, Keycloak, Authentik. It is left out of the first cut because it brings
the redirect and callback dance, provider metadata, and state and nonce
handling — a second hard thing on top of the gateway plumbing, which is itself
the hard part.

**SAML — argued against.** It is XML signature verification, where the failure
mode is a forged assertion and the Rust library situation is thin enough that
the verification would be substantially hand-rolled. Nearly everything that
speaks SAML also speaks OIDC. If a specific deployment demands it, that is the
moment to reconsider — not before.

## Identity to the application

Set on the proxied request, and stripped from the inbound one first:

```
X-Forwarded-User    the subject
X-Forwarded-Groups  when the realm resolves them
```

Header names are configurable, because an estate may already use one of these
for something else — and if it does, the gateway must be the thing that stops
trusting what arrives, not the thing that quietly keeps it.

A signed JWT instead of plain headers is the stronger version, for an
application that wants to verify EasyWAF said it rather than trust its network
position. Worth doing when something asks for it; the header form is what
applications actually read today.

## Brute force

A login form on the edge is a credential-stuffing target from the hour it goes
up, and this cannot wait for rate limiting (0.15.0).

Per-username and per-address counters, in memory and bounded the way the
challenge store is: N failures in a window, then refuse that username for M
minutes. Lost on restart, which is acceptable and should be said out loud
rather than implied.

Every sign-in, failed sign-in and lockout goes to the **audit log** — the one
0.9.0 built, with `realm=` and `site=` added. They are authentication events
and they belong with the others; the flow line records the request itself.

## Data model

```sql
CREATE TABLE auth_realms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    kind            TEXT    NOT NULL,          -- 'local' | 'ldap'
    session_minutes INTEGER NOT NULL DEFAULT 480,
    idle_minutes    INTEGER NOT NULL DEFAULT 60,
    epoch           INTEGER NOT NULL DEFAULT 0,
    config          TEXT,                      -- JSON: URL, base DN, filters
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE auth_users (                      -- local realms only
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    realm_id      INTEGER NOT NULL REFERENCES auth_realms(id) ON DELETE CASCADE,
    username      TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    display_name  TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1,
    epoch         INTEGER NOT NULL DEFAULT 0,
    last_login    TEXT,
    UNIQUE(realm_id, username)
);

CREATE TABLE site_auth (
    site_id  INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    realm_id INTEGER NOT NULL REFERENCES auth_realms(id),
    enabled  INTEGER NOT NULL DEFAULT 1,
    paths    TEXT,        -- prefixes to protect; empty = the whole site
    bypass   TEXT,        -- prefixes never challenged
    basic    INTEGER NOT NULL DEFAULT 0,   -- accept HTTP Basic as well
    headers  TEXT         -- JSON: header names, when not the defaults
);
```

The LDAP service-account password sits in `config`, in the database, in the
clear — the same treatment certificate private keys already get in `certs`. It
is consistent, and it is worth saying rather than leaving to be discovered.

## GUI

* **Settings › Authentication** — realms. Create a local or LDAP realm, test
  the bind before saving (an LDAP realm that cannot bind should fail while
  somebody is looking at it, not at the first sign-in), manage local accounts,
  sign everyone out.
* **Site › Authentication** — pick a realm, protected paths, bypass paths,
  session lifetime, Basic on or off. With the Nextcloud problem stated on the
  page, beside the paths field, where somebody about to break their own sync
  clients will read it.
* **Traffic Monitor** — a request bounced to the login page is a verdict, and a
  request from a signed-in user carries a name worth showing.

## Cross-repository: the flow line changes

Two additions to `easylog-easywaf-type.md`, which EasyLog parses:

* an optional `user=` field, present when the gateway identified the caller
* a new verdict, `unauthenticated`, for a request sent to the login page

Both are additive, and a parser written against the current spec will ignore
the field and see an unknown verdict rather than break. EasyLog should be told
before either ships.

## What the first release does not do

Recorded so they are not mistaken for oversights: no OIDC or SAML, no MFA or
TOTP, no passkeys, no per-user or per-path authorization beyond an LDAP group
filter, no session list, no "remember me", no API tokens, and no re-prompt for
sensitive paths. It authenticates, once, for a time, and tells the application
who it was.

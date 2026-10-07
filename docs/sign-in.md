# Sign-in

The rules ask what a request is, and the CAPTCHA asks whether a person sent it.
Neither asks **who**. A site can: EasyWAF shows a sign-in page in front of the
whole site, or in front of `/admin` on it, and only a visitor who has signed in
reaches the application.

The application needs no change. It is told who the visitor is in a header, and
an application with no login of its own — a dashboard, a status page, an admin
tool somebody wrote in an afternoon — gets one.

## Realms

Names and passwords come from a **realm**, made under **Settings → Sign-in
Realms**. There are two kinds:

| Kind | Where the accounts are |
|---|---|
| Local | In EasyWAF: a name and a password each, added on the realm's page |
| Directory | In an LDAP directory, which is asked at each sign-in |

A realm's accounts are **not** the accounts that open EasyWAF's own interface.
They are kept apart, and neither opens the other: somebody who may read a wiki
cannot edit the firewall in front of it.

Several sites can use one realm. A realm a site is using cannot be deleted —
the site would go from asking everybody to asking nobody.

### Local accounts

Add an account with a name and a password of at least 8 characters. An account
can be disabled without being deleted, and its password set again. Each one's
last sign-in is shown.

### A directory

| Field | What it is |
|---|---|
| Address | `ldap://host` or `ldaps://host`, with a port if it is not the usual one |
| StartTLS | Upgrade an `ldap://` connection before anything is sent on it |
| Check the certificate | On by default. Off accepts any certificate, for a directory with a private CA you cannot install |
| Search as | The account EasyWAF finds the visitor with. Empty searches anonymously |
| Where to look for users | The base DN |
| Who may sign in | The filter that finds the visitor. `{user}` is the name they typed |
| Groups attribute | Optional — `memberOf`, usually. Its values are passed to the application |

A sign-in is a search and then a bind: EasyWAF finds the one entry the filter
matches, and asks the directory whether the password is that entry's. A filter
that matches two entries signs in neither.

**The filter is also who is allowed.** To let in only one group:

```
(&(uid={user})(memberOf=cn=staff,ou=groups,dc=example,dc=com))
```

What a visitor types is escaped before it is put into the filter, so a name
cannot rewrite it.

**Test the directory**, on the realm's page, goes through a sign-in one step
at a time with the settings as saved, and stops at the first step that fails:

1. connecting, and whether the certificate was checked;
2. binding as the search account;
3. reading the base;
4. finding people with the filter.

*Test the connection* does those four and needs nobody's password. *Try a
sign-in* with a name finds that one person — and says so when the filter finds
nobody, or more than one — and with their password as well, binds as them and
lists their groups. Use it before pointing a site at the realm: a wrong
address, a search account that cannot bind and a filter that finds nobody all
look the same to a visitor.

For Active Directory or Samba the filter is usually
`(sAMAccountName={user})` and the groups attribute `memberOf`, and a password
is only accepted over LDAPS or StartTLS.

!!! warning "Use LDAPS or StartTLS"
    Over plain `ldap://` the visitor's password crosses your network in the
    clear between EasyWAF and the directory.

## Asking on a site

On the site's page, under **Sign-in**, choose the realm. Then, if not the whole
site:

- **Paths that need a sign-in** — one per line. Empty means everything.
- **Paths left open** — never asked, whatever the first list says.

A path covers what is under it: `/admin` is `/admin`, `/admin/` and
`/admin/users`, and is not `/administrator`.

!!! warning "Clients that are not browsers"
    A sync client, a mobile app or a script calling an API cannot fill in a
    sign-in page. Put the whole of a Nextcloud behind a sign-in and every
    desktop client stops syncing. Either ask only on the paths people use in a
    browser, or leave the others open — `/remote.php`, `/ocs`, `/api` — and let
    the application's own authentication guard them, as it did before.

**What needs a sign-in is decided on the path as the application will read
it.** `//admin`, `/public/../admin`, `/%61dmin` and `/ADMIN` all need one when
`/admin` does. A path left open is matched exactly as written, so nothing is
opened by accident.

### Only over HTTPS

A name and a password are never asked for in the clear. A request over HTTP for
something that needs a sign-in is redirected to HTTPS when the site has a
certificate, and refused when it has none. Saving a site that asks for a
sign-in and has no HTTPS says so.

Behind another proxy that terminates TLS, that proxy has to be a
[trusted proxy](sites.md#behind-another-proxy), so that its word that the
visitor used HTTPS is believed.

### HTTP Basic

Tick **Accept HTTP Basic as well** for clients that can send a name and password
but cannot fill in a form: `curl -u`, a monitoring probe, a feed reader. A
browser still gets the page. The credential is the gateway's and is not passed
on to the application.

## A session

| | Default | Accepts |
|---|---|---|
| A sign-in lasts | 8 hours | 5 minutes to 30 days |
| … or this long unused | 1 hour | 5 minutes, up to the first |

Both are set on the realm. The session is a signed cookie, valid for the site
it was issued on and no other, marked `Secure` and `HttpOnly`. Nothing about a
session is stored, so sessions survive a restart.

A session ends **at once** when:

- the visitor signs out — a link to `/__easywaf/logout` on the site does it;
- a local account is disabled, deleted, or given a new password;
- **Sign everyone out** is pressed on the realm's page.

For a directory, EasyWAF asks at sign-in and not again. Somebody removed from
the directory keeps a session they already have until it runs out — one hour
unused, eight at most, by default. *Sign everyone out* ends it sooner.

## What the application is told

| Header | Holds |
|---|---|
| `X-Forwarded-User` | The name the visitor signed in with |
| `X-Forwarded-Groups` | Their groups from the directory, comma-separated: `staff`, from `cn=staff,ou=groups,…` |

The names of both can be changed on the site. A signed-in visitor is named on
every path of the site, including the ones left open, so a public page can
still greet them.

**A client cannot name itself.** Both headers are removed from every request to
a site that asks for a sign-in, before the gateway sets them; so is the
session cookie, which the application has no use for.

!!! warning "The application must be reachable only through EasyWAF"
    An application that trusts `X-Forwarded-User` trusts whoever can send it.
    If the backend also answers on an address that does not go through
    EasyWAF, anybody there is whoever they say they are.

## Guessing

Ten failed sign-ins from one address, or fifty for one name from anywhere, and
further attempts are answered *too many attempts* for ten minutes. The second
count is what stops a list of passwords being tried from a thousand addresses
against one account.

Counts are kept in memory, per node, and start again when EasyWAF restarts.

## With the rest of the policy

- **Signing in raises nothing.** A signed-in visitor's requests are inspected
  like anybody's, and blocked like anybody's. IP lists, country rules and Smart
  Protect are applied before the sign-in page is ever shown.
- **A signed-in visitor is not also shown a CAPTCHA.** A password is a better
  answer to the same question.
- **The password is not read by the rules.** The sign-in form's own POST is
  not inspected, so a password with a quote in it is not mistaken for SQL.

## Where it shows

- **Traffic Monitor** names the signed-in visitor under the client address, and
  marks a request that was sent to the sign-in page `SIGN-IN`.
- **The audit log** has a line for each sign-in, refusal and sign-out:
  `event=site-sign-in`, with the site, realm, name, address and result.
- **Flow logs** carry `user=` for a signed-in visitor, and the verdict
  `unauthenticated` for a request sent to the sign-in page. See
  [Logging](logging.md).
- **Export and import** carry realms and each site's settings. See
  [Backup and restore](backup.md).

## What it does not do

No single sign-on from an identity provider (OIDC, SAML), no second factor, no
passkeys, no different rights for different paths beyond a directory filter, and
no list of who is signed in. It asks once, remembers for a while, and tells the
application who it was.

-- 039 — the sign-in gateway: who may reach a site, and a name for them.
--
-- Three tables, and none of them is `users`. Those are the accounts that open
-- EasyWAF's own interface. A visitor to a site who was also a row there would
-- be one mistake away from administering the appliance in front of it, so site
-- identities have a namespace of their own and the two are never joined.
--
--   auth_realms   where identities come from: accounts kept here, or a
--                 directory. A realm is shared by the sites that use it, so
--                 one sign-in policy is written once.
--   auth_users    the accounts of a local realm.
--   site_auth     which realm a site asks for, on which paths.
--
-- `epoch` is how a session is ended before its time. A session cookie carries
-- the realm's and the account's; raising either refuses every cookie minted
-- before, which is what "sign everyone out" and "disable this account" mean.
--
-- The request path reads all three from memory and reloads them when the
-- configuration generation moves, so each has the triggers that move it. An
-- account's `last_login` is the exception: it is written at every sign-in and
-- changes nothing the proxy decides, so the trigger names the columns that do.
--
-- `traffic_events.user` is who the gateway identified, for the rows it did.
--
-- Idempotent: the tables and triggers are created only when missing, and the
-- whole file is applied only while the column it ends with is.

CREATE TABLE IF NOT EXISTS auth_realms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    kind            TEXT    NOT NULL CHECK (kind IN ('local', 'ldap')),
    -- How long a sign-in lasts whatever the visitor does, and how long it
    -- lasts unused.
    session_minutes INTEGER NOT NULL DEFAULT 480,
    idle_minutes    INTEGER NOT NULL DEFAULT 60,
    epoch           INTEGER NOT NULL DEFAULT 0,
    -- JSON, for a directory: where it is and how to ask it.
    config          TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auth_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    realm_id      INTEGER NOT NULL REFERENCES auth_realms(id) ON DELETE CASCADE,
    username      TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    display_name  TEXT    NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    epoch         INTEGER NOT NULL DEFAULT 0,
    last_login    TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (realm_id, username)
);

CREATE TABLE IF NOT EXISTS site_auth (
    site_id      INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    -- A realm in use cannot be deleted from under its sites: they would go
    -- from asking everybody to sign in to asking nobody.
    realm_id     INTEGER NOT NULL REFERENCES auth_realms(id) ON DELETE RESTRICT,
    -- Path prefixes that need a sign-in, one per line. Empty: the whole site.
    paths        TEXT    NOT NULL DEFAULT '',
    -- Path prefixes that never do, whatever `paths` says.
    bypass       TEXT    NOT NULL DEFAULT '',
    -- Accept HTTP Basic as well as the form, for clients that cannot fill one in.
    basic        INTEGER NOT NULL DEFAULT 0 CHECK (basic IN (0, 1)),
    -- The headers the application is told the visitor's name and groups in.
    user_header   TEXT   NOT NULL DEFAULT 'X-Forwarded-User',
    groups_header TEXT   NOT NULL DEFAULT 'X-Forwarded-Groups'
);

CREATE TRIGGER IF NOT EXISTS gen_auth_realms_insert AFTER INSERT ON auth_realms
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS gen_auth_realms_update AFTER UPDATE ON auth_realms
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS gen_auth_realms_delete AFTER DELETE ON auth_realms
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_auth_users_insert AFTER INSERT ON auth_users
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS gen_auth_users_update
AFTER UPDATE OF username, password_hash, enabled, epoch ON auth_users
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS gen_auth_users_delete AFTER DELETE ON auth_users
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_site_auth_insert AFTER INSERT ON site_auth
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS gen_site_auth_update AFTER UPDATE ON site_auth
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS gen_site_auth_delete AFTER DELETE ON site_auth
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

ALTER TABLE traffic_events ADD COLUMN user TEXT;

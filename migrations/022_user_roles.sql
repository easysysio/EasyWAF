-- Roles, an enabled flag, and a way to end a session.
--
-- The table held id, username, password_hash and created_at. Every account was
-- therefore an administrator by the absence of any way to say otherwise, and
-- there was no way to suspend one short of deleting it.
--
-- role: 'admin' sees and changes everything; 'viewer' sees the dashboard,
-- traffic and the read-only pages and changes nothing. Two to begin with,
-- because three roles invented up front usually leaves one that is never used.
--
-- EVERY EXISTING ACCOUNT BECOMES AN ADMIN. There is no other safe default: the
-- accounts that exist when this runs are the ones an operator has been using to
-- administer the appliance, and demoting them on upgrade would lock somebody
-- out of their own installation.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';

-- A suspended account keeps its history and its rules attribution; deleting it
-- would lose both. Enabled by default for the same reason as above.
ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;

-- Sessions are stateless signed cookies, so changing a password did not end one
-- already issued — it stayed valid for its remaining eight hours, in whatever
-- browser held it. The session carries the epoch it was minted at; the server
-- compares it per request and refuses a cookie older than the current value.
-- Bumping this is what "sign out everywhere" means, and it is what a password
-- change, a role change, a suspension and a deletion all do.
ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;

-- Recorded so the account list can show it. Nullable: it is not known for
-- accounts that existed before this column did, and inventing a value would be
-- worse than admitting that.
ALTER TABLE users ADD COLUMN last_login TEXT;

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role, enabled);

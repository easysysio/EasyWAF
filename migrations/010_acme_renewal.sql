-- =========================================================
-- 010_acme_renewal.sql — EasyWAF
-- Renewal state for certificates issued over ACME.
--
-- Every column here exists so the state survives a restart.
-- An in-memory backoff would reset on every start, which
-- turns a crash-looping service — or an operator restarting
-- to "fix" a failing renewal — into one that hammers the CA
-- and gets the account rate limited, making the original
-- problem unfixable for an hour.
--
-- Expiry is read from certs.not_after, which is parsed from
-- the certificate itself and set for uploaded certificates
-- too. The acme_expires column from 001 is left alone rather
-- than kept in step, since two sources for one fact is how
-- they come to disagree.
-- =========================================================

-- When renewal was last attempted, successful or not.
ALTER TABLE certs ADD COLUMN acme_last_attempt TEXT;

-- The error from the last attempt; NULL when it succeeded. This is what
-- distinguishes "renewing quietly" from "failing quietly", which is otherwise
-- invisible until the certificate expires.
ALTER TABLE certs ADD COLUMN acme_last_error TEXT;

-- Not before this time. Written on failure and respected across restarts.
ALTER TABLE certs ADD COLUMN acme_next_attempt TEXT;

-- Consecutive failures, for the backoff. Reset to 0 on success.
ALTER TABLE certs ADD COLUMN acme_failures INTEGER NOT NULL DEFAULT 0;

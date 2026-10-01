-- 038 — whether the tutorial opens after an administrator signs in.
--
-- The tutorial is for a new installation: it walks through putting the first
-- site behind EasyWAF. An appliance that already has an account has been set
-- up by somebody, and should not start showing them how after an upgrade.
--
-- So the answer is decided once, here, by whether an account exists: hidden on
-- an installation that is already in use, shown on one that is not. From then
-- on it is the administrator's — "Don't show this again" on the page sets it.
--
-- Idempotent: the row is written only when it is missing, so a later start
-- never overrules what an administrator chose.

INSERT OR IGNORE INTO settings (key, value)
SELECT 'tutorial_hidden',
       CASE WHEN EXISTS (SELECT 1 FROM users) THEN '1' ELSE '0' END;

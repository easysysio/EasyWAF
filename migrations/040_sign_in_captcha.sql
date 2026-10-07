-- =========================================================
-- 040 — a CAPTCHA with a site's sign-in
--
-- A site can ask for the characters of an image along with the name and
-- password, so that a script cannot try passwords at the form at all.
-- =========================================================

ALTER TABLE site_auth ADD COLUMN captcha INTEGER NOT NULL DEFAULT 0 CHECK (captcha IN (0, 1));

-- =========================================================
-- 011_x_frame_value.sql — EasyWAF
-- Which X-Frame-Options value a site sends.
--
-- The header was hard-coded to DENY, which forbids a page
-- being framed by anything at all — including itself. Real
-- applications frame their own pages (Nextcloud, Collabora,
-- Grafana), and DENY silently breaks those features while
-- looking like a security setting doing its job.
--
-- SAMEORIGIN is what defends against clickjacking: framing
-- by another origin is the threat, and framing by yourself
-- is not. So it is the default for new sites.
--
-- Existing sites are set to DENY explicitly, so the upgrade
-- changes nothing for anyone. Anybody it was breaking can
-- now choose otherwise; anybody relying on it keeps it.
-- =========================================================

ALTER TABLE sites ADD COLUMN x_frame_value TEXT NOT NULL DEFAULT 'SAMEORIGIN';

UPDATE sites SET x_frame_value = 'DENY';

-- Migration 007 — per-policy country rules
--
-- Country filtering belongs to the policy rather than the site: a policy is
-- already what a site points at for its WAF settings, so one country list can
-- be shared by every site using that policy.
--
-- geoip_mode:
--   'off'   — no country filtering (the default, so existing policies are
--             unchanged by this migration)
--   'block' — deny the listed countries, allow everything else
--   'allow' — allow only the listed countries, deny everything else
--
-- geoip_countries holds comma-separated ISO 3166-1 alpha-2 codes, e.g. "CN,RU".
-- An empty list means the rule matches nothing, so switching mode on without
-- choosing countries cannot lock a site out by accident.

ALTER TABLE policies ADD COLUMN geoip_mode      TEXT NOT NULL DEFAULT 'off';
ALTER TABLE policies ADD COLUMN geoip_countries TEXT NOT NULL DEFAULT '';

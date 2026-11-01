-- =========================================================
-- 044 — a rate limit per site
--
-- How many requests one client may make to the site within a window, and
-- what happens to the ones over it. On the site rather than its policy:
-- what counts as normal traffic differs by orders of magnitude between a
-- busy API and a small internal tool, so a number shared through a policy
-- would need overriding on nearly every site that shared it.
--
-- Off by default, with a mode like a policy's: an upgrade must not start
-- refusing anybody, and a limit can be watched in DetectionOnly before it
-- enforces. The window is in seconds.
--
-- Idempotent: the columns are added only while they are missing.
-- =========================================================

ALTER TABLE sites ADD COLUMN rate_limit_mode TEXT NOT NULL DEFAULT 'Off'
    CHECK (rate_limit_mode IN ('Off', 'DetectionOnly', 'On'));
ALTER TABLE sites ADD COLUMN rate_limit_requests INTEGER NOT NULL DEFAULT 600
    CHECK (rate_limit_requests >= 1);
ALTER TABLE sites ADD COLUMN rate_limit_window INTEGER NOT NULL DEFAULT 60
    CHECK (rate_limit_window >= 1);
ALTER TABLE sites ADD COLUMN rate_limit_action TEXT NOT NULL DEFAULT 'block'
    CHECK (rate_limit_action IN ('block', 'challenge'));

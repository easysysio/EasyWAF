-- Migration 005 — per-policy challenge threshold
-- When a request's accumulated WAF score reaches challenge_threshold (but is
-- still below score_threshold), the visitor is shown a CAPTCHA challenge
-- instead of being hard-blocked. 0 disables score-based challenging.

ALTER TABLE policies ADD COLUMN challenge_threshold INTEGER NOT NULL DEFAULT 0;

-- Migration 004 — add external_id to waf_rules
-- external_id stores the numeric ID from a rule file (e.g. 942001).
-- The unique index on (policy_id, external_id) makes repeated imports
-- idempotent: re-importing the same file never duplicates a rule.

ALTER TABLE waf_rules ADD COLUMN external_id INTEGER;

CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_external_id
    ON waf_rules(policy_id, external_id)
    WHERE external_id IS NOT NULL;

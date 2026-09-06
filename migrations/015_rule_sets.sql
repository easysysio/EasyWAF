-- =========================================================
-- 015_rule_sets.sql — EasyWAF
-- Record which set a rule came from, and which version of
-- each set a policy holds.
--
-- Without this there is nothing to compare a published
-- manifest against, which is why correcting a rule has so
-- far meant shipping a migration that rewrites patterns by
-- hand. A policy that knows it holds SQLi v2 can be told
-- v3 exists; a policy that knows nothing cannot.
--
-- The set is recorded rather than derived from the id range.
-- That inference is already wrong in this project's own
-- history: rule 931100 sat in the RCE file for several
-- releases, so 931xxx did not mean RFI.
-- =========================================================

-- Which set an imported rule came from. NULL for custom rules.
ALTER TABLE waf_rules ADD COLUMN rule_set TEXT;

-- Where a clone forked from, informationally. Set only on clones, so an
-- update notice can say "your custom rule was forked from SQLi v2, the set is
-- now v4" — a nudge for a human, never an automatic merge.
ALTER TABLE waf_rules ADD COLUMN cloned_from_external_id INTEGER;
ALTER TABLE waf_rules ADD COLUMN cloned_from_version     INTEGER;

-- A set is installed into a policy, so its version is per policy: policy A may
-- hold 2 while policy B holds 3. The notification is not "an update exists" but
-- "SQLi 3 is available; this policy has 2".
CREATE TABLE IF NOT EXISTS policy_rule_sets (
    policy_id    INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    set_id       TEXT    NOT NULL,
    name         TEXT,
    version      INTEGER NOT NULL,
    installed_at TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (policy_id, set_id)
);

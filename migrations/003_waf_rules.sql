-- Migration 003 — WAF rules table
-- Each row is one pattern-based inspection rule belonging to a policy.
-- Rules are evaluated per-request by the WafModule in the pipeline.

CREATE TABLE IF NOT EXISTS waf_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id   INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,                       -- human-readable label
    description TEXT    NOT NULL DEFAULT '',            -- optional explanation
    zone        TEXT    NOT NULL DEFAULT 'ANY',         -- URL | ARGS | BODY | HEADERS | ANY
    pattern     TEXT    NOT NULL,                       -- regex pattern
    score       INTEGER NOT NULL DEFAULT 5,             -- points added when matched
    action      TEXT    NOT NULL DEFAULT 'score',       -- 'score' | 'block'
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_rules_policy ON waf_rules(policy_id);

-- 029 — an IP list entry can belong to every policy.
--
-- Since 027 a list entry belongs to one policy, which is the unit sites are
-- grouped by and the right default: the public websites block what the hosted
-- applications need not. But some addresses are not a policy's business at
-- all — an office that must never be refused anywhere, a netblock that has no
-- honest reason to reach this appliance — and copying those into every policy
-- means remembering to copy them into the next one too.
--
-- So policy_id becomes nullable, and NULL means every policy: the ones that
-- exist and the ones made later. Nothing else changes; a site with no policy
-- still gets no lists, because a site with no policy is not inspected.
--
-- SQLite cannot drop NOT NULL in place, so both tables are rebuilt. NULL is
-- not unique to SQLite's UNIQUE either, which would let the same address onto
-- the every-policy list twice, so each table gets two partial indexes instead:
-- one for the rows that name a policy, one for the rows that do not.
--
-- Applied once, inside a transaction, by run_migration_029. It runs before 028
-- on that start, because rebuilding a table drops its triggers and 028 is what
-- puts them back.

CREATE TABLE ip_rules_scoped (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- NULL: every policy.
    policy_id  INTEGER REFERENCES policies(id) ON DELETE CASCADE,
    ip         TEXT    NOT NULL,
    list_type  TEXT    NOT NULL CHECK (list_type IN ('allow', 'block')),
    reason     TEXT,
    added_by   TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO ip_rules_scoped (id, policy_id, ip, list_type, reason, added_by, created_at)
SELECT id, policy_id, ip, list_type, reason, added_by, created_at FROM ip_rules;

DROP TABLE ip_rules;
ALTER TABLE ip_rules_scoped RENAME TO ip_rules;

CREATE INDEX idx_ip_rules_policy ON ip_rules(policy_id);
CREATE UNIQUE INDEX idx_ip_rules_one_per_policy ON ip_rules(policy_id, ip)
    WHERE policy_id IS NOT NULL;
CREATE UNIQUE INDEX idx_ip_rules_one_everywhere ON ip_rules(ip)
    WHERE policy_id IS NULL;

CREATE TABLE ip_list_feeds_scoped (
    -- NULL: every policy, unless that policy has a row of its own.
    policy_id  INTEGER REFERENCES policies(id) ON DELETE CASCADE,
    id         TEXT    NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    response   TEXT    NOT NULL DEFAULT 'challenge'
                       CHECK (response IN ('challenge', 'block')),
    changed_by TEXT,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO ip_list_feeds_scoped (policy_id, id, enabled, response, changed_by, updated_at)
SELECT policy_id, id, enabled, response, changed_by, updated_at FROM ip_list_feeds;

DROP TABLE ip_list_feeds;
ALTER TABLE ip_list_feeds_scoped RENAME TO ip_list_feeds;

CREATE UNIQUE INDEX idx_ip_list_feeds_one_per_policy ON ip_list_feeds(policy_id, id)
    WHERE policy_id IS NOT NULL;
CREATE UNIQUE INDEX idx_ip_list_feeds_one_everywhere ON ip_list_feeds(id)
    WHERE policy_id IS NULL;

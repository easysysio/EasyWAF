-- 027 — IP lists and rule exclusions belong to a policy.
--
-- Until now both applied more widely than anything else an operator tunes: IP
-- lists to the whole installation, exclusions to a site whatever policy it
-- used. A policy is how sites are grouped by what they face — the public
-- websites under one, each hosted application under its own — so it is the
-- unit a list or an exclusion is decided for. After this migration a policy
-- holds everything that decides what happens to a request: rules, countries,
-- IP lists and exclusions. A site with no policy gets none of them.
--
-- The move keeps behaviour as close as a narrower model allows:
--
--   * Each manual IP entry and each published-list choice applied to every
--     site, so it is copied into every policy.
--   * Each exclusion moves to the policy its site uses now, with a note naming
--     the site. On a policy several sites share, it now covers all of them —
--     the start-up log lists every one that widened. An exclusion on a site
--     with no policy silenced nothing, and is dropped.
--
-- Applied once, inside a transaction, by run_migration_027. The first
-- statement fails on a database that already has it, so scripts/dev-db.sh
-- (which runs this file with -bail) stops before touching anything.

CREATE TABLE policy_rule_exclusions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id   INTEGER NOT NULL REFERENCES policies(id)  ON DELETE CASCADE,
    -- Catalogue number or custom rule row, exactly one — as in migration 018,
    -- whose reasons still hold.
    external_id INTEGER,
    rule_id     INTEGER          REFERENCES waf_rules(id) ON DELETE CASCADE,
    -- Empty means every path.
    path_prefix TEXT    NOT NULL DEFAULT '',
    -- NULL means every client.
    client_cidr TEXT,
    note        TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK ((external_id IS NULL) <> (rule_id IS NULL))
);

CREATE INDEX idx_policy_exclusions_policy ON policy_rule_exclusions(policy_id);

CREATE UNIQUE INDEX idx_policy_exclusions_unique
    ON policy_rule_exclusions(
        policy_id,
        IFNULL(external_id, -1),
        IFNULL(rule_id, -1),
        path_prefix,
        IFNULL(client_cidr, '')
    );

-- OR IGNORE: two sites on one policy may have excluded the same rule for the
-- same path and client, which is now one exclusion. The older row is kept.
INSERT OR IGNORE INTO policy_rule_exclusions
       (policy_id, external_id, rule_id, path_prefix, client_cidr, note, created_at)
SELECT s.waf_policy_id, e.external_id, e.rule_id, e.path_prefix, e.client_cidr,
       CASE WHEN e.note = '' THEN 'Moved from site ' || s.server_name
            ELSE e.note || ' (moved from site ' || s.server_name || ')' END,
       e.created_at
FROM   site_rule_exclusions e
JOIN   sites s ON s.id = e.site_id
WHERE  s.waf_policy_id IS NOT NULL
ORDER  BY e.id;

DROP TABLE site_rule_exclusions;

-- IP list entries: an address is on at most one list per policy.
CREATE TABLE ip_rules_by_policy (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id  INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    ip         TEXT    NOT NULL,
    list_type  TEXT    NOT NULL CHECK (list_type IN ('allow', 'block')),
    reason     TEXT,
    added_by   TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (policy_id, ip)
);

INSERT INTO ip_rules_by_policy (policy_id, ip, list_type, reason, added_by, created_at)
SELECT p.id, r.ip, r.list_type, r.reason, r.added_by, r.created_at
FROM   ip_rules r CROSS JOIN policies p
ORDER  BY p.id, r.id;

DROP TABLE ip_rules;
ALTER TABLE ip_rules_by_policy RENAME TO ip_rules;
CREATE INDEX idx_ip_rules_policy ON ip_rules(policy_id);

-- Published-list decisions: one per policy per list.
CREATE TABLE ip_list_feeds_by_policy (
    policy_id  INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    id         TEXT    NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    response   TEXT    NOT NULL DEFAULT 'challenge'
                       CHECK (response IN ('challenge', 'block')),
    changed_by TEXT,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (policy_id, id)
);

INSERT INTO ip_list_feeds_by_policy (policy_id, id, enabled, response, changed_by, updated_at)
SELECT p.id, f.id, f.enabled, f.response, f.changed_by, f.updated_at
FROM   ip_list_feeds f CROSS JOIN policies p;

DROP TABLE ip_list_feeds;
ALTER TABLE ip_list_feeds_by_policy RENAME TO ip_list_feeds;

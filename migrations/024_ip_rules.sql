-- 024 — IP allow and block lists.
--
-- One row per entry, the list it belongs to decided by a column rather than by
-- which table it is in: an address is on at most one list, and moving it
-- between them is an update rather than a delete and an insert that could half
-- fail.
--
-- UNIQUE on ip alone, not on (ip, list_type), so the database refuses to hold
-- both an allow and a block entry for the same address. Clicking Allow on a
-- blocked address moves it.

CREATE TABLE IF NOT EXISTS ip_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL UNIQUE,
    list_type  TEXT    NOT NULL CHECK (list_type IN ('allow', 'block')),
    reason     TEXT,
    added_by   TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ip_rules_type ON ip_rules(list_type);

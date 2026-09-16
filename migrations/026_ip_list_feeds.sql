-- 026 — Published IP lists: what the operator has decided about each.
--
-- Only the decision lives here. The lists themselves arrive as signed files,
-- are mirrored beside the database and replaced whole every day; their names,
-- licences and entry counts come from the verified manifest in that mirror.
-- Copying those into a table would give them two sources, one of which is
-- always about to be stale.
--
-- A list with no row is off. Nothing a published list says has any effect
-- until somebody has said what it should mean here.

CREATE TABLE IF NOT EXISTS ip_list_feeds (
    id         TEXT    PRIMARY KEY,
    enabled    INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    response   TEXT    NOT NULL DEFAULT 'challenge'
                       CHECK (response IN ('challenge', 'block')),
    changed_by TEXT,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

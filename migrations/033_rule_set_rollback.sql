-- 033 — the version an update replaced, kept so it can be put back.
--
-- `install_set` overwrites each rule in place. Until now nothing remembered
-- what it overwrote, so an update that turned out to refuse legitimate traffic
-- could only be undone rule by rule, by hand, from memory — which is the
-- situation 0.13.1's automatic-apply switch makes more likely and harder to
-- notice. A switch that applies rule sets to every policy without asking is a
-- gamble until there is a way back; this is the way back.
--
-- One row per policy and set: the version it held and the rules as they were,
-- captured immediately before an update writes over them. One step, not a
-- history — "put back what was just applied" is the thing anybody actually
-- wants at two in the morning, and keeping every version of every set for
-- every policy would grow without a bound anybody chose.
--
-- The rules travel as JSON rather than as rows: they are read back whole, by
-- one policy, at one moment, and never queried across. A table of them would
-- be a second schema for waf_rules that has to be migrated alongside it.
--
-- Idempotent: created only when missing.

CREATE TABLE IF NOT EXISTS policy_rule_set_previous (
    policy_id  INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    set_id     TEXT    NOT NULL,
    -- The version that was in force before the update.
    version    INTEGER NOT NULL,
    -- The version that replaced it, so the page can say what it would undo.
    replaced_by INTEGER NOT NULL,
    rules      TEXT    NOT NULL,
    taken_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (policy_id, set_id)
);

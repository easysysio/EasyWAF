-- =========================================================
-- 043 — the lists a policy sets for the rules that read them
--
-- A rule's pattern may name a list as `%{allowed_methods}`; the policy's row
-- here is what it reads. A policy without a row for a list has OWASP CRS's
-- default, which lives in modules/values.rs, so a later EasyWAF can carry a
-- newer default without rewriting what anyone chose. `value` is the list's
-- words, one space apart.
--
-- Idempotent, and applied on every start.
-- =========================================================

CREATE TABLE IF NOT EXISTS policy_values (
    policy_id INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    name      TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    PRIMARY KEY (policy_id, name)
);

CREATE TRIGGER IF NOT EXISTS gen_policy_values_insert AFTER INSERT ON policy_values
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_policy_values_update AFTER UPDATE ON policy_values
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_policy_values_delete AFTER DELETE ON policy_values
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

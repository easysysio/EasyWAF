-- 025 — a counter that moves whenever inspection's configuration does.
--
-- The WAF and country modules cache each site's policy, rules and exclusions
-- instead of reading them on every request. A cache is only as good as its
-- invalidation, and about thirty handlers write these tables. A version bump
-- each of them had to remember would be one forgotten call away from a rule an
-- administrator disabled carrying on firing — silently, which is the one way a
-- security product must not fail.
--
-- So the database keeps the counter itself. Every insert, update and delete on
-- the four tables inspection reads moves it, whatever wrote the row: a GUI
-- handler, a rule-set update, or sqlite3 at a shell. The modules compare it at
-- most once a second.
--
-- Idempotent throughout, and applied on every start rather than once, so a
-- trigger dropped by hand comes back instead of quietly disabling invalidation.
--
-- Exclusions moved to policy_rule_exclusions in 027, and their triggers — with
-- those for the IP lists — live in 028. The triggers on the old table went with
-- it when 027 dropped it.

CREATE TABLE IF NOT EXISTS config_generation (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO config_generation (id, value) VALUES (1, 0);

CREATE TRIGGER IF NOT EXISTS gen_waf_rules_insert AFTER INSERT ON waf_rules
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_waf_rules_update AFTER UPDATE ON waf_rules
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_waf_rules_delete AFTER DELETE ON waf_rules
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_policies_insert AFTER INSERT ON policies
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_policies_update AFTER UPDATE ON policies
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_policies_delete AFTER DELETE ON policies
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_sites_insert AFTER INSERT ON sites
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_sites_update AFTER UPDATE ON sites
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_sites_delete AFTER DELETE ON sites
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

-- 028 — IP lists and exclusions move the configuration generation too.
--
-- Since 027 they are part of a policy, and the caches keyed on the generation
-- (migration 025) have to forget them when they change, whatever wrote the row.
-- Idempotent, and applied on every start for the reason 025 is.

CREATE TRIGGER IF NOT EXISTS gen_policy_rule_exclusions_insert AFTER INSERT ON policy_rule_exclusions
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_policy_rule_exclusions_update AFTER UPDATE ON policy_rule_exclusions
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_policy_rule_exclusions_delete AFTER DELETE ON policy_rule_exclusions
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_ip_rules_insert AFTER INSERT ON ip_rules
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_ip_rules_update AFTER UPDATE ON ip_rules
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_ip_rules_delete AFTER DELETE ON ip_rules
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_ip_list_feeds_insert AFTER INSERT ON ip_list_feeds
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_ip_list_feeds_update AFTER UPDATE ON ip_list_feeds
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_ip_list_feeds_delete AFTER DELETE ON ip_list_feeds
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

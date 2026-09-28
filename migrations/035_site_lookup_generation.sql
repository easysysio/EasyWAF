-- 035 — what the proxy reads to route a request moves the generation too.
--
-- Until now each request looked its site up in the database: one query per
-- request, and at load most of what a request cost. The proxy now holds every
-- site in memory and reloads them when the generation moves (migration 025),
-- so everything that lookup reads has to move it: sites and policies already
-- do; a site's backends, its aliases and its certificate did not.
--
-- A certificate only by its PEM. Renewal bookkeeping writes the row daily, and
-- emptying every cache for a timestamp would cost a reload for nothing.
--
-- Idempotent, and applied on every start for the reason 025 is.

CREATE TRIGGER IF NOT EXISTS gen_upstreams_insert AFTER INSERT ON upstreams
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_upstreams_update AFTER UPDATE ON upstreams
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_upstreams_delete AFTER DELETE ON upstreams
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_site_aliases_insert AFTER INSERT ON site_aliases
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_site_aliases_update AFTER UPDATE ON site_aliases
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_site_aliases_delete AFTER DELETE ON site_aliases
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_certs_insert AFTER INSERT ON certs
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_certs_update AFTER UPDATE OF cert_pem, key_pem ON certs
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_certs_delete AFTER DELETE ON certs
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

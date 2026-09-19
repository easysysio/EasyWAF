-- 030 — a country rule can apply to every policy.
--
-- Country rules belong to a policy, which is right for the ones that differ
-- between sites: the public websites may refuse a country the hosted
-- applications must still reach. It is the wrong shape for a rule about the
-- appliance rather than about one group of sites — a country nothing here
-- should ever serve — which otherwise has to be set on every policy and on the
-- next one somebody makes.
--
-- One row, because there is one appliance. A policy's own rule is unchanged
-- and still its own; this is applied as well, never instead, and a request
-- refused by either is refused. There is no every-policy rule that lets a
-- country in that a policy refuses: the way past a country rule for one client
-- is its address on an allow list, which skips every check including this one.
--
-- Idempotent, and applied on every start for the reason 025 is: the triggers
-- below are what keeps the per-site caches from serving a rule that has been
-- changed.

CREATE TABLE IF NOT EXISTS geoip_everywhere (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    mode       TEXT    NOT NULL DEFAULT 'off'
                       CHECK (mode IN ('off', 'block', 'allow')),
    countries  TEXT    NOT NULL DEFAULT '',
    changed_by TEXT,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO geoip_everywhere (id, mode, countries) VALUES (1, 'off', '');

CREATE TRIGGER IF NOT EXISTS gen_geoip_everywhere_update AFTER UPDATE ON geoip_everywhere
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

CREATE TRIGGER IF NOT EXISTS gen_geoip_everywhere_insert AFTER INSERT ON geoip_everywhere
BEGIN UPDATE config_generation SET value = value + 1 WHERE id = 1; END;

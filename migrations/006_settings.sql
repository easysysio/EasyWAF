-- Migration 006 — application settings
-- Key/value store for GUI-managed settings that belong to the installation
-- rather than to a single site or policy. Values are TEXT and parsed by the
-- reader, so adding a setting needs no schema change.
--
-- Settings live here rather than in config.toml because they are edited from
-- the GUI at runtime; config.toml stays for what is needed before the database
-- is open (secret, database_url, gui_port).

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Delete traffic_events older than this many days. 0 keeps everything.
INSERT OR IGNORE INTO settings (key, value) VALUES ('traffic_retention_days', '0');

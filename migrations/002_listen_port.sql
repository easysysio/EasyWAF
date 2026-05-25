-- Migration 002 — per-site listen port
-- Adds listen_port to sites so each virtual host can bind its own TCP port.
-- Existing rows get the default value 80 automatically.
-- This statement is intentionally run every startup; SQLite will error if the
-- column already exists, so db.rs wraps the call with a column-exists check.

ALTER TABLE sites ADD COLUMN listen_port INTEGER NOT NULL DEFAULT 80;

-- Migration 008 — remember what an imported rule looked like on import
--
-- Rules are copied out of the bundled .toml files into waf_rules, and from
-- then on an administrator may edit or disable them. A future rule update has
-- to tell those two cases apart: a rule nobody has touched can be refreshed
-- safely, while one that was deliberately changed must be left alone and
-- reported rather than silently reverted.
--
-- That comparison needs the imported values recorded at import time — they
-- cannot be recovered afterwards, since the row itself is what changed. Hence
-- capturing them now, before any update feature exists.
--
-- NULL means "provenance unknown": a rule written by hand in the GUI, which is
-- owned by its author and never a candidate for automatic updates, or one
-- imported before this migration.

ALTER TABLE waf_rules ADD COLUMN imported_pattern TEXT;
ALTER TABLE waf_rules ADD COLUMN imported_score   INTEGER;
ALTER TABLE waf_rules ADD COLUMN imported_action  TEXT;

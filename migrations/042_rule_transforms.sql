-- =========================================================
-- 042 — the decodings a rule's values are matched after
--
-- `transforms` names, joined with commas, the decodings applied to each form
-- of a value before the rule's first condition is matched against it —
-- `cmdLine`, `replaceComments` — in order. Empty for a rule matched against
-- the forms as they are, which is every rule before this. A further
-- condition carries its own in `conditions`.
-- =========================================================

ALTER TABLE waf_rules ADD COLUMN transforms TEXT NOT NULL DEFAULT '';

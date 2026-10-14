-- =========================================================
-- 041 — rules with several conditions
--
-- A rule's zone and pattern are its first condition. `negate` makes that one
-- hold when the pattern matches nothing; `conditions` is a JSON list of the
-- rest, each {"zone", "pattern", "negate"}, all of which must hold too. A
-- rule with neither is what it was.
-- =========================================================

ALTER TABLE waf_rules ADD COLUMN negate INTEGER NOT NULL DEFAULT 0 CHECK (negate IN (0, 1));
ALTER TABLE waf_rules ADD COLUMN conditions TEXT NOT NULL DEFAULT '[]';

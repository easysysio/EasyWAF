-- Where a clone came from, kept apart from what it belongs to.
--
-- `rule_set` was doing both jobs. A clone inherited the set id of the rule it
-- was forked from, which made it a member of that set for every purpose that
-- reads the column: it grouped under that set in the rule list, and it stayed
-- pointing at the set even after the set was uninstalled, so a policy could
-- show rules belonging to something it no longer held.
--
-- A clone is a custom rule. It is never updated, never removed by an update,
-- and answers to nobody — so its membership is NULL, the same as any other
-- custom rule. Where it came from is provenance, and provenance now has its
-- own column.
ALTER TABLE waf_rules ADD COLUMN cloned_from_set TEXT;

-- Move existing clones out of the sets they were sitting in. The set id is not
-- lost: it moves to the column that means what it actually was.
UPDATE waf_rules
   SET cloned_from_set = rule_set,
       rule_set        = NULL
 WHERE cloned_from_external_id IS NOT NULL
   AND rule_set IS NOT NULL;

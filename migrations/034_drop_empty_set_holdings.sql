-- 034 — forget a rule set a policy holds none of.
--
-- Until 0.13.4 the Rule Library applied a selection by inserting the ticked
-- rules and DELETING the unticked ones, and it never touched
-- policy_rule_sets. So unticking a set's rules there emptied the set out of
-- the policy while leaving the row saying the policy held version N of it.
--
-- What that produced is worse than untidy. The Rule Sets page reported "v2,
-- up to date" for a set with nothing behind it, so a policy that inspected
-- none of those requests looked current; the update check compared a version
-- nobody was running; and 0.13.2's rollback offered to put back a version of
-- a set the policy did not have.
--
-- The repair is to forget the holding rather than to reinstate the rules. No
-- rules is a state somebody arrived at deliberately — by unticking them — and
-- putting them back would start matching traffic that has not been matched
-- for as long as the row has been wrong, without anybody asking for it.
-- Forgetting says the true thing: this policy does not hold that set, and its
-- Rule Sets page now offers to install it.
--
-- A set whose rules are all switched OFF is not touched: those rules are rows
-- in waf_rules, the policy does hold the set, and off is a decision that
-- survives updates by design.
--
-- Safe to run on every start: on a correct database it matches nothing.

DELETE FROM policy_rule_sets
 WHERE NOT EXISTS (
     SELECT 1 FROM waf_rules
      WHERE waf_rules.policy_id = policy_rule_sets.policy_id
        AND waf_rules.rule_set  = policy_rule_sets.set_id
 );

-- The kept copy of a version that was replaced, for a set no longer held, is
-- the same fact one table along: it would offer a way back to rules the
-- policy has no current version of.
DELETE FROM policy_rule_set_previous
 WHERE NOT EXISTS (
     SELECT 1 FROM policy_rule_sets
      WHERE policy_rule_sets.policy_id = policy_rule_set_previous.policy_id
        AND policy_rule_sets.set_id    = policy_rule_set_previous.set_id
 );

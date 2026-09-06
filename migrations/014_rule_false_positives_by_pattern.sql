-- =========================================================
-- 014_rule_false_positives_by_pattern.sql — EasyWAF
-- Correct two rules, matched by pattern rather than by id.
--
-- Migration 012 keyed on external_id, and that was wrong.
-- Rules were renumbered when the catalogue moved to OWASP
-- bands — 990xxx became 913xxx, and the command-chaining
-- rule moved from 931100 to 932012 — but a database imported
-- before that keeps the old ids. So 012 corrected the rule
-- for installations that imported recently and silently
-- skipped the ones that had had it longest.
--
-- Matching on the pattern instead reaches both. The pattern
-- is what is actually wrong, it is distinctive enough to
-- match nothing else, and a rule an operator has edited
-- still will not match — which was the point of matching
-- exactly in the first place.
-- =========================================================

-- Command chaining. Matched "; nc_token=" as "semicolon, then netcat", so
-- every request carrying cookies named nc_* scored 8 of a threshold of 10.
-- Fixed in 012 for external_id 932012 only; this reaches 931100 as well.
UPDATE waf_rules
   SET pattern = '[;|`]\s*(ls|cat|id|whoami|uname|wget|curl|bash|sh|python|perl|nc|netcat)\b'
 WHERE pattern = '[;|`]\s*(ls|cat|id|whoami|uname|wget|curl|bash|sh|python|perl|nc|netcat)';

-- Admin path probing. Unanchored, "/admin" matched anywhere in a URL, so an
-- application's own settings page scored 4 every time it was opened —
-- Nextcloud's is /index.php/settings/admin. Anchored to the path root; the
-- file names stay unanchored because nothing legitimately serves them.
UPDATE waf_rules
   SET pattern = '(?i)(^/(admin|wp-admin|phpmyadmin|manager|console|actuator)(/|\?|$)|/(\.env|\.git(/|$)|phpinfo\.php|server-status|web\.config))'
 WHERE pattern = '(?i)/(admin|wp-admin|phpmyadmin|manager|console|actuator|\.env|\.git|phpinfo\.php|server-status|web\.config)';

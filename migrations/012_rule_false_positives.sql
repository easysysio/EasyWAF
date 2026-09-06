-- =========================================================
-- 012_rule_false_positives.sql — EasyWAF
-- Correct two bundled rules that blocked ordinary traffic.
--
-- Rules live in the database, and importing skips any
-- external_id already present, so fixing the .toml files
-- reaches nobody who has already imported them. Without this
-- an upgrade would ship the fix and change nothing.
--
-- Each statement matches the exact pattern EasyWAF shipped.
-- A rule an operator has edited will not match and is left
-- alone: correcting our own mistake is one thing, silently
-- rewriting somebody's tuning is another.
--
-- 932012 matched command names with no word boundary, so
-- "nc" matched the "nc" of "nc_token" and "id" the "id" of
-- "identity". A Cookie header is semicolon-separated, so
-- "; nc_token=..." read as "semicolon, then netcat" and
-- scored 8 of a default threshold of 10 on every request.
--
-- 920002 called any two adjacent percent-escapes double
-- encoding. That is what every non-ASCII character looks
-- like -- "é" is %C3%A9 -- so non-English filenames and
-- base64 tokens scored 6.
-- =========================================================

UPDATE waf_rules
   SET pattern = '[;|`]\s*(ls|cat|id|whoami|uname|wget|curl|bash|sh|python|perl|nc|netcat)\b'
 WHERE external_id = 932012
   AND pattern     = '[;|`]\s*(ls|cat|id|whoami|uname|wget|curl|bash|sh|python|perl|nc|netcat)';

UPDATE waf_rules
   SET pattern = '(?i)%25[0-9a-fA-F]{2}|%%[0-9a-fA-F]{2}'
 WHERE external_id = 920002
   AND pattern     = '(%[0-9a-fA-F]{2}){2,}|%25[0-9a-fA-F]{2}';

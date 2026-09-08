#!/usr/bin/env bash
# Find and remove EasyWAF rule debris — rows that inflate a request's score
# because every rule that matches adds its own.
#
# Two things accumulated before 0.6.6:
#
#   1. Renumbering orphans. Commit 91123b5 changed some catalogue numbers.
#      The rows carrying the old numbers stayed behind, still enabled, so a
#      request matches both the old rule and its replacement.
#   2. Seeded duplicates. The old "Seed defaults" button wrote custom copies
#      of catalogue rules. The button was removed in 0.6.6; its rows were not.
#
# This is how a 4-point request came to score 17.
#
# The debris is DERIVED from the database and the rule files, not read from a
# list of ids — a list taken from one snapshot is wrong the moment a set is
# reinstalled. Nothing is deleted until you have seen it and typed yes.
#
# Usage: prune-debris.sh [database] [rules-directory]

set -euo pipefail

# The packages set WorkingDirectory=/opt/easywaf and the database is created
# there on first run, so that is the default rather than a guess.
DB="${1:-/opt/easywaf/easywaf.db}"
[ -f "$DB" ] || { echo "No database at $DB"; echo "Usage: $0 [database] [rules-dir]"; exit 1; }

# Where EasyWAF itself looks: the mirror beside the database, else the bundle.
RULES="${2:-}"
if [ -z "$RULES" ]; then
    for cand in "$(dirname "$DB")/rules-cache/sets" "$(dirname "$DB")/rules" \
                /usr/share/easywaf/rules ./rules; do
        if compgen -G "$cand/*.rules.toml" >/dev/null 2>&1; then RULES="$cand"; break; fi
    done
fi
[ -n "$RULES" ] && compgen -G "$RULES/*.rules.toml" >/dev/null 2>&1 || {
    echo "No rule files found. Pass the directory as the second argument:"
    echo "  $0 $DB /var/lib/easywaf/rules-cache/sets"
    exit 1
}

echo "Database:   $DB"
echo "Rule files: $RULES"

# Every catalogue number the installed rule files currently publish.
PUBLISHED=$(grep -ho '^[[:space:]]*id[[:space:]]*=[[:space:]]*[0-9]\+' "$RULES"/*.rules.toml \
            | grep -o '[0-9]\+' | sort -u | paste -sd, -)
[ -n "$PUBLISHED" ] || { echo "Could not read any rule ids from $RULES"; exit 1; }
echo "Published:  $(echo "$PUBLISHED" | tr ',' '\n' | wc -l | tr -d ' ') rule numbers"

# The debris, defined once. A temp view lives only as long as the connection
# that made it, so the definition travels with every statement below rather
# than being created once and hoped for.
SQL_VIEW="CREATE TEMP VIEW debris AS
  -- 1. A rule that came from a set whose catalogue no longer contains its
  --    number. Renumbering left it behind; nothing will ever update it again,
  --    and it still scores alongside the rule that replaced it.
  SELECT id, policy_id, external_id, name, 'renumbering orphan' AS why
  FROM   waf_rules
  WHERE  external_id IS NOT NULL
    AND  external_id NOT IN ($PUBLISHED)
    AND  cloned_from_external_id IS NULL   -- a clone is deliberate, not debris
  UNION ALL
  -- 2. A custom rule with no provenance whose pattern is already carried by a
  --    catalogue rule in the same policy. That is the seeder's signature: a
  --    rule someone wrote themselves does not duplicate a catalogue pattern
  --    character for character.
  SELECT c.id, c.policy_id, c.external_id, c.name, 'seeded duplicate'
  FROM   waf_rules c
  WHERE  c.external_id IS NULL
    AND  c.rule_set IS NULL
    AND  c.cloned_from_external_id IS NULL
    AND  EXISTS (SELECT 1 FROM waf_rules o
                 WHERE o.policy_id = c.policy_id
                   AND o.external_id IS NOT NULL
                   AND o.pattern = c.pattern);"

echo
echo "-- What would be deleted -----------------------------------"
sqlite3 -header -column "$DB" "$SQL_VIEW
  SELECT id, policy_id AS pol, COALESCE(external_id,'') AS ext, why,
         substr(name,1,40) AS name
  FROM debris ORDER BY why, policy_id, id;"

COUNT=$(sqlite3 "$DB" "$SQL_VIEW SELECT COUNT(*) FROM debris;")
echo
echo "$COUNT rules match."
[ "$COUNT" -eq 0 ] && { echo "Nothing to do."; exit 0; }

echo
echo "Read the list. A rule you wrote yourself should not be in it — if one is,"
echo "stop and say so rather than deleting it."
BACKUP="$DB.$(date +%Y%m%d-%H%M%S).bak"
read -r -p "Back up to $BACKUP and delete these $COUNT rules? [yes/N] " ans
[ "$ans" = "yes" ] || { echo "Nothing changed."; exit 0; }

sqlite3 "$DB" ".backup '$BACKUP'"
echo "Backed up to $BACKUP"

sqlite3 "$DB" "PRAGMA foreign_keys=ON;
$SQL_VIEW
DELETE FROM waf_rules WHERE id IN (SELECT id FROM debris);"

LEFT=$(sqlite3 "$DB" "$SQL_VIEW SELECT COUNT(*) FROM debris;")
echo "Deleted. $LEFT still match (expected 0)."
echo
echo "Restart EasyWAF, then re-check a request that was scoring too high."

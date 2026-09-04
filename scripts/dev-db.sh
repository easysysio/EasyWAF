#!/usr/bin/env bash
# =========================================================
# dev-db.sh — EasyWAF
# Bring the development database up to date with migrations/.
#
#   ./scripts/dev-db.sh
#
# sqlx validates every query! macro against a real database
# *at compile time*, so the schema has to exist before the
# code will build. That database is the one DATABASE_URL
# points at — .env sets it to ./easywaf.db.
#
# The catch: migrations are applied by the running binary, so
# a database that has not been run against a recent build
# falls behind, and the next `cargo build` fails with a wall
# of "no such column" errors that look like code faults but
# are not. This script closes that gap without needing the
# binary to run first.
#
# Existing data is kept and nothing is ever dropped: every
# migration is additive. A database already brought up to
# date is left completely untouched — the version is checked
# first and the script exits without running anything.
# =========================================================
set -u

DB="${1:-}"

# Fall back to .env, then to the conventional path.
if [ -z "$DB" ]; then
    if [ -f .env ]; then
        DB=$(grep -E '^DATABASE_URL=' .env | head -1 | sed 's|^DATABASE_URL=||; s|^sqlite://||')
    fi
    DB="${DB:-easywaf.db}"
fi

if ! command -v sqlite3 >/dev/null; then
    echo "sqlite3 is required but not installed." >&2
    exit 1
fi

# The highest number in migrations/, e.g. 9 for 009_site_tls.sql. Derived
# rather than counted, so a gap in the numbering cannot silently understate it.
LATEST=$(ls migrations/*.sql 2>/dev/null | sed 's|.*/||; s|_.*||' | sed 's|^0*||' | sort -n | tail -1)

if [ -z "$LATEST" ]; then
    echo "No migrations found in migrations/." >&2
    exit 1
fi

echo "Database: $DB"

if [ -f "$DB" ]; then
    # PRAGMA user_version is SQLite's own per-database integer, unused by
    # EasyWAF itself — the binary decides what to apply by inspecting the
    # schema directly. Stamping it here lets this script skip the whole pass
    # on a database it has already brought up to date, which is the common
    # case: nothing to do, so nothing is touched.
    CURRENT=$(sqlite3 "$DB" "PRAGMA user_version;" 2>/dev/null || echo 0)
    if [ "${CURRENT:-0}" -ge "$LATEST" ]; then
        echo "  already at migration $CURRENT — nothing to do"
        exit 0
    fi
    echo "  at migration ${CURRENT:-0}, latest is $LATEST"
else
    echo "  (creating — it does not exist yet)"
fi
echo

applied=0
skipped=0
failed=0

for f in migrations/*.sql; do
    name=$(basename "$f" .sql)
    # stderr only: 001 runs `PRAGMA journal_mode=WAL`, and the sqlite3 CLI
    # prints the resulting mode to stdout. Capturing both would read that
    # perfectly normal output as a failure.
    err=$(sqlite3 "$DB" < "$f" 2>&1 >/dev/null)

    if [ -z "$err" ]; then
        # No error. For an ALTER this means the column was genuinely added;
        # for a CREATE TABLE IF NOT EXISTS it may equally mean nothing
        # happened. SQLite does not distinguish the two here, so this counts
        # as "ran without complaint" rather than a claim about what changed.
        printf '  \033[32mran\033[0m      %s\n' "$name"
        applied=$((applied + 1))
    elif echo "$err" | grep -qiE "duplicate column|already exists"; then
        # Re-running a migration that is already in place. Every migration is
        # written to be additive, so this is the ordinary case on an existing
        # database rather than a problem.
        printf '  skipped  %s\n' "$name"
        skipped=$((skipped + 1))
    else
        printf '  \033[31mFAILED\033[0m   %s — %s\n' "$name" "$err"
        failed=$((failed + 1))
    fi
done

echo
echo "  $applied ran, $skipped already present, $failed failed"

if [ "$failed" -gt 0 ]; then
    echo
    echo "Some migrations failed. The build will still not see the schema they" >&2
    echo "add — fix those before running cargo build." >&2
    exit 1
fi

# Record how far this database has been brought, so a later run can skip the
# pass entirely rather than replaying every migration to discover there is
# nothing to do.
sqlite3 "$DB" "PRAGMA user_version = $LATEST;" 2>/dev/null

echo
echo "cargo build should now succeed."

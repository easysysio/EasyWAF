#!/usr/bin/env bash
# =========================================================
# fetch-rules.sh — EasyWAF
# Refresh rules/ from the published rule channel.
#
#   ./scripts/fetch-rules.sh
#   ./scripts/fetch-rules.sh https://repo.easysys.io/easywaf/rules
#
# The EasyWAF-rules repository is the source of truth and is
# published to this channel; rules/ here is a snapshot taken
# from it. Taking it with a script rather than by hand is the
# point: a hand-maintained second copy is what left one
# version of a rule corrected and another broken for four
# releases.
#
# Only sets marked tier = "basic" in sets.toml are taken.
# Optional sets are published for installations that want
# them; a set that only matters to one application should not
# cost every deployment the matching.
#
# Written for bash 3.2 (macOS) as well as CI: no mapfile, no
# associative arrays.
# =========================================================
set -euo pipefail

BASE="${1:-${EASYWAF_RULES_URL:-https://repo.easysys.io/easywaf/rules}}"
BASE="${BASE%/}"
DEST="rules"

[ -f Cargo.toml ] && [ -d rules ] || { echo "Run from the EasyWAF repository root." >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required." >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Fetching rule sets from $BASE"

get() {  # get <remote-path> <local-file>
    curl -fsSL --max-time 60 "$BASE/$1" -o "$2" 2>/dev/null
}

if ! get "sets.toml" "$TMP/sets.toml"; then
    echo >&2
    echo "Could not fetch $BASE/sets.toml" >&2
    echo >&2
    echo "The channel serves the EasyWAF-rules repository. If sets.toml is missing," >&2
    echo "that repository has not been published since it was added." >&2
    exit 1
fi

# ── Signature ────────────────────────────────────────────
# A rule set decides what traffic is refused, so an unverified one fetched over
# the network is a supply-chain hole. The channel is not signed yet; until it
# is, this warns rather than refuses, and refuses outright when asked to.
# Once the same GPG key that signs the packages also signs sets.toml, the
# default here should flip to refusing.
REQUIRE_SIG="${EASYWAF_RULES_REQUIRE_SIGNATURE:-0}"
if get "sets.toml.asc" "$TMP/sets.toml.asc" 2>/dev/null; then
    if command -v gpg >/dev/null && gpg --verify "$TMP/sets.toml.asc" "$TMP/sets.toml" 2>/dev/null; then
        echo "  signature: verified"
    else
        echo "  signature: PRESENT BUT DID NOT VERIFY — refusing" >&2
        exit 1
    fi
elif [ "$REQUIRE_SIG" = "1" ]; then
    echo "  signature: absent, and a signature was required — refusing" >&2
    exit 1
else
    echo "  signature: none published yet (set EASYWAF_RULES_REQUIRE_SIGNATURE=1 to refuse)"
fi

# ── Which sets are basic ─────────────────────────────────
# Parsed with awk rather than a TOML library: this runs in CI images and on a
# build host, and should need nothing but curl and awk.
# `.*"` would be greedy and swallow the whole line, so the quoted value is
# matched explicitly. `tier` is read after `file`, which is the order sets.toml
# uses; a set missing either is skipped rather than half-read.
awk '
    function quoted(s,   v) {
        if (match(s, /"[^"]*"/)) return substr(s, RSTART + 1, RLENGTH - 2)
        return ""
    }
    /^[[:space:]]*\[\[sets\]\]/      { file = ""; tier = "" }
    /^[[:space:]]*file[[:space:]]*=/ { file = quoted($0) }
    /^[[:space:]]*tier[[:space:]]*=/ { tier = quoted($0)
                                       if (tier == "basic" && file != "") print file }
' "$TMP/sets.toml" > "$TMP/basic"

COUNT=$(wc -l < "$TMP/basic" | tr -d ' ')
[ "$COUNT" -gt 0 ] || { echo "sets.toml declares no basic sets." >&2; exit 1; }

# Everything is fetched before anything is replaced, so a channel that fails
# halfway leaves the working copy alone rather than half-updated.
mkdir -p "$TMP/new"
while IFS= read -r f; do
    [ -n "$f" ] || continue
    if ! get "$f" "$TMP/new/$(basename "$f")"; then
        echo "sets.toml names $f, which the channel does not serve." >&2
        exit 1
    fi
done < "$TMP/basic"

# Replaced wholesale, not merged: a set withdrawn upstream — because a rule in
# it was wrong — must disappear here too rather than live on in every build.
rm -f "$DEST"/*.rules.toml
cp "$TMP/new"/*.rules.toml "$DEST/"

{
    echo "# Written by scripts/fetch-rules.sh — do not edit."
    echo "# rules/ is a snapshot of the published rule channel."
    echo "source = \"$BASE\""
    echo "taken  = \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
    echo
    for f in "$DEST"/*.rules.toml; do
        if command -v sha256sum >/dev/null; then h=$(sha256sum "$f" | cut -d' ' -f1)
        else h=$(shasum -a 256 "$f" | cut -d' ' -f1); fi
        echo "[[set]]"
        echo "file   = \"$(basename "$f")\""
        echo "sha256 = \"$h\""
    done
} > "$DEST/SOURCE"

RULES=$(grep -ch '^\[\[rules\]\]' "$DEST"/*.rules.toml | awk '{s+=$1} END {print s}')
echo "  $COUNT basic sets, $RULES rules"
echo
echo "Review 'git diff rules/' before committing. These decide what traffic is"
echo "refused; a change here is not one to wave through."

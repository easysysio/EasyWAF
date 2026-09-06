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
# the network is a supply-chain hole. Refusing is the default; the escape hatch
# is for bringing a new channel up, not for routine use.
#
# The manifest carries a sha256 per set, so a verified manifest covers every
# file without needing a signature each.
#
# rules/key.gpg is the trust anchor, and it is deliberately a file in this
# repository rather than something taken from the channel each run. Fetching
# the key from the same server that serves what it signs proves only that the
# server is self-consistent. Pinning it here means a compromised channel can
# serve whatever it likes and still fail verification.
#
# The running appliance reads the same rules/key.gpg to verify updates it
# fetches for itself, so this file is not only a build-time check — it ships.
ALLOW_UNSIGNED="${EASYWAF_RULES_ALLOW_UNSIGNED:-0}"
KEY="$DEST/key.gpg"

if [ ! -f "$KEY" ]; then
    # First run against a channel. Take the key, then say plainly that nothing
    # has been verified yet and a human has to vouch for it once.
    if get "key.gpg" "$TMP/key.gpg"; then
        cp "$TMP/key.gpg" "$KEY"
        echo "  key: none pinned — took $BASE/key.gpg on trust"
        echo "       Confirm the fingerprint below against the channel's own"
        echo "       published one, then commit $KEY. Every later run verifies"
        echo "       against it, so this is the one time it is taken on faith."
        gpg --show-keys --with-fingerprint "$KEY" 2>/dev/null | sed 's/^/       /' || true
    elif [ "$ALLOW_UNSIGNED" != "1" ]; then
        echo >&2
        echo "  No key at $BASE/key.gpg and none pinned at $KEY — refusing." >&2
        echo "  Publish with publish.sh, or set EASYWAF_RULES_ALLOW_UNSIGNED=1" >&2
        echo "  if you are bringing a channel up." >&2
        exit 1
    fi
fi

if get "sets.toml.asc" "$TMP/sets.toml.asc"; then
    command -v gpg >/dev/null || { echo "  signature present but gpg is not installed — refusing" >&2; exit 1; }
    [ -f "$KEY" ] || { echo "  signature present but no key at $KEY — refusing" >&2; exit 1; }
    # A throwaway keyring holding nothing but the pinned key, so a signature by
    # any other key the builder happens to trust is still a failure.
    KR="$TMP/keyring"; mkdir -p "$KR"; chmod 700 "$KR"
    if gpg --homedir "$KR" --batch --quiet --import "$KEY" 2>"$TMP/gpg.err" \
       && gpg --homedir "$KR" --batch --trust-model always \
              --verify "$TMP/sets.toml.asc" "$TMP/sets.toml" 2>"$TMP/gpg.err"; then
        echo "  signature: verified against $KEY"
        sed -n 's/^gpg: *Good signature from /  signed by: /p' "$TMP/gpg.err"
    else
        echo "  signature: DID NOT VERIFY against $KEY — refusing" >&2
        sed 's/^/    /' "$TMP/gpg.err" >&2
        echo "    The channel is signed by a key this repository does not pin." >&2
        echo "    If the signing key was rotated, replace $KEY deliberately —" >&2
        echo "    do not let this script do it for you." >&2
        exit 1
    fi
elif [ "$ALLOW_UNSIGNED" = "1" ]; then
    echo "  signature: ABSENT, continuing because EASYWAF_RULES_ALLOW_UNSIGNED=1"
else
    echo >&2
    echo "  No signature at $BASE/sets.toml.asc — refusing." >&2
    echo "  Rule sets decide what traffic is refused; an unverified one is not" >&2
    echo "  worth the convenience. Publish with publish.sh, or set" >&2
    echo "  EASYWAF_RULES_ALLOW_UNSIGNED=1 if you are bringing a channel up." >&2
    exit 1
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

# Each set is checked against the hash in the manifest that the signature
# covers. Without this, the signature would prove the index authentic while the
# sets themselves arrived unverified.
python3 - "$TMP/sets.toml" "$TMP/new" <<'CHECKSUMS' || exit 1
import hashlib, re, sys, os
manifest, newdir = sys.argv[1], sys.argv[2]
bad = []
for b in open(manifest).read().split("[[sets]]")[1:]:
    def v(k):
        m = re.search(r'^' + k + r'\s*=\s*"([^"]+)"', b, re.M)
        return m.group(1) if m else None
    f, want, tier = v("file"), v("sha256"), v("tier")
    if tier != "basic":
        continue
    if not want:
        bad.append(f + ": manifest carries no sha256")
        continue
    local = os.path.join(newdir, os.path.basename(f))
    got = hashlib.sha256(open(local, "rb").read()).hexdigest()
    if got != want:
        bad.append(f + ": sha256 " + got[:12] + " does not match manifest " + want[:12])
if bad:
    print("  Content does not match the signed manifest - refusing:", file=sys.stderr)
    for x in bad:
        print("    " + x, file=sys.stderr)
    sys.exit(1)
print("  checksums: every set matches the signed manifest")
CHECKSUMS

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
    # Versions come from the manifest: they are what tells an installation an
    # update exists, so a snapshot has to record which ones it holds.
    python3 - "$TMP/sets.toml" <<'VERSIONS'
import re, sys
for b in open(sys.argv[1]).read().split("[[sets]]")[1:]:
    def v(k):
        m = re.search(r'^' + k + r'\s*=\s*"?([^"\n]+)"?', b, re.M)
        return m.group(1).strip() if m else ""
    if v("tier") != "basic":
        continue
    print("[[set]]")
    print('id      = "' + v("id") + '"')
    print("version = " + v("version"))
    print('file    = "' + v("file").split("/")[-1] + '"')
    print('sha256  = "' + v("sha256") + '"')
VERSIONS
} > "$DEST/SOURCE"

RULES=$(grep -ch '^\[\[rules\]\]' "$DEST"/*.rules.toml | awk '{s+=$1} END {print s}')
echo "  $COUNT basic sets, $RULES rules"
echo
echo "Review 'git diff rules/' before committing. These decide what traffic is"
echo "refused; a change here is not one to wave through."

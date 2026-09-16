#!/usr/bin/env bash
# Regenerate the OpenPGP fixtures with gpg, which is what signs the real
# channel — a key made by the library under test would only prove it agrees
# with itself.
set -euo pipefail
cd "$(dirname "$0")"
export GNUPGHOME=$(mktemp -d); trap 'rm -rf "$GNUPGHOME"' EXIT
printf 'rule set manifest fixture\n' > pgp_data.txt
gpg --batch --quiet --passphrase '' --quick-gen-key "EasyWAF Fixture <fixture@example.invalid>" default default never
gpg --batch --quiet --passphrase '' --quick-gen-key "Someone Else <other@example.invalid>" default default never
gpg --batch --yes --armor --local-user fixture@example.invalid --detach-sign -o pgp_good.asc  pgp_data.txt
gpg --batch --yes --armor --local-user other@example.invalid   --detach-sign -o pgp_other.asc pgp_data.txt
gpg --batch --yes --armor --export fixture@example.invalid > pgp_key.asc

# A signed IP list mirror, laid out as EasyWAF keeps one on disk.
rm -rf lists && mkdir -p lists/lists
cat > lists/lists/fixture-drop.txt <<'LIST'
; Fixture DROP List - not real data
; lines after a semicolon are comments

192.0.2.0/24 ; FIX1
198.51.100.0/25 ; FIX2
2001:db8::/32 ; FIX3
LIST
sum=$( (command -v sha256sum >/dev/null && sha256sum lists/lists/fixture-drop.txt || shasum -a 256 lists/lists/fixture-drop.txt) | cut -d' ' -f1)
cat > lists/lists.toml <<TOML
[[lists]]
id          = "fixture-drop"
name        = "Fixture DROP"
description = "Documentation ranges, for tests."
licence     = "CC0"
attribution = "EasyWAF test fixtures"
version     = "2026091601"
entries     = 3
response    = "block"
file        = "lists/fixture-drop.txt"
sha256      = "$sum"
TOML
gpg --batch --yes --armor --local-user fixture@example.invalid --detach-sign -o lists/lists.toml.asc lists/lists.toml
echo "fixtures written"

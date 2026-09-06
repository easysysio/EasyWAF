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
echo "fixtures written"

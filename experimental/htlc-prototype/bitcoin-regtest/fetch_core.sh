#!/usr/bin/env bash
# Install no system packages or services. DEST must be a new task-local directory.
set -euo pipefail
umask 077
dest=${1:?usage: bash fetch_core.sh NEW_TASK_LOCAL_DIRECTORY}
mkdir "$dest"
cd "$dest"
version=31.1
archive=bitcoin-31.1-x86_64-linux-gnu.tar.gz
fingerprint=E777299FC265DD04793070EB944D35F9AC3DB76A
expected_sha256=b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e
for file in "$archive" SHA256SUMS SHA256SUMS.asc; do
    curl --fail --location --proto '=https' --tlsv1.2 --output "$file" "https://bitcoincore.org/bin/bitcoin-core-$version/$file"
done
curl --fail --location --proto '=https' --tlsv1.2 --output fanquake.gpg \
    https://raw.githubusercontent.com/bitcoin-core/guix.sigs/main/builder-keys/fanquake.gpg
mkdir gnupg
chmod 700 gnupg
gpg --homedir gnupg --import fanquake.gpg >gpg-import.log 2>&1
# The manifest has signatures from other builders too. Require the exact pinned
# primary fingerprint's valid signature even if those other keys are unavailable.
gpg --homedir gnupg --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS >gpg-status.log 2>gpg-verify.log || true
awk -v key="$fingerprint" '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && $NF == key { good=1 } END { exit !good }' gpg-status.log
sha256sum --ignore-missing --check SHA256SUMS
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check
tar -xzf "$archive" "bitcoin-$version/bin/bitcoind" "bitcoin-$version/bin/bitcoin-cli"
python3 - "$version" "$archive" "$expected_sha256" "$fingerprint" <<'PY'
import json, sys
from pathlib import Path
version, archive, digest, fingerprint = sys.argv[1:]
Path("release-verification.json").write_text(json.dumps({
    "version": version, "archive": archive, "archive_sha256": digest,
    "valid_signature_primary_fingerprint": fingerprint,
    "sha256_manifest_verified": True,
    "source": f"https://bitcoincore.org/bin/bitcoin-core-{version}/",
}, indent=2) + "\n")
PY
printf 'Verified task-local bitcoind: %s/bitcoin-%s/bin/bitcoind\n' "$PWD" "$version"

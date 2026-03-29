#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_TAR="${1:-$ROOT/audits/native-backend-128b/native-backend-128b-review-package.tar.gz}"
PACKAGE_SHA="${2:-$ROOT/audits/native-backend-128b/package.sha256}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

python3 - <<'PY' "$PACKAGE_TAR" "$PACKAGE_SHA"
import hashlib
from pathlib import Path
import sys

package_tar = Path(sys.argv[1])
package_sha = Path(sys.argv[2])
expected_line = package_sha.read_text(encoding="utf-8").strip()
expected_hash, expected_name = expected_line.split("  ", 1)
actual_hash = hashlib.sha256(package_tar.read_bytes()).hexdigest()
if actual_hash != expected_hash:
    raise SystemExit(f"package hash mismatch: {actual_hash} != {expected_hash}")
if package_tar.name != expected_name:
    raise SystemExit(f"package name mismatch: {package_tar.name} != {expected_name}")
PY

tar -xzf "$PACKAGE_TAR" -C "$WORKDIR"
test -f "$WORKDIR/native-backend-128b-review-package/docs/crypto/native_backend_commitment_reduction.md"
test -f "$WORKDIR/native-backend-128b-review-package/source/tools/native-backend-ref/src/lib.rs"
test -f "$WORKDIR/native-backend-128b-review-package/source/circuits/superneo-hegemon/src/lib.rs"
test -f "$WORKDIR/native-backend-128b-review-package/source/circuits/superneo-backend-lattice/src/lib.rs"
cargo run -p native-backend-ref -- verify-vectors \
  "$WORKDIR/native-backend-128b-review-package/testdata/native_backend_vectors"

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/audits/native-backend-128b}"
PACKAGE_BASENAME="native-backend-128b-review-package"
PACKAGE_TAR="$OUT_DIR/${PACKAGE_BASENAME}.tar.gz"
PACKAGE_SHA="$OUT_DIR/package.sha256"
BENCHMARK_JSON="${NATIVE_BACKEND_BENCHMARK_JSON:-$ROOT/.agent/benchmarks/native_tx_leaf_receipt_root_security_package_final_20260327.json}"

mkdir -p "$OUT_DIR"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
STAGE="$WORKDIR/$PACKAGE_BASENAME"

mkdir -p \
  "$STAGE/docs/crypto" \
  "$STAGE/testdata/native_backend_vectors" \
  "$STAGE/audits/native-backend-128b" \
  "$STAGE/benchmarks"

cp "$ROOT/docs/crypto/native_backend_spec.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_security_analysis.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_attack_worksheet.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_constant_time.md" "$STAGE/docs/crypto/"
cp "$ROOT/testdata/native_backend_vectors/bundle.json" "$STAGE/testdata/native_backend_vectors/"
cp "$ROOT/audits/native-backend-128b/CLAIMS.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/THREAT_MODEL.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/REVIEW_QUESTIONS.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/REPORT_TEMPLATE.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/KNOWN_GAPS.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/BREAKIT_RULES.md" "$STAGE/audits/native-backend-128b/"
cp "$BENCHMARK_JSON" "$STAGE/benchmarks/native_tx_leaf_receipt_root_release.json"
git -C "$ROOT" rev-parse HEAD > "$STAGE/code_fingerprint.txt"

cargo run -p superneo-bench -- --print-native-security-claim > "$STAGE/current_claim.json"
cargo run -p native-backend-ref -- verify-vectors "$ROOT/testdata/native_backend_vectors" \
  > "$STAGE/reference_verifier_report.json"

python3 - <<'PY' "$STAGE" "$PACKAGE_TAR" "$PACKAGE_SHA"
import hashlib
import io
import os
import tarfile
from pathlib import Path
import sys

stage = Path(sys.argv[1])
package_tar = Path(sys.argv[2])
package_sha = Path(sys.argv[3])

with tarfile.open(package_tar, "w:gz", compresslevel=9, format=tarfile.PAX_FORMAT) as tar:
    for path in sorted(stage.rglob("*")):
        arcname = stage.name + "/" + str(path.relative_to(stage))
        info = tar.gettarinfo(str(path), arcname=arcname)
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mtime = 0
        if path.is_file():
            with path.open("rb") as fh:
                tar.addfile(info, fh)
        else:
            tar.addfile(info)

digest = hashlib.sha256(package_tar.read_bytes()).hexdigest()
package_sha.write_text(f"{digest}  {package_tar.name}\n", encoding="utf-8")
print(digest)
PY

printf '%s\n' "$PACKAGE_TAR"
printf '%s\n' "$PACKAGE_SHA"

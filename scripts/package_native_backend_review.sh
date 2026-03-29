#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/audits/native-backend-128b}"
PACKAGE_BASENAME="native-backend-128b-review-package"
PACKAGE_TAR="$OUT_DIR/${PACKAGE_BASENAME}.tar.gz"
PACKAGE_SHA="$OUT_DIR/package.sha256"
BENCHMARK_JSON="${NATIVE_BACKEND_BENCHMARK_JSON:-$ROOT/.agent/benchmarks/native_tx_leaf_receipt_root_claim_alignment_20260328.json}"

mkdir -p "$OUT_DIR"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
STAGE="$WORKDIR/$PACKAGE_BASENAME"

mkdir -p \
  "$STAGE/docs/crypto" \
  "$STAGE/testdata/native_backend_vectors" \
  "$STAGE/audits/native-backend-128b" \
  "$STAGE/benchmarks" \
  "$STAGE/source"

cp "$ROOT/docs/crypto/native_backend_spec.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_commitment_reduction.md" "$STAGE/docs/crypto/"
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

python3 - <<'PY' "$ROOT" "$STAGE/source"
from __future__ import annotations

from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
out = Path(sys.argv[2])

paths = [
    "Cargo.toml",
    "Cargo.lock",
    "circuits/superneo-backend-lattice/Cargo.toml",
    "circuits/superneo-backend-lattice/src",
    "circuits/superneo-ccs/Cargo.toml",
    "circuits/superneo-ccs/src",
    "circuits/superneo-core/Cargo.toml",
    "circuits/superneo-core/src",
    "circuits/superneo-hegemon/Cargo.toml",
    "circuits/superneo-hegemon/src",
    "circuits/superneo-ring/Cargo.toml",
    "circuits/superneo-ring/src",
    "circuits/transaction/Cargo.toml",
    "circuits/transaction/src",
    "circuits/transaction-core/Cargo.toml",
    "circuits/transaction-core/src",
    "protocol/versioning/Cargo.toml",
    "protocol/versioning/src",
    "tools/native-backend-ref/Cargo.toml",
    "tools/native-backend-ref/src",
    "scripts/package_native_backend_review.sh",
    "scripts/verify_native_backend_review_package.sh",
]

for rel in paths:
    src = root / rel
    dst = out / rel
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
PY

python3 - <<'PY' "$ROOT" "$STAGE/code_fingerprint.json"
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
out = Path(sys.argv[2])

def run_bytes(*args: str) -> bytes:
    return subprocess.check_output(args, cwd=root)

head_commit = run_bytes("git", "rev-parse", "HEAD").decode("utf-8").strip()
tracked_diff = run_bytes("git", "diff", "--binary", "HEAD", "--")
staged_diff = run_bytes("git", "diff", "--cached", "--binary", "--")
untracked_raw = run_bytes("git", "ls-files", "--others", "--exclude-standard", "-z")
untracked_paths = [
    item for item in untracked_raw.decode("utf-8", "surrogateescape").split("\0") if item
]

tracked_diff_sha = hashlib.sha256(tracked_diff).hexdigest()
staged_diff_sha = hashlib.sha256(staged_diff).hexdigest()

untracked_entries = []
untracked_acc = hashlib.sha256()
for rel in sorted(untracked_paths):
    path = root / rel
    data = path.read_bytes() if path.is_file() else b""
    digest = hashlib.sha256(data).hexdigest()
    untracked_entries.append(
        {
            "path": rel,
            "sha256": digest,
            "size": len(data),
        }
    )
    untracked_acc.update(rel.encode("utf-8", "surrogateescape"))
    untracked_acc.update(b"\0")
    untracked_acc.update(bytes.fromhex(digest))

fingerprint_input = hashlib.sha256()
fingerprint_input.update(head_commit.encode("utf-8"))
fingerprint_input.update(b"\0")
fingerprint_input.update(bytes.fromhex(tracked_diff_sha))
fingerprint_input.update(bytes.fromhex(staged_diff_sha))
fingerprint_input.update(untracked_acc.digest())

payload = {
    "head_commit": head_commit,
    "dirty": bool(tracked_diff or staged_diff or untracked_entries),
    "tracked_diff_sha256": tracked_diff_sha,
    "staged_diff_sha256": staged_diff_sha,
    "untracked_files": untracked_entries,
    "worktree_fingerprint": fingerprint_input.hexdigest(),
}

out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

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

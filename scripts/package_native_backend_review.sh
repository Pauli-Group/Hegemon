#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/audits/native-backend-128b}"
PACKAGE_BASENAME="native-backend-128b-review-package"
PACKAGE_TAR="$OUT_DIR/${PACKAGE_BASENAME}.tar.gz"
PACKAGE_SHA="$OUT_DIR/package.sha256"
PACKAGE_HELPER="$ROOT/scripts/native_backend_review_package.py"

mkdir -p "$OUT_DIR"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
STAGE="$WORKDIR/$PACKAGE_BASENAME"

mkdir -p \
  "$STAGE/docs/crypto" \
  "$STAGE/testdata/native_backend_vectors" \
  "$STAGE/audits/native-backend-128b" \
  "$STAGE/structured_lattice" \
  "$STAGE/source"

cp "$ROOT/docs/crypto/native_backend_spec.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_formal_theorems.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_commitment_reduction.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_security_analysis.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_cryptanalysis_note.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_verified_aggregation.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_attack_worksheet.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/crypto/native_backend_constant_time.md" "$STAGE/docs/crypto/"
cp "$ROOT/docs/SECURITY_REVIEWS.md" "$STAGE/docs/"
cp "$ROOT/testdata/native_backend_vectors/bundle.json" "$STAGE/testdata/native_backend_vectors/"
cp "$ROOT/audits/native-backend-128b/CLAIMS.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/THREAT_MODEL.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/REVIEW_QUESTIONS.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/REPORT_TEMPLATE.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/KNOWN_GAPS.md" "$STAGE/audits/native-backend-128b/"
cp "$ROOT/audits/native-backend-128b/BREAKIT_RULES.md" "$STAGE/audits/native-backend-128b/"
git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$STAGE/source"
rm -f \
  "$STAGE/source/audits/native-backend-128b/native-backend-128b-review-package.tar.gz" \
  "$STAGE/source/audits/native-backend-128b/package.sha256"
SOURCE_TREE_SHA256="$(python3 -I "$PACKAGE_HELPER" source-digest --source "$STAGE/source")"

python3 -I - "$ROOT" "$STAGE/code_fingerprint.json" "$SOURCE_TREE_SHA256" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
out = Path(sys.argv[2])
source_tree_sha256 = sys.argv[3]

def run_bytes(*args: str) -> bytes:
    return subprocess.check_output(args, cwd=root)

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
fingerprint_input.update(source_tree_sha256.encode("utf-8"))
fingerprint_input.update(b"\0")
fingerprint_input.update(bytes.fromhex(tracked_diff_sha))
fingerprint_input.update(bytes.fromhex(staged_diff_sha))
fingerprint_input.update(untracked_acc.digest())

payload = {
    "source_tree_sha256": source_tree_sha256,
    "dirty": bool(tracked_diff or staged_diff or untracked_entries),
    "tracked_diff_sha256": tracked_diff_sha,
    "staged_diff_sha256": staged_diff_sha,
    "untracked_files": untracked_entries,
    "worktree_fingerprint": fingerprint_input.hexdigest(),
}

if payload["dirty"]:
    raise SystemExit(
        "review package must be generated from a clean committed worktree: "
        + json.dumps(payload, sort_keys=True)
    )

out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

cargo run --locked -p superneo-bench -- --print-native-security-claim > "$STAGE/current_claim.json"
cargo run --locked -p superneo-bench -- --print-native-review-manifest > "$STAGE/review_manifest.json"
cargo run --locked -p superneo-bench -- --print-native-attack-model > "$STAGE/attack_model.json"
cargo run --locked -p superneo-bench -- --print-native-message-class > "$STAGE/message_class.json"
cargo run --locked -p superneo-bench -- --print-native-claim-sweep > "$STAGE/claim_sweep.json"
cargo run --locked -p superneo-bench -- --print-native-structured-lattice-model > "$STAGE/structured_lattice_model.json"
cargo run --locked -p superneo-bench -- --run-native-reduced-cryptanalysis-spikes > "$STAGE/reduced_cryptanalysis_spikes.json"
cargo run --locked -p superneo-bench -- --export-native-flattened-sis-instance "$STAGE/structured_lattice" \
  > "$STAGE/structured_lattice_export_report.json"
cargo run --locked -p native-backend-ref -- verify-vectors "$STAGE/testdata/native_backend_vectors" \
  > "$STAGE/reference_verifier_report.json"
cargo run --locked -p native-backend-ref -- verify-claim --package-dir "$STAGE" \
  > "$STAGE/reference_claim_verifier_report.json"
cargo run --locked -p superneo-bench -- --verify-review-bundle-production "$STAGE/testdata/native_backend_vectors" \
  > "$STAGE/production_verifier_report.json"

python3 -I "$PACKAGE_HELPER" normalize-json-reports --root "$STAGE"

if ! git -C "$ROOT" diff --quiet HEAD -- \
    || ! git -C "$ROOT" diff --cached --quiet -- \
    || [ -n "$(git -C "$ROOT" ls-files --others --exclude-standard)" ]; then
  echo "review package generation changed its committed source inputs" >&2
  exit 1
fi

python3 -I - "$STAGE" "$PACKAGE_TAR" "$PACKAGE_SHA" <<'PY'
import gzip
import hashlib
import tarfile
from pathlib import Path
import sys

stage = Path(sys.argv[1])
package_tar = Path(sys.argv[2])
package_sha = Path(sys.argv[3])

with package_tar.open("wb") as raw:
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=raw,
        mtime=0,
    ) as compressed:
        with tarfile.open(
            fileobj=compressed,
            mode="w",
            format=tarfile.PAX_FORMAT,
        ) as archive:
            for path in sorted(stage.rglob("*")):
                if path.is_symlink():
                    raise SystemExit(f"review package refuses symlink: {path}")
                arcname = stage.name + "/" + str(path.relative_to(stage))
                info = archive.gettarinfo(str(path), arcname=arcname)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                if path.is_file():
                    with path.open("rb") as handle:
                        archive.addfile(info, handle)
                else:
                    archive.addfile(info)

digest = hashlib.sha256(package_tar.read_bytes()).hexdigest()
package_sha.write_text(f"{digest}  {package_tar.name}\n", encoding="utf-8")
print(digest)
PY

printf '%s\n' "$PACKAGE_TAR"
printf '%s\n' "$PACKAGE_SHA"

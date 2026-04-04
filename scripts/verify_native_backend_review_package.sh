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
test -f "$WORKDIR/native-backend-128b-review-package/docs/crypto/native_backend_formal_theorems.md"
test -f "$WORKDIR/native-backend-128b-review-package/docs/crypto/native_backend_verified_aggregation.md"
test -f "$WORKDIR/native-backend-128b-review-package/docs/SECURITY_REVIEWS.md"
test -f "$WORKDIR/native-backend-128b-review-package/current_claim.json"
test -f "$WORKDIR/native-backend-128b-review-package/attack_model.json"
test -f "$WORKDIR/native-backend-128b-review-package/message_class.json"
test -f "$WORKDIR/native-backend-128b-review-package/claim_sweep.json"
test -f "$WORKDIR/native-backend-128b-review-package/review_manifest.json"
test -f "$WORKDIR/native-backend-128b-review-package/reference_verifier_report.json"
test -f "$WORKDIR/native-backend-128b-review-package/reference_claim_verifier_report.json"
test -f "$WORKDIR/native-backend-128b-review-package/production_verifier_report.json"
test -f "$WORKDIR/native-backend-128b-review-package/source/tools/native-backend-ref/src/lib.rs"
test -f "$WORKDIR/native-backend-128b-review-package/source/circuits/superneo-hegemon/src/lib.rs"
test -f "$WORKDIR/native-backend-128b-review-package/source/circuits/superneo-backend-lattice/src/lib.rs"
test -f "$WORKDIR/native-backend-128b-review-package/source/circuits/superneo-bench/src/main.rs"
python3 - <<'PY' \
  "$WORKDIR/native-backend-128b-review-package/review_manifest.json" \
  "$WORKDIR/native-backend-128b-review-package/current_claim.json" \
  "$WORKDIR/native-backend-128b-review-package/attack_model.json" \
  "$WORKDIR/native-backend-128b-review-package/message_class.json" \
  "$WORKDIR/native-backend-128b-review-package/claim_sweep.json" \
  "$WORKDIR/native-backend-128b-review-package/reference_verifier_report.json" \
  "$WORKDIR/native-backend-128b-review-package/reference_claim_verifier_report.json" \
  "$WORKDIR/native-backend-128b-review-package/production_verifier_report.json"
import json
from pathlib import Path
import sys

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
claim = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
attack = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
message = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
sweep = json.loads(Path(sys.argv[5]).read_text(encoding="utf-8"))
reference = json.loads(Path(sys.argv[6]).read_text(encoding="utf-8"))
reference_claim = json.loads(Path(sys.argv[7]).read_text(encoding="utf-8"))
production = json.loads(Path(sys.argv[8]).read_text(encoding="utf-8"))
stats = manifest["exact_live_tx_leaf_commitment"]
guarantees = manifest["guarantee_summary"]
claim_body = claim["native_security_claim"]
attack_claim = attack["native_security_claim"]
attack_stats = attack["exact_live_tx_leaf_commitment"]

assert stats["witness_bits"] == 4935, stats
assert stats["packed_digits"] == 617, stats
assert stats["live_message_ring_elems"] == 12, stats
assert stats["live_coefficient_dimension"] == 648, stats
assert stats["live_problem_l2_bound"] == 6492, stats
assert message["witness_bits"] == 4935, message
assert message["packed_digits"] == 617, message
assert message["live_message_ring_elems"] == 12, message
assert message["live_coefficient_dimension"] == 648, message
assert message["live_problem_l2_bound"] == 6492, message
assert attack_stats == stats, (attack_stats, stats)

assert guarantees["security_object"] == "verified_leaf_aggregation", guarantees
assert guarantees["verified_tx_leaf_replay"] is True, guarantees
assert guarantees["fold_parent_rows_recomputed"] is True, guarantees
assert guarantees["fold_proof_digest_recomputed"] is True, guarantees
assert guarantees["ccs_soundness_from_fold_layer_alone"] is False, guarantees
assert guarantees["external_cryptanalysis_completed"] is False, guarantees

assert claim_body["soundness_scope_label"] == "verified_leaf_aggregation", claim_body
assert attack_claim["soundness_scope_label"] == "verified_leaf_aggregation", attack_claim
assert claim_body["transcript_soundness_bits"] == 312, claim_body
assert claim_body["soundness_floor_bits"] == 305, claim_body
assert attack_claim == claim_body, (attack_claim, claim_body)
assert attack["transcript_model"]["transcript_soundness_bits"] == 312, attack["transcript_model"]
assert attack["transcript_model"]["composition_loss_bits"] == 7, attack["transcript_model"]
assert attack["transcript_model"]["transcript_floor_bits"] == 305, attack["transcript_model"]
assert attack["estimator_trace"]["block_size"] == 3294, attack["estimator_trace"]
assert attack["estimator_trace"]["quantum_bits"] == 872, attack["estimator_trace"]
assert sweep["active_message_cap"] == 76, sweep
assert sweep["active_receipt_root_leaf_cap"] == 128, sweep
assert reference["summary"]["failed_cases"] == 0, reference["summary"]
assert reference_claim["passed"] is True, reference_claim
assert reference_claim["mismatches"] == [], reference_claim["mismatches"]
assert production["summary"]["failed_cases"] == 0, production["summary"]

theorems = set(manifest["theorem_documents"])
assert "docs/crypto/native_backend_formal_theorems.md" in theorems, theorems
assert "docs/crypto/native_backend_verified_aggregation.md" in theorems, theorems
PY
cargo run -p native-backend-ref -- verify-vectors \
  "$WORKDIR/native-backend-128b-review-package/testdata/native_backend_vectors"
cargo run -p native-backend-ref -- verify-claim \
  --package-dir "$WORKDIR/native-backend-128b-review-package"
cargo run -p superneo-bench -- --verify-review-bundle-production \
  "$WORKDIR/native-backend-128b-review-package/testdata/native_backend_vectors"

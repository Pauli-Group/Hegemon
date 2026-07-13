#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_TAR="${1:-$ROOT/audits/native-backend-128b/native-backend-128b-review-package.tar.gz}"
PACKAGE_SHA="${2:-$ROOT/audits/native-backend-128b/package.sha256}"
PACKAGE_HELPER="$ROOT/scripts/native_backend_review_package.py"

for forbidden in \
  NATIVE_BACKEND_REVIEW_CHECKOUT_ROOT \
  NATIVE_BACKEND_REVIEW_CHECKOUT_ONLY \
  NATIVE_BACKEND_BENCHMARK_JSON; do
  if [[ -n "${!forbidden:-}" ]]; then
    echo "$forbidden is not supported by the complete package verifier" >&2
    exit 2
  fi
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

python3 -I "$PACKAGE_HELPER" extract \
  --archive "$PACKAGE_TAR" \
  --sha "$PACKAGE_SHA" \
  --destination "$WORKDIR"
PACKAGE_ROOT="$WORKDIR/native-backend-128b-review-package"
SOURCE_ROOT="$PACKAGE_ROOT/source"

python3 -I "$PACKAGE_HELPER" verify-source \
  --checkout "$ROOT" \
  --package-root "$PACKAGE_ROOT"
python3 -I "$PACKAGE_HELPER" verify-package-layout \
  --package-root "$PACKAGE_ROOT"
python3 -I "$PACKAGE_HELPER" verify-evidence-semantics \
  --root "$PACKAGE_ROOT"
SOURCE_TREE_SHA256="$(python3 -I "$PACKAGE_HELPER" source-digest --source "$SOURCE_ROOT")"

required_files=(
  "docs/crypto/native_backend_commitment_reduction.md"
  "docs/crypto/native_backend_formal_theorems.md"
  "docs/crypto/native_backend_cryptanalysis_note.md"
  "docs/crypto/native_backend_verified_aggregation.md"
  "docs/SECURITY_REVIEWS.md"
  "current_claim.json"
  "attack_model.json"
  "message_class.json"
  "claim_sweep.json"
  "structured_lattice_model.json"
  "reduced_cryptanalysis_spikes.json"
  "structured_lattice_export_report.json"
  "structured_lattice/matrix_metadata.json"
  "structured_lattice/ring_commitment_matrix_u64_le.bin"
  "structured_lattice/flat_commitment_matrix_u64_le.bin"
  "review_manifest.json"
  "reference_verifier_report.json"
  "reference_claim_verifier_report.json"
  "production_verifier_report.json"
  "code_fingerprint.json"
  "source/formal/lean/Hegemon/Native/NativeBackendAlgebra.lean"
  "source/formal/lean/Hegemon/Native/GenerateNativeBackendAlgebraVectors.lean"
  "source/tools/native-backend-ref/src/lib.rs"
  "source/circuits/superneo-hegemon/src/lib.rs"
  "source/circuits/superneo-backend-lattice/src/lib.rs"
  "source/circuits/superneo-bench/src/main.rs"
)
for relative in "${required_files[@]}"; do
  test -f "$PACKAGE_ROOT/$relative"
done

python3 -I - \
  "$PACKAGE_ROOT/review_manifest.json" \
  "$PACKAGE_ROOT/current_claim.json" \
  "$PACKAGE_ROOT/attack_model.json" \
  "$PACKAGE_ROOT/message_class.json" \
  "$PACKAGE_ROOT/claim_sweep.json" \
  "$PACKAGE_ROOT/structured_lattice_model.json" \
  "$PACKAGE_ROOT/reduced_cryptanalysis_spikes.json" \
  "$PACKAGE_ROOT/structured_lattice_export_report.json" \
  "$PACKAGE_ROOT/structured_lattice/matrix_metadata.json" \
  "$PACKAGE_ROOT/reference_verifier_report.json" \
  "$PACKAGE_ROOT/reference_claim_verifier_report.json" \
  "$PACKAGE_ROOT/production_verifier_report.json" \
  "$PACKAGE_ROOT/code_fingerprint.json" \
  "$SOURCE_TREE_SHA256" <<'PY'
import json
from pathlib import Path
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
claim = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
attack = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
message = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
sweep = json.loads(Path(sys.argv[5]).read_text(encoding="utf-8"))
structured = json.loads(Path(sys.argv[6]).read_text(encoding="utf-8"))
reduced = json.loads(Path(sys.argv[7]).read_text(encoding="utf-8"))
export_report = json.loads(Path(sys.argv[8]).read_text(encoding="utf-8"))
matrix_metadata = json.loads(Path(sys.argv[9]).read_text(encoding="utf-8"))
reference = json.loads(Path(sys.argv[10]).read_text(encoding="utf-8"))
reference_claim = json.loads(Path(sys.argv[11]).read_text(encoding="utf-8"))
production = json.loads(Path(sys.argv[12]).read_text(encoding="utf-8"))
fingerprint = json.loads(Path(sys.argv[13]).read_text(encoding="utf-8"))
source_tree_sha256 = sys.argv[14]
stats = manifest["exact_live_tx_leaf_commitment"]
guarantees = manifest["guarantee_summary"]
claim_body = claim["native_security_claim"]
attack_claim = attack["native_security_claim"]
attack_stats = attack["exact_live_tx_leaf_commitment"]

require(stats["witness_bits"] == 4935, f"bad exact commitment stats: {stats}")
require(stats["packed_digits"] == 617, f"bad exact commitment stats: {stats}")
require(stats["live_message_ring_elems"] == 12, f"bad exact commitment stats: {stats}")
require(stats["live_coefficient_dimension"] == 648, f"bad exact commitment stats: {stats}")
require(stats["live_problem_l2_bound"] == 6492, f"bad exact commitment stats: {stats}")
require(message["witness_bits"] == 4935, f"bad message class: {message}")
require(message["packed_digits"] == 617, f"bad message class: {message}")
require(message["live_message_ring_elems"] == 12, f"bad message class: {message}")
require(message["live_coefficient_dimension"] == 648, f"bad message class: {message}")
require(message["live_problem_l2_bound"] == 6492, f"bad message class: {message}")
require(attack_stats == stats, "attack model and manifest commitment stats differ")

require(guarantees["security_object"] == "verified_leaf_aggregation", f"bad guarantees: {guarantees}")
require(guarantees["verified_tx_leaf_replay"] is True, f"bad guarantees: {guarantees}")
require(guarantees["fold_parent_rows_recomputed"] is True, f"bad guarantees: {guarantees}")
require(guarantees["fold_proof_digest_recomputed"] is True, f"bad guarantees: {guarantees}")
require(guarantees["ccs_soundness_from_fold_layer_alone"] is False, f"bad guarantees: {guarantees}")
require(guarantees["external_cryptanalysis_completed"] is False, f"bad guarantees: {guarantees}")

require(claim_body["soundness_scope_label"] == "verified_leaf_aggregation", f"bad claim: {claim_body}")
require(attack_claim["soundness_scope_label"] == "verified_leaf_aggregation", f"bad attack claim: {attack_claim}")
require(claim_body["transcript_soundness_bits"] == 312, f"bad claim: {claim_body}")
require(claim_body["soundness_floor_bits"] == 305, f"bad claim: {claim_body}")
require(attack_claim == claim_body, "attack model and current claim differ")
require(attack["transcript_model"]["transcript_soundness_bits"] == 312, "bad transcript model")
require(attack["transcript_model"]["composition_loss_bits"] == 7, "bad transcript model")
require(attack["transcript_model"]["transcript_floor_bits"] == 305, "bad transcript model")
require(attack["estimator_trace"]["block_size"] == 3294, "bad estimator trace")
require(attack["estimator_trace"]["quantum_bits"] == 872, "bad estimator trace")
require(sweep["active_message_cap"] == 76, f"bad claim sweep: {sweep}")
require(sweep["active_receipt_root_leaf_cap"] == 128, f"bad claim sweep: {sweep}")
require(structured["conservative_instance"]["equation_dimension"] == 594, "bad structured model")
require(structured["conservative_instance"]["witness_dimension"] == 4104, "bad structured model")
require(structured["inverse_crt_report"]["min_one_component_max_coeff_abs"] == 8589934591, "bad inverse CRT report")
require(structured["inverse_crt_report"]["min_nonzero_component_difference_max_coeff_abs"] == 8589934591, "bad inverse CRT report")
require(structured["threshold_table"][0]["target_bits"] == 305, "bad threshold table")
require(structured["threshold_table"][0]["block_size_haircut"] == 2143, "bad threshold table")
require(reduced["reduced_matrix"]["flat_rows"] == 108, "bad reduced matrix")
require(reduced["reduced_matrix"]["flat_cols"] == 108, "bad reduced matrix")
require(all(case["found_nonzero_kernel"] is False for case in reduced["cases"]), "reduced spike found a kernel")
require(matrix_metadata["flat_rows"] == 594, "bad matrix metadata")
require(matrix_metadata["flat_cols"] == 4104, "bad matrix metadata")
require(export_report["flat_matrix_bytes"] == 19502208, "bad structured export")
require(export_report["ring_matrix_bytes"] == 361152, "bad structured export")
require(reference["summary"]["failed_cases"] == 0, f"reference vectors failed: {reference}")
require(reference_claim["passed"] is True, f"reference claim failed: {reference_claim}")
require(reference_claim["mismatches"] == [], f"reference claim mismatches: {reference_claim}")
require(production["summary"]["failed_cases"] == 0, f"production vectors failed: {production}")
require(fingerprint["dirty"] is False, f"dirty package fingerprint: {fingerprint}")
require(fingerprint["untracked_files"] == [], f"untracked package inputs: {fingerprint}")
require(
    fingerprint["source_tree_sha256"] == source_tree_sha256,
    f"source tree fingerprint mismatch: {fingerprint}",
)
require(
    fingerprint["tracked_diff_sha256"]
    == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    f"tracked diff fingerprint is not empty: {fingerprint}",
)
require(
    fingerprint["staged_diff_sha256"]
    == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    f"staged diff fingerprint is not empty: {fingerprint}",
)

theorems = set(manifest["theorem_documents"])
require(
    "docs/crypto/native_backend_formal_theorems.md" in theorems,
    f"formal theorem document missing from manifest: {theorems}",
)
require(
    "docs/crypto/native_backend_verified_aggregation.md" in theorems,
    f"aggregation theorem document missing from manifest: {theorems}",
)
PY

REGENERATED_ROOT="$WORKDIR/regenerated"
VERIFIED_SOURCE_ROOT="$WORKDIR/verified-source"
mkdir -p \
  "$REGENERATED_ROOT/structured_lattice" \
  "$REGENERATED_ROOT/testdata/native_backend_vectors" \
  "$VERIFIED_SOURCE_ROOT"
cp -a "$SOURCE_ROOT/." "$VERIFIED_SOURCE_ROOT/"
cp \
  "$PACKAGE_ROOT/testdata/native_backend_vectors/bundle.json" \
  "$REGENERATED_ROOT/testdata/native_backend_vectors/bundle.json"

(
  cd "$VERIFIED_SOURCE_ROOT"
  export CARGO_TARGET_DIR="$WORKDIR/cargo-target"
  cargo run --locked -p superneo-bench -- --print-native-security-claim \
    > "$REGENERATED_ROOT/current_claim.json"
  cargo run --locked -p superneo-bench -- --print-native-review-manifest \
    > "$REGENERATED_ROOT/review_manifest.json"
  cargo run --locked -p superneo-bench -- --print-native-attack-model \
    > "$REGENERATED_ROOT/attack_model.json"
  cargo run --locked -p superneo-bench -- --print-native-message-class \
    > "$REGENERATED_ROOT/message_class.json"
  cargo run --locked -p superneo-bench -- --print-native-claim-sweep \
    > "$REGENERATED_ROOT/claim_sweep.json"
  cargo run --locked -p superneo-bench -- --print-native-structured-lattice-model \
    > "$REGENERATED_ROOT/structured_lattice_model.json"
  cargo run --locked -p superneo-bench -- --run-native-reduced-cryptanalysis-spikes \
    > "$REGENERATED_ROOT/reduced_cryptanalysis_spikes.json"
  cargo run --locked -p superneo-bench -- \
    --export-native-flattened-sis-instance "$REGENERATED_ROOT/structured_lattice" \
    > "$REGENERATED_ROOT/structured_lattice_export_report.json"
  cargo run --locked -p native-backend-ref -- verify-vectors \
    "$REGENERATED_ROOT/testdata/native_backend_vectors" \
    > "$REGENERATED_ROOT/reference_verifier_report.json"
  cargo run --locked -p native-backend-ref -- verify-claim \
    --package-dir "$REGENERATED_ROOT" \
    > "$REGENERATED_ROOT/reference_claim_verifier_report.json"
  cargo run --locked -p superneo-bench -- --verify-review-bundle-production \
    "$REGENERATED_ROOT/testdata/native_backend_vectors" \
    > "$REGENERATED_ROOT/production_verifier_report.json"
)

python3 -I "$PACKAGE_HELPER" normalize-json-reports --root "$REGENERATED_ROOT"
python3 -I "$PACKAGE_HELPER" verify-evidence-semantics \
  --root "$REGENERATED_ROOT"
python3 -I "$PACKAGE_HELPER" verify-generated-evidence \
  --package-root "$PACKAGE_ROOT" \
  --regenerated-root "$REGENERATED_ROOT"

printf 'native backend review package verified from packaged source\n'

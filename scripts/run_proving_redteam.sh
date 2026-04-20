#!/usr/bin/env bash

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

MODE="${HEGEMON_REDTEAM_MODE:-full}"
if [[ "$MODE" != "ci" && "$MODE" != "full" ]]; then
  echo "Unsupported HEGEMON_REDTEAM_MODE: $MODE" >&2
  exit 2
fi

export PROPTEST_MAX_CASES="${PROPTEST_MAX_CASES:-64}"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="$ROOT/output/proving-redteam/$TIMESTAMP"
mkdir -p "$OUTDIR"

RUNNER_LOG="$OUTDIR/runner.log"
SUMMARY_TXT="$OUTDIR/summary.txt"
SUMMARY_JSON="$OUTDIR/summary.json"

declare -a CAMPAIGNS=()
declare -a RESULTS=()
declare -a LOGS=()

campaign_script() {
  case "$1" in
    parser-malleability)
      cat <<'EOF'
cargo test -p hegemon-node submit_proofs_rejects_non_native_tx_leaf_artifact -- --nocapture
cargo test -p hegemon-node submit_proofs_rejects_binding_hash_mismatch_for_native_tx_leaf -- --nocapture
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo +nightly fuzz run native_tx_leaf_artifact -- -max_total_time=30
fi
EOF
      ;;
    semantic-aliasing)
      cat <<'EOF'
cargo test -p hegemon-node proof_da_blob_rejects_duplicate_binding_hash -- --nocapture
cargo test -p hegemon-node filter_conflicting_shielded_transfers_drops_binding_conflicts_and_keeps_nullifier_overlaps -- --nocapture
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo test -p transaction-circuit --test security_fuzz -- --nocapture
  cargo test -p wallet --test address_fuzz -- --nocapture
fi
EOF
      ;;
    staged-proof-abuse)
      cat <<'EOF'
cargo test -p hegemon-node submit_ciphertexts_rejects_ -- --nocapture
cargo test -p hegemon-node submit_proofs_rejects_ -- --nocapture
cargo test -p hegemon-node sidecar_ -- --nocapture
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo test security_pipeline -- --nocapture
fi
EOF
      ;;
    recursive-block-mismatch)
      cat <<'EOF'
cargo test -p consensus recursive_block_v1_verifier_rejects_tx_count_mismatch -- --nocapture
cargo test -p consensus recursive_block_v2_verifier_rejects_tx_count_mismatch -- --nocapture
cargo test -p consensus --test raw_active_mode raw_active_rejects_bad_tx_proof -- --ignored --nocapture
EOF
      ;;
    receipt-root-tamper)
      cat <<'EOF'
cargo test -p hegemon-node receipt_root -- --nocapture
cargo test -p consensus --test raw_active_mode receipt_root_ -- --ignored --nocapture
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo +nightly fuzz run receipt_root_artifact -- -max_total_time=30
fi
EOF
      ;;
    prover-configuration-downgrade)
      cat <<'EOF'
cargo test -p wallet test_fast_config_is_clamped_without_explicit_override -- --nocapture
cargo test -p wallet test_fast_config_requires_explicit_override_to_weaken_floor -- --nocapture
EOF
      ;;
    review-package-parity)
      cat <<'EOF'
cargo test -p superneo-backend-lattice -p native-backend-ref -p superneo-hegemon -p superneo-bench
cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors
./scripts/package_native_backend_review.sh
./scripts/verify_native_backend_review_package.sh
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo run -p native-backend-timing --release
fi
EOF
      ;;
    *)
      echo "unknown campaign: $1" >&2
      return 2
      ;;
  esac
}

run_campaign() {
  local name="$1"
  local log="$OUTDIR/${name}.log"
  local script
  script="$(campaign_script "$name")"

  CAMPAIGNS+=("$name")
  LOGS+=("$log")

  echo "==> $name" | tee -a "$RUNNER_LOG"
  {
    echo "# mode: $MODE"
    echo "# campaign: $name"
    echo "# started_at_utc: $(date -u +%FT%TZ)"
    echo "# command_script:"
    printf '%s\n' "$script"
    echo
    HEGEMON_REDTEAM_MODE="$MODE" bash -lc "$script"
  } 2>&1 | tee "$log"

  local status="${PIPESTATUS[0]}"
  if [[ "$status" -eq 0 ]]; then
    RESULTS+=("pass")
    echo "PASS $name" | tee -a "$RUNNER_LOG"
  else
    RESULTS+=("fail")
    echo "FAIL $name (exit $status)" | tee -a "$RUNNER_LOG"
  fi
}

run_campaign "parser-malleability"
run_campaign "semantic-aliasing"
run_campaign "staged-proof-abuse"
run_campaign "recursive-block-mismatch"
run_campaign "receipt-root-tamper"
run_campaign "prover-configuration-downgrade"
run_campaign "review-package-parity"

overall="pass"
for result in "${RESULTS[@]}"; do
  if [[ "$result" != "pass" ]]; then
    overall="fail"
    break
  fi
done

{
  echo "mode=$MODE"
  echo "output_dir=$OUTDIR"
  echo "overall=$overall"
  for i in "${!CAMPAIGNS[@]}"; do
    echo "${CAMPAIGNS[$i]} ${RESULTS[$i]} ${LOGS[$i]}"
  done
} >"$SUMMARY_TXT"

{
  printf '{\n'
  printf '  "mode": "%s",\n' "$MODE"
  printf '  "output_dir": "%s",\n' "$OUTDIR"
  printf '  "overall": "%s",\n' "$overall"
  printf '  "campaigns": [\n'
  for i in "${!CAMPAIGNS[@]}"; do
    comma=","
    if [[ "$i" -eq $((${#CAMPAIGNS[@]} - 1)) ]]; then
      comma=""
    fi
    printf '    {"name":"%s","status":"%s","log":"%s"}%s\n' \
      "${CAMPAIGNS[$i]}" "${RESULTS[$i]}" "${LOGS[$i]}" "$comma"
  done
  printf '  ]\n'
  printf '}\n'
} >"$SUMMARY_JSON"

echo "Summary written to $SUMMARY_TXT"
echo "JSON summary written to $SUMMARY_JSON"

if [[ "$overall" != "pass" ]]; then
  exit 1
fi

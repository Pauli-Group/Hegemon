#!/usr/bin/env bash

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

MODE="${HEGEMON_REDTEAM_MODE:-full}"
HEGEMON_FUZZ_TOOLCHAIN="${HEGEMON_FUZZ_TOOLCHAIN:-nightly-2026-06-23}"
if [[ "$MODE" != "ci" && "$MODE" != "full" ]]; then
  echo "Unsupported HEGEMON_REDTEAM_MODE: $MODE" >&2
  exit 2
fi

export PROPTEST_CASES="${PROPTEST_CASES:-${PROPTEST_MAX_CASES:-64}}"
export HEGEMON_FUZZ_TOOLCHAIN
unset PROPTEST_MAX_CASES

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTDIR="$ROOT/output/proving-redteam/$TIMESTAMP"
mkdir -p "$OUTDIR"

RUNNER_LOG="$OUTDIR/runner.log"
SUMMARY_TXT="$OUTDIR/summary.txt"
SUMMARY_JSON="$OUTDIR/summary.json"

declare -a CAMPAIGNS=()
declare -a RESULTS=()
declare -a LOGS=()

cargo_test_filter() {
  local package="$1"
  local filter="$2"
  shift 2

  local list
  if ! list="$(cargo test -p "$package" "$filter" -- --list 2>&1)"; then
    printf '%s\n' "$list" >&2
    return 1
  fi

  local matches
  matches="$(printf '%s\n' "$list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  if [[ "$matches" -eq 0 ]]; then
    echo "red-team gate matched zero tests: cargo test -p $package $filter" >&2
    return 97
  fi

  cargo test -p "$package" "$filter" "$@"
}
export -f cargo_test_filter

cargo_test_lib_filter() {
  local package="$1"
  local filter="$2"
  shift 2

  local list
  if ! list="$(cargo test -p "$package" --lib "$filter" -- --list 2>&1)"; then
    printf '%s\n' "$list" >&2
    return 1
  fi

  local matches
  matches="$(printf '%s\n' "$list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  if [[ "$matches" -eq 0 ]]; then
    echo "red-team gate matched zero tests: cargo test -p $package --lib $filter" >&2
    return 97
  fi

  cargo test -p "$package" --lib "$filter" "$@"
}
export -f cargo_test_lib_filter

cargo_test_target() {
  local package="$1"
  local target="$2"
  shift 2

  local list
  if ! list="$(cargo test -p "$package" --test "$target" -- --list 2>&1)"; then
    printf '%s\n' "$list" >&2
    return 1
  fi

  local matches
  matches="$(printf '%s\n' "$list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  if [[ "$matches" -eq 0 ]]; then
    echo "red-team gate matched zero tests: cargo test -p $package --test $target" >&2
    return 97
  fi

  cargo test -p "$package" --test "$target" "$@"
}
export -f cargo_test_target

campaign_script() {
  case "$1" in
    parser-malleability)
      cat <<'EOF'
cargo_test_filter hegemon-node submit_proofs_rejects_non_native_tx_leaf_artifact -- --nocapture
cargo_test_filter hegemon-node submit_proofs_rejects_repartitioned_tx_leaf_binding_alias -- --nocapture
cargo_test_filter hegemon-node submit_proofs_rejects_binding_hash_mismatch_before_staging -- --nocapture
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo +"${HEGEMON_FUZZ_TOOLCHAIN:-nightly-2026-06-23}" fuzz run native_tx_leaf_artifact -- -max_total_time=30
fi
EOF
      ;;
    semantic-aliasing)
      cat <<'EOF'
cargo_test_filter hegemon-node submit_proofs_rejects_repartitioned_tx_leaf_binding_alias -- --nocapture
cargo_test_filter hegemon-node transfer_action_rejects_inline_repartitioned_tx_leaf_binding_alias -- --nocapture
cargo_test_filter hegemon-node transfer_action_rejects_sidecar_repartitioned_tx_leaf_binding_alias -- --nocapture
cargo_test_filter hegemon-node inbound_bridge_rejects_message_binding_tampering -- --nocapture
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo test -p transaction-circuit --test security_fuzz -- --nocapture
  cargo test -p wallet --test address_fuzz -- --nocapture
fi
EOF
      ;;
    staged-proof-abuse)
      cat <<'EOF'
cargo_test_filter hegemon-node submit_ciphertexts_rejects_ -- --nocapture
cargo_test_filter hegemon-node submit_proofs_rejects_ -- --nocapture
cargo_test_filter hegemon-node rpc_byte_parser_rejects_oversized_strings_before_trust_boundary_decode -- --nocapture
cargo_test_filter hegemon-node sidecar_ -- --nocapture
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo_test_target security-tests security_pipeline -- --nocapture
fi
EOF
      ;;
    recursive-block-mismatch)
      cat <<'EOF'
cargo_test_lib_filter consensus recursive_block_v1_direct_verifier_requires_semantic_replay_before_tx_count_mismatch -- --nocapture
cargo_test_lib_filter consensus recursive_block_v2_direct_verifier_requires_semantic_replay_before_tx_count_mismatch -- --nocapture
cargo_test_target consensus raw_active_mode raw_active_rejects_bad_tx_proof -- --ignored --nocapture
EOF
      ;;
    receipt-root-tamper)
      cat <<'EOF'
cargo_test_lib_filter consensus parallel_receipt_root_payload_mismatches_reject_before_backend -- --nocapture
cargo_test_lib_filter consensus receipt_root_artifact_kind_and_profile_mismatch_reject_before_backend -- --nocapture
cargo_test_lib_filter consensus receipt_root_statement_commitment_mismatch_rejects_before_backend -- --nocapture
cargo_test_target consensus raw_active_mode receipt_root_ -- --ignored --nocapture
if [[ "${HEGEMON_REDTEAM_MODE:-full}" == "full" ]]; then
  cargo +"${HEGEMON_FUZZ_TOOLCHAIN:-nightly-2026-06-23}" fuzz run receipt_root_artifact -- -max_total_time=30
fi
EOF
      ;;
    prover-configuration-downgrade)
      cat <<'EOF'
cargo_test_filter wallet test_fast_config_is_clamped_without_explicit_override -- --nocapture
cargo_test_filter wallet test_fast_config_requires_explicit_override_to_weaken_floor -- --nocapture
EOF
      ;;
    network-transport-abuse)
      cat <<'EOF'
cargo_test_lib_filter pq-noise handshake_does_not_use_public_transcript_as_kem_seed -- --nocapture
cargo_test_lib_filter pq-noise encapsulate_with_seed_consumes_supplied_seed -- --nocapture
cargo_test_lib_filter network encapsulate_with_seed_consumes_supplied_seed -- --nocapture
cargo_test_target network adversarial -- --nocapture
cargo_test_target network handshake duplex_stream_handshake_succeeds_and_rejects_tampering -- --nocapture
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
  local script_file="$OUTDIR/${name}.sh"
  local script_text
  script_text="$(campaign_script "$name")"
  printf '%s\n' "$script_text" >"$script_file"

  CAMPAIGNS+=("$name")
  LOGS+=("$log")

  echo "==> $name" | tee -a "$RUNNER_LOG"
  {
    echo "# mode: $MODE"
    echo "# campaign: $name"
    echo "# started_at_utc: $(date -u +%FT%TZ)"
    echo "# command_script:"
    printf '%s\n' "$script_text"
    echo
    HEGEMON_REDTEAM_MODE="$MODE" bash -euo pipefail "$script_file"
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
run_campaign "network-transport-abuse"
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

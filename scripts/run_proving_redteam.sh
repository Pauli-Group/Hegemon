#!/usr/bin/env bash

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

if [[ -d "${HOME:-}/.elan/bin" ]]; then
  export PATH="${HOME}/.elan/bin:$PATH"
fi
if ! command -v lake >/dev/null 2>&1; then
  echo "Lean lake is required for the SmallWood adversarial conformance campaign" >&2
  exit 2
fi

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

require_filter_execution_summary() {
  local label="$1"
  local expected="$2"
  local output="$3"
  local counts
  counts="$(printf '%s\n' "$output" | awk '
    /test result:/ { passed += $4; failed += $6; ignored += $8; summaries += 1 }
    END { print passed + 0, failed + 0, ignored + 0, summaries + 0 }')"
  local passed failed ignored summaries
  read -r passed failed ignored summaries <<<"$counts"
  if [[ "$summaries" -eq 0 || "$passed" -ne "$expected" || "$failed" -ne 0 || "$ignored" -ne 0 ]]; then
    printf 'red-team gate execution mismatch for %s: expected=%s passed=%s failed=%s ignored=%s summaries=%s\n' \
      "$label" "$expected" "$passed" "$failed" "$ignored" "$summaries" >&2
    return 97
  fi
}
export -f require_filter_execution_summary

cargo_test_filter() {
  local package="$1"
  local filter="$2"
  shift 2

  local list
  if ! list="$(cargo test -p "$package" "$filter" -- --list 2>&1)"; then
    printf '%s\n' "$list" >&2
    return 1
  fi

  local total_matches ignored_matches expected_matches
  total_matches="$(printf '%s\n' "$list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  local ignored_list
  if ! ignored_list="$(cargo test -p "$package" "$filter" -- --ignored --list 2>&1)"; then
    printf '%s\n' "$ignored_list" >&2
    return 1
  fi
  ignored_matches="$(printf '%s\n' "$ignored_list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  expected_matches=$((total_matches - ignored_matches))
  if [[ "$expected_matches" -le 0 ]]; then
    printf 'red-team gate matched no nonignored tests: cargo test -p %s %s (total=%s ignored=%s)\n' \
      "$package" "$filter" "$total_matches" "$ignored_matches" >&2
    return 97
  fi

  local output
  if ! output="$(CARGO_TERM_COLOR=never cargo test -p "$package" "$filter" "$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
  printf '%s\n' "$output"
  require_filter_execution_summary "$package $filter" "$expected_matches" "$output"
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

  local total_matches ignored_matches expected_matches
  total_matches="$(printf '%s\n' "$list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  local ignored_list
  if ! ignored_list="$(cargo test -p "$package" --lib "$filter" -- --ignored --list 2>&1)"; then
    printf '%s\n' "$ignored_list" >&2
    return 1
  fi
  ignored_matches="$(printf '%s\n' "$ignored_list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  expected_matches=$((total_matches - ignored_matches))
  if [[ "$expected_matches" -le 0 ]]; then
    printf 'red-team gate matched no nonignored tests: cargo test -p %s --lib %s (total=%s ignored=%s)\n' \
      "$package" "$filter" "$total_matches" "$ignored_matches" >&2
    return 97
  fi

  local output
  if ! output="$(CARGO_TERM_COLOR=never cargo test -p "$package" --lib "$filter" "$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
  printf '%s\n' "$output"
  require_filter_execution_summary "$package --lib $filter" "$expected_matches" "$output"
}
export -f cargo_test_lib_filter

cargo_test_lib_exact() {
  local package="$1"
  local test_name="$2"
  shift 2

  local listed
  if ! listed="$(cargo test -p "$package" --lib -- --list 2>&1)"; then
    printf '%s\n' "$listed" >&2
    return 1
  fi
  local matches
  matches="$(printf '%s\n' "$listed" \
    | awk -v expected="${test_name}: test" '$0 == expected { count++ } END { print count + 0 }')"
  if [[ "$matches" -ne 1 ]]; then
    echo "red-team gate expected one exact test $test_name in $package, found $matches" >&2
    return 97
  fi

  local ignored
  ignored="$(cargo test -p "$package" --lib -- --ignored --list 2>&1 \
    | awk -v expected="${test_name}: test" '$0 == expected { count++ } END { print count + 0 }')"
  if [[ "$ignored" -ne 0 ]]; then
    echo "red-team gate refuses ignored test $test_name in $package" >&2
    return 97
  fi

  local output
  if ! output="$(CARGO_TERM_COLOR=never cargo test -p "$package" --lib "$test_name" \
      -- --exact "$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
  printf '%s\n' "$output"
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed; 0 ignored;' <<<"$output"; then
    echo "red-team gate did not execute exactly one test: $test_name" >&2
    return 97
  fi
}
export -f cargo_test_lib_exact

cargo_test_target() {
  local package="$1"
  local target="$2"
  shift 2

  local cargo_filter_args=()
  local cargo_filter_count=0
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "--" ]]; then
      break
    fi
    cargo_filter_args+=("$arg")
    cargo_filter_count=$((cargo_filter_count + 1))
  done

  local list
  if [[ "$cargo_filter_count" -eq 0 ]]; then
    if ! list="$(cargo test -p "$package" --test "$target" -- --list 2>&1)"; then
      printf '%s\n' "$list" >&2
      return 1
    fi
  else
    if ! list="$(cargo test -p "$package" --test "$target" "${cargo_filter_args[@]}" -- --list 2>&1)"; then
      printf '%s\n' "$list" >&2
      return 1
    fi
  fi

  local total_matches ignored_matches expected_matches
  total_matches="$(printf '%s\n' "$list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  local ignored_list
  if [[ "$cargo_filter_count" -eq 0 ]]; then
    if ! ignored_list="$(cargo test -p "$package" --test "$target" -- --ignored --list 2>&1)"; then
      printf '%s\n' "$ignored_list" >&2
      return 1
    fi
  else
    if ! ignored_list="$(cargo test -p "$package" --test "$target" "${cargo_filter_args[@]}" -- --ignored --list 2>&1)"; then
      printf '%s\n' "$ignored_list" >&2
      return 1
    fi
  fi
  ignored_matches="$(printf '%s\n' "$ignored_list" | awk '/: test$/ { count++ } END { print count + 0 }')"
  expected_matches=$((total_matches - ignored_matches))
  if [[ "$expected_matches" -le 0 ]]; then
    printf 'red-team gate matched no nonignored tests: cargo test -p %s --test %s (total=%s ignored=%s)\n' \
      "$package" "$target" "$total_matches" "$ignored_matches" >&2
    return 97
  fi

  local output
  if ! output="$(CARGO_TERM_COLOR=never cargo test -p "$package" --test "$target" "$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
  printf '%s\n' "$output"
  require_filter_execution_summary "$package --test $target" "$expected_matches" "$output"
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
    smallwood-lean-spec-hardening)
      cat <<'EOF'
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::lean_generated_smallwood_transcript_binding_vectors_match_production --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::smallwood_active_profile_is_no_grinding_and_pow_bits_are_transcript_bound --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_frontend_inline_merkle_rejects_spend_secret_not_matching_input_pk_auth --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_inline_merkle_rejects_active_input_note_value_and_commitment_mutation --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_inline_merkle_rejects_active_output_binding_mutation --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_inline_merkle_rejects_inactive_nonzero_public_nullifier --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_inline_merkle_rejects_inactive_output_ciphertext_hash --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_inline_merkle_rejects_merkle_sibling_and_root_mutation --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_inline_merkle_rejects_nullifier_position_and_rho_mutation --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_inline_merkle_rejects_public_balance_mutation --nocapture
cargo_test_lib_exact transaction-circuit smallwood_frontend::tests::packed_smallwood_inline_merkle_rejects_public_stablecoin_delta_mutation --nocapture
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
cargo_test_lib_exact consensus proof::tests::recursive_block_v2_product_wrapper_rejects_independent_artifact_mutations --nocapture
cargo_test_filter block-recursion recursive_proof_envelope_component_checks_reject_tampered_envelope -- --nocapture
cargo_test_filter hegemon-node block_artifact_binding_rejects_candidate_artifact_mismatches_in_order -- --nocapture
EOF
      ;;
    receipt-root-tamper)
      cat <<'EOF'
cargo_test_lib_filter consensus receipt_root_artifact_kind_and_profile_mismatch_reject_before_backend -- --nocapture
cargo_test_lib_filter consensus receipt_root_statement_commitment_mismatch_rejects_before_backend -- --nocapture
cargo_test_lib_filter superneo-hegemon native_receipt_root_rejects_ -- --nocapture
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
run_campaign "smallwood-lean-spec-hardening"
run_campaign "staged-proof-abuse"
run_campaign "recursive-block-mismatch"
run_campaign "receipt-root-tamper"
run_campaign "prover-configuration-downgrade"
run_campaign "network-transport-abuse"
if [[ "$MODE" == "full" ]]; then
  run_campaign "review-package-parity"
fi

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

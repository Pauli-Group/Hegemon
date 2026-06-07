#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORMAL_MANIFEST="$ROOT/scripts/hegemon_formal_core/Cargo.toml"
if [ -d "${HOME:-}/.cargo/bin" ]; then
  export PATH="${HOME}/.cargo/bin:$PATH"
fi
if [ -d "${HOME:-}/.elan/bin" ]; then
  export PATH="${HOME}/.elan/bin:$PATH"
fi

run_formal_core() {
  cargo run --quiet --manifest-path "$FORMAL_MANIFEST" -- "$@"
}

printf '=== Hegemon formal-core gate ===\n'

printf '\n[1/11] Checking formal-core checker formatting\n'
cargo fmt --manifest-path "$FORMAL_MANIFEST" -- --check

printf '\n[2/11] Running formal-core checker tests\n'
cargo test --quiet --manifest-path "$FORMAL_MANIFEST"

printf '\n[3/11] Checking Lean formal proof kernel\n'
bash "$ROOT/scripts/check_lean_formal.sh"

printf '\n[4/11] Verifying Lean-generated Rust conformance vectors\n'
LEAN_BRIDGE_VECTORS="$(mktemp)"
LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS="$(mktemp)"
LEAN_BRIDGE_LONG_RANGE_VECTORS="$(mktemp)"
LEAN_BRIDGE_HEADER_MMR_VECTORS="$(mktemp)"
LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS="$(mktemp)"
LEAN_BRIDGE_FLYCLIENT_VECTORS="$(mktemp)"
LEAN_AGGREGATION_V5_VECTORS="$(mktemp)"
LEAN_DA_ROOT_VECTORS="$(mktemp)"
LEAN_SHIELDED_VECTORS="$(mktemp)"
LEAN_CONSENSUS_VECTORS="$(mktemp)"
LEAN_HEADER_VECTORS="$(mktemp)"
LEAN_MINER_IDENTITY_VECTORS="$(mktemp)"
LEAN_POW_VECTORS="$(mktemp)"
LEAN_PROOF_POLICY_VECTORS="$(mktemp)"
LEAN_PROVEN_BATCH_BINDING_VECTORS="$(mktemp)"
LEAN_SUPPLY_VECTORS="$(mktemp)"
LEAN_VERSION_POLICY_VECTORS="$(mktemp)"
LEAN_ACTION_ORDER_VECTORS="$(mktemp)"
LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS="$(mktemp)"
LEAN_NATIVE_RECEIPT_ROOT_VECTORS="$(mktemp)"
LEAN_TRANSACTION_VECTORS="$(mktemp)"
LEAN_MERKLE_VECTORS="$(mktemp)"
LEAN_PUBLIC_INPUT_VECTORS="$(mktemp)"
LEAN_PUBLIC_INPUT_BINDING_VECTORS="$(mktemp)"
LEAN_STATEMENT_HASH_VECTORS="$(mktemp)"
trap 'rm -f "$LEAN_BRIDGE_VECTORS" "$LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS" "$LEAN_BRIDGE_LONG_RANGE_VECTORS" "$LEAN_BRIDGE_HEADER_MMR_VECTORS" "$LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS" "$LEAN_BRIDGE_FLYCLIENT_VECTORS" "$LEAN_AGGREGATION_V5_VECTORS" "$LEAN_DA_ROOT_VECTORS" "$LEAN_SHIELDED_VECTORS" "$LEAN_CONSENSUS_VECTORS" "$LEAN_HEADER_VECTORS" "$LEAN_MINER_IDENTITY_VECTORS" "$LEAN_POW_VECTORS" "$LEAN_PROOF_POLICY_VECTORS" "$LEAN_PROVEN_BATCH_BINDING_VECTORS" "$LEAN_SUPPLY_VECTORS" "$LEAN_VERSION_POLICY_VECTORS" "$LEAN_ACTION_ORDER_VECTORS" "$LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS" "$LEAN_NATIVE_RECEIPT_ROOT_VECTORS" "$LEAN_TRANSACTION_VECTORS" "$LEAN_MERKLE_VECTORS" "$LEAN_PUBLIC_INPUT_VECTORS" "$LEAN_PUBLIC_INPUT_BINDING_VECTORS" "$LEAN_STATEMENT_HASH_VECTORS"' EXIT
(
  cd "$ROOT/formal/lean"
  lake exe gen_bridge_vectors > "$LEAN_BRIDGE_VECTORS"
  lake exe gen_bridge_checkpoint_output_vectors > "$LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS"
  lake exe gen_bridge_long_range_vectors > "$LEAN_BRIDGE_LONG_RANGE_VECTORS"
  lake exe gen_bridge_header_mmr_vectors > "$LEAN_BRIDGE_HEADER_MMR_VECTORS"
  lake exe gen_bridge_header_mmr_transcript_vectors > "$LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS"
  lake exe gen_bridge_flyclient_vectors > "$LEAN_BRIDGE_FLYCLIENT_VECTORS"
  lake exe gen_aggregation_v5_vectors > "$LEAN_AGGREGATION_V5_VECTORS"
  lake exe gen_da_root_vectors > "$LEAN_DA_ROOT_VECTORS"
  lake exe gen_shielded_vectors > "$LEAN_SHIELDED_VECTORS"
  lake exe gen_consensus_vectors > "$LEAN_CONSENSUS_VECTORS"
  lake exe gen_header_vectors > "$LEAN_HEADER_VECTORS"
  lake exe gen_miner_identity_vectors > "$LEAN_MINER_IDENTITY_VECTORS"
  lake exe gen_pow_vectors > "$LEAN_POW_VECTORS"
  lake exe gen_proof_policy_vectors > "$LEAN_PROOF_POLICY_VECTORS"
  lake exe gen_proven_batch_binding_vectors > "$LEAN_PROVEN_BATCH_BINDING_VECTORS"
  lake exe gen_supply_vectors > "$LEAN_SUPPLY_VECTORS"
  lake exe gen_version_policy_vectors > "$LEAN_VERSION_POLICY_VECTORS"
  lake exe gen_action_order_vectors > "$LEAN_ACTION_ORDER_VECTORS"
  lake exe gen_native_tx_leaf_artifact_vectors > "$LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS"
  lake exe gen_native_receipt_root_vectors > "$LEAN_NATIVE_RECEIPT_ROOT_VECTORS"
  lake exe gen_transaction_vectors > "$LEAN_TRANSACTION_VECTORS"
  lake exe gen_merkle_vectors > "$LEAN_MERKLE_VECTORS"
  lake exe gen_public_input_vectors > "$LEAN_PUBLIC_INPUT_VECTORS"
  lake exe gen_public_input_binding_vectors > "$LEAN_PUBLIC_INPUT_BINDING_VECTORS"
  lake exe gen_statement_hash_vectors > "$LEAN_STATEMENT_HASH_VECTORS"
)
HEGEMON_LEAN_BRIDGE_VECTORS="$LEAN_BRIDGE_VECTORS" \
  cargo test -p protocol-kernel lean_generated_bridge_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS="$LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS" \
  cargo test -p consensus-light-client lean_generated_bridge_checkpoint_output_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_LONG_RANGE_VECTORS="$LEAN_BRIDGE_LONG_RANGE_VECTORS" \
  cargo test -p consensus-light-client lean_generated_long_range_shape_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_HEADER_MMR_VECTORS="$LEAN_BRIDGE_HEADER_MMR_VECTORS" \
  cargo test -p consensus-light-client lean_generated_header_mmr_shape_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS="$LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS" \
  cargo test -p consensus-light-client lean_generated_header_mmr_transcript_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_FLYCLIENT_VECTORS="$LEAN_BRIDGE_FLYCLIENT_VECTORS" \
  cargo test -p consensus-light-client lean_generated_flyclient_vectors_match_production -- --nocapture
HEGEMON_LEAN_AGGREGATION_V5_VECTORS="$LEAN_AGGREGATION_V5_VECTORS" \
  cargo test -p consensus lean_generated_aggregation_v5_header_vectors_match_production -- --nocapture
HEGEMON_LEAN_DA_ROOT_VECTORS="$LEAN_DA_ROOT_VECTORS" \
  cargo test -p consensus lean_generated_da_root_vectors_match_production -- --nocapture
HEGEMON_LEAN_SHIELDED_VECTORS="$LEAN_SHIELDED_VECTORS" \
  cargo test -p protocol-shielded-pool lean_generated_nullifier_vectors_match_production -- --nocapture
HEGEMON_LEAN_CONSENSUS_VECTORS="$LEAN_CONSENSUS_VECTORS" \
  cargo test -p consensus lean_generated_fork_choice_vectors_match_production -- --nocapture
HEGEMON_LEAN_HEADER_VECTORS="$LEAN_HEADER_VECTORS" \
  cargo test -p consensus lean_generated_header_preimage_vectors_match_production -- --nocapture
HEGEMON_LEAN_MINER_IDENTITY_VECTORS="$LEAN_MINER_IDENTITY_VECTORS" \
  cargo test -p consensus lean_generated_miner_identity_vectors_match_production -- --nocapture
HEGEMON_LEAN_POW_VECTORS="$LEAN_POW_VECTORS" \
  cargo test -p consensus lean_generated_pow_admission_vectors_match_production -- --nocapture
HEGEMON_LEAN_POW_VECTORS="$LEAN_POW_VECTORS" \
  cargo test -p consensus-light-client lean_generated_pow_admission_vectors_match_light_client -- --nocapture
HEGEMON_LEAN_PROOF_POLICY_VECTORS="$LEAN_PROOF_POLICY_VECTORS" \
  cargo test -p consensus lean_generated_proof_policy_vectors_match_production -- --nocapture
HEGEMON_LEAN_PROVEN_BATCH_BINDING_VECTORS="$LEAN_PROVEN_BATCH_BINDING_VECTORS" \
  cargo test -p consensus lean_generated_proven_batch_binding_vectors_match_production -- --nocapture
HEGEMON_LEAN_SUPPLY_VECTORS="$LEAN_SUPPLY_VECTORS" \
  cargo test -p consensus lean_generated_supply_vectors_match_production -- --nocapture
HEGEMON_LEAN_VERSION_POLICY_VECTORS="$LEAN_VERSION_POLICY_VECTORS" \
  cargo test -p consensus lean_generated_version_policy_vectors_match_production -- --nocapture
HEGEMON_LEAN_SUPPLY_VECTORS="$LEAN_SUPPLY_VECTORS" \
  cargo test -p hegemon-node lean_generated_native_supply_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_ORDER_VECTORS="$LEAN_ACTION_ORDER_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_order_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS="$LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS" \
  cargo test -p superneo-hegemon lean_generated_native_tx_leaf_artifact_vectors_match_production -- --nocapture
HEGEMON_LEAN_NATIVE_RECEIPT_ROOT_VECTORS="$LEAN_NATIVE_RECEIPT_ROOT_VECTORS" \
  cargo test -p superneo-hegemon lean_generated_native_receipt_root_vectors_match_production -- --nocapture
HEGEMON_LEAN_TRANSACTION_VECTORS="$LEAN_TRANSACTION_VECTORS" \
  cargo test -p transaction-circuit lean_generated_balance_vectors_match_production -- --nocapture
HEGEMON_LEAN_MERKLE_VECTORS="$LEAN_MERKLE_VECTORS" \
  cargo test -p transaction-circuit lean_generated_merkle_path_vectors_match_production -- --nocapture
HEGEMON_LEAN_PUBLIC_INPUT_VECTORS="$LEAN_PUBLIC_INPUT_VECTORS" \
  cargo test -p transaction-circuit lean_generated_public_input_shape_vectors_match_production -- --nocapture
HEGEMON_LEAN_PUBLIC_INPUT_BINDING_VECTORS="$LEAN_PUBLIC_INPUT_BINDING_VECTORS" \
  cargo test -p transaction-circuit lean_generated_public_input_binding_vectors_match_production -- --nocapture
HEGEMON_LEAN_STATEMENT_HASH_VECTORS="$LEAN_STATEMENT_HASH_VECTORS" \
  cargo test -p consensus lean_generated_statement_hash_vectors_match_production -- --nocapture

printf '\n[5/11] Auditing formal-core checker dependencies\n'
if ! command -v cargo-audit >/dev/null 2>&1; then
  printf 'cargo-audit is not installed. Install with: cargo install cargo-audit --locked\n' >&2
  exit 2
fi
(
  cd "$ROOT/scripts/hegemon_formal_core"
  cargo audit --color never
)

printf '\n[6/11] Checking formal inventory\n'
run_formal_core check-formal-inventory --root "$ROOT"

printf '\n[7/11] Checking formal security claims ledger\n'
run_formal_core check-claims "$ROOT/config/formal-security-claims.json"

printf '\n[8/11] Checking formal security blueprint DAG\n'
run_formal_core check-blueprint "$ROOT/config/formal-security-blueprint.json" --claims "$ROOT/config/formal-security-claims.json"

printf '\n[9/11] Verifying independent bridge vectors\n'
run_formal_core verify-bridge-vectors "$ROOT/testdata/formal_core_vectors/bridge_messages.json"

printf '\n[10/11] Verifying native backend reference vectors\n'
cargo run --quiet -p native-backend-ref -- verify-vectors "$ROOT/testdata/native_backend_vectors"

printf '\n[11/11] Optional model checker pass\n'
if [ "${HEGEMON_FORMAL_RUN_MODEL_CHECKERS:-0}" = "1" ]; then
  if command -v tlc >/dev/null 2>&1; then
    (
      cd "$ROOT/circuits/formal"
      tlc -deadlock transaction_balance.tla -config transaction_balance.cfg
    )
    (
      cd "$ROOT/consensus/spec/formal"
      tlc -deadlock pow_longest_chain.tla -config pow_longest_chain.cfg
    )
  else
    printf 'tlc not found; skipping TLC because no pinned local binary is available\n'
  fi

  if command -v apalache-mc >/dev/null 2>&1; then
    (
      cd "$ROOT/circuits/formal"
      apalache-mc check --max-steps=20 --inv=BalanceInvariant transaction_balance.tla
    )
    (
      cd "$ROOT/consensus/spec/formal"
      apalache-mc check --max-steps=20 --inv=ForkChoiceInvariant pow_longest_chain.tla
    )
  else
    printf 'apalache-mc not found; skipping Apalache because no pinned local binary is available\n'
  fi
else
  printf 'set HEGEMON_FORMAL_RUN_MODEL_CHECKERS=1 to run installed TLC/Apalache binaries\n'
fi

printf '\n=== Hegemon formal-core gate passed ===\n'

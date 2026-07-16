#!/usr/bin/env bash
set -euo pipefail

if [ -d "${HOME:-}/.elan/bin" ]; then
  export PATH="${HOME}/.elan/bin:$PATH"
fi

usage() {
  cat <<'EOF'
Usage: ./scripts/check-core.sh [lint|test|test-base|test-transaction-lib|test-transaction-integration|test-wallet|test-wallet-base|test-wallet-multisig-setup|test-wallet-multisig-builders|test-wallet-multisig-drift|test-node|test-node-default|test-node-minimal|build|all]

lint   Run the default formatting and lint gate.
test   Run the default fast Rust test gate.
test-base        Run the shared crypto, consensus, network, protocol, bridge, and policy tests.
test-transaction-lib Run the transaction-circuit library tests.
test-transaction-integration Run the transaction-circuit integration tests.
test-wallet      Run the wallet tests.
test-wallet-base Run wallet tests except proof-heavy cases owned by dedicated CI shards.
test-wallet-multisig-setup Run the funded multisig setup proof test.
test-wallet-multisig-builders Run the multisig approval/final proof workflow.
test-wallet-multisig-drift Run the multisig final-plan tamper workflow.
test-node        Run both hegemon-node library feature profiles.
test-node-default Run the default hegemon-node library feature profile.
test-node-minimal Run the no-default-features hegemon-node library profile.
build  Build the release node, wallet, and walletd binaries.
all    Run lint, test, and build gates.
EOF
}

run_lint() {
  cargo fmt --all -- --check
  python3 scripts/check_native_startup_policy.py
  cargo clippy \
    -p hegemon-node \
    -p protocol-kernel \
    -p protocol-shielded-pool \
    -p wallet \
    -p network \
    -p consensus \
    -p consensus-light-client \
    -p synthetic-crypto \
    -p transaction-circuit \
    -p block-circuit \
    -p cashvm-bridge \
    --all-targets -- -D warnings
  cargo clippy \
    -p superneo-backend-lattice \
    -p superneo-hegemon \
    -p superneo-bench \
    -p native-backend-ref \
    -p native-backend-timing \
    --all-targets -- -D warnings
}

prepare_test_environment() {
  export PROPTEST_CASES="${PROPTEST_CASES:-${PROPTEST_MAX_CASES:-64}}"
  unset PROPTEST_MAX_CASES
}

run_test_base() {
  prepare_test_environment
  cargo test -p synthetic-crypto
  cargo test -p consensus-light-client
  cargo test -p consensus
  cargo test -p block-circuit
  cargo test -p network
  cargo test -p protocol-kernel
  cargo test -p protocol-shielded-pool
  cargo test -p cashvm-bridge
  cargo test --test security_pipeline -- --nocapture
  python3 -B scripts/test_release_artifact_manifest.py
  python3 -B scripts/test_check_release_crypto_profile.py
}

run_test_transaction_lib() {
  prepare_test_environment
  cargo test -p transaction-circuit --lib -- \
    --skip private_multisig_accumulator::tests::private_multisig_accumulator_matches_lean_vectors \
    --skip proof::tests::lean_generated_transaction_proof_wrapper_wire_vectors_match_production \
    --skip smallwood_frontend::tests::lean_generated_smallwood_candidate_wrapper_admission_vectors_match_production \
    --skip smallwood_frontend::tests::lean_generated_smallwood_production_constraint_maps_match_every_production_row \
    --skip smallwood_frontend::tests::lean_generated_smallwood_transcript_binding_vectors_match_production \
    --skip smallwood_frontend::tests::lean_generated_smallwood_verifier_statement_projection_vectors_match_production \
    --skip smallwood_recursive::tests::lean_generated_smallwood_recursive_envelope_wire_vectors_match_production
}

run_test_transaction_integration() {
  prepare_test_environment
  cargo test -p transaction-circuit --test security_fuzz
  cargo test -p transaction-circuit --test smallwood_public_statement_binding
  cargo test -p transaction-circuit --test transaction
}

run_test_wallet() {
  prepare_test_environment
  cargo test -p wallet
}

run_test_wallet_base() {
  prepare_test_environment
  cargo test -p wallet -- \
    --skip tx_builder::tests::build_transaction_can_emit_native_tx_leaf_payloads \
    --skip tx_builder::tests::multisig_setup_bundle_has_fee_nullifier_and_reconciled_accumulator \
    --skip tx_builder::tests::multisig_builders_create_approval_and_final_transactions_with_hidden_policy_shape \
    --skip tx_builder::tests::multisig_final_rejects_plan_digest_drift
}

run_test_wallet_multisig_setup() {
  prepare_test_environment
  ./scripts/run_exact_cargo_lib_test.sh wallet \
    tx_builder::tests::multisig_setup_bundle_has_fee_nullifier_and_reconciled_accumulator
}

run_test_wallet_multisig_builders() {
  prepare_test_environment
  ./scripts/run_exact_cargo_lib_test.sh wallet \
    tx_builder::tests::multisig_builders_create_approval_and_final_transactions_with_hidden_policy_shape
}

run_test_wallet_multisig_drift() {
  prepare_test_environment
  ./scripts/run_exact_cargo_lib_test.sh wallet \
    tx_builder::tests::multisig_final_rejects_plan_digest_drift
}

run_test_node_default() {
  prepare_test_environment
  cargo test -p hegemon-node --lib
}

run_test_node_minimal() {
  prepare_test_environment
  cargo test -p hegemon-node --lib --no-default-features
}

run_test_node() {
  run_test_node_default
  run_test_node_minimal
}

run_test() {
  run_test_base
  run_test_transaction_lib
  run_test_transaction_integration
  run_test_wallet
  run_test_node
}

run_build() {
  ./scripts/build_release_artifacts.sh
}

case "${1:-all}" in
  lint)
    run_lint
    ;;
  test)
    run_test
    ;;
  test-base)
    run_test_base
    ;;
  test-transaction-lib)
    run_test_transaction_lib
    ;;
  test-transaction-integration)
    run_test_transaction_integration
    ;;
  test-wallet)
    run_test_wallet
    ;;
  test-wallet-base)
    run_test_wallet_base
    ;;
  test-wallet-multisig-setup)
    run_test_wallet_multisig_setup
    ;;
  test-wallet-multisig-builders)
    run_test_wallet_multisig_builders
    ;;
  test-wallet-multisig-drift)
    run_test_wallet_multisig_drift
    ;;
  test-node)
    run_test_node
    ;;
  test-node-default)
    run_test_node_default
    ;;
  test-node-minimal)
    run_test_node_minimal
    ;;
  build)
    run_build
    ;;
  all)
    run_lint
    run_test
    run_build
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac

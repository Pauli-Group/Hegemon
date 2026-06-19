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

printf '\n[1/13] Checking formal-core checker formatting\n'
cargo fmt --manifest-path "$FORMAL_MANIFEST" -- --check

printf '\n[2/13] Running formal-core checker tests\n'
cargo test --quiet --manifest-path "$FORMAL_MANIFEST"

printf '\n[3/13] Checking Lean formal proof kernel\n'
bash "$ROOT/scripts/check_lean_formal.sh"

printf '\n[4/13] Verifying Lean-generated Rust conformance vectors\n'
LEAN_BRIDGE_VECTORS="$(mktemp)"
LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS="$(mktemp)"
LEAN_BRIDGE_LONG_RANGE_VECTORS="$(mktemp)"
LEAN_BRIDGE_HEADER_MMR_VECTORS="$(mktemp)"
LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS="$(mktemp)"
LEAN_BRIDGE_FLYCLIENT_VECTORS="$(mktemp)"
LEAN_AGGREGATION_V5_VECTORS="$(mktemp)"
LEAN_COMMITMENT_TREE_APPEND_VECTORS="$(mktemp)"
LEAN_DA_ROOT_VECTORS="$(mktemp)"
LEAN_SHIELDED_VECTORS="$(mktemp)"
LEAN_CONSENSUS_VECTORS="$(mktemp)"
LEAN_HEADER_VECTORS="$(mktemp)"
LEAN_MINER_IDENTITY_VECTORS="$(mktemp)"
LEAN_NATIVE_TX_LEAF_ADMISSION_VECTORS="$(mktemp)"
LEAN_POW_VECTORS="$(mktemp)"
LEAN_PROOF_POLICY_VECTORS="$(mktemp)"
LEAN_PROVEN_BATCH_BINDING_VECTORS="$(mktemp)"
LEAN_RECEIPT_ROOT_ADMISSION_VECTORS="$(mktemp)"
LEAN_RECURSIVE_BLOCK_ADMISSION_VECTORS="$(mktemp)"
LEAN_RECURSIVE_BLOCK_V2_VERIFIER_SURFACE_VECTORS="$(mktemp)"
LEAN_RECURSIVE_PUBLIC_REPLAY_VECTORS="$(mktemp)"
LEAN_RECURSIVE_SEMANTIC_INPUT_VECTORS="$(mktemp)"
LEAN_STATEMENT_ANCHOR_ADMISSION_VECTORS="$(mktemp)"
LEAN_SUPPLY_VECTORS="$(mktemp)"
LEAN_SUPPLY_INVARIANT_VECTORS="$(mktemp)"
LEAN_TREE_TRANSITION_VECTORS="$(mktemp)"
LEAN_VERSION_POLICY_VECTORS="$(mktemp)"
LEAN_ACTION_ORDER_VECTORS="$(mktemp)"
LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS="$(mktemp)"
LEAN_ACTION_REQUEST_RAW_JSON_PROJECTION_VECTORS="$(mktemp)"
LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS="$(mktemp)"
LEAN_ACTION_HASH_ADMISSION_VECTORS="$(mktemp)"
LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS="$(mktemp)"
LEAN_ACTION_STATE_EFFECT_VECTORS="$(mktemp)"
LEAN_ACTION_STREAM_EFFECT_VECTORS="$(mktemp)"
LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS="$(mktemp)"
LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS="$(mktemp)"
LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS="$(mktemp)"
LEAN_BLOCK_INDEX_RELOAD_VECTORS="$(mktemp)"
LEAN_CANONICAL_STATE_RELOAD_VECTORS="$(mktemp)"
LEAN_BRIDGE_REPLAY_RELOAD_VECTORS="$(mktemp)"
LEAN_PENDING_ACTION_RELOAD_VECTORS="$(mktemp)"
LEAN_ACTION_SCOPE_ADMISSION_VECTORS="$(mktemp)"
LEAN_BLOCK_ACTION_VALIDATION_VECTORS="$(mktemp)"
LEAN_BLOCK_ACTION_REPLAY_PUBLICATION_VECTORS="$(mktemp)"
LEAN_PENDING_ACTION_FIELD_PROJECTION_VECTORS="$(mktemp)"
LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS="$(mktemp)"
LEAN_BRIDGE_ACTION_RESOURCE_ADMISSION_VECTORS="$(mktemp)"
LEAN_BRIDGE_MINT_REPLAY_POLICY_VECTORS="$(mktemp)"
LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS="$(mktemp)"
LEAN_BRIDGE_VERIFIER_REGISTRATION_POLICY_VECTORS="$(mktemp)"
LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS="$(mktemp)"
LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS="$(mktemp)"
LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS="$(mktemp)"
LEAN_RISC0_RELEASE_VERIFIER_VECTORS="$(mktemp)"
LEAN_NATIVE_BACKEND_REVIEW_POLICY_VECTORS="$(mktemp)"
LEAN_NATIVE_BACKEND_RELEASE_POSTURE_VECTORS="$(mktemp)"
LEAN_RELEASE_PQ_BINARY_POLICY_VECTORS="$(mktemp)"
LEAN_CI_RELEASE_GATE_VECTORS="$(mktemp)"
LEAN_DEPENDENCY_AUDIT_POLICY_VECTORS="$(mktemp)"
LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS="$(mktemp)"
LEAN_TRANSFER_STATE_ADMISSION_VECTORS="$(mktemp)"
LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS="$(mktemp)"
LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS="$(mktemp)"
LEAN_BLOCK_REPLAY_REFINEMENT_VECTORS="$(mktemp)"
LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS="$(mktemp)"
LEAN_CANDIDATE_ARTIFACT_SCALE_WIRE_VECTORS="$(mktemp)"
LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS="$(mktemp)"
LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS="$(mktemp)"
LEAN_CODEC_ADMISSION_VECTORS="$(mktemp)"
LEAN_PENDING_ACTION_SCALE_WIRE_VECTORS="$(mktemp)"
LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS="$(mktemp)"
LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS="$(mktemp)"
LEAN_COINBASE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS="$(mktemp)"
LEAN_OUTBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS="$(mktemp)"
LEAN_INBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS="$(mktemp)"
LEAN_BRIDGE_VERIFIER_REGISTRATION_SCALE_WIRE_VECTORS="$(mktemp)"
LEAN_SHIELDED_TRANSFER_INLINE_SCALE_WIRE_VECTORS="$(mktemp)"
LEAN_SHIELDED_TRANSFER_SIDECAR_SCALE_WIRE_VECTORS="$(mktemp)"
LEAN_MINEABLE_ACTION_ADMISSION_VECTORS="$(mktemp)"
LEAN_NATIVE_MINER_IDENTITY_VECTORS="$(mktemp)"
LEAN_MINED_WORK_ADMISSION_VECTORS="$(mktemp)"
LEAN_MINED_BLOCK_COMMIT_PUBLICATION_VECTORS="$(mktemp)"
LEAN_WORK_TEMPLATE_ADMISSION_VECTORS="$(mktemp)"
LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS="$(mktemp)"
LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS="$(mktemp)"
LEAN_BOUNDED_REQUEST_ADMISSION_VECTORS="$(mktemp)"
LEAN_PREHEAVY_RESOURCE_BOUND_SURFACE_VECTORS="$(mktemp)"
LEAN_RPC_ADMISSION_VECTORS="$(mktemp)"
LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS="$(mktemp)"
LEAN_SIDECAR_UPLOAD_RAW_JSON_PROJECTION_VECTORS="$(mktemp)"
LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS="$(mktemp)"
LEAN_STAGED_PROOF_RELOAD_VECTORS="$(mktemp)"
LEAN_STABLECOIN_POLICY_AUTHORIZATION_VECTORS="$(mktemp)"
LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS="$(mktemp)"
LEAN_SYNC_ADMISSION_VECTORS="$(mktemp)"
LEAN_SYNC_BLOCK_RANGE_PUBLICATION_ADMISSION_VECTORS="$(mktemp)"
LEAN_SYNC_RAW_INGRESS_VECTORS="$(mktemp)"
LEAN_SYNC_RESPONSE_IMPORT_VECTORS="$(mktemp)"
LEAN_NETWORK_SECURE_CHANNEL_VECTORS="$(mktemp)"
LEAN_PQ_NOISE_VECTORS="$(mktemp)"
LEAN_FRAME_RESOURCE_ADMISSION_VECTORS="$(mktemp)"
LEAN_PEER_STORE_CAPACITY_ADMISSION_VECTORS="$(mktemp)"
LEAN_QUEUE_RESOURCE_ADMISSION_VECTORS="$(mktemp)"
LEAN_NOTE_CIPHERTEXT_WIRE_VECTORS="$(mktemp)"
LEAN_WALLET_OUTPUT_BATCH_VECTORS="$(mktemp)"
LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS="$(mktemp)"
LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS="$(mktemp)"
LEAN_NATIVE_RECEIPT_ROOT_VECTORS="$(mktemp)"
LEAN_TRANSACTION_VECTORS="$(mktemp)"
LEAN_AIR_BALANCE_BOUNDARY_VECTORS="$(mktemp)"
LEAN_NOTE_COMMITMENT_INPUT_VECTORS="$(mktemp)"
LEAN_NULLIFIER_INPUT_VECTORS="$(mktemp)"
LEAN_SMALLWOOD_SPEND_AUTHORIZATION_VECTORS="$(mktemp)"
LEAN_SMALLWOOD_CANDIDATE_WRAPPER_ADMISSION_VECTORS="$(mktemp)"
LEAN_SMALLWOOD_PUBLIC_STATEMENT_BINDING_VECTORS="$(mktemp)"
LEAN_SMALLWOOD_VERIFIER_STATEMENT_PROJECTION_VECTORS="$(mktemp)"
LEAN_SMALLWOOD_RECURSIVE_ENVELOPE_WIRE_VECTORS="$(mktemp)"
LEAN_SMALLWOOD_TRANSCRIPT_BINDING_VECTORS="$(mktemp)"
LEAN_MERKLE_VECTORS="$(mktemp)"
LEAN_PUBLIC_INPUT_VECTORS="$(mktemp)"
LEAN_PUBLIC_INPUT_BINDING_VECTORS="$(mktemp)"
LEAN_PROOF_STATEMENT_BINDING_VECTORS="$(mktemp)"
LEAN_PROOF_WRAPPER_ADMISSION_VECTORS="$(mktemp)"
LEAN_PROOF_WRAPPER_WIRE_VECTORS="$(mktemp)"
LEAN_STATEMENT_HASH_VECTORS="$(mktemp)"
LEAN_TX_VALIDITY_CLAIM_MATCHING_VECTORS="$(mktemp)"
trap 'rm -f "$LEAN_BRIDGE_VECTORS" "$LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS" "$LEAN_BRIDGE_LONG_RANGE_VECTORS" "$LEAN_BRIDGE_HEADER_MMR_VECTORS" "$LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS" "$LEAN_BRIDGE_FLYCLIENT_VECTORS" "$LEAN_AGGREGATION_V5_VECTORS" "$LEAN_COMMITMENT_TREE_APPEND_VECTORS" "$LEAN_DA_ROOT_VECTORS" "$LEAN_SHIELDED_VECTORS" "$LEAN_CONSENSUS_VECTORS" "$LEAN_HEADER_VECTORS" "$LEAN_MINER_IDENTITY_VECTORS" "$LEAN_NATIVE_TX_LEAF_ADMISSION_VECTORS" "$LEAN_POW_VECTORS" "$LEAN_PROOF_POLICY_VECTORS" "$LEAN_PROVEN_BATCH_BINDING_VECTORS" "$LEAN_RECEIPT_ROOT_ADMISSION_VECTORS" "$LEAN_RECURSIVE_BLOCK_ADMISSION_VECTORS" "$LEAN_RECURSIVE_BLOCK_V2_VERIFIER_SURFACE_VECTORS" "$LEAN_RECURSIVE_PUBLIC_REPLAY_VECTORS" "$LEAN_RECURSIVE_SEMANTIC_INPUT_VECTORS" "$LEAN_STATEMENT_ANCHOR_ADMISSION_VECTORS" "$LEAN_SUPPLY_VECTORS" "$LEAN_SUPPLY_INVARIANT_VECTORS" "$LEAN_TREE_TRANSITION_VECTORS" "$LEAN_VERSION_POLICY_VECTORS" "$LEAN_ACTION_ORDER_VECTORS" "$LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS" "$LEAN_ACTION_REQUEST_RAW_JSON_PROJECTION_VECTORS" "$LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS" "$LEAN_ACTION_HASH_ADMISSION_VECTORS" "$LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS" "$LEAN_ACTION_STATE_EFFECT_VECTORS" "$LEAN_ACTION_STREAM_EFFECT_VECTORS" "$LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS" "$LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS" "$LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS" "$LEAN_BLOCK_INDEX_RELOAD_VECTORS" "$LEAN_CANONICAL_STATE_RELOAD_VECTORS" "$LEAN_BRIDGE_REPLAY_RELOAD_VECTORS" "$LEAN_PENDING_ACTION_RELOAD_VECTORS" "$LEAN_ACTION_SCOPE_ADMISSION_VECTORS" "$LEAN_BLOCK_ACTION_VALIDATION_VECTORS" "$LEAN_BLOCK_ACTION_REPLAY_PUBLICATION_VECTORS" "$LEAN_PENDING_ACTION_FIELD_PROJECTION_VECTORS" "$LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS" "$LEAN_BRIDGE_ACTION_RESOURCE_ADMISSION_VECTORS" "$LEAN_BRIDGE_MINT_REPLAY_POLICY_VECTORS" "$LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS" "$LEAN_BRIDGE_VERIFIER_REGISTRATION_POLICY_VECTORS" "$LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS" "$LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS" "$LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS" "$LEAN_RISC0_RELEASE_VERIFIER_VECTORS" "$LEAN_NATIVE_BACKEND_REVIEW_POLICY_VECTORS" "$LEAN_NATIVE_BACKEND_RELEASE_POSTURE_VECTORS" "$LEAN_RELEASE_PQ_BINARY_POLICY_VECTORS" "$LEAN_CI_RELEASE_GATE_VECTORS" "$LEAN_DEPENDENCY_AUDIT_POLICY_VECTORS" "$LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS" "$LEAN_TRANSFER_STATE_ADMISSION_VECTORS" "$LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS" "$LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS" "$LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS" "$LEAN_CANDIDATE_ARTIFACT_SCALE_WIRE_VECTORS" "$LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS" "$LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS" "$LEAN_CODEC_ADMISSION_VECTORS" "$LEAN_PENDING_ACTION_SCALE_WIRE_VECTORS" "$LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS" "$LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS" "$LEAN_COINBASE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS" "$LEAN_OUTBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS" "$LEAN_INBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS" "$LEAN_BRIDGE_VERIFIER_REGISTRATION_SCALE_WIRE_VECTORS" "$LEAN_SHIELDED_TRANSFER_INLINE_SCALE_WIRE_VECTORS" "$LEAN_SHIELDED_TRANSFER_SIDECAR_SCALE_WIRE_VECTORS" "$LEAN_MINEABLE_ACTION_ADMISSION_VECTORS" "$LEAN_NATIVE_MINER_IDENTITY_VECTORS" "$LEAN_MINED_WORK_ADMISSION_VECTORS" "$LEAN_MINED_BLOCK_COMMIT_PUBLICATION_VECTORS" "$LEAN_WORK_TEMPLATE_ADMISSION_VECTORS" "$LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS" "$LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS" "$LEAN_BOUNDED_REQUEST_ADMISSION_VECTORS" "$LEAN_PREHEAVY_RESOURCE_BOUND_SURFACE_VECTORS" "$LEAN_RPC_ADMISSION_VECTORS" "$LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS" "$LEAN_STAGED_PROOF_RELOAD_VECTORS" "$LEAN_STABLECOIN_POLICY_AUTHORIZATION_VECTORS" "$LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS" "$LEAN_SYNC_ADMISSION_VECTORS" "$LEAN_SYNC_BLOCK_RANGE_PUBLICATION_ADMISSION_VECTORS" "$LEAN_SYNC_RESPONSE_IMPORT_VECTORS" "$LEAN_NETWORK_SECURE_CHANNEL_VECTORS" "$LEAN_PQ_NOISE_VECTORS" "$LEAN_FRAME_RESOURCE_ADMISSION_VECTORS" "$LEAN_PEER_STORE_CAPACITY_ADMISSION_VECTORS" "$LEAN_QUEUE_RESOURCE_ADMISSION_VECTORS" "$LEAN_NOTE_CIPHERTEXT_WIRE_VECTORS" "$LEAN_WALLET_OUTPUT_BATCH_VECTORS" "$LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS" "$LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS" "$LEAN_NATIVE_RECEIPT_ROOT_VECTORS" "$LEAN_TRANSACTION_VECTORS" "$LEAN_NOTE_COMMITMENT_INPUT_VECTORS" "$LEAN_NULLIFIER_INPUT_VECTORS" "$LEAN_SMALLWOOD_SPEND_AUTHORIZATION_VECTORS" "$LEAN_SMALLWOOD_CANDIDATE_WRAPPER_ADMISSION_VECTORS" "$LEAN_SMALLWOOD_PUBLIC_STATEMENT_BINDING_VECTORS" "$LEAN_SMALLWOOD_VERIFIER_STATEMENT_PROJECTION_VECTORS" "$LEAN_SMALLWOOD_RECURSIVE_ENVELOPE_WIRE_VECTORS" "$LEAN_SMALLWOOD_TRANSCRIPT_BINDING_VECTORS" "$LEAN_MERKLE_VECTORS" "$LEAN_PUBLIC_INPUT_VECTORS" "$LEAN_PUBLIC_INPUT_BINDING_VECTORS" "$LEAN_PROOF_STATEMENT_BINDING_VECTORS" "$LEAN_PROOF_WRAPPER_ADMISSION_VECTORS" "$LEAN_PROOF_WRAPPER_WIRE_VECTORS" "$LEAN_STATEMENT_HASH_VECTORS" "$LEAN_TX_VALIDITY_CLAIM_MATCHING_VECTORS"' EXIT
(
  cd "$ROOT/formal/lean"
  lake exe gen_bridge_vectors > "$LEAN_BRIDGE_VECTORS"
  lake exe gen_bridge_checkpoint_output_vectors > "$LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS"
  lake exe gen_bridge_long_range_vectors > "$LEAN_BRIDGE_LONG_RANGE_VECTORS"
  lake exe gen_bridge_header_mmr_vectors > "$LEAN_BRIDGE_HEADER_MMR_VECTORS"
  lake exe gen_bridge_header_mmr_transcript_vectors > "$LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS"
  lake exe gen_bridge_flyclient_vectors > "$LEAN_BRIDGE_FLYCLIENT_VECTORS"
  lake exe gen_aggregation_v5_vectors > "$LEAN_AGGREGATION_V5_VECTORS"
  lake exe gen_commitment_tree_append_vectors > "$LEAN_COMMITMENT_TREE_APPEND_VECTORS"
  lake exe gen_da_root_vectors > "$LEAN_DA_ROOT_VECTORS"
  lake exe gen_shielded_vectors > "$LEAN_SHIELDED_VECTORS"
  lake exe gen_consensus_vectors > "$LEAN_CONSENSUS_VECTORS"
  lake exe gen_header_vectors > "$LEAN_HEADER_VECTORS"
  lake exe gen_miner_identity_vectors > "$LEAN_MINER_IDENTITY_VECTORS"
  lake exe gen_native_tx_leaf_admission_vectors > "$LEAN_NATIVE_TX_LEAF_ADMISSION_VECTORS"
  lake exe gen_pow_vectors > "$LEAN_POW_VECTORS"
  lake exe gen_proof_policy_vectors > "$LEAN_PROOF_POLICY_VECTORS"
  lake exe gen_proven_batch_binding_vectors > "$LEAN_PROVEN_BATCH_BINDING_VECTORS"
  lake exe gen_receipt_root_admission_vectors > "$LEAN_RECEIPT_ROOT_ADMISSION_VECTORS"
  lake exe gen_recursive_block_admission_vectors > "$LEAN_RECURSIVE_BLOCK_ADMISSION_VECTORS"
  lake exe gen_recursive_block_v2_verifier_surface_vectors > "$LEAN_RECURSIVE_BLOCK_V2_VERIFIER_SURFACE_VECTORS"
  lake exe gen_recursive_public_replay_vectors > "$LEAN_RECURSIVE_PUBLIC_REPLAY_VECTORS"
  lake exe gen_recursive_semantic_input_vectors > "$LEAN_RECURSIVE_SEMANTIC_INPUT_VECTORS"
  lake exe gen_statement_anchor_admission_vectors > "$LEAN_STATEMENT_ANCHOR_ADMISSION_VECTORS"
  lake exe gen_supply_vectors > "$LEAN_SUPPLY_VECTORS"
  lake exe gen_supply_invariant_vectors > "$LEAN_SUPPLY_INVARIANT_VECTORS"
  lake exe gen_tree_transition_vectors > "$LEAN_TREE_TRANSITION_VECTORS"
  lake exe gen_version_policy_vectors > "$LEAN_VERSION_POLICY_VECTORS"
  lake exe gen_action_order_vectors > "$LEAN_ACTION_ORDER_VECTORS"
  lake exe gen_action_request_projection_admission_vectors > "$LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS"
  lake exe gen_action_request_raw_json_projection_vectors > "$LEAN_ACTION_REQUEST_RAW_JSON_PROJECTION_VECTORS"
  lake exe gen_atomic_commit_manifest_admission_vectors > "$LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS"
  lake exe gen_action_hash_admission_vectors > "$LEAN_ACTION_HASH_ADMISSION_VECTORS"
  lake exe gen_action_root_transcript_vectors > "$LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS"
  lake exe gen_action_state_effect_vectors > "$LEAN_ACTION_STATE_EFFECT_VECTORS"
  lake exe gen_action_stream_effect_vectors > "$LEAN_ACTION_STREAM_EFFECT_VECTORS"
  lake exe gen_action_plan_application_admission_vectors > "$LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS"
  lake exe gen_action_wire_replay_projection_admission_vectors > "$LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS"
  lake exe gen_announced_block_admission_vectors > "$LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS"
  lake exe gen_block_index_reload_vectors > "$LEAN_BLOCK_INDEX_RELOAD_VECTORS"
  lake exe gen_canonical_state_reload_vectors > "$LEAN_CANONICAL_STATE_RELOAD_VECTORS"
  lake exe gen_bridge_replay_reload_vectors > "$LEAN_BRIDGE_REPLAY_RELOAD_VECTORS"
  lake exe gen_pending_action_reload_vectors > "$LEAN_PENDING_ACTION_RELOAD_VECTORS"
  lake exe gen_action_scope_admission_vectors > "$LEAN_ACTION_SCOPE_ADMISSION_VECTORS"
  lake exe gen_block_action_validation_vectors > "$LEAN_BLOCK_ACTION_VALIDATION_VECTORS"
  lake exe gen_block_action_replay_publication_vectors > "$LEAN_BLOCK_ACTION_REPLAY_PUBLICATION_VECTORS"
  lake exe gen_pending_action_field_projection_vectors > "$LEAN_PENDING_ACTION_FIELD_PROJECTION_VECTORS"
  lake exe gen_bridge_action_payload_admission_vectors > "$LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS"
  lake exe gen_bridge_action_resource_admission_vectors > "$LEAN_BRIDGE_ACTION_RESOURCE_ADMISSION_VECTORS"
  lake exe gen_bridge_mint_replay_policy_vectors > "$LEAN_BRIDGE_MINT_REPLAY_POLICY_VECTORS"
  lake exe gen_bridge_mint_payload_admission_vectors > "$LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS"
  lake exe gen_bridge_verifier_registration_policy_vectors > "$LEAN_BRIDGE_VERIFIER_REGISTRATION_POLICY_VECTORS"
  lake exe gen_bridge_witness_backscan_vectors > "$LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS"
  lake exe gen_bridge_witness_export_admission_vectors > "$LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS"
  lake exe gen_inbound_bridge_receipt_admission_vectors > "$LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS"
  lake exe gen_risc0_release_verifier_vectors > "$LEAN_RISC0_RELEASE_VERIFIER_VECTORS"
  lake exe gen_native_backend_review_policy_vectors > "$LEAN_NATIVE_BACKEND_REVIEW_POLICY_VECTORS"
  lake exe gen_native_backend_release_posture_vectors > "$LEAN_NATIVE_BACKEND_RELEASE_POSTURE_VECTORS"
  lake exe gen_release_pq_binary_policy_vectors > "$LEAN_RELEASE_PQ_BINARY_POLICY_VECTORS"
  lake exe gen_ci_release_gate_vectors > "$LEAN_CI_RELEASE_GATE_VECTORS"
  lake exe gen_dependency_audit_policy_vectors > "$LEAN_DEPENDENCY_AUDIT_POLICY_VECTORS"
  lake exe gen_transfer_action_payload_admission_vectors > "$LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS"
  lake exe gen_transfer_state_admission_vectors > "$LEAN_TRANSFER_STATE_ADMISSION_VECTORS"
  lake exe gen_stablecoin_policy_authorization_vectors > "$LEAN_STABLECOIN_POLICY_AUTHORIZATION_VECTORS"
  lake exe gen_block_artifact_binding_admission_vectors > "$LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS"
  lake exe gen_block_commitment_admission_vectors > "$LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS"
  lake exe gen_block_replay_refinement_vectors > "$LEAN_BLOCK_REPLAY_REFINEMENT_VECTORS"
  lake exe gen_candidate_artifact_admission_vectors > "$LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS"
  lake exe gen_candidate_artifact_scale_wire_vectors > "$LEAN_CANDIDATE_ARTIFACT_SCALE_WIRE_VECTORS"
  lake exe gen_candidate_artifact_coupling_admission_vectors > "$LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS"
  lake exe gen_canonical_reorg_chain_admission_vectors > "$LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS"
  lake exe gen_codec_admission_vectors > "$LEAN_CODEC_ADMISSION_VECTORS"
  lake exe gen_pending_action_scale_wire_vectors > "$LEAN_PENDING_ACTION_SCALE_WIRE_VECTORS"
  lake exe gen_coinbase_accounting_admission_vectors > "$LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS"
  lake exe gen_coinbase_action_payload_admission_vectors > "$LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS"
  lake exe gen_coinbase_action_payload_scale_wire_vectors > "$LEAN_COINBASE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS"
  lake exe gen_outbound_bridge_action_payload_scale_wire_vectors > "$LEAN_OUTBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS"
  lake exe gen_inbound_bridge_action_payload_scale_wire_vectors > "$LEAN_INBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS"
  lake exe gen_bridge_verifier_registration_scale_wire_vectors > "$LEAN_BRIDGE_VERIFIER_REGISTRATION_SCALE_WIRE_VECTORS"
  lake exe gen_shielded_transfer_inline_scale_wire_vectors > "$LEAN_SHIELDED_TRANSFER_INLINE_SCALE_WIRE_VECTORS"
  lake exe gen_shielded_transfer_sidecar_scale_wire_vectors > "$LEAN_SHIELDED_TRANSFER_SIDECAR_SCALE_WIRE_VECTORS"
  lake exe gen_mineable_action_admission_vectors > "$LEAN_MINEABLE_ACTION_ADMISSION_VECTORS"
  lake exe gen_native_miner_identity_vectors > "$LEAN_NATIVE_MINER_IDENTITY_VECTORS"
  lake exe gen_mined_work_admission_vectors > "$LEAN_MINED_WORK_ADMISSION_VECTORS"
  lake exe gen_mined_block_commit_publication_vectors > "$LEAN_MINED_BLOCK_COMMIT_PUBLICATION_VECTORS"
  lake exe gen_work_template_admission_vectors > "$LEAN_WORK_TEMPLATE_ADMISSION_VECTORS"
  lake exe gen_recursive_artifact_context_admission_vectors > "$LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS"
  lake exe gen_resource_budget_admission_vectors > "$LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS"
  lake exe gen_bounded_request_admission_vectors > "$LEAN_BOUNDED_REQUEST_ADMISSION_VECTORS"
  lake exe gen_preheavy_resource_bound_surface_vectors > "$LEAN_PREHEAVY_RESOURCE_BOUND_SURFACE_VECTORS"
  lake exe gen_rpc_admission_vectors > "$LEAN_RPC_ADMISSION_VECTORS"
  lake exe gen_sidecar_upload_admission_vectors > "$LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS"
  lake exe gen_sidecar_upload_raw_json_projection_vectors > "$LEAN_SIDECAR_UPLOAD_RAW_JSON_PROJECTION_VECTORS"
  lake exe gen_staged_ciphertext_reload_vectors > "$LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS"
  lake exe gen_staged_proof_reload_vectors > "$LEAN_STAGED_PROOF_RELOAD_VECTORS"
  lake exe gen_storage_durability_admission_vectors > "$LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS"
  lake exe gen_sync_admission_vectors > "$LEAN_SYNC_ADMISSION_VECTORS"
  lake exe gen_sync_block_range_publication_admission_vectors > "$LEAN_SYNC_BLOCK_RANGE_PUBLICATION_ADMISSION_VECTORS"
  lake exe gen_sync_raw_ingress_vectors > "$LEAN_SYNC_RAW_INGRESS_VECTORS"
  lake exe gen_sync_response_import_vectors > "$LEAN_SYNC_RESPONSE_IMPORT_VECTORS"
  lake exe gen_network_secure_channel_vectors > "$LEAN_NETWORK_SECURE_CHANNEL_VECTORS"
  lake exe gen_pq_noise_vectors > "$LEAN_PQ_NOISE_VECTORS"
  lake exe gen_frame_resource_admission_vectors > "$LEAN_FRAME_RESOURCE_ADMISSION_VECTORS"
  lake exe gen_peer_store_capacity_admission_vectors > "$LEAN_PEER_STORE_CAPACITY_ADMISSION_VECTORS"
  lake exe gen_queue_resource_admission_vectors > "$LEAN_QUEUE_RESOURCE_ADMISSION_VECTORS"
  lake exe gen_note_ciphertext_wire_vectors > "$LEAN_NOTE_CIPHERTEXT_WIRE_VECTORS"
  lake exe gen_wallet_output_batch_vectors > "$LEAN_WALLET_OUTPUT_BATCH_VECTORS"
  lake exe gen_ciphertext_archive_boundary_vectors > "$LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS"
  lake exe gen_native_tx_leaf_artifact_vectors > "$LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS"
  lake exe gen_native_receipt_root_vectors > "$LEAN_NATIVE_RECEIPT_ROOT_VECTORS"
  lake exe gen_transaction_vectors > "$LEAN_TRANSACTION_VECTORS"
  lake exe gen_air_balance_boundary_vectors > "$LEAN_AIR_BALANCE_BOUNDARY_VECTORS"
  lake exe gen_note_commitment_input_vectors > "$LEAN_NOTE_COMMITMENT_INPUT_VECTORS"
  lake exe gen_nullifier_input_vectors > "$LEAN_NULLIFIER_INPUT_VECTORS"
  lake exe gen_smallwood_spend_authorization_vectors > "$LEAN_SMALLWOOD_SPEND_AUTHORIZATION_VECTORS"
  lake exe gen_smallwood_candidate_wrapper_admission_vectors > "$LEAN_SMALLWOOD_CANDIDATE_WRAPPER_ADMISSION_VECTORS"
  lake exe gen_smallwood_public_statement_binding_vectors > "$LEAN_SMALLWOOD_PUBLIC_STATEMENT_BINDING_VECTORS"
  lake exe gen_smallwood_verifier_statement_projection_vectors > "$LEAN_SMALLWOOD_VERIFIER_STATEMENT_PROJECTION_VECTORS"
  lake exe gen_smallwood_recursive_envelope_wire_vectors > "$LEAN_SMALLWOOD_RECURSIVE_ENVELOPE_WIRE_VECTORS"
  lake exe gen_smallwood_transcript_binding_vectors > "$LEAN_SMALLWOOD_TRANSCRIPT_BINDING_VECTORS"
  lake exe gen_merkle_vectors > "$LEAN_MERKLE_VECTORS"
  lake exe gen_public_input_vectors > "$LEAN_PUBLIC_INPUT_VECTORS"
  lake exe gen_public_input_binding_vectors > "$LEAN_PUBLIC_INPUT_BINDING_VECTORS"
  lake exe gen_proof_statement_binding_vectors > "$LEAN_PROOF_STATEMENT_BINDING_VECTORS"
  lake exe gen_proof_wrapper_admission_vectors > "$LEAN_PROOF_WRAPPER_ADMISSION_VECTORS"
  lake exe gen_proof_wrapper_wire_vectors > "$LEAN_PROOF_WRAPPER_WIRE_VECTORS"
  lake exe gen_statement_hash_vectors > "$LEAN_STATEMENT_HASH_VECTORS"
  lake exe gen_tx_validity_claim_matching_vectors > "$LEAN_TX_VALIDITY_CLAIM_MATCHING_VECTORS"
)
HEGEMON_LEAN_BRIDGE_VECTORS="$LEAN_BRIDGE_VECTORS" \
  cargo test -p protocol-kernel lean_generated_bridge_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS="$LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS" \
  cargo test -p consensus-light-client lean_generated_bridge_checkpoint_output_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_LONG_RANGE_VECTORS="$LEAN_BRIDGE_LONG_RANGE_VECTORS" \
  cargo test -p consensus-light-client lean_generated_long_range_shape_vectors_match_production -- --nocapture
cargo test -p consensus-light-client long_range_proof_wire_decoders_match_independent_raw_oracle --lib -- --nocapture
HEGEMON_LEAN_BRIDGE_HEADER_MMR_VECTORS="$LEAN_BRIDGE_HEADER_MMR_VECTORS" \
  cargo test -p consensus-light-client lean_generated_header_mmr_shape_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS="$LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS" \
  cargo test -p consensus-light-client lean_generated_header_mmr_transcript_vectors_match_production -- --nocapture
HEGEMON_LEAN_BRIDGE_FLYCLIENT_VECTORS="$LEAN_BRIDGE_FLYCLIENT_VECTORS" \
  cargo test -p consensus-light-client lean_generated_flyclient_vectors_match_production -- --nocapture
HEGEMON_LEAN_AGGREGATION_V5_VECTORS="$LEAN_AGGREGATION_V5_VECTORS" \
  cargo test -p consensus lean_generated_aggregation_v5_header_vectors_match_production -- --nocapture
cargo test -p consensus aggregation_v5_envelope_decode_matches_zstd_postcard_oracle_on_mutation_corpus --lib -- --nocapture
HEGEMON_LEAN_COMMITMENT_TREE_APPEND_VECTORS="$LEAN_COMMITMENT_TREE_APPEND_VECTORS" \
  cargo test -p consensus lean_generated_commitment_tree_append_vectors_match_production -- --nocapture
cargo test -p state-merkle commitment_tree_independent_oracle_append_roots_paths_and_bounds -- --nocapture
HEGEMON_LEAN_DA_ROOT_VECTORS="$LEAN_DA_ROOT_VECTORS" \
  cargo test -p consensus lean_generated_da_root_vectors_match_production -- --nocapture
cargo test -p state-da da_merkle_oracle_matches_production_and_rejects_orientation_mutations -- --nocapture
cargo test -p state-da da_proof_verifier_rejects_overlong_paths_before_hash_replay -- --nocapture
HEGEMON_LEAN_SHIELDED_VECTORS="$LEAN_SHIELDED_VECTORS" \
  cargo test -p protocol-shielded-pool lean_generated_nullifier_vectors_match_production -- --nocapture
cargo test -p protocol-shielded-pool nullifier_state_matches_independent_transition_oracle -- --nocapture
cargo test -p consensus nullifier_set_matches_sorted_unique_commitment_oracle_and_rejects_duplicates --lib -- --nocapture
HEGEMON_LEAN_CONSENSUS_VECTORS="$LEAN_CONSENSUS_VECTORS" \
  cargo test -p consensus lean_generated_fork_choice_vectors_match_production -- --nocapture
HEGEMON_LEAN_CONSENSUS_VECTORS="$LEAN_CONSENSUS_VECTORS" \
  cargo test -p hegemon-node lean_generated_native_fork_choice_vectors_match_production -- --nocapture
HEGEMON_LEAN_HEADER_VECTORS="$LEAN_HEADER_VECTORS" \
  cargo test -p consensus lean_generated_header_preimage_vectors_match_production -- --nocapture
HEGEMON_LEAN_MINER_IDENTITY_VECTORS="$LEAN_MINER_IDENTITY_VECTORS" \
  cargo test -p consensus lean_generated_miner_identity_vectors_match_production -- --nocapture
HEGEMON_LEAN_NATIVE_TX_LEAF_ADMISSION_VECTORS="$LEAN_NATIVE_TX_LEAF_ADMISSION_VECTORS" \
  cargo test -p consensus lean_generated_native_tx_leaf_admission_vectors_match_production -- --nocapture
HEGEMON_LEAN_POW_VECTORS="$LEAN_POW_VECTORS" \
  cargo test -p consensus lean_generated_pow_admission_vectors_match_production -- --nocapture
HEGEMON_LEAN_POW_VECTORS="$LEAN_POW_VECTORS" \
  cargo test -p consensus-light-client lean_generated_pow_admission_vectors_match_light_client -- --nocapture
HEGEMON_LEAN_PROOF_POLICY_VECTORS="$LEAN_PROOF_POLICY_VECTORS" \
  cargo test -p consensus lean_generated_proof_policy_vectors_match_production -- --nocapture
HEGEMON_LEAN_PROVEN_BATCH_BINDING_VECTORS="$LEAN_PROVEN_BATCH_BINDING_VECTORS" \
  cargo test -p consensus lean_generated_proven_batch_binding_vectors_match_production -- --nocapture
cargo test -p consensus proven_batch_binding_rejects_da_chunk_count_mismatch -- --nocapture
HEGEMON_LEAN_RECEIPT_ROOT_ADMISSION_VECTORS="$LEAN_RECEIPT_ROOT_ADMISSION_VECTORS" \
  cargo test -p consensus lean_generated_receipt_root_admission_vectors_match_production -- --nocapture
HEGEMON_LEAN_RECURSIVE_BLOCK_ADMISSION_VECTORS="$LEAN_RECURSIVE_BLOCK_ADMISSION_VECTORS" \
  cargo test -p consensus lean_generated_recursive_block_admission_vectors_match_production -- --nocapture
cargo test -p consensus recursive_block_v1_fixed_wire_cap_and_parser_match_oracle --lib -- --nocapture
HEGEMON_LEAN_RECURSIVE_BLOCK_V2_VERIFIER_SURFACE_VECTORS="$LEAN_RECURSIVE_BLOCK_V2_VERIFIER_SURFACE_VECTORS" \
  cargo test -p block-recursion lean_generated_recursive_block_v2_verifier_surface_vectors_match_production -- --nocapture
cargo test -p block-recursion recursive_block_v2_raw_fixed_width_oracle_matches_parser_boundaries -- --nocapture
HEGEMON_LEAN_RECURSIVE_PUBLIC_REPLAY_VECTORS="$LEAN_RECURSIVE_PUBLIC_REPLAY_VECTORS" \
  cargo test -p block-recursion lean_generated_recursive_public_replay_vectors_match_production -- --nocapture
HEGEMON_LEAN_RECURSIVE_SEMANTIC_INPUT_VECTORS="$LEAN_RECURSIVE_SEMANTIC_INPUT_VECTORS" \
  cargo test -p consensus lean_generated_recursive_semantic_input_vectors_match_production -- --nocapture
HEGEMON_LEAN_STATEMENT_ANCHOR_ADMISSION_VECTORS="$LEAN_STATEMENT_ANCHOR_ADMISSION_VECTORS" \
  cargo test -p consensus lean_generated_statement_anchor_admission_vectors_match_production -- --nocapture
HEGEMON_LEAN_SUPPLY_VECTORS="$LEAN_SUPPLY_VECTORS" \
  cargo test -p consensus lean_generated_supply_vectors_match_production -- --nocapture
HEGEMON_LEAN_SUPPLY_INVARIANT_VECTORS="$LEAN_SUPPLY_INVARIANT_VECTORS" \
  cargo test -p consensus lean_generated_supply_invariant_vectors_match_production -- --nocapture
HEGEMON_LEAN_TREE_TRANSITION_VECTORS="$LEAN_TREE_TRANSITION_VECTORS" \
  cargo test -p consensus lean_generated_tree_transition_vectors_match_production -- --nocapture
cargo test -p consensus \
  append_ -- --nocapture
HEGEMON_LEAN_VERSION_POLICY_VECTORS="$LEAN_VERSION_POLICY_VECTORS" \
  cargo test -p consensus lean_generated_version_policy_vectors_match_production -- --nocapture
HEGEMON_LEAN_SUPPLY_VECTORS="$LEAN_SUPPLY_VECTORS" \
  cargo test -p hegemon-node lean_generated_native_supply_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_ORDER_VECTORS="$LEAN_ACTION_ORDER_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_order_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node non_transfer_action_order_key_preimage_ignores_received_ms_for_public_routes --lib --no-default-features -- --nocapture
cargo test -p hegemon-node pending_non_transfer_relative_order_ignores_received_ms_resampling --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS="$LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_request_projection_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_REQUEST_RAW_JSON_PROJECTION_VECTORS="$LEAN_ACTION_REQUEST_RAW_JSON_PROJECTION_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_request_raw_json_projection_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node action_request_projection_accepts_supported_route_fixtures --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS="$LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_atomic_commit_manifest_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_HASH_ADMISSION_VECTORS="$LEAN_ACTION_HASH_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_hash_admission_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node block_actions_reject --lib --no-default-features -- --nocapture
cargo test -p hegemon-node load_pending_actions_ --lib --no-default-features -- --nocapture
cargo test -p hegemon-node reorg_pending_revalidation_prioritizes_existing_pending_over_orphaned_duplicate_nullifier --lib --no-default-features -- --nocapture
cargo test -p hegemon-node load_staged_sizes_ --lib --no-default-features -- --nocapture
cargo test -p hegemon-node load_staged_proofs_ --lib --no-default-features -- --nocapture
cargo test -p hegemon-node canonical_state_reload_ --lib --no-default-features -- --nocapture
cargo test -p hegemon-node bridge_replay_reload_ --lib --no-default-features -- --nocapture
cargo test -p hegemon-node block_index_reload_ --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS="$LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_root_transcript_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_STATE_EFFECT_VECTORS="$LEAN_ACTION_STATE_EFFECT_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_state_effect_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_STREAM_EFFECT_VECTORS="$LEAN_ACTION_STREAM_EFFECT_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_stream_effect_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS="$LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_plan_application_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS="$LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_wire_replay_projection_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS="$LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_announced_block_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BLOCK_INDEX_RELOAD_VECTORS="$LEAN_BLOCK_INDEX_RELOAD_VECTORS" \
  cargo test -p hegemon-node lean_generated_block_index_reload_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_CANONICAL_STATE_RELOAD_VECTORS="$LEAN_CANONICAL_STATE_RELOAD_VECTORS" \
  cargo test -p hegemon-node lean_generated_canonical_state_reload_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BRIDGE_REPLAY_RELOAD_VECTORS="$LEAN_BRIDGE_REPLAY_RELOAD_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_replay_reload_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_PENDING_ACTION_RELOAD_VECTORS="$LEAN_PENDING_ACTION_RELOAD_VECTORS" \
  cargo test -p hegemon-node lean_generated_pending_action_reload_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_ACTION_SCOPE_ADMISSION_VECTORS="$LEAN_ACTION_SCOPE_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_action_scope_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BLOCK_ACTION_VALIDATION_VECTORS="$LEAN_BLOCK_ACTION_VALIDATION_VECTORS" \
  cargo test -p hegemon-node lean_generated_block_action_validation_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BLOCK_ACTION_REPLAY_PUBLICATION_VECTORS="$LEAN_BLOCK_ACTION_REPLAY_PUBLICATION_VECTORS" \
  cargo test -p hegemon-node lean_generated_block_action_replay_publication_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_PENDING_ACTION_FIELD_PROJECTION_VECTORS="$LEAN_PENDING_ACTION_FIELD_PROJECTION_VECTORS" \
  cargo test -p hegemon-node lean_generated_pending_action_field_projection_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS="$LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_action_payload_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BRIDGE_ACTION_RESOURCE_ADMISSION_VECTORS="$LEAN_BRIDGE_ACTION_RESOURCE_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_action_resource_admission_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node bridge_inbound_resource_projection_uses_native_caps --lib --no-default-features -- --nocapture
cargo test -p hegemon-node bridge_inbound_proof_receipt_resource_rejects_before_receipt_decode_or_verify --lib --no-default-features -- --nocapture
cargo test -p hegemon-node bridge_inbound_message_payload_resource_rejects_before_receipt_verify --lib --no-default-features -- --nocapture
cargo test -p hegemon-node submit_action_routes_bridge_payload_admission_before_staging --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS="$LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_witness_backscan_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS="$LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_witness_export_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS="$LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_inbound_bridge_receipt_admission_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node inbound_bridge_receipt_confirmation_count_overflow_fails_closed --lib --no-default-features -- --nocapture
HEGEMON_LEAN_RISC0_RELEASE_VERIFIER_VECTORS="$LEAN_RISC0_RELEASE_VERIFIER_VECTORS" \
  cargo test -p hegemon-node lean_generated_risc0_release_verifier_vectors_match_production --lib --no-default-features -- --nocapture
python3 "$ROOT/scripts/check_native_backend_review_policy_vectors.py" \
  "$LEAN_NATIVE_BACKEND_REVIEW_POLICY_VECTORS" \
  "$ROOT/testdata/native_backend_vectors/bundle.json"
python3 "$ROOT/scripts/check_native_backend_release_posture_policy_vectors.py" \
  "$LEAN_NATIVE_BACKEND_RELEASE_POSTURE_VECTORS" \
  --package "$ROOT/audits/native-backend-128b/native-backend-128b-review-package.tar.gz"
python3 "$ROOT/scripts/check_release_pq_binary_policy_vectors.py" \
  "$LEAN_RELEASE_PQ_BINARY_POLICY_VECTORS"
python3 "$ROOT/scripts/check_ci_release_gate_policy.py" \
  "$LEAN_CI_RELEASE_GATE_VECTORS" \
  --ci-workflow "$ROOT/.github/workflows/ci.yml" \
  --release-workflow "$ROOT/.github/workflows/release.yml" \
  --ruleset-export "$ROOT/.github/rulesets/hegemon-release-required-checks.json"
(
  cd "$ROOT/formal/lean"
  python3 -m json.tool "$LEAN_BRIDGE_MINT_REPLAY_POLICY_VECTORS" >/dev/null
  python3 -m json.tool "$LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS" >/dev/null
  python3 -m json.tool "$LEAN_BRIDGE_VERIFIER_REGISTRATION_POLICY_VECTORS" >/dev/null
  python3 -m json.tool "$LEAN_BOUNDED_REQUEST_ADMISSION_VECTORS" >/dev/null
  python3 -m json.tool "$LEAN_SIDECAR_UPLOAD_RAW_JSON_PROJECTION_VECTORS" >/dev/null
)
HEGEMON_LEAN_BRIDGE_MINT_REPLAY_POLICY_VECTORS="$LEAN_BRIDGE_MINT_REPLAY_POLICY_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_mint_replay_policy_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS="$LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_mint_payload_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BRIDGE_VERIFIER_REGISTRATION_POLICY_VECTORS="$LEAN_BRIDGE_VERIFIER_REGISTRATION_POLICY_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_verifier_registration_policy_vectors_match_production --lib --no-default-features -- --nocapture
python3 "$ROOT/scripts/check_dependency_audit_policy_vectors.py" \
  "$LEAN_DEPENDENCY_AUDIT_POLICY_VECTORS"
DEPENDENCY_AUDIT_UNUSED_AUDIT="$(mktemp)"
DEPENDENCY_AUDIT_UNUSED_POLICY="$(mktemp)"
cat > "$DEPENDENCY_AUDIT_UNUSED_AUDIT" <<'JSON'
{
  "vulnerabilities": {
    "list": []
  },
  "warnings": {}
}
JSON
cat > "$DEPENDENCY_AUDIT_UNUSED_POLICY" <<'JSON'
{
  "schema": 1,
  "generated_at_utc": "2099-01-01",
  "waivers": [
    {
      "id": "RUSTSEC-2099-0001",
      "package": "stale-package",
      "version": "1.0.0",
      "kind": "vulnerability",
      "expires": "2099-01-01",
      "tracking": "DEP-2099-0001",
      "reason": "Synthetic stale waiver used to prove the dependency-audit gate rejects waiver drift.",
      "owner": "release-engineering",
      "reviewed_at": "2026-06-18",
      "remediation": "Remove this synthetic stale waiver before any release."
    }
  ]
}
JSON
set +e
DEPENDENCY_AUDIT_UNUSED_OUTPUT="$("$ROOT/scripts/dependency-audit-gate.sh" \
  --audit-json "$DEPENDENCY_AUDIT_UNUSED_AUDIT" \
  --policy "$DEPENDENCY_AUDIT_UNUSED_POLICY" 2>&1)"
DEPENDENCY_AUDIT_UNUSED_STATUS=$?
set -e
if [ "$DEPENDENCY_AUDIT_UNUSED_STATUS" -eq 0 ]; then
  printf 'dependency-audit gate accepted an unused synthetic waiver\n' >&2
  exit 1
fi
if [[ "$DEPENDENCY_AUDIT_UNUSED_OUTPUT" != *"unused dependency audit waivers"* ]]; then
  printf 'dependency-audit gate rejected the synthetic waiver for the wrong reason:\n%s\n' \
    "$DEPENDENCY_AUDIT_UNUSED_OUTPUT" >&2
  exit 1
fi
cat > "$DEPENDENCY_AUDIT_UNUSED_AUDIT" <<'JSON'
{
  "vulnerabilities": {
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2099-0002",
          "title": "Synthetic dependency finding for malformed waiver metadata"
        },
        "package": {
          "name": "metadata-package",
          "version": "1.0.0"
        }
      }
    ]
  },
  "warnings": {}
}
JSON
cat > "$DEPENDENCY_AUDIT_UNUSED_POLICY" <<'JSON'
{
  "schema": 1,
  "generated_at_utc": "2099-01-01",
  "waivers": [
    {
      "id": "RUSTSEC-2099-0002",
      "package": "metadata-package",
      "version": "1.0.0",
      "kind": "vulnerability",
      "expires": "2099-01-01",
      "tracking": "DEP-2099-0002",
      "reason": "Synthetic waiver used to prove release metadata is mandatory.",
      "owner": "release-engineering",
      "reviewed_at": "2026-06-18"
    }
  ]
}
JSON
set +e
DEPENDENCY_AUDIT_MISSING_METADATA_OUTPUT="$("$ROOT/scripts/dependency-audit-gate.sh" \
  --audit-json "$DEPENDENCY_AUDIT_UNUSED_AUDIT" \
  --policy "$DEPENDENCY_AUDIT_UNUSED_POLICY" 2>&1)"
DEPENDENCY_AUDIT_MISSING_METADATA_STATUS=$?
set -e
if [ "$DEPENDENCY_AUDIT_MISSING_METADATA_STATUS" -eq 0 ]; then
  printf 'dependency-audit gate accepted a synthetic waiver missing remediation metadata\n' >&2
  exit 1
fi
if [[ "$DEPENDENCY_AUDIT_MISSING_METADATA_OUTPUT" != *"missing required fields: remediation"* ]]; then
  printf 'dependency-audit gate rejected the malformed metadata waiver for the wrong reason:\n%s\n' \
    "$DEPENDENCY_AUDIT_MISSING_METADATA_OUTPUT" >&2
  exit 1
fi
HEGEMON_LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS="$LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_transfer_action_payload_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_TRANSFER_STATE_ADMISSION_VECTORS="$LEAN_TRANSFER_STATE_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_transfer_state_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_STABLECOIN_POLICY_AUTHORIZATION_VECTORS="$LEAN_STABLECOIN_POLICY_AUTHORIZATION_VECTORS" \
  cargo test -p hegemon-node lean_generated_stablecoin_policy_authorization_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS="$LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_block_artifact_binding_admission_vectors_match_production --lib --no-default-features -- --nocapture
  cargo test -p hegemon-node materialized_sidecar_transfer_payload_builds_consensus_da_blob --lib --no-default-features -- --nocapture
  cargo test -p hegemon-node materialized_sidecar_da_blob_excludes_inbound_bridge_replay_rows --lib --no-default-features -- --nocapture
  cargo test -p hegemon-node materialized_sidecar_da_blob_bridge_first_excludes_replay_rows --lib --no-default-features -- --nocapture
  cargo test -p hegemon-node pending_action_raw_bytes_project_to_validated_materialized_replay_rows --lib --no-default-features -- --nocapture
  cargo test -p hegemon-node canonical_index_rebuild_projects_decoded_materialized_wire_rows --lib --no-default-features -- --nocapture
cargo test -p hegemon-node canonical_index_rebuild_rejects_malleable_action_bytes_before_projection_rows --lib --no-default-features -- --nocapture
cargo test -p hegemon-node block_range_projects_decoded_materialized_wire_rows --lib --no-default-features -- --nocapture
cargo test -p hegemon-node mined_commit_startup_replay_matches_canonical_publication_rows --lib --no-default-features -- --nocapture
cargo test -p hegemon-node mined_commit_rejects_meta_action_bytes_not_matching_planned_actions --lib --no-default-features -- --nocapture
cargo test -p hegemon-node mined_commit_rejects_ciphertext_hash_size_count_mismatch_before_sled_mutation --lib --no-default-features -- --nocapture
cargo test -p hegemon-node action_block_commit_reloads_canonical_sled_state --lib --no-default-features -- --nocapture
cargo test -p hegemon-node apply_planned_actions_rejects_commitment_batch_overflow_atomically --lib --no-default-features -- --nocapture
cargo test -p hegemon-node action_byte_drift --lib --no-default-features -- --nocapture
cargo test -p hegemon-node committed_sidecar_replay_materializes_ciphertext_from_archive --lib --no-default-features -- --nocapture
cargo test -p hegemon-node startup_rejects_committed_sidecar_archive_hash_drift --lib --no-default-features -- --nocapture
cargo test -p hegemon-node mixed_restart_reorg_rejects_sidecar_nullifier_bridge_replay_before_publication --lib --no-default-features -- --nocapture
cargo test -p hegemon-node reorg_preserves_valid_pending_sidecar_when_staged_ciphertext_survives --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS="$LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_block_commitment_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BLOCK_REPLAY_REFINEMENT_VECTORS="$LEAN_BLOCK_REPLAY_REFINEMENT_VECTORS" \
  cargo test -p hegemon-node lean_generated_block_replay_refinement_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node announced_block_replay_commitment_mismatch_precedes_payload_validation --lib --no-default-features -- --nocapture
HEGEMON_LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS="$LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_candidate_artifact_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_CANDIDATE_ARTIFACT_SCALE_WIRE_VECTORS="$LEAN_CANDIDATE_ARTIFACT_SCALE_WIRE_VECTORS" \
  cargo test -p hegemon-node lean_generated_candidate_artifact_scale_wire_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS="$LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_candidate_artifact_coupling_admission_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node shielded_transfer_rejects_candidate_da_chunk_count_mismatch --lib --no-default-features -- --nocapture
HEGEMON_LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS="$LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_canonical_reorg_chain_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_CODEC_ADMISSION_VECTORS="$LEAN_CODEC_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_codec_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_PENDING_ACTION_SCALE_WIRE_VECTORS="$LEAN_PENDING_ACTION_SCALE_WIRE_VECTORS" \
  cargo test -p hegemon-node lean_generated_pending_action_scale_wire_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node pending_action_exact_decode_matches_scale_decode_oracle_on_mutation_corpus --lib --no-default-features -- --nocapture
cargo test -p hegemon-node consensus_route_scale_exact_decoders_match_raw_decode_oracle_on_mutation_corpus --lib --no-default-features -- --nocapture
cargo test -p hegemon-node native_block_meta_bincode_budget --lib --no-default-features -- --nocapture
cargo test -p hegemon-node native_block_meta_exact_decode_matches_bincode_oracle_on_mutation_corpus --lib --no-default-features -- --nocapture
cargo test -p hegemon-node block_action_byte_budget --lib --no-default-features -- --nocapture
cargo test -p block-circuit commitment_block_proof_decode_rejects --lib -- --nocapture
HEGEMON_LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS="$LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_coinbase_accounting_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS="$LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_coinbase_action_payload_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_COINBASE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS="$LEAN_COINBASE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS" \
  cargo test -p hegemon-node lean_generated_coinbase_action_payload_scale_wire_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_OUTBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS="$LEAN_OUTBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS" \
  cargo test -p hegemon-node lean_generated_outbound_bridge_action_payload_scale_wire_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_INBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS="$LEAN_INBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS" \
  cargo test -p hegemon-node lean_generated_inbound_bridge_action_payload_scale_wire_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BRIDGE_VERIFIER_REGISTRATION_SCALE_WIRE_VECTORS="$LEAN_BRIDGE_VERIFIER_REGISTRATION_SCALE_WIRE_VECTORS" \
  cargo test -p hegemon-node lean_generated_bridge_verifier_registration_scale_wire_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_SHIELDED_TRANSFER_INLINE_SCALE_WIRE_VECTORS="$LEAN_SHIELDED_TRANSFER_INLINE_SCALE_WIRE_VECTORS" \
  cargo test -p hegemon-node lean_generated_shielded_transfer_inline_scale_wire_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_SHIELDED_TRANSFER_SIDECAR_SCALE_WIRE_VECTORS="$LEAN_SHIELDED_TRANSFER_SIDECAR_SCALE_WIRE_VECTORS" \
  cargo test -p hegemon-node lean_generated_shielded_transfer_sidecar_scale_wire_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_MINEABLE_ACTION_ADMISSION_VECTORS="$LEAN_MINEABLE_ACTION_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_mineable_action_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_NATIVE_MINER_IDENTITY_VECTORS="$LEAN_NATIVE_MINER_IDENTITY_VECTORS" \
  cargo test -p hegemon-node lean_generated_native_miner_identity_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_MINED_WORK_ADMISSION_VECTORS="$LEAN_MINED_WORK_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_mined_work_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_MINED_BLOCK_COMMIT_PUBLICATION_VECTORS="$LEAN_MINED_BLOCK_COMMIT_PUBLICATION_VECTORS" \
  cargo test -p hegemon-node lean_generated_mined_block_commit_publication_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_WORK_TEMPLATE_ADMISSION_VECTORS="$LEAN_WORK_TEMPLATE_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_work_template_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS="$LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_recursive_artifact_context_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS="$LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_resource_budget_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_BOUNDED_REQUEST_ADMISSION_VECTORS="$LEAN_BOUNDED_REQUEST_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_bounded_request_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_PREHEAVY_RESOURCE_BOUND_SURFACE_VECTORS="$LEAN_PREHEAVY_RESOURCE_BOUND_SURFACE_VECTORS" \
  cargo test -p hegemon-node lean_generated_preheavy_resource_bound_surface_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_RPC_ADMISSION_VECTORS="$LEAN_RPC_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_rpc_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS="$LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_sidecar_upload_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_SIDECAR_UPLOAD_RAW_JSON_PROJECTION_VECTORS="$LEAN_SIDECAR_UPLOAD_RAW_JSON_PROJECTION_VECTORS" \
  cargo test -p hegemon-node lean_generated_sidecar_upload_raw_json_projection_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node mixed_batch_atomically --lib --no-default-features -- --nocapture
cargo test -p hegemon-node submit_sidecar_action_consumes_embedded_staged_proof_atomically --lib --no-default-features -- --nocapture
HEGEMON_LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS="$LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS" \
  cargo test -p hegemon-node lean_generated_staged_ciphertext_reload_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_STAGED_PROOF_RELOAD_VECTORS="$LEAN_STAGED_PROOF_RELOAD_VECTORS" \
  cargo test -p hegemon-node lean_generated_staged_proof_reload_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS="$LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_storage_durability_admission_vectors_match_production --lib --no-default-features -- --nocapture
bash "$ROOT/scripts/test-node.sh" sigterm-shutdown
HEGEMON_LEAN_SYNC_ADMISSION_VECTORS="$LEAN_SYNC_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_sync_admission_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_SYNC_RAW_INGRESS_VECTORS="$LEAN_SYNC_RAW_INGRESS_VECTORS" \
  cargo test -p hegemon-node lean_generated_sync_raw_ingress_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_SYNC_RESPONSE_IMPORT_VECTORS="$LEAN_SYNC_RESPONSE_IMPORT_VECTORS" \
  cargo test -p hegemon-node lean_generated_sync_response_import_vectors_match_production --lib --no-default-features -- --nocapture
HEGEMON_LEAN_SYNC_BLOCK_RANGE_PUBLICATION_ADMISSION_VECTORS="$LEAN_SYNC_BLOCK_RANGE_PUBLICATION_ADMISSION_VECTORS" \
  cargo test -p hegemon-node lean_generated_sync_block_range_publication_admission_vectors_match_production --lib --no-default-features -- --nocapture
cargo test -p hegemon-node native_sync_response_count_uses_bounded_request_item_gate --lib --no-default-features -- --nocapture
cargo test -p hegemon-node native_sync_response_range_caps_overwide_response_with_bounded_request_item_facts --lib --no-default-features -- --nocapture
cargo test -p hegemon-node block_range_rejects --lib --no-default-features -- --nocapture
cargo test -p hegemon-node materialized_sidecar_observer_projection_ignores_received_time --lib --no-default-features -- --nocapture
cargo test -p network --lib pq_connection_info_and_relay_config_do_not_change_wire_or_consensus_payload_projection -- --nocapture
cargo test -p network oversized_handshake_frame_is_rejected --lib -- --nocapture
cargo test -p network record_addresses_filters_and_caps_per_peer_entries --lib -- --nocapture
cargo test -p network peer_sends_do_not_await_full_queues --lib -- --nocapture
HEGEMON_LEAN_NETWORK_SECURE_CHANNEL_VECTORS="$LEAN_NETWORK_SECURE_CHANNEL_VECTORS" \
  cargo test -p network lean_generated_secure_channel_vectors_match_production -- --nocapture
HEGEMON_LEAN_PQ_NOISE_VECTORS="$LEAN_PQ_NOISE_VECTORS" \
  cargo test -p pq-noise lean_generated_pq_noise_vectors_match_production -- --nocapture
cargo test -p pq-noise encapsulate_with_seed_consumes_supplied_seed -- --nocapture
cargo test -p network encapsulate_with_seed_consumes_supplied_seed --lib -- --nocapture
HEGEMON_LEAN_PQ_NOISE_VECTORS="$LEAN_PQ_NOISE_VECTORS" \
  cargo test -p network lean_generated_pq_wrapper_completion_vectors_match_network_transport --lib -- --nocapture
HEGEMON_LEAN_PQ_NOISE_VECTORS="$LEAN_PQ_NOISE_VECTORS" \
  cargo test -p network lean_generated_pq_wrapper_completion_vectors_match_native_transport --lib -- --nocapture
HEGEMON_LEAN_FRAME_RESOURCE_ADMISSION_VECTORS="$LEAN_FRAME_RESOURCE_ADMISSION_VECTORS" \
  cargo test -p network lean_generated_frame_resource_admission_vectors_match_production -- --nocapture
cargo test -p network network_wire_decode_matches_marker_limit_postcard_oracle_on_mutation_corpus -- --nocapture
HEGEMON_LEAN_PEER_STORE_CAPACITY_ADMISSION_VECTORS="$LEAN_PEER_STORE_CAPACITY_ADMISSION_VECTORS" \
  cargo test -p network lean_generated_peer_store_capacity_vectors_match_production -- --nocapture
HEGEMON_LEAN_QUEUE_RESOURCE_ADMISSION_VECTORS="$LEAN_QUEUE_RESOURCE_ADMISSION_VECTORS" \
  cargo test -p network lean_generated_queue_resource_admission_vectors_match_production -- --nocapture
HEGEMON_LEAN_FRAME_RESOURCE_ADMISSION_VECTORS="$LEAN_FRAME_RESOURCE_ADMISSION_VECTORS" \
  cargo test -p pq-noise lean_generated_frame_resource_admission_vectors_match_production -- --nocapture
cargo test -p pq-noise pq_noise_decode_matches_marker_limit_postcard_oracle_on_mutation_corpus -- --nocapture
HEGEMON_LEAN_NOTE_CIPHERTEXT_WIRE_VECTORS="$LEAN_NOTE_CIPHERTEXT_WIRE_VECTORS" \
  cargo test -p wallet lean_generated_note_ciphertext_wire_vectors_match_production -- --nocapture
cargo test -p wallet note_ciphertext_chain_and_da_parsers_match_independent_byte_oracle_on_mutation_corpus --test note_ciphertext_wire_vectors -- --nocapture
HEGEMON_LEAN_WALLET_OUTPUT_BATCH_VECTORS="$LEAN_WALLET_OUTPUT_BATCH_VECTORS" \
  cargo test -p wallet lean_generated_wallet_output_batch_vectors_match_production --lib -- --nocapture
HEGEMON_LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS="$LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS" \
  cargo test -p hegemon-node lean_generated_ciphertext_archive_boundary_vectors_match_native_rpc --lib --no-default-features -- --nocapture
cargo test -p wallet note_ciphertext_version_gate_rejects_unsupported_wire_and_crypto_formats --lib -- --nocapture
cargo test -p wallet from_da_bytes_rejects_ --lib -- --nocapture
cargo test -p wallet decode_ciphertext_entries_ --lib -- --nocapture
cargo test -p wallet decrypt_rejects --lib -- --nocapture
cargo test -p wallet encrypt_same_plaintext_to_same_address_uses_fresh_kem_randomness --lib -- --nocapture
cargo test -p wallet reencryption_preserves_public_ciphertext_summary_shape --lib -- --nocapture
cargo test -p wallet local_wallet_bookkeeping_does_not_change_public_ciphertext_projection --lib -- --nocapture
cargo test -p wallet local_address_metadata_does_not_change_public_ciphertext_projection --lib -- --nocapture
cargo test -p wallet full_view_decrypt_binds_plaintext_note_data_commitment_and_witness --lib -- --nocapture
cargo test -p wallet build_transaction_can_emit_native_tx_leaf_payloads --lib -- --nocapture
cargo test -p wallet stablecoin_policy_admission --lib -- --nocapture
cargo test -p synthetic-crypto note_encryption::tests::test_decrypt_rejects --lib -- --nocapture
HEGEMON_LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS="$LEAN_NATIVE_TX_LEAF_ARTIFACT_VECTORS" \
  cargo test -p superneo-hegemon lean_generated_native_tx_leaf_artifact_vectors_match_production -- --nocapture
cargo test -p superneo-hegemon native_tx_leaf_artifact --lib -- --nocapture
HEGEMON_LEAN_NATIVE_RECEIPT_ROOT_VECTORS="$LEAN_NATIVE_RECEIPT_ROOT_VECTORS" \
  cargo test -p superneo-hegemon lean_generated_native_receipt_root_vectors_match_production -- --nocapture
cargo test -p superneo-hegemon native_receipt_root_parser_matches_independent_oracle_on_mutation_corpus --lib -- --nocapture
cargo test -p superneo-hegemon superneo_receipts_use_shared_statement_hash_helper --lib -- --nocapture
cargo test -p superneo-hegemon oversized_public_inputs_without_panic --lib -- --nocapture
HEGEMON_LEAN_TRANSACTION_VECTORS="$LEAN_TRANSACTION_VECTORS" \
  cargo test -p transaction-circuit lean_generated_balance_vectors_match_production -- --nocapture
HEGEMON_LEAN_AIR_BALANCE_BOUNDARY_VECTORS="$LEAN_AIR_BALANCE_BOUNDARY_VECTORS" \
  cargo test -p transaction-circuit lean_generated_air_balance_boundary_vectors_match_production --lib -- --nocapture
cargo test -p transaction-circuit p3_air_balance_public_field_mutations_rejected --lib -- --nocapture
HEGEMON_LEAN_NOTE_COMMITMENT_INPUT_VECTORS="$LEAN_NOTE_COMMITMENT_INPUT_VECTORS" \
  cargo test -p wallet lean_generated_note_commitment_input_vectors_match_wallet_plaintext_note_data --lib -- --nocapture
HEGEMON_LEAN_NOTE_COMMITMENT_INPUT_VECTORS="$LEAN_NOTE_COMMITMENT_INPUT_VECTORS" \
  cargo test -p transaction-circuit lean_generated_note_commitment_input_vectors_match_production -- --nocapture
HEGEMON_LEAN_NULLIFIER_INPUT_VECTORS="$LEAN_NULLIFIER_INPUT_VECTORS" \
  cargo test -p transaction-circuit lean_generated_nullifier_input_vectors_match_production -- --nocapture
cargo test -p transaction-circuit commitment_inputs_use_shared_core_preimage -- --nocapture
cargo test -p transaction-circuit nullifier_inputs_use_shared_core_preimage -- --nocapture
HEGEMON_LEAN_SMALLWOOD_SPEND_AUTHORIZATION_VECTORS="$LEAN_SMALLWOOD_SPEND_AUTHORIZATION_VECTORS" \
  cargo test -p transaction-circuit smallwood_spend_authorization_matches_lean_vectors_when_present -- --nocapture
HEGEMON_LEAN_SMALLWOOD_TRANSCRIPT_BINDING_VECTORS="$LEAN_SMALLWOOD_TRANSCRIPT_BINDING_VECTORS" \
  cargo test -p transaction-circuit lean_generated_smallwood_transcript_binding_vectors_match_production -- --nocapture
HEGEMON_LEAN_SMALLWOOD_PUBLIC_STATEMENT_BINDING_VECTORS="$LEAN_SMALLWOOD_PUBLIC_STATEMENT_BINDING_VECTORS" \
  cargo test -p transaction-circuit --test smallwood_public_statement_binding lean_generated_smallwood_public_statement_binding_vectors_match_production -- --nocapture
HEGEMON_LEAN_SMALLWOOD_VERIFIER_STATEMENT_PROJECTION_VECTORS="$LEAN_SMALLWOOD_VERIFIER_STATEMENT_PROJECTION_VECTORS" \
  cargo test -p transaction-circuit lean_generated_smallwood_verifier_statement_projection_vectors_match_production --lib -- --nocapture
cargo test -p transaction-circuit packed_smallwood_frontend_compact_bindings_inline_merkle_skip_initial_mds_witness_satisfies_constraints --lib -- --nocapture
cargo test -p transaction-circuit packed_smallwood_frontend_inline_merkle_rejects_spend_secret_not_matching_input_pk_auth -- --nocapture
cargo test -p transaction-circuit packed_smallwood_inline_merkle_rejects --lib -- --nocapture
cargo test -p transaction-circuit packed_smallwood_inline_merkle_rejects_active_output_binding_mutation --lib -- --nocapture
cargo test -p transaction-circuit packed_smallwood_inline_merkle_rejects_inactive_output_ciphertext_hash --lib -- --nocapture
cargo test -p transaction-circuit packed_smallwood_inline_merkle_rejects_public_balance_mutation --lib -- --nocapture
cargo test -p transaction-circuit packed_smallwood_inline_merkle_rejects_public_stablecoin_delta_mutation --lib -- --nocapture
HEGEMON_LEAN_SMALLWOOD_CANDIDATE_WRAPPER_ADMISSION_VECTORS="$LEAN_SMALLWOOD_CANDIDATE_WRAPPER_ADMISSION_VECTORS" \
  cargo test -p transaction-circuit lean_generated_smallwood_candidate_wrapper_admission_vectors_match_production --lib -- --nocapture
HEGEMON_LEAN_SMALLWOOD_RECURSIVE_ENVELOPE_WIRE_VECTORS="$LEAN_SMALLWOOD_RECURSIVE_ENVELOPE_WIRE_VECTORS" \
  cargo test -p transaction-circuit lean_generated_smallwood_recursive_envelope_wire_vectors_match_production --lib -- --nocapture
cargo test -p disclosure-circuit disclosure_commitment_inputs_use_shared_core_preimage -- --nocapture
HEGEMON_LEAN_MERKLE_VECTORS="$LEAN_MERKLE_VECTORS" \
  cargo test -p transaction-circuit lean_generated_merkle_path_vectors_match_production -- --nocapture
HEGEMON_LEAN_PUBLIC_INPUT_VECTORS="$LEAN_PUBLIC_INPUT_VECTORS" \
  cargo test -p transaction-circuit lean_generated_public_input_shape_vectors_match_production -- --nocapture
HEGEMON_LEAN_PUBLIC_INPUT_BINDING_VECTORS="$LEAN_PUBLIC_INPUT_BINDING_VECTORS" \
  cargo test -p transaction-circuit lean_generated_public_input_binding_vectors_match_production -- --nocapture
HEGEMON_LEAN_PROOF_STATEMENT_BINDING_VECTORS="$LEAN_PROOF_STATEMENT_BINDING_VECTORS" \
  cargo test -p protocol-shielded-pool lean_generated_proof_statement_binding_vectors_match_production -- --nocapture
HEGEMON_LEAN_PROOF_WRAPPER_ADMISSION_VECTORS="$LEAN_PROOF_WRAPPER_ADMISSION_VECTORS" \
  cargo test -p transaction-circuit lean_generated_proof_wrapper_admission_vectors_match_production -- --nocapture
HEGEMON_LEAN_PROOF_WRAPPER_WIRE_VECTORS="$LEAN_PROOF_WRAPPER_WIRE_VECTORS" \
  cargo test -p transaction-circuit lean_generated_transaction_proof_wrapper_wire_vectors_match_production -- --nocapture
cargo test -p transaction-circuit transaction_proof_wrapper_exact_decode_matches_bincode_oracle_on_mutation_corpus -- --nocapture
cargo test -p tx-proof-manifest manifest_rejects_nested_proof_wrapper_admission_failures -- --nocapture
HEGEMON_LEAN_STATEMENT_HASH_VECTORS="$LEAN_STATEMENT_HASH_VECTORS" \
  cargo test -p transaction-circuit lean_generated_statement_hash_vectors_match_production -- --nocapture
HEGEMON_LEAN_STATEMENT_HASH_VECTORS="$LEAN_STATEMENT_HASH_VECTORS" \
  cargo test -p consensus lean_generated_statement_hash_vectors_match_production -- --nocapture
HEGEMON_LEAN_TX_VALIDITY_CLAIM_MATCHING_VECTORS="$LEAN_TX_VALIDITY_CLAIM_MATCHING_VECTORS" \
  cargo test -p consensus lean_generated_tx_validity_claim_matching_vectors_match_production --lib -- --nocapture
cargo test -p consensus tx_validity_ --lib -- --nocapture
cargo test -p consensus verify_aggregation_proof_rejects_legacy_v4_by_default --lib -- --nocapture
HEGEMON_AGG_LEGACY_V4=1 \
  cargo test -p consensus verify_aggregation_proof_rejects_legacy_v4_even_when_env_set --lib -- --nocapture

printf '\n[5/13] Auditing formal-core checker dependencies\n'
if ! command -v cargo-audit >/dev/null 2>&1; then
  printf 'cargo-audit is not installed. Install with: cargo install cargo-audit --locked\n' >&2
  exit 2
fi
(
  cd "$ROOT/scripts/hegemon_formal_core"
  cargo audit --color never
)

printf '\n[6/13] Checking formal inventory\n'
run_formal_core check-formal-inventory --root "$ROOT"

printf '\n[7/13] Checking system-model fail-closed gates\n'
run_formal_core check-system-model-gates "$ROOT/config/system-model-assumption-gates.json"

printf '\n[8/13] Checking formal security claims ledger\n'
run_formal_core check-claims "$ROOT/config/formal-security-claims.json"

printf '\n[9/13] Checking formal security blueprint DAG\n'
run_formal_core check-blueprint "$ROOT/config/formal-security-blueprint.json" --claims "$ROOT/config/formal-security-claims.json"

printf '\n[10/13] Verifying independent bridge vectors\n'
run_formal_core verify-bridge-vectors "$ROOT/testdata/formal_core_vectors/bridge_messages.json"

printf '\n[11/13] Verifying native backend reference vectors\n'
cargo run --quiet -p native-backend-ref -- verify-vectors "$ROOT/testdata/native_backend_vectors"

printf '\n[12/13] Checking native backend release posture\n'
bash "$ROOT/scripts/check_native_backend_release_posture.sh" \
  --package "$ROOT/audits/native-backend-128b/native-backend-128b-review-package.tar.gz"

printf '\n[13/13] Optional model checker pass\n'
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

rm -f "$LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS" "$LEAN_SIDECAR_UPLOAD_RAW_JSON_PROJECTION_VECTORS" "$LEAN_AIR_BALANCE_BOUNDARY_VECTORS"

printf '\n=== Hegemon formal-core gate passed ===\n'

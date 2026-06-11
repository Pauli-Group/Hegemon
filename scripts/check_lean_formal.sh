#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEAN_ROOT="$ROOT/formal/lean"

if [ -d "${HOME:-}/.elan/bin" ]; then
  export PATH="${HOME}/.elan/bin:$PATH"
fi

if ! command -v lake >/dev/null 2>&1; then
  printf 'lake is not installed. Install Lean tooling with:\n' >&2
  printf '  curl https://elan.lean-lang.org/elan-init.sh -sSf | sh -s -- -y --default-toolchain none\n' >&2
  exit 2
fi

if find "$LEAN_ROOT" -name '*.lean' -print0 \
  | xargs -0 grep -nE '\b(sorry|admit)\b|^[[:space:]]*axiom[[:space:]]' >/tmp/hegemon-lean-forbidden.$$ 2>/dev/null; then
  printf 'Lean formal sources contain forbidden proof placeholders or declared axioms:\n' >&2
  cat /tmp/hegemon-lean-forbidden.$$ >&2
  rm -f /tmp/hegemon-lean-forbidden.$$
  exit 1
fi
rm -f /tmp/hegemon-lean-forbidden.$$

(
  cd "$LEAN_ROOT"
  lake build Hegemon gen_bridge_vectors gen_bridge_checkpoint_output_vectors gen_bridge_long_range_vectors gen_bridge_header_mmr_vectors gen_bridge_header_mmr_transcript_vectors gen_bridge_flyclient_vectors gen_aggregation_v5_vectors gen_da_root_vectors gen_shielded_vectors gen_consensus_vectors gen_header_vectors gen_miner_identity_vectors gen_native_tx_leaf_admission_vectors gen_pow_vectors gen_proof_policy_vectors gen_proven_batch_binding_vectors gen_receipt_root_admission_vectors gen_recursive_block_admission_vectors gen_recursive_public_replay_vectors gen_recursive_semantic_input_vectors gen_supply_vectors gen_supply_invariant_vectors gen_tree_transition_vectors gen_version_policy_vectors gen_action_order_vectors gen_action_hash_admission_vectors gen_action_root_transcript_vectors gen_action_state_effect_vectors gen_announced_block_admission_vectors gen_block_index_reload_vectors gen_canonical_state_reload_vectors gen_bridge_replay_reload_vectors gen_action_scope_admission_vectors gen_bridge_action_payload_admission_vectors gen_risc0_release_verifier_vectors gen_native_backend_review_policy_vectors gen_native_backend_release_posture_vectors gen_release_pq_binary_policy_vectors gen_dependency_audit_policy_vectors gen_transfer_action_payload_admission_vectors gen_transfer_state_admission_vectors gen_block_artifact_binding_admission_vectors gen_block_commitment_admission_vectors gen_candidate_artifact_admission_vectors gen_candidate_artifact_coupling_admission_vectors gen_codec_admission_vectors gen_coinbase_accounting_admission_vectors gen_coinbase_action_payload_admission_vectors gen_mineable_action_admission_vectors gen_mined_work_admission_vectors gen_work_template_admission_vectors gen_resource_budget_admission_vectors gen_rpc_admission_vectors gen_sidecar_upload_admission_vectors gen_staged_ciphertext_reload_vectors gen_sync_admission_vectors gen_network_secure_channel_vectors gen_pq_noise_vectors gen_native_tx_leaf_artifact_vectors gen_native_receipt_root_vectors gen_transaction_vectors gen_merkle_vectors gen_public_input_vectors gen_public_input_binding_vectors gen_statement_hash_vectors
  lake env lean Hegemon/Bytes.lean
  lake env lean Hegemon/Bridge/CheckpointOutput.lean
  lake env lean Hegemon/Bridge/Encoding.lean
  lake env lean Hegemon/Bridge/FlyClient.lean
  lake env lean Hegemon/Bridge/HeaderMmr.lean
  lake env lean Hegemon/Bridge/HeaderMmrTranscript.lean
  lake env lean Hegemon/Bridge/LongRange.lean
  lake env lean Hegemon/Bridge/MessageRoot.lean
  lake env lean Hegemon/Bridge/Replay.lean
  lake env lean Hegemon/Bridge/GenerateHeaderMmrVectors.lean
  lake env lean Hegemon/Bridge/GenerateHeaderMmrTranscriptVectors.lean
  lake env lean Hegemon/Bridge/GenerateFlyClientVectors.lean
  lake env lean Hegemon/Bridge/GenerateCheckpointOutputVectors.lean
  lake env lean Hegemon/Bridge/GenerateLongRangeVectors.lean
  lake env lean Hegemon/Bridge/GenerateVectors.lean
  lake env lean Hegemon/Consensus/AggregationV5.lean
  lake env lean Hegemon/Consensus/GenerateAggregationV5Vectors.lean
  lake env lean Hegemon/Consensus/DaRoot.lean
  lake env lean Hegemon/Consensus/GenerateDaRootVectors.lean
  lake env lean Hegemon/Consensus/ForkChoice.lean
  lake env lean Hegemon/Consensus/GenerateVectors.lean
  lake env lean Hegemon/Consensus/Header.lean
  lake env lean Hegemon/Consensus/GenerateHeaderVectors.lean
  lake env lean Hegemon/Consensus/MinerIdentity.lean
  lake env lean Hegemon/Consensus/GenerateMinerIdentityVectors.lean
  lake env lean Hegemon/Consensus/NativeTxLeafAdmission.lean
  lake env lean Hegemon/Consensus/GenerateNativeTxLeafAdmissionVectors.lean
  lake env lean Hegemon/Consensus/PowRules.lean
  lake env lean Hegemon/Consensus/GeneratePowVectors.lean
  lake env lean Hegemon/Consensus/ProofPolicy.lean
  lake env lean Hegemon/Consensus/GenerateProofPolicyVectors.lean
  lake env lean Hegemon/Consensus/ProvenBatchBinding.lean
  lake env lean Hegemon/Consensus/GenerateProvenBatchBindingVectors.lean
  lake env lean Hegemon/Consensus/ReceiptRootAdmission.lean
  lake env lean Hegemon/Consensus/GenerateReceiptRootAdmissionVectors.lean
  lake env lean Hegemon/Consensus/RecursiveBlockAdmission.lean
  lake env lean Hegemon/Consensus/GenerateRecursiveBlockAdmissionVectors.lean
  lake env lean Hegemon/Consensus/RecursivePublicReplay.lean
  lake env lean Hegemon/Consensus/GenerateRecursivePublicReplayVectors.lean
  lake env lean Hegemon/Consensus/RecursiveSemanticInputs.lean
  lake env lean Hegemon/Consensus/GenerateRecursiveSemanticInputVectors.lean
  lake env lean Hegemon/Consensus/Supply.lean
  lake env lean Hegemon/Consensus/GenerateSupplyVectors.lean
  lake env lean Hegemon/Consensus/SupplyInvariant.lean
  lake env lean Hegemon/Consensus/GenerateSupplyInvariantVectors.lean
  lake env lean Hegemon/Consensus/TreeTransition.lean
  lake env lean Hegemon/Consensus/GenerateTreeTransitionVectors.lean
  lake env lean Hegemon/Consensus/VersionPolicy.lean
  lake env lean Hegemon/Consensus/GenerateVersionPolicyVectors.lean
  lake env lean Hegemon/Native/ActionOrder.lean
  lake env lean Hegemon/Native/GenerateActionOrderVectors.lean
  lake env lean Hegemon/Native/ActionHashAdmission.lean
  lake env lean Hegemon/Native/GenerateActionHashAdmissionVectors.lean
  lake env lean Hegemon/Native/ActionRootTranscript.lean
  lake env lean Hegemon/Native/GenerateActionRootTranscriptVectors.lean
  lake env lean Hegemon/Native/ActionStateEffect.lean
  lake env lean Hegemon/Native/GenerateActionStateEffectVectors.lean
  lake env lean Hegemon/Native/AnnouncedBlockAdmission.lean
  lake env lean Hegemon/Native/GenerateAnnouncedBlockAdmissionVectors.lean
  lake env lean Hegemon/Native/BlockIndexReload.lean
  lake env lean Hegemon/Native/GenerateBlockIndexReloadVectors.lean
  lake env lean Hegemon/Native/CanonicalStateReload.lean
  lake env lean Hegemon/Native/GenerateCanonicalStateReloadVectors.lean
  lake env lean Hegemon/Native/BridgeReplayReload.lean
  lake env lean Hegemon/Native/GenerateBridgeReplayReloadVectors.lean
  lake env lean Hegemon/Native/ActionScopeAdmission.lean
  lake env lean Hegemon/Native/GenerateActionScopeAdmissionVectors.lean
  lake env lean Hegemon/Native/BridgeActionPayloadAdmission.lean
  lake env lean Hegemon/Native/GenerateBridgeActionPayloadAdmissionVectors.lean
  lake env lean Hegemon/Native/NativeBackendReviewPolicy.lean
  lake env lean Hegemon/Native/GenerateNativeBackendReviewPolicyVectors.lean
  lake env lean Hegemon/Native/NativeBackendReleasePosture.lean
  lake env lean Hegemon/Native/GenerateNativeBackendReleasePostureVectors.lean
  lake env lean Hegemon/Native/TransferActionPayloadAdmission.lean
  lake env lean Hegemon/Native/GenerateTransferActionPayloadAdmissionVectors.lean
  lake env lean Hegemon/Native/TransferStateAdmission.lean
  lake env lean Hegemon/Native/GenerateTransferStateAdmissionVectors.lean
  lake env lean Hegemon/Native/BlockArtifactBindingAdmission.lean
  lake env lean Hegemon/Native/GenerateBlockArtifactBindingAdmissionVectors.lean
  lake env lean Hegemon/Native/BlockCommitmentAdmission.lean
  lake env lean Hegemon/Native/GenerateBlockCommitmentAdmissionVectors.lean
  lake env lean Hegemon/Native/CandidateArtifactAdmission.lean
  lake env lean Hegemon/Native/GenerateCandidateArtifactAdmissionVectors.lean
  lake env lean Hegemon/Native/CandidateArtifactCouplingAdmission.lean
  lake env lean Hegemon/Native/GenerateCandidateArtifactCouplingAdmissionVectors.lean
  lake env lean Hegemon/Native/CodecAdmission.lean
  lake env lean Hegemon/Native/GenerateCodecAdmissionVectors.lean
  lake env lean Hegemon/Native/CoinbaseAccountingAdmission.lean
  lake env lean Hegemon/Native/GenerateCoinbaseAccountingAdmissionVectors.lean
  lake env lean Hegemon/Native/CoinbaseActionPayloadAdmission.lean
  lake env lean Hegemon/Native/GenerateCoinbaseActionPayloadAdmissionVectors.lean
  lake env lean Hegemon/Native/MineableActionAdmission.lean
  lake env lean Hegemon/Native/GenerateMineableActionAdmissionVectors.lean
  lake env lean Hegemon/Native/MinedWorkAdmission.lean
  lake env lean Hegemon/Native/GenerateMinedWorkAdmissionVectors.lean
  lake env lean Hegemon/Native/WorkTemplateAdmission.lean
  lake env lean Hegemon/Native/GenerateWorkTemplateAdmissionVectors.lean
  lake env lean Hegemon/Native/RecursiveArtifactContextAdmission.lean
  lake env lean Hegemon/Native/GenerateRecursiveArtifactContextAdmissionVectors.lean
  lake env lean Hegemon/Native/ResourceBudgetAdmission.lean
  lake env lean Hegemon/Native/GenerateResourceBudgetAdmissionVectors.lean
  lake env lean Hegemon/Native/RpcAdmission.lean
  lake env lean Hegemon/Native/GenerateRpcAdmissionVectors.lean
  lake env lean Hegemon/Native/SidecarUploadAdmission.lean
  lake env lean Hegemon/Native/GenerateSidecarUploadAdmissionVectors.lean
  lake env lean Hegemon/Native/StagedCiphertextReload.lean
  lake env lean Hegemon/Native/GenerateStagedCiphertextReloadVectors.lean
  lake env lean Hegemon/Native/SyncAdmission.lean
  lake env lean Hegemon/Native/GenerateSyncAdmissionVectors.lean
  lake env lean Hegemon/Network/SecureChannel.lean
  lake env lean Hegemon/Network/GenerateSecureChannelVectors.lean
  lake env lean Hegemon/Network/PqNoise.lean
  lake env lean Hegemon/Network/GeneratePqNoiseVectors.lean
  lake env lean Hegemon/Release/DependencyAuditPolicy.lean
  lake env lean Hegemon/Release/GenerateDependencyAuditPolicyVectors.lean
  lake env lean Hegemon/Release/PqBinaryPolicy.lean
  lake env lean Hegemon/Release/GeneratePqBinaryPolicyVectors.lean
  lake env lean Hegemon/Native/TxLeafArtifact.lean
  lake env lean Hegemon/Native/GenerateTxLeafArtifactVectors.lean
  lake env lean Hegemon/Native/ReceiptRoot.lean
  lake env lean Hegemon/Native/GenerateReceiptRootVectors.lean
  lake env lean Hegemon/Shielded/Nullifier.lean
  lake env lean Hegemon/Shielded/GenerateVectors.lean
  lake env lean Hegemon/Transaction/Balance.lean
  lake env lean Hegemon/Transaction/GenerateVectors.lean
  lake env lean Hegemon/Transaction/MerklePath.lean
  lake env lean Hegemon/Transaction/GenerateMerkleVectors.lean
  lake env lean Hegemon/Transaction/PublicInputs.lean
  lake env lean Hegemon/Transaction/GeneratePublicInputVectors.lean
  lake env lean Hegemon/Transaction/PublicInputBinding.lean
  lake env lean Hegemon/Transaction/GeneratePublicInputBindingVectors.lean
  lake env lean Hegemon/Transaction/StatementHash.lean
  lake env lean Hegemon/Transaction/GenerateStatementHashVectors.lean
)

python3 "$ROOT/scripts/check_lean_claim_axioms.py" \
  --claims "$ROOT/config/formal-security-claims.json" \
  --waivers "$ROOT/config/lean-axiom-waivers.json"

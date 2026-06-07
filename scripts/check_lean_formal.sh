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
  lake build Hegemon gen_bridge_vectors gen_bridge_checkpoint_output_vectors gen_bridge_long_range_vectors gen_bridge_header_mmr_vectors gen_bridge_header_mmr_transcript_vectors gen_bridge_flyclient_vectors gen_aggregation_v5_vectors gen_da_root_vectors gen_shielded_vectors gen_consensus_vectors gen_header_vectors gen_miner_identity_vectors gen_native_tx_leaf_admission_vectors gen_pow_vectors gen_proof_policy_vectors gen_proven_batch_binding_vectors gen_receipt_root_admission_vectors gen_recursive_block_admission_vectors gen_recursive_public_replay_vectors gen_supply_vectors gen_version_policy_vectors gen_action_order_vectors gen_native_tx_leaf_artifact_vectors gen_native_receipt_root_vectors gen_transaction_vectors gen_merkle_vectors gen_public_input_vectors gen_public_input_binding_vectors gen_statement_hash_vectors
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
  lake env lean Hegemon/Consensus/Supply.lean
  lake env lean Hegemon/Consensus/GenerateSupplyVectors.lean
  lake env lean Hegemon/Consensus/VersionPolicy.lean
  lake env lean Hegemon/Consensus/GenerateVersionPolicyVectors.lean
  lake env lean Hegemon/Native/ActionOrder.lean
  lake env lean Hegemon/Native/GenerateActionOrderVectors.lean
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

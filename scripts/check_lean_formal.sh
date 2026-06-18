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
  while IFS= read -r -d '' dir; do
    rel="${dir#"$LEAN_ROOT"/}"
    mkdir -p ".lake/build/lib/lean/$rel" ".lake/build/ir/$rel"
  done < <(find "$LEAN_ROOT/Hegemon" -type d -print0)
  lean_exes=()
  while IFS= read -r target; do
    lean_exes+=("$target")
  done < <(awk '/^lean_exe / { print $2 }' lakefile.lean)
  lake build Hegemon
  for target in "${lean_exes[@]}"; do
    lake build "$target"
  done
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
  lake env lean Hegemon/Bridge/MintReplayPolicy.lean
  lake env lean Hegemon/Bridge/GenerateMintReplayPolicyVectors.lean
  lake env lean Hegemon/Bridge/GenerateCheckpointOutputVectors.lean
  lake env lean Hegemon/Bridge/GenerateLongRangeVectors.lean
  lake env lean Hegemon/Bridge/GenerateVectors.lean
  lake env lean Hegemon/Consensus/AggregationV5.lean
  lake env lean Hegemon/Consensus/GenerateAggregationV5Vectors.lean
  lake env lean Hegemon/Consensus/CommitmentTreeAppend.lean
  lake env lean Hegemon/Consensus/GenerateCommitmentTreeAppendVectors.lean
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
  lake env lean Hegemon/Consensus/RecursiveBlockV2VerifierSurface.lean
  lake env lean Hegemon/Consensus/GenerateRecursiveBlockV2VerifierSurfaceVectors.lean
  lake env lean Hegemon/Consensus/RecursivePublicReplay.lean
  lake env lean Hegemon/Consensus/GenerateRecursivePublicReplayVectors.lean
  lake env lean Hegemon/Consensus/RecursiveSemanticInputs.lean
  lake env lean Hegemon/Consensus/GenerateRecursiveSemanticInputVectors.lean
  lake env lean Hegemon/Consensus/StatementAnchorAdmission.lean
  lake env lean Hegemon/Consensus/GenerateStatementAnchorAdmissionVectors.lean
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
  lake env lean Hegemon/Native/ActionWireReplayProjectionAdmission.lean
  lake env lean Hegemon/Native/GenerateActionWireReplayProjectionAdmissionVectors.lean
  lake env lean Hegemon/Native/AnnouncedBlockAdmission.lean
  lake env lean Hegemon/Native/GenerateAnnouncedBlockAdmissionVectors.lean
  lake env lean Hegemon/Native/BlockIndexReload.lean
  lake env lean Hegemon/Native/GenerateBlockIndexReloadVectors.lean
  lake env lean Hegemon/Native/CanonicalStateReload.lean
  lake env lean Hegemon/Native/GenerateCanonicalStateReloadVectors.lean
  lake env lean Hegemon/Native/BridgeReplayReload.lean
  lake env lean Hegemon/Native/GenerateBridgeReplayReloadVectors.lean
  lake env lean Hegemon/Native/PendingActionReload.lean
  lake env lean Hegemon/Native/GeneratePendingActionReloadVectors.lean
  lake env lean Hegemon/Native/ActionScopeAdmission.lean
  lake env lean Hegemon/Native/GenerateActionScopeAdmissionVectors.lean
  lake env lean Hegemon/Native/BlockActionValidation.lean
  lake env lean Hegemon/Native/BlockActionReplayPublication.lean
  lake env lean Hegemon/Native/BridgeActionPayloadAdmission.lean
  lake env lean Hegemon/Native/GenerateBridgeActionPayloadAdmissionVectors.lean
  lake env lean Hegemon/Native/BridgeActionResourceAdmission.lean
  lake env lean Hegemon/Native/GenerateBridgeActionResourceAdmissionVectors.lean
  lake env lean Hegemon/Native/BridgeWitnessBackscan.lean
  lake env lean Hegemon/Native/GenerateBridgeWitnessBackscanVectors.lean
  lake env lean Hegemon/Native/BridgeWitnessExportAdmission.lean
  lake env lean Hegemon/Native/GenerateBridgeWitnessExportAdmissionVectors.lean
  lake env lean Hegemon/Native/InboundBridgeReceiptAdmission.lean
  lake env lean Hegemon/Native/GenerateInboundBridgeReceiptAdmissionVectors.lean
  lake env lean Hegemon/Native/NativeBackendReviewPolicy.lean
  lake env lean Hegemon/Native/GenerateNativeBackendReviewPolicyVectors.lean
  lake env lean Hegemon/Native/NativeBackendReleasePosture.lean
  lake env lean Hegemon/Native/GenerateNativeBackendReleasePostureVectors.lean
  lake env lean Hegemon/Native/TransferActionPayloadAdmission.lean
  lake env lean Hegemon/Native/GenerateTransferActionPayloadAdmissionVectors.lean
  lake env lean Hegemon/Native/TransferStateAdmission.lean
  lake env lean Hegemon/Native/GenerateTransferStateAdmissionVectors.lean
  lake env lean Hegemon/Native/StablecoinPolicyAuthorization.lean
  lake env lean Hegemon/Native/StablecoinPolicyLiveAuthorization.lean
  lake env lean Hegemon/Native/GenerateStablecoinPolicyAuthorizationVectors.lean
  lake env lean Hegemon/Native/TxLeafCanonicalSurface.lean
  lake env lean Hegemon/Native/TransferNoTheftBoundary.lean
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
  lake env lean Hegemon/Native/PendingActionScaleWire.lean
  lake env lean Hegemon/Native/GeneratePendingActionScaleWireVectors.lean
  lake env lean Hegemon/Native/CoinbaseAccountingAdmission.lean
  lake env lean Hegemon/Native/GenerateCoinbaseAccountingAdmissionVectors.lean
  lake env lean Hegemon/Native/CoinbaseActionPayloadAdmission.lean
  lake env lean Hegemon/Native/GenerateCoinbaseActionPayloadAdmissionVectors.lean
  lake env lean Hegemon/Native/CommitmentTreeMembershipRefinement.lean
  lake env lean Hegemon/Native/MineableActionAdmission.lean
  lake env lean Hegemon/Native/GenerateMineableActionAdmissionVectors.lean
  lake env lean Hegemon/Native/MinerIdentity.lean
  lake env lean Hegemon/Native/GenerateMinerIdentityVectors.lean
  lake env lean Hegemon/Native/MinedWorkAdmission.lean
  lake env lean Hegemon/Native/GenerateMinedWorkAdmissionVectors.lean
  lake env lean Hegemon/Native/MinedBlockCommitPublication.lean
  lake env lean Hegemon/Native/WorkTemplateAdmission.lean
  lake env lean Hegemon/Native/GenerateWorkTemplateAdmissionVectors.lean
  lake env lean Hegemon/Native/RecursiveArtifactContextAdmission.lean
  lake env lean Hegemon/Native/GenerateRecursiveArtifactContextAdmissionVectors.lean
  lake env lean Hegemon/Native/ResourceBudgetAdmission.lean
  lake env lean Hegemon/Native/GenerateResourceBudgetAdmissionVectors.lean
  lake env lean Hegemon/Resource/BoundedRequestAdmission.lean
  lake env lean Hegemon/Resource/GenerateBoundedRequestAdmissionVectors.lean
  lake env lean Hegemon/Network/QueueResourceAdmission.lean
  lake env lean Hegemon/Network/GenerateQueueResourceAdmissionVectors.lean
  lake env lean Hegemon/Native/RpcAdmission.lean
  lake env lean Hegemon/Native/GenerateRpcAdmissionVectors.lean
  lake env lean Hegemon/Native/PreHeavyWorkResourceBoundSurface.lean
  lake env lean Hegemon/Native/GeneratePreHeavyWorkResourceBoundSurfaceVectors.lean
  lake env lean Hegemon/Native/DaSidecarReplayBinding.lean
  lake env lean Hegemon/Native/RawIngressSidecarReplayRecoverability.lean
  lake env lean Hegemon/Native/CanonicalPublicationRefinement.lean
  lake env lean Hegemon/Native/AcceptedBlockAdmissionSafety.lean
  lake env lean Hegemon/Native/PendingActionByteParserRefinement.lean
  lake env lean Hegemon/Native/PendingActionBytePublicationRefinement.lean
  lake env lean Hegemon/Native/PendingActionByteReplayRowCountBinding.lean
  lake env lean Hegemon/Native/RawIngressPendingActionPublicationRefinement.lean
  lake env lean Hegemon/Native/RawIngressActionHashTxLeafPublication.lean
  lake env lean Hegemon/Native/RawIngressDaSidecarCanonicalPublication.lean
  lake env lean Hegemon/Native/RawIngressFullBytePublicationSurface.lean
  lake env lean Hegemon/Native/MaterializedSidecarDaBlobPublication.lean
  lake env lean Hegemon/Native/MaterializedConsensusDaBlobRefinement.lean
  lake env lean Hegemon/Native/MaterializedTransferNoTheftPublication.lean
  lake env lean Hegemon/Native/RawIngressBridgePendingActionPublication.lean
  lake env lean Hegemon/Native/RawIngressTransferNoTheftPublication.lean
  lake env lean Hegemon/Native/SidecarUploadAdmission.lean
  lake env lean Hegemon/Native/GenerateSidecarUploadAdmissionVectors.lean
  lake env lean Hegemon/Native/StagedCiphertextReload.lean
  lake env lean Hegemon/Native/GenerateStagedCiphertextReloadVectors.lean
  lake env lean Hegemon/Native/StagedProofReload.lean
  lake env lean Hegemon/Native/GenerateStagedProofReloadVectors.lean
  lake env lean Hegemon/Native/CandidateArtifactScaleWire.lean
  lake env lean Hegemon/Native/GenerateCandidateArtifactScaleWireVectors.lean
  lake env lean Hegemon/Native/SyncAdmission.lean
  lake env lean Hegemon/Native/SyncBlockReplayPublication.lean
  lake env lean Hegemon/Native/SyncResponseImport.lean
  lake env lean Hegemon/Native/GenerateSyncAdmissionVectors.lean
  lake env lean Hegemon/Native/GenerateSyncResponseImportVectors.lean
  lake env lean Hegemon/Network/SecureChannel.lean
  lake env lean Hegemon/Network/GenerateSecureChannelVectors.lean
  lake env lean Hegemon/Network/PqNoise.lean
  lake env lean Hegemon/Network/PqNoiseHandshakeChannel.lean
  lake env lean Hegemon/Network/GeneratePqNoiseVectors.lean
  lake env lean Hegemon/Privacy/CiphertextPrivacy.lean
  lake env lean Hegemon/Privacy/Observer.lean
  lake env lean Hegemon/Privacy/NativeObserverSurface.lean
  lake env lean Hegemon/Privacy/NativeSidecarObserverSurface.lean
  lake env lean Hegemon/Wallet/NoteCiphertextDecrypt.lean
  lake env lean Hegemon/Wallet/NotePlaintextCommitment.lean
  lake env lean Hegemon/Wallet/NoteCiphertextWire.lean
  lake env lean Hegemon/Wallet/GenerateNoteCiphertextWireVectors.lean
  lake env lean Hegemon/Release/CiReleaseGate.lean
  lake env lean Hegemon/Release/GenerateCiReleaseGateVectors.lean
  lake env lean Hegemon/Release/DependencyAuditPolicy.lean
  lake env lean Hegemon/Release/GenerateDependencyAuditPolicyVectors.lean
  lake env lean Hegemon/Release/PqBinaryPolicy.lean
  lake env lean Hegemon/Release/GeneratePqBinaryPolicyVectors.lean
  lake env lean Hegemon/Native/TxLeafArtifact.lean
  lake env lean Hegemon/Native/TxLeafArtifactProjectionRefinement.lean
  lake env lean Hegemon/Native/GenerateTxLeafArtifactVectors.lean
  lake env lean Hegemon/Native/ReceiptRoot.lean
  lake env lean Hegemon/Native/GenerateReceiptRootVectors.lean
  lake env lean Hegemon/Shielded/Nullifier.lean
  lake env lean Hegemon/Shielded/GenerateVectors.lean
  lake env lean Hegemon/Transaction/AirBalanceBoundary.lean
  lake env lean Hegemon/Transaction/Balance.lean
  lake env lean Hegemon/Transaction/GenerateVectors.lean
  lake env lean Hegemon/Transaction/NoteCommitmentInputs.lean
  lake env lean Hegemon/Transaction/GenerateNoteCommitmentInputVectors.lean
  lake env lean Hegemon/Transaction/NullifierInputs.lean
  lake env lean Hegemon/Transaction/GenerateNullifierInputVectors.lean
  lake env lean Hegemon/Transaction/MerklePath.lean
  lake env lean Hegemon/Transaction/GenerateMerkleVectors.lean
  lake env lean Hegemon/Transaction/PublicInputs.lean
  lake env lean Hegemon/Transaction/GeneratePublicInputVectors.lean
  lake env lean Hegemon/Transaction/PublicInputBinding.lean
  lake env lean Hegemon/Transaction/GeneratePublicInputBindingVectors.lean
  lake env lean Hegemon/Transaction/ProofStatementBinding.lean
  lake env lean Hegemon/Transaction/GenerateProofStatementBindingVectors.lean
  lake env lean Hegemon/Transaction/ProofSystemBoundary.lean
  lake env lean Hegemon/Transaction/ProofWrapperAdmission.lean
  lake env lean Hegemon/Transaction/GenerateProofWrapperAdmissionVectors.lean
  lake env lean Hegemon/Transaction/ProofWrapperWire.lean
  lake env lean Hegemon/Transaction/GenerateProofWrapperWireVectors.lean
  lake env lean Hegemon/Transaction/SmallWoodBalanceBoundary.lean
  lake env lean Hegemon/Transaction/SmallWoodCandidateWrapperAdmission.lean
  lake env lean Hegemon/Transaction/GenerateSmallWoodCandidateWrapperAdmissionVectors.lean
  lake env lean Hegemon/Transaction/SmallWoodSpendAuthorization.lean
  lake env lean Hegemon/Transaction/GenerateSmallWoodSpendAuthorizationVectors.lean
  lake env lean Hegemon/Transaction/SmallWoodPublicStatementBinding.lean
  lake env lean Hegemon/Transaction/GenerateSmallWoodPublicStatementBindingVectors.lean
  lake env lean Hegemon/Transaction/SmallWoodVerifierStatementProjection.lean
  lake env lean Hegemon/Transaction/GenerateSmallWoodVerifierStatementProjectionVectors.lean
  lake env lean Hegemon/Transaction/SmallWoodRecursiveEnvelopeWire.lean
  lake env lean Hegemon/Transaction/GenerateSmallWoodRecursiveEnvelopeWireVectors.lean
  lake env lean Hegemon/Transaction/SmallWoodTranscriptBinding.lean
  lake env lean Hegemon/Transaction/GenerateSmallWoodTranscriptBindingVectors.lean
  lake env lean Hegemon/Transaction/SmallWoodVerifierSoundnessEnvelope.lean
  lake env lean Hegemon/Transaction/StatementHash.lean
  lake env lean Hegemon/Transaction/GenerateStatementHashVectors.lean
)

python3 "$ROOT/scripts/check_lean_claim_axioms.py" \
  --claims "$ROOT/config/formal-security-claims.json" \
  --waivers "$ROOT/config/lean-axiom-waivers.json"

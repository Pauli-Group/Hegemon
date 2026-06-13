import Hegemon.Consensus.ProvenBatchBinding
import Hegemon.Consensus.RecursiveSemanticInputs
import Hegemon.Native.ActionStreamEffect
import Hegemon.Native.ActionWireReplayProjectionAdmission
import Hegemon.Native.BlockArtifactBindingAdmission
import Hegemon.Native.BlockReplayInputProjection
import Hegemon.Native.CandidateArtifactAdmission
import Hegemon.Native.CandidateArtifactCouplingAdmission
import Hegemon.Native.SidecarUploadAdmission

namespace Hegemon
namespace Native
namespace DaSidecarReplayBinding

open Hegemon.Consensus.ProvenBatchBinding
open Hegemon.Consensus.RecursiveSemanticInputs
open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CandidateArtifactAdmission
open Hegemon.Native.CandidateArtifactCouplingAdmission
open Hegemon.Native.SidecarUploadAdmission

structure DaSidecarReplaySurface where
  candidateArtifact : CandidateArtifactInput
  candidateBinding : CandidateArtifactBindingInput
  candidateCoupling : CandidateArtifactCouplingInput
  provenBatchBinding : BindingInput
  recursiveSemanticInput : SemanticDerivationInput
  recursiveSemanticSource : SemanticSourceFields
  ciphertextRequest : RequestCountInput
  ciphertextCapacity : CapacityInput
  proofRequest : RequestCountInput
  proofCapacity : CapacityInput
  proofMetadata : ProofMetadataInput
  proofDecoded : ProofDecodedInput
  actionStream : ActionStreamInput
  wireReplayProjection : ActionWireReplayProjectionInput
deriving DecidableEq, Repr

structure AcceptedDaSidecarReplayFacts
    (surface : DaSidecarReplaySurface)
    (streamOutput : ActionStreamOutput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (semanticFields : RecursiveSemanticFields) : Prop where
  candidateArtifactAccepted :
    evaluateCandidateArtifact surface.candidateArtifact = Except.ok ()
  candidateBindingAccepted :
    evaluateCandidateArtifactBinding surface.candidateBinding = Except.ok ()
  candidateCouplingAccepted :
    evaluateCandidateArtifactCoupling surface.candidateCoupling = Except.ok ()
  provenBatchBindingAccepted :
    evaluateBinding surface.provenBatchBinding = none
  recursiveSemanticFieldsDerived :
    deriveSemanticFields
      surface.recursiveSemanticInput
      surface.recursiveSemanticSource =
        some semanticFields
  ciphertextRequestAccepted :
    evaluateCiphertextRequest surface.ciphertextRequest = Except.ok ()
  ciphertextCapacityAccepted :
    evaluateCiphertextCapacity surface.ciphertextCapacity = Except.ok ()
  proofRequestAccepted :
    evaluateProofRequest surface.proofRequest = Except.ok ()
  proofCapacityAccepted :
    evaluateProofCapacity surface.proofCapacity = Except.ok ()
  proofMetadataAccepted :
    evaluateProofMetadata surface.proofMetadata = Except.ok ()
  proofDecodedAccepted :
    evaluateProofDecoded surface.proofDecoded = Except.ok ()
  actionStreamAccepted :
    evaluateActionStreamEffect surface.actionStream = Except.ok streamOutput
  wireReplayProjectionAccepted :
    evaluateActionWireReplayProjection surface.wireReplayProjection =
      Except.ok wireOutput

theorem accepted_candidate_artifact_implies_nonzero_tx_and_da
    {input : CandidateArtifactInput}
    (accepted : evaluateCandidateArtifact input = Except.ok ()) :
    input.txCount ≠ 0 ∧ input.daChunkCount ≠ 0 := by
  unfold evaluateCandidateArtifact at accepted
  by_cases hDeltas : input.stateDeltasAbsent = false
  · simp [hDeltas] at accepted
  · simp [hDeltas] at accepted
    by_cases hPresent : input.artifactPresent = false
    · simp [hPresent] at accepted
    · simp [hPresent] at accepted
      by_cases hSchema : input.schemaMatches = false
      · simp [hSchema] at accepted
      · simp [hSchema] at accepted
        by_cases hTxZero : input.txCount = 0
        · simp [hTxZero] at accepted
        · simp [hTxZero] at accepted
          by_cases hTxTooLarge : input.txCount > input.maxTxCount
          · simp [hTxTooLarge] at accepted
          · simp [hTxTooLarge] at accepted
            by_cases hDaZero : input.daChunkCount = 0
            · simp [hDaZero] at accepted
            · exact ⟨hTxZero, hDaZero⟩

theorem accepted_candidate_artifact_binding_implies_root_matches
    {input : CandidateArtifactBindingInput}
    (accepted : evaluateCandidateArtifactBinding input = Except.ok ()) :
    input.daRootMatches = true
      ∧ input.txStatementsCommitmentMatches = true
      ∧ input.recursiveStateRootMatches = true := by
  cases input with
  | mk daRootMatches txStatementsCommitmentMatches recursiveStateRootMatches =>
      cases daRootMatches <;> cases txStatementsCommitmentMatches <;>
        cases recursiveStateRootMatches <;>
          simp [evaluateCandidateArtifactBinding] at accepted ⊢

theorem accepted_wire_replay_projection_implies_preconditions
    {input : ActionWireReplayProjectionInput}
    {output : ActionWireReplayProjectionOutput}
    (accepted :
      evaluateActionWireReplayProjection input = Except.ok output) :
    actionWireReplayProjectionPreconditions input = true := by
  have acceptsTrue :
      actionWireReplayProjectionAccepts input = true := by
    simp [actionWireReplayProjectionAccepts, accepted]
  have acceptsEq :=
    accepts_iff_wire_replay_projection_preconditions input
  rw [acceptsTrue] at acceptsEq
  exact acceptsEq.symm

theorem accepted_wire_replay_projection_implies_action_counts
    {input : ActionWireReplayProjectionInput}
    {output : ActionWireReplayProjectionOutput}
    (accepted :
      evaluateActionWireReplayProjection input = Except.ok output) :
    input.actionCount = input.plannedCount
      ∧ input.actionCount = input.actions.length := by
  have preconditions :=
    accepted_wire_replay_projection_implies_preconditions
      (input := input)
      (output := output)
      accepted
  unfold actionWireReplayProjectionPreconditions at preconditions
  by_cases hCounts : actionWireReplayPlanCountsMatch input
  · unfold actionWireReplayPlanCountsMatch at hCounts
    simpa using hCounts
  · simp [hCounts] at preconditions

theorem accepted_proven_batch_binding_implies_da_binding
    {input : BindingInput}
    (accepted : evaluateBinding input = none) :
    input.daRootMatches = true ∧ input.daChunkCount ≠ 0 := by
  unfold evaluateBinding at accepted
  by_cases hRoute :
      routeCompatible input.batchMode input.proofKind = false
  · simp [hRoute] at accepted
  · simp [hRoute] at accepted
    by_cases hTx : input.txCount = input.expectedTxCount
    · simp [hTx] at accepted
      by_cases hStatement : input.statementCommitmentMatches = false
      · simp [hStatement] at accepted
      · simp [hStatement] at accepted
        by_cases hDa : input.daRootMatches = false
        · simp [hDa] at accepted
        · simp [hDa] at accepted
          by_cases hChunk : input.daChunkCount = 0
          · simp [hChunk] at accepted
          · have daTrue : input.daRootMatches = true := by
              cases hValue : input.daRootMatches with
              | false => exact False.elim (hDa hValue)
              | true => rfl
            exact ⟨daTrue, hChunk⟩
    · simp [hTx] at accepted

theorem derived_semantic_fields_da_root_matches_source
    {input : SemanticDerivationInput}
    {source : SemanticSourceFields}
    {fields : RecursiveSemanticFields}
    (derived : deriveSemanticFields input source = some fields) :
    fields.daRoot = source.daRoot := by
  unfold deriveSemanticFields at derived
  cases hAccepts : semanticAccepts input with
  | false =>
      simp [hAccepts] at derived
  | true =>
      simp [hAccepts] at derived
      rcases derived with rfl
      rfl

theorem accepted_sidecar_upload_implies_preconditions
    {ciphertextRequest proofRequest : RequestCountInput}
    {ciphertextCapacity proofCapacity : CapacityInput}
    {proofMetadata : ProofMetadataInput}
    {proofDecoded : ProofDecodedInput}
    (ciphertextRequestAccepted :
      evaluateCiphertextRequest ciphertextRequest = Except.ok ())
    (ciphertextCapacityAccepted :
      evaluateCiphertextCapacity ciphertextCapacity = Except.ok ())
    (proofRequestAccepted :
      evaluateProofRequest proofRequest = Except.ok ())
    (proofCapacityAccepted :
      evaluateProofCapacity proofCapacity = Except.ok ())
    (proofMetadataAccepted :
      evaluateProofMetadata proofMetadata = Except.ok ())
    (proofDecodedAccepted :
      evaluateProofDecoded proofDecoded = Except.ok ()) :
    ¬ ciphertextRequest.itemCount > ciphertextRequest.maxItems
      ∧ capacityPreconditions ciphertextCapacity = true
      ∧ ¬ proofRequest.itemCount > proofRequest.maxItems
      ∧ capacityPreconditions proofCapacity = true
      ∧ proofMetadataPreconditions proofMetadata = true
      ∧ proofDecodedPreconditions proofDecoded = true := by
  have ciphertextAccepts :
      accepts (evaluateCiphertextRequest ciphertextRequest) = true := by
    simp [accepts, ciphertextRequestAccepted]
  have proofAccepts :
      accepts (evaluateProofRequest proofRequest) = true := by
    simp [accepts, proofRequestAccepted]
  have ciphertextRequestBound :=
    (ciphertext_request_accepts_iff_not_over_limit
      (input := ciphertextRequest)).mp ciphertextAccepts
  have proofRequestBound :=
    (proof_request_accepts_iff_not_over_limit
      (input := proofRequest)).mp proofAccepts
  have ciphertextCapacityPre :
      capacityPreconditions ciphertextCapacity = true := by
    have acceptsTrue :
        accepts (evaluateCiphertextCapacity ciphertextCapacity) = true := by
      simp [accepts, ciphertextCapacityAccepted]
    have acceptsEq :=
      ciphertext_capacity_accepts_iff_preconditions ciphertextCapacity
    rw [acceptsEq] at acceptsTrue
    exact acceptsTrue
  have proofCapacityPre :
      capacityPreconditions proofCapacity = true := by
    have acceptsTrue :
        accepts (evaluateProofCapacity proofCapacity) = true := by
      simp [accepts, proofCapacityAccepted]
    have acceptsEq :=
      proof_capacity_accepts_iff_preconditions proofCapacity
    rw [acceptsEq] at acceptsTrue
    exact acceptsTrue
  have proofMetadataPre :
      proofMetadataPreconditions proofMetadata = true := by
    have acceptsTrue :
        accepts (evaluateProofMetadata proofMetadata) = true := by
      simp [accepts, proofMetadataAccepted]
    have acceptsEq :=
      proof_metadata_accepts_iff_preconditions proofMetadata
    rw [acceptsEq] at acceptsTrue
    exact acceptsTrue
  have proofDecodedPre :
      proofDecodedPreconditions proofDecoded = true := by
    have acceptsTrue :
        accepts (evaluateProofDecoded proofDecoded) = true := by
      simp [accepts, proofDecodedAccepted]
    have acceptsEq :=
      proof_decoded_accepts_iff_preconditions proofDecoded
    rw [acceptsEq] at acceptsTrue
    exact acceptsTrue
  exact
    ⟨ciphertextRequestBound,
      ciphertextCapacityPre,
      proofRequestBound,
      proofCapacityPre,
      proofMetadataPre,
      proofDecodedPre⟩

theorem accepted_da_sidecar_replay_facts_expose_binding_preconditions
    {surface : DaSidecarReplaySurface}
    {streamOutput : ActionStreamOutput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields : RecursiveSemanticFields}
    (facts :
      AcceptedDaSidecarReplayFacts
        surface
        streamOutput
        wireOutput
        semanticFields) :
    surface.candidateBinding.daRootMatches = true
      ∧ surface.candidateBinding.txStatementsCommitmentMatches = true
      ∧ surface.candidateBinding.recursiveStateRootMatches = true
      ∧ surface.provenBatchBinding.daRootMatches = true
      ∧ surface.provenBatchBinding.daChunkCount ≠ 0
      ∧ semanticFields.daRoot = surface.recursiveSemanticSource.daRoot
      ∧ surface.candidateArtifact.txCount ≠ 0
      ∧ surface.candidateArtifact.daChunkCount ≠ 0
      ∧ actionStreamPreconditions surface.actionStream = true
      ∧ actionWireReplayProjectionPreconditions
          surface.wireReplayProjection = true
      ∧ surface.wireReplayProjection.actionCount =
          surface.wireReplayProjection.plannedCount
      ∧ surface.wireReplayProjection.actionCount =
          surface.wireReplayProjection.actions.length
      ∧ ¬ surface.ciphertextRequest.itemCount >
          surface.ciphertextRequest.maxItems
      ∧ capacityPreconditions surface.ciphertextCapacity = true
      ∧ ¬ surface.proofRequest.itemCount > surface.proofRequest.maxItems
      ∧ capacityPreconditions surface.proofCapacity = true
      ∧ proofMetadataPreconditions surface.proofMetadata = true
      ∧ proofDecodedPreconditions surface.proofDecoded = true := by
  have bindingFacts :=
    accepted_candidate_artifact_binding_implies_root_matches
      facts.candidateBindingAccepted
  have candidateFacts :=
    accepted_candidate_artifact_implies_nonzero_tx_and_da
      facts.candidateArtifactAccepted
  have provenBatchFacts :=
    accepted_proven_batch_binding_implies_da_binding
      facts.provenBatchBindingAccepted
  have semanticDaRoot :=
    derived_semantic_fields_da_root_matches_source
      facts.recursiveSemanticFieldsDerived
  have streamPreconditions :
      actionStreamPreconditions surface.actionStream = true := by
    simp [
      actionStreamPreconditions,
      actionStreamAccepts,
      facts.actionStreamAccepted
    ]
  have wirePreconditions :=
    accepted_wire_replay_projection_implies_preconditions
      facts.wireReplayProjectionAccepted
  have wireCounts :=
    accepted_wire_replay_projection_implies_action_counts
      facts.wireReplayProjectionAccepted
  have sidecarPreconditions :=
    accepted_sidecar_upload_implies_preconditions
      facts.ciphertextRequestAccepted
      facts.ciphertextCapacityAccepted
      facts.proofRequestAccepted
      facts.proofCapacityAccepted
      facts.proofMetadataAccepted
      facts.proofDecodedAccepted
  exact
    ⟨bindingFacts.1,
      bindingFacts.2.1,
      bindingFacts.2.2,
      provenBatchFacts.1,
      provenBatchFacts.2,
      semanticDaRoot,
      candidateFacts.1,
      candidateFacts.2,
      streamPreconditions,
      wirePreconditions,
      wireCounts.1,
      wireCounts.2,
      sidecarPreconditions.1,
      sidecarPreconditions.2.1,
      sidecarPreconditions.2.2.1,
      sidecarPreconditions.2.2.2.1,
      sidecarPreconditions.2.2.2.2.1,
      sidecarPreconditions.2.2.2.2.2⟩

theorem accepted_projected_replay_with_da_sidecar_facts
    {surface : DaSidecarReplaySurface}
    {streamOutput : ActionStreamOutput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields : RecursiveSemanticFields}
    {initial final : Hegemon.Native.AcceptedChain.NativeLedgerReplayState}
    {projections : List NativeBlockReplayProjection}
    (facts :
      AcceptedDaSidecarReplayFacts
        surface
        streamOutput
        wireOutput
        semanticFields)
    (initialNullifiersNodup : initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.consumedBridgeReplays.Nodup)
    (acceptedReplay :
      projectedLedgerStateAfter initial projections = some final) :
    surface.candidateBinding.daRootMatches = true
      ∧ surface.provenBatchBinding.daRootMatches = true
      ∧ semanticFields.daRoot = surface.recursiveSemanticSource.daRoot
      ∧ projectedCarriedStatePreconditions initial projections = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup := by
  have sidecarFacts :=
    accepted_da_sidecar_replay_facts_expose_binding_preconditions facts
  have replayFacts :=
    accepted_projected_ledger_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedReplay
  rcases replayFacts with
    ⟨_accepted,
      _supply,
      _leaf,
      _commitmentPlan,
      carried,
      spentNodup,
      bridgeNodup⟩
  exact
    ⟨sidecarFacts.1,
      sidecarFacts.2.2.2.1,
      sidecarFacts.2.2.2.2.2.1,
      carried,
      spentNodup,
      bridgeNodup⟩

theorem accepted_raw_projected_replay_with_da_sidecar_facts
    {surface : DaSidecarReplaySurface}
    {streamOutput : ActionStreamOutput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields : RecursiveSemanticFields}
    {initial final : Hegemon.Native.AcceptedChain.NativeLedgerReplayState}
    {blocks : List RawDecodedNativeReplayBlock}
    (facts :
      AcceptedDaSidecarReplayFacts
        surface
        streamOutput
        wireOutput
        semanticFields)
    (initialNullifiersNodup : initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.consumedBridgeReplays.Nodup)
    (acceptedReplay :
      rawProjectedLedgerStateAfter initial blocks = some final) :
    surface.candidateBinding.daRootMatches = true
      ∧ surface.candidateBinding.txStatementsCommitmentMatches = true
      ∧ surface.candidateBinding.recursiveStateRootMatches = true
      ∧ candidateArtifactCouplingPreconditions
          surface.candidateCoupling = true
      ∧ surface.candidateArtifact.txCount ≠ 0
      ∧ surface.candidateArtifact.daChunkCount ≠ 0
      ∧ Hegemon.Native.AcceptedChain.validateNativeLedgerReplayChain
          initial
          (rawReplayInputs blocks) =
          some final
      ∧ Hegemon.Native.AcceptedChain.expectedNativeSupplyAfter
          initial.supply
          (rawReplayInputs blocks) =
          some final.supply
      ∧ Hegemon.Native.AcceptedChain.expectedNativeLeafCountAfter
          initial.leafCount
          (rawReplayInputs blocks) =
          some final.leafCount
      ∧ Hegemon.Native.AcceptedChain.nativeLedgerReplayCommitmentPlanPreconditions
          initial
          (rawReplayInputs blocks) = true
      ∧ rawProjectedCarriedStatePreconditions initial blocks = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup := by
  have bindingFacts :=
    accepted_candidate_artifact_binding_implies_root_matches
      facts.candidateBindingAccepted
  have candidateFacts :=
    accepted_candidate_artifact_implies_nonzero_tx_and_da
      facts.candidateArtifactAccepted
  have couplingAccepts :
      candidateArtifactCouplingAccepts surface.candidateCoupling = true := by
    simp [
      candidateArtifactCouplingAccepts,
      facts.candidateCouplingAccepted
    ]
  have couplingPreconditions :=
    (accepts_iff_coupling_preconditions
      (input := surface.candidateCoupling)).mp
      couplingAccepts
  have replayFacts :=
    accepted_raw_projected_ledger_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedReplay
  rcases replayFacts with
    ⟨accepted,
      supply,
      leaf,
      commitmentPlan,
      carried,
      spentNodup,
      bridgeNodup⟩
  exact
    ⟨bindingFacts.1,
      bindingFacts.2.1,
      bindingFacts.2.2,
      couplingPreconditions,
      candidateFacts.1,
      candidateFacts.2,
      accepted,
      supply,
      leaf,
      commitmentPlan,
      carried,
      spentNodup,
      bridgeNodup⟩

end DaSidecarReplayBinding
end Native
end Hegemon

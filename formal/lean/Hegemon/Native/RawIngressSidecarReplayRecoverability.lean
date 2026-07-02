import Hegemon.Native.ActionRequestProjectionAdmission
import Hegemon.Native.DaSidecarReplayBinding
import Hegemon.Native.PendingActionReload
import Hegemon.Native.StagedCiphertextReload
import Hegemon.Native.StagedProofReload
import Hegemon.Native.TransferStateAdmission

namespace Hegemon
namespace Native
namespace RawIngressSidecarReplayRecoverability

open Hegemon.Native.ActionRequestProjectionAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.DaSidecarReplayBinding
open Hegemon.Native.PendingActionReload
open Hegemon.Native.StagedCiphertextReload
open Hegemon.Native.StagedProofReload
open Hegemon.Native.TransferStateAdmission

structure RawIngressSidecarReplaySurface where
  actionRequest : ActionRequestProjectionInput
  pendingReload : PendingActionReloadInput
  stagedCiphertextReload : StagedCiphertextReloadInput
  stagedProofReload : StagedProofReloadInput
  transferState : TransferStateInput
  daSidecarReplay : DaSidecarReplaySurface
deriving DecidableEq, Repr

structure AcceptedRawIngressSidecarReplay
    (surface : RawIngressSidecarReplaySurface)
    (streamOutput : ActionStreamEffect.ActionStreamOutput)
    (wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields) : Prop where
  actionRequestAccepted :
    evaluateActionRequestProjectionRejection surface.actionRequest = none
  pendingReloadAccepted :
    evaluatePendingActionReloadRejection surface.pendingReload = none
  stagedCiphertextReloadAccepted :
    evaluateStagedCiphertextReloadRejection
      surface.stagedCiphertextReload = none
  stagedProofReloadAccepted :
    evaluateStagedProofReloadRejection surface.stagedProofReload = none
  transferStateAccepted :
    evaluateTransferState surface.transferState = Except.ok ()
  daSidecarReplayFacts :
    AcceptedDaSidecarReplayFacts
      surface.daSidecarReplay
      streamOutput
      wireOutput
      semanticFields

structure RawIngressLedgerTreePublicationFacts
    (surface : RawIngressSidecarReplaySurface)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (initial final : AcceptedChain.NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) : Prop where
  actionRequestOk :
    actionRequestProjectionPreconditions surface.actionRequest = true
  pendingReloadOk :
    pendingActionReloadPreconditions surface.pendingReload = true
  stagedCiphertextReloadOk :
    stagedCiphertextReloadPreconditions
      surface.stagedCiphertextReload = true
  stagedProofReloadOk :
    stagedProofReloadPreconditions surface.stagedProofReload = true
  sidecarCiphertextsAvailable :
    surface.transferState.sidecarCiphertextsAvailable = true
  sidecarCiphertextSizesPresent :
    surface.transferState.sidecarCiphertextSizesPresent = true
  sidecarCiphertextSizesMatch :
    surface.transferState.sidecarCiphertextSizesMatch = true
  candidateDaRootMatches :
    surface.daSidecarReplay.candidateBinding.daRootMatches = true
  candidateTxStatementsCommitmentMatches :
    surface.daSidecarReplay.candidateBinding.txStatementsCommitmentMatches =
      true
  candidateRecursiveStateRootMatches :
    surface.daSidecarReplay.candidateBinding.recursiveStateRootMatches =
      true
  provenBatchDaRootMatches :
    surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
  provenBatchHasChunks :
    surface.daSidecarReplay.provenBatchBinding.daChunkCount ≠ 0
  semanticDaRootBound :
    semanticFields.daRoot =
      surface.daSidecarReplay.recursiveSemanticSource.daRoot
  candidateTxCountNonzero :
    surface.daSidecarReplay.candidateArtifact.txCount ≠ 0
  candidateDaChunkCountNonzero :
    surface.daSidecarReplay.candidateArtifact.daChunkCount ≠ 0
  actionStreamOk :
    ActionStreamEffect.actionStreamPreconditions
      surface.daSidecarReplay.actionStream = true
  wireReplayProjectionOk :
    actionWireReplayProjectionPreconditions
      surface.daSidecarReplay.wireReplayProjection = true
  wireReplayPlannedCount :
    surface.daSidecarReplay.wireReplayProjection.actionCount =
      surface.daSidecarReplay.wireReplayProjection.plannedCount
  wireReplayActionCount :
    surface.daSidecarReplay.wireReplayProjection.actionCount =
      surface.daSidecarReplay.wireReplayProjection.actions.length
  ciphertextRequestWithinBound :
    ¬ surface.daSidecarReplay.ciphertextRequest.itemCount >
      surface.daSidecarReplay.ciphertextRequest.maxItems
  ciphertextCapacityOk :
    SidecarUploadAdmission.capacityPreconditions
      surface.daSidecarReplay.ciphertextCapacity = true
  proofRequestWithinBound :
    ¬ surface.daSidecarReplay.proofRequest.itemCount >
      surface.daSidecarReplay.proofRequest.maxItems
  proofCapacityOk :
    SidecarUploadAdmission.capacityPreconditions
      surface.daSidecarReplay.proofCapacity = true
  proofMetadataOk :
    SidecarUploadAdmission.proofMetadataPreconditions
      surface.daSidecarReplay.proofMetadata = true
  proofDecodedOk :
    SidecarUploadAdmission.proofDecodedPreconditions
      surface.daSidecarReplay.proofDecoded = true
  acceptedLedgerTreeReplay :
    AcceptedChain.validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  commitmentRootPublication :
    AcceptedChain.expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  acceptedLedgerReplay :
    AcceptedChain.validateNativeLedgerReplayChain
      initial.ledger
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger
  replayedSupply :
    AcceptedChain.expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  replayedLeafCursor :
    AcceptedChain.expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount
  canonicalCommitmentPlan :
    AcceptedChain.nativeLedgerReplayCommitmentPlanPreconditions
      initial.ledger
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) = true
  rawTreeCarriedState :
    rawProjectedTreeCarriedStatePreconditions initial blocks = true
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup

structure SidecarTransferStateMaterializedFacts
    (input : TransferStateInput) : Prop where
  anchorKnown : input.anchorKnown = true
  nullifierStateValid :
    input.nullifierState = TransferNullifierState.valid
  commitmentsNonzero : input.commitmentsNonzero = true
  sidecarCiphertextsAvailable :
    input.sidecarCiphertextsAvailable = true
  sidecarCiphertextSizesPresent :
    input.sidecarCiphertextSizesPresent = true
  sidecarCiphertextSizesMatch :
    input.sidecarCiphertextSizesMatch = true

structure RawIngressSidecarReplayPreconditionFacts
    (surface : RawIngressSidecarReplaySurface)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields) : Prop where
  actionRequestOk :
    actionRequestProjectionPreconditions surface.actionRequest = true
  pendingReloadOk :
    pendingActionReloadPreconditions surface.pendingReload = true
  stagedCiphertextReloadOk :
    stagedCiphertextReloadPreconditions
      surface.stagedCiphertextReload = true
  stagedProofReloadOk :
    stagedProofReloadPreconditions surface.stagedProofReload = true
  transferStateOk :
    transferStatePreconditions surface.transferState = true
  candidateDaRootMatches :
    surface.daSidecarReplay.candidateBinding.daRootMatches = true
  provenBatchDaRootMatches :
    surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
  provenBatchHasChunks :
    surface.daSidecarReplay.provenBatchBinding.daChunkCount ≠ 0
  semanticDaRootBound :
    semanticFields.daRoot =
      surface.daSidecarReplay.recursiveSemanticSource.daRoot
  wireReplayProjectionOk :
    actionWireReplayProjectionPreconditions
      surface.daSidecarReplay.wireReplayProjection = true
  wireReplayPlannedCount :
    surface.daSidecarReplay.wireReplayProjection.actionCount =
      surface.daSidecarReplay.wireReplayProjection.plannedCount
  wireReplayActionCount :
    surface.daSidecarReplay.wireReplayProjection.actionCount =
      surface.daSidecarReplay.wireReplayProjection.actions.length

theorem accepted_action_request_projection_implies_preconditions
    {input : ActionRequestProjectionInput}
    (accepted : evaluateActionRequestProjectionRejection input = none) :
    actionRequestProjectionPreconditions input = true := by
  have acceptsTrue :
      actionRequestProjectionAccepts input = true := by
    simp [actionRequestProjectionAccepts, accepted]
  exact
    (accepts_iff_action_request_projection_preconditions
      (input := input)).mp acceptsTrue

theorem accepted_pending_action_reload_implies_preconditions
    {input : PendingActionReloadInput}
    (accepted : evaluatePendingActionReloadRejection input = none) :
    pendingActionReloadPreconditions input = true := by
  have acceptsTrue : pendingActionReloadAccepts input = true := by
    simp [pendingActionReloadAccepts, accepted]
  exact
    (accepts_iff_pending_action_reload_preconditions
      (input := input)).mp acceptsTrue

theorem accepted_staged_ciphertext_reload_implies_preconditions
    {input : StagedCiphertextReloadInput}
    (accepted : evaluateStagedCiphertextReloadRejection input = none) :
    stagedCiphertextReloadPreconditions input = true := by
  have acceptsTrue : stagedCiphertextReloadAccepts input = true := by
    simp [stagedCiphertextReloadAccepts, accepted]
  exact
    (accepts_iff_staged_ciphertext_reload_preconditions
      (input := input)).mp acceptsTrue

theorem accepted_staged_proof_reload_implies_preconditions
    {input : StagedProofReloadInput}
    (accepted : evaluateStagedProofReloadRejection input = none) :
    stagedProofReloadPreconditions input = true := by
  have acceptsTrue : stagedProofReloadAccepts input = true := by
    simp [stagedProofReloadAccepts, accepted]
  exact
    (accepts_iff_staged_proof_reload_preconditions
      (input := input)).mp acceptsTrue

theorem accepted_transfer_state_implies_preconditions
    {input : TransferStateInput}
    (accepted : evaluateTransferState input = Except.ok ()) :
    transferStatePreconditions input = true := by
  have acceptsTrue : transferStateAccepts input = true := by
    simp [transferStateAccepts, accepted]
  have acceptsEq := accepts_iff_state_preconditions input
  rw [acceptsEq] at acceptsTrue
  exact acceptsTrue

theorem accepted_sidecar_transfer_state_materialized_facts
    {input : TransferStateInput}
    (accepted : evaluateTransferState input = Except.ok ())
    (sidecar : input.sidecarRoute = true) :
    SidecarTransferStateMaterializedFacts input := by
  cases input with
  | mk anchorKnown nullifierState commitmentsNonzero stablecoinPolicyAuthorized sidecarRoute
      sidecarCiphertextsAvailable sidecarCiphertextSizesPresent
      sidecarCiphertextSizesMatch =>
      cases anchorKnown <;> cases nullifierState <;>
        cases commitmentsNonzero <;> cases stablecoinPolicyAuthorized <;>
        cases sidecarRoute <;> cases sidecarCiphertextsAvailable <;>
        cases sidecarCiphertextSizesPresent <;>
        cases sidecarCiphertextSizesMatch <;>
        simp [evaluateTransferState] at accepted sidecar ⊢
      exact
        { anchorKnown := rfl
          nullifierStateValid := rfl
          commitmentsNonzero := rfl
          sidecarCiphertextsAvailable := rfl
          sidecarCiphertextSizesPresent := rfl
          sidecarCiphertextSizesMatch := rfl }

theorem accepted_sidecar_transfer_state_implies_sidecar_materialized
    {input : TransferStateInput}
    (accepted : evaluateTransferState input = Except.ok ())
    (sidecar : input.sidecarRoute = true) :
    input.anchorKnown = true
      ∧ input.nullifierState = TransferNullifierState.valid
      ∧ input.commitmentsNonzero = true
      ∧ input.sidecarCiphertextsAvailable = true
      ∧ input.sidecarCiphertextSizesPresent = true
      ∧ input.sidecarCiphertextSizesMatch = true := by
  have facts :
      SidecarTransferStateMaterializedFacts input :=
    accepted_sidecar_transfer_state_materialized_facts accepted sidecar
  exact
    ⟨facts.anchorKnown,
      facts.nullifierStateValid,
      facts.commitmentsNonzero,
      facts.sidecarCiphertextsAvailable,
      facts.sidecarCiphertextSizesPresent,
      facts.sidecarCiphertextSizesMatch⟩

theorem accepted_raw_ingress_sidecar_replay_exposes_named_preconditions
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    (facts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields) :
    RawIngressSidecarReplayPreconditionFacts
      surface
      semanticFields := by
  have requestPre :=
    accepted_action_request_projection_implies_preconditions
      facts.actionRequestAccepted
  have pendingPre :=
    accepted_pending_action_reload_implies_preconditions
      facts.pendingReloadAccepted
  have ciphertextPre :=
    accepted_staged_ciphertext_reload_implies_preconditions
      facts.stagedCiphertextReloadAccepted
  have proofPre :=
    accepted_staged_proof_reload_implies_preconditions
      facts.stagedProofReloadAccepted
  have transferPre :=
    accepted_transfer_state_implies_preconditions
      facts.transferStateAccepted
  have daFacts :=
    accepted_da_sidecar_replay_facts_expose_binding_preconditions
      facts.daSidecarReplayFacts
  rcases daFacts with
    ⟨candidateDaRoot,
      _candidateDaChunkCount,
      _candidateTxStatements,
      _candidateRecursiveState,
      provenDaRoot,
      provenChunks,
      _provenChunkCountMatches,
      semanticDaRoot,
      _candidateTxCount,
      _candidateDaChunkCount,
      _actionStreamPre,
      wirePre,
      wirePlanned,
      wireActions,
      _ciphertextRequestBound,
      _ciphertextCapacityPre,
      _proofRequestBound,
      _proofCapacityPre,
      _proofMetadataPre,
      _proofDecodedPre⟩
  exact
    { actionRequestOk := requestPre
      pendingReloadOk := pendingPre
      stagedCiphertextReloadOk := ciphertextPre
      stagedProofReloadOk := proofPre
      transferStateOk := transferPre
      candidateDaRootMatches := candidateDaRoot
      provenBatchDaRootMatches := provenDaRoot
      provenBatchHasChunks := provenChunks
      semanticDaRootBound := semanticDaRoot
      wireReplayProjectionOk := wirePre
      wireReplayPlannedCount := wirePlanned
      wireReplayActionCount := wireActions }

theorem accepted_raw_ingress_sidecar_replay_exposes_preconditions
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    (facts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields) :
    actionRequestProjectionPreconditions surface.actionRequest = true
      ∧ pendingActionReloadPreconditions surface.pendingReload = true
      ∧ stagedCiphertextReloadPreconditions
          surface.stagedCiphertextReload = true
      ∧ stagedProofReloadPreconditions surface.stagedProofReload = true
      ∧ transferStatePreconditions surface.transferState = true
      ∧ surface.daSidecarReplay.candidateBinding.daRootMatches = true
      ∧ surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
      ∧ surface.daSidecarReplay.provenBatchBinding.daChunkCount ≠ 0
      ∧ actionWireReplayProjectionPreconditions
          surface.daSidecarReplay.wireReplayProjection = true
      ∧ surface.daSidecarReplay.wireReplayProjection.actionCount =
          surface.daSidecarReplay.wireReplayProjection.plannedCount
      ∧ surface.daSidecarReplay.wireReplayProjection.actionCount =
          surface.daSidecarReplay.wireReplayProjection.actions.length := by
  have named :=
    accepted_raw_ingress_sidecar_replay_exposes_named_preconditions
      facts
  exact
    ⟨named.actionRequestOk,
      named.pendingReloadOk,
      named.stagedCiphertextReloadOk,
      named.stagedProofReloadOk,
      named.transferStateOk,
      named.candidateDaRootMatches,
      named.provenBatchDaRootMatches,
      named.provenBatchHasChunks,
      named.wireReplayProjectionOk,
      named.wireReplayPlannedCount,
      named.wireReplayActionCount⟩

theorem accepted_raw_ingress_projected_replay_binds_sidecar_rows
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {initial final : AcceptedChain.NativeLedgerReplayState}
    {projections : List NativeBlockReplayProjection}
    (facts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (initialNullifiersNodup : initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.consumedBridgeReplays.Nodup)
    (acceptedReplay :
      projectedLedgerStateAfter initial projections = some final) :
    actionRequestProjectionPreconditions surface.actionRequest = true
      ∧ pendingActionReloadPreconditions surface.pendingReload = true
      ∧ stagedCiphertextReloadPreconditions
          surface.stagedCiphertextReload = true
      ∧ stagedProofReloadPreconditions surface.stagedProofReload = true
      ∧ surface.transferState.sidecarCiphertextsAvailable = true
      ∧ surface.transferState.sidecarCiphertextSizesPresent = true
      ∧ surface.transferState.sidecarCiphertextSizesMatch = true
      ∧ surface.daSidecarReplay.candidateBinding.daRootMatches = true
      ∧ surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
      ∧ semanticFields.daRoot =
          surface.daSidecarReplay.recursiveSemanticSource.daRoot
      ∧ projectedCarriedStatePreconditions initial projections = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup := by
  have preconditions :=
    accepted_raw_ingress_sidecar_replay_exposes_named_preconditions facts
  have sidecarMaterialized :=
    accepted_sidecar_transfer_state_materialized_facts
      facts.transferStateAccepted
      sidecarRoute
  have replayFacts :=
    accepted_projected_replay_with_da_sidecar_facts
      facts.daSidecarReplayFacts
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedReplay
  rcases replayFacts with
    ⟨candidateDaRoot,
      provenDaRoot,
      semanticDaRoot,
      carriedState,
      spentNodup,
      bridgeNodup⟩
  exact
    ⟨preconditions.actionRequestOk,
      preconditions.pendingReloadOk,
      preconditions.stagedCiphertextReloadOk,
      preconditions.stagedProofReloadOk,
      sidecarMaterialized.sidecarCiphertextsAvailable,
      sidecarMaterialized.sidecarCiphertextSizesPresent,
      sidecarMaterialized.sidecarCiphertextSizesMatch,
      candidateDaRoot,
      provenDaRoot,
      semanticDaRoot,
      carriedState,
      spentNodup,
      bridgeNodup⟩

theorem accepted_raw_ingress_raw_projected_replay_binds_sidecar_rows
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {initial final : AcceptedChain.NativeLedgerReplayState}
    {blocks : List RawDecodedNativeReplayBlock}
    (facts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (initialNullifiersNodup : initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.consumedBridgeReplays.Nodup)
    (acceptedReplay :
      rawProjectedLedgerStateAfter initial blocks = some final) :
    actionRequestProjectionPreconditions surface.actionRequest = true
      ∧ pendingActionReloadPreconditions surface.pendingReload = true
      ∧ stagedCiphertextReloadPreconditions
          surface.stagedCiphertextReload = true
      ∧ stagedProofReloadPreconditions surface.stagedProofReload = true
      ∧ surface.transferState.sidecarCiphertextsAvailable = true
      ∧ surface.transferState.sidecarCiphertextSizesPresent = true
      ∧ surface.transferState.sidecarCiphertextSizesMatch = true
      ∧ surface.daSidecarReplay.candidateBinding.daRootMatches = true
      ∧ surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
      ∧ semanticFields.daRoot =
          surface.daSidecarReplay.recursiveSemanticSource.daRoot
      ∧ AcceptedChain.validateNativeLedgerReplayChain
          initial
          (rawReplayInputs blocks) =
          some final
      ∧ AcceptedChain.expectedNativeSupplyAfter
          initial.supply
          (rawReplayInputs blocks) =
          some final.supply
      ∧ AcceptedChain.expectedNativeLeafCountAfter
          initial.leafCount
          (rawReplayInputs blocks) =
          some final.leafCount
      ∧ AcceptedChain.nativeLedgerReplayCommitmentPlanPreconditions
          initial
          (rawReplayInputs blocks) = true
      ∧ rawProjectedCarriedStatePreconditions initial blocks = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup := by
  have preconditions :=
    accepted_raw_ingress_sidecar_replay_exposes_named_preconditions facts
  have sidecarMaterialized :=
    accepted_sidecar_transfer_state_materialized_facts
      facts.transferStateAccepted
      sidecarRoute
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
      carriedState,
      spentNodup,
      bridgeNodup⟩
  exact
    ⟨preconditions.actionRequestOk,
      preconditions.pendingReloadOk,
      preconditions.stagedCiphertextReloadOk,
      preconditions.stagedProofReloadOk,
      sidecarMaterialized.sidecarCiphertextsAvailable,
      sidecarMaterialized.sidecarCiphertextSizesPresent,
      sidecarMaterialized.sidecarCiphertextSizesMatch,
      preconditions.candidateDaRootMatches,
      preconditions.provenBatchDaRootMatches,
      preconditions.semanticDaRootBound,
      accepted,
      supply,
      leaf,
      commitmentPlan,
      carriedState,
      spentNodup,
      bridgeNodup⟩

theorem accepted_raw_ingress_raw_projected_tree_replay_binds_sidecar_publication
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {initial final : AcceptedChain.NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (facts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedReplay :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    actionRequestProjectionPreconditions surface.actionRequest = true
      ∧ pendingActionReloadPreconditions surface.pendingReload = true
      ∧ stagedCiphertextReloadPreconditions
          surface.stagedCiphertextReload = true
      ∧ stagedProofReloadPreconditions surface.stagedProofReload = true
      ∧ surface.transferState.sidecarCiphertextsAvailable = true
      ∧ surface.transferState.sidecarCiphertextSizesPresent = true
      ∧ surface.transferState.sidecarCiphertextSizesMatch = true
      ∧ surface.daSidecarReplay.candidateBinding.daRootMatches = true
      ∧ surface.daSidecarReplay.candidateBinding.txStatementsCommitmentMatches =
          true
      ∧ surface.daSidecarReplay.candidateBinding.recursiveStateRootMatches =
          true
      ∧ surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
      ∧ surface.daSidecarReplay.provenBatchBinding.daChunkCount ≠ 0
      ∧ semanticFields.daRoot =
          surface.daSidecarReplay.recursiveSemanticSource.daRoot
      ∧ surface.daSidecarReplay.candidateArtifact.txCount ≠ 0
      ∧ surface.daSidecarReplay.candidateArtifact.daChunkCount ≠ 0
      ∧ ActionStreamEffect.actionStreamPreconditions
          surface.daSidecarReplay.actionStream = true
      ∧ actionWireReplayProjectionPreconditions
          surface.daSidecarReplay.wireReplayProjection = true
      ∧ surface.daSidecarReplay.wireReplayProjection.actionCount =
          surface.daSidecarReplay.wireReplayProjection.plannedCount
      ∧ surface.daSidecarReplay.wireReplayProjection.actionCount =
          surface.daSidecarReplay.wireReplayProjection.actions.length
      ∧ ¬ surface.daSidecarReplay.ciphertextRequest.itemCount >
          surface.daSidecarReplay.ciphertextRequest.maxItems
      ∧ SidecarUploadAdmission.capacityPreconditions
          surface.daSidecarReplay.ciphertextCapacity = true
      ∧ ¬ surface.daSidecarReplay.proofRequest.itemCount >
          surface.daSidecarReplay.proofRequest.maxItems
      ∧ SidecarUploadAdmission.capacityPreconditions
          surface.daSidecarReplay.proofCapacity = true
      ∧ SidecarUploadAdmission.proofMetadataPreconditions
          surface.daSidecarReplay.proofMetadata = true
      ∧ SidecarUploadAdmission.proofDecodedPreconditions
          surface.daSidecarReplay.proofDecoded = true
      ∧ AcceptedChain.validateNativeLedgerTreeReplayChain
          initial
          (rawTreeReplayInputs blocks) =
          some final
      ∧ AcceptedChain.expectedCommitmentRootAfter
          initial.commitmentRoot
          (rawTreeReplayInputs blocks) =
          some final.commitmentRoot
      ∧ AcceptedChain.validateNativeLedgerReplayChain
          initial.ledger
          (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
          some final.ledger
      ∧ AcceptedChain.expectedNativeSupplyAfter
          initial.ledger.supply
          (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
          some final.ledger.supply
      ∧ AcceptedChain.expectedNativeLeafCountAfter
          initial.ledger.leafCount
          (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
          some final.ledger.leafCount
      ∧ AcceptedChain.nativeLedgerReplayCommitmentPlanPreconditions
          initial.ledger
          (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) = true
      ∧ rawProjectedTreeCarriedStatePreconditions initial blocks = true
      ∧ final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup := by
  have preconditions :=
    accepted_raw_ingress_sidecar_replay_exposes_named_preconditions facts
  have sidecarMaterialized :=
    accepted_sidecar_transfer_state_materialized_facts
      facts.transferStateAccepted
      sidecarRoute
  have daFacts :=
    accepted_da_sidecar_replay_facts_expose_binding_preconditions
      facts.daSidecarReplayFacts
  have replayFacts :=
    accepted_raw_projected_ledger_tree_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedReplay
  rcases daFacts with
    ⟨candidateDaRoot,
      _candidateDaChunkCountMatches,
      candidateTxStatements,
      candidateRecursiveState,
      provenDaRoot,
      provenChunks,
      _provenChunkCountMatches,
      semanticDaRoot,
      candidateTxCount,
      candidateDaChunkCount,
      actionStreamPre,
      wirePre,
      wirePlanned,
      wireActions,
      ciphertextRequestBound,
      ciphertextCapacityPre,
      proofRequestBound,
      proofCapacityPre,
      proofMetadataPre,
      proofDecodedPre⟩
  rcases replayFacts with
    ⟨treeAccepted,
      rootExpected,
      ledgerAccepted,
      supplyExpected,
      leafExpected,
      commitmentPlan,
      carriedState,
      spentNodup,
      bridgeNodup⟩
  exact
    ⟨preconditions.actionRequestOk,
      preconditions.pendingReloadOk,
      preconditions.stagedCiphertextReloadOk,
      preconditions.stagedProofReloadOk,
      sidecarMaterialized.sidecarCiphertextsAvailable,
      sidecarMaterialized.sidecarCiphertextSizesPresent,
      sidecarMaterialized.sidecarCiphertextSizesMatch,
      candidateDaRoot,
      candidateTxStatements,
      candidateRecursiveState,
      provenDaRoot,
      provenChunks,
      semanticDaRoot,
      candidateTxCount,
      candidateDaChunkCount,
      actionStreamPre,
      wirePre,
      wirePlanned,
      wireActions,
      ciphertextRequestBound,
      ciphertextCapacityPre,
      proofRequestBound,
      proofCapacityPre,
      proofMetadataPre,
      proofDecodedPre,
      treeAccepted,
      rootExpected,
      ledgerAccepted,
      supplyExpected,
      leafExpected,
      commitmentPlan,
      carriedState,
      spentNodup,
      bridgeNodup⟩

theorem raw_ingress_publication_equivalent_to_raw_ledger_tree_replay
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {initial final : AcceptedChain.NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (facts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedReplay :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressLedgerTreePublicationFacts
      surface
      semanticFields
      initial
      final
      blocks := by
  have publicationFacts :=
    accepted_raw_ingress_raw_projected_tree_replay_binds_sidecar_publication
      facts
      sidecarRoute
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedReplay
  rcases publicationFacts with
    ⟨actionRequestOk,
      pendingReloadOk,
      stagedCiphertextReloadOk,
      stagedProofReloadOk,
      sidecarCiphertextsAvailable,
      sidecarCiphertextSizesPresent,
      sidecarCiphertextSizesMatch,
      candidateDaRootMatches,
      candidateTxStatementsCommitmentMatches,
      candidateRecursiveStateRootMatches,
      provenBatchDaRootMatches,
      provenBatchHasChunks,
      semanticDaRootBound,
      candidateTxCountNonzero,
      candidateDaChunkCountNonzero,
      actionStreamOk,
      wireReplayProjectionOk,
      wireReplayPlannedCount,
      wireReplayActionCount,
      ciphertextRequestWithinBound,
      ciphertextCapacityOk,
      proofRequestWithinBound,
      proofCapacityOk,
      proofMetadataOk,
      proofDecodedOk,
      acceptedLedgerTreeReplay,
      commitmentRootPublication,
      acceptedLedgerReplay,
      replayedSupply,
      replayedLeafCursor,
      canonicalCommitmentPlan,
      rawTreeCarriedState,
      finalSpentNullifiersUnique,
      finalBridgeReplaysUnique⟩
  exact
    { actionRequestOk := actionRequestOk
      pendingReloadOk := pendingReloadOk
      stagedCiphertextReloadOk := stagedCiphertextReloadOk
      stagedProofReloadOk := stagedProofReloadOk
      sidecarCiphertextsAvailable := sidecarCiphertextsAvailable
      sidecarCiphertextSizesPresent := sidecarCiphertextSizesPresent
      sidecarCiphertextSizesMatch := sidecarCiphertextSizesMatch
      candidateDaRootMatches := candidateDaRootMatches
      candidateTxStatementsCommitmentMatches :=
        candidateTxStatementsCommitmentMatches
      candidateRecursiveStateRootMatches :=
        candidateRecursiveStateRootMatches
      provenBatchDaRootMatches := provenBatchDaRootMatches
      provenBatchHasChunks := provenBatchHasChunks
      semanticDaRootBound := semanticDaRootBound
      candidateTxCountNonzero := candidateTxCountNonzero
      candidateDaChunkCountNonzero := candidateDaChunkCountNonzero
      actionStreamOk := actionStreamOk
      wireReplayProjectionOk := wireReplayProjectionOk
      wireReplayPlannedCount := wireReplayPlannedCount
      wireReplayActionCount := wireReplayActionCount
      ciphertextRequestWithinBound := ciphertextRequestWithinBound
      ciphertextCapacityOk := ciphertextCapacityOk
      proofRequestWithinBound := proofRequestWithinBound
      proofCapacityOk := proofCapacityOk
      proofMetadataOk := proofMetadataOk
      proofDecodedOk := proofDecodedOk
      acceptedLedgerTreeReplay := acceptedLedgerTreeReplay
      commitmentRootPublication := commitmentRootPublication
      acceptedLedgerReplay := acceptedLedgerReplay
      replayedSupply := replayedSupply
      replayedLeafCursor := replayedLeafCursor
      canonicalCommitmentPlan := canonicalCommitmentPlan
      rawTreeCarriedState := rawTreeCarriedState
      finalSpentNullifiersUnique := finalSpentNullifiersUnique
      finalBridgeReplaysUnique := finalBridgeReplaysUnique }

end RawIngressSidecarReplayRecoverability
end Native
end Hegemon

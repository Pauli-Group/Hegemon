import Hegemon.Native.BlockActionValidation
import Hegemon.Native.PendingActionBytePublicationRefinement
import Hegemon.Native.RawIngressPendingActionPublicationRefinement

namespace Hegemon
namespace Native
namespace PendingActionByteReplayRowCountBinding

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionScopeAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.PendingActionBytePublicationRefinement
open Hegemon.Native.RawIngressPendingActionPublicationRefinement
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TransferStateAdmission

structure PendingActionByteDecodeReplayRowCountFacts
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (wireProjection : ActionWireReplayProjectionInput)
    (wireOutput : ActionWireReplayProjectionOutput) : Prop where
  pendingDecodePreconditions :
    exactDecodePreconditions pendingDecode = true
  pendingDecodeExact :
    pendingDecode.parserAccepts = true
      ∧ pendingDecode.consumedAllBytes = true
      ∧ pendingDecode.canonicalReencodeMatches = true
  blockActionDecodePreconditions :
    blockActionDecodePreconditions blockActionDecode = true
  blockActionDecodeExact :
    actionCountMatches blockActionDecode = true
      ∧ blockActionDecode.everyActionDecodesExactly = true
  blockActionDeclaredCount :
    blockActionDecode.declaredTxCount =
      blockActionDecode.actualActionPayloadCount
  acceptedWireProjection :
    evaluateActionWireReplayProjection wireProjection =
      Except.ok wireOutput
  wireProjectionPreconditions :
    actionWireReplayProjectionPreconditions wireProjection = true
  wireActionCountMatchesDeclared :
    wireProjection.actionCount = blockActionDecode.declaredTxCount
  wireProjectedActionCount :
    wireOutput.projectedActionCount = wireProjection.actionCount
  replayRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount

theorem accepted_pending_action_byte_decode_binds_replay_row_counts
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (wireProjectionAccepted :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (wireActionCountMatchesDeclared :
      wireProjection.actionCount =
        blockActionDecode.declaredTxCount) :
    PendingActionByteDecodeReplayRowCountFacts
      pendingDecode
      blockActionDecode
      wireProjection
      wireOutput := by
  have pendingDecodePreconditionsOk :
      exactDecodePreconditions pendingDecode = true :=
    (exact_accepts_iff_preconditions
      (input := pendingDecode)).mp pendingDecodeAccepted
  have pendingDecodeExactOk :
      pendingDecode.parserAccepts = true
        ∧ pendingDecode.consumedAllBytes = true
        ∧ pendingDecode.canonicalReencodeMatches = true :=
    exact_decode_acceptance_excludes_malleability
      pendingDecodeAccepted
  have blockActionDecodePreconditionsOk :
      blockActionDecodePreconditions blockActionDecode = true :=
    (block_action_decode_accepts_iff_preconditions
      (input := blockActionDecode)).mp blockActionDecodeAccepted
  have blockActionDecodeExactOk :
      actionCountMatches blockActionDecode = true
        ∧ blockActionDecode.everyActionDecodesExactly = true :=
    block_action_decode_acceptance_excludes_malleability
      blockActionDecodeAccepted
  have blockActionDeclaredCountOk :
      blockActionDecode.declaredTxCount =
        blockActionDecode.actualActionPayloadCount :=
    block_action_decode_acceptance_binds_declared_count
      blockActionDecodeAccepted
  have wireProjectionAccepts :
      actionWireReplayProjectionAccepts wireProjection = true := by
    simp [actionWireReplayProjectionAccepts, wireProjectionAccepted]
  have wireProjectionPreconditionsOk :
      actionWireReplayProjectionPreconditions wireProjection = true := by
    simpa [wireProjectionAccepts] using
      (accepts_iff_wire_replay_projection_preconditions wireProjection)
  have wireProjectedActionCountOk :
      wireOutput.projectedActionCount = wireProjection.actionCount :=
    accepted_wire_replay_projection_projected_action_count
      wireProjectionAccepted
  have replayRowsMatchDecodedPayloadsOk :
      wireOutput.projectedActionCount =
        blockActionDecode.actualActionPayloadCount := by
    calc
      wireOutput.projectedActionCount = wireProjection.actionCount :=
        wireProjectedActionCountOk
      _ = blockActionDecode.declaredTxCount :=
        wireActionCountMatchesDeclared
      _ = blockActionDecode.actualActionPayloadCount :=
        blockActionDeclaredCountOk
  exact
    {
      pendingDecodePreconditions := pendingDecodePreconditionsOk,
      pendingDecodeExact := pendingDecodeExactOk,
      blockActionDecodePreconditions := blockActionDecodePreconditionsOk,
      blockActionDecodeExact := blockActionDecodeExactOk,
      blockActionDeclaredCount := blockActionDeclaredCountOk,
      acceptedWireProjection := wireProjectionAccepted,
      wireProjectionPreconditions := wireProjectionPreconditionsOk,
      wireActionCountMatchesDeclared := wireActionCountMatchesDeclared,
      wireProjectedActionCount := wireProjectedActionCountOk,
      replayRowsMatchDecodedPayloads :=
        replayRowsMatchDecodedPayloadsOk
    }

theorem pending_action_byte_publication_facts_bind_replay_row_counts
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReload.PendingActionReloadInput}
    {actionHash : AdmissionInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (facts :
      PendingActionBytePublicationFacts
        pendingDecode
        blockActionDecode
        pendingReload
        actionHash
        wireProjection
        wireOutput
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        blocks) :
    PendingActionByteDecodeReplayRowCountFacts
      pendingDecode
      blockActionDecode
      wireProjection
      wireOutput :=
  {
    pendingDecodePreconditions := facts.pendingDecodePreconditions,
    pendingDecodeExact := facts.pendingDecodeExact,
    blockActionDecodePreconditions := facts.blockActionDecodePreconditions,
    blockActionDecodeExact := facts.blockActionDecodeExact,
    blockActionDeclaredCount :=
      facts.parserWireReplayFacts.blockActionDeclaredCount,
    acceptedWireProjection := facts.acceptedWireProjection,
    wireProjectionPreconditions := facts.wireProjectionPreconditions,
    wireActionCountMatchesDeclared :=
      facts.parserWireReplayFacts.wireActionCountMatchesDeclared,
    wireProjectedActionCount :=
      facts.parserWireReplayFacts.wireProjectedActionCount,
    replayRowsMatchDecodedPayloads :=
      facts.projectedActionRowsMatchDecodedPayloads
  }

theorem accepted_actions_from_validated_count
    {consumed : List Nat}
    {previous : Option Nat}
    {actions : List ValidationAction}
    {validated imported : Nat}
    {summary : BlockActionValidationSummary}
    (accepted :
      evaluateActionsFrom
          consumed
          previous
          actions
          validated
          imported =
        Except.ok summary) :
    summary.validatedActionCount = validated + actions.length := by
  induction actions generalizing consumed previous validated imported with
  | nil =>
      simp [evaluateActionsFrom] at accepted
      cases accepted
      rfl
  | cons action rest ih =>
      unfold evaluateActionsFrom at accepted
      cases hScope : evaluateScopeAdmission action.scope with
      | error rejection =>
          simp [hScope] at accepted
      | ok route =>
          cases hPayload : action.payloadValid
          · simp [hScope, hPayload] at accepted
          ·
              cases route
              ·
                  cases hImport :
                      importValidationBridgeReplay
                        consumed
                        action.bridgeReplayKey with
                  | error rejection =>
                      simp [hScope, hPayload, hImport] at accepted
                  | ok importedPair =>
                      rcases importedPair with ⟨nextConsumed, importedRows⟩
                      simp [hScope, hPayload, hImport] at accepted
                      have restCount := ih accepted
                      simp at restCount ⊢
                      omega
              ·
                  simp [hScope, hPayload] at accepted
                  have restCount := ih accepted
                  simp at restCount ⊢
                  omega
              ·
                  simp [hScope, hPayload] at accepted
                  have restCount := ih accepted
                  simp at restCount ⊢
                  omega
              ·
                  by_cases hOrder :
                      transferOrderExtends
                          previous
                          action.transferKey =
                        false
                  · simp [hScope, hPayload, hOrder] at accepted
                  ·
                      cases hTransfer :
                          TransferStateAdmission.evaluateTransferState
                            action.transferState with
                      | error rejection =>
                          simp [
                            hScope,
                            hPayload,
                            hOrder,
                            hTransfer
                          ] at accepted
                      | ok _ =>
                          simp [
                            hScope,
                            hPayload,
                            hOrder,
                            hTransfer
                          ] at accepted
                          have restCount := ih accepted
                          simp at restCount ⊢
                          omega

theorem accepted_block_action_validation_validated_count
    {validation : BlockActionValidationInput}
    {summary : BlockActionValidationSummary}
    (accepted :
      evaluateBlockActionValidation validation =
        Except.ok summary) :
    summary.validatedActionCount = validation.actions.length := by
  unfold evaluateBlockActionValidation at accepted
  cases hHash : ActionHashAdmission.evaluateAdmissionRejection
      (hashInput validation) with
  | none =>
      simp [hHash] at accepted
      have count :=
        accepted_actions_from_validated_count
          (consumed := validation.consumedBridgeReplays)
          (previous := none)
          (actions := validation.actions)
          (validated := 0)
          (imported := 0)
          accepted
      simpa using count
  | some rejection =>
      simp [hHash] at accepted

structure PendingActionByteDecodeValidatedReplayRowCountFacts
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (wireProjection : ActionWireReplayProjectionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (validation : BlockActionValidationInput)
    (validationSummary : BlockActionValidationSummary) : Prop where
  decodeReplayRowCountFacts :
    PendingActionByteDecodeReplayRowCountFacts
      pendingDecode
      blockActionDecode
      wireProjection
      wireOutput
  blockActionValidationAccepted :
    evaluateBlockActionValidation validation =
      Except.ok validationSummary
  blockActionValidationPreconditions :
    blockActionValidationPreconditions validation = true
  validationCountMatchesActions :
    validationSummary.validatedActionCount = validation.actions.length
  validationActionsMatchDecodedPayloads :
    validation.actions.length = blockActionDecode.actualActionPayloadCount
  replayRowsMatchValidatedActions :
    wireOutput.projectedActionCount =
      validationSummary.validatedActionCount

theorem accepted_pending_action_byte_decode_binds_validated_replay_row_counts
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (wireProjectionAccepted :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (wireActionCountMatchesDeclared :
      wireProjection.actionCount =
        blockActionDecode.declaredTxCount)
    (blockActionValidationAccepted :
      evaluateBlockActionValidation validation =
        Except.ok validationSummary)
    (validationActionsMatchDecodedPayloads :
      validation.actions.length =
        blockActionDecode.actualActionPayloadCount) :
    PendingActionByteDecodeValidatedReplayRowCountFacts
      pendingDecode
      blockActionDecode
      wireProjection
      wireOutput
      validation
      validationSummary := by
  have decodeFacts :=
    accepted_pending_action_byte_decode_binds_replay_row_counts
      pendingDecodeAccepted
      blockActionDecodeAccepted
      wireProjectionAccepted
      wireActionCountMatchesDeclared
  have validationAccepts :
      blockActionValidationAccepts validation = true := by
    simp [
      blockActionValidationAccepts,
      blockActionValidationAccepted
    ]
  have validationPreconditions :
      blockActionValidationPreconditions validation = true := by
    simpa [
      accepts_iff_block_action_validation_preconditions validation
    ] using validationAccepts
  have validationCountMatchesActions :
      validationSummary.validatedActionCount =
        validation.actions.length :=
    accepted_block_action_validation_validated_count
      blockActionValidationAccepted
  have replayRowsMatchValidatedActions :
      wireOutput.projectedActionCount =
        validationSummary.validatedActionCount := by
    calc
      wireOutput.projectedActionCount =
          blockActionDecode.actualActionPayloadCount :=
        decodeFacts.replayRowsMatchDecodedPayloads
      _ = validation.actions.length :=
        validationActionsMatchDecodedPayloads.symm
      _ = validationSummary.validatedActionCount :=
        validationCountMatchesActions.symm
  exact
    {
      decodeReplayRowCountFacts := decodeFacts,
      blockActionValidationAccepted := blockActionValidationAccepted,
      blockActionValidationPreconditions := validationPreconditions,
      validationCountMatchesActions := validationCountMatchesActions,
      validationActionsMatchDecodedPayloads :=
        validationActionsMatchDecodedPayloads,
      replayRowsMatchValidatedActions :=
        replayRowsMatchValidatedActions
    }

structure RawIngressPendingActionReplayRowCountFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) : Prop where
  publicationFacts :
    RawIngressPendingActionPublicationFacts
      surface
      pendingDecode
      blockActionDecode
      actionHash
      wireOutput
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
  decodeReplayRowCountFacts :
    PendingActionByteDecodeReplayRowCountFacts
      pendingDecode
      blockActionDecode
      surface.daSidecarReplay.wireReplayProjection
      wireOutput
  rawIngressRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
  publicationRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount

theorem raw_ingress_pending_action_publication_binds_replay_row_counts
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (publicationFacts :
      RawIngressPendingActionPublicationFacts
        surface
        pendingDecode
        blockActionDecode
        actionHash
        wireOutput
        semanticFields
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        blocks) :
    RawIngressPendingActionReplayRowCountFacts
      surface
      pendingDecode
      blockActionDecode
      actionHash
      wireOutput
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks := by
  have decodeFacts :=
    pending_action_byte_publication_facts_bind_replay_row_counts
      publicationFacts.pendingActionBytePublicationFacts
  exact
    {
      publicationFacts := publicationFacts,
      decodeReplayRowCountFacts := decodeFacts,
      rawIngressRowsMatchDecodedPayloads :=
        decodeFacts.replayRowsMatchDecodedPayloads,
      publicationRowsMatchDecodedPayloads :=
        publicationFacts.pendingActionRowsMatchDecodedPayloads
    }

structure RawIngressPendingActionValidatedReplayRowCountFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (validation : BlockActionValidationInput)
    (validationSummary : BlockActionValidationSummary) : Prop where
  rawIngressReplayRowCountFacts :
    RawIngressPendingActionReplayRowCountFacts
      surface
      pendingDecode
      blockActionDecode
      actionHash
      wireOutput
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
  blockActionValidationAccepted :
    evaluateBlockActionValidation validation =
      Except.ok validationSummary
  blockActionValidationPreconditions :
    blockActionValidationPreconditions validation = true
  validationCountMatchesActions :
    validationSummary.validatedActionCount = validation.actions.length
  validationActionsMatchDecodedPayloads :
    validation.actions.length = blockActionDecode.actualActionPayloadCount
  replayRowsMatchValidatedActions :
    wireOutput.projectedActionCount =
      validationSummary.validatedActionCount

theorem raw_ingress_pending_action_publication_binds_validated_replay_row_counts
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    (publicationFacts :
      RawIngressPendingActionPublicationFacts
        surface
        pendingDecode
        blockActionDecode
        actionHash
        wireOutput
        semanticFields
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        blocks)
    (blockActionValidationAccepted :
      evaluateBlockActionValidation validation =
        Except.ok validationSummary)
    (validationActionsMatchDecodedPayloads :
      validation.actions.length =
        blockActionDecode.actualActionPayloadCount) :
    RawIngressPendingActionValidatedReplayRowCountFacts
      surface
      pendingDecode
      blockActionDecode
      actionHash
      wireOutput
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
      validation
      validationSummary := by
  have rawFacts :=
    raw_ingress_pending_action_publication_binds_replay_row_counts
      publicationFacts
  have validationAccepts :
      blockActionValidationAccepts validation = true := by
    simp [
      blockActionValidationAccepts,
      blockActionValidationAccepted
    ]
  have validationPreconditions :
      blockActionValidationPreconditions validation = true := by
    simpa [
      accepts_iff_block_action_validation_preconditions validation
    ] using validationAccepts
  have validationCountMatchesActions :
      validationSummary.validatedActionCount =
        validation.actions.length :=
    accepted_block_action_validation_validated_count
      blockActionValidationAccepted
  have replayRowsMatchValidatedActions :
      wireOutput.projectedActionCount =
        validationSummary.validatedActionCount := by
    calc
      wireOutput.projectedActionCount =
          blockActionDecode.actualActionPayloadCount :=
        rawFacts.rawIngressRowsMatchDecodedPayloads
      _ = validation.actions.length :=
        validationActionsMatchDecodedPayloads.symm
      _ = validationSummary.validatedActionCount :=
        validationCountMatchesActions.symm
  exact
    {
      rawIngressReplayRowCountFacts := rawFacts,
      blockActionValidationAccepted := blockActionValidationAccepted,
      blockActionValidationPreconditions := validationPreconditions,
      validationCountMatchesActions := validationCountMatchesActions,
      validationActionsMatchDecodedPayloads :=
        validationActionsMatchDecodedPayloads,
      replayRowsMatchValidatedActions :=
        replayRowsMatchValidatedActions
    }

end PendingActionByteReplayRowCountBinding
end Native
end Hegemon

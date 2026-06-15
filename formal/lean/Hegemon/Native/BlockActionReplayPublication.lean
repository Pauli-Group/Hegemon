import Hegemon.Native.ActionWireReplayProjectionAdmission
import Hegemon.Native.BlockActionValidation
import Hegemon.Native.BlockReplayRefinement

namespace Hegemon
namespace Native
namespace BlockActionReplayPublication

open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionScopeAdmission
open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockCommitmentAdmission
open Hegemon.Native.BlockReplayRefinement
open Hegemon.Native.TransferStateAdmission

structure AcceptedBlockActionReplayPublicationFacts
    (validation : BlockActionValidationInput)
    (replay : BlockReplayInput)
    (validationSummary : BlockActionValidationSummary)
    (replaySummary : BlockReplaySummary) : Prop where
  blockActionValidationAccepted :
    evaluateBlockActionValidation validation =
      Except.ok validationSummary
  blockReplayAccepted :
    evaluateBlockReplayRefinement replay =
      Except.ok replaySummary
  actionHashPreconditions :
    admissionPreconditions (hashInput validation) = true
  allDecodedActionsValidated :
    validationSummary.validatedActionCount =
      validation.actions.length
  validationRowsMatchReplayRows :
    validationSummary.validatedActionCount =
      replay.actions.length
  importedBridgeReplayCountsMatch :
    validationSummary.importedBridgeReplayCount =
      replaySummary.importedBridgeReplayCount
  replayTraceCanonical :
    (evaluateBlockReplayRefinementWithTrace replay).1 =
      ["action_stream_effect", "expected_supply",
        "block_commitment", "accepted"]
  replayActionStreamAccepted :
    evaluateActionStreamEffect (streamInput replay) =
      Except.ok
        { nextLeafCount := replaySummary.nextLeafCount,
          importedNullifierCount :=
            replaySummary.importedNullifierCount,
          importedBridgeReplayCount :=
            replaySummary.importedBridgeReplayCount,
          plannedStarts := replaySummary.plannedStarts }
  replayCommitmentPreconditions :
    commitmentPreconditions (commitmentInput replay) = true
  replayExpectedSupply :
    expectedSupply replay = some replaySummary.expectedSupply
  replayClaimedSupplyMatches :
    replaySummary.expectedSupply = replay.claimedSupply
  replayStateRootMatches :
    replay.stateRootMatches = true

theorem accepted_actions_from_counts_rows
    {consumed : List Nat}
    {previousTransfer : Option Nat}
    {actions : List ValidationAction}
    {validated importedReplays : Nat}
    {summary : BlockActionValidationSummary}
    (accepted :
      evaluateActionsFrom
        consumed
        previousTransfer
        actions
        validated
        importedReplays =
        Except.ok summary) :
    summary.validatedActionCount =
      validated + actions.length := by
  induction actions generalizing
      consumed previousTransfer validated importedReplays with
  | nil =>
      simp [evaluateActionsFrom] at accepted
      cases accepted
      rfl
  | cons action rest ih =>
      unfold evaluateActionsFrom at accepted
      cases scopeResult : evaluateScopeAdmission action.scope with
      | error rejection =>
          simp [scopeResult] at accepted
      | ok route =>
          cases payloadValid : action.payloadValid with
          | false =>
              simp [scopeResult, payloadValid] at accepted
          | true =>
              simp [scopeResult, payloadValid] at accepted
              cases route with
              | bridge =>
                  cases replayImport :
                      importValidationBridgeReplay
                        consumed
                        action.bridgeReplayKey with
                  | error rejection =>
                      simp [replayImport] at accepted
                  | ok imported =>
                      cases imported with
                      | mk nextConsumed imported =>
                          have acceptedRest :
                              evaluateActionsFrom
                                nextConsumed
                                previousTransfer
                                rest
                                (validated + 1)
                                (importedReplays + imported) =
                                Except.ok summary := by
                            simpa [replayImport] using accepted
                          have restCount :=
                            ih
                              (consumed := nextConsumed)
                              (previousTransfer := previousTransfer)
                              (validated := validated + 1)
                              (importedReplays :=
                                importedReplays + imported)
                              acceptedRest
                          simpa [
                            Nat.add_assoc,
                            Nat.add_comm,
                            Nat.add_left_comm
                          ] using restCount
              | candidateArtifact =>
                  have restCount :=
                    ih
                      (consumed := consumed)
                      (previousTransfer := previousTransfer)
                      (validated := validated + 1)
                      (importedReplays := importedReplays)
                      accepted
                  simpa [
                    Nat.add_assoc,
                    Nat.add_comm,
                    Nat.add_left_comm
                  ] using restCount
              | coinbase =>
                  have restCount :=
                    ih
                      (consumed := consumed)
                      (previousTransfer := previousTransfer)
                      (validated := validated + 1)
                      (importedReplays := importedReplays)
                      accepted
                  simpa [
                    Nat.add_assoc,
                    Nat.add_comm,
                    Nat.add_left_comm
                  ] using restCount
              | transfer =>
                  cases orderOk :
                      transferOrderExtends
                        previousTransfer
                        action.transferKey with
                  | false =>
                      simp [orderOk] at accepted
                  | true =>
                      simp [orderOk] at accepted
                      cases transferResult :
                          evaluateTransferState action.transferState with
                      | error rejection =>
                          simp [transferResult] at accepted
                      | ok transferSummary =>
                          have acceptedRest :
                              evaluateActionsFrom
                                consumed
                                (some action.transferKey)
                                rest
                                (validated + 1)
                                importedReplays =
                                Except.ok summary := by
                            simpa [transferResult] using accepted
                          have restCount :=
                            ih
                              (consumed := consumed)
                              (previousTransfer :=
                                some action.transferKey)
                              (validated := validated + 1)
                              (importedReplays := importedReplays)
                              acceptedRest
                          simpa [
                            Nat.add_assoc,
                            Nat.add_comm,
                            Nat.add_left_comm
                          ] using restCount

theorem accepted_block_action_validation_hash_preconditions
    {validation : BlockActionValidationInput}
    {summary : BlockActionValidationSummary}
    (accepted :
      evaluateBlockActionValidation validation =
        Except.ok summary) :
    admissionPreconditions (hashInput validation) = true := by
  unfold evaluateBlockActionValidation at accepted
  cases hashReject :
      evaluateAdmissionRejection (hashInput validation) with
  | some rejection =>
      simp [hashReject] at accepted
  | none =>
      have hashAccepts :
          admissionAccepts (hashInput validation) = true := by
        simp [admissionAccepts, hashReject]
      exact
        (accepts_iff_admission_preconditions
          (input := hashInput validation)).mp hashAccepts

theorem accepted_block_action_validation_counts_all_rows
    {validation : BlockActionValidationInput}
    {summary : BlockActionValidationSummary}
    (accepted :
      evaluateBlockActionValidation validation =
        Except.ok summary) :
    summary.validatedActionCount =
      validation.actions.length := by
  unfold evaluateBlockActionValidation at accepted
  cases hashReject :
      evaluateAdmissionRejection (hashInput validation) with
  | some rejection =>
      simp [hashReject] at accepted
  | none =>
      have acceptedActions :
          evaluateActionsFrom
            validation.consumedBridgeReplays
            none
            validation.actions
            0
            0 =
            Except.ok summary := by
        simpa [hashReject] using accepted
      have counts :=
        accepted_actions_from_counts_rows
          (consumed := validation.consumedBridgeReplays)
          (previousTransfer := none)
          (actions := validation.actions)
          (validated := 0)
          (importedReplays := 0)
          acceptedActions
      simpa using counts

theorem accepted_block_action_validation_and_replay_publish_consensus_facts
    {validation : BlockActionValidationInput}
    {replay : BlockReplayInput}
    {validationSummary : BlockActionValidationSummary}
    {replaySummary : BlockReplaySummary}
    (acceptedValidation :
      evaluateBlockActionValidation validation =
        Except.ok validationSummary)
    (acceptedReplay :
      evaluateBlockReplayRefinement replay =
        Except.ok replaySummary)
    (validationRowsMatchReplayRows :
      validationSummary.validatedActionCount =
        replay.actions.length)
    (importedBridgeReplayCountsMatch :
      validationSummary.importedBridgeReplayCount =
        replaySummary.importedBridgeReplayCount) :
    AcceptedBlockActionReplayPublicationFacts
      validation
      replay
      validationSummary
      replaySummary := by
  have tracedAccepted :
      (evaluateBlockReplayRefinementWithTrace replay).2 =
        Except.ok replaySummary := by
    rw [traced_result_matches_untraced]
    exact acceptedReplay
  have supplyFacts := accepted_claims_expected_supply acceptedReplay
  exact
    {
      blockActionValidationAccepted := acceptedValidation,
      blockReplayAccepted := acceptedReplay,
      actionHashPreconditions :=
        accepted_block_action_validation_hash_preconditions
          acceptedValidation,
      allDecodedActionsValidated :=
        accepted_block_action_validation_counts_all_rows
          acceptedValidation,
      validationRowsMatchReplayRows :=
        validationRowsMatchReplayRows,
      importedBridgeReplayCountsMatch :=
        importedBridgeReplayCountsMatch,
      replayTraceCanonical :=
        accepted_trace_is_canonical tracedAccepted,
      replayActionStreamAccepted :=
        accepted_has_action_stream_effect acceptedReplay,
      replayCommitmentPreconditions :=
        accepted_implies_commitment_preconditions acceptedReplay,
      replayExpectedSupply := supplyFacts.left,
      replayClaimedSupplyMatches := supplyFacts.right,
      replayStateRootMatches :=
        accepted_forbids_counterfeit_state_root acceptedReplay
    }

theorem accepted_block_action_validation_derives_replay_row_count
    {validation : BlockActionValidationInput}
    {replay : BlockReplayInput}
    {validationSummary : BlockActionValidationSummary}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    (acceptedValidation :
      evaluateBlockActionValidation validation =
        Except.ok validationSummary)
    (acceptedWireProjection :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (wireActionCountMatchesValidation :
      wireProjection.actionCount =
        validation.actions.length)
    (wireProjectedActionCountMatchesReplay :
      wireOutput.projectedActionCount =
        replay.actions.length) :
    validationSummary.validatedActionCount =
      replay.actions.length := by
  have validationConsumesRows :=
    accepted_block_action_validation_counts_all_rows
      acceptedValidation
  have wireProjectedRows :=
    accepted_wire_replay_projection_projected_action_count
      acceptedWireProjection
  calc
    validationSummary.validatedActionCount =
        validation.actions.length :=
      validationConsumesRows
    _ = wireProjection.actionCount :=
      Eq.symm wireActionCountMatchesValidation
    _ = wireOutput.projectedActionCount :=
      Eq.symm wireProjectedRows
    _ = replay.actions.length :=
      wireProjectedActionCountMatchesReplay

theorem accepted_block_action_validation_derives_bridge_replay_count
    {validationSummary : BlockActionValidationSummary}
    {replaySummary : BlockReplaySummary}
    {wireOutput : ActionWireReplayProjectionOutput}
    (validationBridgeRowsMatchWire :
      validationSummary.importedBridgeReplayCount =
        wireOutput.projectedBridgeReplayRowCount)
    (replayBridgeRowsMatchWire :
      replaySummary.importedBridgeReplayCount =
        wireOutput.projectedBridgeReplayRowCount) :
    validationSummary.importedBridgeReplayCount =
      replaySummary.importedBridgeReplayCount := by
  calc
    validationSummary.importedBridgeReplayCount =
        wireOutput.projectedBridgeReplayRowCount :=
      validationBridgeRowsMatchWire
    _ = replaySummary.importedBridgeReplayCount :=
      Eq.symm replayBridgeRowsMatchWire

theorem accepted_block_action_validation_and_replay_publish_consensus_facts_from_shared_actions
    {validation : BlockActionValidationInput}
    {replay : BlockReplayInput}
    {validationSummary : BlockActionValidationSummary}
    {replaySummary : BlockReplaySummary}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    (acceptedValidation :
      evaluateBlockActionValidation validation =
        Except.ok validationSummary)
    (acceptedReplay :
      evaluateBlockReplayRefinement replay =
        Except.ok replaySummary)
    (acceptedWireProjection :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (wireActionCountMatchesValidation :
      wireProjection.actionCount =
        validation.actions.length)
    (wireProjectedActionCountMatchesReplay :
      wireOutput.projectedActionCount =
        replay.actions.length)
    (validationBridgeRowsMatchWire :
      validationSummary.importedBridgeReplayCount =
        wireOutput.projectedBridgeReplayRowCount)
    (replayBridgeRowsMatchWire :
      replaySummary.importedBridgeReplayCount =
        wireOutput.projectedBridgeReplayRowCount) :
    AcceptedBlockActionReplayPublicationFacts
      validation
      replay
      validationSummary
      replaySummary := by
  have rowCountAgreement :=
    accepted_block_action_validation_derives_replay_row_count
      acceptedValidation
      acceptedWireProjection
      wireActionCountMatchesValidation
      wireProjectedActionCountMatchesReplay
  have bridgeReplayCountAgreement :=
    accepted_block_action_validation_derives_bridge_replay_count
      validationBridgeRowsMatchWire
      replayBridgeRowsMatchWire
  exact
    accepted_block_action_validation_and_replay_publish_consensus_facts
      acceptedValidation
      acceptedReplay
      rowCountAgreement
      bridgeReplayCountAgreement

end BlockActionReplayPublication
end Native
end Hegemon

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

structure BlockActionReplayPublicationInput where
  validation : BlockActionValidationInput
  replay : BlockReplayInput
  wireProjection : ActionWireReplayProjectionInput
deriving DecidableEq, Repr

inductive BlockActionReplayPublicationReject where
  | validationRejected
  | replayRejected
  | wireProjectionRejected
  | validationWireActionCountMismatch
  | wireReplayActionCountMismatch
  | validationBridgeReplayCountMismatch
  | replayBridgeReplayCountMismatch
deriving DecidableEq, Repr

def evaluateBlockActionReplayPublicationRejection
    (input : BlockActionReplayPublicationInput) :
    Option BlockActionReplayPublicationReject :=
  match evaluateBlockActionValidation input.validation with
  | Except.error _ =>
      some BlockActionReplayPublicationReject.validationRejected
  | Except.ok validationSummary =>
      match evaluateBlockReplayRefinement input.replay with
      | Except.error _ =>
          some BlockActionReplayPublicationReject.replayRejected
      | Except.ok replaySummary =>
          match evaluateActionWireReplayProjection input.wireProjection with
          | Except.error _ =>
              some BlockActionReplayPublicationReject.wireProjectionRejected
          | Except.ok wireOutput =>
              if input.wireProjection.actionCount =
                  input.validation.actions.length then
                if wireOutput.projectedActionCount =
                    input.replay.actions.length then
                  if validationSummary.importedBridgeReplayCount =
                      wireOutput.projectedBridgeReplayRowCount then
                    if replaySummary.importedBridgeReplayCount =
                        wireOutput.projectedBridgeReplayRowCount then
                      none
                    else
                      some
                        BlockActionReplayPublicationReject.replayBridgeReplayCountMismatch
                  else
                    some
                      BlockActionReplayPublicationReject.validationBridgeReplayCountMismatch
                else
                  some
                    BlockActionReplayPublicationReject.wireReplayActionCountMismatch
              else
                some
                  BlockActionReplayPublicationReject.validationWireActionCountMismatch

def blockActionReplayPublicationAccepts
    (input : BlockActionReplayPublicationInput) : Bool :=
  evaluateBlockActionReplayPublicationRejection input = none

structure BlockActionReplayPublicationGateFacts
    (input : BlockActionReplayPublicationInput) : Prop where
  validationAccepted :
    blockActionValidationAccepts input.validation = true
  replayAccepted :
    blockReplayAccepts input.replay = true
  wireProjectionAccepted :
    actionWireReplayProjectionAccepts input.wireProjection = true
  wireActionCountMatchesValidation :
    input.wireProjection.actionCount =
      input.validation.actions.length
  wireProjectedActionCountMatchesReplay :
    ∀ {wireOutput : ActionWireReplayProjectionOutput},
      evaluateActionWireReplayProjection input.wireProjection =
        Except.ok wireOutput ->
      wireOutput.projectedActionCount =
        input.replay.actions.length
  validationBridgeRowsMatchWire :
    ∀ {validationSummary : BlockActionValidationSummary}
      {wireOutput : ActionWireReplayProjectionOutput},
      evaluateBlockActionValidation input.validation =
        Except.ok validationSummary ->
      evaluateActionWireReplayProjection input.wireProjection =
        Except.ok wireOutput ->
      validationSummary.importedBridgeReplayCount =
        wireOutput.projectedBridgeReplayRowCount
  replayBridgeRowsMatchWire :
    ∀ {replaySummary : BlockReplaySummary}
      {wireOutput : ActionWireReplayProjectionOutput},
      evaluateBlockReplayRefinement input.replay =
        Except.ok replaySummary ->
      evaluateActionWireReplayProjection input.wireProjection =
        Except.ok wireOutput ->
      replaySummary.importedBridgeReplayCount =
        wireOutput.projectedBridgeReplayRowCount

theorem accepted_block_action_replay_publication_gate_facts
    {input : BlockActionReplayPublicationInput}
    (accepted :
      evaluateBlockActionReplayPublicationRejection input = none) :
    BlockActionReplayPublicationGateFacts input := by
  unfold evaluateBlockActionReplayPublicationRejection at accepted
  cases hValidation :
      evaluateBlockActionValidation input.validation with
  | error rejection =>
      simp [hValidation] at accepted
  | ok validationSummary =>
      cases hReplay :
          evaluateBlockReplayRefinement input.replay with
      | error rejection =>
          simp [hValidation, hReplay] at accepted
      | ok replaySummary =>
          cases hWire :
              evaluateActionWireReplayProjection input.wireProjection with
          | error rejection =>
              simp [hValidation, hReplay, hWire] at accepted
          | ok wireOutput =>
              by_cases hWireValidation :
                  input.wireProjection.actionCount =
                    input.validation.actions.length
              · by_cases hWireReplay :
                    wireOutput.projectedActionCount =
                      input.replay.actions.length
                · by_cases hValidationBridge :
                      validationSummary.importedBridgeReplayCount =
                        wireOutput.projectedBridgeReplayRowCount
                  · by_cases hReplayBridge :
                        replaySummary.importedBridgeReplayCount =
                          wireOutput.projectedBridgeReplayRowCount
                    · have validationAccepts :
                          blockActionValidationAccepts input.validation =
                            true := by
                        simp [blockActionValidationAccepts, hValidation]
                      have replayAccepts :
                          blockReplayAccepts input.replay = true := by
                        simp [blockReplayAccepts, hReplay]
                      have wireAccepts :
                          actionWireReplayProjectionAccepts
                              input.wireProjection = true := by
                        simp [actionWireReplayProjectionAccepts, hWire]
                      exact
                        {
                          validationAccepted := validationAccepts,
                          replayAccepted := replayAccepts,
                          wireProjectionAccepted := wireAccepts,
                          wireActionCountMatchesValidation :=
                            hWireValidation,
                          wireProjectedActionCountMatchesReplay :=
                            by
                              intro output outputAccepted
                              rw [hWire] at outputAccepted
                              cases outputAccepted
                              exact hWireReplay,
                          validationBridgeRowsMatchWire :=
                            by
                              intro summary output
                                validationAccepted' wireAccepted'
                              rw [hValidation] at validationAccepted'
                              rw [hWire] at wireAccepted'
                              cases validationAccepted'
                              cases wireAccepted'
                              exact hValidationBridge,
                          replayBridgeRowsMatchWire :=
                            by
                              intro summary output
                                replayAccepted' wireAccepted'
                              rw [hReplay] at replayAccepted'
                              rw [hWire] at wireAccepted'
                              cases replayAccepted'
                              cases wireAccepted'
                              exact hReplayBridge
                        }
                    · simp [
                        hValidation,
                        hReplay,
                        hWire,
                        hWireValidation,
                        hWireReplay,
                        hValidationBridge,
                        hReplayBridge
                      ] at accepted
                  · simp [
                      hValidation,
                      hReplay,
                      hWire,
                      hWireValidation,
                      hWireReplay,
                      hValidationBridge
                    ] at accepted
                · simp [
                    hValidation,
                    hReplay,
                    hWire,
                    hWireValidation,
                    hWireReplay
                  ] at accepted
              · simp [
                  hValidation,
                  hReplay,
                  hWire,
                  hWireValidation
                ] at accepted

def replayTransferOne : StreamAction :=
  {
    commitmentCount := 1,
    ciphertextCount := 1,
    nullifiers := [1],
    bridgeReplayKey := none
  }

def replayBridgeOne : StreamAction :=
  {
    commitmentCount := 0,
    ciphertextCount := 0,
    nullifiers := [],
    bridgeReplayKey := some 7
  }

def replayBridgeMissing : StreamAction :=
  {
    replayBridgeOne with
    bridgeReplayKey := none
  }

def replayCandidateLike : StreamAction :=
  {
    commitmentCount := 0,
    ciphertextCount := 0,
    nullifiers := [],
    bridgeReplayKey := none
  }

def replayCoinbaseLike : StreamAction :=
  {
    commitmentCount := 1,
    ciphertextCount := 1,
    nullifiers := [],
    bridgeReplayKey := none
  }

def replayTransferTwo : StreamAction :=
  {
    commitmentCount := 1,
    ciphertextCount := 1,
    nullifiers := [2],
    bridgeReplayKey := none
  }

def validPublicationReplay : BlockReplayInput :=
  {
    validReplay with
    leafStart := 30,
    actions := [
      replayTransferOne,
      replayBridgeOne,
      replayCandidateLike,
      replayCoinbaseLike,
      replayTransferTwo
    ]
  }

def wireTransferOne : WireReplayAction :=
  {
    ciphertextHashCount := 1,
    ciphertextSizeCount := 1,
    plannedCiphertextCount := 1,
    ciphertextHashesMatch := true,
    ciphertextSizesMatch := true,
    plannedReplayPresent := false,
    replayKeyMatches := true
  }

def wireBridgeOne : WireReplayAction :=
  {
    ciphertextHashCount := 0,
    ciphertextSizeCount := 0,
    plannedCiphertextCount := 0,
    ciphertextHashesMatch := true,
    ciphertextSizesMatch := true,
    plannedReplayPresent := true,
    replayKeyMatches := true
  }

def wireNoCipherNoReplay : WireReplayAction :=
  {
    ciphertextHashCount := 0,
    ciphertextSizeCount := 0,
    plannedCiphertextCount := 0,
    ciphertextHashesMatch := true,
    ciphertextSizesMatch := true,
    plannedReplayPresent := false,
    replayKeyMatches := true
  }

def wireOneCipherNoReplay : WireReplayAction :=
  {
    ciphertextHashCount := 1,
    ciphertextSizeCount := 1,
    plannedCiphertextCount := 1,
    ciphertextHashesMatch := true,
    ciphertextSizesMatch := true,
    plannedReplayPresent := false,
    replayKeyMatches := true
  }

def validPublicationWireProjection :
    ActionWireReplayProjectionInput :=
  {
    actionCount := 5,
    plannedCount := 5,
    actions := [
      wireTransferOne,
      wireBridgeOne,
      wireNoCipherNoReplay,
      wireOneCipherNoReplay,
      wireOneCipherNoReplay
    ]
  }

def validBlockActionReplayPublication :
    BlockActionReplayPublicationInput :=
  {
    validation := validMixedValidation,
    replay := validPublicationReplay,
    wireProjection := validPublicationWireProjection
  }

def wireValidationCountMismatchPublication :
    BlockActionReplayPublicationInput :=
  {
    validBlockActionReplayPublication with
    wireProjection :=
      {
        emptyProjection with
        actionCount := 4,
        plannedCount := 4,
        actions :=
          [
            wireTransferOne,
            wireBridgeOne,
            wireNoCipherNoReplay,
            wireOneCipherNoReplay
          ]
      }
  }

def wireReplayCountMismatchPublication :
    BlockActionReplayPublicationInput :=
  {
    validBlockActionReplayPublication with
    replay := validTwoActionReplay
  }

def validationBridgeCountMismatchPublication :
    BlockActionReplayPublicationInput :=
  {
    validBlockActionReplayPublication with
    wireProjection :=
      {
        validPublicationWireProjection with
        actions :=
          [
            wireTransferOne,
            wireNoCipherNoReplay,
            wireNoCipherNoReplay,
            wireOneCipherNoReplay,
            wireOneCipherNoReplay
          ]
      }
  }

def replayBridgeCountMismatchPublication :
    BlockActionReplayPublicationInput :=
  {
    validBlockActionReplayPublication with
    replay :=
      {
        validPublicationReplay with
        actions := [
          replayTransferOne,
          replayBridgeMissing,
          replayCandidateLike,
          replayCoinbaseLike,
          replayTransferTwo
        ]
      }
  }

theorem valid_block_action_replay_publication_accepts :
    evaluateBlockActionReplayPublicationRejection
      validBlockActionReplayPublication = none := by
  decide

theorem validation_rejects_before_replay :
    evaluateBlockActionReplayPublicationRejection
      { validBlockActionReplayPublication with
        validation := actionHashMismatchValidation,
        replay := counterfeitSupplyReplay } =
      some
        BlockActionReplayPublicationReject.validationRejected := by
  decide

theorem replay_rejects_before_wire_projection :
    evaluateBlockActionReplayPublicationRejection
      { validBlockActionReplayPublication with
        replay := counterfeitSupplyReplay,
        wireProjection := planLengthMismatch } =
      some
        BlockActionReplayPublicationReject.replayRejected := by
  decide

theorem wire_projection_rejects_before_row_agreement :
    evaluateBlockActionReplayPublicationRejection
      { validBlockActionReplayPublication with
        wireProjection := planLengthMismatch } =
      some
        BlockActionReplayPublicationReject.wireProjectionRejected := by
  decide

theorem validation_wire_action_count_mismatch_rejects :
    evaluateBlockActionReplayPublicationRejection
      wireValidationCountMismatchPublication =
      some
        BlockActionReplayPublicationReject.validationWireActionCountMismatch := by
  decide

theorem wire_replay_action_count_mismatch_rejects :
    evaluateBlockActionReplayPublicationRejection
      wireReplayCountMismatchPublication =
      some
        BlockActionReplayPublicationReject.wireReplayActionCountMismatch := by
  decide

theorem validation_bridge_replay_count_mismatch_rejects :
    evaluateBlockActionReplayPublicationRejection
      validationBridgeCountMismatchPublication =
      some
        BlockActionReplayPublicationReject.validationBridgeReplayCountMismatch := by
  decide

theorem replay_bridge_replay_count_mismatch_rejects :
    evaluateBlockActionReplayPublicationRejection
      replayBridgeCountMismatchPublication =
      some
        BlockActionReplayPublicationReject.replayBridgeReplayCountMismatch := by
  decide

end BlockActionReplayPublication
end Native
end Hegemon

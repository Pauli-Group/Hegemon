import Hegemon.Native.ActionHashAdmission
import Hegemon.Native.ActionScopeAdmission
import Hegemon.Native.ActionStreamEffect
import Hegemon.Native.TransferStateAdmission

namespace Hegemon
namespace Native
namespace BlockActionValidation

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionScopeAdmission
open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.TransferStateAdmission

inductive BlockActionReject where
  | actionCountMismatch
  | actionHashMismatch
  | duplicateActionHash
  | candidateArtifactPayloadWrongRoute
  | bridgeScopeInvalid
  | candidateScopeInvalid
  | candidatePayloadMissing
  | coinbaseScopeInvalid
  | unsupportedActionRoute
  | transferScopeInvalid
  | bridgePayloadInvalid
  | candidatePayloadInvalid
  | coinbasePayloadInvalid
  | transferPayloadInvalid
  | bridgeReplayDuplicate
  | transferOrderInvalid
  | transferUnknownAnchor
  | transferNullifierZero
  | transferNullifierAlreadySpent
  | transferDuplicateNullifier
  | transferNullifierAlreadyPending
  | transferCommitmentZero
  | transferStablecoinPolicyUnauthorized
  | transferSidecarCiphertextMissing
  | transferSidecarCiphertextSizeMissing
  | transferSidecarCiphertextSizeMismatch
deriving DecidableEq, Repr

structure ValidationAction where
  scope : ScopeInput
  payloadValid : Bool
  transferKey : Nat
  transferState : TransferStateInput
  bridgeReplayKey : Option Nat
deriving DecidableEq, Repr

structure BlockActionValidationInput where
  actionCountMatches : Bool
  actionHashesMatch : Bool
  actionHashesUnique : Bool
  consumedBridgeReplays : List Nat
  actions : List ValidationAction
deriving DecidableEq, Repr

structure BlockActionValidationSummary where
  validatedActionCount : Nat
  importedBridgeReplayCount : Nat
  lastTransferKey : Option Nat
deriving DecidableEq, Repr

def hashInput (input : BlockActionValidationInput) : AdmissionInput :=
  {
    actionCountMatches := input.actionCountMatches,
    actionHashesMatch := input.actionHashesMatch,
    actionHashesUnique := input.actionHashesUnique
  }

def mapHashReject : AdmissionReject -> BlockActionReject
  | AdmissionReject.actionCountMismatch =>
      BlockActionReject.actionCountMismatch
  | AdmissionReject.actionHashMismatch =>
      BlockActionReject.actionHashMismatch
  | AdmissionReject.duplicateActionHash =>
      BlockActionReject.duplicateActionHash

def mapScopeReject : ScopeReject -> BlockActionReject
  | ScopeReject.candidateArtifactPayloadWrongRoute =>
      BlockActionReject.candidateArtifactPayloadWrongRoute
  | ScopeReject.bridgeScopeInvalid => BlockActionReject.bridgeScopeInvalid
  | ScopeReject.candidateScopeInvalid =>
      BlockActionReject.candidateScopeInvalid
  | ScopeReject.candidatePayloadMissing =>
      BlockActionReject.candidatePayloadMissing
  | ScopeReject.coinbaseScopeInvalid => BlockActionReject.coinbaseScopeInvalid
  | ScopeReject.unsupportedActionRoute =>
      BlockActionReject.unsupportedActionRoute
  | ScopeReject.transferScopeInvalid => BlockActionReject.transferScopeInvalid

def mapPayloadReject : ActionRoute -> BlockActionReject
  | ActionRoute.bridge => BlockActionReject.bridgePayloadInvalid
  | ActionRoute.candidateArtifact => BlockActionReject.candidatePayloadInvalid
  | ActionRoute.coinbase => BlockActionReject.coinbasePayloadInvalid
  | ActionRoute.transfer => BlockActionReject.transferPayloadInvalid

def mapTransferReject : TransferStateReject -> BlockActionReject
  | TransferStateReject.unknownAnchor =>
      BlockActionReject.transferUnknownAnchor
  | TransferStateReject.nullifierZero =>
      BlockActionReject.transferNullifierZero
  | TransferStateReject.nullifierAlreadySpent =>
      BlockActionReject.transferNullifierAlreadySpent
  | TransferStateReject.duplicateNullifier =>
      BlockActionReject.transferDuplicateNullifier
  | TransferStateReject.nullifierAlreadyPending =>
      BlockActionReject.transferNullifierAlreadyPending
  | TransferStateReject.commitmentZero =>
      BlockActionReject.transferCommitmentZero
  | TransferStateReject.stablecoinPolicyUnauthorized =>
      BlockActionReject.transferStablecoinPolicyUnauthorized
  | TransferStateReject.sidecarCiphertextMissing =>
      BlockActionReject.transferSidecarCiphertextMissing
  | TransferStateReject.sidecarCiphertextSizeMissing =>
      BlockActionReject.transferSidecarCiphertextSizeMissing
  | TransferStateReject.sidecarCiphertextSizeMismatch =>
      BlockActionReject.transferSidecarCiphertextSizeMismatch

def transferOrderExtends (previous : Option Nat) (key : Nat) : Bool :=
  match previous with
  | none => true
  | some prev => if prev <= key then true else false

def importValidationBridgeReplay
    (known : List Nat)
    (key : Option Nat) :
    Except BlockActionReject (List Nat × Nat) :=
  match key with
  | none => Except.ok (known, 0)
  | some replay =>
      if containsNat replay known then
        Except.error BlockActionReject.bridgeReplayDuplicate
      else
        Except.ok (replay :: known, 1)

def evaluateActionsFrom :
    List Nat ->
    Option Nat ->
    List ValidationAction ->
    Nat ->
    Nat ->
    Except BlockActionReject BlockActionValidationSummary
  | _consumed, previousTransfer, [], validated, importedReplays =>
      Except.ok
        { validatedActionCount := validated,
          importedBridgeReplayCount := importedReplays,
          lastTransferKey := previousTransfer }
  | consumed, previousTransfer, action :: rest, validated, importedReplays =>
      match evaluateScopeAdmission action.scope with
      | Except.error rejection => Except.error (mapScopeReject rejection)
      | Except.ok route =>
          if action.payloadValid = false then
            Except.error (mapPayloadReject route)
          else
            match route with
            | ActionRoute.bridge =>
                match importValidationBridgeReplay consumed action.bridgeReplayKey with
                | Except.error rejection => Except.error rejection
                | Except.ok (nextConsumed, imported) =>
                    evaluateActionsFrom
                      nextConsumed
                      previousTransfer
                      rest
                      (validated + 1)
                      (importedReplays + imported)
            | ActionRoute.candidateArtifact =>
                evaluateActionsFrom
                  consumed
                  previousTransfer
                  rest
                  (validated + 1)
                  importedReplays
            | ActionRoute.coinbase =>
                evaluateActionsFrom
                  consumed
                  previousTransfer
                  rest
                  (validated + 1)
                  importedReplays
            | ActionRoute.transfer =>
                if transferOrderExtends previousTransfer action.transferKey = false then
                  Except.error BlockActionReject.transferOrderInvalid
                else
                  match evaluateTransferState action.transferState with
                  | Except.error rejection =>
                      Except.error (mapTransferReject rejection)
                  | Except.ok _ =>
                      evaluateActionsFrom
                        consumed
                        (some action.transferKey)
                        rest
                        (validated + 1)
                        importedReplays

def evaluateBlockActionValidation
    (input : BlockActionValidationInput) :
    Except BlockActionReject BlockActionValidationSummary :=
  match evaluateAdmissionRejection (hashInput input) with
  | some rejection => Except.error (mapHashReject rejection)
  | none =>
      evaluateActionsFrom
        input.consumedBridgeReplays
        none
        input.actions
        0
        0

def blockActionValidationAccepts
    (input : BlockActionValidationInput) : Bool :=
  match evaluateBlockActionValidation input with
  | Except.ok _ => true
  | Except.error _ => false

def blockActionValidationPreconditions
    (input : BlockActionValidationInput) : Bool :=
  blockActionValidationAccepts input

theorem accepts_iff_block_action_validation_preconditions
    (input : BlockActionValidationInput) :
    blockActionValidationAccepts input =
      blockActionValidationPreconditions input := by
  rfl

def validTransferAction (key : Nat) : ValidationAction :=
  {
    scope := validTransfer,
    payloadValid := true,
    transferKey := key,
    transferState := validTransferState,
    bridgeReplayKey := none
  }

def validBridgeAction (key : Option Nat) : ValidationAction :=
  {
    scope := validBridge,
    payloadValid := true,
    transferKey := 0,
    transferState := validTransferState,
    bridgeReplayKey := key
  }

def validCandidateAction : ValidationAction :=
  {
    scope := validCandidateArtifact,
    payloadValid := true,
    transferKey := 0,
    transferState := validTransferState,
    bridgeReplayKey := none
  }

def validCoinbaseAction : ValidationAction :=
  {
    scope := validCoinbase,
    payloadValid := true,
    transferKey := 0,
    transferState := validTransferState,
    bridgeReplayKey := none
  }

def validMixedValidation : BlockActionValidationInput :=
  {
    actionCountMatches := true,
    actionHashesMatch := true,
    actionHashesUnique := true,
    consumedBridgeReplays := [],
    actions := [
      validTransferAction 1,
      validBridgeAction (some 7),
      validCandidateAction,
      validCoinbaseAction,
      validTransferAction 3
    ]
  }

theorem valid_mixed_validation_accepts :
    evaluateBlockActionValidation validMixedValidation =
      Except.ok
        { validatedActionCount := 5,
          importedBridgeReplayCount := 1,
          lastTransferKey := some 3 } := by
  rfl

def nontransferBetweenTransfers : BlockActionValidationInput :=
  {
    validMixedValidation with
    actions := [
      validTransferAction 1,
      validBridgeAction none,
      validTransferAction 1
    ]
  }

theorem nontransfer_between_transfers_accepts :
    evaluateBlockActionValidation nontransferBetweenTransfers =
      Except.ok
        { validatedActionCount := 3,
          importedBridgeReplayCount := 0,
          lastTransferKey := some 1 } := by
  rfl

def actionHashMismatchValidation : BlockActionValidationInput :=
  { validMixedValidation with actionHashesMatch := false }

theorem action_hash_mismatch_rejects :
    evaluateBlockActionValidation actionHashMismatchValidation =
      Except.error BlockActionReject.actionHashMismatch := by
  rfl

def duplicateActionHashValidation : BlockActionValidationInput :=
  {
    validMixedValidation with
    actionHashesUnique := false
  }

theorem duplicate_action_hash_rejects :
    evaluateBlockActionValidation duplicateActionHashValidation =
      Except.error BlockActionReject.duplicateActionHash := by
  rfl

def scopePrecedesPayloadValidation : BlockActionValidationInput :=
  {
    validMixedValidation with
    actions := [
      {
        validBridgeAction none with
        scope := { validBridge with candidateArtifactPayloadScoped := false },
        payloadValid := false
      }
    ]
  }

theorem scope_rejection_precedes_payload :
    evaluateBlockActionValidation scopePrecedesPayloadValidation =
      Except.error BlockActionReject.candidateArtifactPayloadWrongRoute := by
  rfl

def bridgePayloadPrecedesReplayValidation : BlockActionValidationInput :=
  {
    validMixedValidation with
    consumedBridgeReplays := [7],
    actions := [
      {
        validBridgeAction (some 7) with
        payloadValid := false
      }
    ]
  }

theorem bridge_payload_precedes_replay :
    evaluateBlockActionValidation bridgePayloadPrecedesReplayValidation =
      Except.error BlockActionReject.bridgePayloadInvalid := by
  rfl

def bridgeReplayDuplicateValidation : BlockActionValidationInput :=
  {
    validMixedValidation with
    consumedBridgeReplays := [7],
    actions := [validBridgeAction (some 7)]
  }

theorem bridge_replay_duplicate_rejects :
    evaluateBlockActionValidation bridgeReplayDuplicateValidation =
      Except.error BlockActionReject.bridgeReplayDuplicate := by
  rfl

def crossActionBridgeReplayDuplicateValidation :
    BlockActionValidationInput :=
  {
    validMixedValidation with
    actions := [
      validBridgeAction (some 7),
      validBridgeAction (some 7)
    ]
  }

theorem cross_action_bridge_replay_duplicate_rejects :
    evaluateBlockActionValidation crossActionBridgeReplayDuplicateValidation =
      Except.error BlockActionReject.bridgeReplayDuplicate := by
  rfl

def transferPayloadPrecedesOrderValidation : BlockActionValidationInput :=
  {
    validMixedValidation with
    actions := [
      validTransferAction 9,
      {
        validTransferAction 1 with
        payloadValid := false
      }
    ]
  }

theorem transfer_payload_precedes_order :
    evaluateBlockActionValidation transferPayloadPrecedesOrderValidation =
      Except.error BlockActionReject.transferPayloadInvalid := by
  rfl

def descendingTransferOrderValidation : BlockActionValidationInput :=
  {
    validMixedValidation with
    actions := [
      validTransferAction 9,
      validTransferAction 1
    ]
  }

theorem descending_transfer_order_rejects :
    evaluateBlockActionValidation descendingTransferOrderValidation =
      Except.error BlockActionReject.transferOrderInvalid := by
  rfl

def transferOrderPrecedesStateValidation : BlockActionValidationInput :=
  {
    validMixedValidation with
    actions := [
      validTransferAction 9,
      {
        validTransferAction 1 with
        transferState :=
          { validTransferState with anchorKnown := false }
      }
    ]
  }

theorem transfer_order_precedes_state :
    evaluateBlockActionValidation transferOrderPrecedesStateValidation =
      Except.error BlockActionReject.transferOrderInvalid := by
  rfl

def transferStateRejectValidation : BlockActionValidationInput :=
  {
    validMixedValidation with
    actions := [
      {
        validTransferAction 1 with
        transferState :=
          { validTransferState with anchorKnown := false }
      }
    ]
  }

theorem transfer_state_rejects :
    evaluateBlockActionValidation transferStateRejectValidation =
      Except.error BlockActionReject.transferUnknownAnchor := by
  rfl

def transferStateStablecoinPolicyRejectValidation :
    BlockActionValidationInput :=
  {
    validMixedValidation with
    actions := [
      {
        validTransferAction 1 with
        transferState :=
          { validTransferState with stablecoinPolicyAuthorized := false }
      }
    ]
  }

theorem transfer_state_stablecoin_policy_rejects :
    evaluateBlockActionValidation transferStateStablecoinPolicyRejectValidation =
      Except.error BlockActionReject.transferStablecoinPolicyUnauthorized := by
  rfl

end BlockActionValidation
end Native
end Hegemon

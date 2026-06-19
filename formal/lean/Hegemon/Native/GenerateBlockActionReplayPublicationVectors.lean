import Hegemon.Native.BlockActionReplayPublication

open Hegemon.Native.ActionScopeAdmission
open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.BlockActionReplayPublication
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockReplayRefinement
open Hegemon.Native.TransferStateAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListTailJson : List Nat -> String
  | [] => ""
  | head :: tail => ", " ++ toString head ++ natListTailJson tail

def natListJson : List Nat -> String
  | [] => "[]"
  | head :: tail => "[" ++ toString head ++ natListTailJson tail ++ "]"

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def acceptedNatOrNull
    (rejection : Option BlockActionReplayPublicationReject)
    (value : Nat) : String :=
  match rejection with
  | none => toString value
  | some _ => "null"

def acceptedNatStringOrNull
    (rejection : Option BlockActionReplayPublicationReject)
    (value : Nat) : String :=
  match rejection with
  | none => "\"" ++ toString value ++ "\""
  | some _ => "null"

def rejectionJson :
    Option BlockActionReplayPublicationReject -> String
  | none => "null"
  | some BlockActionReplayPublicationReject.validationRejected =>
      "\"validation_rejected\""
  | some BlockActionReplayPublicationReject.replayRejected =>
      "\"replay_rejected\""
  | some BlockActionReplayPublicationReject.wireProjectionRejected =>
      "\"wire_projection_rejected\""
  | some BlockActionReplayPublicationReject.validationWireActionCountMismatch =>
      "\"validation_wire_action_count_mismatch\""
  | some BlockActionReplayPublicationReject.wireReplayActionCountMismatch =>
      "\"wire_replay_action_count_mismatch\""
  | some BlockActionReplayPublicationReject.validationBridgeReplayCountMismatch =>
      "\"validation_bridge_replay_count_mismatch\""
  | some BlockActionReplayPublicationReject.replayBridgeReplayCountMismatch =>
      "\"replay_bridge_replay_count_mismatch\""

def nullifierStateJson : TransferNullifierState -> String
  | TransferNullifierState.valid => "\"valid\""
  | TransferNullifierState.zero => "\"zero\""
  | TransferNullifierState.alreadySpent => "\"already_spent\""
  | TransferNullifierState.duplicate => "\"duplicate\""
  | TransferNullifierState.alreadyPending => "\"already_pending\""

def validationScopeJson (scope : ScopeInput) : String :=
  "          \"scope\": {\n"
    ++ "            \"candidate_artifact_payload_scoped\": "
      ++ boolJson scope.candidateArtifactPayloadScoped ++ ",\n"
    ++ "            \"bridge_route\": " ++ boolJson scope.bridgeRoute ++ ",\n"
    ++ "            \"bridge_scope_valid\": "
      ++ boolJson scope.bridgeScopeValid ++ ",\n"
    ++ "            \"candidate_artifact_route\": "
      ++ boolJson scope.candidateArtifactRoute ++ ",\n"
    ++ "            \"candidate_scope_valid\": "
      ++ boolJson scope.candidateScopeValid ++ ",\n"
    ++ "            \"candidate_payload_present\": "
      ++ boolJson scope.candidatePayloadPresent ++ ",\n"
    ++ "            \"coinbase_route\": "
      ++ boolJson scope.coinbaseRoute ++ ",\n"
    ++ "            \"coinbase_scope_valid\": "
      ++ boolJson scope.coinbaseScopeValid ++ ",\n"
    ++ "            \"transfer_route\": "
      ++ boolJson scope.transferRoute ++ ",\n"
    ++ "            \"transfer_scope_valid\": "
      ++ boolJson scope.transferScopeValid ++ "\n"
    ++ "          }"

def validationTransferStateJson (state : TransferStateInput) : String :=
  "          \"transfer_state\": {\n"
    ++ "            \"anchor_known\": " ++ boolJson state.anchorKnown ++ ",\n"
    ++ "            \"nullifier_state\": "
      ++ nullifierStateJson state.nullifierState ++ ",\n"
    ++ "            \"commitments_nonzero\": "
      ++ boolJson state.commitmentsNonzero ++ ",\n"
    ++ "            \"stablecoin_policy_authorized\": "
      ++ boolJson state.stablecoinPolicyAuthorized ++ ",\n"
    ++ "            \"sidecar_route\": "
      ++ boolJson state.sidecarRoute ++ ",\n"
    ++ "            \"sidecar_ciphertexts_available\": "
      ++ boolJson state.sidecarCiphertextsAvailable ++ ",\n"
    ++ "            \"sidecar_ciphertext_sizes_present\": "
      ++ boolJson state.sidecarCiphertextSizesPresent ++ ",\n"
    ++ "            \"sidecar_ciphertext_sizes_match\": "
      ++ boolJson state.sidecarCiphertextSizesMatch ++ "\n"
    ++ "          }"

def validationActionJson (action : ValidationAction) : String :=
  "        {\n"
    ++ validationScopeJson action.scope ++ ",\n"
    ++ "          \"payload_valid\": "
      ++ boolJson action.payloadValid ++ ",\n"
    ++ "          \"transfer_key\": " ++ toString action.transferKey ++ ",\n"
    ++ validationTransferStateJson action.transferState ++ ",\n"
    ++ "          \"bridge_replay_key\": "
      ++ optionNatJson action.bridgeReplayKey ++ "\n"
    ++ "        }"

def validationActionsTailJson : List ValidationAction -> String
  | [] => ""
  | head :: tail =>
      ",\n" ++ validationActionJson head ++ validationActionsTailJson tail

def validationActionsJson : List ValidationAction -> String
  | [] => "[]"
  | head :: tail =>
      "[\n" ++ validationActionJson head
        ++ validationActionsTailJson tail ++ "\n      ]"

def streamActionJson (action : StreamAction) : String :=
  "        {\n"
    ++ "          \"commitment_count\": "
    ++ toString action.commitmentCount ++ ",\n"
    ++ "          \"ciphertext_count\": "
    ++ toString action.ciphertextCount ++ ",\n"
    ++ "          \"nullifiers\": " ++ natListJson action.nullifiers ++ ",\n"
    ++ "          \"bridge_replay_key\": "
    ++ optionNatJson action.bridgeReplayKey ++ "\n"
    ++ "        }"

def streamActionsTailJson : List StreamAction -> String
  | [] => ""
  | head :: tail => ",\n" ++ streamActionJson head ++ streamActionsTailJson tail

def streamActionsJson : List StreamAction -> String
  | [] => "[]"
  | head :: tail =>
      "[\n" ++ streamActionJson head ++ streamActionsTailJson tail ++ "\n      ]"

def wireReplayActionJson (action : WireReplayAction) : String :=
  "        {\n"
    ++ "          \"ciphertext_hash_count\": "
    ++ toString action.ciphertextHashCount ++ ",\n"
    ++ "          \"ciphertext_size_count\": "
    ++ toString action.ciphertextSizeCount ++ ",\n"
    ++ "          \"planned_ciphertext_count\": "
    ++ toString action.plannedCiphertextCount ++ ",\n"
    ++ "          \"ciphertext_hashes_match\": "
    ++ boolJson action.ciphertextHashesMatch ++ ",\n"
    ++ "          \"ciphertext_sizes_match\": "
    ++ boolJson action.ciphertextSizesMatch ++ ",\n"
    ++ "          \"planned_replay_present\": "
    ++ boolJson action.plannedReplayPresent ++ ",\n"
    ++ "          \"replay_key_matches\": "
    ++ boolJson action.replayKeyMatches ++ "\n"
    ++ "        }"

def wireReplayActionsTailJson : List WireReplayAction -> String
  | [] => ""
  | head :: tail =>
      ",\n" ++ wireReplayActionJson head ++ wireReplayActionsTailJson tail

def wireReplayActionsJson : List WireReplayAction -> String
  | [] => "[]"
  | head :: tail =>
      "[\n" ++ wireReplayActionJson head
        ++ wireReplayActionsTailJson tail ++ "\n      ]"

def acceptedValidationCountJson
    (rejection : Option BlockActionReplayPublicationReject)
    (result : Except BlockActionReject BlockActionValidationSummary) :
    String :=
  match rejection, result with
  | none, Except.ok summary => toString summary.validatedActionCount
  | _, _ => "null"

def acceptedValidationBridgeCountJson
    (rejection : Option BlockActionReplayPublicationReject)
    (result : Except BlockActionReject BlockActionValidationSummary) :
    String :=
  match rejection, result with
  | none, Except.ok summary => toString summary.importedBridgeReplayCount
  | _, _ => "null"

def acceptedReplayNatStringJson
    (rejection : Option BlockActionReplayPublicationReject)
    (result : Except BlockReplayReject BlockReplaySummary)
    (selector : BlockReplaySummary -> Nat) : String :=
  match rejection, result with
  | none, Except.ok summary => "\"" ++ toString (selector summary) ++ "\""
  | _, _ => "null"

def acceptedWireCountJson
    (rejection : Option BlockActionReplayPublicationReject)
    (result :
      Except ActionWireReplayProjectionReject
        ActionWireReplayProjectionOutput)
    (selector : ActionWireReplayProjectionOutput -> Nat) : String :=
  match rejection, result with
  | none, Except.ok summary => toString (selector summary)
  | _, _ => "null"

def publicationCaseJson
    (name : String)
    (input : BlockActionReplayPublicationInput) : String :=
  let rejection := evaluateBlockActionReplayPublicationRejection input
  let validationResult := evaluateBlockActionValidation input.validation
  let replayResult := evaluateBlockReplayRefinement input.replay
  let wireResult :=
    evaluateActionWireReplayProjection input.wireProjection
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"validation_action_count_matches\": "
      ++ boolJson input.validation.actionCountMatches ++ ",\n"
    ++ "      \"validation_action_hashes_match\": "
      ++ boolJson input.validation.actionHashesMatch ++ ",\n"
    ++ "      \"validation_action_hashes_unique\": "
      ++ boolJson input.validation.actionHashesUnique ++ ",\n"
    ++ "      \"validation_consumed_bridge_replays\": "
      ++ natListJson input.validation.consumedBridgeReplays ++ ",\n"
    ++ "      \"validation_actions\": "
      ++ validationActionsJson input.validation.actions ++ ",\n"
    ++ "      \"replay_leaf_start\": "
      ++ toString input.replay.leafStart ++ ",\n"
    ++ "      \"replay_spent_nullifiers\": "
      ++ natListJson input.replay.spentNullifiers ++ ",\n"
    ++ "      \"replay_consumed_bridge_replays\": "
      ++ natListJson input.replay.consumedBridgeReplays ++ ",\n"
    ++ "      \"replay_actions\": "
      ++ streamActionsJson input.replay.actions ++ ",\n"
    ++ "      \"replay_parent_supply\": \""
      ++ toString input.replay.parentSupply ++ "\",\n"
    ++ "      \"replay_height\": " ++ toString input.replay.height ++ ",\n"
    ++ "      \"replay_fee_total\": "
      ++ toString input.replay.feeTotal ++ ",\n"
    ++ "      \"replay_has_coinbase\": "
      ++ boolJson input.replay.hasCoinbase ++ ",\n"
    ++ "      \"replay_claimed_supply\": \""
      ++ toString input.replay.claimedSupply ++ "\",\n"
    ++ "      \"replay_tx_count_matches\": "
      ++ boolJson input.replay.txCountMatches ++ ",\n"
    ++ "      \"replay_state_root_matches\": "
      ++ boolJson input.replay.stateRootMatches ++ ",\n"
    ++ "      \"replay_kernel_root_matches\": "
      ++ boolJson input.replay.kernelRootMatches ++ ",\n"
    ++ "      \"replay_nullifier_root_matches\": "
      ++ boolJson input.replay.nullifierRootMatches ++ ",\n"
    ++ "      \"replay_extrinsics_root_matches\": "
      ++ boolJson input.replay.extrinsicsRootMatches ++ ",\n"
    ++ "      \"replay_message_root_matches\": "
      ++ boolJson input.replay.messageRootMatches ++ ",\n"
    ++ "      \"replay_message_count_matches\": "
      ++ boolJson input.replay.messageCountMatches ++ ",\n"
    ++ "      \"replay_header_mmr_root_matches\": "
      ++ boolJson input.replay.headerMmrRootMatches ++ ",\n"
    ++ "      \"replay_header_mmr_len_matches\": "
      ++ boolJson input.replay.headerMmrLenMatches ++ ",\n"
    ++ "      \"wire_action_count\": "
      ++ toString input.wireProjection.actionCount ++ ",\n"
    ++ "      \"wire_planned_count\": "
      ++ toString input.wireProjection.plannedCount ++ ",\n"
    ++ "      \"wire_actions\": "
      ++ wireReplayActionsJson input.wireProjection.actions ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson rejection ++ ",\n"
    ++ "      \"expected_validated_action_count\": "
      ++ acceptedValidationCountJson rejection validationResult ++ ",\n"
    ++ "      \"expected_replay_action_count\": "
      ++ acceptedNatOrNull rejection input.replay.actions.length ++ ",\n"
    ++ "      \"expected_wire_projected_action_count\": "
      ++ acceptedWireCountJson rejection wireResult
        ActionWireReplayProjectionOutput.projectedActionCount ++ ",\n"
    ++ "      \"expected_imported_bridge_replay_count\": "
      ++ acceptedValidationBridgeCountJson rejection validationResult ++ ",\n"
    ++ "      \"expected_wire_projected_bridge_replay_count\": "
      ++ acceptedWireCountJson rejection wireResult
        ActionWireReplayProjectionOutput.projectedBridgeReplayRowCount ++ ",\n"
    ++ "      \"expected_replay_next_leaf_count\": "
      ++ acceptedReplayNatStringJson rejection replayResult
        BlockReplaySummary.nextLeafCount ++ ",\n"
    ++ "      \"expected_replay_supply\": "
      ++ acceptedReplayNatStringJson rejection replayResult
        BlockReplaySummary.expectedSupply ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"block_action_replay_publication_cases\": [\n"
    ++ publicationCaseJson
      "valid-block-action-replay-publication"
      validBlockActionReplayPublication ++ ",\n"
    ++ publicationCaseJson
      "validation-rejects-before-replay"
      { validBlockActionReplayPublication with
        validation := actionHashMismatchValidation,
        replay := counterfeitSupplyReplay } ++ ",\n"
    ++ publicationCaseJson
      "replay-rejects-before-wire-projection"
      { validBlockActionReplayPublication with
        replay := counterfeitSupplyReplay,
        wireProjection := planLengthMismatch } ++ ",\n"
    ++ publicationCaseJson
      "wire-projection-rejects-before-row-agreement"
      { validBlockActionReplayPublication with
        wireProjection := planLengthMismatch } ++ ",\n"
    ++ publicationCaseJson
      "validation-wire-action-count-mismatch"
      wireValidationCountMismatchPublication ++ ",\n"
    ++ publicationCaseJson
      "wire-replay-action-count-mismatch"
      wireReplayCountMismatchPublication ++ ",\n"
    ++ publicationCaseJson
      "validation-bridge-replay-count-mismatch"
      validationBridgeCountMismatchPublication ++ ",\n"
    ++ publicationCaseJson
      "replay-bridge-replay-count-mismatch"
      replayBridgeCountMismatchPublication ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

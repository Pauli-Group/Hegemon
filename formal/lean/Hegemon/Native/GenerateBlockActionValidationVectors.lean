import Hegemon.Native.BlockActionValidation

open Hegemon.Native.ActionScopeAdmission
open Hegemon.Native.BlockActionValidation
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

def natOrNull :
    Except BlockActionReject BlockActionValidationSummary ->
    (BlockActionValidationSummary -> Nat) -> String
  | Except.ok summary, selector => toString (selector summary)
  | Except.error _, _ => "null"

def optionNatOrNull :
    Except BlockActionReject BlockActionValidationSummary ->
    (BlockActionValidationSummary -> Option Nat) -> String
  | Except.ok summary, selector => optionNatJson (selector summary)
  | Except.error _, _ => "null"

def nullifierStateJson : TransferNullifierState -> String
  | TransferNullifierState.valid => "\"valid\""
  | TransferNullifierState.zero => "\"zero\""
  | TransferNullifierState.alreadySpent => "\"already_spent\""
  | TransferNullifierState.duplicate => "\"duplicate\""
  | TransferNullifierState.alreadyPending => "\"already_pending\""

def rejectionJson :
    Except BlockActionReject BlockActionValidationSummary -> String
  | Except.ok _ => "null"
  | Except.error BlockActionReject.actionCountMismatch =>
      "\"action_count_mismatch\""
  | Except.error BlockActionReject.actionHashMismatch =>
      "\"action_hash_mismatch\""
  | Except.error BlockActionReject.duplicateActionHash =>
      "\"duplicate_action_hash\""
  | Except.error BlockActionReject.candidateArtifactPayloadWrongRoute =>
      "\"candidate_artifact_payload_wrong_route\""
  | Except.error BlockActionReject.bridgeScopeInvalid =>
      "\"bridge_scope_invalid\""
  | Except.error BlockActionReject.candidateScopeInvalid =>
      "\"candidate_scope_invalid\""
  | Except.error BlockActionReject.candidatePayloadMissing =>
      "\"candidate_payload_missing\""
  | Except.error BlockActionReject.coinbaseScopeInvalid =>
      "\"coinbase_scope_invalid\""
  | Except.error BlockActionReject.unsupportedActionRoute =>
      "\"unsupported_action_route\""
  | Except.error BlockActionReject.transferScopeInvalid =>
      "\"transfer_scope_invalid\""
  | Except.error BlockActionReject.bridgePayloadInvalid =>
      "\"bridge_payload_invalid\""
  | Except.error BlockActionReject.candidatePayloadInvalid =>
      "\"candidate_payload_invalid\""
  | Except.error BlockActionReject.coinbasePayloadInvalid =>
      "\"coinbase_payload_invalid\""
  | Except.error BlockActionReject.transferPayloadInvalid =>
      "\"transfer_payload_invalid\""
  | Except.error BlockActionReject.bridgeReplayDuplicate =>
      "\"bridge_replay_duplicate\""
  | Except.error BlockActionReject.transferOrderInvalid =>
      "\"transfer_order_invalid\""
  | Except.error BlockActionReject.transferUnknownAnchor =>
      "\"transfer_unknown_anchor\""
  | Except.error BlockActionReject.transferNullifierZero =>
      "\"transfer_nullifier_zero\""
  | Except.error BlockActionReject.transferNullifierAlreadySpent =>
      "\"transfer_nullifier_already_spent\""
  | Except.error BlockActionReject.transferDuplicateNullifier =>
      "\"transfer_duplicate_nullifier\""
  | Except.error BlockActionReject.transferNullifierAlreadyPending =>
      "\"transfer_nullifier_already_pending\""
  | Except.error BlockActionReject.transferCommitmentZero =>
      "\"transfer_commitment_zero\""
  | Except.error BlockActionReject.transferSidecarCiphertextMissing =>
      "\"transfer_sidecar_ciphertext_missing\""
  | Except.error BlockActionReject.transferSidecarCiphertextSizeMissing =>
      "\"transfer_sidecar_ciphertext_size_missing\""
  | Except.error BlockActionReject.transferSidecarCiphertextSizeMismatch =>
      "\"transfer_sidecar_ciphertext_size_mismatch\""

def scopeJson (scope : ScopeInput) : String :=
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

def transferStateJson (state : TransferStateInput) : String :=
  "          \"transfer_state\": {\n"
    ++ "            \"anchor_known\": " ++ boolJson state.anchorKnown ++ ",\n"
    ++ "            \"nullifier_state\": "
      ++ nullifierStateJson state.nullifierState ++ ",\n"
    ++ "            \"commitments_nonzero\": "
      ++ boolJson state.commitmentsNonzero ++ ",\n"
    ++ "            \"sidecar_route\": "
      ++ boolJson state.sidecarRoute ++ ",\n"
    ++ "            \"sidecar_ciphertexts_available\": "
      ++ boolJson state.sidecarCiphertextsAvailable ++ ",\n"
    ++ "            \"sidecar_ciphertext_sizes_present\": "
      ++ boolJson state.sidecarCiphertextSizesPresent ++ ",\n"
    ++ "            \"sidecar_ciphertext_sizes_match\": "
      ++ boolJson state.sidecarCiphertextSizesMatch ++ "\n"
    ++ "          }"

def actionJson (action : ValidationAction) : String :=
  "        {\n"
    ++ scopeJson action.scope ++ ",\n"
    ++ "          \"payload_valid\": "
      ++ boolJson action.payloadValid ++ ",\n"
    ++ "          \"transfer_key\": "
      ++ toString action.transferKey ++ ",\n"
    ++ transferStateJson action.transferState ++ ",\n"
    ++ "          \"bridge_replay_key\": "
      ++ optionNatJson action.bridgeReplayKey ++ "\n"
    ++ "        }"

def actionsTailJson : List ValidationAction -> String
  | [] => ""
  | head :: tail => ",\n" ++ actionJson head ++ actionsTailJson tail

def actionsJson : List ValidationAction -> String
  | [] => "[]"
  | head :: tail => "[\n" ++ actionJson head ++ actionsTailJson tail ++ "\n      ]"

def caseJson
    (name : String)
    (input : BlockActionValidationInput) : String :=
  let result := evaluateBlockActionValidation input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"action_count_matches\": "
      ++ boolJson input.actionCountMatches ++ ",\n"
    ++ "      \"action_hashes_match\": "
      ++ boolJson input.actionHashesMatch ++ ",\n"
    ++ "      \"action_hashes_unique\": "
      ++ boolJson input.actionHashesUnique ++ ",\n"
    ++ "      \"consumed_bridge_replays\": "
      ++ natListJson input.consumedBridgeReplays ++ ",\n"
    ++ "      \"actions\": " ++ actionsJson input.actions ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson
        (match result with | Except.ok _ => true | Except.error _ => false)
      ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ ",\n"
    ++ "      \"expected_validated_action_count\": "
      ++ natOrNull result BlockActionValidationSummary.validatedActionCount ++ ",\n"
    ++ "      \"expected_imported_bridge_replay_count\": "
      ++ natOrNull result
        BlockActionValidationSummary.importedBridgeReplayCount ++ ",\n"
    ++ "      \"expected_last_transfer_key\": "
      ++ optionNatOrNull result
        BlockActionValidationSummary.lastTransferKey ++ "\n"
    ++ "    }"

def actionCountMismatchValidation : BlockActionValidationInput :=
  { validMixedValidation with actionCountMatches := false }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"block_action_validation_cases\": [\n"
    ++ caseJson "valid-mixed-validation" validMixedValidation ++ ",\n"
    ++ caseJson "nontransfer-between-transfers"
      nontransferBetweenTransfers ++ ",\n"
    ++ caseJson "action-count-mismatch-rejected"
      actionCountMismatchValidation ++ ",\n"
    ++ caseJson "action-hash-mismatch-rejected"
      actionHashMismatchValidation ++ ",\n"
    ++ caseJson "duplicate-action-hash-rejected"
      duplicateActionHashValidation ++ ",\n"
    ++ caseJson "scope-rejection-precedes-payload"
      scopePrecedesPayloadValidation ++ ",\n"
    ++ caseJson "bridge-payload-precedes-replay"
      bridgePayloadPrecedesReplayValidation ++ ",\n"
    ++ caseJson "prior-bridge-replay-duplicate-rejected"
      bridgeReplayDuplicateValidation ++ ",\n"
    ++ caseJson "cross-action-bridge-replay-duplicate-rejected"
      crossActionBridgeReplayDuplicateValidation ++ ",\n"
    ++ caseJson "transfer-payload-precedes-order"
      transferPayloadPrecedesOrderValidation ++ ",\n"
    ++ caseJson "descending-transfer-order-rejected"
      descendingTransferOrderValidation ++ ",\n"
    ++ caseJson "transfer-order-precedes-state"
      transferOrderPrecedesStateValidation ++ ",\n"
    ++ caseJson "transfer-state-rejected"
      transferStateRejectValidation ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

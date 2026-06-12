import Hegemon.Native.ActionWireReplayProjectionAdmission

open Hegemon.Native.ActionWireReplayProjectionAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def replayProjectionRejectionJson :
    Except ActionWireReplayProjectionReject ActionWireReplayProjectionOutput -> String
  | Except.ok _ => "null"
  | Except.error ActionWireReplayProjectionReject.planLengthMismatch =>
      "\"plan_length_mismatch\""
  | Except.error ActionWireReplayProjectionReject.ciphertextCountMismatch =>
      "\"ciphertext_count_mismatch\""
  | Except.error ActionWireReplayProjectionReject.ciphertextHashMismatch =>
      "\"ciphertext_hash_mismatch\""
  | Except.error ActionWireReplayProjectionReject.ciphertextSizeMismatch =>
      "\"ciphertext_size_mismatch\""
  | Except.error ActionWireReplayProjectionReject.replayKeyMismatch =>
      "\"replay_key_mismatch\""

def natOrNull :
    Except ActionWireReplayProjectionReject ActionWireReplayProjectionOutput ->
    (ActionWireReplayProjectionOutput -> Nat) -> String
  | Except.ok output, selector => toString (selector output)
  | Except.error _, _ => "null"

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
  | head :: tail => ",\n" ++ wireReplayActionJson head ++ wireReplayActionsTailJson tail

def wireReplayActionsJson : List WireReplayAction -> String
  | [] => "[]"
  | head :: tail =>
      "[\n" ++ wireReplayActionJson head ++ wireReplayActionsTailJson tail ++ "\n      ]"

def wireReplayProjectionCaseJson
    (name : String)
    (input : ActionWireReplayProjectionInput) : String :=
  let result := evaluateActionWireReplayProjection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"action_count\": " ++ toString input.actionCount ++ ",\n"
    ++ "      \"planned_count\": " ++ toString input.plannedCount ++ ",\n"
    ++ "      \"actions\": " ++ wireReplayActionsJson input.actions ++ ",\n"
    ++ "      \"expected_projected_action_count\": "
      ++ natOrNull result ActionWireReplayProjectionOutput.projectedActionCount ++ ",\n"
    ++ "      \"expected_projected_ciphertext_row_count\": "
      ++ natOrNull result ActionWireReplayProjectionOutput.projectedCiphertextRowCount ++ ",\n"
    ++ "      \"expected_projected_bridge_replay_row_count\": "
      ++ natOrNull result ActionWireReplayProjectionOutput.projectedBridgeReplayRowCount ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (match result with | Except.ok _ => true | Except.error _ => false)
      ++ ",\n"
    ++ "      \"expected_rejection\": " ++ replayProjectionRejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_wire_replay_projection_admission_cases\": [\n"
    ++ wireReplayProjectionCaseJson "valid-mixed-projection"
      validMixedProjection ++ ",\n"
    ++ wireReplayProjectionCaseJson "empty-projection"
      emptyProjection ++ ",\n"
    ++ wireReplayProjectionCaseJson "plan-length-mismatch-rejected"
      planLengthMismatch ++ ",\n"
    ++ wireReplayProjectionCaseJson "ciphertext-count-mismatch-rejected"
      ciphertextCountMismatch ++ ",\n"
    ++ wireReplayProjectionCaseJson "ciphertext-hash-mismatch-rejected"
      ciphertextHashMismatch ++ ",\n"
    ++ wireReplayProjectionCaseJson "ciphertext-size-mismatch-rejected"
      ciphertextSizeMismatch ++ ",\n"
    ++ wireReplayProjectionCaseJson "replay-key-mismatch-rejected"
      replayKeyMismatch ++ ",\n"
    ++ wireReplayProjectionCaseJson "count-mismatch-precedes-hash"
      count_mismatch_precedes_hash_input ++ ",\n"
    ++ wireReplayProjectionCaseJson "hash-mismatch-precedes-size"
      hash_mismatch_precedes_size_input ++ ",\n"
    ++ wireReplayProjectionCaseJson "size-mismatch-precedes-replay"
      size_mismatch_precedes_replay_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

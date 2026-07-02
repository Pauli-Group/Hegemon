import Hegemon.Native.ActionStateEffect

open Hegemon.Native.ActionStateEffect

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def nullifierImportStateJson : NullifierImportState -> String
  | NullifierImportState.valid => "\"valid\""
  | NullifierImportState.zero => "\"zero\""
  | NullifierImportState.duplicate => "\"duplicate\""

def bridgeReplayStateJson : BridgeReplayState -> String
  | BridgeReplayState.absent => "\"absent\""
  | BridgeReplayState.valid => "\"valid\""
  | BridgeReplayState.alreadyConsumed => "\"already_consumed\""

def rejectionJson :
    Except ActionStateEffectReject ActionStateEffectOutput -> String
  | Except.ok _ => "null"
  | Except.error ActionStateEffectReject.ciphertextCountMismatch =>
      "\"ciphertext_count_mismatch\""
  | Except.error ActionStateEffectReject.commitmentIndexOverflow =>
      "\"commitment_index_overflow\""
  | Except.error ActionStateEffectReject.nullifierZero => "\"nullifier_zero\""
  | Except.error ActionStateEffectReject.duplicateNullifier =>
      "\"duplicate_nullifier\""
  | Except.error ActionStateEffectReject.bridgeReplayDuplicate =>
      "\"bridge_replay_duplicate\""

def natOrNull :
    Except ActionStateEffectReject ActionStateEffectOutput ->
    (ActionStateEffectOutput -> Nat) -> String
  | Except.ok output, selector => toString (selector output)
  | Except.error _, _ => "null"

def boolOrNull :
    Except ActionStateEffectReject ActionStateEffectOutput ->
    (ActionStateEffectOutput -> Bool) -> String
  | Except.ok output, selector => boolJson (selector output)
  | Except.error _, _ => "null"

def actionStateEffectCaseJson
    (name : String)
    (input : ActionStateEffectInput) : String :=
  let result := evaluateActionStateEffect input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"leaf_start\": " ++ toString input.leafStart ++ ",\n"
    ++ "      \"commitment_count\": " ++ toString input.commitmentCount ++ ",\n"
    ++ "      \"ciphertext_count\": " ++ toString input.ciphertextCount ++ ",\n"
    ++ "      \"nullifier_count\": " ++ toString input.nullifierCount ++ ",\n"
    ++ "      \"nullifier_state\": "
      ++ nullifierImportStateJson input.nullifierState ++ ",\n"
    ++ "      \"bridge_replay_state\": "
      ++ bridgeReplayStateJson input.bridgeReplayState ++ ",\n"
    ++ "      \"expected_next_leaf_count\": "
      ++ natOrNull result ActionStateEffectOutput.nextLeafCount ++ ",\n"
    ++ "      \"expected_imported_nullifier_count\": "
      ++ natOrNull result ActionStateEffectOutput.importedNullifierCount ++ ",\n"
    ++ "      \"expected_imported_bridge_replay\": "
      ++ boolOrNull result ActionStateEffectOutput.importedBridgeReplay ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (match result with | Except.ok _ => true | Except.error _ => false)
      ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_state_effect_cases\": [\n"
    ++ actionStateEffectCaseJson "valid-transfer-effect"
      validTransferEffect ++ ",\n"
    ++ actionStateEffectCaseJson "valid-bridge-replay-effect"
      validBridgeReplayEffect ++ ",\n"
    ++ actionStateEffectCaseJson "ciphertext-count-mismatch-rejected"
      ciphertextCountMismatch ++ ",\n"
    ++ actionStateEffectCaseJson "commitment-index-overflow-rejected"
      commitmentIndexOverflow ++ ",\n"
    ++ actionStateEffectCaseJson "max-leaf-empty-action-accepted"
      maxLeafEmptyAction ++ ",\n"
    ++ actionStateEffectCaseJson "zero-nullifier-rejected"
      zeroNullifier ++ ",\n"
    ++ actionStateEffectCaseJson "duplicate-nullifier-rejected"
      duplicateNullifier ++ ",\n"
    ++ actionStateEffectCaseJson "bridge-replay-duplicate-rejected"
      bridgeReplayDuplicate ++ ",\n"
    ++ actionStateEffectCaseJson "count-mismatch-precedes-overflow"
      count_mismatch_precedes_overflow_input ++ ",\n"
    ++ actionStateEffectCaseJson "overflow-precedes-nullifier"
      overflow_precedes_nullifier_input ++ ",\n"
    ++ actionStateEffectCaseJson "nullifier-precedes-bridge-replay"
      nullifier_precedes_bridge_replay_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

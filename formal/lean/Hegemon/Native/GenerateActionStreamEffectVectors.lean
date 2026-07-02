import Hegemon.Native.ActionStreamEffect

open Hegemon.Native.ActionStreamEffect

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

def rejectionJson :
    Except ActionStreamReject ActionStreamOutput -> String
  | Except.ok _ => "null"
  | Except.error ActionStreamReject.ciphertextCountMismatch =>
      "\"ciphertext_count_mismatch\""
  | Except.error ActionStreamReject.commitmentIndexOverflow =>
      "\"commitment_index_overflow\""
  | Except.error ActionStreamReject.nullifierZero => "\"nullifier_zero\""
  | Except.error ActionStreamReject.duplicateNullifier =>
      "\"duplicate_nullifier\""
  | Except.error ActionStreamReject.bridgeReplayDuplicate =>
      "\"bridge_replay_duplicate\""

def natOrNull :
    Except ActionStreamReject ActionStreamOutput ->
    (ActionStreamOutput -> Nat) -> String
  | Except.ok output, selector => toString (selector output)
  | Except.error _, _ => "null"

def natListOrNull :
    Except ActionStreamReject ActionStreamOutput ->
    (ActionStreamOutput -> List Nat) -> String
  | Except.ok output, selector => natListJson (selector output)
  | Except.error _, _ => "null"

def streamActionJson (action : StreamAction) : String :=
  "        {\n"
    ++ "          \"commitment_count\": "
    ++ toString action.commitmentCount ++ ",\n"
    ++ "          \"ciphertext_count\": "
    ++ toString action.ciphertextCount ++ ",\n"
    ++ "          \"nullifiers\": "
    ++ natListJson action.nullifiers ++ ",\n"
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

def actionStreamEffectCaseJson
    (name : String)
    (input : ActionStreamInput) : String :=
  let result := evaluateActionStreamEffect input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"leaf_start\": " ++ toString input.leafStart ++ ",\n"
    ++ "      \"spent_nullifiers\": "
      ++ natListJson input.spentNullifiers ++ ",\n"
    ++ "      \"consumed_bridge_replays\": "
      ++ natListJson input.consumedBridgeReplays ++ ",\n"
    ++ "      \"actions\": " ++ streamActionsJson input.actions ++ ",\n"
    ++ "      \"expected_next_leaf_count\": "
      ++ natOrNull result ActionStreamOutput.nextLeafCount ++ ",\n"
    ++ "      \"expected_imported_nullifier_count\": "
      ++ natOrNull result ActionStreamOutput.importedNullifierCount ++ ",\n"
    ++ "      \"expected_imported_bridge_replay_count\": "
      ++ natOrNull result ActionStreamOutput.importedBridgeReplayCount ++ ",\n"
    ++ "      \"expected_planned_starts\": "
      ++ natListOrNull result ActionStreamOutput.plannedStarts ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (match result with | Except.ok _ => true | Except.error _ => false)
      ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_stream_effect_cases\": [\n"
    ++ actionStreamEffectCaseJson "valid-two-action-stream"
      validTwoActionStream ++ ",\n"
    ++ actionStreamEffectCaseJson "empty-stream"
      emptyStream ++ ",\n"
    ++ actionStreamEffectCaseJson "cross-action-duplicate-nullifier-rejected"
      crossActionDuplicateNullifier ++ ",\n"
    ++ actionStreamEffectCaseJson "within-action-duplicate-nullifier-rejected"
      withinActionDuplicateNullifier ++ ",\n"
    ++ actionStreamEffectCaseJson "prior-spent-duplicate-nullifier-rejected"
      priorSpentDuplicateNullifier ++ ",\n"
    ++ actionStreamEffectCaseJson "zero-nullifier-second-action-rejected"
      zeroNullifierSecondAction ++ ",\n"
    ++ actionStreamEffectCaseJson "cross-action-bridge-replay-duplicate-rejected"
      crossActionBridgeReplayDuplicate ++ ",\n"
    ++ actionStreamEffectCaseJson "prior-consumed-bridge-replay-duplicate-rejected"
      priorConsumedBridgeReplayDuplicate ++ ",\n"
    ++ actionStreamEffectCaseJson "second-action-commitment-overflow-rejected"
      secondActionCommitmentOverflow ++ ",\n"
    ++ actionStreamEffectCaseJson "count-mismatch-precedes-duplicate"
      countMismatchPrecedesDuplicate ++ ",\n"
    ++ actionStreamEffectCaseJson "overflow-precedes-nullifier"
      overflowPrecedesNullifier ++ ",\n"
    ++ actionStreamEffectCaseJson "nullifier-precedes-bridge-replay"
      nullifierPrecedesBridgeReplay ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

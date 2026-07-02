import Hegemon.Native.PendingActionFieldProjectionVectors

open Hegemon.Native.PendingActionFieldProjectionVectors

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def jsonString (value : String) : String :=
  "\"" ++ value ++ "\""

def rowRefJson (row : ProjectionRowRef) : String :=
  "        {\n"
    ++ "          \"action_index\": " ++ toString row.actionIndex ++ ",\n"
    ++ "          \"offset\": " ++ toString row.offset ++ ",\n"
    ++ "          \"commitment_index\": " ++ toString row.commitmentIndex ++ "\n"
    ++ "        }"

def rowRefListTailJson : List ProjectionRowRef -> String
  | [] => ""
  | head :: tail => ",\n" ++ rowRefJson head ++ rowRefListTailJson tail

def rowRefListJson : List ProjectionRowRef -> String
  | [] => "[]"
  | head :: tail =>
      "[\n" ++ rowRefJson head ++ rowRefListTailJson tail ++ "\n      ]"

def natListTailJson : List Nat -> String
  | [] => ""
  | head :: tail => ", " ++ toString head ++ natListTailJson tail

def natListJson : List Nat -> String
  | [] => "[]"
  | head :: tail => "[" ++ toString head ++ natListTailJson tail ++ "]"

def actionSpecJson (action : ProjectionActionSpec) : String :=
  "        {\n"
    ++ "          \"fixture_name\": " ++ jsonString action.fixtureName ++ ",\n"
    ++ "          \"commitment_count\": "
      ++ toString action.commitmentCount ++ ",\n"
    ++ "          \"nullifier_count\": "
      ++ toString action.nullifierCount ++ ",\n"
    ++ "          \"ciphertext_count\": "
      ++ toString action.ciphertextCount ++ ",\n"
    ++ "          \"has_bridge_replay\": "
      ++ boolJson action.hasBridgeReplay ++ "\n"
    ++ "        }"

def actionSpecListTailJson : List ProjectionActionSpec -> String
  | [] => ""
  | head :: tail => ",\n" ++ actionSpecJson head ++ actionSpecListTailJson tail

def actionSpecListJson : List ProjectionActionSpec -> String
  | [] => "[]"
  | head :: tail =>
      "[\n" ++ actionSpecJson head ++ actionSpecListTailJson tail ++ "\n      ]"

def projectionCaseJson (case : ProjectionCase) : String :=
  let rows := case.expectedRows
  "    {\n"
    ++ "      \"name\": " ++ jsonString case.name ++ ",\n"
    ++ "      \"actions\": " ++ actionSpecListJson case.actions ++ ",\n"
    ++ "      \"expected_commitment_rows\": "
      ++ rowRefListJson rows.commitmentRows ++ ",\n"
    ++ "      \"expected_nullifier_rows\": "
      ++ rowRefListJson rows.nullifierRows ++ ",\n"
    ++ "      \"expected_bridge_replay_rows\": "
      ++ natListJson rows.bridgeReplayRows ++ ",\n"
    ++ "      \"expected_ciphertext_index_rows\": "
      ++ rowRefListJson rows.ciphertextIndexRows ++ ",\n"
    ++ "      \"expected_ciphertext_archive_rows\": "
      ++ rowRefListJson rows.ciphertextArchiveRows ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (projectionCaseAccepts case) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"pending_action_field_projection_cases\": [\n"
    ++ projectionCaseJson sidecarOnlyCase ++ ",\n"
    ++ projectionCaseJson mixedCanonicalCase ++ ",\n"
    ++ projectionCaseJson bridgeFirstCase ++ ",\n"
    ++ projectionCaseJson twoSidecarCase ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

import Hegemon.Native.MinedWorkAdmission

open Hegemon.Native.MinedWorkAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option MinedWorkReject -> String
  | none => "null"
  | some MinedWorkReject.parentHashMismatch => "\"parent_hash_mismatch\""
  | some MinedWorkReject.heightNotNext => "\"height_not_next\""

def minedWorkCaseJson (name : String) (input : MinedWorkInput) : String :=
  let result := evaluateMinedWorkRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"best_height\": " ++ toString input.bestHeight ++ ",\n"
    ++ "      \"work_height\": " ++ toString input.workHeight ++ ",\n"
    ++ "      \"parent_hash_matches\": " ++ boolJson input.parentHashMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"mined_work_admission_cases\": [\n"
    ++ minedWorkCaseJson "valid-mined-work" valid ++ ",\n"
    ++ minedWorkCaseJson "parent-hash-mismatch-rejected" parentMismatch ++ ",\n"
    ++ minedWorkCaseJson "height-mismatch-rejected" heightMismatch ++ ",\n"
    ++ minedWorkCaseJson "height-overflow-rejected" heightOverflow ++ ",\n"
    ++ minedWorkCaseJson "parent-mismatch-precedes-height-failure"
      parent_mismatch_precedes_height_failure_input ++ ",\n"
    ++ minedWorkCaseJson "max-predecessor-accepts-max-height"
      maxPredecessorAcceptsMaxHeight ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

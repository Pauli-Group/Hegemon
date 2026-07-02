import Hegemon.Native.ActionHashAdmission

open Hegemon.Native.ActionHashAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option AdmissionReject -> String
  | none => "null"
  | some AdmissionReject.actionCountMismatch => "\"action_count_mismatch\""
  | some AdmissionReject.actionHashMismatch => "\"action_hash_mismatch\""
  | some AdmissionReject.duplicateActionHash => "\"duplicate_action_hash\""

def actionHashAdmissionCaseJson (name : String) (input : AdmissionInput) : String :=
  let result := evaluateAdmissionRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"action_count_matches\": " ++ boolJson input.actionCountMatches ++ ",\n"
    ++ "      \"action_hashes_match\": " ++ boolJson input.actionHashesMatch ++ ",\n"
    ++ "      \"action_hashes_unique\": " ++ boolJson input.actionHashesUnique ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def validInput : AdmissionInput :=
  {
    actionCountMatches := true,
    actionHashesMatch := true,
    actionHashesUnique := true
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_hash_admission_cases\": [\n"
    ++ actionHashAdmissionCaseJson "valid-action-hash-admission" validInput ++ ",\n"
    ++ actionHashAdmissionCaseJson "action-count-mismatch-rejected"
      { validInput with actionCountMatches := false } ++ ",\n"
    ++ actionHashAdmissionCaseJson "action-hash-mismatch-rejected"
      { validInput with actionHashesMatch := false } ++ ",\n"
    ++ actionHashAdmissionCaseJson "duplicate-action-hash-rejected"
      { validInput with actionHashesUnique := false } ++ ",\n"
    ++ actionHashAdmissionCaseJson "hash-mismatch-precedes-duplicate"
      { validInput with actionHashesMatch := false, actionHashesUnique := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

import Hegemon.Native.RecursiveArtifactContextAdmission

open Hegemon.Native.RecursiveArtifactContextAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson :
    Except RecursiveArtifactContextReject Nat -> String
  | Except.ok _ => "null"
  | Except.error RecursiveArtifactContextReject.heightNotNext =>
      "\"height_not_next\""

def heightJson :
    Except RecursiveArtifactContextReject Nat -> String
  | Except.ok height => toString height
  | Except.error _ => "null"

def recursiveArtifactContextCaseJson
    (name : String)
    (input : RecursiveArtifactContextInput) : String :=
  let result := evaluateRecursiveArtifactContext input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"best_height\": " ++ toString input.bestHeight ++ ",\n"
    ++ "      \"expected_height\": " ++ heightJson result ++ ",\n"
    ++ "      \"expected_valid\": " ++
      boolJson (match result with | Except.ok _ => true | Except.error _ => false) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"recursive_artifact_context_admission_cases\": [\n"
    ++ recursiveArtifactContextCaseJson "valid-context" valid ++ ",\n"
    ++ recursiveArtifactContextCaseJson "height-overflow-rejected"
      heightOverflow ++ ",\n"
    ++ recursiveArtifactContextCaseJson
      "max-predecessor-accepts-max-height"
      maxPredecessorAcceptsMaxHeight ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

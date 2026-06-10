import Hegemon.Release.PqBinaryPolicy

open Hegemon.Release.PqBinaryPolicy

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option PqBinaryReject -> String
  | none => "null"
  | some PqBinaryReject.sourceForbidden => "\"source_forbidden\""
  | some PqBinaryReject.dependencyForbidden => "\"dependency_forbidden\""
  | some PqBinaryReject.binaryForbidden => "\"binary_forbidden\""

def pqBinaryPolicyCaseJson (name : String) (input : PqBinaryAuditInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"source_scan_clean\": " ++ boolJson input.sourceScanClean ++ ",\n"
    ++ "      \"dependency_scan_clean\": " ++ boolJson input.dependencyScanClean ++ ",\n"
    ++ "      \"binary_scan_clean\": " ++ boolJson input.binaryScanClean ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (pqBinaryAuditAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (pqBinaryAuditRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"release_pq_binary_policy_cases\": [\n"
    ++ pqBinaryPolicyCaseJson "all-scans-clean-accepts"
      allScansClean ++ ",\n"
    ++ pqBinaryPolicyCaseJson "source-forbidden-rejects"
      sourceForbidden ++ ",\n"
    ++ pqBinaryPolicyCaseJson "dependency-forbidden-after-source-clean"
      dependencyForbidden ++ ",\n"
    ++ pqBinaryPolicyCaseJson "binary-forbidden-after-source-dependency-clean"
      binaryForbidden ++ ",\n"
    ++ pqBinaryPolicyCaseJson "source-forbidden-precedes-all"
      {
        sourceScanClean := false,
        dependencyScanClean := false,
        binaryScanClean := false
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

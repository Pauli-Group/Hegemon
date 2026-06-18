import Hegemon.Privacy.CiphertextArchiveBoundary

open Hegemon.Privacy.CiphertextArchiveBoundary

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CiphertextArchiveBoundaryRejection -> String
  | none => "null"
  | some CiphertextArchiveBoundaryRejection.indexGap => "\"index_gap\""
  | some CiphertextArchiveBoundaryRejection.indexBeyondLeafCount =>
      "\"index_beyond_leaf_count\""

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ rest.foldl
        (fun acc value => acc ++ ", " ++ toString value)
        (toString first) ++ "]"

def caseJson (case : CiphertextArchiveBoundaryCase) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ case.name ++ "\",\n"
    ++ "      \"leaf_count\": " ++ toString case.leafCount ++ ",\n"
    ++ "      \"archive_indices\": " ++ natArrayJson case.archiveIndices ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (accepts case) ++ ",\n"
    ++ "      \"expected_error\": " ++ rejectionJson (firstRejection case) ++ "\n"
    ++ "    }"

def casesJson : List CiphertextArchiveBoundaryCase -> String
  | [] => ""
  | [case] => caseJson case
  | case :: rest => caseJson case ++ ",\n" ++ casesJson rest

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"ciphertext_archive_boundary_cases\": [\n"
    ++ casesJson allCases ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

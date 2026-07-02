import Hegemon.Native.ActionRootTranscript

open Hegemon
open Hegemon.Native.ActionRootTranscript

def stringArrayJson : List String -> String
  | [] => "[]"
  | first :: rest =>
      "[\"" ++ first ++ "\"" ++ rest.foldl (fun acc value => acc ++ ", \"" ++ value ++ "\"") "" ++ "]"

def actionRootCaseJson (name : String) (actionHashes : List (List Byte)) : String :=
  let preimage := actionRootPreimage actionHashes
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"action_hashes_hex\": "
    ++ stringArrayJson (actionHashes.map hexBytes) ++ ",\n"
    ++ "      \"expected_preimage_hex\": \"" ++ hexBytes preimage ++ "\",\n"
    ++ "      \"expected_preimage_len\": " ++ toString preimage.length ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_root_transcript_cases\": [\n"
    ++ actionRootCaseJson "empty-action-root" [] ++ ",\n"
    ++ actionRootCaseJson "single-action-hash" [sampleHashA] ++ ",\n"
    ++ actionRootCaseJson "two-action-hashes-ordered" [sampleHashA, sampleHashB] ++ ",\n"
    ++ actionRootCaseJson "two-action-hashes-reversed" [sampleHashB, sampleHashA] ++ ",\n"
    ++ actionRootCaseJson "max-byte-action-hash" [maxHash] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

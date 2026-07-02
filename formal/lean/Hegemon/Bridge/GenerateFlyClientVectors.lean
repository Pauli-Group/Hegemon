import Hegemon.Bridge.FlyClient

open Hegemon
open Hegemon.Bridge.FlyClient

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ toString first ++ rest.foldl (fun acc value => acc ++ ", " ++ toString value) "" ++ "]"

def transcriptCaseJson (name : String) (input : TranscriptInput) : String :=
  let preimage := transcriptPreimage input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"mmr_root_hex\": \"" ++ hexBytes input.mmrRoot ++ "\",\n"
    ++ "      \"tip_hash_hex\": \"" ++ hexBytes input.tipHash ++ "\",\n"
    ++ "      \"message_header_hash_hex\": \"" ++ hexBytes input.messageHeaderHash ++ "\",\n"
    ++ "      \"start_inclusive\": " ++ toString input.startInclusive ++ ",\n"
    ++ "      \"end_exclusive\": " ++ toString input.endExclusive ++ ",\n"
    ++ "      \"sample_index\": " ++ toString input.sampleIndex ++ ",\n"
    ++ "      \"expected_preimage_hex\": \"" ++ hexBytes preimage ++ "\",\n"
    ++ "      \"expected_preimage_len\": " ++ toString preimage.length ++ "\n"
    ++ "    }"

def indexCaseJson
    (name : String)
    (startInclusive endExclusive sampleCount : Nat)
    (digestPrefixes : List Nat) : String :=
  let heights := sampleHeightsFromPrefixes
    startInclusive
    endExclusive
    sampleCount
    digestPrefixes
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"start_inclusive\": " ++ toString startInclusive ++ ",\n"
    ++ "      \"end_exclusive\": " ++ toString endExclusive ++ ",\n"
    ++ "      \"sample_count\": " ++ toString sampleCount ++ ",\n"
    ++ "      \"digest_prefix_values\": " ++ natArrayJson digestPrefixes ++ ",\n"
    ++ "      \"expected_sample_heights\": " ++ natArrayJson heights ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"flyclient_transcript_cases\": [\n"
    ++ transcriptCaseJson "valid-transcript" validTranscript ++ ",\n"
    ++ transcriptCaseJson "max-u32-sample-index-transcript" maxIndexTranscript ++ "\n"
    ++ "  ],\n"
    ++ "  \"flyclient_index_cases\": [\n"
    ++ indexCaseJson "modulo-sample-height" 11 14 1 [5] ++ ",\n"
    ++ indexCaseJson "zero-prefix-starts-at-range-start" 10 20 1 [0] ++ ",\n"
    ++ indexCaseJson "max-u64-prefix-modulo" 10 20 1 [18446744073709551615] ++ ",\n"
    ++ indexCaseJson "duplicate-samples-are-preserved" 10 20 3 [0, 10, 20] ++ ",\n"
    ++ indexCaseJson "prefixes-truncate-to-sample-count" 10 20 2 [0, 1, 2] ++ ",\n"
    ++ indexCaseJson "zero-sample-count-empty" 10 20 0 [0, 1, 2] ++ ",\n"
    ++ indexCaseJson "equal-range-empty" 10 10 3 [7, 8, 9] ++ ",\n"
    ++ indexCaseJson "reversed-range-empty" 20 10 3 [7, 8, 9] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

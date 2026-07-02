import Hegemon.Bridge.HeaderMmrTranscript

open Hegemon
open Hegemon.Bridge.HeaderMmrTranscript

def stringArrayJson : List String -> String
  | [] => "[]"
  | first :: rest =>
      "[\"" ++ first ++ "\"" ++ rest.foldl (fun acc value => acc ++ ", \"" ++ value ++ "\"") "" ++ "]"

def parentCaseJson (name : String) (input : ParentInput) : String :=
  let preimage := parentPreimage input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"level\": " ++ toString input.level ++ ",\n"
    ++ "      \"left_hex\": \"" ++ hexBytes input.left ++ "\",\n"
    ++ "      \"right_hex\": \"" ++ hexBytes input.right ++ "\",\n"
    ++ "      \"expected_preimage_hex\": \"" ++ hexBytes preimage ++ "\",\n"
    ++ "      \"expected_preimage_len\": " ++ toString preimage.length ++ "\n"
    ++ "    }"

def rootCaseJson (name : String) (input : RootInput) : String :=
  let preimage := rootPreimage input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"leaf_count\": " ++ toString input.leafCount ++ ",\n"
    ++ "      \"peak_hashes_hex\": " ++ stringArrayJson (input.peaks.map hexBytes) ++ ",\n"
    ++ "      \"expected_peak_count\": " ++ toString input.peaks.length ++ ",\n"
    ++ "      \"expected_preimage_hex\": \"" ++ hexBytes preimage ++ "\",\n"
    ++ "      \"expected_preimage_len\": " ++ toString preimage.length ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"header_mmr_parent_transcript_cases\": [\n"
    ++ parentCaseJson "sample-parent-level-two" sampleParent ++ ",\n"
    ++ parentCaseJson "max-u32-parent-level" maxLevelParent ++ "\n"
    ++ "  ],\n"
    ++ "  \"header_mmr_root_transcript_cases\": [\n"
    ++ rootCaseJson "empty-root" emptyRoot ++ ",\n"
    ++ rootCaseJson "two-peak-root" twoPeakRoot ++ ",\n"
    ++ rootCaseJson "reversed-two-peak-root" reversedTwoPeakRoot ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

import Hegemon.Native.BridgeWitnessBackscan

open Hegemon.Native.BridgeWitnessBackscan

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natOptionJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def rejectionJson : Option BridgeWitnessBackscanReject -> String
  | none => "null"
  | some BridgeWitnessBackscanReject.blockActionsDecodeFailed =>
      "\"block_actions_decode_failed\""
  | some BridgeWitnessBackscanReject.noBridgeMessageInBackscan =>
      "\"no_bridge_message_in_backscan\""

def entryJson (entry : BridgeWitnessBackscanEntry) : String :=
  "        {\n"
    ++ "          \"height\": " ++ toString entry.height ++ ",\n"
    ++ "          \"canonical_hash_present\": "
      ++ boolJson entry.canonicalHashPresent ++ ",\n"
    ++ "          \"block_known\": " ++ boolJson entry.blockKnown ++ ",\n"
    ++ "          \"block_actions_decoded\": "
      ++ boolJson entry.blockActionsDecoded ++ ",\n"
    ++ "          \"message_index_in_bounds\": "
      ++ boolJson entry.messageIndexInBounds ++ "\n"
    ++ "        }"

def entriesJson : List BridgeWitnessBackscanEntry -> String
  | [] => ""
  | [entry] => entryJson entry
  | entry :: rest => entryJson entry ++ ",\n" ++ entriesJson rest

def bridgeWitnessBackscanCaseJson
    (name : String)
    (entries : List BridgeWitnessBackscanEntry) : String :=
  let result := evaluateBridgeWitnessBackscan entries
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"entries\": [\n"
    ++ entriesJson entries ++ "\n"
    ++ "      ],\n"
    ++ "      \"expected_valid\": " ++ boolJson result.isOk ++ ",\n"
    ++ "      \"expected_selected_height\": "
      ++ natOptionJson (bridgeWitnessBackscanSelectedHeight entries) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (bridgeWitnessBackscanRejection entries) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_witness_backscan_cases\": [\n"
    ++ bridgeWitnessBackscanCaseJson
      "newest-eligible-candidate-wins" newestEligible ++ ",\n"
    ++ bridgeWitnessBackscanCaseJson
      "skipped-records-and-index-misses-reach-older-match"
      skippedBeforeOlderEligible ++ ",\n"
    ++ bridgeWitnessBackscanCaseJson
      "decode-failure-precedes-older-match"
      decodeFailureBeforeOlderEligible ++ ",\n"
    ++ bridgeWitnessBackscanCaseJson
      "no-eligible-bridge-message-rejected"
      noEligibleBridgeMessage ++ ",\n"
    ++ bridgeWitnessBackscanCaseJson
      "empty-backscan-rejected" [] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

import Hegemon.Native.SyncRawIngress

open Hegemon.Native.SyncResponseImport
open Hegemon.Native.SyncRawIngress

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson : List Nat -> String
  | [] => "[]"
  | head :: tail =>
      "[" ++ toString head ++ String.join (tail.map fun value => ", " ++ toString value) ++ "]"

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def kindJson : SyncRawIngressKind -> String
  | SyncRawIngressKind.request => "\"request\""
  | SyncRawIngressKind.response => "\"response\""
  | SyncRawIngressKind.decodeError => "\"decode_error\""

def rejectionJson : Option SyncRawIngressReject -> String
  | none => "null"
  | some SyncRawIngressReject.wireDecodeRejected => "\"wire_decode_rejected\""
  | some SyncRawIngressReject.responseBlockCountTooLarge =>
      "\"response_block_count_too_large\""

def outcomeJson : SyncResponseImportOutcome -> String
  | SyncResponseImportOutcome.imported => "\"imported\""
  | SyncResponseImportOutcome.alreadyKnown => "\"already_known\""
  | SyncResponseImportOutcome.error => "\"error\""

def outcomeListJson : List SyncResponseImportOutcome -> String
  | [] => "[]"
  | head :: tail =>
      "[" ++ outcomeJson head
        ++ String.join (tail.map fun value => ", " ++ outcomeJson value)
        ++ "]"

def optionRangeFromJson : Option (Nat × Nat) -> String
  | none => "null"
  | some range => optionNatJson (some range.fst)

def optionRangeToJson : Option (Nat × Nat) -> String
  | none => "null"
  | some range => optionNatJson (some range.snd)

def caseJson (name : String) (case : SyncRawIngressCase) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"raw_bytes\": " ++ natListJson case.rawBytes ++ ",\n"
    ++ "      \"expected_kind\": " ++ kindJson case.kind ++ ",\n"
    ++ "      \"from_height\": " ++ toString case.fromHeight ++ ",\n"
    ++ "      \"to_height\": " ++ toString case.toHeight ++ ",\n"
    ++ "      \"request_best_height\": " ++ toString case.requestBestHeight ++ ",\n"
    ++ "      \"max_blocks\": " ++ toString case.maxBlocks ++ ",\n"
    ++ "      \"response_best_height\": " ++ toString case.responseBestHeight ++ ",\n"
    ++ "      \"response_heights\": " ++ natListJson case.responseHeights ++ ",\n"
    ++ "      \"outcomes\": " ++ outcomeListJson case.outcomes ++ ",\n"
    ++ "      \"local_best_height\": " ++ toString case.localBestHeight ++ ",\n"
    ++ "      \"peer_best_height\": " ++ toString case.peerBestHeight ++ ",\n"
    ++ "      \"expected_has_range\": " ++ boolJson case.expectedRange.isSome ++ ",\n"
    ++ "      \"expected_from_height\": " ++ optionRangeFromJson case.expectedRange ++ ",\n"
    ++ "      \"expected_to_height\": " ++ optionRangeToJson case.expectedRange ++ ",\n"
    ++ "      \"expected_sorted_heights\": "
      ++ natListJson case.expectedSortedHeights ++ ",\n"
    ++ "      \"expected_attempted_blocks\": "
      ++ toString case.expectedAttemptedBlocks ++ ",\n"
    ++ "      \"expected_imported_blocks\": "
      ++ toString case.expectedImportedBlocks ++ ",\n"
    ++ "      \"expected_stopped_on_error\": "
      ++ boolJson case.expectedStoppedOnError ++ ",\n"
    ++ "      \"expected_request_more\": "
      ++ boolJson case.expectedRequestMore ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (case.expectedReject == none) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson case.expectedReject ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"sync_raw_ingress_cases\": [\n"
    ++ caseJson "valid-raw-sync-request-capped-range" validRawRequest ++ ",\n"
    ++ caseJson "raw-sync-request-trailing-rejected" trailingRawRequest ++ ",\n"
    ++ caseJson "raw-sync-request-missing-marker-rejected"
      missingMarkerRawRequest ++ ",\n"
    ++ caseJson "raw-sync-unknown-variant-rejected"
      unknownVariantRawMessage ++ ",\n"
    ++ caseJson "valid-empty-raw-sync-response" validEmptyRawResponse ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

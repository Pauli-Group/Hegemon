import Hegemon.Native.SyncResponseImport

open Hegemon.Native.SyncResponseImport

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option SyncResponseImportReject -> String
  | none => "null"
  | some SyncResponseImportReject.responseBlockCountTooLarge =>
      "\"response_block_count_too_large\""
  | some SyncResponseImportReject.outcomeCountOverResponse =>
      "\"outcome_count_over_response\""

def outcomeJson : SyncResponseImportOutcome -> String
  | SyncResponseImportOutcome.imported => "\"imported\""
  | SyncResponseImportOutcome.alreadyKnown => "\"already_known\""
  | SyncResponseImportOutcome.error => "\"error\""

def natJson (value : Nat) : String :=
  toString value

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ natJson first ++ rest.foldl
        (fun acc value => acc ++ ", " ++ natJson value) "" ++ "]"

def outcomeArrayJson : List SyncResponseImportOutcome -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ outcomeJson first ++ rest.foldl
        (fun acc value => acc ++ ", " ++ outcomeJson value) "" ++ "]"

def importCaseJson (name : String) (input : SyncResponseImportInput) : String :=
  let rejection := evaluateSyncResponseImportRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"response_heights\": "
      ++ natArrayJson input.responseHeights ++ ",\n"
    ++ "      \"max_blocks\": " ++ natJson input.maxBlocks ++ ",\n"
    ++ "      \"outcomes\": " ++ outcomeArrayJson input.outcomes ++ ",\n"
    ++ "      \"local_best_height\": "
      ++ natJson input.localBestHeight ++ ",\n"
    ++ "      \"peer_best_height\": "
      ++ natJson input.peerBestHeight ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (syncResponseImportAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectJson rejection ++ ",\n"
    ++ "      \"expected_sorted_heights\": "
      ++ natArrayJson (sortHeights input.responseHeights) ++ ",\n"
    ++ "      \"expected_attempted_blocks\": "
      ++ natJson (attemptedUntilStop input.outcomes) ++ ",\n"
    ++ "      \"expected_imported_blocks\": "
      ++ natJson (importedUntilStop input.outcomes) ++ ",\n"
    ++ "      \"expected_stopped_on_error\": "
      ++ boolJson (stoppedOnError input.outcomes) ++ ",\n"
    ++ "      \"expected_request_more\": "
      ++ boolJson (shouldRequestMore input) ++ "\n"
    ++ "    }"

def importResponseExactLimit : SyncResponseImportInput :=
  {
    responseHeights := List.range 512,
    maxBlocks := 512,
    outcomes :=
      (List.range 512).map
        (fun _ => SyncResponseImportOutcome.alreadyKnown),
    localBestHeight := 512,
    peerBestHeight := 512
  }

def importResponsePeerCaughtUp : SyncResponseImportInput :=
  {
    responseHeights := [2, 1],
    maxBlocks := 512,
    outcomes := [
      SyncResponseImportOutcome.imported,
      SyncResponseImportOutcome.imported
    ],
    localBestHeight := 9,
    peerBestHeight := 9
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"sync_response_import_cases\": [\n"
    ++ importCaseJson "sync-response-import-unsorted"
      importResponseUnsorted ++ ",\n"
    ++ importCaseJson "sync-response-import-stops-on-error"
      importResponseStopsOnError ++ ",\n"
    ++ importCaseJson "sync-response-import-empty-peer-ahead"
      importResponseEmptyPeerAhead ++ ",\n"
    ++ importCaseJson "sync-response-import-exact-limit"
      importResponseExactLimit ++ ",\n"
    ++ importCaseJson "sync-response-import-peer-caught-up"
      importResponsePeerCaughtUp ++ ",\n"
    ++ importCaseJson "sync-response-import-over-limit"
      importResponseOverLimit ++ ",\n"
    ++ importCaseJson "sync-response-import-outcome-over-response"
      importResponseOutcomeOverResponse ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

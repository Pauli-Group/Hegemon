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
  | some SyncResponseImportReject.outcomeTraceIncomplete =>
      "\"outcome_trace_incomplete\""
  | some SyncResponseImportReject.postClassificationOutcomeInvalid =>
      "\"post_classification_outcome_invalid\""

def outcomeJson : SyncResponseImportOutcome -> String
  | SyncResponseImportOutcome.imported => "\"imported\""
  | SyncResponseImportOutcome.alreadyKnown => "\"already_known\""
  | SyncResponseImportOutcome.storedNoncanonical =>
      "\"stored_noncanonical\""
  | SyncResponseImportOutcome.missingParent => "\"missing_parent\""
  | SyncResponseImportOutcome.error => "\"error\""

def postClassificationOutcomeJson :
    SyncResponsePostClassificationOutcome -> String
  | .noIssue => "\"none\""
  | .missingAncestor => "\"missing_ancestor\""
  | .corrupt => "\"corrupt\""

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

def importCaseJson
    (name : String)
    (input : SyncResponseImportInput)
    (plan : SyncResponseRecoveryPlan) : String :=
  let rejection := evaluateSyncResponseImportRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"response_heights\": "
      ++ natArrayJson input.responseHeights ++ ",\n"
    ++ "      \"max_blocks\": " ++ natJson input.maxBlocks ++ ",\n"
    ++ "      \"outcomes\": " ++ outcomeArrayJson input.outcomes ++ ",\n"
    ++ "      \"post_classification_outcome\": "
      ++ postClassificationOutcomeJson input.postClassificationOutcome ++ ",\n"
    ++ "      \"local_best_height\": "
      ++ natJson input.localBestHeight ++ ",\n"
    ++ "      \"peer_best_height\": "
      ++ natJson input.peerBestHeight ++ ",\n"
    ++ "      \"current_request_from_height\": "
      ++ natJson plan.currentFromHeight ++ ",\n"
    ++ "      \"current_request_to_height\": "
      ++ natJson plan.currentToHeight ++ ",\n"
    ++ "      \"candidate_request_available\": "
      ++ boolJson plan.candidateAvailable ++ ",\n"
    ++ "      \"candidate_request_from_height\": "
      ++ natJson plan.candidateFromHeight ++ ",\n"
    ++ "      \"candidate_request_to_height\": "
      ++ natJson plan.candidateToHeight ++ ",\n"
    ++ "      \"backoff_scheduled\": "
      ++ boolJson plan.backoffScheduled ++ ",\n"
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
    ++ "      \"expected_stored_noncanonical_blocks\": "
      ++ natJson (storedNoncanonicalUntilStop input.outcomes) ++ ",\n"
    ++ "      \"expected_stopped_on_error\": "
      ++ boolJson (responseStoppedOnError input) ++ ",\n"
    ++ "      \"expected_stopped_on_missing_parent\": "
      ++ boolJson (responseStoppedOnMissingParent input) ++ ",\n"
    ++ "      \"expected_completed_without_canonical_progress\": "
      ++ boolJson (completedWithoutCanonicalProgress input) ++ ",\n"
    ++ "      \"expected_request_more\": "
      ++ boolJson (shouldRequestMore input) ++ ",\n"
    ++ "      \"expected_recovery_required\": "
      ++ boolJson (recoveryRequired input) ++ ",\n"
    ++ "      \"expected_backoff_required\": "
      ++ boolJson (backoffRequired input) ++ ",\n"
    ++ "      \"expected_recovery_range_changed\": "
      ++ boolJson (recoveryRangeChanged plan) ++ ",\n"
    ++ "      \"expected_useful_recovery_or_backoff\": "
      ++ boolJson (usefulRecoveryOrBackoff plan) ++ ",\n"
    ++ "      \"expected_immediate_request_allowed\": "
      ++ boolJson (immediateRequestAllowed input plan) ++ ",\n"
    ++ "      \"expected_follow_up_allowed\": "
      ++ boolJson (followUpAllowed input plan) ++ "\n"
    ++ "    }"

def postClassificationMissingParentCaseJson
    (name : String)
    (input : SyncResponsePostClassificationMissingParentInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"had_blocks\": " ++ boolJson input.hadBlocks ++ ",\n"
    ++ "      \"attempted_blocks\": "
      ++ natJson input.attemptedBlocks ++ ",\n"
    ++ "      \"response_block_count\": "
      ++ natJson input.responseBlockCount ++ ",\n"
    ++ "      \"imported_blocks\": "
      ++ natJson input.importedBlocks ++ ",\n"
    ++ "      \"stored_noncanonical_blocks\": "
      ++ natJson input.storedNoncanonicalBlocks ++ ",\n"
    ++ "      \"stopped_on_error\": "
      ++ boolJson input.stoppedOnError ++ ",\n"
    ++ "      \"stopped_on_missing_parent\": "
      ++ boolJson input.stoppedOnMissingParent ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (postClassificationMissingParentAccepts input) ++ "\n"
    ++ "    }"

def noRecoveryPlan : SyncResponseRecoveryPlan :=
  {
    currentFromHeight := 0,
    currentToHeight := 0,
    candidateAvailable := false,
    candidateFromHeight := 0,
    candidateToHeight := 0,
    backoffScheduled := false
  }

def importResponseExactLimit : SyncResponseImportInput :=
  {
    responseHeights := List.range 512,
    maxBlocks := 512,
    outcomes :=
      (List.range 512).map
        (fun _ => SyncResponseImportOutcome.alreadyKnown),
    postClassificationOutcome := .noIssue,
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
    postClassificationOutcome := .noIssue,
    localBestHeight := 9,
    peerBestHeight := 9
  }

def exactLimitRecoveryPlan : SyncResponseRecoveryPlan :=
  {
    currentFromHeight := 1,
    currentToHeight := 512,
    candidateAvailable := true,
    candidateFromHeight := 0,
    candidateToHeight := 511,
    backoffScheduled := false
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 3,\n"
    ++ "  \"sync_response_import_cases\": [\n"
    ++ importCaseJson "sync-response-import-unsorted"
      importResponseUnsorted noRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-stops-on-error"
      importResponseStopsOnError deferredBackoffPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-missing-parent-same-range"
      importResponseStopsOnMissingParent sameRangeRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-missing-parent-changed-range"
      importResponseStopsOnMissingParent changedAncestorRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-all-known-peer-ahead"
      importResponseAllKnownPeerAhead changedAncestorRecoveryPlan ++ ",\n"
    ++ importCaseJson
      "sync-response-import-all-known-post-classification-missing-ancestor"
      importResponseAllKnownMissingAncestor changedAncestorRecoveryPlan ++ ",\n"
    ++ importCaseJson
      "sync-response-import-all-known-post-classification-corrupt"
      importResponseAllKnownCorrupt deferredBackoffPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-stored-noncanonical-peer-ahead"
      importResponseStoredNoncanonicalPeerAhead
      changedAncestorRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-known-imported-known-peer-ahead"
      importResponseKnownImportedKnownPeerAhead noRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-known-stored-known-peer-ahead"
      importResponseKnownStoredKnownPeerAhead changedAncestorRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-empty-peer-ahead"
      importResponseEmptyPeerAhead noRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-exact-limit"
      importResponseExactLimit exactLimitRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-peer-caught-up"
      importResponsePeerCaughtUp noRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-over-limit"
      importResponseOverLimit noRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-outcome-over-response"
      importResponseOutcomeOverResponse noRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-incomplete-nonterminal"
      importResponseIncompleteNonterminal noRecoveryPlan ++ ",\n"
    ++ importCaseJson "sync-response-import-invalid-post-classification"
      importResponseInvalidPostClassification noRecoveryPlan ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_response_post_classification_missing_parent_cases\": [\n"
    ++ postClassificationMissingParentCaseJson
      "post-classification-missing-parent-full-trace"
      postClassificationMissingParentReady ++ ",\n"
    ++ postClassificationMissingParentCaseJson
      "post-classification-missing-parent-incomplete-trace"
      { postClassificationMissingParentReady with attemptedBlocks := 2 } ++ ",\n"
    ++ postClassificationMissingParentCaseJson
      "post-classification-missing-parent-without-blocks"
      { postClassificationMissingParentReady with hadBlocks := false } ++ ",\n"
    ++ postClassificationMissingParentCaseJson
      "post-classification-missing-parent-after-error"
      { postClassificationMissingParentReady with stoppedOnError := true } ++ ",\n"
    ++ postClassificationMissingParentCaseJson
      "post-classification-missing-parent-after-import"
      { postClassificationMissingParentReady with importedBlocks := 1 } ++ ",\n"
    ++ postClassificationMissingParentCaseJson
      "post-classification-missing-parent-after-noncanonical-store"
      { postClassificationMissingParentReady with
        storedNoncanonicalBlocks := 1 } ++ ",\n"
    ++ postClassificationMissingParentCaseJson
      "post-classification-missing-parent-after-missing-parent"
      { postClassificationMissingParentReady with
        stoppedOnMissingParent := true } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

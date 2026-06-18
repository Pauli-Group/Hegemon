import Hegemon.Native.SyncAdmission

namespace Hegemon
namespace Native
namespace SyncResponseImport

open Hegemon.Native.SyncAdmission

inductive SyncResponseImportReject where
  | responseBlockCountTooLarge
  | outcomeCountOverResponse
deriving DecidableEq, Repr

inductive SyncResponseImportOutcome where
  | imported
  | alreadyKnown
  | error
deriving DecidableEq, Repr

structure SyncResponseImportInput where
  responseHeights : List Nat
  maxBlocks : Nat
  outcomes : List SyncResponseImportOutcome
  localBestHeight : Nat
  peerBestHeight : Nat
deriving DecidableEq, Repr

def responseCountInput
    (input : SyncResponseImportInput) : SyncResponseCountInput :=
  {
    blockCount := input.responseHeights.length,
    maxBlocks := input.maxBlocks
  }

def responseHasBlocks (input : SyncResponseImportInput) : Bool :=
  input.responseHeights.isEmpty = false

def shouldRequestMore (input : SyncResponseImportInput) : Bool :=
  responseHasBlocks input
    && decide (input.localBestHeight < input.peerBestHeight)

def insertHeight (height : Nat) : List Nat -> List Nat
  | [] => [height]
  | current :: rest =>
      if height ≤ current then
        height :: current :: rest
      else
        current :: insertHeight height rest

def sortHeights : List Nat -> List Nat
  | [] => []
  | height :: rest => insertHeight height (sortHeights rest)

def attemptedUntilStop : List SyncResponseImportOutcome -> Nat
  | [] => 0
  | SyncResponseImportOutcome.imported :: rest =>
      attemptedUntilStop rest + 1
  | SyncResponseImportOutcome.alreadyKnown :: rest =>
      attemptedUntilStop rest + 1
  | SyncResponseImportOutcome.error :: _ => 1

def importedUntilStop : List SyncResponseImportOutcome -> Nat
  | [] => 0
  | SyncResponseImportOutcome.imported :: rest =>
      importedUntilStop rest + 1
  | SyncResponseImportOutcome.alreadyKnown :: rest =>
      importedUntilStop rest
  | SyncResponseImportOutcome.error :: _ => 0

def stoppedOnError : List SyncResponseImportOutcome -> Bool
  | [] => false
  | SyncResponseImportOutcome.imported :: rest => stoppedOnError rest
  | SyncResponseImportOutcome.alreadyKnown :: rest => stoppedOnError rest
  | SyncResponseImportOutcome.error :: _ => true

def evaluateSyncResponseImportRejection
    (input : SyncResponseImportInput) :
    Option SyncResponseImportReject :=
  if responseCountAccepts (responseCountInput input) = false then
    some SyncResponseImportReject.responseBlockCountTooLarge
  else if input.outcomes.length ≤ input.responseHeights.length then
    none
  else
    some SyncResponseImportReject.outcomeCountOverResponse

def syncResponseImportAccepts
    (input : SyncResponseImportInput) : Bool :=
  evaluateSyncResponseImportRejection input = none

structure AcceptedSyncResponseImportFacts
    (input : SyncResponseImportInput) : Prop where
  responseCountWithinLimit :
    input.responseHeights.length ≤ input.maxBlocks
  outcomeCountWithinResponse :
    input.outcomes.length ≤ input.responseHeights.length
  attemptedBlocksWithinResponse :
    attemptedUntilStop input.outcomes ≤ input.responseHeights.length
  importedBlocksWithinAttempts :
    importedUntilStop input.outcomes ≤ attemptedUntilStop input.outcomes
  importedBlocksWithinResponse :
    importedUntilStop input.outcomes ≤ input.responseHeights.length
  requestMoreIff :
    shouldRequestMore input = true ↔
      input.responseHeights.isEmpty = false
        ∧ input.localBestHeight < input.peerBestHeight

theorem attempted_until_stop_le_length
    (outcomes : List SyncResponseImportOutcome) :
    attemptedUntilStop outcomes ≤ outcomes.length := by
  induction outcomes with
  | nil =>
      simp [attemptedUntilStop]
  | cons outcome rest ih =>
      cases outcome <;> simp [attemptedUntilStop, ih] <;> omega

theorem imported_until_stop_le_attempted
    (outcomes : List SyncResponseImportOutcome) :
    importedUntilStop outcomes ≤ attemptedUntilStop outcomes := by
  induction outcomes with
  | nil =>
      simp [importedUntilStop, attemptedUntilStop]
  | cons outcome rest ih =>
      cases outcome <;>
        simp [importedUntilStop, attemptedUntilStop, ih] <;> omega

theorem should_request_more_iff
    {input : SyncResponseImportInput} :
    shouldRequestMore input = true ↔
      input.responseHeights.isEmpty = false
        ∧ input.localBestHeight < input.peerBestHeight := by
  unfold shouldRequestMore responseHasBlocks
  by_cases hasBlocks : input.responseHeights.isEmpty = false
  · by_cases peerAhead : input.localBestHeight < input.peerBestHeight <;>
      simp [hasBlocks, peerAhead]
  · by_cases peerAhead : input.localBestHeight < input.peerBestHeight <;>
      simp [hasBlocks, peerAhead]

theorem sync_response_import_acceptance_exposes_facts
    {input : SyncResponseImportInput}
    (accepted : syncResponseImportAccepts input = true) :
    AcceptedSyncResponseImportFacts input := by
  unfold syncResponseImportAccepts at accepted
  unfold evaluateSyncResponseImportRejection at accepted
  by_cases countRejected :
      responseCountAccepts (responseCountInput input) = false
  · simp [countRejected] at accepted
  · have countAccepted :
        responseCountAccepts (responseCountInput input) = true := by
      cases h : responseCountAccepts (responseCountInput input) <;>
        simp [h] at countRejected ⊢
    simp [countAccepted] at accepted
    by_cases outcomeCountWithinResponse :
        input.outcomes.length ≤ input.responseHeights.length
    · have responseCountWithinLimit :
          input.responseHeights.length ≤ input.maxBlocks := by
        simpa [responseCountInput] using
          (response_count_accepts_iff_within_limit
            (input := responseCountInput input)).mp countAccepted
      have attemptedBlocksWithinResponse :
          attemptedUntilStop input.outcomes ≤ input.responseHeights.length := by
        exact
          Nat.le_trans
            (attempted_until_stop_le_length input.outcomes)
            outcomeCountWithinResponse
      have importedBlocksWithinAttempts :
          importedUntilStop input.outcomes ≤
            attemptedUntilStop input.outcomes :=
        imported_until_stop_le_attempted input.outcomes
      have importedBlocksWithinResponse :
          importedUntilStop input.outcomes ≤
            input.responseHeights.length :=
        Nat.le_trans
          importedBlocksWithinAttempts
          attemptedBlocksWithinResponse
      exact
        {
          responseCountWithinLimit := responseCountWithinLimit,
          outcomeCountWithinResponse := outcomeCountWithinResponse,
          attemptedBlocksWithinResponse :=
            attemptedBlocksWithinResponse,
          importedBlocksWithinAttempts :=
            importedBlocksWithinAttempts,
          importedBlocksWithinResponse :=
            importedBlocksWithinResponse,
          requestMoreIff := should_request_more_iff
        }
    · simp [outcomeCountWithinResponse] at accepted

def importResponseUnsorted : SyncResponseImportInput :=
  {
    responseHeights := [5, 3, 4],
    maxBlocks := 512,
    outcomes := [
      SyncResponseImportOutcome.imported,
      SyncResponseImportOutcome.alreadyKnown,
      SyncResponseImportOutcome.imported
    ],
    localBestHeight := 5,
    peerBestHeight := 8
  }

theorem sync_response_import_unsorted_accepts :
    evaluateSyncResponseImportRejection importResponseUnsorted = none := by
  decide

theorem sync_response_import_sorts_unsorted_heights :
    sortHeights importResponseUnsorted.responseHeights = [3, 4, 5] := by
  decide

theorem sync_response_import_unsorted_attempts_all :
    attemptedUntilStop importResponseUnsorted.outcomes = 3
      ∧ importedUntilStop importResponseUnsorted.outcomes = 2
      ∧ stoppedOnError importResponseUnsorted.outcomes = false := by
  decide

theorem sync_response_import_unsorted_requests_more :
    shouldRequestMore importResponseUnsorted = true := by
  decide

def importResponseStopsOnError : SyncResponseImportInput :=
  {
    responseHeights := [7, 6, 8],
    maxBlocks := 512,
    outcomes := [
      SyncResponseImportOutcome.imported,
      SyncResponseImportOutcome.error
    ],
    localBestHeight := 7,
    peerBestHeight := 12
  }

theorem sync_response_import_stops_on_first_error :
    attemptedUntilStop importResponseStopsOnError.outcomes = 2
      ∧ importedUntilStop importResponseStopsOnError.outcomes = 1
      ∧ stoppedOnError importResponseStopsOnError.outcomes = true := by
  decide

def importResponseEmptyPeerAhead : SyncResponseImportInput :=
  {
    responseHeights := [],
    maxBlocks := 512,
    outcomes := [],
    localBestHeight := 5,
    peerBestHeight := 9
  }

theorem sync_response_import_empty_never_requests_more :
    shouldRequestMore importResponseEmptyPeerAhead = false := by
  decide

def importResponseOverLimit : SyncResponseImportInput :=
  {
    responseHeights := [1, 2, 3],
    maxBlocks := 2,
    outcomes := [],
    localBestHeight := 0,
    peerBestHeight := 3
  }

theorem sync_response_import_over_limit_rejects :
    evaluateSyncResponseImportRejection importResponseOverLimit =
      some SyncResponseImportReject.responseBlockCountTooLarge := by
  decide

def importResponseOutcomeOverResponse : SyncResponseImportInput :=
  {
    responseHeights := [1],
    maxBlocks := 512,
    outcomes := [
      SyncResponseImportOutcome.imported,
      SyncResponseImportOutcome.imported
    ],
    localBestHeight := 1,
    peerBestHeight := 2
  }

theorem sync_response_import_outcome_over_response_rejects :
    evaluateSyncResponseImportRejection importResponseOutcomeOverResponse =
      some SyncResponseImportReject.outcomeCountOverResponse := by
  decide

end SyncResponseImport
end Native
end Hegemon

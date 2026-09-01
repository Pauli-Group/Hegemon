import Hegemon.Native.SyncAdmission

namespace Hegemon
namespace Native
namespace SyncResponseImport

open Hegemon.Native.SyncAdmission

inductive SyncResponseImportReject where
  | responseBlockCountTooLarge
  | outcomeCountOverResponse
  | outcomeTraceIncomplete
  | postClassificationOutcomeInvalid
deriving DecidableEq, Repr

inductive SyncResponseImportOutcome where
  | imported
  | alreadyKnown
  | storedNoncanonical
  | missingParent
  | error
deriving DecidableEq, Repr

inductive SyncResponsePostClassificationOutcome where
  | noIssue
  | missingAncestor
  | corrupt
deriving DecidableEq, Repr

structure SyncResponseImportInput where
  responseHeights : List Nat
  maxBlocks : Nat
  outcomes : List SyncResponseImportOutcome
  postClassificationOutcome : SyncResponsePostClassificationOutcome
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

def peerRemainsAhead (input : SyncResponseImportInput) : Bool :=
  decide (input.localBestHeight < input.peerBestHeight)

def peerAtOrAhead (input : SyncResponseImportInput) : Bool :=
  decide (input.localBestHeight ≤ input.peerBestHeight)

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
  | SyncResponseImportOutcome.storedNoncanonical :: rest =>
      attemptedUntilStop rest + 1
  | SyncResponseImportOutcome.missingParent :: _ => 1
  | SyncResponseImportOutcome.error :: _ => 1

def importedUntilStop : List SyncResponseImportOutcome -> Nat
  | [] => 0
  | SyncResponseImportOutcome.imported :: rest =>
      importedUntilStop rest + 1
  | SyncResponseImportOutcome.alreadyKnown :: rest =>
      importedUntilStop rest
  | SyncResponseImportOutcome.storedNoncanonical :: rest =>
      importedUntilStop rest
  | SyncResponseImportOutcome.missingParent :: _ => 0
  | SyncResponseImportOutcome.error :: _ => 0

def storedNoncanonicalUntilStop : List SyncResponseImportOutcome -> Nat
  | [] => 0
  | SyncResponseImportOutcome.imported :: rest =>
      storedNoncanonicalUntilStop rest
  | SyncResponseImportOutcome.alreadyKnown :: rest =>
      storedNoncanonicalUntilStop rest
  | SyncResponseImportOutcome.storedNoncanonical :: rest =>
      storedNoncanonicalUntilStop rest + 1
  | SyncResponseImportOutcome.missingParent :: _ => 0
  | SyncResponseImportOutcome.error :: _ => 0

def stoppedOnError : List SyncResponseImportOutcome -> Bool
  | [] => false
  | SyncResponseImportOutcome.imported :: rest => stoppedOnError rest
  | SyncResponseImportOutcome.alreadyKnown :: rest => stoppedOnError rest
  | SyncResponseImportOutcome.storedNoncanonical :: rest => stoppedOnError rest
  | SyncResponseImportOutcome.missingParent :: _ => false
  | SyncResponseImportOutcome.error :: _ => true

def stoppedOnMissingParent : List SyncResponseImportOutcome -> Bool
  | [] => false
  | SyncResponseImportOutcome.imported :: rest => stoppedOnMissingParent rest
  | SyncResponseImportOutcome.alreadyKnown :: rest => stoppedOnMissingParent rest
  | SyncResponseImportOutcome.storedNoncanonical :: rest =>
      stoppedOnMissingParent rest
  | SyncResponseImportOutcome.missingParent :: _ => true
  | SyncResponseImportOutcome.error :: _ => false

def responseStoppedOnError (input : SyncResponseImportInput) : Bool :=
  stoppedOnError input.outcomes ||
    decide
      (input.postClassificationOutcome =
        SyncResponsePostClassificationOutcome.corrupt)

def responseStoppedOnMissingParent
    (input : SyncResponseImportInput) : Bool :=
  stoppedOnMissingParent input.outcomes ||
    decide
      (input.postClassificationOutcome =
        SyncResponsePostClassificationOutcome.missingAncestor)

def allOutcomesAlreadyKnown : List SyncResponseImportOutcome -> Bool
  | [] => true
  | SyncResponseImportOutcome.alreadyKnown :: rest =>
      allOutcomesAlreadyKnown rest
  | _ => false

def postClassificationOutcomeConsistent
    (input : SyncResponseImportInput) : Bool :=
  match input.postClassificationOutcome with
  | .noIssue => true
  | .missingAncestor | .corrupt =>
      responseHasBlocks input
        && decide
          (input.outcomes.length = input.responseHeights.length)
        && allOutcomesAlreadyKnown input.outcomes
        && (stoppedOnError input.outcomes = false)
        && (stoppedOnMissingParent input.outcomes = false)

structure SyncResponsePostClassificationMissingParentInput where
  hadBlocks : Bool
  attemptedBlocks : Nat
  responseBlockCount : Nat
  importedBlocks : Nat
  storedNoncanonicalBlocks : Nat
  stoppedOnError : Bool
  stoppedOnMissingParent : Bool
deriving DecidableEq, Repr

def postClassificationMissingParentAccepts
    (input : SyncResponsePostClassificationMissingParentInput) : Bool :=
  input.hadBlocks
    && decide (input.attemptedBlocks = input.responseBlockCount)
    && decide (input.importedBlocks = 0)
    && decide (input.storedNoncanonicalBlocks = 0)
    && (input.stoppedOnError = false)
    && (input.stoppedOnMissingParent = false)

def outcomeTraceCompleteOrTerminal
    (input : SyncResponseImportInput) : Bool :=
  decide (input.outcomes.length = input.responseHeights.length)
    || stoppedOnError input.outcomes
    || stoppedOnMissingParent input.outcomes

def completedWithoutCanonicalProgress
    (input : SyncResponseImportInput) : Bool :=
  responseHasBlocks input
    && decide
      (attemptedUntilStop input.outcomes = input.responseHeights.length)
    && decide (importedUntilStop input.outcomes = 0)
    && (responseStoppedOnError input = false)
    && (responseStoppedOnMissingParent input = false)

def stoppedOnNoProgress (input : SyncResponseImportInput) : Bool :=
  responseStoppedOnMissingParent input
    || completedWithoutCanonicalProgress input

def shouldRequestMore (input : SyncResponseImportInput) : Bool :=
  responseHasBlocks input
    && peerRemainsAhead input
    && (responseStoppedOnError input = false)
    && (stoppedOnNoProgress input = false)

def recoveryRequired (input : SyncResponseImportInput) : Bool :=
  responseHasBlocks input
    && peerAtOrAhead input
    && (responseStoppedOnError input = false)
    && stoppedOnNoProgress input

def backoffRequired (input : SyncResponseImportInput) : Bool :=
  responseHasBlocks input
    && peerRemainsAhead input
    && responseStoppedOnError input

structure SyncResponseRecoveryPlan where
  currentFromHeight : Nat
  currentToHeight : Nat
  candidateAvailable : Bool
  candidateFromHeight : Nat
  candidateToHeight : Nat
  backoffScheduled : Bool
deriving DecidableEq, Repr

def recoveryRangeChanged (plan : SyncResponseRecoveryPlan) : Bool :=
  plan.candidateAvailable
    && decide
      (plan.currentFromHeight != plan.candidateFromHeight
        || plan.currentToHeight != plan.candidateToHeight)
    && decide (plan.candidateFromHeight ≤ plan.candidateToHeight)

def usefulRecoveryOrBackoff (plan : SyncResponseRecoveryPlan) : Bool :=
  recoveryRangeChanged plan || plan.backoffScheduled

def immediateRequestAllowed
    (input : SyncResponseImportInput)
    (plan : SyncResponseRecoveryPlan) : Bool :=
  shouldRequestMore input
    || (recoveryRequired input && recoveryRangeChanged plan)

def followUpAllowed
    (input : SyncResponseImportInput)
    (plan : SyncResponseRecoveryPlan) : Bool :=
  immediateRequestAllowed input plan
    || (backoffRequired input && plan.backoffScheduled)
    || (recoveryRequired input && plan.backoffScheduled)

def evaluateSyncResponseImportRejection
    (input : SyncResponseImportInput) :
    Option SyncResponseImportReject :=
  if responseCountAccepts (responseCountInput input) = false then
    some SyncResponseImportReject.responseBlockCountTooLarge
  else if input.outcomes.length ≤ input.responseHeights.length then
    if outcomeTraceCompleteOrTerminal input then
      if postClassificationOutcomeConsistent input then
        none
      else
        some SyncResponseImportReject.postClassificationOutcomeInvalid
    else
      some SyncResponseImportReject.outcomeTraceIncomplete
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
  outcomeTraceCompleteOrTerminal :
    outcomeTraceCompleteOrTerminal input = true
  postClassificationOutcomeConsistent :
    postClassificationOutcomeConsistent input = true
  attemptedBlocksWithinResponse :
    attemptedUntilStop input.outcomes ≤ input.responseHeights.length
  importedBlocksWithinAttempts :
    importedUntilStop input.outcomes ≤ attemptedUntilStop input.outcomes
  storedNoncanonicalBlocksWithinAttempts :
    storedNoncanonicalUntilStop input.outcomes ≤
      attemptedUntilStop input.outcomes
  importedBlocksWithinResponse :
    importedUntilStop input.outcomes ≤ input.responseHeights.length
  requestMoreIff :
    shouldRequestMore input = true ↔
      input.responseHeights.isEmpty = false
        ∧ input.localBestHeight < input.peerBestHeight
        ∧ responseStoppedOnError input = false
        ∧ stoppedOnNoProgress input = false
  recoveryRequiredIff :
    recoveryRequired input = true ↔
      input.responseHeights.isEmpty = false
        ∧ input.localBestHeight ≤ input.peerBestHeight
        ∧ responseStoppedOnError input = false
        ∧ stoppedOnNoProgress input = true

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

theorem stored_noncanonical_until_stop_le_attempted
    (outcomes : List SyncResponseImportOutcome) :
    storedNoncanonicalUntilStop outcomes ≤ attemptedUntilStop outcomes := by
  induction outcomes with
  | nil =>
      simp [storedNoncanonicalUntilStop, attemptedUntilStop]
  | cons outcome rest ih =>
      cases outcome <;>
        simp [storedNoncanonicalUntilStop, attemptedUntilStop, ih] <;> omega

theorem should_request_more_iff
    {input : SyncResponseImportInput} :
    shouldRequestMore input = true ↔
      input.responseHeights.isEmpty = false
        ∧ input.localBestHeight < input.peerBestHeight
        ∧ responseStoppedOnError input = false
        ∧ stoppedOnNoProgress input = false := by
  simp [shouldRequestMore, responseHasBlocks, peerRemainsAhead,
    Bool.and_eq_true, decide_eq_true_eq, and_assoc]

theorem recovery_required_iff
    {input : SyncResponseImportInput} :
    recoveryRequired input = true ↔
      input.responseHeights.isEmpty = false
        ∧ input.localBestHeight ≤ input.peerBestHeight
        ∧ responseStoppedOnError input = false
        ∧ stoppedOnNoProgress input = true := by
  simp [recoveryRequired, responseHasBlocks, peerAtOrAhead,
    Bool.and_eq_true, decide_eq_true_eq, and_assoc]

theorem recovery_required_blocks_direct_continuation
    {input : SyncResponseImportInput}
    (required : recoveryRequired input = true) :
    shouldRequestMore input = false := by
  have recoveryFacts := recovery_required_iff.mp required
  simp [shouldRequestMore, responseHasBlocks, peerRemainsAhead,
    recoveryFacts.1, recoveryFacts.2.2.1,
    recoveryFacts.2.2.2]

theorem immediate_recovery_requires_changed_range
    {input : SyncResponseImportInput}
    {plan : SyncResponseRecoveryPlan}
    (required : recoveryRequired input = true)
    (allowed : immediateRequestAllowed input plan = true) :
    recoveryRangeChanged plan = true := by
  have directBlocked := recovery_required_blocks_direct_continuation required
  simp [immediateRequestAllowed, directBlocked, required] at allowed
  exact allowed

theorem follow_up_after_stop_requires_useful_recovery_or_backoff
    {input : SyncResponseImportInput}
    {plan : SyncResponseRecoveryPlan}
    (stopped : recoveryRequired input = true ∨ backoffRequired input = true)
    (allowed : followUpAllowed input plan = true) :
    usefulRecoveryOrBackoff plan = true := by
  cases stopped with
  | inl recovery =>
      have directBlocked := recovery_required_blocks_direct_continuation recovery
      simp [followUpAllowed, immediateRequestAllowed, directBlocked, recovery]
        at allowed
      have useful :
          recoveryRangeChanged plan = true ∨ plan.backoffScheduled = true := by
        rcases allowed with (changed | redundantBackoff) | scheduled
        · exact Or.inl changed
        · exact Or.inr redundantBackoff.2
        · exact Or.inr scheduled
      simpa [usefulRecoveryOrBackoff] using useful
  | inr backoff =>
      have errorStopped : responseStoppedOnError input = true := by
        simp [backoffRequired, responseHasBlocks, peerRemainsAhead,
          Bool.and_eq_true] at backoff
        exact backoff.2
      have directBlocked : shouldRequestMore input = false := by
        simp [shouldRequestMore, errorStopped]
      have recoveryBlocked : recoveryRequired input = false := by
        simp [recoveryRequired, errorStopped]
      simp [followUpAllowed, immediateRequestAllowed, usefulRecoveryOrBackoff,
        directBlocked, recoveryBlocked, backoff] at allowed ⊢
      exact Or.inr allowed

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
    · by_cases traceCompleteOrTerminal :
          outcomeTraceCompleteOrTerminal input = true
      · by_cases postClassificationConsistent :
            postClassificationOutcomeConsistent input = true
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
          have storedNoncanonicalBlocksWithinAttempts :
            storedNoncanonicalUntilStop input.outcomes ≤
              attemptedUntilStop input.outcomes :=
            stored_noncanonical_until_stop_le_attempted input.outcomes
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
              outcomeTraceCompleteOrTerminal := traceCompleteOrTerminal,
              postClassificationOutcomeConsistent :=
                postClassificationConsistent,
              attemptedBlocksWithinResponse :=
                attemptedBlocksWithinResponse,
              importedBlocksWithinAttempts :=
                importedBlocksWithinAttempts,
              storedNoncanonicalBlocksWithinAttempts :=
                storedNoncanonicalBlocksWithinAttempts,
              importedBlocksWithinResponse :=
                importedBlocksWithinResponse,
              requestMoreIff := should_request_more_iff,
              recoveryRequiredIff := recovery_required_iff
            }
        · simp [outcomeCountWithinResponse, traceCompleteOrTerminal,
            postClassificationConsistent] at accepted
      · simp [outcomeCountWithinResponse, traceCompleteOrTerminal] at accepted
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
    postClassificationOutcome := .noIssue,
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
    postClassificationOutcome := .noIssue,
    localBestHeight := 7,
    peerBestHeight := 12
  }

theorem sync_response_import_stops_on_first_error :
    attemptedUntilStop importResponseStopsOnError.outcomes = 2
      ∧ importedUntilStop importResponseStopsOnError.outcomes = 1
      ∧ stoppedOnError importResponseStopsOnError.outcomes = true := by
  decide

theorem sync_response_import_error_blocks_immediate_retry :
    shouldRequestMore importResponseStopsOnError = false
      ∧ backoffRequired importResponseStopsOnError = true := by
  decide

def importResponseStopsOnMissingParent : SyncResponseImportInput :=
  {
    responseHeights := [43530, 43531, 43532],
    maxBlocks := 64,
    outcomes := [
      SyncResponseImportOutcome.missingParent,
      SyncResponseImportOutcome.imported
    ],
    postClassificationOutcome := .noIssue,
    localBestHeight := 43529,
    peerBestHeight := 69941
  }

def sameRangeRecoveryPlan : SyncResponseRecoveryPlan :=
  {
    currentFromHeight := 43530,
    currentToHeight := 43593,
    candidateAvailable := true,
    candidateFromHeight := 43530,
    candidateToHeight := 43593,
    backoffScheduled := false
  }

def changedAncestorRecoveryPlan : SyncResponseRecoveryPlan :=
  {
    currentFromHeight := 43530,
    currentToHeight := 43593,
    candidateAvailable := true,
    candidateFromHeight := 43466,
    candidateToHeight := 43530,
    backoffScheduled := false
  }

def deferredBackoffPlan : SyncResponseRecoveryPlan :=
  {
    currentFromHeight := 6,
    currentToHeight := 8,
    candidateAvailable := false,
    candidateFromHeight := 0,
    candidateToHeight := 0,
    backoffScheduled := true
  }

theorem sync_response_import_stops_on_missing_parent :
    attemptedUntilStop importResponseStopsOnMissingParent.outcomes = 1
      ∧ importedUntilStop importResponseStopsOnMissingParent.outcomes = 0
      ∧ stoppedOnMissingParent
          importResponseStopsOnMissingParent.outcomes = true
      ∧ stoppedOnError importResponseStopsOnMissingParent.outcomes = false := by
  decide

theorem sync_response_import_missing_parent_requires_recovery :
    shouldRequestMore importResponseStopsOnMissingParent = false
      ∧ recoveryRequired importResponseStopsOnMissingParent = true := by
  decide

theorem sync_response_import_same_range_is_not_useful_recovery :
    recoveryRangeChanged sameRangeRecoveryPlan = false
      ∧ immediateRequestAllowed
          importResponseStopsOnMissingParent sameRangeRecoveryPlan = false := by
  decide

theorem sync_response_import_changed_ancestor_range_allows_recovery :
    recoveryRangeChanged changedAncestorRecoveryPlan = true
      ∧ immediateRequestAllowed
          importResponseStopsOnMissingParent changedAncestorRecoveryPlan = true := by
  decide

def importResponseAllKnownPeerAhead : SyncResponseImportInput :=
  {
    responseHeights := [43530, 43531, 43532],
    maxBlocks := 64,
    outcomes := [
      SyncResponseImportOutcome.alreadyKnown,
      SyncResponseImportOutcome.alreadyKnown,
      SyncResponseImportOutcome.alreadyKnown
    ],
    postClassificationOutcome := .noIssue,
    localBestHeight := 43529,
    peerBestHeight := 69941
  }

theorem sync_response_import_all_known_ahead_requires_recovery :
    completedWithoutCanonicalProgress importResponseAllKnownPeerAhead = true
      ∧ shouldRequestMore importResponseAllKnownPeerAhead = false
      ∧ recoveryRequired importResponseAllKnownPeerAhead = true := by
  decide

def postClassificationMissingParentReady :
    SyncResponsePostClassificationMissingParentInput :=
  {
    hadBlocks := true,
    attemptedBlocks := 3,
    responseBlockCount := 3,
    importedBlocks := 0,
    storedNoncanonicalBlocks := 0,
    stoppedOnError := false,
    stoppedOnMissingParent := false
  }

theorem post_classification_missing_parent_accepts_after_full_trace :
    postClassificationMissingParentAccepts
      postClassificationMissingParentReady = true := by
  decide

theorem post_classification_missing_parent_rejects_incomplete_trace :
    postClassificationMissingParentAccepts
      { postClassificationMissingParentReady with attemptedBlocks := 2 } =
        false := by
  decide

theorem post_classification_missing_parent_rejects_without_blocks :
    postClassificationMissingParentAccepts
      { postClassificationMissingParentReady with hadBlocks := false } =
        false := by
  decide

theorem post_classification_missing_parent_rejects_after_error :
    postClassificationMissingParentAccepts
      { postClassificationMissingParentReady with stoppedOnError := true } =
        false := by
  decide

theorem post_classification_missing_parent_rejects_after_import :
    postClassificationMissingParentAccepts
      { postClassificationMissingParentReady with importedBlocks := 1 } =
        false := by
  decide

theorem post_classification_missing_parent_rejects_after_noncanonical_store :
    postClassificationMissingParentAccepts
      { postClassificationMissingParentReady with
        storedNoncanonicalBlocks := 1 } = false := by
  decide

def importResponseAllKnownMissingAncestor : SyncResponseImportInput :=
  { importResponseAllKnownPeerAhead with
    postClassificationOutcome := .missingAncestor }

def importResponseAllKnownCorrupt : SyncResponseImportInput :=
  { importResponseAllKnownPeerAhead with
    postClassificationOutcome := .corrupt }

theorem sync_response_import_post_classification_missing_ancestor_requires_recovery :
    evaluateSyncResponseImportRejection
        importResponseAllKnownMissingAncestor = none
      ∧ responseStoppedOnMissingParent
          importResponseAllKnownMissingAncestor = true
      ∧ responseStoppedOnError importResponseAllKnownMissingAncestor = false
      ∧ completedWithoutCanonicalProgress
          importResponseAllKnownMissingAncestor = false
      ∧ shouldRequestMore importResponseAllKnownMissingAncestor = false
      ∧ recoveryRequired importResponseAllKnownMissingAncestor = true
      ∧ immediateRequestAllowed
          importResponseAllKnownMissingAncestor
          changedAncestorRecoveryPlan = true := by
  decide

theorem sync_response_import_post_classification_corruption_is_terminal :
    evaluateSyncResponseImportRejection importResponseAllKnownCorrupt = none
      ∧ responseStoppedOnError importResponseAllKnownCorrupt = true
      ∧ responseStoppedOnMissingParent importResponseAllKnownCorrupt = false
      ∧ shouldRequestMore importResponseAllKnownCorrupt = false
      ∧ recoveryRequired importResponseAllKnownCorrupt = false
      ∧ backoffRequired importResponseAllKnownCorrupt = true
      ∧ followUpAllowed importResponseAllKnownCorrupt deferredBackoffPlan = true := by
  decide

def importResponseInvalidPostClassification : SyncResponseImportInput :=
  {
    responseHeights := [43530],
    maxBlocks := 64,
    outcomes := [SyncResponseImportOutcome.missingParent],
    postClassificationOutcome := .missingAncestor,
    localBestHeight := 43529,
    peerBestHeight := 69941
  }

theorem sync_response_import_post_classification_after_row_stop_rejects :
    evaluateSyncResponseImportRejection
      importResponseInvalidPostClassification =
        some SyncResponseImportReject.postClassificationOutcomeInvalid := by
  decide

def importResponseAllKnownEqualHeight : SyncResponseImportInput :=
  {
    responseHeights := [43530, 43531, 43532],
    maxBlocks := 64,
    outcomes := [
      SyncResponseImportOutcome.alreadyKnown,
      SyncResponseImportOutcome.alreadyKnown,
      SyncResponseImportOutcome.alreadyKnown
    ],
    postClassificationOutcome := .noIssue,
    localBestHeight := 69941,
    peerBestHeight := 69941
  }

theorem sync_response_import_all_known_equal_height_requires_recovery :
    completedWithoutCanonicalProgress importResponseAllKnownEqualHeight = true
      ∧ shouldRequestMore importResponseAllKnownEqualHeight = false
      ∧ recoveryRequired importResponseAllKnownEqualHeight = true := by
  decide

def importResponseStoredNoncanonicalPeerAhead : SyncResponseImportInput :=
  {
    responseHeights := [43530, 43531, 43532],
    maxBlocks := 64,
    outcomes := [
      SyncResponseImportOutcome.storedNoncanonical,
      SyncResponseImportOutcome.storedNoncanonical,
      SyncResponseImportOutcome.storedNoncanonical
    ],
    postClassificationOutcome := .noIssue,
    localBestHeight := 43529,
    peerBestHeight := 69941
  }

theorem sync_response_import_stored_noncanonical_ahead_requires_recovery :
    storedNoncanonicalUntilStop
        importResponseStoredNoncanonicalPeerAhead.outcomes = 3
      ∧ importedUntilStop importResponseStoredNoncanonicalPeerAhead.outcomes = 0
      ∧ completedWithoutCanonicalProgress
          importResponseStoredNoncanonicalPeerAhead = true
      ∧ shouldRequestMore importResponseStoredNoncanonicalPeerAhead = false
      ∧ recoveryRequired importResponseStoredNoncanonicalPeerAhead = true := by
  decide

def importResponseKnownImportedKnownPeerAhead : SyncResponseImportInput :=
  {
    responseHeights := [43530, 43531, 43532],
    maxBlocks := 64,
    outcomes := [
      SyncResponseImportOutcome.alreadyKnown,
      SyncResponseImportOutcome.imported,
      SyncResponseImportOutcome.alreadyKnown
    ],
    postClassificationOutcome := .noIssue,
    localBestHeight := 43532,
    peerBestHeight := 69941
  }

theorem sync_response_import_known_imported_known_continues_after_adoption :
    evaluateSyncResponseImportRejection
        importResponseKnownImportedKnownPeerAhead = none
      ∧ attemptedUntilStop
          importResponseKnownImportedKnownPeerAhead.outcomes = 3
      ∧ importedUntilStop
          importResponseKnownImportedKnownPeerAhead.outcomes = 1
      ∧ storedNoncanonicalUntilStop
          importResponseKnownImportedKnownPeerAhead.outcomes = 0
      ∧ completedWithoutCanonicalProgress
          importResponseKnownImportedKnownPeerAhead = false
      ∧ shouldRequestMore importResponseKnownImportedKnownPeerAhead = true
      ∧ recoveryRequired importResponseKnownImportedKnownPeerAhead = false := by
  decide

def importResponseKnownStoredKnownPeerAhead : SyncResponseImportInput :=
  {
    responseHeights := [43530, 43531, 43532],
    maxBlocks := 64,
    outcomes := [
      SyncResponseImportOutcome.alreadyKnown,
      SyncResponseImportOutcome.storedNoncanonical,
      SyncResponseImportOutcome.alreadyKnown
    ],
    postClassificationOutcome := .noIssue,
    localBestHeight := 43529,
    peerBestHeight := 69941
  }

theorem sync_response_import_known_stored_known_requires_recovery :
    evaluateSyncResponseImportRejection
        importResponseKnownStoredKnownPeerAhead = none
      ∧ attemptedUntilStop
          importResponseKnownStoredKnownPeerAhead.outcomes = 3
      ∧ importedUntilStop
          importResponseKnownStoredKnownPeerAhead.outcomes = 0
      ∧ storedNoncanonicalUntilStop
          importResponseKnownStoredKnownPeerAhead.outcomes = 1
      ∧ completedWithoutCanonicalProgress
          importResponseKnownStoredKnownPeerAhead = true
      ∧ shouldRequestMore importResponseKnownStoredKnownPeerAhead = false
      ∧ recoveryRequired importResponseKnownStoredKnownPeerAhead = true := by
  decide

def importResponseEmptyPeerAhead : SyncResponseImportInput :=
  {
    responseHeights := [],
    maxBlocks := 512,
    outcomes := [],
    postClassificationOutcome := .noIssue,
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
    postClassificationOutcome := .noIssue,
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
    postClassificationOutcome := .noIssue,
    localBestHeight := 1,
    peerBestHeight := 2
  }

theorem sync_response_import_outcome_over_response_rejects :
    evaluateSyncResponseImportRejection importResponseOutcomeOverResponse =
      some SyncResponseImportReject.outcomeCountOverResponse := by
  decide

def importResponseIncompleteNonterminal : SyncResponseImportInput :=
  {
    responseHeights := [43530, 43531, 43532],
    maxBlocks := 64,
    outcomes := [SyncResponseImportOutcome.alreadyKnown],
    postClassificationOutcome := .noIssue,
    localBestHeight := 43529,
    peerBestHeight := 69941
  }

theorem sync_response_import_incomplete_nonterminal_trace_rejects :
    evaluateSyncResponseImportRejection importResponseIncompleteNonterminal =
      some SyncResponseImportReject.outcomeTraceIncomplete := by
  decide

end SyncResponseImport
end Native
end Hegemon

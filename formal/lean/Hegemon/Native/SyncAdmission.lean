import Hegemon.Resource.BoundedRequestAdmission

namespace Hegemon
namespace Native
namespace SyncAdmission

open Hegemon.Resource.BoundedRequestAdmission

def u64Max : Nat := 18446744073709551615

def saturatingAddU64 (lhs rhs : Nat) : Nat :=
  if u64Max - lhs < rhs then u64Max else lhs + rhs

structure SyncResponseRangeInput where
  fromHeight : Nat
  toHeight : Nat
  bestHeight : Nat
  maxBlocks : Nat
deriving DecidableEq, Repr

structure SyncMissingRequestInput where
  bestHeight : Nat
  announcedHeight : Nat
  maxBlocks : Nat
deriving DecidableEq, Repr

structure SyncResponseCountInput where
  blockCount : Nat
  maxBlocks : Nat
deriving DecidableEq, Repr

structure SyncRequestRateInput where
  requestsInWindow : Nat
  maxRequests : Nat
  windowElapsedMs : Nat
  windowMs : Nat
deriving DecidableEq, Repr

structure SyncRequestRateStateBoundInput where
  currentEntries : Nat
  maxEntries : Nat
deriving DecidableEq, Repr

structure MiningSyncEvidenceInput where
  verifiedNewProgress : Bool
  verifiedKnownAtOrBelowLocalBest : Bool
  localBestHeight : Nat
  peerBestHeight : Nat
  stoppedOnError : Bool
deriving DecidableEq, Repr

structure MiningGateInput where
  hasSeeds : Bool
  dev : Bool
  bootstrapAuthoring : Bool
  observedGateOpen : Bool
deriving DecidableEq, Repr

def responseCapEnd (input : SyncResponseRangeInput) : Nat :=
  let maxEnd := saturatingAddU64 input.fromHeight (input.maxBlocks - 1)
  min input.toHeight (min input.bestHeight maxEnd)

def responseRange (input : SyncResponseRangeInput) : Option (Nat × Nat) :=
  if input.maxBlocks = 0 then
    none
  else
    let cappedTo := responseCapEnd input
    if input.fromHeight ≤ cappedTo then
      some (input.fromHeight, cappedTo)
    else
      none

def missingRequestRange (input : SyncMissingRequestInput) : Option (Nat × Nat) :=
  if input.maxBlocks = 0 then
    none
  else
    if input.announcedHeight ≤ input.bestHeight then
      none
    else
      let fromHeight :=
        if 0 < input.bestHeight ∧ input.bestHeight < input.maxBlocks then
          1
        else
          saturatingAddU64 input.bestHeight 1
      let capEnd :=
        max fromHeight (saturatingAddU64 fromHeight (input.maxBlocks - 1))
      some (fromHeight, min input.announcedHeight capEnd)

def responseCountRejects (input : SyncResponseCountInput) : Bool :=
  input.blockCount > input.maxBlocks

def responseCountAccepts (input : SyncResponseCountInput) : Bool :=
  responseCountRejects input = false

def requestRateRejects (input : SyncRequestRateInput) : Bool :=
  if input.maxRequests = 0 then
    true
  else if input.windowElapsedMs ≥ input.windowMs then
    false
  else
    input.requestsInWindow ≥ input.maxRequests

def requestRateAccepts (input : SyncRequestRateInput) : Bool :=
  requestRateRejects input = false

def requestRateStateRetainedBeforeInsert
    (input : SyncRequestRateStateBoundInput) : Nat :=
  if input.maxEntries = 0 then
    0
  else
    min input.currentEntries (input.maxEntries - 1)

def requestRateStateEntriesAfterInsert
    (input : SyncRequestRateStateBoundInput) : Nat :=
  if input.maxEntries = 0 then
    0
  else
    requestRateStateRetainedBeforeInsert input + 1

def requestRateStateAccepts
    (input : SyncRequestRateStateBoundInput) : Bool :=
  requestRateStateEntriesAfterInsert input ≤ input.maxEntries

def miningSyncObservedPeerHeight
    (input : MiningSyncEvidenceInput) : Option Nat :=
  if input.stoppedOnError then
    none
  else if input.verifiedNewProgress then
    some input.localBestHeight
  else if input.verifiedKnownAtOrBelowLocalBest
      && input.peerBestHeight ≤ input.localBestHeight then
    some input.peerBestHeight
  else
    none

def miningGateAllowsWork (input : MiningGateInput) : Bool :=
  if input.hasSeeds then
    input.observedGateOpen
  else
    input.dev || input.bootstrapAuthoring

def responseRangeBlockCount (range : Nat × Nat) : Nat :=
  range.snd + 1 - range.fst

def responseRangeBoundedPolicy
    (input : SyncResponseRangeInput) : ResourcePolicy :=
  {
    rawByteCap := u64Max,
    decodedByteCap := u64Max,
    itemCountCap := input.maxBlocks,
    itemByteCap := u64Max,
    aggregateByteCap := u64Max,
    workUnitCap := u64Max
  }

def responseRangeBoundedRequest (range : Nat × Nat) : ResourceRequest :=
  {
    rawBytes := 0,
    decodedBytes := 0,
    itemCount := responseRangeBlockCount range,
    maxItemBytes := 0,
    aggregateBytes := 0,
    workUnits := 0
  }

theorem saturating_add_u64_window_count_le
    (lhs rhs : Nat) :
    saturatingAddU64 lhs rhs + 1 - lhs ≤ rhs + 1 := by
  unfold saturatingAddU64
  by_cases over : u64Max - lhs < rhs
  · simp [over]
    omega
  · simp [over]
    omega

theorem response_cap_end_window_count_le
    (input : SyncResponseRangeInput)
    (maxNonzero : input.maxBlocks ≠ 0) :
    responseCapEnd input + 1 - input.fromHeight ≤ input.maxBlocks := by
  have capEndLe :
      responseCapEnd input ≤
        saturatingAddU64 input.fromHeight (input.maxBlocks - 1) := by
    unfold responseCapEnd
    exact
      Nat.le_trans
        (Nat.min_le_right input.toHeight
          (min input.bestHeight
            (saturatingAddU64 input.fromHeight (input.maxBlocks - 1))))
        (Nat.min_le_right input.bestHeight
          (saturatingAddU64 input.fromHeight (input.maxBlocks - 1)))
  have window :=
    saturating_add_u64_window_count_le
      input.fromHeight
      (input.maxBlocks - 1)
  have maxPositive : 1 ≤ input.maxBlocks :=
    Nat.succ_le_of_lt (Nat.pos_of_ne_zero maxNonzero)
  have window' :
      saturatingAddU64 input.fromHeight (input.maxBlocks - 1)
          + 1 - input.fromHeight ≤ input.maxBlocks := by
    simpa [Nat.sub_add_cancel maxPositive] using window
  omega

theorem response_range_block_count_within_max_blocks
    {input : SyncResponseRangeInput}
    {range : Nat × Nat}
    (accepted : responseRange input = some range) :
    responseRangeBlockCount range ≤ input.maxBlocks := by
  unfold responseRange at accepted
  by_cases maxZero : input.maxBlocks = 0
  · simp [maxZero] at accepted
  · by_cases fromWithin : input.fromHeight ≤ responseCapEnd input
    · simp [maxZero, fromWithin] at accepted
      cases accepted
      exact response_cap_end_window_count_le input maxZero
    · simp [maxZero, fromWithin] at accepted

theorem response_range_bounded_request_accepts
    {input : SyncResponseRangeInput}
    {range : Nat × Nat}
    (accepted : responseRange input = some range) :
    evaluateBoundedRequest
      (responseRangeBoundedPolicy input)
      (responseRangeBoundedRequest range) = none := by
  have countWithin :=
    response_range_block_count_within_max_blocks accepted
  have countNotOver :
      ¬ input.maxBlocks < responseRangeBlockCount range :=
    Nat.not_lt.mpr countWithin
  simp [
    evaluateBoundedRequest,
    responseRangeBoundedPolicy,
    responseRangeBoundedRequest,
    countNotOver
  ]

theorem accepted_response_range_exposes_bounded_request_facts
    {input : SyncResponseRangeInput}
    {range : Nat × Nat}
    (accepted : responseRange input = some range) :
    AcceptedBoundedRequestFacts
      (responseRangeBoundedPolicy input)
      (responseRangeBoundedRequest range) :=
  accepted_bounded_request_exposes_all_caps
    (response_range_bounded_request_accepts accepted)

theorem response_range_accepts_iff_from_within_cap
    {input : SyncResponseRangeInput} :
    responseRange input ≠ none ↔
      input.maxBlocks ≠ 0 ∧ input.fromHeight ≤ responseCapEnd input := by
  unfold responseRange
  by_cases max_zero : input.maxBlocks = 0
  · simp [max_zero]
  · by_cases h : input.fromHeight ≤ responseCapEnd input <;> simp [max_zero, h]

theorem response_range_empty_when_from_after_cap
    {input : SyncResponseRangeInput}
    (h : ¬ input.fromHeight ≤ responseCapEnd input) :
    responseRange input = none := by
  unfold responseRange
  by_cases max_zero : input.maxBlocks = 0 <;> simp [max_zero, h]

theorem response_range_empty_when_max_blocks_zero
    {input : SyncResponseRangeInput}
    (h : input.maxBlocks = 0) :
    responseRange input = none := by
  unfold responseRange
  simp [h]

theorem response_range_some_when_from_within_cap
    {input : SyncResponseRangeInput}
    (max_nonzero : input.maxBlocks ≠ 0)
    (h : input.fromHeight ≤ responseCapEnd input) :
    responseRange input = some (input.fromHeight, responseCapEnd input) := by
  unfold responseRange
  simp [max_nonzero, h]

theorem missing_request_none_when_announced_not_ahead
    {input : SyncMissingRequestInput}
    (h : input.announcedHeight ≤ input.bestHeight) :
    missingRequestRange input = none := by
  unfold missingRequestRange
  by_cases max_zero : input.maxBlocks = 0 <;> simp [max_zero, h]

theorem missing_request_none_when_max_blocks_zero
    {input : SyncMissingRequestInput}
    (h : input.maxBlocks = 0) :
    missingRequestRange input = none := by
  unfold missingRequestRange
  simp [h]

theorem missing_request_some_when_announced_ahead
    {input : SyncMissingRequestInput}
    (max_nonzero : input.maxBlocks ≠ 0)
    (h : ¬ input.announcedHeight ≤ input.bestHeight) :
    missingRequestRange input =
      let fromHeight :=
        if 0 < input.bestHeight ∧ input.bestHeight < input.maxBlocks then
          1
        else
          saturatingAddU64 input.bestHeight 1
      some (
        fromHeight,
        min input.announcedHeight
          (max fromHeight
            (saturatingAddU64 fromHeight (input.maxBlocks - 1)))
      ) := by
  unfold missingRequestRange
  simp [max_nonzero, h]

theorem response_count_accepts_iff_within_limit
    {input : SyncResponseCountInput} :
    responseCountAccepts input = true ↔ input.blockCount ≤ input.maxBlocks := by
  unfold responseCountAccepts responseCountRejects
  by_cases over : input.blockCount > input.maxBlocks
  · have not_le : ¬ input.blockCount ≤ input.maxBlocks := Nat.not_le_of_gt over
    simp [over, not_le]
  · have le : input.blockCount ≤ input.maxBlocks := Nat.le_of_not_gt over
    simp [over, le]

theorem request_rate_accepts_when_window_elapsed
    {input : SyncRequestRateInput}
    (elapsed : input.windowMs ≤ input.windowElapsedMs)
    (maxNonzero : input.maxRequests ≠ 0) :
    requestRateAccepts input = true := by
  unfold requestRateAccepts requestRateRejects
  simp [maxNonzero, elapsed]

theorem request_rate_rejects_full_unelapsed_window
    {input : SyncRequestRateInput}
    (full : input.maxRequests ≤ input.requestsInWindow)
    (notElapsed : input.windowElapsedMs < input.windowMs)
    (maxNonzero : input.maxRequests ≠ 0) :
    requestRateRejects input = true := by
  unfold requestRateRejects
  have notElapsedLe : ¬ input.windowMs ≤ input.windowElapsedMs :=
    Nat.not_le_of_gt notElapsed
  simp [maxNonzero, notElapsedLe, full]

theorem request_rate_state_after_insert_within_max
    {input : SyncRequestRateStateBoundInput}
    (maxNonzero : input.maxEntries ≠ 0) :
    requestRateStateAccepts input = true := by
  unfold requestRateStateAccepts requestRateStateEntriesAfterInsert
    requestRateStateRetainedBeforeInsert
  simp [maxNonzero]
  have maxPositive : 1 ≤ input.maxEntries :=
    Nat.succ_le_of_lt (Nat.pos_of_ne_zero maxNonzero)
  omega

theorem request_rate_state_zero_cap_stays_empty
    {input : SyncRequestRateStateBoundInput}
    (maxZero : input.maxEntries = 0) :
    requestRateStateEntriesAfterInsert input = 0
      ∧ requestRateStateAccepts input = true := by
  unfold requestRateStateAccepts requestRateStateEntriesAfterInsert
  simp [maxZero]

theorem mining_sync_observation_none_on_error
    {input : MiningSyncEvidenceInput}
    (stopped : input.stoppedOnError = true) :
    miningSyncObservedPeerHeight input = none := by
  unfold miningSyncObservedPeerHeight
  simp [stopped]

theorem mining_sync_observation_imported_progress_uses_local_best
    {input : MiningSyncEvidenceInput}
    (notStopped : input.stoppedOnError = false)
    (newProgress : input.verifiedNewProgress = true) :
    miningSyncObservedPeerHeight input = some input.localBestHeight := by
  unfold miningSyncObservedPeerHeight
  simp [notStopped, newProgress]

theorem mining_sync_observation_known_peer_uses_peer_height
    {input : MiningSyncEvidenceInput}
    (notStopped : input.stoppedOnError = false)
    (noNewProgress : input.verifiedNewProgress = false)
    (known : input.verifiedKnownAtOrBelowLocalBest = true)
    (within : input.peerBestHeight ≤ input.localBestHeight) :
    miningSyncObservedPeerHeight input = some input.peerBestHeight := by
  unfold miningSyncObservedPeerHeight
  simp [notStopped, noNewProgress, known, within]

theorem mining_gate_seeded_follows_observed_gate
    {input : MiningGateInput}
    (seeded : input.hasSeeds = true) :
    miningGateAllowsWork input = input.observedGateOpen := by
  unfold miningGateAllowsWork
  simp [seeded]

theorem mining_gate_empty_live_without_bootstrap_rejects
    {input : MiningGateInput}
    (unseeded : input.hasSeeds = false)
    (notDev : input.dev = false)
    (notBootstrap : input.bootstrapAuthoring = false) :
    miningGateAllowsWork input = false := by
  unfold miningGateAllowsWork
  simp [unseeded, notDev, notBootstrap]

theorem mining_gate_empty_dev_allows
    {input : MiningGateInput}
    (unseeded : input.hasSeeds = false)
    (dev : input.dev = true) :
    miningGateAllowsWork input = true := by
  unfold miningGateAllowsWork
  simp [unseeded, dev]

theorem mining_gate_empty_bootstrap_allows
    {input : MiningGateInput}
    (unseeded : input.hasSeeds = false)
    (bootstrap : input.bootstrapAuthoring = true) :
    miningGateAllowsWork input = true := by
  unfold miningGateAllowsWork
  simp [unseeded, bootstrap]

def responseRangeValid : SyncResponseRangeInput :=
  {
    fromHeight := 10,
    toHeight := 20,
    bestHeight := 50,
    maxBlocks := 512
  }

theorem response_range_valid_keeps_requested_end :
    responseRange responseRangeValid = some (10, 20) := by
  decide

def responseRangeCapsAtBest : SyncResponseRangeInput :=
  {
    fromHeight := 10,
    toHeight := 80,
    bestHeight := 25,
    maxBlocks := 512
  }

theorem response_range_caps_at_best :
    responseRange responseRangeCapsAtBest = some (10, 25) := by
  decide

def responseRangeCapsAtMaxBlocks : SyncResponseRangeInput :=
  {
    fromHeight := 10,
    toHeight := 1000,
    bestHeight := 2000,
    maxBlocks := 512
  }

theorem response_range_caps_at_max_blocks :
    responseRange responseRangeCapsAtMaxBlocks = some (10, 521) := by
  decide

def responseRangeEmptyWhenFromPastBest : SyncResponseRangeInput :=
  {
    fromHeight := 100,
    toHeight := 200,
    bestHeight := 90,
    maxBlocks := 512
  }

theorem response_range_empty_when_from_past_best :
    responseRange responseRangeEmptyWhenFromPastBest = none := by
  decide

def responseRangeSaturatingInput : SyncResponseRangeInput :=
  {
    fromHeight := u64Max - 5,
    toHeight := u64Max,
    bestHeight := u64Max,
    maxBlocks := 512
  }

theorem response_range_saturating_cap :
    responseRange responseRangeSaturatingInput = some (u64Max - 5, u64Max) := by
  decide

def missingRequestNoop : SyncMissingRequestInput :=
  {
    bestHeight := 50,
    announcedHeight := 50,
    maxBlocks := 512
  }

theorem missing_request_noop_when_not_ahead :
    missingRequestRange missingRequestNoop = none := by
  decide

def missingRequestShort : SyncMissingRequestInput :=
  {
    bestHeight := 50,
    announcedHeight := 55,
    maxBlocks := 512
  }

theorem missing_request_short :
    missingRequestRange missingRequestShort = some (1, 55) := by
  decide

def missingRequestCapsAtMaxBlocks : SyncMissingRequestInput :=
  {
    bestHeight := 50,
    announcedHeight := 2000,
    maxBlocks := 512
  }

theorem missing_request_caps_at_max_blocks :
    missingRequestRange missingRequestCapsAtMaxBlocks = some (1, 512) := by
  decide

def missingRequestBootstrapFork : SyncMissingRequestInput :=
  {
    bestHeight := 145,
    announcedHeight := 21971,
    maxBlocks := 2048
  }

theorem missing_request_bootstrap_fork_backfills_from_height_one :
    missingRequestRange missingRequestBootstrapFork = some (1, 2048) := by
  decide

def missingRequestAtU64Max : SyncMissingRequestInput :=
  {
    bestHeight := u64Max,
    announcedHeight := u64Max,
    maxBlocks := 512
  }

theorem missing_request_at_u64_max_noop :
    missingRequestRange missingRequestAtU64Max = none := by
  decide

def responseCountExactLimit : SyncResponseCountInput :=
  {
    blockCount := 512,
    maxBlocks := 512
  }

theorem response_count_exact_limit_accepts :
    responseCountAccepts responseCountExactLimit = true := by
  decide

def responseCountOverLimit : SyncResponseCountInput :=
  {
    blockCount := 513,
    maxBlocks := 512
  }

theorem response_count_over_limit_rejects :
    responseCountRejects responseCountOverLimit = true := by
  decide

def requestRateUnderLimit : SyncRequestRateInput :=
  {
    requestsInWindow := 3,
    maxRequests := 4,
    windowElapsedMs := 0,
    windowMs := 10000
  }

theorem request_rate_under_limit_accepts :
    requestRateAccepts requestRateUnderLimit = true := by
  decide

def requestRateFullWindow : SyncRequestRateInput :=
  {
    requestsInWindow := 4,
    maxRequests := 4,
    windowElapsedMs := 0,
    windowMs := 10000
  }

theorem request_rate_full_window_rejects :
    requestRateRejects requestRateFullWindow = true := by
  decide

def requestRateElapsedWindow : SyncRequestRateInput :=
  {
    requestsInWindow := 4,
    maxRequests := 4,
    windowElapsedMs := 10000,
    windowMs := 10000
  }

theorem request_rate_elapsed_window_accepts :
    requestRateAccepts requestRateElapsedWindow = true := by
  decide

def requestRateZeroCap : SyncRequestRateInput :=
  {
    requestsInWindow := 0,
    maxRequests := 0,
    windowElapsedMs := 0,
    windowMs := 10000
  }

theorem request_rate_zero_cap_rejects :
    requestRateRejects requestRateZeroCap = true := by
  decide

def requestRateStateBelowCap : SyncRequestRateStateBoundInput :=
  {
    currentEntries := 8,
    maxEntries := 4096
  }

theorem request_rate_state_below_cap_accepts :
    requestRateStateAccepts requestRateStateBelowCap = true := by
  decide

def requestRateStateAtCap : SyncRequestRateStateBoundInput :=
  {
    currentEntries := 4096,
    maxEntries := 4096
  }

theorem request_rate_state_at_cap_evicts_one_before_insert :
    requestRateStateRetainedBeforeInsert requestRateStateAtCap = 4095
      ∧ requestRateStateEntriesAfterInsert requestRateStateAtCap = 4096 := by
  decide

def requestRateStateOverCap : SyncRequestRateStateBoundInput :=
  {
    currentEntries := 4104,
    maxEntries := 4096
  }

theorem request_rate_state_over_cap_evicts_to_cap_before_insert :
    requestRateStateRetainedBeforeInsert requestRateStateOverCap = 4095
      ∧ requestRateStateEntriesAfterInsert requestRateStateOverCap = 4096 := by
  decide

def requestRateStateZeroCap : SyncRequestRateStateBoundInput :=
  {
    currentEntries := 1,
    maxEntries := 0
  }

theorem request_rate_state_zero_cap_stays_empty_example :
    requestRateStateEntriesAfterInsert requestRateStateZeroCap = 0
      ∧ requestRateStateAccepts requestRateStateZeroCap = true := by
  decide

def miningEvidenceImportedProgress : MiningSyncEvidenceInput :=
  {
    verifiedNewProgress := true,
    verifiedKnownAtOrBelowLocalBest := false,
    localBestHeight := 9,
    peerBestHeight := 12,
    stoppedOnError := false
  }

def miningEvidenceKnownEqualTip : MiningSyncEvidenceInput :=
  {
    verifiedNewProgress := false,
    verifiedKnownAtOrBelowLocalBest := true,
    localBestHeight := 12,
    peerBestHeight := 12,
    stoppedOnError := false
  }

def miningEvidenceKnownBelowTip : MiningSyncEvidenceInput :=
  {
    verifiedNewProgress := false,
    verifiedKnownAtOrBelowLocalBest := true,
    localBestHeight := 12,
    peerBestHeight := 10,
    stoppedOnError := false
  }

def miningEvidenceKnownAheadRejects : MiningSyncEvidenceInput :=
  {
    verifiedNewProgress := false,
    verifiedKnownAtOrBelowLocalBest := true,
    localBestHeight := 10,
    peerBestHeight := 12,
    stoppedOnError := false
  }

def miningEvidenceMissingParentRejects : MiningSyncEvidenceInput :=
  {
    verifiedNewProgress := false,
    verifiedKnownAtOrBelowLocalBest := false,
    localBestHeight := 10,
    peerBestHeight := 10,
    stoppedOnError := false
  }

def miningEvidenceErrorRejects : MiningSyncEvidenceInput :=
  {
    verifiedNewProgress := true,
    verifiedKnownAtOrBelowLocalBest := true,
    localBestHeight := 10,
    peerBestHeight := 10,
    stoppedOnError := true
  }

def miningGateLiveEmptyNoBootstrap : MiningGateInput :=
  {
    hasSeeds := false,
    dev := false,
    bootstrapAuthoring := false,
    observedGateOpen := true
  }

theorem mining_gate_live_empty_no_bootstrap_rejects :
    miningGateAllowsWork miningGateLiveEmptyNoBootstrap = false := by
  decide

def miningGateDevEmpty : MiningGateInput :=
  {
    hasSeeds := false,
    dev := true,
    bootstrapAuthoring := false,
    observedGateOpen := false
  }

theorem mining_gate_dev_empty_allows :
    miningGateAllowsWork miningGateDevEmpty = true := by
  decide

def miningGateBootstrapEmpty : MiningGateInput :=
  {
    hasSeeds := false,
    dev := false,
    bootstrapAuthoring := true,
    observedGateOpen := false
  }

theorem mining_gate_bootstrap_empty_allows :
    miningGateAllowsWork miningGateBootstrapEmpty = true := by
  decide

def miningGateSeededClosed : MiningGateInput :=
  {
    hasSeeds := true,
    dev := true,
    bootstrapAuthoring := true,
    observedGateOpen := false
  }

theorem mining_gate_seeded_closed_rejects :
    miningGateAllowsWork miningGateSeededClosed = false := by
  decide

def miningGateSeededOpen : MiningGateInput :=
  {
    hasSeeds := true,
    dev := false,
    bootstrapAuthoring := false,
    observedGateOpen := true
  }

theorem mining_gate_seeded_open_allows :
    miningGateAllowsWork miningGateSeededOpen = true := by
  decide

theorem mining_evidence_known_equal_tip_observes_peer_height :
    miningSyncObservedPeerHeight miningEvidenceKnownEqualTip = some 12 := by
  decide

theorem mining_evidence_known_ahead_rejects :
    miningSyncObservedPeerHeight miningEvidenceKnownAheadRejects = none := by
  decide

end SyncAdmission
end Native
end Hegemon

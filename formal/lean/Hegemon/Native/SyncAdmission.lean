namespace Hegemon
namespace Native
namespace SyncAdmission

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
      let fromHeight := saturatingAddU64 input.bestHeight 1
      let capEnd := max fromHeight (saturatingAddU64 input.bestHeight input.maxBlocks)
      some (fromHeight, min input.announcedHeight capEnd)

def responseCountRejects (input : SyncResponseCountInput) : Bool :=
  input.blockCount > input.maxBlocks

def responseCountAccepts (input : SyncResponseCountInput) : Bool :=
  responseCountRejects input = false

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
      some (
        saturatingAddU64 input.bestHeight 1,
        min input.announcedHeight
          (max (saturatingAddU64 input.bestHeight 1)
            (saturatingAddU64 input.bestHeight input.maxBlocks))
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
    missingRequestRange missingRequestShort = some (51, 55) := by
  decide

def missingRequestCapsAtMaxBlocks : SyncMissingRequestInput :=
  {
    bestHeight := 50,
    announcedHeight := 2000,
    maxBlocks := 512
  }

theorem missing_request_caps_at_max_blocks :
    missingRequestRange missingRequestCapsAtMaxBlocks = some (51, 562) := by
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

end SyncAdmission
end Native
end Hegemon

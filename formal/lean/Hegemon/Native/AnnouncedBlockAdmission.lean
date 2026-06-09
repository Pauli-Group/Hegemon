namespace Hegemon
namespace Native
namespace AnnouncedBlockAdmission

def u64Max : Nat := 18446744073709551615

def checkedAddOneU64 (value : Nat) : Option Nat :=
  if value < u64Max then some (value + 1) else none

def saturatingAddU64 (lhs rhs : Nat) : Nat :=
  if u64Max - lhs < rhs then u64Max else lhs + rhs

inductive AnnouncedBlockReject where
  | heightNotNext
  | parentHashMismatch
  | timestampDidNotAdvance
  | futureSkew
  | hashWorkHashMismatch
deriving DecidableEq, Repr

structure AnnouncedBlockInput where
  parentHeight : Nat
  announcedHeight : Nat
  parentHashMatches : Bool
  parentTimestampMs : Nat
  announcedTimestampMs : Nat
  nowMs : Nat
  maxFutureSkewMs : Nat
  hashMatchesWorkHash : Bool
deriving DecidableEq, Repr

def nextHeightMatches (input : AnnouncedBlockInput) : Bool :=
  checkedAddOneU64 input.parentHeight = some input.announcedHeight

def futureLimit (input : AnnouncedBlockInput) : Nat :=
  saturatingAddU64 input.nowMs input.maxFutureSkewMs

def timestampAdvances (input : AnnouncedBlockInput) : Bool :=
  input.parentTimestampMs < input.announcedTimestampMs

def timestampWithinFutureSkew (input : AnnouncedBlockInput) : Bool :=
  input.announcedTimestampMs ≤ futureLimit input

def evaluateAnnouncedBlockRejection
    (input : AnnouncedBlockInput) : Option AnnouncedBlockReject :=
  if nextHeightMatches input = false then
    some AnnouncedBlockReject.heightNotNext
  else if input.parentHashMatches = false then
    some AnnouncedBlockReject.parentHashMismatch
  else if timestampAdvances input = false then
    some AnnouncedBlockReject.timestampDidNotAdvance
  else if timestampWithinFutureSkew input = false then
    some AnnouncedBlockReject.futureSkew
  else if input.hashMatchesWorkHash = false then
    some AnnouncedBlockReject.hashWorkHashMismatch
  else
    none

def announcedBlockAccepts (input : AnnouncedBlockInput) : Bool :=
  evaluateAnnouncedBlockRejection input = none

def announcedBlockPreconditions (input : AnnouncedBlockInput) : Bool :=
  nextHeightMatches input
    && input.parentHashMatches
    && timestampAdvances input
    && timestampWithinFutureSkew input
    && input.hashMatchesWorkHash

theorem accepts_iff_announced_block_preconditions
    {input : AnnouncedBlockInput} :
    announcedBlockAccepts input = true ↔
      announcedBlockPreconditions input = true := by
  unfold announcedBlockAccepts announcedBlockPreconditions
  unfold evaluateAnnouncedBlockRejection
  cases next : nextHeightMatches input <;>
    cases parent : input.parentHashMatches <;>
    cases advance : timestampAdvances input <;>
    cases future : timestampWithinFutureSkew input <;>
    cases hash : input.hashMatchesWorkHash <;>
    simp

def valid : AnnouncedBlockInput :=
  {
    parentHeight := 41,
    announcedHeight := 42,
    parentHashMatches := true,
    parentTimestampMs := 1000,
    announcedTimestampMs := 1001,
    nowMs := 1000,
    maxFutureSkewMs := 5000,
    hashMatchesWorkHash := true
  }

theorem valid_accepts :
    evaluateAnnouncedBlockRejection valid = none := by
  native_decide

def heightMismatch : AnnouncedBlockInput :=
  { valid with announcedHeight := 43 }

theorem height_mismatch_rejects :
    evaluateAnnouncedBlockRejection heightMismatch =
      some AnnouncedBlockReject.heightNotNext := by
  native_decide

def heightOverflow : AnnouncedBlockInput :=
  {
    parentHeight := u64Max,
    announcedHeight := u64Max,
    parentHashMatches := true,
    parentTimestampMs := 1000,
    announcedTimestampMs := 1001,
    nowMs := 1000,
    maxFutureSkewMs := 5000,
    hashMatchesWorkHash := true
  }

theorem height_overflow_rejects :
    evaluateAnnouncedBlockRejection heightOverflow =
      some AnnouncedBlockReject.heightNotNext := by
  native_decide

def parentMismatch : AnnouncedBlockInput :=
  { valid with parentHashMatches := false }

theorem parent_mismatch_rejects :
    evaluateAnnouncedBlockRejection parentMismatch =
      some AnnouncedBlockReject.parentHashMismatch := by
  native_decide

def timestampDidNotAdvance : AnnouncedBlockInput :=
  { valid with announcedTimestampMs := valid.parentTimestampMs }

theorem timestamp_did_not_advance_rejects :
    evaluateAnnouncedBlockRejection timestampDidNotAdvance =
      some AnnouncedBlockReject.timestampDidNotAdvance := by
  native_decide

def futureSkew : AnnouncedBlockInput :=
  {
    parentHeight := 41,
    announcedHeight := 42,
    parentHashMatches := true,
    parentTimestampMs := 1000,
    announcedTimestampMs := 6001,
    nowMs := 1000,
    maxFutureSkewMs := 5000,
    hashMatchesWorkHash := true
  }

theorem future_skew_rejects :
    evaluateAnnouncedBlockRejection futureSkew =
      some AnnouncedBlockReject.futureSkew := by
  native_decide

def hashWorkHashMismatch : AnnouncedBlockInput :=
  { valid with hashMatchesWorkHash := false }

theorem hash_work_hash_mismatch_rejects :
    evaluateAnnouncedBlockRejection hashWorkHashMismatch =
      some AnnouncedBlockReject.hashWorkHashMismatch := by
  native_decide

def parent_mismatch_precedes_timestamp_failure_input : AnnouncedBlockInput :=
  { valid with parentHashMatches := false, announcedTimestampMs := valid.parentTimestampMs }

theorem parent_mismatch_precedes_timestamp_failure :
    evaluateAnnouncedBlockRejection parent_mismatch_precedes_timestamp_failure_input =
      some AnnouncedBlockReject.parentHashMismatch := by
  native_decide

def saturatedFutureLimitAcceptsMaxTimestamp : AnnouncedBlockInput :=
  {
    parentHeight := 7,
    announcedHeight := 8,
    parentHashMatches := true,
    parentTimestampMs := u64Max - 1,
    announcedTimestampMs := u64Max,
    nowMs := u64Max,
    maxFutureSkewMs := 10,
    hashMatchesWorkHash := true
  }

theorem saturated_future_limit_accepts_max_timestamp :
    evaluateAnnouncedBlockRejection saturatedFutureLimitAcceptsMaxTimestamp = none := by
  native_decide

end AnnouncedBlockAdmission
end Native
end Hegemon

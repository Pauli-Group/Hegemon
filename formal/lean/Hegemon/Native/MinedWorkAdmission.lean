namespace Hegemon
namespace Native
namespace MinedWorkAdmission

def u64Max : Nat := 18446744073709551615

def checkedAddOneU64 (value : Nat) : Option Nat :=
  if value < u64Max then some (value + 1) else none

inductive MinedWorkReject where
  | parentHashMismatch
  | heightNotNext
deriving DecidableEq, Repr

structure MinedWorkInput where
  bestHeight : Nat
  workHeight : Nat
  parentHashMatches : Bool
deriving DecidableEq, Repr

def nextHeightMatches (input : MinedWorkInput) : Bool :=
  checkedAddOneU64 input.bestHeight = some input.workHeight

def evaluateMinedWorkRejection
    (input : MinedWorkInput) : Option MinedWorkReject :=
  if input.parentHashMatches = false then
    some MinedWorkReject.parentHashMismatch
  else if nextHeightMatches input = false then
    some MinedWorkReject.heightNotNext
  else
    none

def minedWorkAccepts (input : MinedWorkInput) : Bool :=
  evaluateMinedWorkRejection input = none

def minedWorkPreconditions (input : MinedWorkInput) : Bool :=
  input.parentHashMatches && nextHeightMatches input

theorem accepts_iff_mined_work_preconditions
    {input : MinedWorkInput} :
    minedWorkAccepts input = true ↔
      minedWorkPreconditions input = true := by
  unfold minedWorkAccepts minedWorkPreconditions
  unfold evaluateMinedWorkRejection
  cases parent : input.parentHashMatches <;>
    cases next : nextHeightMatches input <;>
    simp

def valid : MinedWorkInput :=
  {
    bestHeight := 41,
    workHeight := 42,
    parentHashMatches := true
  }

theorem valid_accepts :
    evaluateMinedWorkRejection valid = none := by
  decide

def parentMismatch : MinedWorkInput :=
  { valid with parentHashMatches := false }

theorem parent_mismatch_rejects :
    evaluateMinedWorkRejection parentMismatch =
      some MinedWorkReject.parentHashMismatch := by
  decide

def heightMismatch : MinedWorkInput :=
  { valid with workHeight := 43 }

theorem height_mismatch_rejects :
    evaluateMinedWorkRejection heightMismatch =
      some MinedWorkReject.heightNotNext := by
  decide

def heightOverflow : MinedWorkInput :=
  {
    bestHeight := u64Max,
    workHeight := u64Max,
    parentHashMatches := true
  }

theorem height_overflow_rejects :
    evaluateMinedWorkRejection heightOverflow =
      some MinedWorkReject.heightNotNext := by
  decide

def parent_mismatch_precedes_height_failure_input : MinedWorkInput :=
  {
    bestHeight := u64Max,
    workHeight := u64Max,
    parentHashMatches := false
  }

theorem parent_mismatch_precedes_height_failure :
    evaluateMinedWorkRejection parent_mismatch_precedes_height_failure_input =
      some MinedWorkReject.parentHashMismatch := by
  decide

def maxPredecessorAcceptsMaxHeight : MinedWorkInput :=
  {
    bestHeight := u64Max - 1,
    workHeight := u64Max,
    parentHashMatches := true
  }

theorem max_predecessor_accepts_max_height :
    evaluateMinedWorkRejection maxPredecessorAcceptsMaxHeight = none := by
  decide

end MinedWorkAdmission
end Native
end Hegemon

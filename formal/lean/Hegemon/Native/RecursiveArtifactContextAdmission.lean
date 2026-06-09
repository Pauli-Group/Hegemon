namespace Hegemon
namespace Native
namespace RecursiveArtifactContextAdmission

def u64Max : Nat := 18446744073709551615

def checkedAddOneU64 (value : Nat) : Option Nat :=
  if value < u64Max then some (value + 1) else none

inductive RecursiveArtifactContextReject where
  | heightNotNext
deriving DecidableEq, Repr

structure RecursiveArtifactContextInput where
  bestHeight : Nat
deriving DecidableEq, Repr

def evaluateRecursiveArtifactContext
    (input : RecursiveArtifactContextInput) :
    Except RecursiveArtifactContextReject Nat :=
  match checkedAddOneU64 input.bestHeight with
  | some nextHeight => Except.ok nextHeight
  | none => Except.error RecursiveArtifactContextReject.heightNotNext

def recursiveArtifactContextAccepts
    (input : RecursiveArtifactContextInput) : Bool :=
  match evaluateRecursiveArtifactContext input with
  | Except.ok _ => true
  | Except.error _ => false

def recursiveArtifactContextPreconditions
    (input : RecursiveArtifactContextInput) : Bool :=
  (checkedAddOneU64 input.bestHeight).isSome

theorem accepts_iff_recursive_artifact_context_preconditions
    {input : RecursiveArtifactContextInput} :
    recursiveArtifactContextAccepts input = true ↔
      recursiveArtifactContextPreconditions input = true := by
  unfold recursiveArtifactContextAccepts
    recursiveArtifactContextPreconditions
    evaluateRecursiveArtifactContext
  cases checkedAddOneU64 input.bestHeight <;> simp

def valid : RecursiveArtifactContextInput :=
  {
    bestHeight := 41
  }

theorem valid_accepts :
    evaluateRecursiveArtifactContext valid = Except.ok 42 := by
  rfl

def heightOverflow : RecursiveArtifactContextInput :=
  {
    bestHeight := u64Max
  }

theorem height_overflow_rejects :
    evaluateRecursiveArtifactContext heightOverflow =
      Except.error RecursiveArtifactContextReject.heightNotNext := by
  rfl

def maxPredecessorAcceptsMaxHeight :
    RecursiveArtifactContextInput :=
  {
    bestHeight := u64Max - 1
  }

theorem max_predecessor_accepts_max_height :
    evaluateRecursiveArtifactContext maxPredecessorAcceptsMaxHeight =
      Except.ok u64Max := by
  rfl

end RecursiveArtifactContextAdmission
end Native
end Hegemon

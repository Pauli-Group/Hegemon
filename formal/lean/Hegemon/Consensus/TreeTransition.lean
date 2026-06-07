namespace Hegemon
namespace Consensus
namespace TreeTransition

inductive TreeTransitionReject where
  | startingRootMismatch
  | applyFailed
  | endingRootMismatch
deriving DecidableEq, Repr

structure TreeTransitionInput where
  parentRoot : Nat
  appliedRoot : Nat
  proofStartingRoot : Nat
  proofEndingRoot : Nat
  applyCommitmentsSucceeds : Bool
deriving DecidableEq, Repr

def evaluateTreeTransition (input : TreeTransitionInput) : Option TreeTransitionReject :=
  if input.proofStartingRoot = input.parentRoot then
    if input.applyCommitmentsSucceeds then
      if input.proofEndingRoot = input.appliedRoot then
        none
      else
        some TreeTransitionReject.endingRootMismatch
    else
      some TreeTransitionReject.applyFailed
  else
    some TreeTransitionReject.startingRootMismatch

def treeTransitionPreconditions (input : TreeTransitionInput) : Bool :=
  decide (input.proofStartingRoot = input.parentRoot)
    && input.applyCommitmentsSucceeds
    && decide (input.proofEndingRoot = input.appliedRoot)

def treeTransitionAccepts (input : TreeTransitionInput) : Bool :=
  evaluateTreeTransition input = none

def acceptedAppliedRoot (input : TreeTransitionInput) : Option Nat :=
  if treeTransitionAccepts input then
    some input.appliedRoot
  else
    none

theorem tree_transition_accepts_iff_preconditions (input : TreeTransitionInput) :
    treeTransitionAccepts input = treeTransitionPreconditions input := by
  unfold treeTransitionAccepts treeTransitionPreconditions evaluateTreeTransition
  by_cases hStart : input.proofStartingRoot = input.parentRoot
  · simp [hStart]
    cases input.applyCommitmentsSucceeds
    · simp
    · by_cases hEnd : input.proofEndingRoot = input.appliedRoot
      · simp [hEnd]
      · simp [hEnd]
  · simp [hStart]

def validInput : TreeTransitionInput :=
  {
    parentRoot := 11,
    appliedRoot := 12,
    proofStartingRoot := 11,
    proofEndingRoot := 12,
    applyCommitmentsSucceeds := true
  }

theorem valid_transition_accepts :
    evaluateTreeTransition validInput = none := by
  native_decide

theorem accepted_transition_returns_applied_root
    (input : TreeTransitionInput)
    (h : treeTransitionAccepts input = true) :
    acceptedAppliedRoot input = some input.appliedRoot := by
  simp [acceptedAppliedRoot, h]

theorem starting_root_mismatch_rejects :
    evaluateTreeTransition { validInput with proofStartingRoot := 99 } =
      some TreeTransitionReject.startingRootMismatch := by
  native_decide

theorem apply_failure_rejects :
    evaluateTreeTransition { validInput with applyCommitmentsSucceeds := false } =
      some TreeTransitionReject.applyFailed := by
  native_decide

theorem ending_root_mismatch_rejects :
    evaluateTreeTransition { validInput with proofEndingRoot := 99 } =
      some TreeTransitionReject.endingRootMismatch := by
  native_decide

theorem starting_root_mismatch_precedes_apply_failure :
    evaluateTreeTransition
        { validInput with
          proofStartingRoot := 99,
          applyCommitmentsSucceeds := false
        } =
      some TreeTransitionReject.startingRootMismatch := by
  native_decide

theorem apply_failure_precedes_ending_root_mismatch :
    evaluateTreeTransition
        { validInput with
          applyCommitmentsSucceeds := false,
          proofEndingRoot := 99
        } =
      some TreeTransitionReject.applyFailed := by
  native_decide

theorem empty_valid_transition_accepts :
    evaluateTreeTransition
        {
          parentRoot := 22,
          appliedRoot := 22,
          proofStartingRoot := 22,
          proofEndingRoot := 22,
          applyCommitmentsSucceeds := true
        } = none := by
  native_decide

end TreeTransition
end Consensus
end Hegemon

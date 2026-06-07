namespace Hegemon
namespace Native
namespace ResourceBudgetAdmission

def usizeMax : Nat := 18446744073709551615

def saturatingAdd (cap lhs rhs : Nat) : Nat :=
  if cap - lhs < rhs then cap else lhs + rhs

def saturatingSub (_cap lhs rhs : Nat) : Nat :=
  lhs - rhs

inductive BudgetReject where
  | mempoolByteBudgetExceeded
  | stagedProofByteBudgetExceeded
deriving DecidableEq, Repr

structure MempoolBudgetInput where
  pendingBytes : Nat
  candidateBytes : Nat
  maxBytes : Nat
deriving DecidableEq, Repr

structure StagedProofBudgetInput where
  stagedBytes : Nat
  existingBytes : Nat
  proofBytes : Nat
  maxBytes : Nat
deriving DecidableEq, Repr

def mempoolBudgetTotal (input : MempoolBudgetInput) : Nat :=
  saturatingAdd usizeMax input.pendingBytes input.candidateBytes

def stagedProofBudgetTotal (input : StagedProofBudgetInput) : Nat :=
  saturatingAdd usizeMax
    (saturatingSub usizeMax input.stagedBytes input.existingBytes)
    input.proofBytes

def evaluateMempoolBudgetRejection
    (input : MempoolBudgetInput) : Option BudgetReject :=
  if input.maxBytes < mempoolBudgetTotal input then
    some BudgetReject.mempoolByteBudgetExceeded
  else
    none

def evaluateStagedProofBudgetRejection
    (input : StagedProofBudgetInput) : Option BudgetReject :=
  if input.maxBytes < stagedProofBudgetTotal input then
    some BudgetReject.stagedProofByteBudgetExceeded
  else
    none

def mempoolBudgetAccepts (input : MempoolBudgetInput) : Bool :=
  evaluateMempoolBudgetRejection input = none

def stagedProofBudgetAccepts (input : StagedProofBudgetInput) : Bool :=
  evaluateStagedProofBudgetRejection input = none

theorem mempool_accepts_iff_not_over_limit
    {input : MempoolBudgetInput} :
    mempoolBudgetAccepts input = true ↔
      ¬ input.maxBytes < mempoolBudgetTotal input := by
  unfold mempoolBudgetAccepts evaluateMempoolBudgetRejection
  by_cases over : input.maxBytes < mempoolBudgetTotal input <;> simp [over]

theorem staged_proof_accepts_iff_not_over_limit
    {input : StagedProofBudgetInput} :
    stagedProofBudgetAccepts input = true ↔
      ¬ input.maxBytes < stagedProofBudgetTotal input := by
  unfold stagedProofBudgetAccepts evaluateStagedProofBudgetRejection
  by_cases over : input.maxBytes < stagedProofBudgetTotal input <;> simp [over]

theorem mempool_over_limit_rejects
    {input : MempoolBudgetInput}
    (over : input.maxBytes < mempoolBudgetTotal input) :
    evaluateMempoolBudgetRejection input =
      some BudgetReject.mempoolByteBudgetExceeded := by
  unfold evaluateMempoolBudgetRejection
  simp [over]

theorem mempool_within_limit_accepts
    {input : MempoolBudgetInput}
    (within : ¬ input.maxBytes < mempoolBudgetTotal input) :
    evaluateMempoolBudgetRejection input = none := by
  unfold evaluateMempoolBudgetRejection
  simp [within]

theorem staged_proof_over_limit_rejects
    {input : StagedProofBudgetInput}
    (over : input.maxBytes < stagedProofBudgetTotal input) :
    evaluateStagedProofBudgetRejection input =
      some BudgetReject.stagedProofByteBudgetExceeded := by
  unfold evaluateStagedProofBudgetRejection
  simp [over]

theorem staged_proof_within_limit_accepts
    {input : StagedProofBudgetInput}
    (within : ¬ input.maxBytes < stagedProofBudgetTotal input) :
    evaluateStagedProofBudgetRejection input = none := by
  unfold evaluateStagedProofBudgetRejection
  simp [within]

def mempoolExactLimitInput : MempoolBudgetInput :=
  {
    pendingBytes := 4,
    candidateBytes := 1,
    maxBytes := 5
  }

theorem mempool_exact_limit_accepts :
    evaluateMempoolBudgetRejection mempoolExactLimitInput = none := by
  native_decide

def mempoolOverLimitInput : MempoolBudgetInput :=
  {
    pendingBytes := 4,
    candidateBytes := 2,
    maxBytes := 5
  }

theorem mempool_over_limit_example_rejects :
    evaluateMempoolBudgetRejection mempoolOverLimitInput =
      some BudgetReject.mempoolByteBudgetExceeded := by
  native_decide

def mempoolSaturatedOverflowInput : MempoolBudgetInput :=
  {
    pendingBytes := usizeMax,
    candidateBytes := 1,
    maxBytes := usizeMax - 1
  }

theorem mempool_saturated_overflow_rejects :
    evaluateMempoolBudgetRejection mempoolSaturatedOverflowInput =
      some BudgetReject.mempoolByteBudgetExceeded := by
  native_decide

def stagedProofReplacementInput : StagedProofBudgetInput :=
  {
    stagedBytes := 4,
    existingBytes := 4,
    proofBytes := 5,
    maxBytes := 5
  }

theorem staged_proof_replacement_subtracts_existing :
    stagedProofBudgetTotal stagedProofReplacementInput = 5 := by
  native_decide

theorem staged_proof_replacement_accepts :
    evaluateStagedProofBudgetRejection stagedProofReplacementInput = none := by
  native_decide

def stagedProofOverLimitInput : StagedProofBudgetInput :=
  {
    stagedBytes := 4,
    existingBytes := 0,
    proofBytes := 2,
    maxBytes := 5
  }

theorem staged_proof_over_limit_example_rejects :
    evaluateStagedProofBudgetRejection stagedProofOverLimitInput =
      some BudgetReject.stagedProofByteBudgetExceeded := by
  native_decide

def stagedProofExistingOvercountInput : StagedProofBudgetInput :=
  {
    stagedBytes := 2,
    existingBytes := 4,
    proofBytes := 5,
    maxBytes := 5
  }

theorem staged_proof_existing_overcount_saturates_to_zero :
    stagedProofBudgetTotal stagedProofExistingOvercountInput = 5 := by
  native_decide

def stagedProofSaturatedOverflowInput : StagedProofBudgetInput :=
  {
    stagedBytes := usizeMax,
    existingBytes := 0,
    proofBytes := 1,
    maxBytes := usizeMax - 1
  }

theorem staged_proof_saturated_overflow_rejects :
    evaluateStagedProofBudgetRejection stagedProofSaturatedOverflowInput =
      some BudgetReject.stagedProofByteBudgetExceeded := by
  native_decide

end ResourceBudgetAdmission
end Native
end Hegemon

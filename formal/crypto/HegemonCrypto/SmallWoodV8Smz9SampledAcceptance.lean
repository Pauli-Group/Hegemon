import HegemonCrypto.SmallWoodV8Smz9AccumulatedExtraction

/-!
# Joint sampled acceptance for the fixed SMZ9 monomial source

The source has data rows `X^388`, `X^389`, and 138 zero rows; all five masks are zero.
The adversary may choose all five degree-at-most-387 responses after seeing the entire uniform
five-by-140 matrix. Only the final twenty-element subset is sampled freshly after that choice.
This module counts that joint experiment. It does not infer Fiat--Shamir/QROM freshness,
construct a knowledge extractor, prove PIOP semantic validity, or authorize production.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SampledAcceptance

open Polynomial
open scoped BigOperators
open V8Smz9AccumulatedExtraction V8Smz9OracleExtraction
open V8Smz9AdmissibleRootProbability UniformSubsetSampling

noncomputable section

set_option maxHeartbeats 100000
set_option maxRecDepth 5000

local instance : NeZero V8Smz9LogicalOracle.decsRowCount := ⟨by decide⟩
local instance : NeZero V8Smz9LogicalOracle.decsEta := ⟨by decide⟩

abbrev Matrix := Smz9Matrix
abbrev Response := Matrix → Fin V8Smz9LogicalOracle.decsEta → Goldilocks[X]

/-- The quantified response rule can depend arbitrarily on the complete matrix. -/
def ResponsesDegreeBounded (response : Response) : Prop :=
  ∀ matrix row, (response matrix row).natDegree ≤ 387

/-- Fixed before the matrix: two monomial rows in the exact 140-row field layout. -/
def fixedMonomialData (column : Fin V8Smz9LogicalOracle.decsRowCount)
    (index : Fin decsDomainSize) : Goldilocks :=
  (if column = 0 then V8Smz9DisjointCoset.evaluationPoint index ^ 388 else 0) +
    (if column = 1 then V8Smz9DisjointCoset.evaluationPoint index ^ 389 else 0)

def fixedMonomialMask (_row : Fin V8Smz9LogicalOracle.decsEta)
    (_index : Fin decsDomainSize) : Goldilocks := 0

/-- The exact linear response discrepancy for the fixed two-monomial, zero-mask source. -/
def discrepancy (matrix : Matrix) (response : Response)
    (row : Fin V8Smz9LogicalOracle.decsEta) : Goldilocks[X] :=
  C (matrix row 0) * X ^ 388 + C (matrix row 1) * X ^ 389 - response matrix row

/-- The discrepancy is the actual 140-data-plus-zero-mask response equation. -/
theorem discrepancy_eval_eq_source_response (matrix : Matrix) (response : Response)
    (row : Fin V8Smz9LogicalOracle.decsEta) (index : Fin decsDomainSize) :
    (discrepancy matrix response row).eval (V8Smz9DisjointCoset.evaluationPoint index) =
      (∑ column, matrix row column * fixedMonomialData column index) +
        fixedMonomialMask row index -
        (response matrix row).eval (V8Smz9DisjointCoset.evaluationPoint index) := by
  simp [discrepancy, fixedMonomialData, fixedMonomialMask, mul_add, Finset.sum_add_distrib]

def BothColumnsZero (matrix : Matrix) : Prop :=
  ∀ row, matrix row 0 = 0 ∧ matrix row 1 = 0

/-- A response is fixed before this joint agreement set is tested by the final subset. -/
def agreement (matrix : Matrix) (response : Response) : Finset (Fin decsDomainSize) :=
  Finset.univ.filter fun index => ∀ row,
    (discrepancy matrix response row).eval (V8Smz9DisjointCoset.evaluationPoint index) = 0

theorem discrepancy_degree_le (matrix : Matrix) (response : Response)
    (bounded : ResponsesDegreeBounded response)
    (row : Fin V8Smz9LogicalOracle.decsEta) :
    (discrepancy matrix response row).natDegree ≤ 389 := by
  unfold discrepancy
  apply (natDegree_sub_le _ _).trans
  apply max_le
  · apply (natDegree_add_le _ _).trans
    apply max_le
    · exact (natDegree_C_mul_le _ _).trans (by simp)
    · exact (natDegree_C_mul_le _ _).trans (by simp)
  · exact (bounded matrix row).trans (by decide)

theorem discrepancy_nonzero_of_column_nonzero (matrix : Matrix) (response : Response)
    (bounded : ResponsesDegreeBounded response)
    (row : Fin V8Smz9LogicalOracle.decsEta)
    (nonzero : matrix row 0 ≠ 0 ∨ matrix row 1 ≠ 0) :
    discrepancy matrix response row ≠ 0 := by
  have c388 : (response matrix row).coeff 388 = 0 :=
    coeff_eq_zero_of_natDegree_lt ((bounded matrix row).trans_lt (by decide))
  have c389 : (response matrix row).coeff 389 = 0 :=
    coeff_eq_zero_of_natDegree_lt ((bounded matrix row).trans_lt (by decide))
  intro zeroPolynomial
  rcases nonzero with first | second
  · have coefficient := congrArg (fun polynomial : Goldilocks[X] => polynomial.coeff 388)
      zeroPolynomial
    simp [discrepancy, coeff_C_mul, coeff_X_pow, c388] at coefficient
    exact first coefficient
  · have coefficient := congrArg (fun polynomial : Goldilocks[X] => polynomial.coeff 389)
      zeroPolynomial
    simp [discrepancy, coeff_C_mul, coeff_X_pow, c389] at coefficient
    exact second coefficient

/-- Outside the two-column-zero event, one nonzero discrepancy bounds common agreement. -/
theorem nonexceptional_agreement_card_le (matrix : Matrix) (response : Response)
    (bounded : ResponsesDegreeBounded response) (ordinary : ¬ BothColumnsZero matrix) :
    (agreement matrix response).card ≤ 389 := by
  classical
  have witness : ∃ row, matrix row 0 ≠ 0 ∨ matrix row 1 ≠ 0 := by
    simpa only [BothColumnsZero, not_forall, not_and_or] using ordinary
  obtain ⟨row, rowNonzero⟩ := witness
  have subset : agreement matrix response ⊆ decsRootIndices (discrepancy matrix response row) := by
    intro index member
    exact Finset.mem_filter.mpr
      ⟨Finset.mem_univ _, (Finset.mem_filter.mp member).2 row⟩
  exact (Finset.card_le_card subset).trans
    ((decs_root_indices_card_le
      (discrepancy_nonzero_of_column_nonzero matrix response bounded row rowNonzero)).trans
      (discrepancy_degree_le matrix response bounded row))

abbrev FreeColumn :=
  { column : Fin V8Smz9LogicalOracle.decsRowCount // column ≠ 0 ∧ column ≠ 1 }

abbrev ExceptionalMatrix := { matrix : Matrix // BothColumnsZero matrix }

noncomputable instance : Fintype ExceptionalMatrix := Fintype.ofFinite _

/-- Erasing the two constrained columns is a bijection, not an independence assumption. -/
def exceptionalMatrixEquiv : ExceptionalMatrix ≃
    (Fin V8Smz9LogicalOracle.decsEta → FreeColumn → Goldilocks) where
  toFun matrix row column := matrix.val row column.val
  invFun free := ⟨fun row column =>
    if kept : column ≠ 0 ∧ column ≠ 1 then free row ⟨column, kept⟩ else 0, by
      intro row
      simp⟩
  left_inv matrix := by
    apply Subtype.ext
    funext row column
    dsimp
    split_ifs with kept
    · rfl
    · rcases not_and_or.mp kept with first | second
      · have eqZero : column = 0 := Classical.not_not.mp first
        simpa only [eqZero] using (matrix.property row).1.symm
      · have eqOne : column = 1 := Classical.not_not.mp second
        simpa only [eqOne] using (matrix.property row).2.symm
  right_inv free := by
    funext row column
    exact dif_pos column.property

theorem free_column_card : Fintype.card FreeColumn = 138 := by decide

private theorem function_matrix_card (F Row Column : Type*)
    [Fintype F] [Fintype Row] [Fintype Column] [DecidableEq Row] [DecidableEq Column] :
    Fintype.card (Row → Column → F) =
      Fintype.card F ^ (Fintype.card Column * Fintype.card Row) := by
  simp only [Fintype.card_fun, pow_mul]

theorem exceptional_matrix_card :
    Fintype.card ExceptionalMatrix = Fintype.card Goldilocks ^ 690 := by
  calc
    Fintype.card ExceptionalMatrix =
        Fintype.card (Fin V8Smz9LogicalOracle.decsEta → FreeColumn → Goldilocks) :=
      Fintype.card_congr exceptionalMatrixEquiv
    _ = Fintype.card Goldilocks ^
        (Fintype.card FreeColumn * Fintype.card (Fin V8Smz9LogicalOracle.decsEta)) :=
      function_matrix_card _ _ _
    _ = Fintype.card Goldilocks ^ 690 := by
      apply congrArg (fun exponent : Nat => Fintype.card Goldilocks ^ exponent)
      rw [free_column_card, Fintype.card_fin]
      decide

theorem matrix_card : Fintype.card Matrix = Fintype.card Goldilocks ^ 700 := by
  calc
    Fintype.card Matrix = Fintype.card Goldilocks ^
        (Fintype.card (Fin V8Smz9LogicalOracle.decsRowCount) *
          Fintype.card (Fin V8Smz9LogicalOracle.decsEta)) := function_matrix_card _ _ _
    _ = Fintype.card Goldilocks ^ 700 := by
      apply congrArg (fun exponent : Nat => Fintype.card Goldilocks ^ exponent)
      rw [Fintype.card_fin, Fintype.card_fin]
      decide

def exceptionalProbability : Rat :=
  Fintype.card ExceptionalMatrix / Fintype.card Matrix

private theorem power_ratio (value : Rat) (nonzero : value ≠ 0) :
    value ^ 690 / value ^ 700 = (1 / value) ^ 10 := by
  field_simp [nonzero]

/-- The two simultaneous zero columns have exactly ten independent field constraints. -/
theorem exceptional_probability_exact :
    exceptionalProbability = ((1 : Rat) / Fintype.card Goldilocks) ^ 10 := by
  rw [exceptionalProbability, exceptional_matrix_card, matrix_card]
  simp only [Nat.cast_pow]
  have fieldCardNonzero : (Fintype.card Goldilocks : Rat) ≠ 0 := by
    exact_mod_cast Fintype.card_ne_zero (α := Goldilocks)
  exact power_ratio _ fieldCardNonzero

/-- Fresh uniform twenty-subset acceptance, conditional on the complete matrix/response prefix. -/
def conditionalAcceptanceProbability (matrix : Matrix) (response : Response) : Rat :=
  uniformBadSubsetProbability (Finset.univ : Finset (Fin decsDomainSize))
    (agreement matrix response) 20

def smallAgreementBound : Rat :=
  (Nat.choose 389 20 : Rat) / Nat.choose decsDomainSize 20

theorem conditional_acceptance_probability_le (matrix : Matrix) (response : Response)
    (bounded : ResponsesDegreeBounded response) (ordinary : ¬ BothColumnsZero matrix) :
    conditionalAcceptanceProbability matrix response ≤ smallAgreementBound := by
  unfold conditionalAcceptanceProbability smallAgreementBound
  have bound := uniform_bad_subset_probability_le (Finset.subset_univ _)
    (nonexceptional_agreement_card_le matrix response bounded ordinary)
    (show 20 ≤ (Finset.univ : Finset (Fin decsDomainSize)).card by
      rw [Finset.card_univ, Fintype.card_fin]
      decide)
  simpa only [Finset.card_univ, Fintype.card_fin] using bound

theorem conditional_acceptance_probability_le_one (matrix : Matrix) (response : Response) :
    conditionalAcceptanceProbability matrix response ≤ 1 := by
  unfold conditionalAcceptanceProbability uniformBadSubsetProbability
  apply (div_le_one (by
    rw [sample_space_card]
    exact_mod_cast Nat.choose_pos (show 20 ≤
      (Finset.univ : Finset (Fin decsDomainSize)).card by
        rw [Finset.card_univ, Fintype.card_fin]
        decide))).mpr
  exact_mod_cast Finset.card_le_card (Finset.filter_subset _ _)

/-- Average conditional acceptance over the uniform full matrix; the response remains dependent. -/
def jointAcceptanceProbability (response : Response) : Rat :=
  (∑ matrix : Matrix, conditionalAcceptanceProbability matrix response) / Fintype.card Matrix

/-- Accepted outcomes use the existing exact twenty-element challenge type. -/
abbrev AcceptedChallenge (matrix : Matrix) (response : Response) :=
  { challenge : V8Smz9LogicalOracle.DecsOpeningChallenge //
      challenge.val ⊆ agreement matrix response }

noncomputable instance (matrix : Matrix) (response : Response) :
    Fintype (AcceptedChallenge matrix response) := Fintype.ofFinite _

def acceptedChallengeEquivPowerset (matrix : Matrix) (response : Response) :
    AcceptedChallenge matrix response ≃
      { sample // sample ∈ (agreement matrix response).powersetCard 20 } where
  toFun challenge := ⟨challenge.val.val,
    Finset.mem_powersetCard.mpr ⟨challenge.property, challenge.val.property⟩⟩
  invFun sample := ⟨⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩,
    (Finset.mem_powersetCard.mp sample.property).1⟩
  left_inv _ := by apply Subtype.ext; apply Subtype.ext; rfl
  right_inv _ := by apply Subtype.ext; rfl

theorem accepted_challenge_card (matrix : Matrix) (response : Response) :
    Fintype.card (AcceptedChallenge matrix response) =
      Nat.choose (agreement matrix response).card 20 := by
  rw [Fintype.card_congr (acceptedChallengeEquivPowerset matrix response)]
  simp only [Fintype.card_coe, Finset.card_powersetCard]

abbrev AcceptedExperiment (response : Response) :=
  (matrix : Matrix) × AcceptedChallenge matrix response

/-- Exact accepted-outcome fraction in the independent matrix/subset product experiment. -/
def uniformExperimentAcceptanceProbability (response : Response) : Rat :=
  Fintype.card (AcceptedExperiment response) /
    (Fintype.card Matrix * Fintype.card V8Smz9LogicalOracle.DecsOpeningChallenge)

/-- Finite counting justifies averaging over the prefix; response independence is not assumed. -/
theorem joint_probability_eq_uniform_experiment (response : Response) :
    jointAcceptanceProbability response = uniformExperimentAcceptanceProbability response := by
  unfold jointAcceptanceProbability uniformExperimentAcceptanceProbability
  rw [Fintype.card_sigma, V8Smz9LogicalOracle.decs_opening_challenge_card]
  simp only [accepted_challenge_card, Nat.cast_sum]
  simp_rw [conditionalAcceptanceProbability,
    uniform_bad_subset_probability_exact (Finset.subset_univ _)]
  simp only [Finset.card_univ, Fintype.card_fin]
  rw [show V8Smz9LogicalOracle.decsOpeningCount = 20 by decide]
  rw [← Finset.sum_div, div_div, mul_comm]
  simp only [V8Smz9OracleExtraction.decsDomainSize]

private theorem weighted_average_identity (count exceptional bound : Rat) (nonzero : count ≠ 0) :
    count * bound + (1 - bound) * exceptional =
      (exceptional / count + (1 - exceptional / count) * bound) * count := by
  field_simp [nonzero]
  ring

/-- Pointwise conditioning permits matrix-dependent responses without multiplying unrelated events. -/
theorem joint_acceptance_probability_le (response : Response)
    (bounded : ResponsesDegreeBounded response) :
    jointAcceptanceProbability response ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 10 +
      (1 - ((1 : Rat) / Fintype.card Goldilocks) ^ 10) * smallAgreementBound := by
  classical
  have pointwise (matrix : Matrix) : conditionalAcceptanceProbability matrix response ≤
      smallAgreementBound + (1 - smallAgreementBound) *
        (if BothColumnsZero matrix then (1 : Rat) else 0) := by
    by_cases exceptional : BothColumnsZero matrix
    · simpa only [if_pos exceptional, mul_one, add_sub_cancel] using
        conditional_acceptance_probability_le_one matrix response
    · simpa only [if_neg exceptional, mul_zero, add_zero] using
        conditional_acceptance_probability_le matrix response bounded exceptional
  have indicatorCount : (∑ matrix : Matrix,
      if BothColumnsZero matrix then (1 : Rat) else 0) = Fintype.card ExceptionalMatrix := by
    simp only [Finset.sum_boole]
    exact congrArg (fun number : Nat => (number : Rat)) (Fintype.card_subtype _).symm
  have sumBound := Finset.sum_le_sum (fun matrix (_ : matrix ∈ (Finset.univ : Finset Matrix)) =>
    pointwise matrix)
  simp only [Finset.sum_add_distrib, Finset.sum_const, Finset.card_univ,
    nsmul_eq_mul, ← Finset.mul_sum, indicatorCount] at sumBound
  rw [← exceptional_probability_exact]
  unfold jointAcceptanceProbability exceptionalProbability
  have matrixPositive : (0 : Rat) < Fintype.card Matrix := by
    exact_mod_cast Fintype.card_pos (α := Matrix)
  apply (div_le_iff₀ matrixPositive).mpr
  apply sumBound.trans_eq
  exact weighted_average_identity _ _ _ (ne_of_gt matrixPositive)

/-- The complete finite experiment bound, including the fresh final twenty-subset draw. -/
theorem uniform_experiment_acceptance_probability_le (response : Response)
    (bounded : ResponsesDegreeBounded response) :
    uniformExperimentAcceptanceProbability response ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 10 +
      (1 - ((1 : Rat) / Fintype.card Goldilocks) ^ 10) *
        ((Nat.choose 389 20 : Rat) / Nat.choose decsDomainSize 20) := by
  rw [← joint_probability_eq_uniform_experiment]
  exact joint_acceptance_probability_le response bounded

end

end HegemonCrypto.SmallWood.V8Smz9SampledAcceptance

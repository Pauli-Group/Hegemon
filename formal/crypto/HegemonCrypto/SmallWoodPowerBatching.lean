import HegemonCrypto.FiniteFieldSampling
import Hegemon.Transaction.SmallWoodNoGrindingSoundness
import Mathlib.Algebra.BigOperators.Field
import Mathlib.Algebra.Polynomial.BigOperators
import Mathlib.Data.Fintype.BigOperators
import Mathlib.Data.Fintype.Powerset
import Mathlib.GroupTheory.Index

/-!
# SmallWood batching reductions

Historical DECS challenges sample one field element `gamma` per repetition and combine a
length-`n` residual vector as

`sum_j residual[j] * gamma^(j + 1)`.

The active Level-5 format instead samples the full uniform matrix required by SmallWood Theorem 1.
Its exact DECS term is one affine-fiber bound `|F|^-eta`, because a bad support is fixed from the
committed rows before the matrix is sampled. The scalar-power reduction below remains for
historical proof formats.
-/

namespace HegemonCrypto.SmallWoodPowerBatching

open Polynomial
open HegemonCrypto.FiniteFieldSampling
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodTranscriptBinding

noncomputable section

variable {F : Type*}
variable [Field F]

/-- Polynomial evaluated by the deployed scalar-power batching challenge. -/
def powerBatchPolynomial
    {width : Nat}
    (residual : Fin width -> F) : F[X] :=
  Finset.univ.sum fun index =>
    Polynomial.monomial (index.val + 1) (residual index)

/-- Every residual occupies its own nonconstant polynomial coefficient. -/
theorem power_batch_polynomial_coeff
    {width : Nat}
    (residual : Fin width -> F)
    (index : Fin width) :
    (powerBatchPolynomial residual).coeff (index.val + 1) =
      residual index := by
  simp only [powerBatchPolynomial, Polynomial.finsetSum_coeff]
  rw [Finset.sum_eq_single index]
  · simp
  · intro other _ otherNe
    rw [Polynomial.coeff_monomial, if_neg]
    intro exponentEqual
    apply otherNe
    apply Fin.ext
    omega
  · simp

/-- A nonzero residual vector yields a nonzero scalar-power polynomial. -/
theorem power_batch_polynomial_ne_zero
    {width : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0) :
    powerBatchPolynomial residual ≠ 0 := by
  obtain ⟨index, residualNonzero⟩ := hasNonzeroResidual
  intro polynomialZero
  have coefficientZero :
      (powerBatchPolynomial residual).coeff (index.val + 1) = 0 := by
    rw [polynomialZero]
    exact Polynomial.coeff_zero _
  rw [power_batch_polynomial_coeff] at coefficientZero
  exact residualNonzero coefficientZero

/-- The deployed exponent schedule `1, ..., width` has degree at most `width`. -/
theorem power_batch_polynomial_degree_le
    {width : Nat}
    (residual : Fin width -> F) :
    (powerBatchPolynomial residual).natDegree ≤ width := by
  apply Polynomial.natDegree_sum_le_of_forall_le Finset.univ
  intro index _
  exact (Polynomial.natDegree_monomial_le _).trans (by omega)

section Probability

variable [Fintype F] [DecidableEq F]

/-- Product probability for independent uniform scalar challenges. -/
def independentPowerBatchFailureProbability
    {width : Nat}
    (residual : Fin width -> F)
    (repetitions : Nat) : Rat :=
  (uniformRootProbability (powerBatchPolynomial residual)) ^ repetitions

/--
Exact finite-field reduction for the deployed challenge format: a nonzero residual survives
`repetitions` independent scalar-power checks with probability at most
`(width / |F|)^repetitions`.
-/
theorem independent_power_batch_failure_probability_le
    {width : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0)
    (repetitions : Nat) :
    independentPowerBatchFailureProbability residual repetitions ≤
      ((width : Rat) / Fintype.card F) ^ repetitions := by
  have polynomialNonzero :
      powerBatchPolynomial residual ≠ 0 :=
    power_batch_polynomial_ne_zero hasNonzeroResidual
  have oneRound :
      uniformRootProbability (powerBatchPolynomial residual) ≤
        (width : Rat) / Fintype.card F := by
    refine (uniform_root_probability_le_degree polynomialNonzero).trans ?_
    exact div_le_div_of_nonneg_right
      (by exact_mod_cast power_batch_polynomial_degree_le residual)
      (by positivity)
  exact pow_le_pow_left₀
    (uniform_root_probability_nonnegative (powerBatchPolynomial residual))
    oneRound
    repetitions

end Probability

section UniformMatrix

variable [Fintype F] [DecidableEq F]

/-- Linear form evaluated by one row of the active uniform DECS challenge matrix. -/
def uniformDotProduct
    {width : Nat}
    (residual coefficients : Fin width -> F) : F :=
  Finset.univ.sum fun index => residual index * coefficients index

/-- The active uniform batching check as an additive homomorphism in its random coefficients. -/
def uniformDotHom
    {width : Nat}
    (residual : Fin width -> F) : (Fin width -> F) →+ F where
  toFun := uniformDotProduct residual
  map_zero' := by
    simp [uniformDotProduct]
  map_add' left right := by
    simp [uniformDotProduct, mul_add, Finset.sum_add_distrib]

omit [Fintype F] [DecidableEq F] in
/-- A nonzero residual makes the uniform batching linear form surjective. -/
theorem uniform_dot_hom_surjective
    {width : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0) :
    Function.Surjective (uniformDotHom residual) := by
  obtain ⟨pivot, pivotNonzero⟩ := hasNonzeroResidual
  intro target
  let coefficients : Fin width -> F := fun index =>
    if index = pivot then target / residual pivot else 0
  refine ⟨coefficients, ?_⟩
  change uniformDotProduct residual coefficients = target
  rw [uniformDotProduct, Finset.sum_eq_single pivot]
  · simp only [coefficients, if_pos, div_eq_mul_inv]
    calc
      residual pivot * (target * (residual pivot)⁻¹) =
          target * (residual pivot * (residual pivot)⁻¹) := by ac_rfl
      _ = target := by rw [mul_inv_cancel₀ pivotNonzero, mul_one]
  · intro index _ indexNe
    simp [coefficients, indexNe]
  · simp

/-- Coefficient vectors whose active uniform batching row annihilates one residual vector. -/
def uniformDotZeroSet
    {width : Nat}
    (residual : Fin width -> F) : Finset (Fin width -> F) :=
  Finset.univ.filter fun coefficients =>
    uniformDotProduct residual coefficients = 0

/-- Coefficient vectors whose linear form takes one prescribed affine target. -/
def uniformDotFiberSet
    {width : Nat}
    (residual : Fin width -> F)
    (target : F) : Finset (Fin width -> F) :=
  Finset.univ.filter fun coefficients =>
    uniformDotProduct residual coefficients = target

/--
For a nonzero residual, every affine target has exactly the same number of coefficient preimages
as zero.  This is the finite-field fact used by the DECS expression `Gamma * v + u = 0`.
-/
theorem uniform_dot_fiber_card_eq_zero
    {width : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0)
    (target : F) :
    (uniformDotFiberSet residual target).card =
      (uniformDotZeroSet residual).card := by
  let hom := uniformDotHom residual
  have surjective : Function.Surjective hom :=
    uniform_dot_hom_surjective hasNonzeroResidual
  simpa [uniformDotFiberSet, uniformDotZeroSet, hom, uniformDotHom] using
    AddMonoidHom.card_fiber_eq_of_mem_range hom
      (surjective target) (surjective 0)

/-- Exact probability that one uniformly sampled coefficient row annihilates the residual. -/
def uniformDotZeroProbability
    {width : Nat}
    (residual : Fin width -> F) : Rat :=
  (uniformDotZeroSet residual).card / Fintype.card (Fin width -> F)

/--
Every output of a surjective additive homomorphism has the same number of coefficient preimages.
Consequently a nonzero residual is annihilated by exactly a `1 / |F|` fraction of all rows.
-/
theorem uniform_dot_zero_probability_exact
    {width : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0) :
    uniformDotZeroProbability residual = (1 : Rat) / Fintype.card F := by
  let hom := uniformDotHom residual
  have surjective : Function.Surjective hom :=
    uniform_dot_hom_surjective hasNonzeroResidual
  have fiberEqual : ∀ output : F,
      (Finset.univ.filter fun coefficients => hom coefficients = output).card =
        (Finset.univ.filter fun coefficients => hom coefficients = 0).card := by
    intro output
    exact AddMonoidHom.card_fiber_eq_of_mem_range hom
      (surjective output) (surjective 0)
  have partition :
      Fintype.card (Fin width -> F) =
        ∑ output : F,
          (Finset.univ.filter fun coefficients => hom coefficients = output).card := by
    simpa using
      (Finset.card_eq_sum_card_fiberwise
        (s := (Finset.univ : Finset (Fin width -> F)))
        (t := (Finset.univ : Finset F))
        (f := hom)
        (by simp))
  have partitionExact :
      Fintype.card (Fin width -> F) =
        Fintype.card F *
          (Finset.univ.filter fun coefficients => hom coefficients = 0).card := by
    calc
      Fintype.card (Fin width -> F) =
          ∑ output : F,
            (Finset.univ.filter fun coefficients => hom coefficients = output).card :=
        partition
      _ = ∑ _output : F,
            (Finset.univ.filter fun coefficients => hom coefficients = 0).card := by
        apply Finset.sum_congr rfl
        intro output _
        exact fiberEqual output
      _ = Fintype.card F *
            (Finset.univ.filter fun coefficients => hom coefficients = 0).card := by
        simp
  have zeroFiberPositive :
      0 < (Finset.univ.filter fun coefficients => hom coefficients = 0).card := by
    apply Finset.card_pos.mpr
    refine ⟨0, ?_⟩
    simp [hom, uniformDotHom, uniformDotProduct]
  have fieldCardPositive : 0 < Fintype.card F := Fintype.card_pos
  unfold uniformDotZeroProbability uniformDotZeroSet
  change
    ((Finset.univ.filter fun coefficients => hom coefficients = 0).card : Rat) /
        Fintype.card (Fin width -> F) =
      1 / Fintype.card F
  rw [partitionExact]
  push_cast
  field_simp

/-- Exact probability that one uniform row reaches one fixed affine target. -/
def uniformDotFiberProbability
    {width : Nat}
    (residual : Fin width -> F)
    (target : F) : Rat :=
  (uniformDotFiberSet residual target).card /
    Fintype.card (Fin width -> F)

theorem uniform_dot_fiber_probability_exact
    {width : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0)
    (target : F) :
    uniformDotFiberProbability residual target =
      (1 : Rat) / Fintype.card F := by
  rw [uniformDotFiberProbability,
    uniform_dot_fiber_card_eq_zero hasNonzeroResidual,
    ← uniformDotZeroProbability,
    uniform_dot_zero_probability_exact hasNonzeroResidual]

/-- Failure probability for `repetitions` independent active uniform challenge rows. -/
def independentUniformMatrixFailureProbability
    {width : Nat}
    (residual : Fin width -> F)
    (repetitions : Nat) : Rat :=
  (uniformDotZeroProbability residual) ^ repetitions

/-- The active full-matrix format has exact failure probability `|F|^-repetitions`. -/
theorem independent_uniform_matrix_failure_probability_exact
    {width : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0)
    (repetitions : Nat) :
    independentUniformMatrixFailureProbability residual repetitions =
      ((1 : Rat) / Fintype.card F) ^ repetitions := by
  rw [independentUniformMatrixFailureProbability,
    uniform_dot_zero_probability_exact hasNonzeroResidual]

/-- One row and one full matrix of active uniformly sampled batching coefficients. -/
abbrev CoefficientRow (width : Nat) := Fin width -> F
abbrev CoefficientMatrix (width repetitions : Nat) :=
  Fin repetitions -> CoefficientRow (F := F) width

/--
The concrete finite set of coefficient matrices that annihilate one residual in every row.
This is the actual finite sample-space event whose probability was previously represented only
as a power of the one-row probability.
-/
def uniformMatrixFailureSet
    {width : Nat}
    (residual : Fin width -> F)
    (repetitions : Nat) :
    Finset (CoefficientMatrix (F := F) width repetitions) :=
  Fintype.piFinset fun _ => uniformDotZeroSet residual

theorem uniform_matrix_failure_set_card
    {width : Nat}
    (residual : Fin width -> F)
    (repetitions : Nat) :
    (uniformMatrixFailureSet residual repetitions).card =
      (uniformDotZeroSet residual).card ^ repetitions := by
  simp [uniformMatrixFailureSet]

/-- Probability of the concrete all-rows matrix event in the finite uniform matrix space. -/
def uniformMatrixFailureProbability
    {width : Nat}
    (residual : Fin width -> F)
    (repetitions : Nat) : Rat :=
  (uniformMatrixFailureSet residual repetitions).card /
    Fintype.card (CoefficientMatrix (F := F) width repetitions)

/--
The concrete finite matrix event has exactly the independent product probability.  Independence
is therefore a theorem about the product sample space, not an ambient protocol assumption.
-/
theorem uniform_matrix_failure_probability_eq_independent
    {width : Nat}
    (residual : Fin width -> F)
    (repetitions : Nat) :
    uniformMatrixFailureProbability residual repetitions =
      independentUniformMatrixFailureProbability residual repetitions := by
  rw [uniformMatrixFailureProbability, uniform_matrix_failure_set_card,
    independentUniformMatrixFailureProbability, uniformDotZeroProbability]
  have totalCard :
      Fintype.card (CoefficientMatrix (F := F) width repetitions) =
        Fintype.card (CoefficientRow (F := F) width) ^ repetitions := by
    simp [CoefficientMatrix, CoefficientRow]
  rw [totalCard]
  push_cast
  exact (div_pow _ _ repetitions).symm

/--
Concrete finite matrix event for the DECS affine condition `Gamma * v + u = 0`, represented as
one prescribed target per independently sampled matrix row.
-/
def uniformAffineMatrixFailureSet
    {width repetitions : Nat}
    (residual : Fin width -> F)
    (target : Fin repetitions -> F) :
    Finset (CoefficientMatrix (F := F) width repetitions) :=
  Fintype.piFinset fun row =>
    uniformDotFiberSet residual (target row)

theorem uniform_affine_matrix_failure_set_card
    {width repetitions : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0)
    (target : Fin repetitions -> F) :
    (uniformAffineMatrixFailureSet residual target).card =
      (uniformDotZeroSet residual).card ^ repetitions := by
  rw [uniformAffineMatrixFailureSet, Fintype.card_piFinset]
  simp_rw [uniform_dot_fiber_card_eq_zero hasNonzeroResidual]
  simp

def uniformAffineMatrixFailureProbability
    {width repetitions : Nat}
    (residual : Fin width -> F)
    (target : Fin repetitions -> F) : Rat :=
  (uniformAffineMatrixFailureSet residual target).card /
    Fintype.card (CoefficientMatrix (F := F) width repetitions)

/-- Exact finite probability of the full affine DECS matrix condition. -/
theorem uniform_affine_matrix_failure_probability_exact
    {width repetitions : Nat}
    {residual : Fin width -> F}
    (hasNonzeroResidual : ∃ index, residual index ≠ 0)
    (target : Fin repetitions -> F) :
    uniformAffineMatrixFailureProbability residual target =
      ((1 : Rat) / Fintype.card F) ^ repetitions := by
  rw [uniformAffineMatrixFailureProbability,
    uniform_affine_matrix_failure_set_card hasNonzeroResidual]
  have totalCard :
      Fintype.card (CoefficientMatrix (F := F) width repetitions) =
        Fintype.card (CoefficientRow (F := F) width) ^ repetitions := by
    simp [CoefficientMatrix, CoefficientRow]
  rw [totalCard]
  push_cast
  rw [← div_pow]
  change
    uniformDotZeroProbability residual ^ repetitions =
      ((1 : Rat) / Fintype.card F) ^ repetitions
  rw [uniform_dot_zero_probability_exact hasNonzeroResidual]

/-- A finite family of residuals fails when one member is annihilated by the whole matrix. -/
def residualFamilyFailureSet
    {Index : Type*}
    [Fintype Index] [DecidableEq Index]
    {width : Nat}
    (residual : Index -> Fin width -> F)
    (repetitions : Nat) :
    Finset (CoefficientMatrix (F := F) width repetitions) :=
  Finset.univ.biUnion fun index =>
    uniformMatrixFailureSet (residual index) repetitions

/-- Probability of the union of all residual-family matrix failures. -/
def residualFamilyFailureProbability
    {Index : Type*}
    [Fintype Index] [DecidableEq Index]
    {width : Nat}
    (residual : Index -> Fin width -> F)
    (repetitions : Nat) : Rat :=
  (residualFamilyFailureSet residual repetitions).card /
    Fintype.card (CoefficientMatrix (F := F) width repetitions)

/--
Union bound for a finite family of nonzero residuals.  The only loss over the exact one-residual
probability is the number of candidate residuals.
-/
theorem residual_family_failure_probability_le
    {Index : Type*}
    [Fintype Index] [DecidableEq Index]
    {width : Nat}
    (residual : Index -> Fin width -> F)
    (allNonzero : ∀ index, ∃ coordinate, residual index coordinate ≠ 0)
    (repetitions : Nat) :
    residualFamilyFailureProbability residual repetitions ≤
      Fintype.card Index *
        (((1 : Rat) / Fintype.card F) ^ repetitions) := by
  let total :=
    Fintype.card (CoefficientMatrix (F := F) width repetitions)
  have totalPositive : (0 : Rat) < total := by
    exact_mod_cast Fintype.card_pos
  calc
    residualFamilyFailureProbability residual repetitions =
        (residualFamilyFailureSet residual repetitions).card / total := rfl
    _ ≤
        (∑ index : Index,
          (uniformMatrixFailureSet (residual index) repetitions).card : Nat) /
          total := by
      apply (div_le_div_iff_of_pos_right totalPositive).2
      exact_mod_cast Finset.card_biUnion_le
    _ =
        ∑ index : Index,
          ((uniformMatrixFailureSet (residual index) repetitions).card : Rat) /
            total := by
      push_cast
      exact Finset.sum_div Finset.univ
        (fun index =>
          ((uniformMatrixFailureSet (residual index) repetitions).card : Rat))
        total
    _ =
        ∑ _index : Index,
          (((1 : Rat) / Fintype.card F) ^ repetitions) := by
      apply Finset.sum_congr rfl
      intro index _
      rw [← independent_uniform_matrix_failure_probability_exact
          (allNonzero index) repetitions,
        ← uniform_matrix_failure_probability_eq_independent]
      rfl
    _ =
        Fintype.card Index *
          (((1 : Rat) / Fintype.card F) ^ repetitions) := by
      simp

/-- Union of the affine DECS matrix-failure events for a finite candidate family. -/
def affineResidualFamilyFailureSet
    {Index : Type*}
    [Fintype Index] [DecidableEq Index]
    {width repetitions : Nat}
    (residual : Index -> Fin width -> F)
    (target : Index -> Fin repetitions -> F) :
    Finset (CoefficientMatrix (F := F) width repetitions) :=
  Finset.univ.biUnion fun index =>
    uniformAffineMatrixFailureSet (residual index) (target index)

def affineResidualFamilyFailureProbability
    {Index : Type*}
    [Fintype Index] [DecidableEq Index]
    {width repetitions : Nat}
    (residual : Index -> Fin width -> F)
    (target : Index -> Fin repetitions -> F) : Rat :=
  (affineResidualFamilyFailureSet residual target).card /
    Fintype.card (CoefficientMatrix (F := F) width repetitions)

/--
The exact DECS family bound: each nonzero residual can hit an arbitrary affine target with
probability `|F|^-repetitions`, and a finite union loses only the family cardinality.
-/
theorem affine_residual_family_failure_probability_le
    {Index : Type*}
    [Fintype Index] [DecidableEq Index]
    {width repetitions : Nat}
    (residual : Index -> Fin width -> F)
    (target : Index -> Fin repetitions -> F)
    (allNonzero : ∀ index, ∃ coordinate, residual index coordinate ≠ 0) :
    affineResidualFamilyFailureProbability residual target ≤
      Fintype.card Index *
        (((1 : Rat) / Fintype.card F) ^ repetitions) := by
  let total :=
    Fintype.card (CoefficientMatrix (F := F) width repetitions)
  have totalPositive : (0 : Rat) < total := by
    exact_mod_cast Fintype.card_pos
  calc
    affineResidualFamilyFailureProbability residual target =
        (affineResidualFamilyFailureSet residual target).card / total := rfl
    _ ≤
        (∑ index : Index,
          (uniformAffineMatrixFailureSet
            (residual index) (target index)).card : Nat) / total := by
      apply (div_le_div_iff_of_pos_right totalPositive).2
      exact_mod_cast Finset.card_biUnion_le
    _ =
        ∑ index : Index,
          ((uniformAffineMatrixFailureSet
            (residual index) (target index)).card : Rat) / total := by
      push_cast
      exact Finset.sum_div Finset.univ
        (fun index =>
          ((uniformAffineMatrixFailureSet
            (residual index) (target index)).card : Rat))
        total
    _ =
        ∑ _index : Index,
          (((1 : Rat) / Fintype.card F) ^ repetitions) := by
      apply Finset.sum_congr rfl
      intro index _
      exact uniform_affine_matrix_failure_probability_exact
        (allNonzero index) (target index)
    _ =
        Fintype.card Index *
          (((1 : Rat) / Fintype.card F) ^ repetitions) := by
      simp

/-- Candidate low-degree supports considered by the active DECS extraction union bound. -/
abbrev FixedCardinalitySupport (width supportSize : Nat) :=
  { support : Finset (Fin width) // support.card = supportSize }

theorem fixed_cardinality_support_count
    (width supportSize : Nat) :
    Fintype.card (FixedCardinalitySupport width supportSize) =
      Nat.choose width supportSize := by
  simpa only [FixedCardinalitySupport, Fintype.card_fin] using
    (Fintype.card_finset_len (α := Fin width) supportSize)

/--
Homogeneous fixed-support union bound.  This is useful for the PIOP batching stage; the DECS stage
uses the affine theorem below.
-/
theorem fixed_support_uniform_matrix_failure_probability_le
    {width supportSize repetitions : Nat}
    (residual :
      FixedCardinalitySupport width supportSize -> Fin width -> F)
    (allNonzero : ∀ support, ∃ coordinate, residual support coordinate ≠ 0) :
    residualFamilyFailureProbability residual repetitions ≤
      Nat.choose width supportSize *
        (((1 : Rat) / Fintype.card F) ^ repetitions) := by
  simpa [fixed_cardinality_support_count] using
    residual_family_failure_probability_le residual allNonzero repetitions

/--
SmallWood's first failure term follows for any extraction reduction that assigns one nonzero
residual and one arbitrary affine offset to every support of size `d_decs + 2`.  The separate DECS
algebra theorem supplies these values from the over-degree interpolation witness.
-/
theorem fixed_support_uniform_affine_matrix_failure_probability_le
    {width supportSize repetitions : Nat}
    (residual :
      FixedCardinalitySupport width supportSize -> Fin width -> F)
    (target :
      FixedCardinalitySupport width supportSize -> Fin repetitions -> F)
    (allNonzero : ∀ support, ∃ coordinate, residual support coordinate ≠ 0) :
    affineResidualFamilyFailureProbability residual target ≤
      Nat.choose width supportSize *
        (((1 : Rat) / Fintype.card F) ^ repetitions) := by
  simpa [fixed_cardinality_support_count] using
    affine_residual_family_failure_probability_le
      residual target allNonzero

/--
Supports carrying an actual nonzero residual.  A bad Reed--Solomon word need not have a nonzero
residual on every support, so the production reduction ranges over this subtype rather than
assuming every fixed-cardinality support is bad.
-/
abbrev NonzeroResidualSupport
    {supportWidth supportSize residualWidth : Nat}
    (residual :
      FixedCardinalitySupport supportWidth supportSize -> Fin residualWidth -> F) :=
  { support : FixedCardinalitySupport supportWidth supportSize //
    ∃ coordinate, residual support coordinate ≠ 0 }

omit [Fintype F] in
/-- The number of genuinely bad supports is at most the full binomial support count. -/
theorem nonzero_residual_support_count_le
    {supportWidth supportSize residualWidth : Nat}
    (residual :
      FixedCardinalitySupport supportWidth supportSize -> Fin residualWidth -> F) :
    Fintype.card (NonzeroResidualSupport residual) ≤
      Nat.choose supportWidth supportSize := by
  classical
  calc
    Fintype.card (NonzeroResidualSupport residual) ≤
        Fintype.card (FixedCardinalitySupport supportWidth supportSize) :=
      Fintype.card_subtype_le _
    _ = Nat.choose supportWidth supportSize :=
      fixed_cardinality_support_count supportWidth supportSize

/--
Correct fixed-support DECS union bound.  Only supports with a nonzero residual participate; this
requires no false premise that every `supportSize` subset witnesses the bad word.
-/
theorem nonzero_support_uniform_affine_matrix_failure_probability_le
    {supportWidth supportSize residualWidth repetitions : Nat}
    (residual :
      FixedCardinalitySupport supportWidth supportSize -> Fin residualWidth -> F)
    (target :
      FixedCardinalitySupport supportWidth supportSize -> Fin repetitions -> F) :
    affineResidualFamilyFailureProbability
        (fun support : NonzeroResidualSupport residual =>
          residual support.val)
        (fun support : NonzeroResidualSupport residual =>
          target support.val) ≤
      Nat.choose supportWidth supportSize *
        (((1 : Rat) / Fintype.card F) ^ repetitions) := by
  classical
  have subtypeBound :=
    affine_residual_family_failure_probability_le
      (fun support : NonzeroResidualSupport residual =>
        residual support.val)
      (fun support : NonzeroResidualSupport residual =>
        target support.val)
      (fun support => support.property)
  calc
    affineResidualFamilyFailureProbability
        (fun support : NonzeroResidualSupport residual =>
          residual support.val)
        (fun support : NonzeroResidualSupport residual =>
          target support.val) ≤
        Fintype.card (NonzeroResidualSupport residual) *
          (((1 : Rat) / Fintype.card F) ^ repetitions) :=
      subtypeBound
    _ ≤ Nat.choose supportWidth supportSize *
          (((1 : Rat) / Fintype.card F) ^ repetitions) := by
      gcongr
      exact_mod_cast nonzero_residual_support_count_le residual

end UniformMatrix

/--
The executable 128-step multiplicative binomial routine used by the production ledger equals
Mathlib's combinatorial `Nat.choose`.  This bridge lets the finite support count feed the exact
integer security arithmetic without replacing the efficient checked evaluator.
-/
theorem ledger_binomial_eq_nat_choose
    (value count : Nat) :
    binomial value count = Nat.choose value count := by
  induction count with
  | zero =>
      simp [binomial]
  | succ count induction =>
      rw [binomial, List.range_succ, List.foldl_append]
      simp only [List.foldl_cons, List.foldl_nil]
      rw [← binomial, induction]
      exact Nat.div_eq_of_eq_mul_left
        (Nat.succ_pos count)
        (Nat.choose_succ_right_eq value count).symm

/--
The active ledger's first term is the exact single-support affine-fiber bound. The full uniform
matrix lets the extractor choose one nonzero support from the committed rows before the matrix
is sampled, so no union over supports is charged.
-/
theorem active_epsilon1_is_uniform_matrix_bound :
    (epsilon1Numerator : Rat) / epsilon1Denominator =
      ((1 : Rat) / goldilocksOrder) ^ activeProfile.decsEta := by
  rw [epsilon1Numerator, epsilon1Denominator]
  push_cast
  simp

/--
The active PIOP challenge is now the full uniform matrix required by SmallWood Theorem 7, so its
batching term is exactly `|F|^-rho` without a structured-distribution correction.
-/
theorem active_epsilon2_is_uniform_matrix_bound :
    (epsilon2Numerator : Rat) / epsilon2Denominator =
      ((1 : Rat) / goldilocksOrder) ^ activeProfile.rho := by
  rw [epsilon2Numerator, epsilon2Denominator]
  push_cast
  simp

end

end HegemonCrypto.SmallWoodPowerBatching

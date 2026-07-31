import HegemonCrypto.Goldilocks
import HegemonCrypto.SmallWoodPowerBatching
import Mathlib.LinearAlgebra.Lagrange

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

/-!
# SmallWood DECS extraction

This module proves the deterministic algebra behind the first SmallWood soundness term.  A word
outside the degree-`d` Reed--Solomon code has a support of `d + 2` evaluation points whose
Lagrange interpolant has a nonzero top coefficient.  The active uniform DECS challenge can hide
that residual only by satisfying the affine matrix equation counted in
`SmallWoodPowerBatching`.

No cryptographic assumption appears in these theorems.  Commitment binding and the
Fiat--Shamir/QROM transfer are separate reductions.
-/

namespace HegemonCrypto.SmallWood.DecsExtraction

open Polynomial
open scoped BigOperators
open HegemonCrypto.SmallWoodPowerBatching
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open Hegemon.Transaction.SmallWoodTranscriptBinding

noncomputable section

variable {F Index : Type*}
variable [Field F]
variable [DecidableEq Index]

/-- Top Lagrange coefficient on one candidate low-degree support. -/
def lagrangeResidual
    (support : Finset Index)
    (point : Index -> F)
    (values : Index -> F) : F :=
  (Lagrange.interpolate support point values).coeff (support.card - 1)

/-- The residual is linear in the opened values. -/
theorem lagrange_residual_add
    (support : Finset Index)
    (point : Index -> F)
    (left right : Index -> F) :
    lagrangeResidual support point (left + right) =
      lagrangeResidual support point left +
        lagrangeResidual support point right := by
  unfold lagrangeResidual
  rw [map_add, coeff_add]

/-- Scalar multiplication commutes with the residual. -/
theorem lagrange_residual_smul
    (support : Finset Index)
    (point : Index -> F)
    (scalar : F)
    (values : Index -> F) :
    lagrangeResidual support point (scalar • values) =
      scalar * lagrangeResidual support point values := by
  unfold lagrangeResidual
  rw [map_smul, coeff_smul]
  rfl

/-- A finite linear combination of words induces the same combination of residuals. -/
theorem lagrange_residual_sum
    {Row : Type*}
    (rows : Finset Row)
    (support : Finset Index)
    (point : Index -> F)
    (coefficient : Row -> F)
    (values : Row -> Index -> F) :
    lagrangeResidual support point
        (fun index => ∑ row ∈ rows, coefficient row * values row index) =
      ∑ row ∈ rows,
        coefficient row * lagrangeResidual support point (values row) := by
  classical
  induction rows using Finset.induction_on with
  | empty =>
      simp [lagrangeResidual]
  | @insert row rows rowNotMem induction =>
      simp only [Finset.sum_insert rowNotMem]
      rw [show
        (fun index =>
            coefficient row * values row index +
              ∑ selected ∈ rows, coefficient selected * values selected index) =
          coefficient row • values row +
            (fun index =>
              ∑ selected ∈ rows, coefficient selected * values selected index) by
        funext index
        simp]
      rw [lagrange_residual_add, lagrange_residual_smul, induction]

/--
On a support of size `degreeBound + 2`, a degree-`degreeBound` polynomial has zero top
interpolation coefficient.
-/
theorem lagrange_residual_of_low_degree_polynomial
    {support : Finset Index}
    {point values : Index -> F}
    {degreeBound : Nat}
    (supportCard : support.card = degreeBound + 2)
    (pointInjective : Set.InjOn point support)
    {polynomial : F[X]}
    (degreeBounded : polynomial.natDegree <= degreeBound)
    (agrees : ∀ index, index ∈ support ->
      polynomial.eval (point index) = values index) :
    lagrangeResidual support point values = 0 := by
  have polynomialDegreeLt : polynomial.degree < support.card := by
    refine lt_of_le_of_lt (degree_le_of_natDegree_le degreeBounded) ?_
    rw [supportCard]
    exact_mod_cast (by omega : degreeBound < degreeBound + 2)
  have interpolationEquation :
      polynomial = Lagrange.interpolate support point values :=
    Lagrange.eq_interpolate_of_eval_eq values pointInjective polynomialDegreeLt agrees
  rw [lagrangeResidual, ← interpolationEquation]
  apply coeff_eq_zero_of_natDegree_lt
  rw [supportCard]
  omega

/--
The top residual vanishes exactly when the support values are interpolated by a polynomial of degree at most
`degreeBound`.
-/
theorem lagrange_residual_eq_zero_iff
    {support : Finset Index}
    {point values : Index -> F}
    {degreeBound : Nat}
    (supportCard : support.card = degreeBound + 2)
    (pointInjective : Set.InjOn point support) :
    lagrangeResidual support point values = 0 ↔
      ∃ polynomial : F[X],
        polynomial.natDegree <= degreeBound ∧
          ∀ index ∈ support,
            polynomial.eval (point index) = values index := by
  constructor
  · intro residualZero
    let polynomial := Lagrange.interpolate support point values
    have polynomialDegree :
        polynomial.degree <= (support.card - 1 : Nat) :=
      Lagrange.degree_interpolate_le values pointInjective
    have polynomialNatDegree :
        polynomial.natDegree <= support.card - 1 :=
      natDegree_le_of_degree_le polynomialDegree
    have topCoefficientZero :
        polynomial.coeff (support.card - 1) = 0 := by
      simpa [polynomial, lagrangeResidual] using residualZero
    have reducedDegree :
        polynomial.natDegree <= support.card - 1 - 1 :=
      Polynomial.natDegree_le_pred polynomialNatDegree topCoefficientZero
    refine ⟨polynomial, ?_, ?_⟩
    · rw [supportCard] at reducedDegree
      omega
    · intro index indexMembership
      exact Lagrange.eval_interpolate_at_node values pointInjective indexMembership
  · rintro ⟨polynomial, degreeBounded, agrees⟩
    exact lagrange_residual_of_low_degree_polynomial
      supportCard pointInjective degreeBounded agrees

/-- A word is in the degree-bounded Reed--Solomon code on the selected domain. -/
def IsDegreeBoundedWord
    (domain : Finset Index)
    (point values : Index -> F)
    (degreeBound : Nat) : Prop :=
  ∃ polynomial : F[X],
    polynomial.natDegree <= degreeBound ∧
      ∀ index ∈ domain,
        polynomial.eval (point index) = values index

/--
Every word outside the degree-`degreeBound` code has a concrete `degreeBound + 2`-point
Lagrange witness with nonzero residual.
-/
theorem exists_nonzero_lagrange_residual
    {domain : Finset Index}
    {point values : Index -> F}
    {degreeBound : Nat}
    (enoughPoints : degreeBound + 2 <= domain.card)
    (pointInjective : Set.InjOn point domain)
    (notDegreeBounded :
      ¬ IsDegreeBoundedWord domain point values degreeBound) :
    ∃ support : Finset Index,
      support ⊆ domain ∧
        support.card = degreeBound + 2 ∧
          lagrangeResidual support point values ≠ 0 := by
  obtain ⟨base, baseSubset, baseCard⟩ :=
    Finset.exists_subset_card_eq
      (show degreeBound + 1 <= domain.card by omega)
  let basePolynomial := Lagrange.interpolate base point values
  have baseInjective : Set.InjOn point base :=
    pointInjective.mono (Finset.coe_subset.mpr baseSubset)
  have basePolynomialDegree :
      basePolynomial.degree <= (base.card - 1 : Nat) :=
    Lagrange.degree_interpolate_le values baseInjective
  have basePolynomialNatDegree :
      basePolynomial.natDegree <= degreeBound := by
    have := natDegree_le_of_degree_le basePolynomialDegree
    rw [baseCard] at this
    omega
  have mismatch :
      ∃ index ∈ domain,
        basePolynomial.eval (point index) ≠ values index := by
    by_contra noMismatch
    push Not at noMismatch
    exact notDegreeBounded
      ⟨basePolynomial, basePolynomialNatDegree, noMismatch⟩
  obtain ⟨outside, outsideDomain, outsideMismatch⟩ := mismatch
  have outsideNotBase : outside ∉ base := by
    intro outsideBase
    have agreesAtOutside :
        basePolynomial.eval (point outside) = values outside :=
      Lagrange.eval_interpolate_at_node values baseInjective outsideBase
    exact outsideMismatch agreesAtOutside
  let support := insert outside base
  have supportSubset : support ⊆ domain := by
    intro index indexMembership
    rcases Finset.mem_insert.mp indexMembership with rfl | inBase
    · exact outsideDomain
    · exact baseSubset inBase
  have supportCard : support.card = degreeBound + 2 := by
    simp [support, outsideNotBase, baseCard]
  have supportInjective : Set.InjOn point support :=
    pointInjective.mono (Finset.coe_subset.mpr supportSubset)
  refine ⟨support, supportSubset, supportCard, ?_⟩
  intro residualZero
  obtain ⟨supportPolynomial, supportPolynomialDegree, supportAgrees⟩ :=
    (lagrange_residual_eq_zero_iff supportCard supportInjective).mp residualZero
  have basePolynomialDegreeLt : basePolynomial.degree < base.card := by
    refine lt_of_le_of_lt
      (degree_le_of_natDegree_le basePolynomialNatDegree) ?_
    rw [baseCard]
    exact_mod_cast Nat.lt_succ_self degreeBound
  have supportPolynomialDegreeLt : supportPolynomial.degree < base.card := by
    refine lt_of_le_of_lt
      (degree_le_of_natDegree_le supportPolynomialDegree) ?_
    rw [baseCard]
    exact_mod_cast Nat.lt_succ_self degreeBound
  have polynomialsEqual : basePolynomial = supportPolynomial := by
    apply Polynomial.eq_of_degrees_lt_of_eval_index_eq base baseInjective
      basePolynomialDegreeLt supportPolynomialDegreeLt
    intro index indexMembership
    rw [Lagrange.eval_interpolate_at_node values baseInjective indexMembership]
    exact (supportAgrees index
      (Finset.mem_insert_of_mem indexMembership)).symm
  have supportAgreesOutside :
      supportPolynomial.eval (point outside) = values outside :=
    supportAgrees outside (Finset.mem_insert_self outside base)
  exact outsideMismatch (polynomialsEqual ▸ supportAgreesOutside)

/-- Affine combination used by one active DECS challenge row. -/
def affineCombinedWord
    {width repetitions : Nat}
    (rows : Fin width -> Index -> F)
    (mask : Fin repetitions -> Index -> F)
    (matrix : CoefficientMatrix (F := F) width repetitions)
    (repetition : Fin repetitions) : Index -> F :=
  fun index =>
    (∑ row, matrix repetition row * rows row index) +
      mask repetition index

/-- The residual of the verifier's masked combination is the affine matrix equation. -/
theorem affine_combined_word_residual
    {width repetitions : Nat}
    (support : Finset Index)
    (point : Index -> F)
    (rows : Fin width -> Index -> F)
    (mask : Fin repetitions -> Index -> F)
    (matrix : CoefficientMatrix (F := F) width repetitions)
    (repetition : Fin repetitions) :
    lagrangeResidual support point
        (affineCombinedWord rows mask matrix repetition) =
      uniformDotProduct
          (fun row => lagrangeResidual support point (rows row))
          (matrix repetition) +
        lagrangeResidual support point (mask repetition) := by
  change
    lagrangeResidual support point
        ((fun index => ∑ row, matrix repetition row * rows row index) +
          mask repetition) =
      (∑ row,
        lagrangeResidual support point (rows row) * matrix repetition row) +
        lagrangeResidual support point (mask repetition)
  rw [lagrange_residual_add]
  congr 1
  rw [lagrange_residual_sum Finset.univ support point
    (matrix repetition) rows]
  apply Finset.sum_congr rfl
  intro row _
  exact mul_comm _ _

/--
If every masked combination is degree bounded on a support carrying a nonzero row residual, the
sampled matrix lies in the exact affine failure set counted by the probability theorem.
-/
theorem degree_bounded_combinations_imply_affine_failure
    [Fintype F] [DecidableEq F]
    {width repetitions degreeBound : Nat}
    {support : Finset Index}
    {point : Index -> F}
    (supportCard : support.card = degreeBound + 2)
    (pointInjective : Set.InjOn point support)
    (rows : Fin width -> Index -> F)
    (mask : Fin repetitions -> Index -> F)
    (matrix : CoefficientMatrix (F := F) width repetitions)
    (combinedDegreeBounded : ∀ repetition,
      IsDegreeBoundedWord support point
        (affineCombinedWord rows mask matrix repetition) degreeBound) :
    matrix ∈ uniformAffineMatrixFailureSet
      (fun row => lagrangeResidual support point (rows row))
      (fun repetition =>
        -lagrangeResidual support point (mask repetition)) := by
  rw [uniformAffineMatrixFailureSet, Fintype.mem_piFinset]
  intro repetition
  simp only [uniformDotFiberSet, Finset.mem_filter, Finset.mem_univ, true_and]
  obtain ⟨polynomial, polynomialDegree, polynomialAgrees⟩ :=
    combinedDegreeBounded repetition
  have residualZero :
      lagrangeResidual support point
          (affineCombinedWord rows mask matrix repetition) = 0 :=
    lagrange_residual_of_low_degree_polynomial supportCard pointInjective
      polynomialDegree polynomialAgrees
  rw [affine_combined_word_residual] at residualZero
  exact eq_neg_of_add_eq_zero_left residualZero

/-- Residual vector attached to one fixed-cardinality DECS support. -/
def supportResidual
    {domainSize width supportSize : Nat}
    (point : Fin domainSize -> F)
    (rows : Fin width -> Fin domainSize -> F)
    (support : FixedCardinalitySupport domainSize supportSize) :
    Fin width -> F :=
  fun row => lagrangeResidual support.val point (rows row)

/-- Affine offset contributed by the independently committed masking word. -/
def supportMaskTarget
    {domainSize repetitions supportSize : Nat}
    (point : Fin domainSize -> F)
    (mask : Fin repetitions -> Fin domainSize -> F)
    (support : FixedCardinalitySupport domainSize supportSize) :
    Fin repetitions -> F :=
  fun repetition =>
    -lagrangeResidual support.val point (mask repetition)

/-- Fixed-cardinality supports that witness at least one nonzero committed-row residual. -/
abbrev BadSupport
    {domainSize width supportSize : Nat}
    (point : Fin domainSize -> F)
    (rows : Fin width -> Fin domainSize -> F) :=
  NonzeroResidualSupport
    (supportResidual
      (domainSize := domainSize)
      (width := width)
      (supportSize := supportSize)
      point rows)

/--
Finite matrix event in which every masked challenge combination is a degree-bounded word on the
full DECS evaluation domain.
-/
noncomputable def degreeEnforcementFailureSet
    [Fintype F] [DecidableEq F]
    {domainSize width repetitions degreeBound : Nat}
    (point : Fin domainSize -> F)
    (rows : Fin width -> Fin domainSize -> F)
    (mask : Fin repetitions -> Fin domainSize -> F) :
    Finset (CoefficientMatrix (F := F) width repetitions) := by
  classical
  exact Finset.univ.filter fun matrix =>
    ∀ repetition,
      IsDegreeBoundedWord Finset.univ point
        (affineCombinedWord rows mask matrix repetition) degreeBound

noncomputable def degreeEnforcementFailureProbability
    [Fintype F] [DecidableEq F]
    {domainSize width repetitions degreeBound : Nat}
    (point : Fin domainSize -> F)
    (rows : Fin width -> Fin domainSize -> F)
    (mask : Fin repetitions -> Fin domainSize -> F) : Rat :=
  (degreeEnforcementFailureSet
      (degreeBound := degreeBound) point rows mask).card /
    Fintype.card (CoefficientMatrix (F := F) width repetitions)

/--
If one committed row is not degree bounded, every matrix that makes all masked combinations
degree bounded belongs to the affine failure union over genuinely bad supports.
-/
theorem degree_enforcement_failure_subset_affine_bad_supports
    [Fintype F] [DecidableEq F]
    {domainSize width repetitions degreeBound : Nat}
    (enoughPoints : degreeBound + 2 <= domainSize)
    (point : Fin domainSize -> F)
    (pointInjective : Function.Injective point)
    (rows : Fin width -> Fin domainSize -> F)
    (mask : Fin repetitions -> Fin domainSize -> F)
    (hasBadRow : ∃ row,
      ¬ IsDegreeBoundedWord Finset.univ point (rows row) degreeBound) :
    degreeEnforcementFailureSet
        (degreeBound := degreeBound) point rows mask ⊆
      affineResidualFamilyFailureSet
        (fun support :
            BadSupport (supportSize := degreeBound + 2) point rows =>
          supportResidual
            (domainSize := domainSize) (width := width) point rows support.val)
        (fun support :
            BadSupport (supportSize := degreeBound + 2) point rows =>
          supportMaskTarget
            (domainSize := domainSize) (repetitions := repetitions)
            point mask support.val) := by
  classical
  intro matrix matrixFailure
  have allCombinationsDegreeBounded :
      ∀ repetition,
        IsDegreeBoundedWord Finset.univ point
          (affineCombinedWord rows mask matrix repetition) degreeBound :=
    (Finset.mem_filter.mp
      (show matrix ∈ Finset.univ.filter (fun selected =>
        ∀ repetition,
          IsDegreeBoundedWord Finset.univ point
            (affineCombinedWord rows mask selected repetition) degreeBound) by
        simpa [degreeEnforcementFailureSet] using matrixFailure)).2
  obtain ⟨badRow, badRowNotDegreeBounded⟩ := hasBadRow
  obtain ⟨support, _supportSubset, supportCard, supportResidualNonzero⟩ :=
    exists_nonzero_lagrange_residual
      (domain := Finset.univ)
      (point := point)
      (values := rows badRow)
      (degreeBound := degreeBound)
      (by simpa using enoughPoints)
      pointInjective.injOn
      badRowNotDegreeBounded
  let fixedSupport :
      FixedCardinalitySupport domainSize (degreeBound + 2) :=
    ⟨support, supportCard⟩
  have fixedSupportBad :
      ∃ coordinate,
        supportResidual
          (domainSize := domainSize) (width := width)
          point rows fixedSupport coordinate ≠ 0 := by
    exact ⟨badRow, supportResidualNonzero⟩
  let badSupport :
      BadSupport (supportSize := degreeBound + 2) point rows :=
    ⟨fixedSupport, fixedSupportBad⟩
  rw [affineResidualFamilyFailureSet]
  apply Finset.mem_biUnion.mpr
  refine ⟨badSupport, Finset.mem_univ _, ?_⟩
  apply degree_bounded_combinations_imply_affine_failure
    supportCard
    (pointInjective.injOn)
    rows
    mask
    matrix
  intro repetition
  obtain ⟨polynomial, polynomialDegree, polynomialAgrees⟩ :=
    allCombinationsDegreeBounded repetition
  exact ⟨polynomial, polynomialDegree, fun index _ =>
    polynomialAgrees index (Finset.mem_univ index)⟩

/--
Concrete DECS degree-enforcement bound for fixed committed rows and masks.  The probability is over
the exact finite uniform challenge-matrix sample space; the only premise is that at least one row
is outside the degree-bounded code.
-/
theorem degree_enforcement_failure_probability_le
    [Fintype F] [DecidableEq F]
    {domainSize width repetitions degreeBound : Nat}
    (enoughPoints : degreeBound + 2 <= domainSize)
    (point : Fin domainSize -> F)
    (pointInjective : Function.Injective point)
    (rows : Fin width -> Fin domainSize -> F)
    (mask : Fin repetitions -> Fin domainSize -> F)
    (hasBadRow : ∃ row,
      ¬ IsDegreeBoundedWord Finset.univ point (rows row) degreeBound) :
    degreeEnforcementFailureProbability
        (degreeBound := degreeBound) point rows mask ≤
      Nat.choose domainSize (degreeBound + 2) *
        (((1 : Rat) / Fintype.card F) ^ repetitions) := by
  classical
  let total :=
    Fintype.card (CoefficientMatrix (F := F) width repetitions)
  have totalPositive : (0 : Rat) < total := by
    exact_mod_cast Fintype.card_pos
  have eventSubset :=
    degree_enforcement_failure_subset_affine_bad_supports
      enoughPoints point pointInjective rows mask hasBadRow
  calc
    degreeEnforcementFailureProbability
        (degreeBound := degreeBound) point rows mask =
        (degreeEnforcementFailureSet
          (degreeBound := degreeBound) point rows mask).card / total := rfl
    _ ≤
        (affineResidualFamilyFailureSet
          (fun support :
              BadSupport (supportSize := degreeBound + 2) point rows =>
            supportResidual
              (domainSize := domainSize) (width := width)
              point rows support.val)
          (fun support :
              BadSupport (supportSize := degreeBound + 2) point rows =>
            supportMaskTarget
              (domainSize := domainSize) (repetitions := repetitions)
              point mask support.val)).card / total := by
      apply (div_le_div_iff_of_pos_right totalPositive).2
      exact_mod_cast Finset.card_le_card eventSubset
    _ =
        affineResidualFamilyFailureProbability
          (fun support :
              BadSupport (supportSize := degreeBound + 2) point rows =>
            supportResidual
              (domainSize := domainSize) (width := width)
              point rows support.val)
          (fun support :
              BadSupport (supportSize := degreeBound + 2) point rows =>
            supportMaskTarget
              (domainSize := domainSize) (repetitions := repetitions)
              point mask support.val) := rfl
    _ ≤ Nat.choose domainSize (degreeBound + 2) *
          (((1 : Rat) / Fintype.card F) ^ repetitions) :=
      nonzero_support_uniform_affine_matrix_failure_probability_le
        (supportResidual
          (domainSize := domainSize)
          (width := width)
          (supportSize := degreeBound + 2) point rows)
        (supportMaskTarget
          (domainSize := domainSize)
          (repetitions := repetitions)
          (supportSize := degreeBound + 2) point mask)

/--
For the full uniform coefficient matrix used by Hegemon V4, the bad support can be selected once
from the committed rows before the verifier samples the matrix.  The verifier-failure event is
therefore contained in one affine fiber, not a union over every possible support.

This strengthening does not apply to SmallWood's structured scalar-power challenge.  It relies on
all `width * repetitions` coefficients being independent uniform field elements.
-/
theorem uniform_matrix_degree_enforcement_failure_probability_le
    [Fintype F] [DecidableEq F]
    {domainSize width repetitions degreeBound : Nat}
    (enoughPoints : degreeBound + 2 <= domainSize)
    (point : Fin domainSize -> F)
    (pointInjective : Function.Injective point)
    (rows : Fin width -> Fin domainSize -> F)
    (mask : Fin repetitions -> Fin domainSize -> F)
    (hasBadRow : ∃ row,
      ¬ IsDegreeBoundedWord Finset.univ point (rows row) degreeBound) :
    degreeEnforcementFailureProbability
        (degreeBound := degreeBound) point rows mask ≤
      ((1 : Rat) / Fintype.card F) ^ repetitions := by
  classical
  obtain ⟨badRow, badRowNotDegreeBounded⟩ := hasBadRow
  obtain ⟨support, _supportSubset, supportCard, supportResidualNonzero⟩ :=
    exists_nonzero_lagrange_residual
      (domain := Finset.univ)
      (point := point)
      (values := rows badRow)
      (degreeBound := degreeBound)
      (by simpa using enoughPoints)
      pointInjective.injOn
      badRowNotDegreeBounded
  let fixedSupport :
      FixedCardinalitySupport domainSize (degreeBound + 2) :=
    ⟨support, supportCard⟩
  have fixedSupportBad :
      ∃ coordinate,
        supportResidual
          (domainSize := domainSize) (width := width)
          point rows fixedSupport coordinate ≠ 0 := by
    exact ⟨badRow, supportResidualNonzero⟩
  have eventSubset :
      degreeEnforcementFailureSet
          (degreeBound := degreeBound) point rows mask ⊆
        uniformAffineMatrixFailureSet
          (supportResidual
            (domainSize := domainSize) (width := width)
            point rows fixedSupport)
          (supportMaskTarget
            (domainSize := domainSize) (repetitions := repetitions)
            point mask fixedSupport) := by
    intro matrix matrixFailure
    have allCombinationsDegreeBounded :
        ∀ repetition,
          IsDegreeBoundedWord Finset.univ point
            (affineCombinedWord rows mask matrix repetition) degreeBound :=
      (Finset.mem_filter.mp
        (show matrix ∈ Finset.univ.filter (fun selected =>
          ∀ repetition,
            IsDegreeBoundedWord Finset.univ point
              (affineCombinedWord rows mask selected repetition) degreeBound) by
          simpa [degreeEnforcementFailureSet] using matrixFailure)).2
    apply degree_bounded_combinations_imply_affine_failure
      supportCard
      pointInjective.injOn
      rows
      mask
      matrix
    intro repetition
    obtain ⟨polynomial, polynomialDegree, polynomialAgrees⟩ :=
      allCombinationsDegreeBounded repetition
    exact ⟨polynomial, polynomialDegree, fun index _ =>
      polynomialAgrees index (Finset.mem_univ index)⟩
  let total :=
    Fintype.card (CoefficientMatrix (F := F) width repetitions)
  have totalPositive : (0 : Rat) < total := by
    exact_mod_cast Fintype.card_pos
  calc
    degreeEnforcementFailureProbability
        (degreeBound := degreeBound) point rows mask =
        (degreeEnforcementFailureSet
          (degreeBound := degreeBound) point rows mask).card / total := rfl
    _ ≤
        (uniformAffineMatrixFailureSet
          (supportResidual
            (domainSize := domainSize) (width := width)
            point rows fixedSupport)
          (supportMaskTarget
            (domainSize := domainSize) (repetitions := repetitions)
            point mask fixedSupport)).card / total := by
      apply (div_le_div_iff_of_pos_right totalPositive).2
      exact_mod_cast Finset.card_le_card eventSubset
    _ =
        uniformAffineMatrixFailureProbability
          (supportResidual
            (domainSize := domainSize) (width := width)
            point rows fixedSupport)
          (supportMaskTarget
            (domainSize := domainSize) (repetitions := repetitions)
            point mask fixedSupport) := rfl
    _ = ((1 : Rat) / Fintype.card F) ^ repetitions :=
      uniform_affine_matrix_failure_probability_exact
        fixedSupportBad
        (supportMaskTarget
          (domainSize := domainSize) (repetitions := repetitions)
          point mask fixedSupport)

/--
Active Level-5 instantiation of the V4 DECS degree-enforcement theorem. The committed rows fix
one bad support before the full uniform challenge matrix is sampled, so the production ledger
uses the exact `|Goldilocks|^-eta` affine-fiber term.
-/
theorem active_degree_enforcement_failure_probability_le
    (point : Fin activeProfile.decsNbEvals -> Goldilocks)
    (pointInjective : Function.Injective point)
    (rows :
      Fin activeLvcsRowCount ->
        Fin activeProfile.decsNbEvals -> Goldilocks)
    (mask :
      Fin activeProfile.decsEta ->
        Fin activeProfile.decsNbEvals -> Goldilocks)
    (hasBadRow : ∃ row,
      ¬ IsDegreeBoundedWord Finset.univ point
        (rows row) activeDecsPolynomialDegree) :
    degreeEnforcementFailureProbability
        (degreeBound := activeDecsPolynomialDegree)
        point rows mask ≤
      (epsilon1Numerator : Rat) / epsilon1Denominator := by
  calc
    degreeEnforcementFailureProbability
        (degreeBound := activeDecsPolynomialDegree)
        point rows mask ≤
        (((1 : Rat) / goldilocksOrder) ^
          activeProfile.decsEta) :=
      by
        simpa only [goldilocks_card, goldilocksModulus, goldilocksOrder] using
          uniform_matrix_degree_enforcement_failure_probability_le
            (by decide)
            point
            pointInjective
            rows
            mask
            hasBadRow
    _ = (epsilon1Numerator : Rat) / epsilon1Denominator :=
      active_epsilon1_is_uniform_matrix_bound.symm

end

end HegemonCrypto.SmallWood.DecsExtraction

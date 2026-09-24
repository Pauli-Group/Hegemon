import HegemonCrypto.SmallWoodOracleExtraction
import Mathlib.LinearAlgebra.Lagrange

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact SmallWood DECS polynomial restoration

The production verifier receives the coefficients in degrees `k .. d` and evaluations at `k`
distinct DECS points.  Rust's `poly_restore` subtracts the transmitted high-degree part from
those evaluations, interpolates the remaining degree-`k - 1` polynomial, and adds the two parts.

This module proves that construction is exact and unique.  It is deterministic polynomial
algebra and does not use a cryptographic assumption.
-/

namespace HegemonCrypto.SmallWood.DecsRestore

open Polynomial
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.RoundByRound

noncomputable section

variable {F Index : Type*}
variable [Field F]
variable [DecidableEq Index]

/-- Two polynomials carry exactly the same transmitted coefficients from degree `k` upward. -/
def SameHighCoefficients (k : Nat) (left right : F[X]) : Prop :=
  ∀ degree, k ≤ degree -> left.coeff degree = right.coeff degree

/-- Equal high coefficients force the difference to have degree strictly below the cutoff. -/
theorem degree_sub_lt_of_same_high_coefficients
    {k : Nat}
    {left right : F[X]}
    (sameHigh : SameHighCoefficients k left right) :
    (left - right).degree < k := by
  rw [degree_lt_iff_coeff_zero]
  intro degree highDegree
  rw [coeff_sub, sameHigh degree highDegree, sub_self]

omit [DecidableEq Index] in
/--
The high coefficients and `k` evaluations at distinct points determine at most one polynomial.
This is the algebraic uniqueness property used by production `poly_restore`.
-/
theorem eq_of_same_high_coefficients_and_eval
    {support : Finset Index}
    {point : Index -> F}
    {k : Nat}
    {left right : F[X]}
    (supportCard : support.card = k)
    (pointInjective : Set.InjOn point support)
    (sameHigh : SameHighCoefficients k left right)
    (sameEval :
      ∀ index ∈ support,
        left.eval (point index) = right.eval (point index)) :
    left = right := by
  apply Polynomial.eq_of_degree_sub_lt_of_eval_index_eq
    support pointInjective
  · rw [supportCard]
    exact degree_sub_lt_of_same_high_coefficients sameHigh
  · exact sameEval

/--
Restore a polynomial from its high-degree part and evaluations of the complete polynomial.
The caller supplies the high part with its coefficients already placed at their actual degrees,
matching Rust's `x^k * poly(high, x)` calculation.
-/
def restorePolynomial
    (support : Finset Index)
    (point : Index -> F)
    (highPart : F[X])
    (evaluations : Index -> F) : F[X] :=
  Lagrange.interpolate support point
      (fun index => evaluations index - highPart.eval (point index)) +
    highPart

/-- Restoration reproduces every supplied evaluation. -/
theorem restore_polynomial_eval
    {support : Finset Index}
    {point : Index -> F}
    {highPart : F[X]}
    {evaluations : Index -> F}
    (pointInjective : Set.InjOn point support)
    {index : Index}
    (indexMembership : index ∈ support) :
    (restorePolynomial support point highPart evaluations).eval (point index) =
      evaluations index := by
  rw [restorePolynomial, eval_add,
    Lagrange.eval_interpolate_at_node _ pointInjective indexMembership]
  exact sub_add_cancel _ _

/-- Restoration leaves every coefficient at or above the number of samples unchanged. -/
theorem restore_polynomial_same_high_coefficients
    {support : Finset Index}
    {point : Index -> F}
    {highPart : F[X]}
    {evaluations : Index -> F}
    (pointInjective : Set.InjOn point support) :
    SameHighCoefficients support.card
      (restorePolynomial support point highPart evaluations)
      highPart := by
  intro degree highDegree
  rw [restorePolynomial, coeff_add]
  have interpolationDegree :
      (Lagrange.interpolate support point
        (fun index => evaluations index - highPart.eval (point index))).degree <
          support.card :=
    Lagrange.degree_interpolate_lt _ pointInjective
  have coefficientZero :
      (Lagrange.interpolate support point
        (fun index => evaluations index - highPart.eval (point index))).coeff degree = 0 :=
    coeff_eq_zero_of_degree_lt
      (interpolationDegree.trans_le (by exact_mod_cast highDegree))
  rw [coefficientZero, zero_add]

/-- Restoration remains within any degree bound containing both pieces. -/
theorem restore_polynomial_natDegree_le
    {support : Finset Index}
    {point : Index -> F}
    {highPart : F[X]}
    {evaluations : Index -> F}
    {degreeBound : Nat}
    (pointInjective : Set.InjOn point support)
    (supportWithinBound : support.card ≤ degreeBound + 1)
    (highPartDegree : highPart.natDegree ≤ degreeBound) :
    (restorePolynomial support point highPart evaluations).natDegree ≤ degreeBound := by
  apply natDegree_add_le_of_degree_le
  · apply natDegree_le_iff_coeff_eq_zero.mpr
    intro degree aboveBound
    have supportLeDegree : support.card ≤ degree := by omega
    exact coeff_eq_zero_of_degree_lt
      ((Lagrange.degree_interpolate_lt
          (fun index => evaluations index - highPart.eval (point index))
          pointInjective).trans_le
        (by exact_mod_cast supportLeDegree))
  · exact highPartDegree

/--
Any degree-bounded polynomial with the transmitted high coefficients and sampled evaluations is
the polynomial returned by restoration.
-/
theorem restore_polynomial_unique
    {support : Finset Index}
    {point : Index -> F}
    {highPart candidate : F[X]}
    {evaluations : Index -> F}
    (pointInjective : Set.InjOn point support)
    (sameHigh :
      SameHighCoefficients support.card candidate highPart)
    (sameEval :
      ∀ index ∈ support,
        candidate.eval (point index) = evaluations index) :
    candidate = restorePolynomial support point highPart evaluations := by
  apply eq_of_same_high_coefficients_and_eval
    (support := support)
    (point := point)
    (k := support.card)
    rfl
    pointInjective
  · intro degree highDegree
    rw [sameHigh degree highDegree]
    exact
      (restore_polynomial_same_high_coefficients
        (support := support)
        (point := point)
        (highPart := highPart)
        (evaluations := evaluations)
        pointInjective degree highDegree).symm
  · intro index indexMembership
    rw [sameEval index indexMembership]
    exact
      (restore_polynomial_eval
        (support := support)
        (point := point)
        (highPart := highPart)
        (evaluations := evaluations)
        pointInjective indexMembership).symm

/-! ## Active production instantiation -/

/-- The production 23-position DECS opening determines one degree-397 polynomial uniquely. -/
theorem active_decs_restore_unique
    (challenge : DecsOpeningChallenge)
    {highPart candidate : Goldilocks[X]}
    {evaluations : Fin decsEvaluationCount -> Goldilocks}
    (sameHigh :
      SameHighCoefficients decsOpenedEvaluations candidate highPart)
    (sameEval :
      ∀ index ∈ challenge.val,
        candidate.eval (activeEvaluationPoint index) = evaluations index) :
    candidate =
      restorePolynomial challenge.val activeEvaluationPoint highPart evaluations := by
  apply restore_polynomial_unique
  · exact active_evaluation_point_injective.injOn
  · simpa [challenge.property] using sameHigh
  · exact sameEval

theorem active_decs_restore_degree_le
    (challenge : DecsOpeningChallenge)
    {highPart : Goldilocks[X]}
    {evaluations : Fin decsEvaluationCount -> Goldilocks}
    (highPartDegree : highPart.natDegree ≤ decsPolynomialDegree) :
    (restorePolynomial challenge.val activeEvaluationPoint highPart evaluations).natDegree ≤
      decsPolynomialDegree := by
  apply restore_polynomial_natDegree_le
  · exact active_evaluation_point_injective.injOn
  · rw [challenge.property]
    decide
  · exact highPartDegree

end

end HegemonCrypto.SmallWood.DecsRestore

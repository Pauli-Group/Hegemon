import Mathlib.LinearAlgebra.Lagrange

/-!
# Exact zero-sum linear PIOP low map

This module proves injectivity of the concrete six-by-six map used by SmallWood's linear
mask.  It derives injectivity from the exact correction factor checked by Rust; it does not
assume the rank of an unrelated matrix.
-/

namespace HegemonCrypto.SmallWood.LinearPiopExact

open Polynomial
open scoped BigOperators

set_option maxHeartbeats 0
set_option maxRecDepth 100000

noncomputable section

variable {F I : Type*} [Field F]

def packingMean (packing : Finset I) (point : I → F) (degree : Nat) : F :=
  (packing.card : F)⁻¹ * ∑ index ∈ packing, point index ^ degree

def linearMaskPolynomial
    (packing : Finset I) (point : I → F) (coins : Fin 6 → F) : F[X] :=
  ∑ degree : Fin 6,
    C (coins degree) *
      (X ^ (degree.val + 1) - C (packingMean packing point (degree.val + 1)))

def exactLinearLowMap
    (packing : Finset I) (point : I → F) (openings : Fin 6 → F)
    (coins : Fin 6 → F) : Fin 6 → F :=
  fun opening => (linearMaskPolynomial packing point coins).eval (openings opening)

def rootPolynomial (openings : Fin 6 → F) : F[X] :=
  ∏ opening : Fin 6, (X - C (openings opening))

def rootDenominator (openings : Fin 6 → F) : F :=
  ∏ opening : Fin 6, -openings opening

def normalizedRootPolynomial (openings : Fin 6 → F) : F[X] :=
  rootPolynomial openings * C (rootDenominator openings)⁻¹

def correctionFactor
    (packing : Finset I) (point : I → F) (openings : Fin 6 → F) : F :=
  ∑ index ∈ packing,
    (normalizedRootPolynomial openings).eval (point index)

theorem correctionFactor_eq_rust_formula
    (packing : Finset I) (point : I → F) (openings : Fin 6 → F) :
    correctionFactor packing point openings =
      (∑ index ∈ packing,
        ∏ opening : Fin 6, (point index - openings opening)) *
        (rootDenominator openings)⁻¹ := by
  unfold correctionFactor normalizedRootPolynomial rootPolynomial
  simp_rw [eval_mul, eval_prod, eval_sub, eval_X, eval_C]
  rw [← Finset.sum_mul]

def augmentedPoint (openings : Fin 6 → F) : Option (Fin 6) → F
  | none => 0
  | some opening => openings opening

theorem augmentedPoint_injective
    {openings : Fin 6 → F}
    (openingsInjective : Function.Injective openings)
    (openingsNonzero : ∀ opening, openings opening ≠ 0) :
    Function.Injective (augmentedPoint openings) := by
  intro left right equal
  cases left with
  | none =>
      cases right with
      | none => rfl
      | some opening =>
          exfalso
          exact openingsNonzero opening equal.symm
  | some leftOpening =>
      cases right with
      | none =>
          exfalso
          exact openingsNonzero leftOpening equal
      | some rightOpening =>
          exact congrArg some (openingsInjective equal)

theorem linearMaskPolynomial_natDegree_le
    (packing : Finset I) (point : I → F) (coins : Fin 6 → F) :
    (linearMaskPolynomial packing point coins).natDegree ≤ 6 := by
  unfold linearMaskPolynomial
  apply natDegree_sum_le_of_forall_le
  intro degree _
  calc
    (C (coins degree) *
        (X ^ (degree.val + 1) -
          C (packingMean packing point (degree.val + 1)))).natDegree ≤
        (C (coins degree)).natDegree +
          (X ^ (degree.val + 1) -
            C (packingMean packing point (degree.val + 1))).natDegree :=
      natDegree_mul_le
    _ ≤ 0 + max (degree.val + 1) 0 := by
      apply Nat.add_le_add
      · simp
      · refine (natDegree_sub_le _ _).trans (max_le_max ?_ ?_)
        · simp
        · simp
    _ ≤ 6 := by omega

theorem rootPolynomial_natDegree_le (openings : Fin 6 → F) :
    (rootPolynomial openings).natDegree ≤ 6 := by
  unfold rootPolynomial
  calc
    (∏ opening : Fin 6, (X - C (openings opening))).natDegree ≤
        ∑ _opening : Fin 6, 1 := by
      refine (natDegree_prod_le Finset.univ _).trans ?_
      apply Finset.sum_le_sum
      intro opening _
      simp
    _ = 6 := by simp

theorem normalizedRootPolynomial_natDegree_le (openings : Fin 6 → F) :
    (normalizedRootPolynomial openings).natDegree ≤ 6 := by
  unfold normalizedRootPolynomial
  calc
    (rootPolynomial openings * C (rootDenominator openings)⁻¹).natDegree ≤
        (rootPolynomial openings).natDegree +
          (C (rootDenominator openings)⁻¹ : F[X]).natDegree := natDegree_mul_le
    _ ≤ 6 + 0 := Nat.add_le_add (rootPolynomial_natDegree_le openings) (by simp)
    _ = 6 := rfl

theorem linearMaskPolynomial_eval
    (packing : Finset I) (point : I → F) (coins : Fin 6 → F) (x : F) :
    (linearMaskPolynomial packing point coins).eval x =
      ∑ degree : Fin 6,
        coins degree *
          (x ^ (degree.val + 1) - packingMean packing point (degree.val + 1)) := by
  change
    (evalRingHom x)
        (∑ degree : Fin 6,
          C (coins degree) *
            (X ^ (degree.val + 1) -
              C (packingMean packing point (degree.val + 1)))) = _
  rw [map_sum]
  simp

theorem exactLinearLowMap_apply
    (packing : Finset I) (point : I → F) (openings : Fin 6 → F)
    (coins : Fin 6 → F) (opening : Fin 6) :
    exactLinearLowMap packing point openings coins opening =
      ∑ degree : Fin 6,
        coins degree *
          (openings opening ^ (degree.val + 1) -
            packingMean packing point (degree.val + 1)) :=
  linearMaskPolynomial_eval packing point coins (openings opening)

theorem normalizedRootPolynomial_eval_opening
    (openings : Fin 6 → F) (opening : Fin 6) :
    (normalizedRootPolynomial openings).eval (openings opening) = 0 := by
  rw [normalizedRootPolynomial, eval_mul, rootPolynomial, eval_prod]
  have productZero :
      (∏ index : Fin 6, (openings opening - openings index)) = 0 := by
    apply Finset.prod_eq_zero (Finset.mem_univ opening)
    simp
  simp only [eval_sub, eval_X, eval_C]
  rw [productZero]
  simp

theorem rootDenominator_ne_zero
    {openings : Fin 6 → F}
    (openingsNonzero : ∀ opening, openings opening ≠ 0) :
    rootDenominator openings ≠ 0 := by
  unfold rootDenominator
  apply Finset.prod_ne_zero_iff.mpr
  intro opening _
  exact neg_ne_zero.mpr (openingsNonzero opening)

theorem normalizedRootPolynomial_eval_zero
    {openings : Fin 6 → F}
    (openingsNonzero : ∀ opening, openings opening ≠ 0) :
    (normalizedRootPolynomial openings).eval 0 = 1 := by
  have denominatorNonzero := rootDenominator_ne_zero openingsNonzero
  rw [normalizedRootPolynomial, eval_mul, rootPolynomial, eval_prod]
  simp only [eval_sub, eval_X, eval_C, zero_sub]
  change rootDenominator openings * (rootDenominator openings)⁻¹ = 1
  exact mul_inv_cancel₀ denominatorNonzero

def scaledNormalizedRoot
    (openings : Fin 6 → F) (polynomial : F[X]) : F[X] :=
  C (polynomial.eval 0) * normalizedRootPolynomial openings

theorem scaledNormalizedRoot_natDegree_le
    (openings : Fin 6 → F) (polynomial : F[X]) :
    (scaledNormalizedRoot openings polynomial).natDegree ≤ 6 := by
  unfold scaledNormalizedRoot
  calc
    (C (polynomial.eval 0) * normalizedRootPolynomial openings).natDegree ≤
        (C (polynomial.eval 0)).natDegree +
          (normalizedRootPolynomial openings).natDegree := natDegree_mul_le
    _ ≤ 0 + 6 := Nat.add_le_add (by simp)
      (normalizedRootPolynomial_natDegree_le openings)
    _ = 6 := rfl

theorem linearMaskPolynomial_eq_scaledNormalizedRoot
    {packing : Finset I} {point : I → F} {openings : Fin 6 → F}
    (openingsInjective : Function.Injective openings)
    (openingsNonzero : ∀ opening, openings opening ≠ 0)
    (coins : Fin 6 → F)
    (mapZero : exactLinearLowMap packing point openings coins = 0) :
    linearMaskPolynomial packing point coins =
      scaledNormalizedRoot openings (linearMaskPolynomial packing point coins) := by
  apply Polynomial.eq_of_degrees_lt_of_eval_index_eq
    (Finset.univ : Finset (Option (Fin 6)))
    (augmentedPoint_injective openingsInjective openingsNonzero).injOn
  · have bound := linearMaskPolynomial_natDegree_le packing point coins
    have strict : (linearMaskPolynomial packing point coins).natDegree < 7 := by omega
    exact degree_le_natDegree.trans_lt (WithBot.coe_lt_coe.mpr strict)
  · have bound := scaledNormalizedRoot_natDegree_le openings
      (linearMaskPolynomial packing point coins)
    have strict :
        (scaledNormalizedRoot openings
          (linearMaskPolynomial packing point coins)).natDegree < 7 := by omega
    exact degree_le_natDegree.trans_lt (WithBot.coe_lt_coe.mpr strict)
  · intro index _
    cases index with
    | none =>
        simp [augmentedPoint, scaledNormalizedRoot,
          normalizedRootPolynomial_eval_zero openingsNonzero]
    | some opening =>
        have openingZero := congrFun mapZero opening
        simp [exactLinearLowMap] at openingZero
        dsimp [augmentedPoint]
        rw [openingZero]
        simp [scaledNormalizedRoot,
          normalizedRootPolynomial_eval_opening]

theorem card_mul_packingMean
    {packing : Finset I} {point : I → F}
    (packingCardNonzero : (packing.card : F) ≠ 0)
    (degree : Nat) :
    (packing.card : F) * packingMean packing point degree =
      ∑ index ∈ packing, point index ^ degree := by
  unfold packingMean
  rw [← mul_assoc, mul_inv_cancel₀ packingCardNonzero, one_mul]

theorem linearMaskPolynomial_packing_sum_zero
    {packing : Finset I} {point : I → F}
    (packingCardNonzero : (packing.card : F) ≠ 0)
    (coins : Fin 6 → F) :
    (∑ index ∈ packing,
      (linearMaskPolynomial packing point coins).eval (point index)) = 0 := by
  simp_rw [linearMaskPolynomial_eval]
  calc
    (∑ index ∈ packing,
        ∑ degree : Fin 6,
          coins degree *
            (point index ^ (degree.val + 1) -
              packingMean packing point (degree.val + 1))) =
        ∑ degree : Fin 6,
          ∑ index ∈ packing,
            coins degree *
              (point index ^ (degree.val + 1) -
                packingMean packing point (degree.val + 1)) := by
      rw [Finset.sum_comm]
    _ = ∑ degree : Fin 6,
          coins degree *
            ((∑ index ∈ packing, point index ^ (degree.val + 1)) -
              (packing.card : F) *
                packingMean packing point (degree.val + 1)) := by
      apply Finset.sum_congr rfl
      intro degree _
      simp_rw [mul_sub]
      rw [Finset.sum_sub_distrib, ← Finset.mul_sum]
      congr 1
      simp
      ring
    _ = 0 := by
      apply Finset.sum_eq_zero
      intro degree _
      rw [card_mul_packingMean packingCardNonzero]
      ring

theorem linearMaskPolynomial_eval_zero_eq_zero
    {packing : Finset I} {point : I → F} {openings : Fin 6 → F}
    (packingCardNonzero : (packing.card : F) ≠ 0)
    (openingsInjective : Function.Injective openings)
    (openingsNonzero : ∀ opening, openings opening ≠ 0)
    (correctionNonzero : correctionFactor packing point openings ≠ 0)
    (coins : Fin 6 → F)
    (mapZero : exactLinearLowMap packing point openings coins = 0) :
    (linearMaskPolynomial packing point coins).eval 0 = 0 := by
  have polynomialEqual :=
    linearMaskPolynomial_eq_scaledNormalizedRoot
      openingsInjective openingsNonzero coins mapZero
  have packingSumZero :=
    linearMaskPolynomial_packing_sum_zero
      (point := point) packingCardNonzero coins
  rw [polynomialEqual] at packingSumZero
  have productZero :
      (linearMaskPolynomial packing point coins).eval 0 *
        correctionFactor packing point openings = 0 := by
    simpa [scaledNormalizedRoot, correctionFactor, eval_mul, Finset.mul_sum]
      using packingSumZero
  exact (mul_eq_zero.mp productZero).resolve_right correctionNonzero

theorem linearMaskPolynomial_eq_zero
    {packing : Finset I} {point : I → F} {openings : Fin 6 → F}
    (packingCardNonzero : (packing.card : F) ≠ 0)
    (openingsInjective : Function.Injective openings)
    (openingsNonzero : ∀ opening, openings opening ≠ 0)
    (correctionNonzero : correctionFactor packing point openings ≠ 0)
    (coins : Fin 6 → F)
    (mapZero : exactLinearLowMap packing point openings coins = 0) :
    linearMaskPolynomial packing point coins = 0 := by
  rw [linearMaskPolynomial_eq_scaledNormalizedRoot
    openingsInjective openingsNonzero coins mapZero]
  have evaluationZero := linearMaskPolynomial_eval_zero_eq_zero packingCardNonzero
    openingsInjective openingsNonzero correctionNonzero coins mapZero
  simp [scaledNormalizedRoot, evaluationZero]

theorem linearMaskPolynomial_coeff
    (packing : Finset I) (point : I → F) (coins : Fin 6 → F)
    (degree : Fin 6) :
    (linearMaskPolynomial packing point coins).coeff (degree.val + 1) =
      coins degree := by
  simp [linearMaskPolynomial, coeff_C_mul, coeff_sub, coeff_X_pow]
  rw [Finset.sum_eq_single degree]
  · simp
  · intro other _ otherNe
    have valuesNe : degree.val ≠ other.val := by
      intro valuesEqual
      exact otherNe (Fin.ext valuesEqual.symm)
    simp [valuesNe]
  · simp

theorem exactLinearLowMap_injective
    {packing : Finset I} {point : I → F} {openings : Fin 6 → F}
    (packingCardNonzero : (packing.card : F) ≠ 0)
    (openingsInjective : Function.Injective openings)
    (openingsNonzero : ∀ opening, openings opening ≠ 0)
    (correctionNonzero : correctionFactor packing point openings ≠ 0) :
    Function.Injective (exactLinearLowMap packing point openings) := by
  intro left right sameView
  funext degree
  let difference : Fin 6 → F := fun index => left index - right index
  have differenceMapZero : exactLinearLowMap packing point openings difference = 0 := by
    funext opening
    have sameOpening := congrFun sameView opening
    simp only [exactLinearLowMap, linearMaskPolynomial_eval] at sameOpening ⊢
    change
      (∑ index : Fin 6,
        (left index - right index) *
          (openings opening ^ (index.val + 1) -
            packingMean packing point (index.val + 1))) = 0
    calc
      (∑ index : Fin 6,
          (left index - right index) *
            (openings opening ^ (index.val + 1) -
              packingMean packing point (index.val + 1))) =
          (∑ index : Fin 6,
            left index *
              (openings opening ^ (index.val + 1) -
                packingMean packing point (index.val + 1))) -
            ∑ index : Fin 6,
              right index *
                (openings opening ^ (index.val + 1) -
                  packingMean packing point (index.val + 1)) := by
        simp_rw [sub_mul]
        rw [Finset.sum_sub_distrib]
      _ = 0 := sub_eq_zero.mpr sameOpening
  have polynomialZero := linearMaskPolynomial_eq_zero packingCardNonzero
    openingsInjective openingsNonzero correctionNonzero difference differenceMapZero
  have coefficientZero := congrArg
    (fun polynomial : F[X] => polynomial.coeff (degree.val + 1)) polynomialZero
  rw [linearMaskPolynomial_coeff packing point difference degree] at coefficientZero
  simp only [coeff_zero] at coefficientZero
  exact sub_eq_zero.mp (by simpa [difference] using coefficientZero)

end

end HegemonCrypto.SmallWood.LinearPiopExact

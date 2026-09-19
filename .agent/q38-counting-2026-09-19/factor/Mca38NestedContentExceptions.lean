import Mathlib.Algebra.Polynomial.Bivariate
import Mathlib.Algebra.Polynomial.Roots

/-! Count the actual parameter exceptions of a Y-independent nested factor.
The obstruction is a nonzero coefficient of that factor, not an assumed
exceptional-label set. Supports and responses may depend on the label. -/
namespace HegemonCrypto.SmallWood.Mca38NestedContentExceptions
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false

section Swapping
variable {R : Type*} [CommRing R]

theorem swap_coefficient (F : Polynomial (Polynomial R)) (i j : Nat) :
    ((Polynomial.Bivariate.swap F).coeff j).coeff i = (F.coeff i).coeff j := by
  induction F using Polynomial.induction_on' with
  | add p q hp hq => simp only [map_add, Polynomial.coeff_add, hp, hq]
  | monomial n p =>
    rw [Polynomial.Bivariate.swap_monomial]
    by_cases h : n = i
    · subst n
      simp only [Polynomial.coeff_mul_C, Polynomial.coeff_map,
        Polynomial.coeff_C_mul, Polynomial.coeff_X_pow,
        Polynomial.coeff_monomial]
      simp
    · simp only [Polynomial.coeff_mul_C, Polynomial.coeff_map,
        Polynomial.coeff_C_mul, Polynomial.coeff_X_pow,
        Polynomial.coeff_monomial, if_neg h, if_neg (Ne.symm h),
        mul_zero, Polynomial.coeff_zero]

theorem coefficient_degree_le_swap (F : Polynomial (Polynomial R)) (i : Nat) :
    (F.coeff i).natDegree ≤ (Polynomial.Bivariate.swap F).natDegree := by
  apply Polynomial.natDegree_le_iff_coeff_eq_zero.mpr
  intro j above
  rw [← swap_coefficient F i j,
    Polynomial.coeff_eq_zero_of_natDegree_lt above, Polynomial.coeff_zero]

end Swapping

variable {K : Type*} [Field K]
abbrev Tri (K : Type*) [Field K] := Polynomial (Polynomial (Polynomial K))

def zView (F : Tri K) : Tri K :=
  Polynomial.Bivariate.swap (F.map (Polynomial.Bivariate.swap (R := K)).toRingHom)

theorem actual_coefficient_Z_height (F : Tri K) (j i : Nat) :
    ((F.coeff j).coeff i).natDegree ≤ (zView F).natDegree := by
  have first := coefficient_degree_le_swap (F.coeff j) i
  have second := coefficient_degree_le_swap
    (F.map (Polynomial.Bivariate.swap (R := K)).toRingHom) j
  exact first.trans (by simpa [Polynomial.coeff_map, zView] using second)

def responseSpecialization (F : Tri K) (z : K) (P : Polynomial K) : Polynomial K :=
  (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P

theorem independent_factor_coefficient_vanishes
    (F : Tri K) (independent : F.natDegree = 0) (z : K) (P : Polynomial K)
    (root : responseSpecialization F z P = 0) (i : Nat) :
    ((F.coeff 0).coeff i).eval z = 0 := by
  have constant := Polynomial.eq_C_of_natDegree_eq_zero independent
  have mappedZero : (F.coeff 0).map (Polynomial.evalRingHom z) = 0 := by
    unfold responseSpecialization at root
    rw [constant, Polynomial.map_C, Polynomial.eval_C] at root
    exact root
  have coefficient := congrArg (fun p => p.coeff i) mappedZero
  simpa only [Polynomial.coeff_map, Polynomial.coeff_zero,
    Polynomial.coe_evalRingHom] using coefficient

/-- Every label admitting any response for a nonzero Y-independent factor
is a root of one actual nonzero Z coefficient. -/
theorem yIndependent_label_count (F : Tri K) (nonzero : F ≠ 0)
    (independent : F.natDegree = 0) (labels : Finset K)
    (responses : ∀ z ∈ labels, ∃ P : Polynomial K, responseSpecialization F z P = 0) :
    labels.card ≤ (zView F).natDegree := by
  have coeffNonzero : F.coeff 0 ≠ 0 := by
    intro zero
    apply nonzero
    rw [Polynomial.eq_C_of_natDegree_eq_zero independent, zero, map_zero]
  have existsCoefficient : ∃ i, (F.coeff 0).coeff i ≠ 0 := by
    by_contra! allZero
    exact coeffNonzero (Polynomial.ext (by simpa only [Polynomial.coeff_zero] using allZero))
  obtain ⟨i, actualNonzero⟩ := existsCoefficient
  have count : labels.card ≤ ((F.coeff 0).coeff i).natDegree := by
    apply Polynomial.card_le_degree_of_subset_roots
    intro z member
    obtain ⟨P, root⟩ := responses z member
    exact (Polynomial.mem_roots actualNonzero).mpr
      (independent_factor_coefficient_vanishes F independent z P root i)
  exact count.trans (actual_coefficient_Z_height F 0 i)

end
end HegemonCrypto.SmallWood.Mca38NestedContentExceptions

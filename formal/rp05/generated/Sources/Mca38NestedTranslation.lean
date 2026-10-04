import Mca38NestedFactorCoverage
import Mca38NestedContentExceptions
import Mca38LocalizedNewtonStart

/-! Translation of the actual X-variable to the regular origin.  This uses
the polynomial-algebra automorphism `p(X) ↦ p(X + x₀)` on every outer-Y
coefficient, so nonzeroness and Y-degree are transported by an actual
equivalence rather than by a degree premise.
-/
namespace HegemonCrypto.SmallWood.Mca38NestedTranslation
open HegemonCrypto.SmallWood.Mca38NestedContentExceptions
open HegemonCrypto.SmallWood.Mca38Published
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]
variable {n : Nat}
abbrev Tri := Polynomial (Polynomial (Polynomial K))

def translatePolynomial {R : Type*} [CommRing R] (t : R) :
    Polynomial R →+* Polynomial R :=
  (Polynomial.algEquivAevalXAddC t).toRingHom

theorem translatePolynomial_apply {R : Type*} [CommRing R]
    (t : R) (Q : Polynomial R) :
    translatePolynomial t Q = Q.comp (Polynomial.X + Polynomial.C t) := by
  change (Polynomial.algEquivAevalXAddC t) Q = _
  rw [Polynomial.algEquivAevalXAddC_apply]
  rfl

def translateX (x₀ : K) (F : Tri (K := K)) : Tri (K := K) :=
  F.map (translatePolynomial (Polynomial.C x₀))

theorem translateX_injective (x₀ : K) :
    Function.Injective (translateX (K := K) x₀) := by
  intro F G h
  exact Polynomial.map_injective _
    (Polynomial.algEquivAevalXAddC (Polynomial.C x₀)).injective h

theorem translateX_ne_zero (x₀ : K) {F : Tri (K := K)} (hF : F ≠ 0) :
    translateX x₀ F ≠ 0 := by
  intro zero
  apply hF
  apply translateX_injective x₀
  simpa [translateX] using zero

theorem translateX_Y_degree (x₀ : K) (F : Tri (K := K)) :
    (translateX x₀ F).natDegree = F.natDegree := by
  exact Polynomial.natDegree_map_eq_of_injective
    (f := translatePolynomial (Polynomial.C x₀))
    (Polynomial.algEquivAevalXAddC (Polynomial.C x₀)).injective F

theorem translate_coefficient_map (x₀ z : K) (Q : Polynomial (Polynomial K)) :
    (translatePolynomial (Polynomial.C x₀) Q).map (Polynomial.evalRingHom z) =
      translatePolynomial x₀ (Q.map (Polynomial.evalRingHom z)) := by
  rw [translatePolynomial_apply, translatePolynomial_apply, Polynomial.map_comp]
  simp

theorem translate_coefficients_specialize (x₀ z : K) (F : Tri (K := K)) :
    (translateX x₀ F).map (Polynomial.mapRingHom (Polynomial.evalRingHom z)) =
      (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).map
        (translatePolynomial x₀) := by
  apply Polynomial.ext
  intro j
  simpa only [translateX, Polynomial.coeff_map, Polynomial.coe_mapRingHom]
    using translate_coefficient_map x₀ z (F.coeff j)

theorem translateX_specialization
    (x₀ z : K) (P : Polynomial K) (F : Tri (K := K)) :
    responseSpecialization (translateX x₀ F) z
        (P.comp (Polynomial.X + Polynomial.C x₀)) =
      (responseSpecialization F z P).comp (Polynomial.X + Polynomial.C x₀) := by
  unfold responseSpecialization
  rw [translate_coefficients_specialize]
  have naturality := Polynomial.eval_map_apply
    (p := F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z)))
    (f := translatePolynomial x₀) P
  simpa only [translatePolynomial_apply] using naturality

theorem translateX_origin
    (x₀ : K) (F : Tri (K := K)) :
    coefficientOrigin (translateX x₀ F) =
      F.map (Polynomial.evalRingHom (Polynomial.C x₀)) := by
  apply Polynomial.ext
  intro j
  simp only [coefficientOrigin, translateX, Polynomial.coeff_map,
    Polynomial.coe_evalRingHom, translatePolynomial_apply, Polynomial.eval_comp]
  simp

theorem translate_coefficient_height (x₀ : K) (Q : Polynomial (Polynomial K))
    (Z : Nat) (height : ∀ i, (Q.coeff i).natDegree ≤ Z) (j : Nat) :
    ((translatePolynomial (Polynomial.C x₀) Q).coeff j).natDegree ≤ Z := by
  rw [translatePolynomial_apply, Polynomial.comp_eq_sum_left, Polynomial.sum,
    Polynomial.finsetSum_coeff]
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro i _
  rw [Polynomial.coeff_C_mul]
  have power : (Polynomial.X + Polynomial.C (Polynomial.C x₀)) ^ i =
      ((Polynomial.X + Polynomial.C x₀) ^ i).map Polynomial.C := by
    simp only [Polynomial.map_pow, Polynomial.map_add, Polynomial.map_X, Polynomial.map_C]
  have scalar : (((Polynomial.X + Polynomial.C (Polynomial.C x₀)) ^ i).coeff j).natDegree ≤ 0 := by
    rw [power, Polynomial.coeff_map]
    simp
  exact Polynomial.natDegree_mul_le.trans
    ((Nat.add_le_add (height i) scalar).trans (by omega))

theorem translateX_Z_coefficient_height (x₀ : K) (F : Tri (K := K)) (j i : Nat) :
    (((translateX x₀ F).coeff j).coeff i).natDegree ≤ (zView F).natDegree := by
  rw [translateX, Polynomial.coeff_map]
  exact translate_coefficient_height x₀ (F.coeff j) (zView F).natDegree
    (fun k => actual_coefficient_Z_height F j k) i

theorem translated_response_degree
    (x₀ : K) (P : Polynomial K) (hP : P.natDegree ≤ 405) :
    (P.comp (Polynomial.X + Polynomial.C x₀)).natDegree ≤ 405 := by
  have hcomp := Polynomial.natDegree_comp_le (p := P)
    (q := Polynomial.X + Polynomial.C x₀)
  have degreeOne : (Polynomial.X + Polynomial.C x₀).natDegree ≤ 1 := by
    calc
      _ ≤ max (Polynomial.X : Polynomial K).natDegree (Polynomial.C x₀).natDegree :=
        Polynomial.natDegree_add_le _ _
      _ ≤ 1 := by simp
  exact hcomp.trans ((Nat.mul_le_mul hP degreeOne).trans (by omega))

theorem translated_support_eval
    (x₀ : K) (point : Fin n → K) (a : Fin n) (P : Polynomial K) :
    (P.comp (Polynomial.X + Polynomial.C x₀)).eval (point a - x₀) =
      P.eval (point a) := by
  rw [Polynomial.eval_comp]
  simp [sub_add_cancel]

end
end HegemonCrypto.SmallWood.Mca38NestedTranslation

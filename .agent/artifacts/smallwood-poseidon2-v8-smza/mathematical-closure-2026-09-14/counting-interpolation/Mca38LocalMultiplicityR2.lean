import Mathlib.Algebra.Polynomial.Div
import Mathlib.Algebra.Polynomial.Taylor
import Mathlib.Algebra.Polynomial.AlgebraMap
import Mathlib.Algebra.Polynomial.BigOperators
import Mathlib.Tactic.NormNum

/-! Actual bivariate Taylor coefficients imply multiplicity after polynomial
substitution. No label-count or factor-classification premise is introduced. -/

namespace HegemonCrypto.SmallWood.Mca38Published
open scoped BigOperators
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

/-- If all terms of total order below m vanish, substituting a polynomial
with zero constant coefficient leaves a multiple of X^m. -/
theorem X_pow_dvd_eval_of_low_coeff_zero (Q : Polynomial (Polynomial K))
    (W : Polynomial K) (m : ℕ) (hW : Polynomial.X ∣ W)
    (hlow : ∀ r s : ℕ, r + s < m → (Q.coeff s).coeff r = 0) :
    Polynomial.X ^ m ∣ Q.eval W := by
  rw [Q.eval_eq_sum_range' (n := Q.natDegree + 1) (by omega) W]
  apply Finset.dvd_sum
  intro s _
  have hwp : Polynomial.X ^ s ∣ W ^ s := by
    obtain ⟨v, hv⟩ := hW
    refine ⟨v ^ s, ?_⟩
    rw [hv, mul_pow]
  by_cases hs : s < m
  · have hc : Polynomial.X ^ (m - s) ∣ Q.coeff s := by
      apply Polynomial.X_pow_dvd_iff.mpr
      intro r hr
      exact hlow r s (by omega)
    have hp := mul_dvd_mul hc hwp
    rw [← pow_add, Nat.sub_add_cancel (by omega : s ≤ m)] at hp
    exact hp
  · have hle : m ≤ s := Nat.le_of_not_gt hs
    exact dvd_mul_of_dvd_right ((pow_dvd_pow Polynomial.X hle).trans hwp) _

/-- Actual coordinate shift Q(X+x,Y+y), represented as a polynomial in Y
whose coefficients are polynomials in X. -/
def bivariateTaylor (Q : Polynomial (Polynomial K)) (x y : K) :
    Polynomial (Polynomial K) :=
  Polynomial.taylor (Polynomial.C y)
    (Q.map (Polynomial.taylorAlgHom x).toRingHom)

theorem bivariateTaylor_eval (Q : Polynomial (Polynomial K)) (P : Polynomial K)
    (x y : K) :
    (bivariateTaylor Q x y).eval (Polynomial.taylor x P - Polynomial.C y) =
      Polynomial.taylor x (Q.eval P) := by
  rw [bivariateTaylor, Polynomial.taylor_eval_sub]
  have h := Polynomial.eval_map_apply (p := Q)
    (f := (Polynomial.taylorAlgHom x).toRingHom) P
  simpa [Polynomial.taylorAlgHom] using h

/-- A degree-m zero of the two-variable Taylor expansion remains a
multiplicity-m zero after substituting any P with P(x)=y. -/
theorem local_multiplicity_of_bivariate_coefficients
    (Q : Polynomial (Polynomial K)) (P : Polynomial K) (x y : K) (m : ℕ)
    (hP : P.eval x = y)
    (hlow : ∀ r s : ℕ, r + s < m →
      ((bivariateTaylor Q x y).coeff s).coeff r = 0) :
    (Polynomial.X - Polynomial.C x) ^ m ∣ Q.eval P := by
  have hW : Polynomial.X ∣ Polynomial.taylor x P - Polynomial.C y := by
    rw [Polynomial.X_dvd_iff]
    simp only [Polynomial.coeff_sub, Polynomial.taylor_coeff_zero,
      Polynomial.coeff_C_zero, hP, sub_self]
  have hm := X_pow_dvd_eval_of_low_coeff_zero (bivariateTaylor Q x y)
    (Polynomial.taylor x P - Polynomial.C y) m hW hlow
  rw [bivariateTaylor_eval] at hm
  rw [Polynomial.X_sub_C_pow_dvd_iff]
  simpa only [Polynomial.taylor_apply] using hm

end
end HegemonCrypto.SmallWood.Mca38Published



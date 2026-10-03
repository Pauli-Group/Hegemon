import Mca38HasseCoefficientR2
import Mca38LocalMultiplicityR2
import Mca38SpecializationDegreeR2

/-! Actual solved matrix -> bivariate Taylor zeroes -> local divisibility
for every matching response. Imports will be pinned to checked revisions. -/
namespace HegemonCrypto.SmallWood.Mca38Published
open scoped BigOperators
noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]

def nestedInterpolant (c : MonomialIndex → K) (z : K) :
    Polynomial (Polynomial K) :=
  ∑ v, Polynomial.C
      (Polynomial.C (c v * z ^ v.2.2.val) * Polynomial.X ^ v.2.1.val) *
    Polynomial.X ^ v.1.val

theorem bivariateTaylor_monomial_coeff (a x y : K) (i j r s : ℕ) :
    ((bivariateTaylor
        (Polynomial.C (Polynomial.C a * Polynomial.X ^ i) * Polynomial.X ^ j)
        x y).coeff s).coeff r =
      a * (Nat.choose i r : K) * (Nat.choose j s : K) *
        x ^ (i - r) * y ^ (j - s) := by
  have hp : bivariateTaylor
      (Polynomial.C (Polynomial.C a * Polynomial.X ^ i) * Polynomial.X ^ j) x y =
      Polynomial.C (Polynomial.C a * (Polynomial.X + Polynomial.C x) ^ i) *
        (Polynomial.X + Polynomial.C (Polynomial.C y)) ^ j := by
    simp only [bivariateTaylor, Polynomial.map_mul, Polynomial.map_C,
      Polynomial.map_pow, Polynomial.map_X, AlgHom.toRingHom_eq_coe,
      Polynomial.taylorAlgHom, Polynomial.taylor_mul, Polynomial.taylor_C,
      Polynomial.taylor_pow, Polynomial.taylor_X]
    change Polynomial.C (Polynomial.taylor x (Polynomial.C a * Polynomial.X ^ i)) *
        (Polynomial.X + Polynomial.C (Polynomial.C y)) ^ j = _
    rw [Polynomial.taylor_mul, Polynomial.taylor_C,
      Polynomial.taylor_pow, Polynomial.taylor_X]
  rw [hp, Polynomial.coeff_C_mul, Polynomial.coeff_X_add_C_pow]
  simp only [← Polynomial.C_pow, ← Polynomial.C_eq_natCast, ← Polynomial.C_mul]
  rw [Polynomial.coeff_mul_C, Polynomial.coeff_C_mul,
    Polynomial.coeff_X_add_C_pow]
  ring

theorem nestedInterpolant_eval (c : MonomialIndex → K) (z : K) (P : Polynomial K) :
    (nestedInterpolant c z).eval P = specializedInterpolant c z P := by
  simp only [nestedInterpolant, specializedInterpolant, Polynomial.eval_finsetSum]
  apply Finset.sum_congr rfl
  intro v _
  simp only [Polynomial.eval_mul, Polynomial.eval_C, Polynomial.eval_pow,
    Polynomial.eval_X, specializedTerm]
  ring

theorem nestedTaylor_coeff_eq_hasse_eval
    (c : MonomialIndex → K) (point U V : Fin n → K) (z : K)
    (a : Fin n) (s : Fin multiplicity) (r : Fin (multiplicity - s.val)) :
    ((bivariateTaylor (nestedInterpolant c z) (point a) (U a + z * V a)).coeff s.val).coeff r.val =
      (hasseGeneratingPolynomial c point U V a s r).eval z := by
  unfold nestedInterpolant
  simp only [bivariateTaylor, Polynomial.map_sum, map_sum,
    Polynomial.finsetSum_coeff]
  change (∑ v, ((bivariateTaylor
      (Polynomial.C (Polynomial.C (c v * z ^ v.2.2.val) *
        Polynomial.X ^ v.2.1.val) * Polynomial.X ^ v.1.val)
      (point a) (U a + z * V a)).coeff s.val).coeff r.val) = _
  simp only [bivariateTaylor_monomial_coeff, hasseGeneratingPolynomial,
    Polynomial.eval_finsetSum, Polynomial.eval_mul, Polynomial.eval_C,
    hasseMonomialPolynomial, Polynomial.eval_pow, Polynomial.eval_add,
    Polynomial.eval_X]
  apply Finset.sum_congr rfl
  intro v _
  ring

theorem actual_local_multiplicity
    (c : MonomialIndex → K) (point U V : Fin n → K)
    (hsolve : ∀ e : EquationIndex, (∑ v, c v * hasseCoefficient point U V e v) = 0)
    (z : K) (P : Polynomial K) (a : Fin n)
    (hmatch : P.eval (point a) = U a + z * V a) :
    (Polynomial.X - Polynomial.C (point a)) ^ multiplicity ∣
      specializedInterpolant c z P := by
  rw [← nestedInterpolant_eval]
  apply local_multiplicity_of_bivariate_coefficients
    (nestedInterpolant c z) P (point a) (U a + z * V a) multiplicity hmatch
  intro r s hrs
  have hs : s < multiplicity := by omega
  have hr : r < multiplicity - s := by omega
  rw [nestedTaylor_coeff_eq_hasse_eval c point U V z a ⟨s, hs⟩ ⟨r, hr⟩,
    hasseGeneratingPolynomial_eq_zero c point U V hsolve]
  exact Polynomial.eval_zero

end
end HegemonCrypto.SmallWood.Mca38Published

import Mca38GsInterpolationR3
import Mathlib.Algebra.Polynomial.Eval.Degree
import Mathlib.Algebra.Polynomial.BigOperators
import Mathlib.Tactic.Ring

/-! Identify the actual interpolation matrix with coefficients of genuine
Hasse-derivative generating polynomials, and prove those polynomials zero. -/
namespace HegemonCrypto.SmallWood.Mca38Published
open scoped BigOperators
noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]

theorem coeff_linear_power (u v : K) (j t : ℕ) :
    ((Polynomial.C u + Polynomial.X * Polynomial.C v) ^ j).coeff t =
      (Nat.choose j t : K) * u ^ (j - t) * v ^ t := by
  have hp : (Polynomial.C u + Polynomial.X * Polynomial.C v) ^ j =
      ((Polynomial.X + Polynomial.C u) ^ j).comp
        (Polynomial.C v * Polynomial.X) := by
    simp only [Polynomial.pow_comp, Polynomial.add_comp,
      Polynomial.X_comp, Polynomial.C_comp]
    congr 1
    ring
  rw [hp, Polynomial.comp_C_mul_X_coeff, Polynomial.coeff_X_add_C_pow]
  ring

def hasseMonomialPolynomial (x u v : K) (i j h r s : ℕ) : Polynomial K :=
  Polynomial.C ((Nat.choose i r : K) * (Nat.choose j s : K) * x ^ (i - r)) *
    (Polynomial.C u + Polynomial.X * Polynomial.C v) ^ (j - s) *
    Polynomial.X ^ h

theorem hasseMonomialPolynomial_coeff (x u v : K) (i j h r s t : ℕ) :
    (hasseMonomialPolynomial x u v i j h r s).coeff t =
      if h ≤ t ∧ t - h ≤ j - s then
        (Nat.choose i r : K) * (Nat.choose j s : K) *
          (Nat.choose (j - s) (t - h) : K) *
          x ^ (i - r) * u ^ (j - s - (t - h)) * v ^ (t - h)
      else 0 := by
  rw [hasseMonomialPolynomial, Polynomial.coeff_mul_X_pow']
  by_cases hh : h ≤ t
  · rw [if_pos hh, Polynomial.coeff_C_mul, coeff_linear_power]
    by_cases ht : t - h ≤ j - s
    · rw [if_pos ⟨hh, ht⟩]
      ring
    · rw [if_neg (by omega),
        Nat.choose_eq_zero_of_lt (Nat.lt_of_not_ge ht)]
      simp
  · rw [if_neg hh, if_neg (by omega)]

def hasseGeneratingPolynomial (c : MonomialIndex → K) (point U V : Fin n → K)
    (a : Fin n) (s : Fin multiplicity) (r : Fin (multiplicity - s.val)) :
    Polynomial K :=
  ∑ v : MonomialIndex, Polynomial.C (c v) *
    hasseMonomialPolynomial (point a) (U a) (V a)
      v.2.1.val v.1.val v.2.2.val r.val s.val

theorem hasseGeneratingPolynomial_coeff_below
    (c : MonomialIndex → K) (point U V : Fin n → K)
    (a : Fin n) (s : Fin multiplicity) (r : Fin (multiplicity - s.val))
    (t : Fin (zBound - s.val)) :
    (hasseGeneratingPolynomial c point U V a s r).coeff t.val =
      ∑ v, c v * hasseCoefficient point U V (a, ⟨s, r, t⟩) v := by
  simp only [hasseGeneratingPolynomial, Polynomial.finsetSum_coeff,
    Polynomial.coeff_C_mul, hasseMonomialPolynomial_coeff, hasseCoefficient]

theorem hasseGeneratingPolynomial_coeff_above
    (c : MonomialIndex → K) (point U V : Fin n → K)
    (a : Fin n) (s : Fin multiplicity) (r : Fin (multiplicity - s.val))
    (t : ℕ) (ht : zBound - s.val ≤ t) :
    (hasseGeneratingPolynomial c point U V a s r).coeff t = 0 := by
  rw [hasseGeneratingPolynomial, Polynomial.finsetSum_coeff]
  apply Finset.sum_eq_zero
  intro v _
  rw [Polynomial.coeff_C_mul, hasseMonomialPolynomial_coeff]
  by_cases hs : s.val ≤ v.1.val
  · have hv := monomial_z_specialization_degree v
    have hnot : ¬ (v.2.2.val ≤ t ∧ t - v.2.2.val ≤ v.1.val - s.val) := by
      omega
    rw [if_neg hnot, mul_zero]
  · have hchoose : Nat.choose v.1.val s.val = 0 :=
      Nat.choose_eq_zero_of_lt (Nat.lt_of_not_ge hs)
    split_ifs <;> simp only [hchoose, Nat.cast_zero, mul_zero, zero_mul]

/-- Every actual Hasse generating polynomial is identically zero, not merely
zero at a sampled label. Above-bound coefficients vanish by monomial shape;
below-bound coefficients are precisely the solved interpolation equations. -/
theorem hasseGeneratingPolynomial_eq_zero
    (c : MonomialIndex → K) (point U V : Fin n → K)
    (hsolve : ∀ e : EquationIndex,
      (∑ v, c v * hasseCoefficient point U V e v) = 0)
    (a : Fin n) (s : Fin multiplicity) (r : Fin (multiplicity - s.val)) :
    hasseGeneratingPolynomial c point U V a s r = 0 := by
  ext t
  rw [Polynomial.coeff_zero]
  by_cases ht : t < zBound - s.val
  · rw [hasseGeneratingPolynomial_coeff_below c point U V a s r ⟨t, ht⟩]
    exact hsolve _
  · exact hasseGeneratingPolynomial_coeff_above c point U V a s r t
      (Nat.le_of_not_gt ht)

end
end HegemonCrypto.SmallWood.Mca38Published



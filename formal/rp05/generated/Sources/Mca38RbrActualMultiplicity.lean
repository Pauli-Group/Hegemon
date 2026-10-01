import Mca38RoundByRoundInterpolation
import Mca38ActualMultiplicityR2
import Mathlib.Algebra.Polynomial.RingDivision
import Mathlib.RingTheory.Coprime.Lemmas

/-! Source-only round-by-round transport at the 65,536 analysis cutoff.

This is the old Hasse -> local multiplicity -> support composition chain with
the new coefficient/equation indices.  No support, label, or vanishing premise
is introduced; the only existence input is the actual finite matrix supplied
by `Mca38RoundByRoundInterpolation`.
-/
namespace HegemonCrypto.SmallWood.Mca38RoundByRound
open scoped BigOperators
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

open HegemonCrypto.SmallWood.Mca38RoundByRoundParameters
open HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation

variable {K : Type*} [Field K]

def specializedTerm (c : CoefficientIndex → K) (z : K) (P : Polynomial K)
    (v : CoefficientIndex) : Polynomial K :=
  Polynomial.C (c v * z ^ v.2.2.val) *
    (Polynomial.X ^ v.2.1.val * P ^ v.1.val)

def specializedInterpolant (c : CoefficientIndex → K) (z : K) (P : Polynomial K) :
    Polynomial K := ∑ v, specializedTerm c z P v

theorem specializedTerm_natDegree (c : CoefficientIndex → K) (z : K)
    (P : Polynomial K) (hP : P.natDegree ≤ degree) (v : CoefficientIndex) :
    (specializedTerm c z P v).natDegree < xBound := by
  have ht : (specializedTerm c z P v).natDegree ≤
      v.2.1.val + v.1.val * degree := by
    calc
      _ ≤ (Polynomial.X ^ v.2.1.val * P ^ v.1.val).natDegree :=
        Polynomial.natDegree_C_mul_le _ _
      _ ≤ (Polynomial.X ^ v.2.1.val : Polynomial K).natDegree +
          (P ^ v.1.val).natDegree := Polynomial.natDegree_mul_le
      _ ≤ v.2.1.val + v.1.val * degree := by
        rw [Polynomial.natDegree_X_pow]
        exact Nat.add_le_add_left (Polynomial.natDegree_pow_le_of_le _ hP) _
  have hv := coefficient_weighted_degree v
  have hv' : v.2.1.val + v.1.val * degree < xBound := by
    simpa [Nat.mul_comm] using hv
  exact lt_of_le_of_lt ht hv'

theorem specializedInterpolant_natDegree (c : CoefficientIndex → K) (z : K)
    (P : Polynomial K) (hP : P.natDegree ≤ degree) :
    (specializedInterpolant c z P).natDegree < multiplicity * threshold := by
  have hs : (specializedInterpolant c z P).natDegree ≤ xBound - 1 := by
    apply Polynomial.natDegree_sum_le_of_forall_le
    intro v _
    have hv := specializedTerm_natDegree c z P hP v
    omega
  have hgeom := exact_analysis_geometry
  omega

theorem specializedInterpolant_eq_zero_of_large_divisor
    (c : CoefficientIndex → K) (z : K) (P D : Polynomial K)
    (hP : P.natDegree ≤ degree) (hD : D ∣ specializedInterpolant c z P)
    (hdegree : multiplicity * threshold ≤ D.natDegree) :
    specializedInterpolant c z P = 0 := by
  by_contra hz
  have hle := Polynomial.natDegree_le_of_dvd hD hz
  have hlt := specializedInterpolant_natDegree c z P hP
  omega

def nestedInterpolant (c : CoefficientIndex → K) (z : K) :
    Polynomial (Polynomial K) :=
  ∑ v, Polynomial.C
      (Polynomial.C (c v * z ^ v.2.2.val) * Polynomial.X ^ v.2.1.val) *
    Polynomial.X ^ v.1.val

theorem nestedInterpolant_eval (c : CoefficientIndex → K) (z : K) (P : Polynomial K) :
    (nestedInterpolant c z).eval P = specializedInterpolant c z P := by
  simp only [nestedInterpolant, specializedInterpolant, Polynomial.eval_finsetSum,
    Polynomial.eval_mul, Polynomial.eval_C, Polynomial.eval_pow, Polynomial.eval_X]
  apply Finset.sum_congr rfl
  intro v _
  simp only [specializedTerm]
  ring

def hasseGeneratingPolynomial (c : CoefficientIndex → K) (point U V : Fin domain → K)
    (a : Fin domain) (s : Fin multiplicity)
    (r : Fin (multiplicity - s.val)) : Polynomial K :=
  ∑ v, Polynomial.C (c v) *
    HegemonCrypto.SmallWood.Mca38Published.hasseMonomialPolynomial
      (point a) (U a) (V a) v.2.1.val v.1.val v.2.2.val r.val s.val

theorem hasseGeneratingPolynomial_eq_zero
    (c : CoefficientIndex → K) (point U V : Fin domain → K)
    (hsolve : ∀ e : EquationIndex,
      (∑ v, c v * hasseCoefficient point U V e v) = 0)
    (a : Fin domain) (s : Fin multiplicity)
    (r : Fin (multiplicity - s.val)) :
    hasseGeneratingPolynomial c point U V a s r = 0 := by
  ext t
  rw [Polynomial.coeff_zero]
  by_cases ht : t < zBound - s.val
  · rw [hasseGeneratingPolynomial, Polynomial.finsetSum_coeff]
    simp only [Polynomial.coeff_C_mul,
      HegemonCrypto.SmallWood.Mca38Published.hasseMonomialPolynomial_coeff]
    exact hsolve (a, ⟨s, r, ⟨t, ht⟩⟩)
  · rw [hasseGeneratingPolynomial, Polynomial.finsetSum_coeff]
    apply Finset.sum_eq_zero
    intro v _
    rw [Polynomial.coeff_C_mul,
      HegemonCrypto.SmallWood.Mca38Published.hasseMonomialPolynomial_coeff]
    by_cases hs : s.val ≤ v.1.val
    · have hv := coefficient_z_specialization_degree v
      have : ¬ (v.2.2.val ≤ t ∧ t - v.2.2.val ≤ v.1.val - s.val) := by omega
      rw [if_neg this]
      simp
    · have hchoose : Nat.choose v.1.val s.val = 0 :=
        Nat.choose_eq_zero_of_lt (Nat.lt_of_not_ge hs)
      simp [hchoose]

theorem bivariateTaylor_monomial_coeff (a x y : K) (i j r s : ℕ) :
    ((HegemonCrypto.SmallWood.Mca38Published.bivariateTaylor
      (Polynomial.C (Polynomial.C a * Polynomial.X ^ i) * Polynomial.X ^ j)
      x y).coeff s).coeff r =
      a * (Nat.choose i r : K) * (Nat.choose j s : K) *
        x ^ (i - r) * y ^ (j - s) :=
  HegemonCrypto.SmallWood.Mca38Published.bivariateTaylor_monomial_coeff a x y i j r s

theorem nestedTaylor_coeff_eq_hasse_eval
    (c : CoefficientIndex → K) (point U V : Fin domain → K) (z : K)
    (a : Fin domain) (s : Fin multiplicity)
    (r : Fin (multiplicity - s.val)) :
    ((HegemonCrypto.SmallWood.Mca38Published.bivariateTaylor
      (nestedInterpolant c z) (point a) (U a + z * V a)).coeff s.val).coeff r.val =
      (hasseGeneratingPolynomial c point U V a s r).eval z := by
  unfold nestedInterpolant
  simp only [HegemonCrypto.SmallWood.Mca38Published.bivariateTaylor,
    Polynomial.map_sum, map_sum, Polynomial.finsetSum_coeff]
  change (∑ v, ((HegemonCrypto.SmallWood.Mca38Published.bivariateTaylor
      (Polynomial.C (Polynomial.C (c v * z ^ v.2.2.val) *
        Polynomial.X ^ v.2.1.val) * Polynomial.X ^ v.1.val)
      (point a) (U a + z * V a)).coeff s.val).coeff r.val) =
      (hasseGeneratingPolynomial c point U V a s r).eval z
  simp only [bivariateTaylor_monomial_coeff, hasseGeneratingPolynomial,
    HegemonCrypto.SmallWood.Mca38Published.hasseMonomialPolynomial,
    Polynomial.eval_finsetSum, Polynomial.eval_mul, Polynomial.eval_C,
    Polynomial.eval_pow, Polynomial.eval_add, Polynomial.eval_X]
  apply Finset.sum_congr rfl
  intro v _
  ring

theorem actual_local_multiplicity
    (c : CoefficientIndex → K) (point U V : Fin domain → K)
    (hsolve : ∀ e : EquationIndex,
      (∑ v, c v * hasseCoefficient point U V e v) = 0)
    (z : K) (P : Polynomial K) (a : Fin domain)
    (hmatch : P.eval (point a) = U a + z * V a) :
    (Polynomial.X - Polynomial.C (point a)) ^
        Mca38RoundByRoundParameters.multiplicity ∣
      specializedInterpolant c z P := by
  rw [← nestedInterpolant_eval]
  apply HegemonCrypto.SmallWood.Mca38Published.local_multiplicity_of_bivariate_coefficients
    (nestedInterpolant c z) P (point a) (U a + z * V a) multiplicity hmatch
  intro r s hrs
  have hs : s < multiplicity := by omega
  have hr : r < multiplicity - s := by omega
  rw [nestedTaylor_coeff_eq_hasse_eval c point U V z a ⟨s, hs⟩ ⟨r, hr⟩,
    hasseGeneratingPolynomial_eq_zero c point U V hsolve]
  exact Polynomial.eval_zero

end
end HegemonCrypto.SmallWood.Mca38RoundByRound

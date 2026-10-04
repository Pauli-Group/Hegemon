import Mca38GsInterpolationR3
import Mathlib.Algebra.Polynomial.BigOperators

/-! Actual Q(X,P(X),z) specialization and its strict degree budget.
The Hasse-multiplicity-to-divisibility step is not assumed to be proved here. -/
namespace HegemonCrypto.SmallWood.Mca38Published
open scoped BigOperators
noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]

def specializedTerm (c : MonomialIndex → K) (z : K) (P : Polynomial K)
    (v : MonomialIndex) : Polynomial K :=
  Polynomial.C (c v * z ^ v.2.2.val) *
    (Polynomial.X ^ v.2.1.val * P ^ v.1.val)

def specializedInterpolant (c : MonomialIndex → K) (z : K) (P : Polynomial K) :
    Polynomial K := ∑ v, specializedTerm c z P v

theorem specializedTerm_natDegree (c : MonomialIndex → K) (z : K)
    (P : Polynomial K) (hP : P.natDegree ≤ k) (v : MonomialIndex) :
    (specializedTerm c z P v).natDegree < xBound := by
  have ht :
      (specializedTerm c z P v).natDegree ≤ v.2.1.val + v.1.val * k := by
    calc
      _ ≤ (Polynomial.X ^ v.2.1.val * P ^ v.1.val).natDegree :=
        Polynomial.natDegree_C_mul_le _ _
      _ ≤ (Polynomial.X ^ v.2.1.val : Polynomial K).natDegree +
          (P ^ v.1.val).natDegree := Polynomial.natDegree_mul_le
      _ ≤ v.2.1.val + v.1.val * k := by
        rw [Polynomial.natDegree_X_pow]
        exact Nat.add_le_add_left (Polynomial.natDegree_pow_le_of_le _ hP) _
  have hv := monomial_weighted_degree v
  have hcomm : v.1.val * k = k * v.1.val := Nat.mul_comm _ _
  omega

theorem specializedInterpolant_natDegree (c : MonomialIndex → K) (z : K)
    (P : Polynomial K) (hP : P.natDegree ≤ k) :
    (specializedInterpolant c z P).natDegree < multiplicity * cutoff := by
  have hs : (specializedInterpolant c z P).natDegree ≤ xBound - 1 := by
    apply Polynomial.natDegree_sum_le_of_forall_le
    intro v _
    have hv := specializedTerm_natDegree c z P hP v
    omega
  rw [← exact_support_multiplicity_budget]
  have hx : 0 < xBound := by norm_num [xBound]
  omega

/-- Once multiplicity on the full distinct-point support supplies a divisor
of degree at least m*g, the actual specialization must be zero. This consumes
a polynomial divisibility witness, not a desired label-count hypothesis. -/
theorem specializedInterpolant_eq_zero_of_large_divisor
    (c : MonomialIndex → K) (z : K) (P D : Polynomial K)
    (hP : P.natDegree ≤ k)
    (hD : D ∣ specializedInterpolant c z P)
    (hdegree : multiplicity * cutoff ≤ D.natDegree) :
    specializedInterpolant c z P = 0 := by
  by_contra hz
  have hle := Polynomial.natDegree_le_of_dvd hD hz
  have hlt := specializedInterpolant_natDegree c z P hP
  omega

end
end HegemonCrypto.SmallWood.Mca38Published



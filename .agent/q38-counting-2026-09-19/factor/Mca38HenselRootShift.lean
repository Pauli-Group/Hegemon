import Mca38ClearedResidualAssembly
import Mca38SimpleFactorStartR2

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R S : Type*} [CommRing R] [CommRing S]

/-- Shift the dependent variable by its represented starting root. -/
def henselRootShift (F : Polynomial (Polynomial R)) (c : R) :
    Polynomial (Polynomial R) := Polynomial.taylor (Polynomial.C c) F

theorem henselRootShift_map_eval (φ : R →+* S)
    (F : Polynomial (Polynomial R)) (c : R) (p : Polynomial S) :
    ((henselRootShift F c).map (Polynomial.mapRingHom φ)).eval
      (p - Polynomial.C (φ c)) =
      (F.map (Polynomial.mapRingHom φ)).eval p := by
  rw [henselRootShift, Polynomial.map_taylor]
  change (Polynomial.taylor ((Polynomial.C c).map φ)
    (F.map (Polynomial.mapRingHom φ))).eval (p - Polynomial.C (φ c)) = _
  rw [Polynomial.map_C, Polynomial.taylor_eval_sub]

theorem henselRootShift_derivative_origin
    (F : Polynomial (Polynomial R)) (c : R) :
    ((henselRootShift F c).coeff 1).coeff 0 = (F.derivative.eval (Polynomial.C c)).coeff 0 := by
  rw [henselRootShift, Polynomial.taylor_coeff_one]

theorem henselRootShift_natDegree (F : Polynomial (Polynomial R)) (c : R) :
    (henselRootShift F c).natDegree = F.natDegree := by
  exact Polynomial.natDegree_taylor F (Polynomial.C c)

theorem correction_constant_zero (φ : R →+* S) (p : Polynomial S) (c : R)
    (hc : p.coeff 0 = φ c) : (p - Polynomial.C (φ c)).coeff 0 = 0 := by
  simp only [Polynomial.coeff_sub, Polynomial.coeff_C_zero, hc, sub_self]

theorem correction_natDegree_le (p : Polynomial S) (c : S) (N : ℕ)
    (hp : p.natDegree ≤ N) : (p - Polynomial.C c).natDegree ≤ N := by
  exact (Polynomial.natDegree_sub_le p (Polynomial.C c)).trans (max_le hp (by simp))

def fullHenselNumerator (A : ℕ → Polynomial R) (d c : Polynomial R) (N : ℕ) :
    Polynomial (Polynomial R) :=
  Polynomial.C (c * d^(2*N-1)) + commonHenselNumerator A d N

/-- Restore the represented constant root without introducing an unrelated
denominator or numerator. -/
theorem fullHenselNumerator_clear (φ : Polynomial R →+* S)
    (A : ℕ → Polynomial R) (d c : Polynomial R) (N : ℕ) (p : Polynomial S)
    (hp : p.natDegree ≤ N) (hp0 : p.coeff 0 = φ c)
    (hA : ∀ n, 0 < n → n ≤ N → φ (A n) = φ d ^ (2*n-1) *
      (p - Polynomial.C (φ c)).coeff n) :
    (fullHenselNumerator A d c N).map φ = Polynomial.C (φ d^(2*N-1)) * p := by
  have h := commonHenselNumerator_clear φ A d N (p - Polynomial.C (φ c))
    (correction_natDegree_le p (φ c) N hp) (correction_constant_zero φ p c hp0) hA
  rw [fullHenselNumerator, Polynomial.map_add, Polynomial.map_C, map_mul, map_pow, h]
  rw [Polynomial.C_mul]
  ring

/-- The sharper derivative height leaves room for the constant root.
For the T degree, deg(c)=1 and deg(d)≤m−1 give this arithmetic premise
with D=m; for the Z degree c has degree zero. -/
theorem fullHenselNumerator_height (A : ℕ → Polynomial R) (d c : Polynomial R)
    (D N : ℕ) (hd : d.natDegree ≤ D)
    (hc : c.natDegree + (2*N-1)*d.natDegree ≤ (2*N-1)*D)
    (hA : ∀ n, 0 < n → n ≤ N → (A n).natDegree ≤ (2*n-1)*D) :
    ∀ i, ((fullHenselNumerator A d c N).coeff i).natDegree ≤ (2*N-1)*D := by
  intro i
  rw [fullHenselNumerator, Polynomial.coeff_add]
  refine (Polynomial.natDegree_add_le _ _).trans ?_
  apply max_le
  · rw [Polynomial.coeff_C]
    split_ifs
    · exact Polynomial.natDegree_mul_le.trans
        ((Nat.add_le_add_left Polynomial.natDegree_pow_le _).trans hc)
    · simp
  · exact commonHenselNumerator_height A d D N hd hA i

end
end HegemonCrypto.SmallWood.Mca38Published

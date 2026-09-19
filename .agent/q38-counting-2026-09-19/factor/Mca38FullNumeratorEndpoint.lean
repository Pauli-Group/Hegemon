import Mca38TaylorCoefficientHeight

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R S : Type*} [CommRing R] [CommRing S]

theorem fullHenselNumerator_map (σ : Polynomial R →+* Polynomial R)
    (A : ℕ → Polynomial R) (d c : Polynomial R) (N : ℕ) :
    (fullHenselNumerator A d c N).map σ =
      fullHenselNumerator (fun n => σ (A n)) (σ d) (σ c) N := by
  classical
  simp only [fullHenselNumerator, commonHenselNumerator, Polynomial.map_add,
    Polynomial.map_sum, Polynomial.map_monomial, map_mul, map_pow]
  congr 1
  · simp
  · apply Finset.sum_congr rfl
    intro n _
    split_ifs <;> simp

/-- Assemble one actual full-response numerator with simultaneous heights
from the finite Hensel recurrence. The response has its original represented
constant root, rather than an assumed zero constant coefficient. -/
theorem exists_full_hensel_numerator [Nontrivial S]
    (σ : Polynomial R →+* Polynomial R) (φ : Polynomial R →+* S)
    (F : Polynomial (Polynomial (Polynomial R))) (c : Polynomial R)
    (p : Polynomial S) (D₁ D₂ N : ℕ)
    (hF₁ : ∀ j i, (((henselRootShift F c).coeff j).coeff i).natDegree ≤ D₁)
    (hF₂ : ∀ j i, (σ (((henselRootShift F c).coeff j).coeff i)).natDegree ≤ D₂)
    (hd : IsUnit (φ (((henselRootShift F c).coeff 1).coeff 0)))
    (hc₁ : c.natDegree + (2*N-1)*
        (((henselRootShift F c).coeff 1).coeff 0).natDegree ≤ (2*N-1)*D₁)
    (hc₂ : (σ c).natDegree + (2*N-1)*
        (σ (((henselRootShift F c).coeff 1).coeff 0)).natDegree ≤ (2*N-1)*D₂)
    (hp : p.natDegree ≤ N) (hp0 : p.coeff 0 = φ c)
    (hroot : Polynomial.X^(N+1) ∣ (F.map (Polynomial.mapRingHom φ)).eval p) :
    ∃ Q : Polynomial (Polynomial R),
      (∀ i, (Q.coeff i).natDegree ≤ (2*N-1)*D₁) ∧
      (∀ i, (σ (Q.coeff i)).natDegree ≤ (2*N-1)*D₂) ∧
      Q.map φ = Polynomial.C (φ (((henselRootShift F c).coeff 1).coeff 0)^(2*N-1))*p := by
  classical
  let d := ((henselRootShift F c).coeff 1).coeff 0
  have hshift : Polynomial.X^(N+1) ∣
      ((henselRootShift F c).map (Polynomial.mapRingHom φ)).eval
        (p-Polynomial.C (φ c)) := by
    rw [henselRootShift_map_eval]
    exact hroot
  have hex := finite_polynomial_shared_hensel_height σ φ (henselRootShift F c)
    (p-Polynomial.C (φ c)) D₁ D₂ N hF₁ hF₂ hd
    (correction_constant_zero φ p c hp0) hshift
  have htotal : ∀ n, ∃ A : Polynomial R, (0<n ∧ n≤N) →
      A.natDegree ≤ (2*n-1)*D₁ ∧ (σ A).natDegree ≤ (2*n-1)*D₂ ∧
      φ A = φ d^(2*n-1)*(p-Polynomial.C (φ c)).coeff n := by
    intro n
    by_cases hn : 0<n ∧ n≤N
    · obtain ⟨A, hA⟩ := hex n hn.1 hn.2
      exact ⟨A, fun _ => hA⟩
    · exact ⟨0, fun h => (hn h).elim⟩
  choose A hA using htotal
  refine ⟨fullHenselNumerator A d c N, ?_, ?_, ?_⟩
  · exact fullHenselNumerator_height A d c D₁ N (hF₁ 1 0) hc₁
      (fun n hn hN => (hA n ⟨hn,hN⟩).1)
  · intro i
    have h := fullHenselNumerator_height (fun n => σ (A n)) (σ d) (σ c)
      D₂ N (hF₂ 1 0) hc₂ (fun n hn hN => (hA n ⟨hn,hN⟩).2.1) i
    rw [← fullHenselNumerator_map σ A d c N, Polynomial.coeff_map] at h
    exact h
  · exact fullHenselNumerator_clear φ A d c N p hp hp0
      (fun n hn hN => (hA n ⟨hn,hN⟩).2.2)

end
end HegemonCrypto.SmallWood.Mca38Published

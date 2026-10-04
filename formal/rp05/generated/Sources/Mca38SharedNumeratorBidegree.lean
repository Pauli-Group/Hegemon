import Mca38UnitHenselHeight

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R : Type*} [CommRing R]

/-- The explicit variable interchange homomorphism for nested polynomials.
The inner variable is sent to the outer variable and vice versa. -/
def coefficientVariableSwap {K : Type*} [CommRing K] :
    Polynomial (Polynomial K) →+* Polynomial (Polynomial K) :=
  Polynomial.eval₂RingHom (Polynomial.mapRingHom Polynomial.C) (Polynomial.C Polynomial.X)

theorem henselNumerator_ringHom {ι : Type*}
    (σ : Polynomial R →+* Polynomial R) (s : Finset ι)
    (c : ι → Polynomial R) (d : Polynomial R) (A : ℕ → Polynomial R)
    (i : ι → ℕ) (l : ι → List ℕ) :
    σ (henselNumerator s c d A i l) =
      henselNumerator s (fun t => σ (c t)) (σ d) (fun r => σ (A r)) i l := by
  simp only [henselNumerator, henselNumeratorTerm, map_neg, map_sum,
    map_mul, map_pow, map_list_prod, List.map_map, Function.comp_def]

/-- A single numerator simultaneously satisfies both degree bounds.
The same recurrence construction is used for both; this does not combine
unrelated existential representatives from two one-variable proofs. -/
theorem exists_shared_hensel_numerator_through_order
    {S ι : Type*} [CommRing S]
    (σ : Polynomial R →+* Polynomial R) (φ : Polynomial R →+* S)
    (d : Polynomial R) (a : ℕ → S)
    (s : ℕ → Finset ι) (c : ℕ → ι → Polynomial R)
    (i : ℕ → ι → ℕ) (l : ℕ → ι → List ℕ) (D₁ D₂ N : ℕ)
    (hd : IsUnit (φ d)) (hd₁ : d.natDegree ≤ D₁) (hd₂ : (σ d).natDegree ≤ D₂)
    (hc₁ : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, (c n t).natDegree ≤ D₁)
    (hc₂ : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, (σ (c n t)).natDegree ≤ D₂)
    (hl : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, ∀ r ∈ l n t, 0 < r ∧ r < n)
    (hn : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, i n t + (l n t).sum = n)
    (ht : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, 2 ≤ 2 * i n t + (l n t).length)
    (hrec : ∀ n, 0 < n → n ≤ N →
      φ d * a n = -(∑ t ∈ s n, φ (c n t) * ((l n t).map a).prod)) :
    ∀ n, 0 < n → n ≤ N → ∃ A : Polynomial R,
      A.natDegree ≤ (2 * n - 1) * D₁ ∧
      (σ A).natDegree ≤ (2 * n - 1) * D₂ ∧
      φ A = φ d ^ (2 * n - 1) * a n := by
  classical
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro hnpos hnN
    have hprefix : ∀ r : ℕ, ∃ A : Polynomial R, (0 < r ∧ r < n) →
        A.natDegree ≤ (2 * r - 1) * D₁ ∧
        (σ A).natDegree ≤ (2 * r - 1) * D₂ ∧
        φ A = φ d ^ (2 * r - 1) * a r := by
      intro r
      by_cases hr : 0 < r ∧ r < n
      · obtain ⟨A, hA⟩ := ih r hr.2 hr.1 ((Nat.le_of_lt hr.2).trans hnN)
        exact ⟨A, fun _ => hA⟩
      · exact ⟨0, fun h => (hr h).elim⟩
    choose A hA using hprefix
    refine ⟨henselNumerator (s n) (c n) d A (i n) (l n), ?_, ?_, ?_⟩
    · exact henselNumerator_natDegree_le (s n) (c n) d A (i n) (l n) D₁ n
        hd₁ (hc₁ n hnpos hnN)
        (fun t ht r hr => (hl n hnpos hnN t ht r hr).1)
        (hn n hnpos hnN) (ht n hnpos hnN)
        (fun t ht r hr => (hA r (hl n hnpos hnN t ht r hr)).1)
    · rw [henselNumerator_ringHom]
      exact henselNumerator_natDegree_le (s n) (fun t => σ (c n t)) (σ d)
        (fun r => σ (A r)) (i n) (l n) D₂ n hd₂ (hc₂ n hnpos hnN)
        (fun t ht r hr => (hl n hnpos hnN t ht r hr).1)
        (hn n hnpos hnN) (ht n hnpos hnN)
        (fun t ht r hr => (hA r (hl n hnpos hnN t ht r hr)).2.1)
    · exact henselNumerator_clear_of_isUnit φ (s n) (c n) d A a (i n) (l n) n hd
        (fun t ht r hr => (hl n hnpos hnN t ht r hr).1)
        (hn n hnpos hnN) (ht n hnpos hnN)
        (fun t ht r hr => (hA r (hl n hnpos hnN t ht r hr)).2.2)
        (hrec n hnpos hnN)

theorem finite_polynomial_shared_hensel_height
    {S : Type*} [CommRing S] [Nontrivial S]
    (σ : Polynomial R →+* Polynomial R) (φ : Polynomial R →+* S)
    (F : Polynomial (Polynomial (Polynomial R))) (p : Polynomial S) (D₁ D₂ N : ℕ)
    (hcoeff₁ : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ D₁)
    (hcoeff₂ : ∀ j i, (σ ((F.coeff j).coeff i)).natDegree ≤ D₂)
    (hd : IsUnit (φ ((F.coeff 1).coeff 0)))
    (hp : p.coeff 0 = 0)
    (hroot : Polynomial.X ^ (N + 1) ∣
      (F.map (Polynomial.mapRingHom φ)).eval p) :
    ∀ n, 0 < n → n ≤ N → ∃ A : Polynomial R,
      A.natDegree ≤ (2 * n - 1) * D₁ ∧
      (σ A).natDegree ≤ (2 * n - 1) * D₂ ∧
      φ A = φ ((F.coeff 1).coeff 0) ^ (2 * n - 1) * p.coeff n := by
  let f : Polynomial (Polynomial S) := F.map (Polynomial.mapRingHom φ)
  have hmap : ∀ j i, (f.coeff j).coeff i = φ ((F.coeff j).coeff i) := by
    intro j i
    simp only [f, Polynomial.coeff_map, Polynomial.coe_mapRingHom]
  have hfd : (f.coeff 1).coeff 0 ≠ 0 := by rw [hmap]; exact hd.ne_zero
  apply exists_shared_hensel_numerator_through_order σ φ ((F.coeff 1).coeff 0) p.coeff
    (henselRecurrenceIndices f)
    (fun _ t => (F.coeff t.1).coeff (henselIndexOrder t))
    (fun _ => henselIndexOrder) (fun _ => henselIndexList) D₁ D₂ N
    hd (hcoeff₁ 1 0) (hcoeff₂ 1 0)
  · intro n hn hnN t ht
    exact hcoeff₁ _ _
  · intro n hn hnN t ht
    exact hcoeff₂ _ _
  · intro n hn hnN t ht
    exact (henselRecurrenceIndices_spec f n hn t ht).1
  · intro n hn hnN t ht
    exact (henselRecurrenceIndices_spec f n hn t ht).2.1
  · intro n hn hnN t ht
    exact (henselRecurrenceIndices_spec f n hn t ht).2.2
  · intro n hn hnN
    have hz : (f.eval p).coeff n = 0 :=
      (Polynomial.X_pow_dvd_iff.mp hroot) n (Nat.lt_succ_of_le hnN)
    have h := hensel_actual_recurrence f p n hn hp hfd hz
    simpa only [henselIndexCoefficient, hmap] using h

end
end HegemonCrypto.SmallWood.Mca38Published

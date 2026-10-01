import Mca38HenselPolynomialHeight

/-! Derivative-unit version of the checked finite-height construction.
This applies inside a finite localization without assuming an integral domain
or an injection into the algebraic function field. -/
namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R : Type*} [CommRing R]

theorem henselNumerator_clear_of_isUnit {ι S : Type*} [CommRing S]
    (φ : Polynomial R →+* S) (s : Finset ι)
    (c : ι → Polynomial R) (d : Polynomial R) (A : ℕ → Polynomial R)
    (a : ℕ → S) (i : ι → ℕ) (l : ι → List ℕ) (n : ℕ)
    (hd : IsUnit (φ d))
    (hl : ∀ t ∈ s, ∀ r ∈ l t, 0 < r)
    (hn : ∀ t ∈ s, i t + (l t).sum = n)
    (hterm : ∀ t ∈ s, 2 ≤ 2 * i t + (l t).length)
    (hA : ∀ t ∈ s, ∀ r ∈ l t, φ (A r) = φ d ^ (2 * r - 1) * a r)
    (hrec : φ d * a n = -(∑ t ∈ s, φ (c t) * ((l t).map a).prod)) :
    φ (henselNumerator s c d A i l) = φ d ^ (2 * n - 1) * a n := by
  apply hd.mul_left_cancel
  calc
    φ d * φ (henselNumerator s c d A i l) =
        -(∑ t ∈ s, φ d * φ (henselNumeratorTerm (c t) d A (i t) (l t))) := by
      simp only [henselNumerator, map_neg, map_sum, mul_neg, Finset.mul_sum]
    _ = -(∑ t ∈ s, φ d ^ (2 * n - 1) * (φ (c t) * ((l t).map a).prod)) := by
      congr 1
      apply Finset.sum_congr rfl
      intro t ht
      exact henselNumeratorTerm_clear φ (c t) d A a n (i t) (l t)
        (hl t ht) (hn t ht) (hterm t ht) (hA t ht)
    _ = φ d ^ (2 * n - 1) * (-(∑ t ∈ s, φ (c t) * ((l t).map a).prod)) := by
      rw [mul_neg, Finset.mul_sum]
    _ = φ d * (φ d ^ (2 * n - 1) * a n) := by rw [← hrec]; ring


theorem exists_hensel_numerator_through_order_of_isUnit
    {R S ι : Type*} [CommRing R] [CommRing S]
    (φ : Polynomial R →+* S) (d : Polynomial R) (a : ℕ → S)
    (s : ℕ → Finset ι) (c : ℕ → ι → Polynomial R)
    (i : ℕ → ι → ℕ) (l : ℕ → ι → List ℕ) (D N : ℕ)
    (hd : IsUnit (φ d)) (hdDegree : d.natDegree ≤ D)
    (hc : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, (c n t).natDegree ≤ D)
    (hl : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, ∀ r ∈ l n t, 0 < r ∧ r < n)
    (hn : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, i n t + (l n t).sum = n)
    (ht : ∀ n, 0 < n → n ≤ N → ∀ t ∈ s n, 2 ≤ 2 * i n t + (l n t).length)
    (hrec : ∀ n, 0 < n → n ≤ N →
      φ d * a n = -(∑ t ∈ s n, φ (c n t) * ((l n t).map a).prod)) :
    ∀ n, 0 < n → n ≤ N → ∃ A : Polynomial R,
      A.natDegree ≤ (2 * n - 1) * D ∧ φ A = φ d ^ (2 * n - 1) * a n := by
  classical
  intro n
  induction n using Nat.strong_induction_on with
  | h n ih =>
    intro hnpos hnN
    have hprefix : ∀ r : ℕ, ∃ A : Polynomial R, (0 < r ∧ r < n) →
        A.natDegree ≤ (2 * r - 1) * D ∧ φ A = φ d ^ (2 * r - 1) * a r := by
      intro r
      by_cases hr : 0 < r ∧ r < n
      · obtain ⟨A, hA⟩ := ih r hr.2 hr.1 ((Nat.le_of_lt hr.2).trans hnN)
        exact ⟨A, fun _ => hA⟩
      · exact ⟨0, fun h => (hr h).elim⟩
    choose A hA using hprefix
    refine ⟨henselNumerator (s n) (c n) d A (i n) (l n), ?_, ?_⟩
    · exact henselNumerator_natDegree_le (s n) (c n) d A (i n) (l n) D n
        hdDegree (hc n hnpos hnN)
        (fun t ht r hr => (hl n hnpos hnN t ht r hr).1)
        (hn n hnpos hnN) (ht n hnpos hnN)
        (fun t ht r hr => (hA r (hl n hnpos hnN t ht r hr)).1)
    · exact henselNumerator_clear_of_isUnit φ (s n) (c n) d A a (i n) (l n) n hd
        (fun t ht r hr => (hl n hnpos hnN t ht r hr).1)
        (hn n hnpos hnN) (ht n hnpos hnN)
        (fun t ht r hr => (hA r (hl n hnpos hnN t ht r hr)).2)
        (hrec n hnpos hnN)

theorem finite_polynomial_hensel_height_of_isUnit
    {R S : Type*} [CommRing R] [CommRing S] [Nontrivial S]
    (φ : Polynomial R →+* S)
    (F : Polynomial (Polynomial (Polynomial R))) (p : Polynomial S) (D N : ℕ)
    (hcoeff : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ D)
    (hd : IsUnit (φ ((F.coeff 1).coeff 0)))
    (hp : p.coeff 0 = 0)
    (hroot : Polynomial.X ^ (N + 1) ∣
      (F.map (Polynomial.mapRingHom φ)).eval p) :
    ∀ n, 0 < n → n ≤ N → ∃ A : Polynomial R,
      A.natDegree ≤ (2 * n - 1) * D ∧
      φ A = φ ((F.coeff 1).coeff 0) ^ (2 * n - 1) * p.coeff n := by
  let f : Polynomial (Polynomial S) := F.map (Polynomial.mapRingHom φ)
  have hmap : ∀ j i, (f.coeff j).coeff i = φ ((F.coeff j).coeff i) := by
    intro j i
    simp only [f, Polynomial.coeff_map, Polynomial.coe_mapRingHom]
  have hfd : (f.coeff 1).coeff 0 ≠ 0 := by rw [hmap]; exact hd.ne_zero
  apply exists_hensel_numerator_through_order_of_isUnit φ ((F.coeff 1).coeff 0) p.coeff
    (henselRecurrenceIndices f)
    (fun _ t => (F.coeff t.1).coeff (henselIndexOrder t))
    (fun _ => henselIndexOrder) (fun _ => henselIndexList) D N
    hd (hcoeff 1 0)
  · intro n hn hnN t ht
    exact hcoeff _ _
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

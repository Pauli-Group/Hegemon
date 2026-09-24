import Mca38HenselHeightR3

/-! Bounded-order induction: suitable for a finite Newton approximation whose
residual vanishes only through a specified order, not an exact polynomial root. -/
namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

theorem exists_hensel_numerator_through_order
    {R S ι : Type*} [CommRing R] [CommRing S] [IsDomain S]
    (φ : Polynomial R →+* S) (d : Polynomial R) (a : ℕ → S)
    (s : ℕ → Finset ι) (c : ℕ → ι → Polynomial R)
    (i : ℕ → ι → ℕ) (l : ℕ → ι → List ℕ) (D N : ℕ)
    (hd : φ d ≠ 0) (hdDegree : d.natDegree ≤ D)
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
    · exact henselNumerator_clear φ (s n) (c n) d A a (i n) (l n) n hd
        (fun t ht r hr => (hl n hnpos hnN t ht r hr).1)
        (hn n hnpos hnN) (ht n hnpos hnN)
        (fun t ht r hr => (hA r (hl n hnpos hnN t ht r hr)).2)
        (hrec n hnpos hnN)

end
end HegemonCrypto.SmallWood.Mca38Published

import Mathlib.Algebra.Polynomial.BigOperators
import Lean.Elab.Tactic.Omega
import Mathlib.Tactic.Ring

/-!
Linear numerator-height control for coefficientwise finite Hensel lifting.
This file constructs the numerator monomials and proves their degree bound;
it does not assume a numerator-height or bad-label-count conclusion.
The connection to the interpolant's coefficient recurrence is not yet made.
-/

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false

private theorem hensel_weight_sum (l : List ℕ) (hl : ∀ r ∈ l, 0 < r) :
    (l.map (fun r => 2 * r - 1)).sum + l.length = 2 * l.sum := by
  induction l with
  | nil => simp
  | cons r l ih =>
      have hr := hl r (by simp)
      have ht := ih (fun s hs => hl s (by simp [hs]))
      simp only [List.map_cons, List.sum_cons, List.length_cons]
      omega

/-- The exact denominator exponents for every non-linear/source term of
the implicit coefficient recurrence. The excluded derivative term is
precisely the only positive-order term with `2*i + length < 2`. -/
theorem hensel_term_exponent (n i : ℕ) (l : List ℕ)
    (hl : ∀ r ∈ l, 0 < r) (hn : i + l.sum = n)
    (hterm : 2 ≤ 2 * i + l.length) :
    1 + (2 * i + l.length - 2) + (l.map (fun r => 2 * r - 1)).sum =
      2 * n - 1 := by
  have h := hensel_weight_sum l hl
  omega

variable {R : Type*} [CommRing R]

/-- Numerator of a single coefficient contribution after clearing the
common denominator `d^(2*n-1)`. `l` lists the positive input orders. -/
noncomputable def henselNumeratorTerm
    (c d : Polynomial R) (A : ℕ → Polynomial R) (i : ℕ) (l : List ℕ) :
    Polynomial R :=
  c * d ^ (2 * i + l.length - 2) * (l.map A).prod

private theorem hensel_product_degree (A : ℕ → Polynomial R) (D : ℕ)
    (l : List ℕ) (hA : ∀ r ∈ l, (A r).natDegree ≤ (2 * r - 1) * D) :
    (l.map A).prod.natDegree ≤ (l.map (fun r => 2 * r - 1)).sum * D := by
  induction l with
  | nil => simp
  | cons r l ih =>
      have hr := hA r (by simp)
      have ht := ih (fun s hs => hA s (by simp [hs]))
      simp only [List.map_cons, List.prod_cons, List.sum_cons]
      calc
        (A r * (l.map A).prod).natDegree ≤
            (A r).natDegree + (l.map A).prod.natDegree := Polynomial.natDegree_mul_le
        _ ≤ (2 * r - 1) * D + (l.map (fun r => 2 * r - 1)).sum * D :=
          Nat.add_le_add hr ht
        _ = _ := (Nat.add_mul _ _ _).symm

/-- Numerator growth is linear in the lifted order, independently of the
number of factors in each coefficient contribution. Valid over any
commutative coefficient ring, in particular `R=K[T]` before reduction by H. -/
theorem henselNumeratorTerm_natDegree_le
    (c d : Polynomial R) (A : ℕ → Polynomial R) (D n i : ℕ) (l : List ℕ)
    (hc : c.natDegree ≤ D) (hd : d.natDegree ≤ D)
    (hl : ∀ r ∈ l, 0 < r) (hn : i + l.sum = n)
    (hterm : 2 ≤ 2 * i + l.length)
    (hA : ∀ r ∈ l, (A r).natDegree ≤ (2 * r - 1) * D) :
    (henselNumeratorTerm c d A i l).natDegree ≤ (2 * n - 1) * D := by
  have hp : (d ^ (2 * i + l.length - 2)).natDegree ≤
      (2 * i + l.length - 2) * D :=
    Polynomial.natDegree_pow_le.trans (Nat.mul_le_mul_left _ hd)
  have he := hensel_term_exponent n i l hl hn hterm
  unfold henselNumeratorTerm
  calc
    (c * d ^ (2 * i + l.length - 2) * (l.map A).prod).natDegree ≤
        (c.natDegree + (d ^ (2 * i + l.length - 2)).natDegree) +
          (l.map A).prod.natDegree :=
      Polynomial.natDegree_mul_le.trans
        (Nat.add_le_add_right Polynomial.natDegree_mul_le _)
    _ ≤ (D + (2 * i + l.length - 2) * D) +
        (l.map (fun r => 2 * r - 1)).sum * D :=
      Nat.add_le_add (Nat.add_le_add hc hp) (hensel_product_degree A D l hA)
    _ = (1 + (2 * i + l.length - 2) +
        (l.map (fun r => 2 * r - 1)).sum) * D := by
      simp only [Nat.add_mul, Nat.one_mul]
    _ = _ := by rw [he]

/-- An explicit finite numerator. Each index denotes a monomial in the
coefficient expansion; repeated equal monomials are allowed. -/
noncomputable def henselNumerator {ι : Type*} (s : Finset ι)
    (c : ι → Polynomial R) (d : Polynomial R) (A : ℕ → Polynomial R)
    (i : ι → ℕ) (l : ι → List ℕ) : Polynomial R :=
  -(∑ t ∈ s, henselNumeratorTerm (c t) d A (i t) (l t))

theorem henselNumerator_natDegree_le {ι : Type*} (s : Finset ι)
    (c : ι → Polynomial R) (d : Polynomial R) (A : ℕ → Polynomial R)
    (i : ι → ℕ) (l : ι → List ℕ) (D n : ℕ)
    (hd : d.natDegree ≤ D)
    (hc : ∀ t ∈ s, (c t).natDegree ≤ D)
    (hl : ∀ t ∈ s, ∀ r ∈ l t, 0 < r)
    (hn : ∀ t ∈ s, i t + (l t).sum = n)
    (hterm : ∀ t ∈ s, 2 ≤ 2 * i t + (l t).length)
    (hA : ∀ t ∈ s, ∀ r ∈ l t, (A r).natDegree ≤ (2 * r - 1) * D) :
    (henselNumerator s c d A i l).natDegree ≤ (2 * n - 1) * D := by
  unfold henselNumerator
  rw [Polynomial.natDegree_neg]
  exact Polynomial.natDegree_sum_le_of_forall_le s _ (fun t ht =>
    henselNumeratorTerm_natDegree_le (c t) d A D n (i t) (l t)
      (hc t ht) hd (hl t ht) (hn t ht) (hterm t ht) (hA t ht))

private theorem hensel_scaled_product {S : Type*} [CommRing S]
    (d : S) (a b : ℕ → S) (l : List ℕ)
    (hb : ∀ r ∈ l, b r = d ^ (2 * r - 1) * a r) :
    (l.map b).prod = d ^ (l.map (fun r => 2 * r - 1)).sum * (l.map a).prod := by
  induction l with
  | nil => simp
  | cons r l ih =>
      have hr := hb r (by simp)
      have ht := ih (fun s hs => hb s (by simp [hs]))
      simp only [List.map_cons, List.prod_cons, List.sum_cons, hr, ht, pow_add]
      ring

/-- Clearing one contribution commutes with every chosen specialization
homomorphism. No homomorphism out of the full rational-function field is
assumed. The target can be the finite localization or a specialization field. -/
theorem henselNumeratorTerm_clear {S : Type*} [CommRing S]
    (φ : Polynomial R →+* S) (c d : Polynomial R) (A : ℕ → Polynomial R)
    (a : ℕ → S) (n i : ℕ) (l : List ℕ)
    (hl : ∀ r ∈ l, 0 < r) (hn : i + l.sum = n)
    (hterm : 2 ≤ 2 * i + l.length)
    (hA : ∀ r ∈ l, φ (A r) = φ d ^ (2 * r - 1) * a r) :
    φ d * φ (henselNumeratorTerm c d A i l) =
      φ d ^ (2 * n - 1) * (φ c * (l.map a).prod) := by
  have hp := hensel_scaled_product (φ d) a (fun r => φ (A r)) l hA
  have he := hensel_term_exponent n i l hl hn hterm
  simp only [henselNumeratorTerm, map_mul, map_pow, map_list_prod, List.map_map, Function.comp_def]
  rw [hp, ← he]
  simp only [pow_add, pow_one]
  ring

/-- The finite polynomial above really is a cleared numerator for a
coefficient satisfying the implicit recurrence. Its height is supplied by
`henselNumerator_natDegree_le`, not by an extra hypothesis here. -/
theorem henselNumerator_clear {ι S : Type*} [CommRing S] [IsDomain S]
    (φ : Polynomial R →+* S) (s : Finset ι)
    (c : ι → Polynomial R) (d : Polynomial R) (A : ℕ → Polynomial R)
    (a : ℕ → S) (i : ι → ℕ) (l : ι → List ℕ) (n : ℕ)
    (hd : φ d ≠ 0)
    (hl : ∀ t ∈ s, ∀ r ∈ l t, 0 < r)
    (hn : ∀ t ∈ s, i t + (l t).sum = n)
    (hterm : ∀ t ∈ s, 2 ≤ 2 * i t + (l t).length)
    (hA : ∀ t ∈ s, ∀ r ∈ l t, φ (A r) = φ d ^ (2 * r - 1) * a r)
    (hrec : φ d * a n = -(∑ t ∈ s, φ (c t) * ((l t).map a).prod)) :
    φ (henselNumerator s c d A i l) = φ d ^ (2 * n - 1) * a n := by
  apply mul_left_cancel₀ hd
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

end HegemonCrypto.SmallWood.Mca38Published

import Mca38HenselCompositionR3
import Mathlib.Algebra.BigOperators.Group.Finset.Sigma
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Lean.Elab.Tactic.Omega
import Mathlib.Tactic.Ring

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false

abbrev HenselCompositionIndex := Σ j : ℕ, Σ _ : ℕ × ℕ, Fin j → ℕ

def henselDerivativeIndex (n : ℕ) : HenselCompositionIndex :=
  ⟨1, ⟨(0, n), fun _ => n⟩⟩

variable {R : Type*} [CommRing R]

noncomputable def henselAllIndices (f : Polynomial (Polynomial R)) (n : ℕ) :
    Finset HenselCompositionIndex :=
  f.support.sigma (fun j => (Finset.antidiagonal n).sigma (fun uv =>
    (Finset.Nat.antidiagonalTuple j uv.2).filter (fun v => ∀ r, 0 < v r)))

noncomputable def henselRecurrenceIndices (f : Polynomial (Polynomial R)) (n : ℕ) :
    Finset HenselCompositionIndex := by
  classical
  exact (henselAllIndices f n).erase (henselDerivativeIndex n)

def henselIndexOrder (t : HenselCompositionIndex) : ℕ := t.2.1.1

def henselIndexList (t : HenselCompositionIndex) : List ℕ := List.ofFn t.2.2

noncomputable def henselIndexCoefficient (f : Polynomial (Polynomial R))
    (t : HenselCompositionIndex) : R := (f.coeff t.1).coeff (henselIndexOrder t)

theorem henselAllIndices_spec (f : Polynomial (Polynomial R)) (n : ℕ)
    (t : HenselCompositionIndex) (ht : t ∈ henselAllIndices f n) :
    (∀ r, 0 < t.2.2 r) ∧
      henselIndexOrder t + ∑ r, t.2.2 r = n := by
  rcases Finset.mem_sigma.mp ht with ⟨_, ht⟩
  rcases Finset.mem_sigma.mp ht with ⟨huv, ht⟩
  rcases Finset.mem_filter.mp ht with ⟨hv, hp⟩
  exact ⟨hp, by
    rw [Finset.Nat.mem_antidiagonalTuple.mp hv]
    exact Finset.mem_antidiagonal.mp huv⟩

theorem hensel_derivative_member (f : Polynomial (Polynomial R)) (n : ℕ)
    (hn : 0 < n) (hd : (f.coeff 1).coeff 0 ≠ 0) :
    henselDerivativeIndex n ∈ henselAllIndices f n := by
  have hsupport : 1 ∈ f.support := by
    by_contra h
    have hf := Polynomial.notMem_support_iff.mp h
    exact hd (by rw [hf]; simp)
  apply Finset.mem_sigma.mpr
  refine ⟨hsupport, ?_⟩
  apply Finset.mem_sigma.mpr
  refine ⟨Finset.mem_antidiagonal.mpr (zero_add n), ?_⟩
  apply Finset.mem_filter.mpr
  refine ⟨Finset.Nat.mem_antidiagonalTuple.mpr ?_, fun _ => hn⟩
  change (∑ _ : Fin 1, n) = n
  simp

theorem hensel_remaining_index_not_linear
    (f : Polynomial (Polynomial R)) (n : ℕ) (t : HenselCompositionIndex)
    (ht : t ∈ henselRecurrenceIndices f n) :
    ¬ (t.1 = 1 ∧ henselIndexOrder t = 0) := by
  classical
  have hm := Finset.mem_erase.mp ht
  have hs := (henselAllIndices_spec f n t hm.2).2
  rcases t with ⟨j, ⟨⟨i, q⟩, v⟩⟩
  intro he
  rcases he with ⟨hj, hi⟩
  change j = 1 at hj
  change i = 0 at hi
  subst j
  subst i
  have hv : v = fun _ => n := by
    funext r
    have hr : r = 0 := Subsingleton.elim _ _
    subst r
    simpa [henselIndexOrder] using hs
  have hq : q = n := by
    have hmem := Finset.mem_sigma.mp hm.2
    have hp := Finset.mem_sigma.mp hmem.2
    simpa using Finset.mem_antidiagonal.mp hp.1
  apply hm.1
  simp [henselDerivativeIndex, hv, hq]

/-- Every enumerated residual term consumes only earlier positive root
coefficients. These are the exact well-foundedness and exponent premises of
the numerator-height induction, now derived from the actual index set. -/
theorem henselRecurrenceIndices_spec
    (f : Polynomial (Polynomial R)) (n : ℕ) (hn : 0 < n)
    (t : HenselCompositionIndex) (ht : t ∈ henselRecurrenceIndices f n) :
    (∀ r ∈ henselIndexList t, 0 < r ∧ r < n) ∧
      henselIndexOrder t + (henselIndexList t).sum = n ∧
      2 ≤ 2 * henselIndexOrder t + (henselIndexList t).length := by
  classical
  obtain ⟨hp, hs⟩ := henselAllIndices_spec f n t (Finset.mem_erase.mp ht).2
  have hnot := hensel_remaining_index_not_linear f n t ht
  have hlen : (henselIndexList t).length = t.1 := by simp [henselIndexList]
  have hsum : (henselIndexList t).sum = ∑ r, t.2.2 r := by
    exact List.sum_ofFn
  have hpositiveSum : (∑ r, t.2.2 r) = t.1 + ∑ r, (t.2.2 r - 1) := by
    calc
      (∑ r, t.2.2 r) = ∑ r, (1 + (t.2.2 r - 1)) := by
        apply Finset.sum_congr rfl
        intro r _
        have hr := hp r
        omega
      _ = _ := by simp [Finset.sum_add_distrib]
  have hterm : 2 ≤ 2 * henselIndexOrder t + t.1 := by
    by_cases hz : t.1 = 0
    · have he : (∑ r, t.2.2 r) = 0 := by
        haveI : IsEmpty (Fin t.1) := ⟨fun r => by have hr := r.isLt; omega⟩
        simp
      omega
    · omega
  refine ⟨?_, by omega, by omega⟩
  rw [henselIndexList, List.forall_mem_ofFn_iff]
  intro r
  have hr := hp r
  have hsingle : t.2.2 r - 1 ≤ ∑ s, (t.2.2 s - 1) :=
    Finset.single_le_sum (f := fun s : Fin t.1 => t.2.2 s - 1)
      (fun _ _ => Nat.zero_le _) (Finset.mem_univ r)
  constructor
  · exact hr
  · have hj := r.isLt
    omega

theorem hensel_actual_recurrence
    (f : Polynomial (Polynomial R)) (p : Polynomial R) (n : ℕ)
    (hn : 0 < n) (hp : p.coeff 0 = 0) (hd : (f.coeff 1).coeff 0 ≠ 0)
    (hroot : (f.eval p).coeff n = 0) :
    (f.coeff 1).coeff 0 * p.coeff n =
      -(∑ t ∈ henselRecurrenceIndices f n,
        henselIndexCoefficient f t * ((henselIndexList t).map p.coeff).prod) := by
  classical
  have he : (f.eval p).coeff n =
      ∑ t ∈ henselAllIndices f n,
        henselIndexCoefficient f t * ((henselIndexList t).map p.coeff).prod := by
    rw [Polynomial.eval_eq_sum]
    simp only [Polynomial.sum, Polynomial.finsetSum_coeff, Polynomial.coeff_mul]
    simp_rw [coeff_pow_positive_compositions p hp]
    simp only [henselAllIndices, Finset.sum_sigma, henselIndexCoefficient,
      henselIndexOrder, henselIndexList, List.map_ofFn, List.prod_ofFn,
      Finset.mul_sum, Function.comp_def]
  have hsplit := Finset.add_sum_erase (henselAllIndices f n)
    (fun t => henselIndexCoefficient f t * ((henselIndexList t).map p.coeff).prod)
    (hensel_derivative_member f n hn hd)
  have hvalue : henselIndexCoefficient f (henselDerivativeIndex n) *
      ((henselIndexList (henselDerivativeIndex n)).map p.coeff).prod =
      (f.coeff 1).coeff 0 * p.coeff n := by
    simp [henselIndexCoefficient, henselIndexOrder, henselIndexList, henselDerivativeIndex]
  rw [hvalue, ← he, hroot] at hsplit
  change (f.coeff 1).coeff 0 * p.coeff n +
    (∑ t ∈ henselRecurrenceIndices f n,
      henselIndexCoefficient f t * ((henselIndexList t).map p.coeff).prod) = 0 at hsplit
  exact eq_neg_of_add_eq_zero_left hsplit

end HegemonCrypto.SmallWood.Mca38Published

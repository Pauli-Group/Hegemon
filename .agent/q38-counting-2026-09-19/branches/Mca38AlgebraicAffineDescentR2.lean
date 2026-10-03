import Mathlib.LinearAlgebra.Lagrange
import Mathlib.Tactic.NormNum

/-! Affine descent from actual identical source-line incidences.
The extension field may be an algebraic root field, but no blanket descent of
its polynomial branches is assumed. More than d identical incidences force
descent by interpolation; otherwise the identical incidence count is at most d.
-/
namespace HegemonCrypto.SmallWood.Mca38Published
noncomputable section
open scoped Classical
set_option autoImplicit false

variable {K E I : Type*} [Field K] [Field E]

theorem affine_descent_of_identical_incidences
    (f : K →+* E) (z : E) (A : Polynomial E) (d : ℕ)
    (hA : A.natDegree ≤ d) (point U V : I → K)
    (S : Finset I) (hinj : Set.InjOn point (S : Set I))
    (hcard : d < S.card)
    (hmatch : ∀ a ∈ S, A.eval (f (point a)) = f (U a) + z * f (V a)) :
    ∃ u v : Polynomial K, u.natDegree ≤ d ∧ v.natDegree ≤ d ∧
      A = u.map f + Polynomial.C z * v.map f := by
  classical
  obtain ⟨T, hTS, hTcard⟩ := Finset.exists_subset_card_eq (Nat.succ_le_of_lt hcard)
  have hTinj : Set.InjOn point (T : Set I) :=
    fun _ ha _ hb h => hinj (hTS ha) (hTS hb) h
  let u : Polynomial K := Lagrange.interpolate T point U
  let v : Polynomial K := Lagrange.interpolate T point V
  have hu : u.natDegree ≤ d := by
    have h := Polynomial.natDegree_le_of_degree_le
      (Lagrange.degree_interpolate_le U hTinj)
    simpa [u, hTcard] using h
  have hv : v.natDegree ≤ d := by
    have h := Polynomial.natDegree_le_of_degree_le
      (Lagrange.degree_interpolate_le V hTinj)
    simpa [v, hTcard] using h
  let B : Polynomial E := u.map f + Polynomial.C z * v.map f
  have hB : B.natDegree ≤ d := by
    apply (Polynomial.natDegree_add_le (u.map f) (Polynomial.C z * v.map f)).trans
    apply max_le
    · exact Polynomial.natDegree_map_le.trans hu
    · exact (Polynomial.natDegree_C_mul_le z (v.map f)).trans
        (Polynomial.natDegree_map_le.trans hv)
  have hdiff : (A - B).natDegree ≤ d :=
    (Polynomial.natDegree_sub_le A B).trans (max_le hA hB)
  have hzero : A - B = 0 := by
    apply Polynomial.eq_zero_of_natDegree_lt_card_of_eval_eq_zero
      (A - B) (f := fun a : T => f (point a.val))
    · intro a b heq
      apply Subtype.ext
      exact hTinj a.property b.property (f.injective heq)
    · intro a
      have hua : u.eval (point a.val) = U a.val :=
        Lagrange.eval_interpolate_at_node U hTinj a.property
      have hva : v.eval (point a.val) = V a.val :=
        Lagrange.eval_interpolate_at_node V hTinj a.property
      simp only [Polynomial.eval_sub, B, Polynomial.eval_add, Polynomial.eval_mul,
        Polynomial.eval_C, Polynomial.eval_map_apply, hua, hva,
        hmatch a.val (hTS a.property), sub_self]
    · rw [Fintype.card_coe, hTcard]
      exact Nat.lt_succ_of_le hdiff
  exact ⟨u, v, hu, hv, sub_eq_zero.mp hzero⟩

/-- This dichotomy applies before any specialization in the challenge label:
an algebraic branch either descends to an actual affine polynomial pair, or
there are at most d positions where the entire source line lies on it. -/
theorem algebraic_branch_affine_or_few_identical_incidences
    (f : K →+* E) (z : E) (A : Polynomial E) (d : ℕ)
    (hA : A.natDegree ≤ d) (point U V : I → K)
    (positions : Finset I) (hinj : Set.InjOn point (positions : Set I)) :
    (∃ u v : Polynomial K, u.natDegree ≤ d ∧ v.natDegree ≤ d ∧
      A = u.map f + Polynomial.C z * v.map f) ∨
    (positions.filter (fun a =>
      A.eval (f (point a)) = f (U a) + z * f (V a))).card ≤ d := by
  classical
  let S := positions.filter (fun a =>
    A.eval (f (point a)) = f (U a) + z * f (V a))
  by_cases h : S.card ≤ d
  · exact Or.inr h
  · apply Or.inl
    exact affine_descent_of_identical_incidences f z A d hA point U V S
      (fun _ ha _ hb heq => hinj (Finset.mem_filter.mp ha).1
        (Finset.mem_filter.mp hb).1 heq)
      (Nat.lt_of_not_ge h)
      (fun a ha => (Finset.mem_filter.mp ha).2)

end
end HegemonCrypto.SmallWood.Mca38Published

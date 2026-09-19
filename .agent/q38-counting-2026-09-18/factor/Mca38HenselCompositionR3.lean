import Mathlib.Algebra.Polynomial.BigOperators
import Mathlib.Algebra.Polynomial.Eval.Defs
import Mathlib.Data.Fin.Tuple.NatAntidiagonal
import Mathlib.Algebra.BigOperators.Ring.List

/-! Exact finite composition enumeration for an actual polynomial residual.
No coefficient-expansion identity is assumed. -/

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false

variable {R : Type*} [CommRing R]

theorem coeff_pow_compositions (p : Polynomial R) (j n : ℕ) :
    (p ^ j).coeff n =
      ∑ v ∈ Finset.Nat.antidiagonalTuple j n, ∏ r, p.coeff (v r) := by
  induction j generalizing n with
  | zero =>
      cases n <;> simp [Polynomial.coeff_one]
  | succ j ih =>
      rw [pow_succ', Polynomial.coeff_mul]
      simp_rw [ih]
      change
        ((List.Nat.antidiagonal n).map (fun uv => p.coeff uv.1 *
          ((List.Nat.antidiagonalTuple j uv.2).map
            (fun v => ∏ r, p.coeff (v r))).sum)).sum =
        ((List.Nat.antidiagonalTuple (j + 1) n).map
          (fun v => ∏ r, p.coeff (v r))).sum
      simp only [List.Nat.antidiagonalTuple, List.flatMap_def, List.map_flatten, List.sum_flatten,
        List.map_map, Function.comp_def, Fin.prod_univ_succ, Fin.cons_zero,
        Fin.cons_succ, List.sum_map_mul_left]

/-- The coefficient of a genuine bivariate polynomial evaluation, expanded
over its Y support, X convolution pairs, and finite power compositions. -/
theorem hensel_residual_compositions
    (f : Polynomial (Polynomial R)) (p : Polynomial R) (n : ℕ) :
    (f.eval p).coeff n =
      ∑ j ∈ f.support, ∑ uv ∈ Finset.antidiagonal n,
        (f.coeff j).coeff uv.1 *
          (∑ v ∈ Finset.Nat.antidiagonalTuple j uv.2, ∏ r, p.coeff (v r)) := by
  rw [Polynomial.eval_eq_sum]
  simp only [Polynomial.sum, Polynomial.finsetSum_coeff, Polynomial.coeff_mul]
  simp_rw [coeff_pow_compositions]

/-- If the root series has zero constant term, only positive compositions
contribute. This isolates the condition needed by the linear height bound. -/
theorem coeff_pow_positive_compositions
    (p : Polynomial R) (hp : p.coeff 0 = 0) (j n : ℕ) :
    (p ^ j).coeff n =
      ∑ v ∈ (Finset.Nat.antidiagonalTuple j n).filter (fun v => ∀ r, 0 < v r),
        ∏ r, p.coeff (v r) := by
  classical
  rw [coeff_pow_compositions]
  apply Eq.symm
  apply Finset.sum_subset (Finset.filter_subset _ _)
  intro v hv hnot
  have hbad : ¬ ∀ r, 0 < v r := by
    intro h
    exact hnot (Finset.mem_filter.mpr ⟨hv, h⟩)
  obtain ⟨r, hr⟩ := Classical.not_forall.mp hbad
  apply Finset.prod_eq_zero (Finset.mem_univ r)
  have hz : v r = 0 := Nat.eq_zero_of_le_zero (Nat.le_of_not_gt hr)
  rw [hz, hp]

end HegemonCrypto.SmallWood.Mca38Published

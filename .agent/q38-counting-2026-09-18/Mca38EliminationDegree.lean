import Mathlib.Algebra.Polynomial.BigOperators
import Mathlib.Algebra.Polynomial.Roots
import Mathlib.LinearAlgebra.Matrix.Determinant.Basic

/-! Quantitative elimination support. The determinant is an actual polynomial,
not an assumed exceptional-label bound. A later resultant construction must
establish its nonvanishing and show which labels make it vanish. -/
namespace HegemonCrypto.SmallWood.Mca38Published
open scoped BigOperators
noncomputable section
set_option autoImplicit false

theorem elimination_determinant_natDegree {K I : Type*}
    [CommRing K] [Fintype I] [DecidableEq I]
    (A : Matrix I I (Polynomial K)) (height : I → ℕ)
    (hheight : ∀ i j, (A i j).natDegree ≤ height j) :
    A.det.natDegree ≤ ∑ j, height j := by
  rw [Matrix.det_apply]
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro σ _
  have hs : (Equiv.Perm.sign σ • ∏ i, A (σ i) i).natDegree =
      (∏ i, A (σ i) i).natDegree := by
    rcases Int.units_eq_one_or (Equiv.Perm.sign σ) with h | h
    · rw [h, one_smul]
    · rw [h, Units.neg_smul, one_smul, Polynomial.natDegree_neg]
  rw [hs]
  exact (Polynomial.natDegree_prod_le _ _).trans
    (Finset.sum_le_sum (fun j _ => hheight (σ j) j))

theorem elimination_determinant_two_blocks {K : Type*} [CommRing K]
    (m n df dg : ℕ)
    (A : Matrix (Fin m ⊕ Fin n) (Fin m ⊕ Fin n) (Polynomial K))
    (hf : ∀ i j, (A i (Sum.inl j)).natDegree ≤ df)
    (hg : ∀ i j, (A i (Sum.inr j)).natDegree ≤ dg) :
    A.det.natDegree ≤ m * df + n * dg := by
  have bound := elimination_determinant_natDegree A
    (Sum.elim (fun _ => df) (fun _ => dg)) (by
      intro i j
      cases j with
      | inl j => exact hf i j
      | inr j => exact hg i j)
  simpa using bound

theorem elimination_exception_card {K I : Type*}
    [Field K] [Fintype I] [DecidableEq I]
    (A : Matrix I I (Polynomial K)) (height : I → ℕ)
    (hheight : ∀ i j, (A i j).natDegree ≤ height j)
    (hne : A.det ≠ 0) (labels : Finset K)
    (hexception : ∀ z ∈ labels, A.det.eval z = 0) :
    labels.card ≤ ∑ j, height j := by
  have roots : labels.card ≤ A.det.natDegree := by
    apply Polynomial.card_le_degree_of_subset_roots
    intro z hz
    exact (Polynomial.mem_roots hne).mpr (hexception z hz)
  exact roots.trans (elimination_determinant_natDegree A height hheight)

end
end HegemonCrypto.SmallWood.Mca38Published

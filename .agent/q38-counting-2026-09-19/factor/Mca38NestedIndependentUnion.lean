import Mca38NestedInterpolationHeights

/-! The complete Y-independent branch of the actual factor partition.

Every label admitting any response through a Y-independent normalized factor
is charged to that factor's actual Z degree. Repeated factors do not introduce
an unproved disjointness premise: a union bound is applied to the multiset.
The exact additive Z ledger bounds the entire branch by 10,000 labels.
-/
namespace HegemonCrypto.SmallWood.Mca38NestedIndependentUnion
open HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
open HegemonCrypto.SmallWood.Mca38NestedInterpolationHeights
open HegemonCrypto.SmallWood.Mca38RoundByRound
open HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation
open scoped Classical
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

def factorLabels (H : Tri (K := K)) (labels : Finset K) : Finset K :=
  labels.filter fun z => H.natDegree = 0 ∧ ∃ P : Polynomial K, specializePoly z P H = 0

def independentLabels (fs : Multiset (Tri (K := K))) (labels : Finset K) : Finset K :=
  labels.filter fun z => ∃ H ∈ fs, H.natDegree = 0 ∧
    ∃ P : Polynomial K, specializePoly z P H = 0

theorem factorLabels_card_le (H : Tri (K := K)) (nonzero : H ≠ 0)
    (labels : Finset K) : (factorLabels H labels).card ≤ (zView H).natDegree := by
  by_cases independent : H.natDegree = 0
  · apply HegemonCrypto.SmallWood.Mca38NestedContentExceptions.yIndependent_label_count
      H nonzero independent
    intro z member
    obtain ⟨P, root⟩ := (Finset.mem_filter.mp member).2.2
    exact ⟨P, root⟩
  · simp [factorLabels, independent]

theorem independentLabels_cons (H : Tri (K := K)) (fs : Multiset (Tri (K := K)))
    (labels : Finset K) : independentLabels (H ::ₘ fs) labels =
      factorLabels H labels ∪ independentLabels fs labels := by
  ext z
  simp only [independentLabels, factorLabels, Finset.mem_filter,
    Finset.mem_union, Multiset.mem_cons]
  aesop

theorem independentLabels_card_le (fs : Multiset (Tri (K := K)))
    (nonzero : ∀ H ∈ fs, H ≠ 0) (labels : Finset K) :
    (independentLabels fs labels).card ≤
      (fs.map (fun H => (zView H).natDegree)).sum := by
  induction fs using Multiset.induction_on with
  | empty => simp [independentLabels]
  | @cons H fs ih =>
    rw [independentLabels_cons, Multiset.map_cons, Multiset.sum_cons]
    exact (Finset.card_union_le _ _).trans (Nat.add_le_add
      (factorLabels_card_le H (nonzero H (Multiset.mem_cons_self H fs)) labels)
      (ih (fun G member => nonzero G (Multiset.mem_cons_of_mem member))))

theorem actual_independent_labels_card_le (F : Tri (K := K)) (hF : F ≠ 0)
    (labels : Finset K) :
    (independentLabels (factors F) labels).card ≤ (zView F).natDegree := by
  have count := independentLabels_card_le (factors F)
    (fun _ member => factors_nonzero member) labels
  rwa [(degree_ledger F hF).2.2] at count

theorem rbr_independent_labels_card_le (c : CoefficientIndex → K) (hc : c ≠ 0)
    (labels : Finset K) :
    (independentLabels (factors (trivariateNested c)) labels).card ≤ 10000 := by
  exact (actual_independent_labels_card_le (trivariateNested c)
    (trivariateNested_ne_zero c hc) labels).trans
      (actual_nested_interpolant_heights c).2.2

/-- Actual factor coverage after removing the counted independent branch.
The response and its support may be chosen separately for every label. -/
theorem positive_factor_outside_independent_labels (F : Tri (K := K))
    (hF : F ≠ 0) (labels : Finset K) (z : K) (member : z ∈ labels)
    (outside : z ∉ independentLabels (factors F) labels)
    (P : Polynomial K) (root : specializePoly z P F = 0) :
    ∃ H ∈ factors F, 0 < H.natDegree ∧ specializePoly z P H = 0 := by
  obtain ⟨H, factor, zero⟩ := specialization_factor_coverage F hF z P root
  refine ⟨H, factor, ?_, zero⟩
  apply Nat.pos_of_ne_zero
  intro independent
  apply outside
  exact Finset.mem_filter.mpr ⟨member, H, factor, independent, P, zero⟩

end
end HegemonCrypto.SmallWood.Mca38NestedIndependentUnion

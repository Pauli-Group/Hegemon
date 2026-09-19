import Mathlib.Algebra.Polynomial.Roots
import Mathlib.Data.Finset.Card

/-! Double-count the actual label/position incidences. Supports may depend
arbitrarily on the label. Only nonidentical positions need obstruction
polynomials; their nonvanishing and specialization roots are the algebraic
facts supplied by the finite-Hensel numerator construction. -/
namespace HegemonCrypto.SmallWood.Mca38NonidenticalIncidenceCount
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false

variable {K I : Type*} [Field K] [DecidableEq I]

theorem label_position_double_count
    (labels : Finset K) (positions identical : Finset I)
    (support : K → Finset I) (threshold degree : Nat)
    (supportSubset : ∀ z ∈ labels, support z ⊆ positions)
    (supportLarge : ∀ z ∈ labels, threshold ≤ (support z).card)
    (fewIdentical : identical.card ≤ degree)
    (obstruction : I → Polynomial K)
    (nonzero : ∀ a ∈ positions \ identical, obstruction a ≠ 0)
    (root : ∀ z ∈ labels, ∀ a ∈ support z, a ∉ identical →
      (obstruction a).eval z = 0) :
    labels.card * (threshold-degree) ≤
      ∑ a ∈ positions \ identical, (obstruction a).natDegree := by
  have rowLower : ∀ z ∈ labels,
      threshold-degree ≤ ((positions \ identical).filter (fun a => a ∈ support z)).card := by
    intro z hz
    have same : (positions \ identical).filter (fun a => a ∈ support z) =
        support z \ identical := by
      ext a
      simp only [Finset.mem_filter, Finset.mem_sdiff]
      constructor
      · rintro ⟨⟨_, outside⟩, inside⟩
        exact ⟨inside, outside⟩
      · rintro ⟨inside, outside⟩
        exact ⟨⟨supportSubset z hz inside, outside⟩, inside⟩
    rw [same]
    have split := Finset.card_sdiff_add_card_inter (support z) identical
    have intersection := Finset.card_le_card
      (Finset.inter_subset_right : support z ∩ identical ⊆ identical)
    have large := supportLarge z hz
    omega
  have columnUpper : ∀ a ∈ positions \ identical,
      (labels.filter (fun z => a ∈ support z)).card ≤ (obstruction a).natDegree := by
    intro a ha
    apply Polynomial.card_le_degree_of_subset_roots
    intro z hz
    obtain ⟨inLabels, inSupport⟩ := Finset.mem_filter.mp hz
    exact (Polynomial.mem_roots (nonzero a ha)).mpr
      (root z inLabels a inSupport (Finset.mem_sdiff.mp ha).2)
  have transpose :
      (∑ z ∈ labels, ((positions \ identical).filter (fun a => a ∈ support z)).card) =
        ∑ a ∈ positions \ identical, (labels.filter (fun z => a ∈ support z)).card := by
    simp only [Finset.card_eq_sum_ones, Finset.sum_filter]
    exact Finset.sum_comm
  calc
    labels.card * (threshold-degree) = ∑ _z ∈ labels, (threshold-degree) := by simp
    _ ≤ ∑ z ∈ labels, ((positions \ identical).filter (fun a => a ∈ support z)).card :=
      Finset.sum_le_sum rowLower
    _ = ∑ a ∈ positions \ identical, (labels.filter (fun z => a ∈ support z)).card := transpose
    _ ≤ _ := Finset.sum_le_sum columnUpper

end
end HegemonCrypto.SmallWood.Mca38NonidenticalIncidenceCount

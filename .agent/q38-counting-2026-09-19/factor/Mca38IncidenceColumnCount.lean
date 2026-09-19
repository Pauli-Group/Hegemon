import Mathlib.Algebra.Polynomial.Roots
import Mathlib.Data.Finset.Card

/-! Incidence double counting with independently supplied per-column bounds.
The column bounds are deliberately conclusions of the caller's obstruction
construction, not an assumed global label-count bound. -/
namespace HegemonCrypto.SmallWood.Mca38IncidenceColumnCount
open scoped BigOperators
open Classical
noncomputable section
set_option autoImplicit false

variable {K I : Type*} [DecidableEq I]

theorem label_position_column_bound
    (labels : Finset K) (positions identical : Finset I)
    (support : K → Finset I) (threshold degree : Nat)
    (supportSubset : ∀ z ∈ labels, support z ⊆ positions)
    (supportLarge : ∀ z ∈ labels, threshold ≤ (support z).card)
    (fewIdentical : identical.card ≤ degree)
    (columnBound : I → Nat)
    (columnUpper : ∀ a ∈ positions \ identical,
      (labels.filter (fun z => a ∈ support z)).card ≤ columnBound a) :
    labels.card * (threshold - degree) ≤
      ∑ a ∈ positions \ identical, columnBound a := by
  have rowLower : ∀ z ∈ labels,
      threshold - degree ≤ ((positions \ identical).filter (fun a => a ∈ support z)).card := by
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
    apply Nat.sub_le_iff_le_add'.2
    have split := Finset.card_sdiff_add_card_inter (support z) identical
    have intersection := Finset.card_le_card
      (Finset.inter_subset_right : support z ∩ identical ⊆ identical)
    calc
      threshold ≤ (support z).card := supportLarge z hz
      _ = (support z \ identical).card + (support z ∩ identical).card := split.symm
      _ ≤ (support z \ identical).card + degree :=
        Nat.add_le_add_left (intersection.trans fewIdentical) _
      _ = degree + (support z \ identical).card := Nat.add_comm _ _
  have transpose :
      (∑ z ∈ labels, ((positions \ identical).filter (fun a => a ∈ support z)).card) =
        ∑ a ∈ positions \ identical, (labels.filter (fun z => a ∈ support z)).card := by
    simp only [Finset.card_eq_sum_ones, Finset.sum_filter]
    exact Finset.sum_comm
  calc
    labels.card * (threshold - degree) = ∑ _z ∈ labels, (threshold - degree) := by simp
    _ ≤ ∑ z ∈ labels, ((positions \ identical).filter (fun a => a ∈ support z)).card :=
      Finset.sum_le_sum rowLower
    _ = ∑ a ∈ positions \ identical, (labels.filter (fun z => a ∈ support z)).card := transpose
    _ ≤ _ := Finset.sum_le_sum columnUpper

theorem label_position_uniform_column_bound
    (labels : Finset K) (positions identical : Finset I)
    (support : K → Finset I) (threshold degree B : Nat)
    (supportSubset : ∀ z ∈ labels, support z ⊆ positions)
    (supportLarge : ∀ z ∈ labels, threshold ≤ (support z).card)
    (fewIdentical : identical.card ≤ degree)
    (columnUpper : ∀ a ∈ positions \ identical,
      (labels.filter (fun z => a ∈ support z)).card ≤ B) :
    labels.card * (threshold - degree) ≤ positions.card * B := by
  calc
    labels.card * (threshold - degree) ≤
        ∑ a ∈ positions \ identical, B := label_position_column_bound
          labels positions identical support threshold degree supportSubset
          supportLarge fewIdentical (fun _ => B) columnUpper
    _ ≤ positions.card * B := by
      simpa using Nat.mul_le_mul_right B
        (Finset.card_le_card (Finset.sdiff_subset : positions \ identical ⊆ positions))

end
end HegemonCrypto.SmallWood.Mca38IncidenceColumnCount

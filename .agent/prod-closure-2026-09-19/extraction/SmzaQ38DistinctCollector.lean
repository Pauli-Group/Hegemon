import Mathlib.Data.List.Dedup
import Mathlib.Data.List.TakeDrop
import Lean.Elab.Tactic.Omega

/-! Generic early-stopping first-distinct collector identity. No protocol
or field definitions are duplicated in this import-light proof. -/
namespace HegemonCrypto.SmallWood.SmzaQ38DistinctCollector
set_option autoImplicit false
set_option Elab.async false

def collectDistinct {α : Type*} [DecidableEq α]
    (cap : Nat) : List α → List α → List α
  | [], selected => selected
  | candidate :: rest, selected =>
      if selected.length = cap then selected else
      if candidate ∈ selected then collectDistinct cap rest selected
      else collectDistinct cap rest (selected.concat candidate)

theorem collectDistinct_full {α : Type*} [DecidableEq α]
    (cap : Nat) (candidates selected : List α)
    (full : selected.length = cap) :
    collectDistinct cap candidates selected = selected := by
  cases candidates <;> simp [collectDistinct, full]

theorem append_union {α : Type*} [DecidableEq α]
    (left right selected : List α) :
    (left ++ right) ∪ selected = left ∪ (right ∪ selected) := by
  induction left with
  | nil => rfl
  | cons candidate rest ih => simp only [List.cons_append, List.cons_union, ih]

/-- Reversal turns the insertion-order seen list into the suffix preserved
by List.union. This invariant proves early stopping, not just set equality. -/
theorem collectDistinct_eq {α : Type*} [DecidableEq α]
    (cap : Nat) (candidates selected : List α)
    (bounded : selected.length ≤ cap) :
    collectDistinct cap candidates selected =
      (candidates.reverse ∪ selected.reverse).reverse.take cap := by
  induction candidates generalizing selected with
  | nil => simpa [collectDistinct] using (List.take_of_length_le bounded).symm
  | cons candidate rest ih =>
      by_cases full : selected.length = cap
      · rw [collectDistinct, if_pos full]
        obtain ⟨initial, _, equation⟩ :=
          List.sublist_suffix_of_union (candidate :: rest).reverse selected.reverse
        rw [← equation, List.reverse_append, List.reverse_reverse]
        exact (List.take_left' full).symm
      · by_cases member : candidate ∈ selected
        · rw [collectDistinct, if_neg full, if_pos member, ih selected bounded]
          simp only [List.reverse_cons, append_union, List.cons_union,
            List.nil_union, List.insert_of_mem (List.mem_reverse.mpr member)]
        · have nextBound : (selected.concat candidate).length ≤ cap := by
            simp only [List.length_concat]
            omega
          rw [collectDistinct, if_neg full, if_neg member,
            ih (selected.concat candidate) nextBound]
          have outside : candidate ∉ selected.reverse := by simpa using member
          rw [List.concat_eq_append, List.reverse_concat]
          simp only [List.reverse_cons, append_union, List.cons_union,
            List.nil_union, List.insert_of_not_mem outside]

theorem collectDistinct_empty {α : Type*} [DecidableEq α]
    (cap : Nat) (candidates : List α) :
    collectDistinct cap candidates [] = candidates.reverse.dedup.reverse.take cap := by
  rw [collectDistinct_eq cap candidates [] (by simp)]
  have unionEq : candidates.reverse ∪ [] = candidates.reverse.dedup := by
    simpa using (List.dedup_append candidates.reverse []).symm
  simp only [List.reverse_nil, unionEq]

end HegemonCrypto.SmallWood.SmzaQ38DistinctCollector

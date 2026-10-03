import SmzaRp05CurrentFiniteLedgerHistory
import SmzaRp05HistoricalTree

/-! # Exact fresh positions for appended output-opening streams

This small bridge identifies a block's output openings at their global
append positions in a complete finite log.  It is independent of the source
record/proof construction: callers supply the actual chronological opening
lists and suffix, not a value-realization equation.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOutputLedgerPositions

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05KnownEmptySupply (knownEmptyOpening)
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree (openingAt)
open SmzaFiniteLedgerSupply (nativeValue)

set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

/-- The global ledger positions occupied by an appended opening list. -/
def appendedOutputIds (prior added : List V8NoteOpening) : Finset Nat :=
  (Finset.range added.length).image (fun index => prior.length + index)

/-- At the offset of its local index, an appended opening is the actual
opening stored in the complete `prior ++ added ++ suffix` history. -/
theorem opening_at_appended_offset
    (prior added suffix : List V8NoteOpening) {index : Nat}
    (indexBound : index < added.length) :
    openingAt (prior ++ added ++ suffix) (prior.length + index) =
      added.getD index knownEmptyOpening := by
  have registryEq : prior ++ added ++ suffix = prior ++ (added ++ suffix) := by
    simp only [List.append_assoc]
  rw [registryEq]
  have positionBound : prior.length + index < (prior ++ (added ++ suffix)).length := by
    simp only [List.length_append]
    omega
  simp only [openingAt, if_pos positionBound]
  rw [List.getD_append_right _ _ _ _ (by omega)]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ indexBound]

/-- The appended position set cannot overlap positions already present in
the prefix. -/
theorem appended_ids_disjoint_prefix
    (prior added : List V8NoteOpening) (ids : Finset Nat)
    (idsInPrefix : ∀ id ∈ ids, id < prior.length) :
    Disjoint (appendedOutputIds prior added) ids := by
  rw [Finset.disjoint_left]
  intro id idAppended idPrefix
  rcases Finset.mem_image.mp idAppended with ⟨index, indexRange, positionEq⟩
  have indexBound : index < added.length := Finset.mem_range.mp indexRange
  have prefixBound := idsInPrefix id idPrefix
  omega

private theorem sum_native_getD (added : List V8NoteOpening) :
    (∑ index ∈ Finset.range added.length,
      nativeValue (added.getD index knownEmptyOpening)) =
      (added.map nativeValue).sum := by
  induction added with
  | nil => simp
  | cons head tail ih =>
      simp only [List.length_cons]
      rw [Finset.sum_range_succ']
      simp only [List.getD_cons_zero, List.getD_cons_succ,
        List.map_cons, List.sum_cons]
      calc
        (∑ index ∈ Finset.range tail.length,
            nativeValue (tail.getD index knownEmptyOpening)) + nativeValue head =
            (List.map nativeValue tail).sum + nativeValue head :=
              congrArg (fun value => value + nativeValue head) ih
        _ = nativeValue head + (List.map nativeValue tail).sum := Nat.add_comm _ _

/-- Summing native values over the new global positions is exactly summing
the values in the appended opening stream. No output-value equality is
assumed here; the current typed output-stream theorem can be applied to the
right-hand list sum by the source-record caller. -/
theorem appended_output_native_sum
    (prior added suffix : List V8NoteOpening) :
    (∑ id ∈ appendedOutputIds prior added,
      nativeValue (openingAt (prior ++ added ++ suffix) id)) =
      (added.map nativeValue).sum := by
  unfold appendedOutputIds
  rw [Finset.sum_image]
  · have indexed :
        (∑ index ∈ Finset.range added.length,
          nativeValue (openingAt (prior ++ added ++ suffix)
            (prior.length + index))) =
          (∑ index ∈ Finset.range added.length,
            nativeValue (added.getD index knownEmptyOpening)) := by
      apply Finset.sum_congr rfl
      intro index indexBound
      rw [opening_at_appended_offset prior added suffix (Finset.mem_range.mp indexBound)]
    rw [indexed]
    exact sum_native_getD added
  · intro left leftBound right rightBound samePosition
    have offsetEq : prior.length + left = prior.length + right := samePosition
    exact Nat.add_left_cancel offsetEq

end HegemonCrypto.SmallWood.SmzaRp05CurrentOutputLedgerPositions

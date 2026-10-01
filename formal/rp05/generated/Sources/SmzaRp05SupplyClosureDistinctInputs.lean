import SmzaRp05SupplyClosureAcceptedMerkle
import SmzaRp05AuthorizationClosureSameNote
import SmzaRp05SupplyClosureAvailability

/-! The native duplicate-nullifier guard prevents two active slots of the
same accepted transaction from consuming the same authenticated note at the
same position.  The raw value and rho equalities are derived from note words.
The final finite-sum lemma counts distinct positive inputs exactly once. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameSource
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open scoped BigOperators Classical

set_option autoImplicit false

theorem accepted_input_value_source
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (input : Fin 2) :
    spongeSourceWord packed (noteCall input) 0 =
      packed.getD (34 * input.val * 64) 0 := by
  have equation := accepted_cell_field SmzaRp05NoteFrameInstance.certificate
    accepted (input, 0, 0) (by simp [boundCell])
  have fieldEquality :
      (spongeSourceWord packed (noteCall input) 0 : Goldilocks) =
        (packed.getD (34 * input.val * 64) 0 : Goldilocks) := by
    simpa [sourceIndex, expectedConstant, noteConstant, spongeSourceWord,
      packedWord, Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      sub_eq_zero] using equation
  exact canonical_nat_cast_injective
    (sponge_source_word_canonical accepted.2.1 _ _)
    (packed_word_canonical accepted.2.1 _) fieldEquality

theorem equal_note_words_source_word {packed : List Nat}
    (same : exactV8NoteWords (projectNote packed 1) =
      exactV8NoteWords (projectNote packed 38))
    (word : Nat) (bound : word < 18) :
    spongeSourceWord packed 1 word = spongeSourceWord packed 38 word := by
  have equality := congrArg (fun words : List Nat => words.getD word 0) same
  change (((List.range 18).map (spongeSourceWord packed 1)).getD word 0) =
    (((List.range 18).map (spongeSourceWord packed 38)).getD word 0) at equality
  simpa [List.getD_eq_getElem?_getD, bound] using equality

def publicNullifier (publicWords : List Nat) (input : Fin 2) : Digest :=
  (List.range 7).map (fun limb => publicWords.getD (4 + input.val * 7 + limb) 0)

theorem accepted_same_note_position_public_nullifiers
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (leftActive : publicWords.getD 0 0 = 1)
    (rightActive : publicWords.getD 1 0 = 1)
    (sameNote : exactV8NoteWords (projectNote packed 1) =
      exactV8NoteWords (projectNote packed 38))
    (samePosition : projectPosition packed 0 = projectPosition packed 1) :
    publicNullifier publicWords 0 = publicNullifier publicWords 1 := by
  have sameValue : packed.getD 0 0 = packed.getD (34 * 64) 0 := by
    have left := accepted_input_value_source accepted 0
    have right := accepted_input_value_source accepted 1
    have same := equal_note_words_source_word sameNote 0 (by decide)
    simpa [noteCall] using left.symm.trans (same.trans right)
  have samePreimage :=
    SmzaRp05AuthorizationClosureSameNote.accepted_same_note_position_nullifier_preimages_equal
      accepted rightActive sameValue
      (fun limb => equal_note_words_source_word sameNote (6 + limb.val) (by omega))
      samePosition
  apply List.map_congr_left
  intro limb member
  have bound : limb < 7 := List.mem_range.mp member
  have left := SmzaRp05CurrentNullifierCertificates.accepted_current_active_public_nullifier
    accepted (0 : Fin 2) leftActive ⟨limb, bound⟩
  have right := SmzaRp05CurrentNullifierCertificates.accepted_current_active_public_nullifier
    accepted (1 : Fin 2) rightActive ⟨limb, bound⟩
  rw [samePreimage] at left
  exact left.trans right.symm

theorem native_duplicate_guard_distinct_positions
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (leftActive : publicWords.getD 0 0 = 1)
    (rightActive : publicWords.getD 1 0 = 1)
    (guard : publicNullifier publicWords 0 ≠ publicNullifier publicWords 1)
    (samePositionNotes : projectPosition packed 0 = projectPosition packed 1 →
      exactV8NoteWords (projectNote packed 1) =
        exactV8NoteWords (projectNote packed 38)) :
    projectPosition packed 0 ≠ projectPosition packed 1 := by
  intro samePosition
  exact guard (accepted_same_note_position_public_nullifiers accepted
    leftActive rightActive (samePositionNotes samePosition) samePosition)

/-- Aggregate the two input slots, allowing zero-value empty inputs to
coincide. Only positive slots consume the finite live registry. -/
theorem two_input_available
    (live : Finset Nat) (value : Nat → Nat)
    (leftPosition rightPosition leftValue rightValue : Nat)
    (leftAvailable : leftValue > 0 →
      leftPosition ∈ live ∧ leftValue ≤ value leftPosition)
    (rightAvailable : rightValue > 0 →
      rightPosition ∈ live ∧ rightValue ≤ value rightPosition)
    (distinct : leftValue > 0 → rightValue > 0 → leftPosition ≠ rightPosition) :
    leftValue + rightValue ≤ ∑ position ∈ live, value position := by
  classical
  by_cases leftPositive : leftValue > 0
  · obtain ⟨leftMember, leftBound⟩ := leftAvailable leftPositive
    by_cases rightPositive : rightValue > 0
    · obtain ⟨rightMember, rightBound⟩ := rightAvailable rightPositive
      have different := distinct leftPositive rightPositive
      have subset : ({leftPosition, rightPosition} : Finset Nat) ⊆ live := by
        intro position member
        simp only [Finset.mem_insert, Finset.mem_singleton] at member
        rcases member with rfl | rfl <;> assumption
      calc
        leftValue + rightValue ≤ value leftPosition + value rightPosition :=
          Nat.add_le_add leftBound rightBound
        _ = ∑ position ∈ ({leftPosition, rightPosition} : Finset Nat),
            value position := by simp [different]
        _ ≤ ∑ position ∈ live, value position :=
          Finset.sum_le_sum_of_subset_of_nonneg subset (by intros; exact Nat.zero_le _)
    · have zero : rightValue = 0 := by omega
      simpa [zero] using leftBound.trans
        (Finset.single_le_sum (fun position member => Nat.zero_le (value position)) leftMember)
  · have zero : leftValue = 0 := by omega
    by_cases rightPositive : rightValue > 0
    · obtain ⟨rightMember, rightBound⟩ := rightAvailable rightPositive
      simpa [zero] using rightBound.trans
        (Finset.single_le_sum (fun position member => Nat.zero_le (value position)) rightMember)
    · have zeroRight : rightValue = 0 := by omega
      simp [zero, zeroRight]

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs

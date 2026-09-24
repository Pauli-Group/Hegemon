import HegemonCrypto.SmallWoodV8Smz9SourceTypedPrefix
import HegemonCrypto.SmallWoodV8Smz9InputMerkleSources

/-! Forward construction of the actual Merkle current/direction CSR copies.
No packed acceptance, equal-lane evidence, or copy-equality premise is used.
The generic constructor reuses the SAME live-state input at every readback;
the typed endpoint then internally selects the existing typed schedule.
This covers only families 15 and 16, not full packed acceptance or Rust refinement. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

/-- Canonical global metadata identifies the actual list index, not just membership. -/
theorem exact_attempt_lookup (entry : CsrExecutableAttempt) (member : entry ∈ exactCsrAttempts) :
    exactCsrAttempts[entry.globalIndex]? = some entry := by
  obtain ⟨index, found⟩ := List.getElem?_of_mem member
  have canonical := checkCsr_sound _ _ _ hgv8rp03_csr_check_passes index entry found
  have same : entry.globalIndex = index := canonical.1.1
  rw [same]
  exact found

theorem exact_current_attempt_lookup (offset : Fin 448) :
    exactCsrAttempts[16942 + offset.val]? = some (V8Smz9InputMerkleSources.currentAttempt offset.val) := by
  exact exact_attempt_lookup _ (V8Smz9InputMerkleSources.exact_current_attempt offset.isLt)

theorem exact_direction_attempt_lookup (offset : Fin 448) :
    exactCsrAttempts[17390 + offset.val]? = some (V8Smz9InputMerkleSources.directionAttempt offset.val) := by
  exact exact_attempt_lookup _ (V8Smz9InputMerkleSources.exact_direction_attempt offset.isLt)

theorem source_inline_index_agrees (step limb component : Nat) :
    V8Smz9InputMerkleSources.inlineIndex step limb component =
      V8Smz9SourceInlineRows.inlineIndex (step / 32) (step % 32) limb component := by
  unfold V8Smz9InputMerkleSources.inlineIndex V8Smz9SourceInlineRows.inlineIndex V8Smz9SourceInlineRows.inlineSlot
  have split : step / 32 * 32 + step % 32 = step := by omega
  rw [split]
  simp only [Nat.mul_comm]

theorem source_previous_call_agrees (step : Nat) :
    V8Smz9InputMerkleSources.previousCall step = V8Smz9SourceInlineRows.previousCall (step / 32) (step % 32) := by
  rfl

theorem constructed_current_copy (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (step : Fin 64) (limb : Fin 7) :
    (constructedAssignment statement witness live tail).getD
        (V8Smz9InputMerkleSources.inlineIndex step.val limb.val 0) 0 =
      (constructedAssignment statement witness live tail).getD
        (hashFinalIndex (V8Smz9InputMerkleSources.previousCall step.val) limb.val) 0 := by
  rw [source_inline_index_agrees, source_previous_call_agrees]
  have previousBound := V8Smz9SourceInlineRows.previous_call_live (step.val / 32) (step.val % 32)
    (by omega) (by omega)
  rw [constructed_orientation_readback statement witness live tail
      ⟨step.val / 32, by omega⟩ ⟨step.val % 32, by omega⟩ limb ⟨0, by decide⟩,
    constructed_auth_final_at_hash_index statement witness live tail
      ⟨V8Smz9SourceInlineRows.previousCall (step.val / 32) (step.val % 32), previousBound⟩ limb]
  exact (V8Smz9SourceInlineRows.oriented_components live witness _ _ _).1

theorem constructed_raw_direction (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (step : Fin 64) :
    (constructedAssignment statement witness live tail).getD
        (rawIndex (inputDirectionRow (step.val / 32) (step.val % 32))) 0 =
      V8Smz9SourceInlineRows.direction witness (step.val / 32) (step.val % 32) := by
  have indexBound : rawIndex (inputDirectionRow (step.val / 32) (step.val % 32)) < 5888 := by
    unfold rawIndex rawRowStart Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor inputDirectionRow
    omega
  rw [constructed_first92_unchanged statement witness live tail ⟨_, indexBound⟩]
  have source := V8Smz9SourceReplicatedRows.placed_input_direction statement witness [] (step.val / 32)
    (step.val % 32) 0 (by omega) (by omega) (by decide)
  have address : rawIndex (34 * (step.val / 32) + (2 + step.val % 32)) + 0 =
      rawIndex (inputDirectionRow (step.val / 32) (step.val % 32)) := by
    rw [Nat.add_zero]
    unfold inputDirectionRow
    congr 1
    omega
  simpa only [V8Smz9SourceReplicatedRows.placePrefix, List.append_nil, address, V8Smz9SourceInlineRows.direction] using source

theorem constructed_direction_copy (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (step : Fin 64) (limb : Fin 7) :
    (constructedAssignment statement witness live tail).getD
        (V8Smz9InputMerkleSources.inlineIndex step.val limb.val 3) 0 =
      (constructedAssignment statement witness live tail).getD
        (rawIndex (inputDirectionRow (step.val / 32) (step.val % 32))) 0 := by
  rw [source_inline_index_agrees,
    constructed_orientation_readback statement witness live tail
      ⟨step.val / 32, by omega⟩ ⟨step.val % 32, by omega⟩ limb ⟨3, by decide⟩,
    constructed_raw_direction statement witness live tail step]
  exact (V8Smz9SourceInlineRows.oriented_components live witness _ _ _).2.2.2

noncomputable section

/-- Interpret the actual coefficient DAG: no claimed coefficient equations are inputs. -/
theorem actual_copy_residual_formula (pub : Nat → F) (packed : List Nat)
    (global family localIndex left right : Nat) :
    actualCsrResidual pub packed (attempt global family localIndex 0 [(left, 1), (right, 158)] 0) =
      (packed.getD left 0 : F) - (packed.getD right 0 : F) := by
  have zeroOne := actual_csr_zero_one pub
  have negative : actualCsrCoefficients pub 158 = -1 := by
    simpa using (actual_dense_negative_coefficients pub).1 0 (by decide)
  simp only [actualCsrResidual, actualCsrTerms, attempt, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, zeroOne.1, zeroOne.2, negative, one_mul, neg_one_mul,
    add_zero, sub_eq_add_neg, neg_zero]

theorem constructed_current_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (pub : Nat → F) (offset : Fin 448) :
    actualCsrResidual pub (constructedAssignment statement witness live tail)
      (V8Smz9InputMerkleSources.currentAttempt offset.val) = 0 := by
  rw [V8Smz9InputMerkleSources.currentAttempt, actual_copy_residual_formula]
  rw [constructed_current_copy statement witness live tail ⟨offset.val / 7, by omega⟩
    ⟨offset.val % 7, by omega⟩]
  exact sub_self _

theorem constructed_direction_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (pub : Nat → F) (offset : Fin 448) :
    actualCsrResidual pub (constructedAssignment statement witness live tail)
      (V8Smz9InputMerkleSources.directionAttempt offset.val) = 0 := by
  rw [V8Smz9InputMerkleSources.directionAttempt, actual_copy_residual_formula]
  rw [constructed_direction_copy statement witness live tail ⟨offset.val / 7, by omega⟩
    ⟨offset.val % 7, by omega⟩]
  exact sub_self _

theorem constructed_all_448_current_actual_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (pub : Nat → F) (offset : Fin 448) :
    (exactCsrAttempts[16942 + offset.val]?).map
      (actualCsrResidual pub (constructedAssignment statement witness live tail)) = some 0 := by
  rw [exact_current_attempt_lookup, Option.map_some,
    constructed_current_attempt_zero statement witness live tail pub offset]

theorem constructed_all_448_direction_actual_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (pub : Nat → F) (offset : Fin 448) :
    (exactCsrAttempts[17390 + offset.val]?).map
      (actualCsrResidual pub (constructedAssignment statement witness live tail)) = some 0 := by
  rw [exact_direction_attempt_lookup, Option.map_some,
    constructed_direction_attempt_zero statement witness live tail pub offset]

/-- All 896 consecutive actual raw CSR entries, not a reconstructed substitute list. -/
theorem constructed_all_896_actual_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (pub : Nat → F) (offset : Fin 896) :
    (exactCsrAttempts[16942 + offset.val]?).map
      (actualCsrResidual pub (constructedAssignment statement witness live tail)) = some 0 := by
  by_cases current : offset.val < 448
  · exact constructed_all_448_current_actual_csr_zero statement witness live tail pub ⟨offset.val, current⟩
  · have address : 16942 + offset.val = 17390 + (offset.val - 448) := by omega
    rw [address]
    exact constructed_all_448_direction_actual_csr_zero statement witness live tail pub
      ⟨offset.val - 448, by omega⟩

/-- The typed endpoint has no free live states and needs no typed-validity assumption. -/
theorem typed_all_896_actual_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (pub : Nat → F) (offset : Fin 896) :
    (exactCsrAttempts[16942 + offset.val]?).map
      (actualCsrResidual pub (typedAssignment statement witness tail)) = some 0 :=
  constructed_all_896_actual_csr_zero statement witness _ tail pub offset

end


end HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies

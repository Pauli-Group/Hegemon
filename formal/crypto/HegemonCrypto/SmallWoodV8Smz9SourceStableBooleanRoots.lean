import HegemonCrypto.SmallWoodV8Smz9SourceStableBooleanRootFormulas

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableBooleanRoots

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization (AuthHashFinals)
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

/-- Every computed low digit, including absent-list padding, is below four.
No value range admission is needed for this digit-only property. -/
theorem source_range_digit_getD_bound (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) (aux : SourceAux) (index : Nat) :
    (sourceRangeDigits stablePublic witness aux).getD index 0 < 4 := by
  cases found : (sourceRangeDigits stablePublic witness aux)[index]? with
  | none => simp only [List.getD_eq_getElem?_getD,found,Option.getD_none]; decide
  | some word =>
      have member := List.mem_of_getElem? found
      obtain ⟨entry,_,member⟩ := List.mem_flatMap.mp member
      obtain ⟨digit,_,rfl⟩ := List.mem_map.mp member
      simpa only [List.getD_eq_getElem?_getD,found,Option.getD_some] using
        source_radix_digit_bound entry.1 digit

theorem actual_source_tail_radix_bound (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (slot : Fin 23) (lane : Nat) :
    sourceTailWord statement witness hashes (16 + slot.val) lane < 4 := by
  have readback := source_tail_family_readback statement witness hashes .ranges slot.val lane slot.isLt
  change sourceTailWord statement witness hashes (16 + slot.val) lane =
    (sourceRangeDigits statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).getD (slot.val * 64 + lane) 0 at readback
  rw [readback]
  exact source_range_digit_getD_bound _ _ _ _

noncomputable section

def sourceTailLaneField (before : List Nat) (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Fin 64) : Nat → F :=
  fun row => ((packedWitnessLaneRows (embedSourceTail before statement witness hashes) lane.val).getD row 0 : F)

theorem source_tail_lane_field_readback (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 41408) (row : Fin 39) (lane : Fin 64) :
    sourceTailLaneField before statement witness hashes lane (647 + row.val) =
      (sourceTailWord statement witness hashes row.val lane.val : F) := by
  unfold sourceTailLaneField
  rw [source_tail_global_lane_readback before statement witness hashes prefixLength row lane]

theorem valid_source_tail_actual_boolean_root_zero (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 41408) (pub : Nat → F) (lane : Fin 64) :
    fieldAt exactNonlinearExpressions pub
      (sourceTailLaneField before statement witness hashes lane) 8130 = 0 := by
  rw [actual_stable_boolean_root_formula]
  have readback := source_tail_lane_field_readback before statement witness hashes
    prefixLength (⟨11,by decide⟩ : Fin 39) lane
  change sourceTailLaneField before statement witness hashes lane 658 =
    (sourceTailWord statement witness hashes 11 lane.val : F) at readback
  rw [readback]
  exact boolean_word_field_equation _ (valid_tail_boolean_row_boolean statement witness valid hashes lane.val)

theorem source_tail_actual_radix_root_zero (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 41408) (pub : Nat → F) (lane : Fin 64) (slot : Fin 23) :
    fieldAt exactNonlinearExpressions pub
      (sourceTailLaneField before statement witness hashes lane) (8138 + 6 * slot.val) = 0 := by
  rw [actual_stable_radix_four_root_formula]
  have readback := source_tail_lane_field_readback before statement witness hashes
    prefixLength (⟨16 + slot.val,by omega⟩ : Fin 39) lane
  have address : 647 + (16 + slot.val) = 663 + slot.val := by omega
  simp only [address] at readback
  rw [readback]
  exact radix_four_field_equation _ (actual_source_tail_radix_bound statement witness hashes slot lane.val)

/-- Zero-based generated root indices 805 and 807..829, each in every physical lane. -/
theorem valid_source_tail_boolean_and_radix_roots_zero (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 41408) (pub : Nat → F) :
    ∀ lane : Fin 64,
      (exactNonlinearRoots[805]?).map
        (fieldAt exactNonlinearExpressions pub (sourceTailLaneField before statement witness hashes lane)) = some 0 ∧
      ∀ slot : Fin 23, (exactNonlinearRoots[807 + slot.val]?).map
        (fieldAt exactNonlinearExpressions pub (sourceTailLaneField before statement witness hashes lane)) = some 0 := by
  intro lane
  constructor
  · rw [actual_stable_boolean_root_identity.1,Option.map_some,
      valid_source_tail_actual_boolean_root_zero before statement witness valid hashes prefixLength pub lane]
  · intro slot
    rw [(actual_stable_radix_root_identities slot).1,Option.map_some,
      source_tail_actual_radix_root_zero before statement witness hashes prefixLength pub lane slot]


end
end HegemonCrypto.SmallWood.V8Smz9SourceStableBooleanRoots

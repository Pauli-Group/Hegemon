import HegemonCrypto.SmallWoodV8Smz9SourceTypedPrefix
import HegemonCrypto.SmallWoodV8Smz9SourceTailReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceTailRolesCanonical
import HegemonCrypto.SmallWoodV8Smz9SourceAuthorizationDigests
import HegemonCrypto.SmallWoodV8Smz9SourceTailNumericCanonical
import HegemonCrypto.SmallWoodV8Smz9SourceTailMultiplicationCanonical

/-! One complete source-shaped candidate, with no free live hash states,
hash-final accessor or stable-tail input. The prefix and tail use the same
actual 125-call typed schedule. Selected constraints and canonical words
do not assert full packed acceptance or executable Rust refinement. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate

open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def typedSourceFinals (statement : V8PublicStatement) (witness : V8Witness) : AuthHashFinals :=
  computedAuthFinals (typedLiveInitialStates statement witness)

def typedSourceTail (statement : V8PublicStatement) (witness : V8Witness) : List Nat :=
  sourceTailPacked statement witness (typedSourceFinals statement witness)

def fullTypedSourceCandidate (statement : V8PublicStatement) (witness : V8Witness) : List Nat :=
  typedAssignment statement witness (typedSourceTail statement witness)

theorem typed_source_finals_canonical (statement : V8PublicStatement) (witness : V8Witness) :
    HashFinalsCanonical (typedSourceFinals statement witness) :=
  computed_auth_finals_canonical _

theorem typed_source_tail_length (statement : V8PublicStatement) (witness : V8Witness) :
    (typedSourceTail statement witness).length = 2496 :=
  source_tail_shape statement witness _

theorem full_candidate_as_tail_embedding (statement : V8PublicStatement) (witness : V8Witness) :
    fullTypedSourceCandidate statement witness =
      embedSourceTail (typedPrefix statement witness) statement witness
        (typedSourceFinals statement witness) := rfl

theorem full_candidate_length (statement : V8PublicStatement) (witness : V8Witness) :
    (fullTypedSourceCandidate statement witness).length = 43904 :=
  constructed_full_length statement witness _ _ (typed_source_tail_length statement witness)

theorem typed_source_tail_cell_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (row : Fin 39) (lane : Fin 64) :
    sourceTailWord statement witness (typedSourceFinals statement witness) row.val lane.val < fieldModulus := by
  by_cases sourceRows : row.val < 2
  · exact valid_source_tail_sources_canonical statement witness valid _ ⟨row.val, sourceRows⟩ lane
  by_cases roleRows : row.val < 9
  · have address : 2 + (row.val - 2) = row.val := by omega
    simpa only [address] using valid_tail_role_rows_canonical statement witness valid _
      (typed_source_finals_canonical statement witness) ⟨row.val - 2, by omega⟩ lane
  by_cases selectorRow : row.val = 9
  · rw [selectorRow]
    exact source_tail_selector_canonical statement witness _ lane
  by_cases inverseRow : row.val = 10
  · rw [inverseRow]
    exact source_tail_inverse_canonical statement witness _ lane
  by_cases booleanRow : row.val = 11
  · rw [booleanRow]
    exact valid_tail_boolean_row_canonical statement witness valid _ lane
  by_cases numericRow : row.val = 12
  · rw [numericRow]
    exact valid_source_numeric_row_canonical statement witness valid _ lane.val
  by_cases mulRows : row.val < 16
  · have address : 13 + (row.val - 13) = row.val := by omega
    simpa only [address] using valid_source_multiplication_rows_canonical statement witness valid _
      ⟨row.val - 13, by omega⟩ lane.val
  · have address : 16 + (row.val - 16) = row.val := by omega
    simpa only [address] using source_tail_ranges_canonical statement witness
      (typedSourceFinals statement witness) ⟨row.val - 16, by omega⟩ lane

theorem typed_source_tail_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords 2496 (typedSourceTail statement witness) := by
  refine ⟨typed_source_tail_length statement witness, ?_⟩
  intro value member
  obtain ⟨slot, rfl⟩ := List.mem_ofFn.mp member
  exact typed_source_tail_cell_canonical statement witness valid
    ⟨slot.val / 64, by omega⟩ ⟨slot.val % 64, by omega⟩

/-- Entire concrete candidate canonicality, from the fixed typed relation alone. -/
theorem full_candidate_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords 43904 (fullTypedSourceCandidate statement witness) :=
  typed_assignment_canonical statement witness valid _ (typed_source_tail_canonical statement witness valid)

/-- Public admission is a separate typed fact, not inferred from candidate size. -/
theorem typed_public_words_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords publicWordCount (encodePublicStatement statement) :=
  valid_public_words_exact statement witness valid

theorem full_candidate_prefix_unchanged (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 41408) :
    (fullTypedSourceCandidate statement witness).getD index.val 0 =
      (typedPrefix statement witness).getD index.val 0 :=
  source_tail_prefix_unchanged _ statement witness _ index.val
    (by rw [constructed_prefix_length]; exact index.isLt) 0

theorem full_candidate_source_word_readback (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 128) :
    (fullTypedSourceCandidate statement witness).getD (41408 + slot.val) 0 =
      stableSourceWord statement witness slot.val := by
  change (typedAssignment statement witness _).getD _ 0 = _
  rw [typed_tail_unchanged]
  have readback := source_tail_packed_readback statement witness
    (typedSourceFinals statement witness) ⟨slot.val / 64, by omega⟩ ⟨slot.val % 64, by omega⟩ 0
  have address : slot.val / 64 * 64 + slot.val % 64 = slot.val := by omega
  have sourceRows : slot.val / 64 < 2 := by omega
  simpa only [typedSourceTail, sourceTailWord, if_pos sourceRows, address] using readback

theorem full_candidate_stable_private_readback (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 94) :
    (fullTypedSourceCandidate statement witness).getD (41408 + slot.val) 0 =
      stableWitnessWord witness.stablecoin (sourcePrivateIndex slot.val) := by
  rw [full_candidate_source_word_readback statement witness ⟨slot.val, by omega⟩]
  simp only [stableSourceWord, if_pos slot.isLt]

/-- The stable source reorder reads actual typed words, not absent-list defaults. -/
theorem full_candidate_private_source_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 94) :
    witness.stablecoin.words[sourcePrivateIndex slot.val]? =
      some ((fullTypedSourceCandidate statement witness).getD (41408 + slot.val) 0) := by
  rw [full_candidate_stable_private_readback]
  have bound : sourcePrivateIndex slot.val < witness.stablecoin.words.length := by
    rw [(valid_stable_words_exact statement witness valid).1]
    exact source_private_index_bound slot.val slot.isLt
  simp [stableWitnessWord, List.getD, bound]

theorem full_candidate_parent_public_readback (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 18) :
    (fullTypedSourceCandidate statement witness).getD (41502 + slot.val) 0 =
      wordAt (encodePublicStatement statement) (63 + slot.val) := by
  have address : 41502 + slot.val = 41408 + (94 + slot.val) := by omega
  rw [address, full_candidate_source_word_readback statement witness ⟨94 + slot.val, by omega⟩]
  exact stable_source_parent_readback statement witness slot.val slot.isLt

theorem full_candidate_spend_keys_readback (statement : V8PublicStatement) (witness : V8Witness)
    (input : Fin 2) (limb : Fin 4) :
    (fullTypedSourceCandidate statement witness).getD (41520 + input.val * 4 + limb.val) 0 =
      wordAt (witness.inputs.getD input.val default).spendKey limb.val := by
  have address : 41520 + input.val * 4 + limb.val = 41408 + (112 + input.val * 4 + limb.val) := by omega
  rw [address, full_candidate_source_word_readback statement witness ⟨112 + input.val * 4 + limb.val, by omega⟩]
  exact stable_source_spend_key_readback statement witness input limb

theorem full_candidate_tail_word_readback (statement : V8PublicStatement) (witness : V8Witness)
    (row : Fin 39) (lane : Fin 64) :
    (Poseidon2V8RelationProgram.packedWitnessLaneRows
      (fullTypedSourceCandidate statement witness) lane.val).getD (647 + row.val) 0 =
      sourceTailWord statement witness (typedSourceFinals statement witness) row.val lane.val :=
  source_tail_global_lane_readback _ statement witness _
    (typed_prefix_length statement witness) row lane

theorem full_candidate_tail_family_readback (statement : V8PublicStatement) (witness : V8Witness)
    (family : TailFamily) (offset : Nat) (bound : offset < family.width) (lane : Fin 64) :
    (Poseidon2V8RelationProgram.packedWitnessLaneRows
      (fullTypedSourceCandidate statement witness) lane.val).getD
        (647 + family.base + offset) 0 =
      tailFamilyWord statement witness (typedSourceFinals statement witness) family offset lane.val :=
  source_tail_global_family_readback _ statement witness _
    (typed_prefix_length statement witness) family offset bound lane

theorem full_candidate_initial_source_readback (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (call : Fin 125) (lane : Fin 16) :
    (fullTypedSourceCandidate statement witness).getD
        (Poseidon2V8DecoderRefinement.hashInitialIndex call.val lane.val) 0 =
      (actualSourceFrame statement witness call).getD lane.val 0 :=
  typed_initial_readback statement witness valid _ call lane

theorem full_candidate_initial_source_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (call : Fin 125) (lane : Fin 16) :
    (fullTypedSourceCandidate statement witness)[Poseidon2V8DecoderRefinement.hashInitialIndex call.val lane.val]? =
      some ((actualSourceFrame statement witness call).getD lane.val 0) :=
  typed_packed_initial_entry_present statement witness valid _ call lane

theorem full_candidate_final_source_kernel_readback (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (call : Fin 125) (lane : Fin 16) :
    (fullTypedSourceCandidate statement witness).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex call.val lane.val) 0 =
      (Poseidon2Width16Kernel.permutation (actualSourceFrame statement witness call)).getD lane.val 0 :=
  typed_final_is_actual_source_kernel statement witness valid _ call lane

theorem full_candidate_final_schedule_readback (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (lane : Fin 16) :
    (fullTypedSourceCandidate statement witness).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex call.val lane.val) 0 =
      (stateWords (scheduledFinal statement witness call.val)).getD lane.val 0 :=
  typed_final_is_scheduled_final statement witness _ call lane

/-- The tail's final-digest accessor is exactly this same scheduled result. -/
theorem typed_source_finals_are_actual_schedule (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (limb : Fin 7) :
    typedSourceFinals statement witness call limb =
      (stateWords (scheduledFinal statement witness call.val)).getD limb.val 0 := by
  have source := constructed_auth_final_at_hash_index statement witness
    (typedLiveInitialStates statement witness) (typedSourceTail statement witness) call limb
  have scheduled := full_candidate_final_schedule_readback statement witness call
    ⟨limb.val, by omega⟩
  exact source.symm.trans scheduled

theorem typed_source_policy_role_is_current (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) (limb : Fin 7) :
    sourceRoleWord statement witness (typedSourceFinals statement witness) 22 limb.val =
      witness.authorization.current.policyRoot.getD limb.val 0 := by
  change (if witness.authorization.mode = .singleKey then sourceUnitWord limb.val else
    authHashWord (typedSourceFinals statement witness) 97 limb.val) = _
  rw [if_neg nonsingle, auth_hash_word_readback _ ⟨97, by decide⟩ limb]
  exact typed_non_single_policy_call_is_current statement witness valid nonsingle limb

theorem full_candidate_policy_role_readback (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) (limb : Fin 7) :
    (Poseidon2V8RelationProgram.packedWitnessLaneRows
      (fullTypedSourceCandidate statement witness) 22).getD (649 + limb.val) 0 =
      witness.authorization.current.policyRoot.getD limb.val 0 := by
  have readback := full_candidate_tail_family_readback statement witness .roleDifference
    limb.val limb.isLt ⟨22, by decide⟩
  dsimp only [TailFamily.base, tailFamilyWord] at readback
  exact readback.trans (typed_source_policy_role_is_current statement witness valid nonsingle limb)

theorem full_candidate_last_padding_zero (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) (padding : 26 ≤ lane.val) :
    (Poseidon2V8RelationProgram.packedWitnessLaneRows
      (fullTypedSourceCandidate statement witness) lane.val).getD 685 0 = 0 :=
  source_tail_global_padding_zero _ statement witness _
    (typed_prefix_length statement witness) lane padding

noncomputable section

theorem full_candidate_all_seven_actual_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (value : Fin 7) :
    (exactCsrAttempts[15665 + value.val]?).map
        (actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (fullTypedSourceCandidate statement witness)) = some 0 :=
  typed_all_seven_actual_csr_zero statement witness _ value

theorem full_candidate_all_five_actual_dense_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ∀ lane : Fin 64,
      (∀ slot : Fin 4,
        fieldAt exactNonlinearExpressions
          (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (laneField (fullTypedSourceCandidate statement witness) lane.val)
          (1183 + 6 * slot.val) = 0) ∧
      fieldAt exactNonlinearExpressions
        (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val) 1203 = 0 :=
  typed_all_five_actual_dense_roots_zero statement witness valid _

theorem full_candidate_all_332_actual_hash_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (publicWords : List Nat) (lane : Fin 64)
    (root : Nat) (member : root ∈ (exactNonlinearRoots.drop 471).take 332) :
    fieldAt exactNonlinearExpressions (fun i => (publicWords.getD i 0 : F))
      (laneField (fullTypedSourceCandidate statement witness) lane.val) root = 0 :=
  typed_all_332_actual_hash_roots_zero statement witness _ publicWords lane root member

end


end HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate

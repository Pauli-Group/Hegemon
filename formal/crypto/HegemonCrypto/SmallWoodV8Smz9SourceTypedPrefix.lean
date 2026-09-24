import HegemonCrypto.SmallWoodV8Smz9SourceConstructedPrefix
import HegemonCrypto.SmallWoodV8Smz9TypedScheduleInventory

/-! The source-shaped prefix now has no free live-state input: all 125 initial
states are computed by the actual typed schedule. The final 39 stable rows
remain caller data. Canonical shape and selected constraints are not full
relation acceptance or executable Rust refinement. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix

open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def typedPrefix (statement : V8PublicStatement) (witness : V8Witness) : List Nat :=
  constructedPrefix statement witness (typedLiveInitialStates statement witness)

def typedAssignment (statement : V8PublicStatement) (witness : V8Witness)
    (stableTail : List Nat) : List Nat :=
  constructedAssignment statement witness (typedLiveInitialStates statement witness) stableTail

def actualSourceFrame (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) : List Nat :=
  rawPreparedPlan (scheduledFinal statement witness)
    (sourceCallPlan statement witness call.val (scheduledFinal statement witness))

theorem typed_prefix_length (statement : V8PublicStatement) (witness : V8Witness) :
    (typedPrefix statement witness).length = 41408 :=
  constructed_prefix_length statement witness _

theorem typed_prefix_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords 41408 (typedPrefix statement witness) :=
  constructed_prefix_canonical statement witness valid _

theorem typed_assignment_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (stableTail : List Nat)
    (tailCanonical : ExactWords 2496 stableTail) :
    ExactWords 43904 (typedAssignment statement witness stableTail) := by
  refine ⟨constructed_full_length statement witness _ stableTail tailCanonical.1, ?_⟩
  intro value member
  rcases List.mem_append.mp member with leading | tail
  · exact (typed_prefix_canonical statement witness valid).2 value leading
  · exact tailCanonical.2 value tail

theorem typed_tail_unchanged (statement : V8PublicStatement) (witness : V8Witness)
    (stableTail : List Nat) (index fallback : Nat) :
    (typedAssignment statement witness stableTail).getD (41408 + index) fallback =
      stableTail.getD index fallback :=
  constructed_tail_unchanged statement witness _ stableTail index fallback

theorem actual_source_frame_length (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (call : Fin 125) :
    (actualSourceFrame statement witness call).length = 16 := by
  rw [actualSourceFrame, ← typed_valid_initial_is_actual_source_frame statement witness valid call]
  exact state_words_length _

/-- This is an actual `some` source-list entry; no fallback value is credited. -/
theorem actual_source_initial_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (call : Fin 125) (lane : Fin 16) :
    (actualSourceFrame statement witness call)[lane.val]? =
      some (typedLiveInitialStates statement witness call lane).val := by
  rw [actualSourceFrame, ← typed_valid_initial_is_actual_source_frame statement witness valid call]
  simp only [stateWords, List.getElem?_ofFn, dif_pos lane.isLt]

theorem typed_initial_readback (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (stableTail : List Nat)
    (call : Fin 125) (lane : Fin 16) :
    (typedAssignment statement witness stableTail).getD
        (Poseidon2V8DecoderRefinement.hashInitialIndex call.val lane.val) 0 =
      (actualSourceFrame statement witness call).getD lane.val 0 := by
  change (placeHashBlock _ _ stableTail).getD _ 0 = _
  rw [placed_live_initial _ stableTail _ (before_hash_length statement witness _) call lane]
  simp only [List.getD_eq_getElem?_getD,
    actual_source_initial_entry_present statement witness valid call lane, Option.getD_some]

/-- The global packed coordinate is also present, for any tail, even empty. -/
theorem typed_packed_initial_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (stableTail : List Nat)
    (call : Fin 125) (lane : Fin 16) :
    (typedAssignment statement witness stableTail)[Poseidon2V8DecoderRefinement.hashInitialIndex call.val lane.val]? =
      some ((actualSourceFrame statement witness call).getD lane.val 0) := by
  have length : (typedAssignment statement witness stableTail).length = 41408 + stableTail.length := by
    simp only [typedAssignment, constructedAssignment, List.length_append, constructed_prefix_length]
  have bound : Poseidon2V8DecoderRefinement.hashInitialIndex call.val lane.val <
      (typedAssignment statement witness stableTail).length := by
    rw [length]
    unfold Poseidon2V8DecoderRefinement.hashInitialIndex Poseidon2V8DecoderRefinement.hashRowStart
      Poseidon2V8DecoderRefinement.packingFactor Poseidon2V8DecoderRefinement.hashRowsPerGroup
    omega
  have present : (typedAssignment statement witness stableTail)[Poseidon2V8DecoderRefinement.hashInitialIndex call.val lane.val]? =
      some ((typedAssignment statement witness stableTail).getD
        (Poseidon2V8DecoderRefinement.hashInitialIndex call.val lane.val) 0) := by
    simp [List.getD, bound]
  rwa [typed_initial_readback statement witness valid stableTail call lane] at present

theorem typed_call_initial_exact (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) :
    callInitial (typedLiveInitialStates statement witness) call.val =
      stateWords (scheduledInitial statement witness call.val) := by
  simp only [callInitial, dif_pos call.isLt, stateWords, typedLiveInitialStates]

theorem typed_final_is_actual_source_kernel (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (stableTail : List Nat)
    (call : Fin 125) (lane : Fin 16) :
    (typedAssignment statement witness stableTail).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex call.val lane.val) 0 =
      (Poseidon2Width16Kernel.permutation (actualSourceFrame statement witness call)).getD lane.val 0 := by
  change (placeHashBlock _ _ stableTail).getD _ 0 = _
  rw [placed_final_at_decoder_index _ stableTail _ (before_hash_length statement witness _)
    call.val lane.val (by omega) lane.isLt, typed_call_initial_exact]
  have initial := typed_valid_initial_is_actual_source_frame statement witness valid call
  change stateWords (scheduledInitial statement witness call.val) = actualSourceFrame statement witness call at initial
  rw [initial]

theorem typed_final_is_scheduled_final (statement : V8PublicStatement) (witness : V8Witness)
    (stableTail : List Nat) (call : Fin 125) (lane : Fin 16) :
    (typedAssignment statement witness stableTail).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex call.val lane.val) 0 =
      (stateWords (scheduledFinal statement witness call.val)).getD lane.val 0 := by
  change (placeHashBlock _ _ stableTail).getD _ 0 = _
  rw [placed_final_at_decoder_index _ stableTail _ (before_hash_length statement witness _)
    call.val lane.val (by omega) lane.isLt, typed_call_initial_exact,
    every_call_has_actual_kernel_final]

noncomputable section

theorem typed_all_seven_actual_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (stableTail : List Nat) (value : Fin 7) :
    (exactCsrAttempts[15665 + value.val]?).map
        (actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (typedAssignment statement witness stableTail)) = some 0 :=
  constructed_all_seven_actual_csr_zero statement witness _ stableTail value

theorem typed_all_five_actual_dense_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (stableTail : List Nat) :
    ∀ lane : Fin 64,
      (∀ slot : Fin 4,
        fieldAt exactNonlinearExpressions
          (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (laneField (typedAssignment statement witness stableTail) lane.val)
          (1183 + 6 * slot.val) = 0) ∧
      fieldAt exactNonlinearExpressions
        (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (laneField (typedAssignment statement witness stableTail) lane.val) 1203 = 0 :=
  constructed_all_five_actual_dense_roots_zero statement witness valid _ stableTail

theorem typed_all_332_actual_hash_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (stableTail publicWords : List Nat) (lane : Fin 64)
    (root : Nat) (member : root ∈ (exactNonlinearRoots.drop 471).take 332) :
    fieldAt exactNonlinearExpressions (fun i => (publicWords.getD i 0 : F))
      (laneField (typedAssignment statement witness stableTail) lane.val) root = 0 :=
  constructed_all_332_actual_hash_roots_zero statement witness _ stableTail publicWords lane root member

end


end HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix


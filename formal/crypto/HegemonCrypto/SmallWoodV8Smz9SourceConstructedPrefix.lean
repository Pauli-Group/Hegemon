import HegemonCrypto.SmallWoodV8Smz9SourceDensePrefix
import HegemonCrypto.SmallWoodV8Smz9SourceAuthReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceInlineRows
import HegemonCrypto.SmallWoodV8Smz9ComputedHashRoots

/-! Source-shaped first 647 rows. All digest accessors are derived from the
same computed live hash columns. The 125 live initial states remain explicit
canonical inputs; their typed schedule derivation is a separate component.
The final 39 rows remain arbitrary caller data. No full acceptance is claimed. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix

open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceDensePrefix
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceDenseRoots
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def computedAuthFinals (live : LiveInitialStates) : AuthHashFinals :=
  fun call limb => callFinalWord live call.val limb.val

theorem computed_auth_finals_canonical (live : LiveInitialStates) :
    HashFinalsCanonical (computedAuthFinals live) :=
  fun call limb => call_final_word_canonical live call.val limb.val

def authBlock (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) : List Nat :=
  sourceAuthPacked statement witness (computedAuthFinals live)

def beforeInline (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) : List Nat :=
  packedPrefix statement witness ++ authBlock statement witness live ++
    sourceDensePacked (typedSourceValues statement witness)

def beforeHash (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) : List Nat :=
  beforeInline statement witness live ++ inlinePacked live witness

def constructedPrefix (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) : List Nat :=
  beforeHash statement witness live ++ (hashRows live).flatten

def constructedAssignment (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) : List Nat :=
  constructedPrefix statement witness live ++ stableTail

theorem auth_block_length (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) : (authBlock statement witness live).length = 9920 :=
  (source_auth_shape statement witness (computedAuthFinals live)).2

theorem before_inline_length (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) : (beforeInline statement witness live).length = 16128 := by
  simp only [beforeInline, List.length_append, packed_prefix_length,
    auth_block_length, source_dense_packed_length]

theorem before_hash_length (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) : (beforeHash statement witness live).length = 18112 := by
  simp only [beforeHash, List.length_append, before_inline_length, inline_packed_length]

theorem constructed_prefix_length (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) : (constructedPrefix statement witness live).length = 41408 := by
  simp only [constructedPrefix, List.length_append, before_hash_length, hash_flat_length]

theorem constructed_full_length (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) (tailLength : stableTail.length = 2496) :
    (constructedAssignment statement witness live stableTail).length = 43904 := by
  simp only [constructedAssignment, List.length_append, constructed_prefix_length, tailLength]

theorem constructed_as_hash_placement (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) :
    constructedAssignment statement witness live stableTail =
      placeHashBlock (beforeHash statement witness live) live stableTail := rfl

theorem constructed_as_dense_composition (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) :
    constructedAssignment statement witness live stableTail =
      composedAssignment statement witness (authBlock statement witness live)
        (inlinePacked live witness ++ (hashRows live).flatten ++ stableTail) := by
  simp only [constructedAssignment, constructedPrefix, beforeHash, beforeInline,
    composedAssignment, embedSourceDense, beforeDense, List.append_assoc]

theorem constructed_as_inline_placement (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) :
    constructedAssignment statement witness live stableTail =
      placeInline (beforeInline statement witness live)
        ((hashRows live).flatten ++ stableTail) live witness := by
  simp only [constructedAssignment, constructedPrefix, beforeHash, placeInline, List.append_assoc]

theorem constructed_as_auth_placement (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) :
    constructedAssignment statement witness live stableTail =
      embedSourceAuth (packedPrefix statement witness)
        (sourceDensePacked (typedSourceValues statement witness) ++
          inlinePacked live witness ++ (hashRows live).flatten ++ stableTail)
        statement witness (computedAuthFinals live) := by
  simp only [constructedAssignment, constructedPrefix, beforeHash, beforeInline,
    authBlock, embedSourceAuth, List.append_assoc]

theorem constructed_prefix_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (live : LiveInitialStates) :
    ExactWords 41408 (constructedPrefix statement witness live) := by
  refine ⟨constructed_prefix_length statement witness live, ?_⟩
  intro value member
  simp only [constructedPrefix, beforeHash, beforeInline, List.mem_append] at member
  rcases member with (((first | auth) | dense) | inline) | hash
  · exact (packed_prefix_canonical statement witness valid).2 value first
  · exact valid_source_auth_packed_canonical statement witness valid (computedAuthFinals live)
      (computed_auth_finals_canonical live) value auth
  · obtain ⟨slot, rfl⟩ := List.mem_ofFn.mp dense
    exact source_dense_cells_canonical _ (typed_source_values_bounded statement witness valid) slot.val
  · exact (inline_packed_canonical statement witness valid live).2 value inline
  · obtain ⟨row, rowMember, valueMember⟩ := List.mem_flatten.mp hash
    exact ((hash_rows_canonical live).2 row rowMember).2 value valueMember

theorem constructed_tail_unchanged (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) (index fallback : Nat) :
    (constructedAssignment statement witness live stableTail).getD (41408 + index) fallback =
      stableTail.getD index fallback := by
  rw [← constructed_prefix_length statement witness live]
  simp only [constructedAssignment, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_right (Nat.le_add_right _ _), Nat.add_sub_cancel_left]

theorem constructed_first92_unchanged (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) (index : Fin 5888) :
    (constructedAssignment statement witness live stableTail).getD index.val 0 =
      (packedPrefix statement witness).getD index.val 0 := by
  rw [constructed_as_auth_placement]
  exact source_auth_prefix_unchanged _ _ statement witness (computedAuthFinals live)
    index.val (by rw [packed_prefix_length]; exact index.isLt) 0

theorem constructed_auth_family_readback (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) (family : AuthFamily)
    (index : Nat) (bound : index < family.width) (lane : Fin 64) :
    (Poseidon2V8RelationProgram.packedWitnessLaneRows
      (constructedAssignment statement witness live stableTail) lane.val).getD
        (92 + family.base + index) 0 =
      authFamilyWord statement witness (computedAuthFinals live) family index := by
  rw [constructed_as_auth_placement]
  exact source_auth_global_family_readback _ _ statement witness (computedAuthFinals live)
    (packed_prefix_length statement witness) family index bound lane

theorem constructed_auth_final_at_hash_index (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) (call : Fin 125) (limb : Fin 7) :
    (constructedAssignment statement witness live stableTail).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex call.val limb.val) 0 =
      computedAuthFinals live call limb := by
  exact call_final_word_at_existing_hash_index _ stableTail live
    (before_hash_length statement witness live) call.val limb.val (by omega) limb.isLt

theorem constructed_orientation_readback (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) (input : Fin 2) (level : Fin 32)
    (limb : Fin 7) (component : Fin 4) :
    (constructedAssignment statement witness live stableTail).getD
        (inlineIndex input.val level.val limb.val component.val) 0 =
      orientedWord live witness input.val level.val limb.val component.val := by
  rw [constructed_as_inline_placement]
  exact placed_all_orientation_words _ _ live witness (before_inline_length statement witness live)
    input level limb component

noncomputable section

theorem constructed_all_seven_actual_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail : List Nat) (value : Fin 7) :
    (exactCsrAttempts[15665 + value.val]?).map
        (actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (constructedAssignment statement witness live stableTail)) = some 0 := by
  rw [constructed_as_dense_composition]
  exact composed_all_seven_actual_csr_zero statement witness _ _
    (auth_block_length statement witness live) value

theorem constructed_all_five_actual_dense_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (live : LiveInitialStates)
    (stableTail : List Nat) :
    ∀ lane : Fin 64,
      (∀ slot : Fin 4,
        fieldAt exactNonlinearExpressions
          (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (laneField (constructedAssignment statement witness live stableTail) lane.val)
          (1183 + 6 * slot.val) = 0) ∧
      fieldAt exactNonlinearExpressions
        (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (laneField (constructedAssignment statement witness live stableTail) lane.val) 1203 = 0 := by
  rw [constructed_as_dense_composition]
  exact valid_typed_dense_actual_roots_zero statement witness valid _ _
    (before_dense_length statement witness _ (auth_block_length statement witness live))

theorem constructed_all_332_actual_hash_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (stableTail publicWords : List Nat) (lane : Fin 64)
    (root : Nat) (member : root ∈ (exactNonlinearRoots.drop 471).take 332) :
    fieldAt exactNonlinearExpressions (fun i => (publicWords.getD i 0 : F))
      (laneField (constructedAssignment statement witness live stableTail) lane.val) root = 0 :=
  computed_block_exact_root_span_zero _ stableTail live (before_hash_length statement witness live)
    publicWords lane.val lane.isLt root member

end


end HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix


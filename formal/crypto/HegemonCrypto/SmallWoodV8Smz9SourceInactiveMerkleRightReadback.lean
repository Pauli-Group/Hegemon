import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem zero_words_getD (words : List Nat) (zero : ZeroWords words) (index : Nat) :
    words.getD index 0 = 0 := by
  cases found : words[index]? with
  | none => simp only [List.getD_eq_getElem?_getD,found,Option.getD_none]
  | some value =>
      have valueZero := zero value (List.mem_of_getElem? found)
      simp only [List.getD_eq_getElem?_getD,found,Option.getD_some,valueZero]

theorem typed_inactive_input_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2)
    (inactive : flagAt statement.inputFlags input.val = 0) :
    ZeroInputWitness (witness.inputs.getD input.val default) := by
  have facts := valid.2.1.2.2.1 input.val input.isLt
  have real : input.val < witness.inputs.length := by rw [valid.2.1.1]; exact input.isLt
  simp only [List.getD_eq_getElem _ _ real] at facts ⊢
  have activeZero : witness.inputs[input.val].active = 0 := facts.1.trans inactive
  rw [if_pos activeZero] at facts
  exact facts.2

theorem typed_inactive_direction_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (level : Nat)
    (inactive : flagAt statement.inputFlags input.val = 0) :
    direction witness input.val level = 0 := by
  have zero := typed_inactive_input_zero statement witness valid input inactive
  have positionZero := zero.2.2.2.2.1
  simp only [direction,positionBit,positionZero,Nat.zero_div,Nat.zero_mod]

theorem typed_inactive_sibling_word_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (level : Fin 32) (limb : Nat)
    (inactive : flagAt statement.inputFlags input.val = 0) :
    siblingWord witness input.val level.val limb = 0 := by
  have zero := typed_inactive_input_zero statement witness valid input inactive
  obtain ⟨_,_,_,_,_,siblingLength,siblingsZero,_,_⟩ := zero
  have real : level.val < (witness.inputs.getD input.val default).siblings.length := by
    rw [siblingLength]
    exact level.isLt
  have present : (witness.inputs.getD input.val default).siblings[level.val]? =
      some ((witness.inputs.getD input.val default).siblings.getD level.val []) := by
    rw [List.getD_eq_getElem _ _ real,List.getElem?_eq_getElem real]
  exact zero_words_getD _ (siblingsZero _ (List.mem_of_getElem? present)).2 limb

theorem typed_inactive_oriented_right_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (live : LiveInitialStates)
    (input : Fin 2) (level : Fin 32) (limb : Nat)
    (inactive : flagAt statement.inputFlags input.val = 0) :
    orientedWord live witness input.val level.val limb 2 = 0 := by
  rw [(oriented_components live witness input.val level.val limb).2.2.1,
    typed_inactive_direction_zero statement witness valid input level.val inactive,
    if_pos rfl,typed_inactive_sibling_word_zero statement witness valid input level limb inactive]

theorem constructed_inactive_right_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (live : LiveInitialStates) (stableTail : List Nat)
    (input : Fin 2) (level : Fin 32) (limb : Fin 7)
    (inactive : flagAt statement.inputFlags input.val = 0) :
    (constructedAssignment statement witness live stableTail).getD
      (inlineRightAddress input.val level.val limb.val) 0 = 0 := by
  rw [← inline_right_index_is_existing_source_index,
    constructed_orientation_readback statement witness live stableTail input level limb ⟨2,by decide⟩,
    typed_inactive_oriented_right_zero statement witness valid live input level limb.val inactive]

theorem full_candidate_inactive_right_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (level : Fin 32) (limb : Fin 7)
    (inactive : flagAt statement.inputFlags input.val = 0) :
    (fullTypedSourceCandidate statement witness).getD
      (inlineRightAddress input.val level.val limb.val) 0 = 0 :=
  constructed_inactive_right_zero statement witness valid (typedLiveInitialStates statement witness)
    (typedSourceTail statement witness) input level limb inactive


end HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight


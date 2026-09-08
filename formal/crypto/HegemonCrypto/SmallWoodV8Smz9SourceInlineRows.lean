import HegemonCrypto.SmallWoodV8Smz9SourceReplicatedRows
import HegemonCrypto.SmallWoodV8Smz9HonestHashPlacement

/-! Exactly the 31 source inline rows252..282. All448 orientation slots are
constructed from typed siblings/position and actual computed hash-call final
words. The125 live hash initial states remain explicit component inputs; their
derivation from typed semantics is not assumed here. The three policy rows
select zero/computed call97 digest exactly as Rust, with57 zero lanes per row.
No packed acceptance, presumed binding, full-lowerer, or Rust-execution claim. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceInlineRows

open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows (positionBit position_bit_boolean)
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def callFinalWord (live : LiveInitialStates) (call limb : Nat) : Nat :=
  (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).finalState.getD limb 0

theorem call_final_word_canonical (live : LiveInitialStates) (call limb : Nat) :
    callFinalWord live call limb < fieldModulus :=
  getD_canonical _ (compressed_trace_canonical _).2 limb

theorem call_final_word_is_permutation (live : LiveInitialStates) (call limb : Nat) :
    callFinalWord live call limb =
      (Poseidon2Width16Kernel.permutation (callInitial live call)).getD limb 0 := by
  unfold callFinalWord
  rw [Poseidon2Width16Kernel.compressed_trace_final_state]

def previousCall (input level : Nat) : Nat :=
  if level = 0 then Poseidon2V8DecoderRefinement.inputNoteCall input + 2
  else Poseidon2V8DecoderRefinement.inputMerkleCall input level - 1

theorem previous_call_live (input level : Nat) (_inputBound : input < 2) (levelBound : level < 32) :
    previousCall input level < 125 := by
  unfold previousCall Poseidon2V8DecoderRefinement.inputNoteCall
    Poseidon2V8DecoderRefinement.inputMerkleCall
  split <;> split <;> omega

def siblingWord (witness : V8Witness) (input level limb : Nat) : Nat :=
  ((witness.inputs.getD input default).siblings.getD level []).getD limb 0

private theorem getD_real_entry {α : Type} (values : List α) (fallback : α)
    (index : Nat) (bound : index < values.length) :
    values[index]? = some (values.getD index fallback) := by
  simp [List.getD, bound]

theorem call_final_word_entry_present (live : LiveInitialStates) (call : Fin 128) (limb : Fin 7) :
    (Poseidon2Width16Kernel.compressedTrace (callInitial live call.val)).finalState[limb.val]? =
      some (callFinalWord live call.val limb.val) := by
  apply getD_real_entry _ 0 limb.val
  have length := compressed_trace_final_length (callInitial live call.val)
  change (Poseidon2Width16Kernel.compressedTrace (callInitial live call.val)).finalState.length = 16 at length
  rw [length]
  omega

theorem typed_siblings_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    (witness.inputs.getD input.val default).siblings.length = 32 ∧
      ∀ sibling, sibling ∈ (witness.inputs.getD input.val default).siblings → ExactWords 7 sibling := by
  have entry := valid.2.1.2.2.1 input.val input.isLt
  change _ ∧ (if (witness.inputs.getD input.val default).active = 0 then
    ZeroInputWitness (witness.inputs.getD input.val default) else _) at entry
  split at entry
  · obtain ⟨_, _, _, _, _, siblingLength, siblings, _, _⟩ := entry.2
    exact ⟨siblingLength, fun sibling member => (siblings sibling member).1⟩
  · obtain ⟨_, _, _, _, siblingLength, siblings, _⟩ := entry.2
    exact ⟨siblingLength, siblings⟩

theorem typed_sibling_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (level : Fin 32) :
    ExactWords 7 ((witness.inputs.getD input.val default).siblings.getD level.val []) := by
  have shape := typed_siblings_exact statement witness valid input
  have bound : level.val < (witness.inputs.getD input.val default).siblings.length := by
    rw [shape.1]
    exact level.isLt
  have present : (witness.inputs.getD input.val default).siblings[level.val]? =
      some ((witness.inputs.getD input.val default).siblings.getD level.val []) :=
    getD_real_entry _ [] level.val bound
  exact shape.2 _ (List.mem_of_getElem? present)

theorem sibling_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (input : Fin 2) (level : Fin 32) (limb : Nat) :
    siblingWord witness input.val level.val limb < fieldModulus :=
  HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows.exact_words_getD_canonical _ 7 limb
    (typed_sibling_exact statement witness valid input level)

theorem typed_sibling_word_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (input : Fin 2) (level : Fin 32) (limb : Fin 7) :
    ((witness.inputs.getD input.val default).siblings.getD level.val [])[limb.val]? =
      some (siblingWord witness input.val level.val limb.val) := by
  apply getD_real_entry _ 0 limb.val
  rw [(typed_sibling_exact statement witness valid input level).1]
  exact limb.isLt

def direction (witness : V8Witness) (input level : Nat) : Nat :=
  positionBit (witness.inputs.getD input default).position level

theorem direction_boolean (witness : V8Witness) (input level : Nat) :
    direction witness input level = 0 ∨ direction witness input level = 1 :=
  position_bit_boolean _ _

def orientedWord (live : LiveInitialStates) (witness : V8Witness)
    (input level limb component : Nat) : Nat :=
  let previous := callFinalWord live (previousCall input level) limb
  let sibling := siblingWord witness input level limb
  let bit := direction witness input level
  if component = 0 then previous
  else if component = 1 then (if bit = 0 then previous else sibling)
  else if component = 2 then (if bit = 0 then sibling else previous)
  else bit

theorem oriented_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (live : LiveInitialStates)
    (input : Fin 2) (level : Fin 32) (limb component : Nat) :
    orientedWord live witness input.val level.val limb component < fieldModulus := by
  have previous := call_final_word_canonical live (previousCall input.val level.val) limb
  have sibling := sibling_word_canonical statement witness valid input level limb
  have bit : direction witness input.val level.val < fieldModulus := by
    rcases direction_boolean witness input.val level.val with zero | one
    · rw [zero]; decide
    · rw [one]; decide
  dsimp only [orientedWord]
  split
  · exact previous
  · split
    · split <;> assumption
    · split
      · split <;> assumption
      · exact bit

def nonSingle (witness : V8Witness) : Nat :=
  if witness.authorization.mode = .singleKey then 0 else 1

def policyWord (live : LiveInitialStates) (witness : V8Witness) (limb : Nat) : Nat :=
  if witness.authorization.mode = .singleKey then 0 else callFinalWord live 97 limb

def inlineSlot (input level limb : Nat) : Nat := (input * 32 + level) * 7 + limb

def inlineCell (live : LiveInitialStates) (witness : V8Witness) (row lane : Nat) : Nat :=
  if row < 28 then
    let slot := row / 4 * 64 + lane
    orientedWord live witness (slot / 224) ((slot % 224) / 7) (slot % 7) (row % 4)
  else if lane < 7 then
    if row = 28 then policyWord live witness lane
    else if row = 29 then callFinalWord live 97 lane
    else nonSingle witness
  else 0

def inlineRows (live : LiveInitialStates) (witness : V8Witness) : List (List Nat) :=
  List.ofFn fun row : Fin 31 => List.ofFn fun lane : Fin 64 => inlineCell live witness row.val lane.val

def inlinePacked (live : LiveInitialStates) (witness : V8Witness) : List Nat :=
  (inlineRows live witness).flatten

def placeInline (before after : List Nat) (live : LiveInitialStates) (witness : V8Witness) : List Nat :=
  before ++ (inlinePacked live witness ++ after)

theorem inline_slot_inverse (input level limb : Nat)
    (inputBound : input < 2) (levelBound : level < 32) (limbBound : limb < 7) :
    inlineSlot input level limb < 448 ∧
      inlineSlot input level limb / 224 = input ∧
      (inlineSlot input level limb % 224) / 7 = level ∧
      inlineSlot input level limb % 7 = limb := by
  unfold inlineSlot
  omega

theorem inline_slot_complete (slot : Fin 448) :
    slot.val / 224 < 2 ∧ (slot.val % 224) / 7 < 32 ∧ slot.val % 7 < 7 ∧
      inlineSlot (slot.val / 224) ((slot.val % 224) / 7) (slot.val % 7) = slot.val := by
  unfold inlineSlot
  omega

theorem inline_orientation_cell (live : LiveInitialStates) (witness : V8Witness)
    (input level limb component : Nat) (inputBound : input < 2)
    (levelBound : level < 32) (limbBound : limb < 7) (componentBound : component < 4) :
    inlineCell live witness ((inlineSlot input level limb / 64) * 4 + component)
        (inlineSlot input level limb % 64) = orientedWord live witness input level limb component := by
  have inverse := inline_slot_inverse input level limb inputBound levelBound limbBound
  have rowBound : inlineSlot input level limb / 64 * 4 + component < 28 := by omega
  have group : (inlineSlot input level limb / 64 * 4 + component) / 4 =
      inlineSlot input level limb / 64 := by omega
  have part : (inlineSlot input level limb / 64 * 4 + component) % 4 = component := by omega
  have reassembled : inlineSlot input level limb / 64 * 64 + inlineSlot input level limb % 64 =
      inlineSlot input level limb := by omega
  simp only [inlineCell, if_pos rowBound, group, part, reassembled,
    inverse.2.1, inverse.2.2.1, inverse.2.2.2]

theorem inline_cell_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (live : LiveInitialStates)
    (row lane : Nat) (rowBound : row < 31) (laneBound : lane < 64) :
    inlineCell live witness row lane < fieldModulus := by
  unfold inlineCell
  split
  · have slotBound : row / 4 * 64 + lane < 448 := by omega
    exact oriented_word_canonical statement witness valid live
      ⟨(row / 4 * 64 + lane) / 224, by omega⟩
      ⟨((row / 4 * 64 + lane) % 224) / 7, by omega⟩ _ _
  · split
    · split
      · unfold policyWord
        split
        · decide
        · exact call_final_word_canonical _ _ _
      · split
        · exact call_final_word_canonical _ _ _
        · unfold nonSingle
          split <;> decide
    · decide

theorem inline_rows_shape (live : LiveInitialStates) (witness : V8Witness) :
    (inlineRows live witness).length = 31 ∧
      ∀ row, row ∈ inlineRows live witness → row.length = 64 := by
  constructor
  · simp only [inlineRows, List.length_ofFn]
  · intro row member
    obtain ⟨index, rfl⟩ := List.mem_ofFn.mp member
    exact List.length_ofFn

theorem inline_rows_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (live : LiveInitialStates) :
    ∀ row, row ∈ inlineRows live witness → ∀ value, value ∈ row → value < fieldModulus := by
  intro row member value valueMember
  obtain ⟨rowIndex, rfl⟩ := List.mem_ofFn.mp member
  obtain ⟨lane, rfl⟩ := List.mem_ofFn.mp valueMember
  exact inline_cell_canonical statement witness valid live rowIndex.val lane.val rowIndex.isLt lane.isLt

theorem inline_packed_length (live : LiveInitialStates) (witness : V8Witness) :
    (inlinePacked live witness).length = 1984 := by
  unfold inlinePacked
  rw [rectangular_flatten_length _ 64 (inline_rows_shape live witness).2,
    (inline_rows_shape live witness).1]

theorem inline_packed_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (live : LiveInitialStates) :
    ExactWords 1984 (inlinePacked live witness) := by
  refine ⟨inline_packed_length live witness, ?_⟩
  intro value member
  obtain ⟨row, rowMember, valueMember⟩ := List.mem_flatten.mp member
  exact inline_rows_canonical statement witness valid live row rowMember value valueMember

theorem inline_row_word (live : LiveInitialStates) (witness : V8Witness)
    (row lane : Nat) (rowBound : row < 31) (laneBound : lane < 64) :
    ((inlineRows live witness).getD row []).getD lane 0 = inlineCell live witness row lane := by
  unfold inlineRows
  rw [ofFn_getD _ [] row rowBound, ofFn_getD _ 0 lane laneBound]

theorem placed_inline_cell (before after : List Nat) (live : LiveInitialStates) (witness : V8Witness)
    (beforeLength : before.length = 16128) (row lane : Nat)
    (rowBound : row < 31) (laneBound : lane < 64) :
    (placeInline before after live witness).getD (16128 + (row * 64 + lane)) 0 =
      inlineCell live witness row lane := by
  have prefixOffset := getD_append_offset before (inlinePacked live witness ++ after) (row * 64 + lane)
  rw [beforeLength] at prefixOffset
  rw [show placeInline before after live witness = before ++ (inlinePacked live witness ++ after) from rfl,
    prefixOffset, getD_append_left _ _ _ (by rw [inline_packed_length]; omega)]
  unfold inlinePacked
  rw [rectangular_flatten_getD _ 64 row lane (inline_rows_shape live witness).2
    (by rw [(inline_rows_shape live witness).1]; exact rowBound) laneBound]
  exact inline_row_word live witness row lane rowBound laneBound

/-- The literal source inline_index formula, retaining its row/lane orientation. -/
def inlineIndex (input level limb component : Nat) : Nat :=
  (252 + (inlineSlot input level limb / 64) * 4 + component) * 64 +
    inlineSlot input level limb % 64

theorem placed_all_orientation_words (before after : List Nat) (live : LiveInitialStates)
    (witness : V8Witness) (beforeLength : before.length = 16128)
    (input : Fin 2) (level : Fin 32) (limb : Fin 7) (component : Fin 4) :
    (placeInline before after live witness).getD
        (inlineIndex input.val level.val limb.val component.val) 0 =
      orientedWord live witness input.val level.val limb.val component.val := by
  have inverse := inline_slot_inverse input.val level.val limb.val input.isLt level.isLt limb.isLt
  have address : inlineIndex input.val level.val limb.val component.val =
      16128 + (((inlineSlot input.val level.val limb.val / 64) * 4 + component.val) * 64 +
        inlineSlot input.val level.val limb.val % 64) := by
    unfold inlineIndex
    omega
  rw [address, placed_inline_cell before after live witness beforeLength _ _ (by omega) (by omega)]
  exact inline_orientation_cell live witness input.val level.val limb.val component.val
    input.isLt level.isLt limb.isLt component.isLt

theorem oriented_components (live : LiveInitialStates) (witness : V8Witness)
    (input level limb : Nat) :
    orientedWord live witness input level limb 0 = callFinalWord live (previousCall input level) limb ∧
    orientedWord live witness input level limb 1 =
      (if direction witness input level = 0 then callFinalWord live (previousCall input level) limb
        else siblingWord witness input level limb) ∧
    orientedWord live witness input level limb 2 =
      (if direction witness input level = 0 then siblingWord witness input level limb
        else callFinalWord live (previousCall input level) limb) ∧
    orientedWord live witness input level limb 3 = direction witness input level := by
  simp [orientedWord]

theorem inline_right_index_is_existing_source_index (input level limb : Nat) :
    inlineIndex input level limb 2 =
      HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness.inlineRightAddress input level limb := by
  unfold inlineIndex inlineSlot
    HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness.inlineRightAddress
  dsimp only
  have slot : (input * 32 + level) * 7 + limb = 224 * input + 7 * level + limb := by omega
  rw [slot]
  omega

theorem placed_right_at_existing_source_index (before after : List Nat) (live : LiveInitialStates)
    (witness : V8Witness) (beforeLength : before.length = 16128)
    (input : Fin 2) (level : Fin 32) (limb : Fin 7) :
    (placeInline before after live witness).getD
        (HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness.inlineRightAddress input.val level.val limb.val) 0 =
      (if direction witness input.val level.val = 0 then siblingWord witness input.val level.val limb.val
        else callFinalWord live (previousCall input.val level.val) limb.val) := by
  rw [← inline_right_index_is_existing_source_index]
  have result := placed_all_orientation_words before after live witness beforeLength input level limb ⟨2, by decide⟩
  exact result.trans (oriented_components live witness input.val level.val limb.val).2.2.1

theorem call_final_word_at_existing_hash_index (before after : List Nat) (live : LiveInitialStates)
    (beforeLength : before.length = 18112) (call limb : Nat)
    (callBound : call < 128) (limbBound : limb < 7) :
    (placeHashBlock before live after).getD (Poseidon2V8DecoderRefinement.hashFinalIndex call limb) 0 =
      callFinalWord live call limb := by
  exact (placed_final_at_decoder_index before after live beforeLength call limb callBound (by omega)).trans
    (call_final_word_is_permutation live call limb).symm

theorem inline_policy_cells (live : LiveInitialStates) (witness : V8Witness) (limb : Fin 7) :
    inlineCell live witness 28 limb.val = policyWord live witness limb.val ∧
    inlineCell live witness 29 limb.val = callFinalWord live 97 limb.val ∧
    inlineCell live witness 30 limb.val = nonSingle witness := by
  simp [inlineCell, limb.isLt]

theorem placed_policy_cells (before after : List Nat) (live : LiveInitialStates) (witness : V8Witness)
    (beforeLength : before.length = 16128) (limb : Fin 7) :
    (placeInline before after live witness).getD (17920 + limb.val) 0 = policyWord live witness limb.val ∧
    (placeInline before after live witness).getD (17984 + limb.val) 0 = callFinalWord live 97 limb.val ∧
    (placeInline before after live witness).getD (18048 + limb.val) 0 = nonSingle witness := by
  have first := placed_inline_cell before after live witness beforeLength 28 limb.val (by decide) (by omega)
  have second := placed_inline_cell before after live witness beforeLength 29 limb.val (by decide) (by omega)
  have third := placed_inline_cell before after live witness beforeLength 30 limb.val (by decide) (by omega)
  simpa only [Nat.reduceMul, ← Nat.add_assoc, Nat.reduceAdd] using
    And.intro (first.trans (inline_policy_cells live witness limb).1)
    (And.intro
    (second.trans (inline_policy_cells live witness limb).2.1)
    (third.trans (inline_policy_cells live witness limb).2.2))

theorem inline_policy_padding_zero (live : LiveInitialStates) (witness : V8Witness)
    (row lane : Nat) (policyRow : 28 ≤ row) (rowBound : row < 31)
    (padding : 7 ≤ lane) (laneBound : lane < 64) : inlineCell live witness row lane = 0 := by
  simp only [inlineCell, if_neg (by omega : ¬row < 28), if_neg (by omega : ¬lane < 7)]

theorem placed_policy_padding_zero (before after : List Nat) (live : LiveInitialStates)
    (witness : V8Witness) (beforeLength : before.length = 16128) (row : Fin 3) (lane : Fin 57) :
    (placeInline before after live witness).getD (17920 + row.val * 64 + (7 + lane.val)) 0 = 0 := by
  have address : 17920 + row.val * 64 + (7 + lane.val) =
      16128 + ((28 + row.val) * 64 + (7 + lane.val)) := by omega
  rw [address, placed_inline_cell before after live witness beforeLength _ _ (by omega) (by omega)]
  exact inline_policy_padding_zero live witness _ _ (by omega) (by omega) (by omega) (by omega)

theorem policy_single_is_zero (live : LiveInitialStates) (witness : V8Witness)
    (single : witness.authorization.mode = .singleKey) (limb : Nat) :
    policyWord live witness limb = 0 ∧ nonSingle witness = 0 := by
  simp only [policyWord, nonSingle, if_pos single, and_self]

theorem policy_nonsingle_is_computed (live : LiveInitialStates) (witness : V8Witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) (limb : Nat) :
    policyWord live witness limb = callFinalWord live 97 limb ∧ nonSingle witness = 1 := by
  simp only [policyWord, nonSingle, if_neg nonsingle, and_self]

theorem placed_before_unchanged (before after : List Nat) (live : LiveInitialStates) (witness : V8Witness)
    (index : Nat) (bound : index < before.length) :
    (placeInline before after live witness).getD index 0 = before.getD index 0 :=
  getD_append_left before _ index bound

theorem placed_after_unchanged (before after : List Nat) (live : LiveInitialStates) (witness : V8Witness)
    (beforeLength : before.length = 16128) (index : Nat) :
    (placeInline before after live witness).getD (18112 + index) 0 = after.getD index 0 := by
  have offset : 18112 + index = before.length + ((inlinePacked live witness).length + index) := by
    rw [beforeLength, inline_packed_length]
    omega
  rw [offset]
  unfold placeInline
  rw [getD_append_offset, getD_append_offset]

theorem placed_full_length (before after : List Nat) (live : LiveInitialStates) (witness : V8Witness)
    (beforeLength : before.length = 16128) (afterLength : after.length = 25792) :
    (placeInline before after live witness).length = 43904 := by
  simp only [placeInline, List.length_append, beforeLength, inline_packed_length, afterLength]


end HegemonCrypto.SmallWood.V8Smz9SourceInlineRows

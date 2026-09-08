import HegemonCrypto.SmallWoodV8Smz9SourceDenseTyped
import Hegemon.Transaction.Poseidon2V8DecoderRefinement

/-! Construct only source assignment rows 0 through 91, from the fixed typed
statement/witness. Every row repeats in 64 lanes; the remaining packed words
are arbitrary caller data. No accepted packed assignment or root-evaluation
premise is used. Natural division/modulo describes position bits; correspondence
to the Rust u64 shift-and implementation remains a separate refinement task. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization

set_option maxRecDepth 10000
set_option maxHeartbeats 600000
set_option Elab.async false

def positionBit (position bit : Nat) : Nat := (position / 2 ^ bit) % 2

theorem position_bit_boolean (position bit : Nat) :
    positionBit position bit = 0 ∨ positionBit position bit = 1 := by
  have bound := Nat.mod_lt (position / 2 ^ bit) (by decide : 0 < 2)
  unfold positionBit
  omega

theorem typed_input_asset_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    (witness.inputs.getD slot.val default).note.assetId < fieldModulus := by
  have input := valid.2.1.2.2.1 slot.val slot.isLt
  change _ ∧ (if (witness.inputs.getD slot.val default).active = 0 then
    ZeroInputWitness (witness.inputs.getD slot.val default) else _) at input
  split at input
  · rw [input.2.2.2.2.1.2.1]
    decide
  · exact input.2.1.2.1

theorem typed_output_asset_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    (witness.outputs.getD slot.val default).note.assetId < fieldModulus := by
  have output := valid.2.1.2.2.2.1 slot.val slot.isLt
  change _ ∧ (if (witness.outputs.getD slot.val default).active = 0 then
    ZeroOutputWitness (witness.outputs.getD slot.val default) else _) at output
  split at output
  · rw [output.2.2.1.2.1]
    decide
  · exact output.2.1.2.1

theorem typed_output_authorization_key_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    ExactWords 4 (witness.outputs.getD slot.val default).note.authorizationKey := by
  have output := valid.2.1.2.2.2.1 slot.val slot.isLt
  change _ ∧ (if (witness.outputs.getD slot.val default).active = 0 then
    ZeroOutputWitness (witness.outputs.getD slot.val default) else _) at output
  split at output
  · exact output.2.2.1.2.2.2.2.1
  · exact output.2.1.2.2.2.2.1

theorem typed_encoded_public_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords 120 (encodePublicStatement statement) := by
  have canonicalPublic := valid.1
  unfold CanonicalPublicStatement at canonicalPublic
  tauto

theorem typed_input_position_bounded (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    (witness.inputs.getD slot.val default).position < 2 ^ 32 := by
  have input := valid.2.1.2.2.1 slot.val slot.isLt
  change _ ∧ (if (witness.inputs.getD slot.val default).active = 0 then
    ZeroInputWitness (witness.inputs.getD slot.val default) else _) at input
  split at input
  · rw [input.2.2.2.2.2.1]
    decide
  · exact input.2.2.2.2.1

theorem exact_words_getD_canonical (words : List Nat) (count index : Nat)
    (exact : ExactWords count words) : words.getD index 0 < fieldModulus :=
  HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials.canonical_getD words exact.2 index

theorem typed_admission_lengths (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    witness.inputs.length = 2 ∧ witness.outputs.length = 2 ∧
      (encodePublicStatement statement).length = 120 :=
  ⟨valid.2.1.1, valid.2.1.2.1, (typed_encoded_public_exact statement witness valid).1⟩

private theorem getD_real_entry {α : Type} (values : List α) (fallback : α)
    (index : Nat) (bound : index < values.length) :
    values[index]? = some (values.getD index fallback) := by
  simp [List.getD, bound]

theorem typed_input_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    witness.inputs[slot.val]? = some (witness.inputs.getD slot.val default) :=
  getD_real_entry _ _ _ (by rw [(typed_admission_lengths statement witness valid).1]; exact slot.isLt)

theorem typed_output_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) :
    witness.outputs[slot.val]? = some (witness.outputs.getD slot.val default) :=
  getD_real_entry _ _ _ (by rw [(typed_admission_lengths statement witness valid).2.1]; exact slot.isLt)

theorem typed_output_key_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) (limb : Fin 4) :
    (witness.outputs.getD slot.val default).note.authorizationKey[limb.val]? =
      some ((witness.outputs.getD slot.val default).note.authorizationKey.getD limb.val 0) :=
  getD_real_entry _ _ _ (by
    rw [(typed_output_authorization_key_exact statement witness valid slot).1]
    exact limb.isLt)

theorem typed_ciphertext_entry_present (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) (limb : Fin 6) :
    (encodePublicStatement statement)[32 + slot.val * 6 + limb.val]? =
      some ((encodePublicStatement statement).getD (32 + slot.val * 6 + limb.val) 0) :=
  getD_real_entry _ _ _ (by rw [(typed_admission_lengths statement witness valid).2.2]; omega)

/-- One source input block: value, asset, then the 32 position bits. -/
def inputWord (witness : V8Witness) (slot offset : Nat) : Nat :=
  let input := witness.inputs.getD slot default
  if offset = 0 then input.note.value
  else if offset = 1 then input.note.assetId
  else positionBit input.position (offset - 2)

/-- One source output block: value, asset, six encoded-public ciphertext words,
then four private authorization-key limbs. -/
def outputWord (statement : V8PublicStatement) (witness : V8Witness)
    (slot offset : Nat) : Nat :=
  let output := witness.outputs.getD slot default
  if offset = 0 then output.note.value
  else if offset = 1 then output.note.assetId
  else if offset < 8 then (encodePublicStatement statement).getD (32 + slot * 6 + (offset - 2)) 0
  else output.note.authorizationKey.getD (offset - 8) 0

/-- Exact source dispatch for the bounded 92-row prefix; no values beyond that
prefix are assigned by the construction. -/
def sourceWord (statement : V8PublicStatement) (witness : V8Witness) (row : Nat) : Nat :=
  if row < 68 then inputWord witness (row / 34) (row % 34)
  else outputWord statement witness ((row - 68) / 12) ((row - 68) % 12)

def replicatedRows (statement : V8PublicStatement) (witness : V8Witness) : List (List Nat) :=
  List.ofFn fun row : Fin 92 => List.replicate 64 (sourceWord statement witness row.val)

def packedPrefix (statement : V8PublicStatement) (witness : V8Witness) : List Nat :=
  (replicatedRows statement witness).flatten

def placePrefix (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) : List Nat := packedPrefix statement witness ++ tail

theorem input_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) (offset : Nat) :
    inputWord witness slot.val offset < fieldModulus := by
  unfold inputWord
  split
  · exact lt_trans (typed_input_value_bounded statement witness valid slot) (by decide)
  · split
    · exact typed_input_asset_canonical statement witness valid slot
    · rcases position_bit_boolean (witness.inputs.getD slot.val default).position (offset - 2) with zero | one
      · rw [zero]; decide
      · rw [one]; decide

theorem output_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 2) (offset : Nat) :
    outputWord statement witness slot.val offset < fieldModulus := by
  unfold outputWord
  split
  · exact lt_trans (typed_output_value_bounded statement witness valid slot) (by decide)
  · split
    · exact typed_output_asset_canonical statement witness valid slot
    · split
      · exact exact_words_getD_canonical _ 120 _ (typed_encoded_public_exact statement witness valid)
      · exact exact_words_getD_canonical _ 4 _ (typed_output_authorization_key_exact statement witness valid slot)

theorem source_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (row : Nat) (bound : row < 92) :
    sourceWord statement witness row < fieldModulus := by
  unfold sourceWord
  split
  · exact input_word_canonical statement witness valid ⟨row / 34, by omega⟩ _
  · exact output_word_canonical statement witness valid ⟨(row - 68) / 12, by omega⟩ _

theorem source_input_word (statement : V8PublicStatement) (witness : V8Witness)
    (slot offset : Nat) (slotBound : slot < 2) (offsetBound : offset < 34) :
    sourceWord statement witness (34 * slot + offset) = inputWord witness slot offset := by
  have rowBound : 34 * slot + offset < 68 := by omega
  have quotient : (34 * slot + offset) / 34 = slot := by omega
  have remainder : (34 * slot + offset) % 34 = offset := by omega
  simp only [sourceWord, if_pos rowBound, quotient, remainder]

theorem source_output_word (statement : V8PublicStatement) (witness : V8Witness)
    (slot offset : Nat) (slotBound : slot < 2) (offsetBound : offset < 12) :
    sourceWord statement witness (68 + 12 * slot + offset) = outputWord statement witness slot offset := by
  have rowBound : ¬68 + 12 * slot + offset < 68 := by omega
  have difference : 68 + 12 * slot + offset - 68 = 12 * slot + offset := by omega
  have quotient : (12 * slot + offset) / 12 = slot := by omega
  have remainder : (12 * slot + offset) % 12 = offset := by omega
  simp only [sourceWord, if_neg rowBound, difference, quotient, remainder]

theorem replicated_rows_shape (statement : V8PublicStatement) (witness : V8Witness) :
    (replicatedRows statement witness).length = 92 ∧
      ∀ row, row ∈ replicatedRows statement witness → row.length = 64 := by
  constructor
  · simp [replicatedRows]
  · intro row member
    obtain ⟨index, rfl⟩ := List.mem_ofFn.mp member
    simp

theorem replicated_rows_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ∀ row, row ∈ replicatedRows statement witness → ∀ word, word ∈ row → word < fieldModulus := by
  intro row member word wordMember
  obtain ⟨index, rfl⟩ := List.mem_ofFn.mp member
  have same : word = sourceWord statement witness index.val := by simpa using List.mem_replicate.mp wordMember
  rw [same]
  exact source_word_canonical statement witness valid index.val index.isLt

private theorem ofFn_getD {α : Type} {count : Nat} (f : Fin count → α)
    (fallback : α) (index : Nat) (bound : index < count) :
    (List.ofFn f).getD index fallback = f ⟨index, bound⟩ := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn, dif_pos bound, Option.getD_some]

private theorem getD_append_left (left right : List Nat) (index : Nat) (bound : index < left.length) :
    (left ++ right).getD index 0 = left.getD index 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_append_left bound]

private theorem getD_append_offset (left right : List Nat) (index : Nat) :
    (left ++ right).getD (left.length + index) 0 = right.getD index 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_append_right (by omega :
    left.length ≤ left.length + index), Nat.add_sub_cancel_left]

private theorem rectangular_flatten_length (rows : List (List Nat)) (columns : Nat)
    (shape : ∀ row, row ∈ rows → row.length = columns) :
    rows.flatten.length = rows.length * columns := by
  induction rows with
  | nil => simp
  | cons head tail ih =>
      have headLength := shape head (by simp)
      have tailShape := fun row member => shape row (List.mem_cons_of_mem head member)
      simp only [List.flatten_cons, List.length_append, List.length_cons,
        headLength, ih tailShape, Nat.add_mul, Nat.one_mul]
      omega

private theorem rectangular_flatten_getD (rows : List (List Nat)) (columns row lane : Nat)
    (shape : ∀ entry, entry ∈ rows → entry.length = columns)
    (rowBound : row < rows.length) (laneBound : lane < columns) :
    rows.flatten.getD (row * columns + lane) 0 = (rows.getD row []).getD lane 0 := by
  induction rows generalizing row with
  | nil => simp at rowBound
  | cons head tail ih =>
      have headLength := shape head (by simp)
      have tailShape := fun entry member => shape entry (List.mem_cons_of_mem head member)
      cases row with
      | zero =>
          simp only [Nat.zero_mul, Nat.zero_add, List.flatten_cons, List.getD_cons_zero]
          exact getD_append_left head tail.flatten lane (by omega)
      | succ row =>
          have offset : (row + 1) * columns + lane = head.length + (row * columns + lane) := by
            rw [headLength, Nat.add_mul, Nat.one_mul]
            omega
          simp only [List.flatten_cons, List.getD_cons_succ, offset, getD_append_offset]
          exact ih row tailShape (by simpa using rowBound)

theorem replicated_row_word (statement : V8PublicStatement) (witness : V8Witness)
    (row lane : Nat) (rowBound : row < 92) (laneBound : lane < 64) :
    ((replicatedRows statement witness).getD row []).getD lane 0 =
      sourceWord statement witness row := by
  unfold replicatedRows
  rw [ofFn_getD _ [] row rowBound]
  simp only [List.getD_eq_getElem?_getD, List.getElem?_replicate, if_pos laneBound, Option.getD_some]

theorem packed_prefix_length (statement : V8PublicStatement) (witness : V8Witness) :
    (packedPrefix statement witness).length = 5888 := by
  unfold packedPrefix
  rw [rectangular_flatten_length _ 64 (replicated_rows_shape statement witness).2,
    (replicated_rows_shape statement witness).1]

theorem packed_prefix_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords 5888 (packedPrefix statement witness) := by
  refine ⟨packed_prefix_length statement witness, ?_⟩
  intro value member
  obtain ⟨row, rowMember, valueMember⟩ := List.mem_flatten.mp member
  exact replicated_rows_canonical statement witness valid row rowMember value valueMember

theorem placed_length (statement : V8PublicStatement) (witness : V8Witness) (tail : List Nat) :
    (placePrefix statement witness tail).length = 5888 + tail.length := by
  simp only [placePrefix, List.length_append, packed_prefix_length]

theorem placed_full_length (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (tailLength : tail.length = 38016) :
    (placePrefix statement witness tail).length = 43904 := by
  rw [placed_length, tailLength]

/-- All untouched words retain their original values, including noncanonical
and nonzero caller data; no assumption is made about the unimplemented tail. -/
theorem placed_tail_unchanged (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (index : Nat) :
    (placePrefix statement witness tail).getD (5888 + index) 0 = tail.getD index 0 := by
  have result := getD_append_offset (packedPrefix statement witness) tail index
  rw [packed_prefix_length] at result
  exact result

theorem placed_source_word (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (row lane : Nat) (rowBound : row < 92) (laneBound : lane < 64) :
    (placePrefix statement witness tail).getD
        (Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex row + lane) 0 =
      sourceWord statement witness row := by
  simp only [placePrefix, Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add]
  rw [getD_append_left _ _ _ (by rw [packed_prefix_length]; omega)]
  unfold packedPrefix
  rw [rectangular_flatten_getD _ 64 row lane (replicated_rows_shape statement witness).2
    (by rw [(replicated_rows_shape statement witness).1]; exact rowBound) laneBound]
  exact replicated_row_word statement witness row lane rowBound laneBound

theorem placed_input_value (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (slot lane : Nat) (slotBound : slot < 2) (laneBound : lane < 64) :
    (placePrefix statement witness tail).getD
        (Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex (34 * slot) + lane) 0 =
      (witness.inputs.getD slot default).note.value := by
  rw [placed_source_word statement witness tail _ lane (by omega) laneBound]
  have result := source_input_word statement witness slot 0 slotBound (by decide)
  simpa only [Nat.add_zero, inputWord, ↓reduceIte] using result

theorem placed_input_asset (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (slot lane : Nat) (slotBound : slot < 2) (laneBound : lane < 64) :
    (placePrefix statement witness tail).getD
        (Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex (34 * slot + 1) + lane) 0 =
      (witness.inputs.getD slot default).note.assetId := by
  rw [placed_source_word statement witness tail _ lane (by omega) laneBound,
    source_input_word statement witness slot 1 slotBound (by decide)]
  simp [inputWord]

theorem placed_input_direction (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (slot bit lane : Nat) (slotBound : slot < 2)
    (bitBound : bit < 32) (laneBound : lane < 64) :
    (placePrefix statement witness tail).getD
        (Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex (34 * slot + (2 + bit)) + lane) 0 =
      positionBit (witness.inputs.getD slot default).position bit := by
  rw [placed_source_word statement witness tail _ lane (by omega) laneBound,
    source_input_word statement witness slot (2 + bit) slotBound (by omega)]
  simp only [inputWord, if_neg (by omega : ¬2 + bit = 0), if_neg (by omega : ¬2 + bit = 1),
    Nat.add_sub_cancel_left]

theorem placed_output_value (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (slot lane : Nat) (slotBound : slot < 2) (laneBound : lane < 64) :
    (placePrefix statement witness tail).getD
        (Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex (68 + 12 * slot) + lane) 0 =
      (witness.outputs.getD slot default).note.value := by
  rw [placed_source_word statement witness tail _ lane (by omega) laneBound]
  have result := source_output_word statement witness slot 0 slotBound (by decide)
  simpa only [Nat.add_zero, outputWord, ↓reduceIte] using result

theorem placed_output_asset (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (slot lane : Nat) (slotBound : slot < 2) (laneBound : lane < 64) :
    (placePrefix statement witness tail).getD
        (Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex (68 + 12 * slot + 1) + lane) 0 =
      (witness.outputs.getD slot default).note.assetId := by
  rw [placed_source_word statement witness tail _ lane (by omega) laneBound,
    source_output_word statement witness slot 1 slotBound (by decide)]
  simp [outputWord]

theorem placed_output_ciphertext (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (slot limb lane : Nat) (slotBound : slot < 2)
    (limbBound : limb < 6) (laneBound : lane < 64) :
    (placePrefix statement witness tail).getD
        (Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex (68 + 12 * slot + (2 + limb)) + lane) 0 =
      (encodePublicStatement statement).getD (32 + slot * 6 + limb) 0 := by
  rw [placed_source_word statement witness tail _ lane (by omega) laneBound,
    source_output_word statement witness slot (2 + limb) slotBound (by omega)]
  simp only [outputWord, if_neg (by omega : ¬2 + limb = 0), if_neg (by omega : ¬2 + limb = 1),
    if_pos (by omega : 2 + limb < 8), Nat.add_sub_cancel_left]

theorem placed_output_authorization_key (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (slot limb lane : Nat) (slotBound : slot < 2)
    (limbBound : limb < 4) (laneBound : lane < 64) :
    (placePrefix statement witness tail).getD
        (Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex (68 + 12 * slot + (8 + limb)) + lane) 0 =
      (witness.outputs.getD slot default).note.authorizationKey.getD limb 0 := by
  rw [placed_source_word statement witness tail _ lane (by omega) laneBound,
    source_output_word statement witness slot (8 + limb) slotBound (by omega)]
  simp only [outputWord, if_neg (by omega : ¬8 + limb = 0), if_neg (by omega : ¬8 + limb = 1),
    if_neg (by omega : ¬8 + limb < 8), Nat.add_sub_cancel_left]

theorem placed_private_value_addresses (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) :
    (placePrefix statement witness tail).getD 0 0 = (witness.inputs.getD 0 default).note.value ∧
    (placePrefix statement witness tail).getD 2176 0 = (witness.inputs.getD 1 default).note.value ∧
    (placePrefix statement witness tail).getD 4352 0 = (witness.outputs.getD 0 default).note.value ∧
    (placePrefix statement witness tail).getD 5120 0 = (witness.outputs.getD 1 default).note.value := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · exact placed_input_value statement witness tail 0 0 (by decide) (by decide)
  · exact placed_input_value statement witness tail 1 0 (by decide) (by decide)
  · exact placed_output_value statement witness tail 0 0 (by decide) (by decide)
  · exact placed_output_value statement witness tail 1 0 (by decide) (by decide)


end HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows

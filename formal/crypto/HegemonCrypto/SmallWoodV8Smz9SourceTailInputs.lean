import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputs

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTail

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization (auth_exact_words_getD)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

/-- Rust source_fields orders config, siblings, issuer secret, then before counters. -/
def sourcePrivateIndex (slot : Nat) : Nat :=
  if slot < 55 then slot else if slot < 90 then slot + 4 else slot - 35

def typedPrivateIndex (slot : Nat) : Nat :=
  if slot < 55 then slot else if slot < 59 then slot + 35 else slot - 4

theorem source_private_index_bound (slot : Nat) (bound : slot < 94) :
    sourcePrivateIndex slot < 94 := by
  unfold sourcePrivateIndex
  split_ifs <;> omega

theorem typed_private_index_bound (slot : Nat) (bound : slot < 94) :
    typedPrivateIndex slot < 94 := by
  unfold typedPrivateIndex
  split_ifs <;> omega

theorem source_private_reorder_roundtrip (slot : Nat) (bound : slot < 94) :
    typedPrivateIndex (sourcePrivateIndex slot) = slot := by
  unfold sourcePrivateIndex typedPrivateIndex
  split_ifs <;> omega

theorem typed_private_reorder_roundtrip (slot : Nat) (bound : slot < 94) :
    sourcePrivateIndex (typedPrivateIndex slot) = slot := by
  unfold sourcePrivateIndex typedPrivateIndex
  split_ifs <;> omega

theorem source_private_reorder_injective (left right : Nat)
    (leftBound : left < 94) (rightBound : right < 94)
    (same : sourcePrivateIndex left = sourcePrivateIndex right) : left = right := by
  rw [← source_private_reorder_roundtrip left leftBound,
    ← source_private_reorder_roundtrip right rightBound, same]

def stableSourceWord (statement : V8PublicStatement) (witness : V8Witness) (slot : Nat) : Nat :=
  if slot < 94 then stableWitnessWord witness.stablecoin (sourcePrivateIndex slot)
  else if slot < 112 then wordAt (encodePublicStatement statement) (slot - 31)
  else if slot < 116 then wordAt (witness.inputs.getD 0 default).spendKey (slot - 112)
  else if slot < 120 then wordAt (witness.inputs.getD 1 default).spendKey (slot - 116)
  else 0

def stableSourcePacked (statement : V8PublicStatement) (witness : V8Witness) : List Nat :=
  List.ofFn fun slot : Fin 128 => stableSourceWord statement witness slot.val

theorem stable_source_shape (statement : V8PublicStatement) (witness : V8Witness) :
    (stableSourcePacked statement witness).length = 2 * 64 := by
  simp only [stableSourcePacked, List.length_ofFn]

theorem stable_source_packed_readback (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 128) (fallback : Nat) :
    (stableSourcePacked statement witness).getD slot.val fallback =
      stableSourceWord statement witness slot.val := by
  simp only [stableSourcePacked, List.getD_eq_getElem?_getD, List.getElem?_ofFn,
    slot.isLt, dif_pos, Option.getD_some]

theorem stable_source_config_readback (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (bound : index < 55) :
    stableSourceWord statement witness index = stableWitnessWord witness.stablecoin index := by
  simp only [stableSourceWord, if_pos (show index < 94 by omega),
    sourcePrivateIndex, if_pos bound]

theorem stable_source_sibling_readback (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (bound : index < 28) :
    stableSourceWord statement witness (55 + index) =
      stableWitnessWord witness.stablecoin (59 + index) := by
  have first : ¬55 + index < 55 := by omega
  have second : 55 + index < 90 := by omega
  simp only [stableSourceWord, if_pos (show 55 + index < 94 by omega),
    sourcePrivateIndex, if_neg first, if_pos second]
  congr 1
  omega

theorem stable_source_issuer_readback (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (bound : index < 7) :
    stableSourceWord statement witness (83 + index) =
      stableWitnessWord witness.stablecoin (87 + index) := by
  have first : ¬83 + index < 55 := by omega
  have second : 83 + index < 90 := by omega
  simp only [stableSourceWord, if_pos (show 83 + index < 94 by omega),
    sourcePrivateIndex, if_neg first, if_pos second]
  congr 1
  omega

theorem stable_source_before_readback (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (bound : index < 4) :
    stableSourceWord statement witness (90 + index) =
      stableWitnessWord witness.stablecoin (55 + index) := by
  have first : ¬90 + index < 55 := by omega
  have second : ¬90 + index < 90 := by omega
  simp only [stableSourceWord, if_pos (show 90 + index < 94 by omega),
    sourcePrivateIndex, if_neg first, if_neg second]
  congr 1
  omega

theorem stable_source_parent_readback (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (bound : index < 18) :
    stableSourceWord statement witness (94 + index) =
      wordAt (encodePublicStatement statement) (63 + index) := by
  simp only [stableSourceWord, if_neg (show ¬94 + index < 94 by omega),
    if_pos (show 94 + index < 112 by omega)]
  congr 1
  omega

theorem stable_source_spend_key_readback (statement : V8PublicStatement) (witness : V8Witness)
    (input : Fin 2) (limb : Fin 4) :
    stableSourceWord statement witness (112 + input.val * 4 + limb.val) =
      wordAt (witness.inputs.getD input.val default).spendKey limb.val := by
  fin_cases input <;> simp only [Nat.zero_mul, Nat.one_mul,
    Nat.add_zero] <;> unfold stableSourceWord <;> split_ifs <;> try omega
  all_goals (congr 1; omega)

theorem stable_source_padding_zero (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Nat) (bound : 120 ≤ slot) :
    stableSourceWord statement witness slot = 0 := by
  simp only [stableSourceWord, if_neg (show ¬slot < 94 by omega),
    if_neg (show ¬slot < 112 by omega), if_neg (show ¬slot < 116 by omega),
    if_neg (show ¬slot < 120 by omega)]

theorem valid_public_words_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords publicWordCount (encodePublicStatement statement) := by
  exact valid.1.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

theorem valid_stable_words_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords 94 witness.stablecoin.words := by
  exact valid.2.1.2.2.2.2.2

theorem valid_input_spend_words_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Nat) (bound : input < 2) :
    ExactWords 4 (witness.inputs.getD input default).spendKey := by
  have shape := valid.2.1.2.2.1 input (by simpa only [inputCount] using bound)
  dsimp only at shape
  have inputBound : input < witness.inputs.length := by
    rw [valid.2.1.1]
    exact bound
  have same (fallback : V8InputWitness) :
      witness.inputs.getD input fallback = witness.inputs.getD input default := by
    simp [List.getD, inputBound]
  simp only [same] at shape
  have data := shape.2
  by_cases inactive : (witness.inputs.getD input default).active = 0
  · rw [if_pos inactive] at data
    exact data.2.1
  · rw [if_neg inactive] at data
    exact data.2.1

theorem valid_stable_source_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Nat) :
    stableSourceWord statement witness slot < fieldModulus := by
  unfold stableSourceWord
  split_ifs
  · exact auth_exact_words_getD (valid_stable_words_exact statement witness valid) _
  · exact auth_exact_words_getD (valid_public_words_exact statement witness valid) _
  · exact auth_exact_words_getD (valid_input_spend_words_exact statement witness valid 0 (by decide)) _
  · exact auth_exact_words_getD (valid_input_spend_words_exact statement witness valid 1 (by decide)) _
  · decide

theorem valid_stable_source_packed_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ∀ word, word ∈ stableSourcePacked statement witness → word < fieldModulus := by
  intro word member
  obtain ⟨slot, rfl⟩ := List.mem_ofFn.mp member
  exact valid_stable_source_word_canonical statement witness valid _


end HegemonCrypto.SmallWood.V8Smz9SourceStableTail


import SmzaRp05PcsMerklePayload
import SmzaRp05TracePrefixes

/-!
# Exact source leaf word decoding

The payload is calculated by `normalizedLeafPayload` from reconstructed rows
and existing mask words. These lemmas identify the decoded data and masking
cells with those original inputs. They do not assume a leaf-value agreement
certificate or change the verifier payload.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLeafCodec

open HegemonCrypto.CanonicalBytes
open SmzaRp05PcsMerklePayload
open SmzaRp05ExecutableChallengeStage (FieldWord)

set_option autoImplicit false

private theorem encoded_chunk {α : Type} (values : List α) (encode : α → Nat)
    (fallback : α) (suffix : List Byte) (index : Nat) (bound : index < values.length) :
    (((values.flatMap fun value => encodeLE 8 (encode value)) ++ suffix).drop
      (8 * index)).take 8 = encodeLE 8 (encode (values.getD index fallback)) := by
  induction values generalizing index with
  | nil => simp at bound
  | cons head rest ih =>
      cases index with
      | zero =>
          simpa only [List.flatMap_cons, List.append_assoc, Nat.mul_zero,
            List.drop_zero, List.getD_cons_zero, encodeLE_length]
            using (List.take_append_length (l₁ := encodeLE 8 (encode head))
              (l₂ := (rest.flatMap fun value => encodeLE 8 (encode value)) ++ suffix))
      | succ index =>
          have restBound : index < rest.length := by simpa using bound
          have offset : 8 * (index + 1) = (encodeLE 8 (encode head)).length + 8 * index := by
            simp only [encodeLE_length]
            omega
          simp only [List.flatMap_cons, List.append_assoc, offset,
            List.drop_length_add_append, List.getD_cons_succ]
          exact ih index restBound

private theorem prefix_encoded_word {α : Type} (bytePrefix : List Byte)
    (offset : Nat) (prefixLength : bytePrefix.length = 8 * offset)
    (values : List α) (encode : α → Nat) (fallback : α) (suffix : List Byte)
    (index : Nat) (bound : index < values.length) :
    V8SmzaOracleParser.wordAt
      (bytePrefix ++ ((values.flatMap fun value => encodeLE 8 (encode value)) ++ suffix))
      (offset + index) = encode (values.getD index fallback) % 256 ^ 8 := by
  unfold V8SmzaOracleParser.wordAt
  change decodeLE (((bytePrefix ++
      ((values.flatMap fun value => encodeLE 8 (encode value)) ++ suffix)).drop
      (8 * (offset + index))).take 8) = _
  have position : 8 * (offset + index) = bytePrefix.length + 8 * index := by omega
  rw [position, List.drop_length_add_append,
    encoded_chunk values encode fallback suffix index bound, decodeLE_encodeLE]

theorem normalized_data_word (salt tape : List Byte) (index : Nat)
    (row : List Goldilocks) (masks : List FieldWord)
    (saltLength : salt.length = 32) (tapeLength : tape.length = 64)
    (column : Nat) (bound : column < row.length) :
    V8SmzaOracleParser.wordAt (normalizedLeafPayload salt tape index row masks)
      (14 + column) = (row.getD column 0).val := by
  let bytePrefix := salt ++ encodeLE 8 index ++ tape ++ encodeLE 8 row.length
  have prefixLength : bytePrefix.length = 8 * 14 := by
    simp [bytePrefix, saltLength, tapeLength, encodeLE_length]
  have decoded := prefix_encoded_word bytePrefix 14 prefixLength row (fun value => value.val)
    0 (encodeLE 8 masks.length ++ masks.flatMap fun word => encodeLE 8 word.val)
    column bound
  have wordBound : (row.getD column 0).val < 256 ^ 8 := by
    exact lt_trans (row.getD column 0).val_lt
      (by norm_num [Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus])
  simpa only [normalizedLeafPayload, bytePrefix, List.append_assoc,
    Nat.mod_eq_of_lt wordBound] using decoded

private theorem encoded_fields_length {α : Type} (values : List α) (encode : α → Nat) :
    (values.flatMap fun value => encodeLE 8 (encode value)).length = 8 * values.length := by
  induction values with
  | nil => simp
  | cons head rest ih =>
      simp only [List.flatMap_cons, List.length_append, encodeLE_length, ih,
        List.length_cons]
      omega

theorem normalized_mask_word (salt tape : List Byte) (index : Nat)
    (row : List Goldilocks) (masks : List FieldWord)
    (saltLength : salt.length = 32) (tapeLength : tape.length = 64)
    (rowLength : row.length = 140)
    (column : Nat) (bound : column < masks.length) :
    V8SmzaOracleParser.wordAt (normalizedLeafPayload salt tape index row masks)
      (155 + column) = (masks.getD column ⟨0, by decide⟩).val := by
  let bytePrefix := salt ++ encodeLE 8 index ++ tape ++ encodeLE 8 row.length ++
    row.flatMap (fun value => encodeLE 8 value.val) ++ encodeLE 8 masks.length
  have rowBytes := encoded_fields_length row (fun value => value.val)
  have prefixLength : bytePrefix.length = 8 * 155 := by
    simp [bytePrefix, saltLength, tapeLength, rowLength, encodeLE_length, rowBytes]
  have decoded := prefix_encoded_word bytePrefix 155 prefixLength masks (fun word => word.val)
    ⟨0, by decide⟩ [] column bound
  have wordBound : (masks.getD column ⟨0, by decide⟩).val < 256 ^ 8 := by
    exact (masks.getD column ⟨0, by decide⟩).isLt.trans
      (by norm_num [SmzaRp05ExecutableChallengeStage.modulus])
  simpa only [normalizedLeafPayload, bytePrefix, List.append_assoc, List.append_nil,
    Nat.mod_eq_of_lt wordBound] using decoded

theorem normalized_data_field (salt tape : List Byte) (index : Nat)
    (row : List Goldilocks) (masks : List FieldWord)
    (saltLength : salt.length = 32) (tapeLength : tape.length = 64)
    (column : Nat) (bound : column < row.length) :
    (SmzaRp05TracePrefixes.fieldWordAt (normalizedLeafPayload salt tape index row masks)
      (14 + column)).val = (row.getD column 0).val := by
  change V8SmzaOracleParser.wordAt (normalizedLeafPayload salt tape index row masks)
      (14 + column) % Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus =
    (row.getD column 0).val
  rw [normalized_data_word salt tape index row masks saltLength tapeLength column bound]
  exact Nat.mod_eq_of_lt (row.getD column 0).val_lt

theorem normalized_mask_field (salt tape : List Byte) (index : Nat)
    (row : List Goldilocks) (masks : List FieldWord)
    (saltLength : salt.length = 32) (tapeLength : tape.length = 64)
    (rowLength : row.length = 140)
    (column : Nat) (bound : column < masks.length) :
    (SmzaRp05TracePrefixes.fieldWordAt (normalizedLeafPayload salt tape index row masks)
      (155 + column)).val = (masks.getD column ⟨0, by decide⟩).val := by
  change V8SmzaOracleParser.wordAt (normalizedLeafPayload salt tape index row masks)
      (155 + column) % Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus =
    (masks.getD column ⟨0, by decide⟩).val
  rw [normalized_mask_word salt tape index row masks saltLength tapeLength rowLength column bound]
  have modulus_eq : SmzaRp05ExecutableChallengeStage.modulus =
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus := by
    norm_num [SmzaRp05ExecutableChallengeStage.modulus,
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]
  exact Nat.mod_eq_of_lt (modulus_eq ▸ (masks.getD column ⟨0, by decide⟩).isLt)

end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLeafCodec

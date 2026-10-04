import SmallWoodV8SmzaOracleParserR2
import HegemonCrypto.SmallWoodV8Smz9HonestHashPlacement
import SmzaRp05CurrentAcceptedRoleSupport
import SmzaRp05ExecutablePcsClosureMca406
import SmzaRp05CurrentMaxAgreementRecovery

/-!
# Current RP05 pre-query response decoding

The current R2 SMZA parser is used for the active `piopInputDomain` frame.
These lemmas invert the exact fixed-width word serialization and locate the
five 406-coefficient slices after the eight digest words. They keep the
statement-binding suffix explicit and do not substitute an older framing.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentResponsePrequeryDecode

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood (Goldilocks)
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement (goldilocksModulus)
open SmzaRp05DecsResponseProjection (FieldRow)

set_option autoImplicit false

/-- The current parser's word reader inverts consecutive fixed-width
little-endian words. -/
theorem word_at_encoded_words (words : List Nat) (index : Nat)
    (indexBound : index < words.length)
    (wordBound : words.getD index 0 < 256 ^ 8) :
    V8SmzaOracleParser.wordAt ((words.map (encodeLE 8)).flatten) index =
      words.getD index 0 := by
  induction words generalizing index with
  | nil => simp at indexBound
  | cons head tail ih =>
      cases index with
      | zero =>
          have headBound : head < 256 ^ 8 := by
            simp only [List.getD_cons_zero] at wordBound
            exact wordBound
          have takeHead :
              List.take 8 (encodeLE 8 head ++ ((tail.map (encodeLE 8)).flatten)) =
                encodeLE 8 head :=
            List.take_append_of_le_length (by simp [encodeLE_length])
          change HegemonCrypto.SmallWood.V8Smz9CoherentMerkleGeometry.wordAt
            (((head :: tail).map (encodeLE 8)).flatten) 0 = _
          simp only [List.map_cons, List.flatten_cons]
          unfold HegemonCrypto.SmallWood.V8Smz9CoherentMerkleGeometry.wordAt
          simp only [Nat.mul_zero, List.drop_zero]
          rw [takeHead]
          rw [decodeLE_encodeLE]
          exact Nat.mod_eq_of_lt headBound
      | succ index =>
          have tailIndexBound : index < tail.length := by simpa using indexBound
          have tailWordBound : tail.getD index 0 < 256 ^ 8 := by simpa using wordBound
          have dropHead :
              List.drop 8 (encodeLE 8 head ++ ((tail.map (encodeLE 8)).flatten)) =
                (tail.map (encodeLE 8)).flatten := by
            rw [List.drop_append_of_le_length (by simp [encodeLE_length])]
            simp [encodeLE_length]
          have dropAt :
              List.drop (8 * (index + 1))
                  (encodeLE 8 head ++ ((tail.map (encodeLE 8)).flatten)) =
                List.drop (8 * index) ((tail.map (encodeLE 8)).flatten) := by
            rw [show 8 * (index + 1) = 8 + 8 * index by omega]
            rw [← List.drop_drop]
            exact congrArg (List.drop (8 * index)) dropHead
          change HegemonCrypto.SmallWood.V8Smz9CoherentMerkleGeometry.wordAt
            (((head :: tail).map (encodeLE 8)).flatten) (index + 1) = _
          simp only [List.map_cons, List.flatten_cons]
          rw [HegemonCrypto.SmallWood.V8Smz9CoherentMerkleGeometry.wordAt, dropAt]
          exact ih index tailIndexBound tailWordBound

/-- The current raw-frame parser round-trips the actual PIOP input domain and
the complete serialized payload. The count is exactly the number of words. -/
theorem current_piop_frame_roundtrip (words : List Nat)
    (wordCountBound : words.length < 256 ^ 8) :
    V8SmzaOracleParser.parseFramed
      (V8SmzaOracleParser.framedInput SmallWoodTranscript.piopInputDomain
        ((words.map (encodeLE 8)).flatten)) =
      some (SmallWoodTranscript.piopInputDomain,
        (words.map (encodeLE 8)).flatten) := by
  have payloadLength : ((words.map (encodeLE 8)).flatten).length = 8 * words.length := by
    induction words with
    | nil => rfl
    | cons word rest ih =>
        have restBound : rest.length < 256 ^ 8 := by
          simp only [List.length_cons] at wordCountBound
          omega
        simp only [List.map_cons, List.flatten_cons, List.length_append,
          encodeLE_length]
        rw [ih restBound]
        simp only [List.length_cons]
        omega
  apply V8SmzaOracleParser.frame_roundtrip
  · norm_num [SmallWoodTranscript.piopInputDomain, SmallWoodTranscript.level5DomainPrefix]
  · rw [payloadLength]
    omega
  · rw [payloadLength]
    omega

/-- The stream index `8 + row * 406 + coefficient` is the requested cell of
the flattened restored rows. Digest prefix and statement suffix stay explicit. -/
theorem encoded_response_word_at
    (leading suffix : List Nat) (fieldRows : List FieldRow)
    (row coefficient : Nat)
    (leadingLength : leading.length = 8)
    (rowShape : ∀ values, values ∈ fieldRows → values.length = 406)
    (rowBound : row < fieldRows.length) (coefficientBound : coefficient < 406) :
    (leading ++ ((fieldRows.map fun values => values.map fun value => value.val).flatten ++ suffix)).getD
        (8 + row * 406 + coefficient) 0 =
      ((fieldRows.getD row []).getD coefficient 0).val := by
  let rows : List (List Nat) := fieldRows.map fun values => values.map fun value => value.val
  have natRowShape : ∀ values, values ∈ rows → values.length = 406 := by
    intro values member
    rcases List.mem_map.mp member with ⟨source, sourceMember, rfl⟩
    simp [rowShape source sourceMember]
  have natCell : (rows.getD row []).getD coefficient 0 =
      ((fieldRows.getD row []).getD coefficient 0).val := by
    cases hrow : fieldRows[row]? with
    | none => simp [rows, hrow]
    | some values =>
        have hcell : (values.map fun value => value.val).getD coefficient 0 =
            (values.getD coefficient 0).val := by
          cases hvalue : values[coefficient]? <;> simp [hvalue]
        simpa [rows, hrow] using hcell
  have cellBound : (rows.getD row []).getD coefficient 0 < 256 ^ 8 := by
    rw [natCell]
    have fieldBound := ((fieldRows.getD row []).getD coefficient 0).val_lt
    exact lt_trans fieldBound (by norm_num [goldilocksModulus])
  have rowBound' : row < rows.length := by simpa [rows] using rowBound
  have flattenedLength := HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization.rectangular_flatten_length
    rows 406 natRowShape
  rw [List.getD_append_right _ _ _ _ (by rw [leadingLength]; omega)]
  have payloadOffset : 8 + row * 406 + coefficient - leading.length =
      row * 406 + coefficient := by rw [leadingLength]; omega
  rw [payloadOffset]
  rw [List.getD_append _ _ _ _ (by rw [flattenedLength]; omega)]
  rw [HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization.rectangular_flatten_getD
    rows 406 row coefficient natRowShape rowBound' coefficientBound]
  exact natCell

/-- Parsed bytes expose the exact restored coefficient at the source's
post-digest row/column offset. The `streamEq` premise is just the serializer
equation and `cellBound` follows from the Goldilocks canonical range. -/
theorem parsed_encoded_response_coefficient_at
    (leading suffix : List Nat) (rows : List FieldRow)
    (payload : List HegemonCrypto.CanonicalBytes.Byte)
    (row coefficient : Nat)
    (leadingLength : leading.length = 8)
    (rowShape : ∀ values, values ∈ rows → values.length = 406)
    (rowBound : row < rows.length) (coefficientBound : coefficient < 406)
    (streamEq : payload =
      ((leading ++ (((rows.map fun values => values.map fun value => value.val)).flatten ++ suffix)).map
        (encodeLE 8)).flatten) :
    V8SmzaOracleParser.wordAt payload (8 + row * 406 + coefficient) =
      ((rows.getD row []).getD coefficient 0).val := by
  rw [streamEq]
  rw [word_at_encoded_words]
  · exact encoded_response_word_at leading suffix rows row coefficient
      leadingLength rowShape rowBound coefficientBound
  · rw [List.length_append, leadingLength]
    let rowsNat := rows.map fun values => values.map fun value => value.val
    have flattenedLength := HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization.rectangular_flatten_length
      rowsNat 406 (by
        intro values member
        rcases List.mem_map.mp member with ⟨source, sourceMember, rfl⟩
        simp [rowShape source sourceMember])
    simp only [List.length_append]
    change 8 + row * 406 + coefficient <
      8 + (rowsNat.flatten.length + suffix.length)
    rw [flattenedLength]
    have rowCount : rowsNat.length = rows.length := by simp [rowsNat]
    omega
  · rw [encoded_response_word_at leading suffix rows row coefficient
      leadingLength rowShape rowBound coefficientBound]
    have fieldBound := ((rows.getD row []).getD coefficient 0).val_lt
    exact lt_trans fieldBound (by norm_num [goldilocksModulus])

/-- An earlier input that is exactly the current source frame decodes to the
same coefficient slice. This joins parser round-trip to the row-slice lemma;
the prefix/suffix equality remains an explicit source serialization fact. -/
theorem prior_input_decodes_response_coefficient
    (input payload : List HegemonCrypto.CanonicalBytes.Byte)
    (words leading suffix : List Nat) (rows : List FieldRow)
    (row coefficient : Nat)
    (wordCountBound : words.length < 256 ^ 8)
    (frameEq : input = V8SmzaOracleParser.framedInput
      SmallWoodTranscript.piopInputDomain ((words.map (encodeLE 8)).flatten))
    (parsed : V8SmzaOracleParser.parseFramed input =
      some (SmallWoodTranscript.piopInputDomain, payload))
    (wordsEq : words = leading ++
      (((rows.map fun values => values.map fun value => value.val).flatten) ++ suffix))
    (leadingLength : leading.length = 8)
    (rowShape : ∀ values, values ∈ rows → values.length = 406)
    (rowBound : row < rows.length) (coefficientBound : coefficient < 406) :
    V8SmzaOracleParser.wordAt payload (8 + row * 406 + coefficient) =
      ((rows.getD row []).getD coefficient 0).val := by
  have roundtrip := current_piop_frame_roundtrip words wordCountBound
  rw [frameEq] at parsed
  have pairEq := Option.some.inj (parsed.symm.trans roundtrip)
  have payloadEq := congrArg Prod.snd pairEq
  exact parsed_encoded_response_coefficient_at leading suffix rows payload row coefficient
    leadingLength rowShape rowBound coefficientBound (by simpa only [wordsEq] using payloadEq)

end HegemonCrypto.SmallWood.SmzaRp05CurrentResponsePrequeryDecode

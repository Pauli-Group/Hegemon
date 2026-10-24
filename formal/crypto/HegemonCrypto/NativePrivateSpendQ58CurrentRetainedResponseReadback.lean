import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedDecs
import HegemonCrypto.NativePrivateSpendQ58CurrentLeafInput
import SmzaRp05CurrentResponsePrequeryDecode
import SmzaRp05ExecutableMerkleVerifier
import SmzaRecordedTracePath

/-!
Current COMPFF01 response-hash readback at an earlier recorded-relation cut.
The source Program computes restoration/transcript before its literal raw
SHA512 read. It never asks for responseAtSample, Satisfies, source-table
agreement or an accepted-query support premise. Missing earlier preimages and
collisions are explicit outcomes; their physical probability is not asserted.

F1 interprets this one native source stage and the supplied chronological cut.
This component does not prove an earlier table cut, a complete quantum trace
transport, a source-wide refinement or accepted-invalid soundness.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRetainedResponseReadback

open HegemonCrypto.CanonicalBytes (Byte encodeLE encodeLE_length)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields FieldRow)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05ExecutablePcsClosureAlgebra
  (coefficientPolynomial coefficient_polynomial_coeff)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open NativePrivateSpendQ58CurrentAcceptedDecs
  (currentRestore currentTranscript CurrentOpenedEquations
   current_transcript_derives_opened_checks)
open V8Smz9CoherentMerkleGeometry
  (Records ExtractionTrace extract wordAt selectedInput)
open SmzaRecordedTracePath
  (RecordsCollisionFree RecordedPath readPath recorded_path_readback
   selected_input_of_recorded)
open scoped Classical

set_option autoImplicit false
noncomputable section

abbrev RawInput := List Byte
abbrev RawDigest := Fin 64 → Byte
abbrev PriorRecords := Records RawInput RawDigest
abbrev Coefficients := Fin 140 → Fin 5 → Goldilocks
abbrev Response := V8Smz9McaRecovery.BoundedResponse Goldilocks (Fin 5) 13172

/-- Complete current profile/role/count header. The role is PIOP-input,
not the distinct final PIOP-transcript role. -/
def responseHeader (wordCount : Nat) : RawInput :=
  encodeLE 8 NativePrivateSpendQ58CurrentLeafInput.currentProfile.length ++
    NativePrivateSpendQ58CurrentLeafInput.currentProfile ++
      encodeLE 8 SmallWoodTranscript.piopInputDomain.length ++
        SmallWoodTranscript.piopInputDomain ++ encodeLE 8 wordCount

theorem current_response_header_length (wordCount : Nat) :
    (responseHeader wordCount).length = 129 := by
  simp only [responseHeader, List.length_append, encodeLE_length]
  decide

def encodedWords (words : List Nat) : List Byte :=
  (words.map (encodeLE 8)).flatten

private theorem encoded_words_length (words : List Nat) :
    (encodedWords words).length = 8 * words.length := by
  induction words with
  | nil => rfl
  | cons word rest ih =>
      simp only [encodedWords, List.map_cons, List.flatten_cons,
        List.length_append, encodeLE_length, List.length_cons] at *
      omega

/-- Native concrete_smallwood_sha512_oracle_query_v1 framing, counter0.
8 root words + 5*13173 response words + 77 common statement words. -/
def responseInput (words : List Nat) : RawInput :=
  responseHeader words.length ++ (encodedWords words ++ encodeLE 8 0)

/-- Total raw decoder. On the good arm its input is proved equal to the
literal current source request; no parser success or payload equality is
supplied as a premise. Malformed/historical inputs remain in the raw domain. -/
def responsePayload (raw : RawInput) : List Byte :=
  (raw.drop 129).take 527600

private theorem response_payload_of_frame (words : List Nat)
    (wordLength : words.length = 65950) :
    responsePayload (responseInput words) = encodedWords words := by
  have headerLength := current_response_header_length words.length
  have dropHeader : (responseInput words).drop 129 =
      encodedWords words ++ encodeLE 8 0 := by
    unfold responseInput
    simpa only [headerLength] using
      (List.drop_left (l₁ := responseHeader words.length)
        (l₂ := encodedWords words ++ encodeLE 8 0))
  have payloadLength : (encodedWords words).length = 527600 := by
    rw [encoded_words_length, wordLength]
  unfold responsePayload
  rw [dropHeader, List.take_append_of_le_length (by rw [payloadLength])]
  rw [← payloadLength]
  exact List.take_length

private theorem mapped_rows_shape (rows : List FieldRow)
    (shape : ∀ row, row ∈ rows → row.length = 13173) :
    ∀ values, values ∈ rows.map (fun row => row.map (fun value => value.val)) →
      values.length = 13173 := by
  intro values member
  obtain ⟨row, rowMember, rfl⟩ := List.mem_map.mp member
  simpa only [List.length_map] using shape row rowMember

private theorem response_words_length
    (leading suffix : List Nat) (rows : List FieldRow)
    (leadingLength : leading.length = 8) (suffixLength : suffix.length = 77)
    (rowCount : rows.length = 5)
    (rowShape : ∀ row, row ∈ rows → row.length = 13173) :
    (leading ++
      ((rows.map (fun row => row.map (fun value => value.val))).flatten ++
        suffix)).length = 65950 := by
  have flattened := V8Smz9HonestHashMaterialization.rectangular_flatten_length
    (rows.map (fun row => row.map (fun value => value.val))) 13173
    (mapped_rows_shape rows rowShape)
  simp only [List.length_map, rowCount] at flattened
  rw [List.length_append, List.length_append, leadingLength, suffixLength,
    flattened]

/-- Current rectangular coefficient offset, with the suffix untouched. -/
private theorem response_word_at
    (leading suffix : List Nat) (rows : List FieldRow)
    (row coefficient : Nat) (leadingLength : leading.length = 8)
    (rowShape : ∀ values, values ∈ rows → values.length = 13173)
    (rowBound : row < rows.length) (coefficientBound : coefficient < 13173) :
    (leading ++
      ((rows.map (fun values => values.map (fun value => value.val))).flatten ++
        suffix)).getD (8 + row * 13173 + coefficient) 0 =
      ((rows.getD row []).getD coefficient 0).val := by
  let natRows := rows.map (fun values => values.map (fun value => value.val))
  have natShape : ∀ values, values ∈ natRows → values.length = 13173 :=
    mapped_rows_shape rows rowShape
  have natCell : (natRows.getD row []).getD coefficient 0 =
      ((rows.getD row []).getD coefficient 0).val := by
    cases sourceRow : rows[row]? with
    | none => simp [natRows, sourceRow]
    | some values =>
        have cell : (values.map (fun value => value.val)).getD coefficient 0 =
            (values.getD coefficient 0).val := by
          cases sourceValue : values[coefficient]? <;> simp [sourceValue]
        simpa [natRows, sourceRow] using cell
  have natBound : row < natRows.length := by simpa [natRows] using rowBound
  have flattened := V8Smz9HonestHashMaterialization.rectangular_flatten_length
    natRows 13173 natShape
  rw [List.getD_append_right _ _ _ _ (by rw [leadingLength]; omega)]
  rw [show 8 + row * 13173 + coefficient - leading.length =
      row * 13173 + coefficient by rw [leadingLength]; omega]
  rw [List.getD_append _ _ _ _ (by rw [flattened]; omega)]
  rw [V8Smz9HonestHashMaterialization.rectangular_flatten_getD natRows
    13173 row coefficient natShape natBound coefficientBound]
  exact natCell

private theorem source_frame_coefficient
    (leading suffix : List Nat) (rows : List FieldRow)
    (row : Fin 5) (coefficient : Fin 13173)
    (leadingLength : leading.length = 8) (suffixLength : suffix.length = 77)
    (rowCount : rows.length = 5)
    (rowShape : ∀ values, values ∈ rows → values.length = 13173) :
    (wordAt (responsePayload (responseInput
      (leading ++
        ((rows.map (fun values => values.map (fun value => value.val))).flatten ++
          suffix)))) (8 + row.val * 13173 + coefficient.val) : Goldilocks) =
      (rows.getD row.val []).getD coefficient.val 0 := by
  let words := leading ++
    ((rows.map (fun values => values.map (fun value => value.val))).flatten ++ suffix)
  have lengthWords : words.length = 65950 :=
    response_words_length leading suffix rows leadingLength suffixLength rowCount rowShape
  have rowBound : row.val < rows.length := by rw [rowCount]; exact row.isLt
  have cell := response_word_at leading suffix rows row.val coefficient.val
    leadingLength rowShape rowBound coefficient.isLt
  have indexBound : 8 + row.val * 13173 + coefficient.val < words.length := by
    rw [lengthWords]
    have rowLt := row.isLt
    have coefficientLt := coefficient.isLt
    omega
  have wordBound : words.getD (8 + row.val * 13173 + coefficient.val) 0 <
      256 ^ 8 := by
    rw [show words.getD (8 + row.val * 13173 + coefficient.val) 0 =
        ((rows.getD row.val []).getD coefficient.val 0).val from cell]
    exact lt_trans ((rows.getD row.val []).getD coefficient.val 0).val_lt
      (by norm_num [Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus])
  have decoded := SmzaRp05CurrentResponsePrequeryDecode.word_at_encoded_words
    words (8 + row.val * 13173 + coefficient.val) indexBound wordBound
  change (wordAt (responsePayload (responseInput words)) _ : Goldilocks) = _
  rw [response_payload_of_frame words lengthWords]
  change (V8SmzaOracleParser.wordAt (encodedWords words) _ : Goldilocks) = _
  rw [show V8SmzaOracleParser.wordAt (encodedWords words)
      (8 + row.val * 13173 + coefficient.val) =
        words.getD (8 + row.val * 13173 + coefficient.val) 0 from decoded, cell]
  exact ZMod.natCast_zmod_val _

def responseOfRaw (raw : RawInput) : Response := fun row =>
  (Polynomial.degreeLTEquiv Goldilocks 13173).symm
    (fun coefficient =>
      (wordAt (responsePayload raw)
        (8 + row.val * 13173 + coefficient.val) : Goldilocks))

private theorem source_frame_polynomial
    (leading suffix : List Nat) (rows : List FieldRow)
    (row : Fin 5) (leadingLength : leading.length = 8)
    (suffixLength : suffix.length = 77) (rowCount : rows.length = 5)
    (rowShape : ∀ values, values ∈ rows → values.length = 13173) :
    V8Smz9McaRecovery.responsePolynomials
      (responseOfRaw (responseInput (leading ++
        ((rows.map (fun values => values.map (fun value => value.val))).flatten ++
          suffix)))) row = coefficientPolynomial (rows.getD row.val []) := by
  change (responseOfRaw _ row).val = _
  apply Polynomial.ext
  intro degree
  by_cases bound : degree < 13173
  · let index : Fin 13173 := ⟨degree, bound⟩
    let coefficients : Fin 13173 → Goldilocks := fun coefficient =>
      (wordAt (responsePayload (responseInput (leading ++
        ((rows.map (fun values => values.map (fun value => value.val))).flatten ++
          suffix)))) (8 + row.val * 13173 + coefficient.val) : Goldilocks)
    have encoded := congrFun
      ((Polynomial.degreeLTEquiv Goldilocks 13173).apply_symm_apply coefficients) index
    change ((responseOfRaw _ row).val).coeff degree = _ at encoded
    rw [coefficient_polynomial_coeff]
    exact encoded.trans (source_frame_coefficient leading suffix rows row index
      leadingLength suffixLength rowCount rowShape)
  · have rowBound : row.val < rows.length := by rw [rowCount]; exact row.isLt
    have member : rows.getD row.val [] ∈ rows := by
      rw [List.getD_eq_getElem rows [] rowBound]
      exact List.getElem_mem rowBound
    have beyond : (rows.getD row.val []).getD degree 0 = 0 := by
      rw [List.getD_eq_getElem?_getD,
        List.getElem?_eq_none (by rw [rowShape _ member]; omega)]
      rfl
    rw [coefficient_polynomial_coeff, beyond]
    have degreeBound := V8Smz9McaRecovery.bounded_response_degree
      (responseOfRaw (responseInput (leading ++
        ((rows.map (fun values => values.map (fun value => value.val))).flatten ++
          suffix)))) row
    change (responseOfRaw _ row).val.natDegree ≤ 13172 at degreeBound
    exact Polynomial.coeff_eq_zero_of_natDegree_lt (by omega)

/-- Literal ordinary source continuation. Failure before restoration makes
no response-hash call. Success makes exactly the current full-width request. -/
def sourceHashProgram (hashMtWords : List Nat) (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (common : List Nat) : Program RawDigest :=
  match currentTranscript hashMtWords fields rows gamma points with
  | none => .done none
  | some words => ask (responseInput (words ++ common))

private theorem source_hash_success
    (oracle : Oracle) (hashMtWords : List Nat) (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (common : List Nat) (target : RawDigest)
    (success : (sourceHashProgram hashMtWords fields rows gamma points common).eval
      oracle = some target) :
    ∃ words,
      currentTranscript hashMtWords fields rows gamma points = some words ∧
      oracle (responseInput (words ++ common)) = target ∧
      (responseInput (words ++ common), target) ∈
        ((sourceHashProgram hashMtWords fields rows gamma points common).record oracle).2 := by
  cases built : currentTranscript hashMtWords fields rows gamma points with
  | none => simp [sourceHashProgram, built, Program.eval] at success
  | some words =>
      have digestEq : oracle (responseInput (words ++ common)) = target :=
        Option.some.inj (by simpa only [sourceHashProgram, built, ask, Program.eval]
          using success)
      refine ⟨words, rfl, digestEq, ?_⟩
      simp [sourceHashProgram, built, ask, Program.record, digestEq]

private def responseNext (_ : Unit) (_ : RawInput) :
    Option (List (Unit × RawDigest)) := some []

/-- Selection consults the earlier relation only. The target is the response
commitment fixed at the appropriate earlier role cut in the physical game;
its chronology is not inferred from the later verifier record. -/
def priorInput (prior : PriorRecords) (target : RawDigest) : Option RawInput :=
  selectedInput responseNext prior () target

def priorResponse (prior : PriorRecords) (target : RawDigest) : Response :=
  responseOfRaw ((priorInput prior target).getD [])

def priorResponseRule (prior : PriorRecords) (target : RawDigest) :
    Coefficients → Response := fun _ => priorResponse prior target

/-- A single response stage has a zero-length recorded path and fuel1.
This uses the generic PR205 extractor, without any concrete Merkle tree. -/
theorem prior_response_recorded_path_readback
    (prior : PriorRecords) (target : RawDigest) (input : RawInput)
    (collisionFree : RecordsCollisionFree prior)
    (recorded : (input, target) ∈ prior) :
    readPath [] (extract responseNext prior 1 () target) = some input := by
  exact recorded_path_readback responseNext prior collisionFree () target [] input
    (.here () target input recorded (by simp only [responseNext, Option.isSome_some]))
    1 (by decide)

/-- The good arm derives all five current response polynomials from the
PRIOR-selected raw request. Missing preimages/collisions are outcomes, not
new assumptions excluding cryptographic failures. The selected input and
response rule do not inspect the58 challenge positions or restored rows. -/
theorem current_source_response_binds_prior_or_bad_event
    (oracle : Oracle) (prior : PriorRecords) (target : RawDigest)
    (hashMtWords : List Nat) (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (common : List Nat) (rootLength : hashMtWords.length = 8)
    (commonLength : common.length = 77)
    (success : (sourceHashProgram hashMtWords fields rows gamma points common).eval
      oracle = some target) :
    (¬ ∃ input, (input, target) ∈ prior) ∨
    (¬ RecordsCollisionFree (prior ∪
      ((sourceHashProgram hashMtWords fields rows gamma points common).record oracle).2.toFinset)) ∨
    ∃ polynomials : List FieldRow,
      currentRestore fields rows gamma points = some polynomials ∧
      polynomials.length = 5 ∧
      (∀ row, row < 5 → (polynomials.getD row []).length = 13173) ∧
      (∀ row, row < 5 →
        (coefficientPolynomial (polynomials.getD row [])).natDegree ≤ 13172) ∧
      CurrentOpenedEquations fields rows gamma points polynomials ∧
      (∀ row : Fin 5,
        V8Smz9McaRecovery.responsePolynomials (priorResponse prior target) row =
          coefficientPolynomial (polynomials.getD row.val [])) := by
  by_cases present : ∃ input, (input, target) ∈ prior
  · by_cases collisionFree : RecordsCollisionFree (prior ∪
        ((sourceHashProgram hashMtWords fields rows gamma points common).record oracle).2.toFinset)
    · apply Or.inr
      apply Or.inr
      obtain ⟨words, built, _digestEq, recorded⟩ := source_hash_success oracle
        hashMtWords fields rows gamma points common target success
      obtain ⟨polynomials, restored, wordsEq, rowCount, rowLengths, degrees,
        equations⟩ := current_transcript_derives_opened_checks hashMtWords
          fields rows gamma points words built
      obtain ⟨earlier, earlierMember⟩ := present
      have same : earlier = responseInput (words ++ common) :=
        collisionFree earlier (responseInput (words ++ common)) target
          (Finset.mem_union_left _ earlierMember)
          (Finset.mem_union_right _ (List.mem_toFinset.mpr recorded))
      have sourcePrior : (responseInput (words ++ common), target) ∈ prior := by
        simpa only [same] using earlierMember
      have priorFree : RecordsCollisionFree prior := by
        intro left right output leftMember rightMember
        exact collisionFree left right output
          (Finset.mem_union_left _ leftMember) (Finset.mem_union_left _ rightMember)
      have selected : priorInput prior target = some (responseInput (words ++ common)) :=
        selected_input_of_recorded responseNext prior priorFree () target
          (responseInput (words ++ common)) sourcePrior
          (by simp only [responseNext, Option.isSome_some])
      have rowShape : ∀ values, values ∈ polynomials → values.length = 13173 := by
        intro values member
        obtain ⟨index, bounded, rfl⟩ := List.mem_iff_getElem.mp member
        have rowBound : index < 5 := by rw [rowCount] at bounded; exact bounded
        have lengthRow := rowLengths index rowBound
        rw [List.getD_eq_getElem polynomials [] bounded] at lengthRow
        exact lengthRow
      refine ⟨polynomials, restored, rowCount, rowLengths, degrees, equations, ?_⟩
      intro row
      rw [priorResponse, selected, Option.getD_some]
      have serializer : words ++ common = hashMtWords ++
          ((polynomials.map (fun values => values.map (fun value => value.val))).flatten ++
            common) := by
        rw [wordsEq]
        simp only [List.map_flatten, List.append_assoc]
      rw [serializer]
      exact source_frame_polynomial hashMtWords common polynomials row rootLength
        commonLength rowCount rowShape
    · exact Or.inr (Or.inl collisionFree)
  · exact Or.inl present

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRetainedResponseReadback

import SmzaRp05CurrentDecsFrameReadback
import SmzaRp05CurrentRetainedResponseBridge

/-! The successful source response-hash constructor determines its current
FPP payload and root edge. No independently chosen response payload is used. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFppFrameReadback

open HegemonCrypto.CanonicalBytes (Byte encodeLE encodeLE_length)
open SmzaRp05ExecutableMerkleVerifier (Program ask)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields FieldRow)
open SmzaRp05CurrentAcceptedRoleSupport
  (selected_response_hash_program_input responseTranscriptInput)
open SmzaRp05ExecutablePcsClosureMca406 (successful_restore_rows_have_406_coefficients)
open SmzaRp05ExecutablePcsClosureDecsChecks (successful_hash_fpp_program_has_restoration)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload globalOnlineNext)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawInput RawDigest)

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

private theorem encoded_words_length (words : List Nat) :
    (words.flatMap (encodeLE 8)).length = words.length * 8 := by
  induction words with
  | nil => rfl
  | cons word words ih =>
      simp only [List.flatMap_cons, List.length_append, encodeLE_length,
        List.length_cons, ih]
      omega

private theorem uniform_flatten_length {α : Type} (rows : List (List α))
    (width : Nat) (shape : ∀ row ∈ rows, row.length = width) :
    rows.flatten.length = rows.length * width := by
  induction rows with
  | nil => simp
  | cons row rows ih =>
      have headLength := shape row (by simp)
      have tailShape : ∀ entry ∈ rows, entry.length = width := by
        intro entry member
        exact shape entry (by simp [member])
      simp only [List.flatten_cons, List.length_append, List.length_cons,
        headLength, ih tailShape]
      ring

theorem successful_response_program_has_current_fpp_edge
    (ns : Namespace) (root : RawDigest) (fields : DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (statementBinding : List Nat) (bindingLength : statementBinding.length = 138)
    (program : Program RawDigest)
    (selected : SmzaRp05DecsResponseProjection.hashFppProgram root fields
      rows gamma evalPoints 140 368 statementBinding = some program) :
    ∃ input : RawInput, ∃ payload : List Byte,
      program = ask input ∧
      V8SmzaOracleParser.parseFramed input =
        some (SmallWoodTranscript.piopInputDomain, payload) ∧
      globalNormalizedPayload ns input = some ⟨.fpp, payload⟩ ∧
      globalOnlineNext ns .fpp input = some [(.root, root)] ∧
      payload.drop 16304 = statementBinding.flatMap (encodeLE 8) := by
  obtain ⟨pcsWords, input, wordsFormed, inputFormed, programEq⟩ :=
    selected_response_hash_program_input root fields rows gamma evalPoints
      140 368 statementBinding program selected
  obtain ⟨polynomials, restored⟩ := successful_hash_fpp_program_has_restoration
    root fields rows gamma evalPoints 140 368 statementBinding program selected
  have shape := successful_restore_rows_have_406_coefficients fields rows gamma
    evalPoints polynomials restored
  have rowShape : ∀ values, values ∈ polynomials → values.length = 406 := by
    intro values member
    obtain ⟨index, indexBound, valueEq⟩ := List.mem_iff_getElem.mp member
    subst values
    have indexLt : index < 5 := by rw [shape.1] at indexBound; exact indexBound
    have rowLength := shape.2 index indexLt
    rw [List.getD_eq_getElem polynomials [] indexBound] at rowLength
    exact rowLength
  have polynomialLength : polynomials.flatten.length = 2030 := by
    rw [uniform_flatten_length polynomials 406 rowShape, shape.1]
  have pcsWordsEq : pcsWords =
      SmzaRp05ExecutableChallengeStage.digestWords root ++
        polynomials.flatten.map (fun coefficient => coefficient.val) := by
    have formed := wordsFormed
    simp only [SmzaRp05DecsResponseProjection.responseTranscriptWords,
      restored, Pure.pure] at formed
    exact (Option.some.inj formed).symm
  let words := pcsWords ++ statementBinding
  let payload := words.flatMap (encodeLE 8)
  have wordLength : words.length = 2176 := by
    simp only [words, pcsWordsEq, List.length_append, List.length_map,
      SmzaRp05ExecutableChallengeStage.digestWords, List.length_range,
      polynomialLength, bindingLength]
  have frameEq : input = V8SmzaOracleParser.framedInput
      SmallWoodTranscript.piopInputDomain payload := by
    have formed := inputFormed
    simp only [responseTranscriptInput, wordsFormed, Pure.pure] at formed
    exact (Option.some.inj formed).symm
  have parsed : V8SmzaOracleParser.parseFramed input =
      some (SmallWoodTranscript.piopInputDomain, payload) := by
    rw [frameEq]
    exact SmzaRp05CurrentResponsePrequeryDecode.current_piop_frame_roundtrip
      words (by rw [wordLength]; decide)
  have payloadLength : payload.length = 17408 := by
    rw [show payload = words.flatMap (encodeLE 8) from rfl,
      encoded_words_length, wordLength]
  have normalized : globalNormalizedPayload ns input = some ⟨.fpp, payload⟩ := by
    rw [frameEq]
    exact SmzaRp05ExecutableMerkleVerifier.global_nonleaf_frame
      ns .fpp payload (by decide) payloadLength
  have payloadPrefix : payload = List.ofFn root ++
      ((polynomials.flatten.map fun coefficient => coefficient.val) ++
        statementBinding).flatMap (encodeLE 8) := by
    simp only [payload, words, pcsWordsEq, List.append_assoc, List.flatMap_append]
    rw [SmzaRp05CurrentDecsFrameReadback.digest_words_encode_exact]
  have rootEdge : globalOnlineNext ns .fpp input = some [(.root, root)] := by
    unfold globalOnlineNext
    rw [normalized]
    change some [(V8SmzaOracleParser.Stage.root,
      V8SmzaOracleParser.digestAt payload 0)] = _
    have digestRead : V8SmzaOracleParser.digestAt payload 0 = root := by
      rw [payloadPrefix]
      exact SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append root _
    rw [digestRead]
  let coefficientBytes :=
    (polynomials.flatten.map fun coefficient => coefficient.val).flatMap (encodeLE 8)
  have coefficientBytesLength : coefficientBytes.length = 16240 := by
    change ((polynomials.flatten.map fun coefficient => coefficient.val).flatMap
      (encodeLE 8)).length = 16240
    rw [encoded_words_length]
    simp only [List.length_map]
    rw [polynomialLength]
  have fixedPrefixLength : (List.ofFn root ++ coefficientBytes).length = 16304 := by
    simp only [List.length_append, List.length_ofFn, coefficientBytesLength]
  have payloadParts : payload =
      (List.ofFn root ++ coefficientBytes) ++ statementBinding.flatMap (encodeLE 8) := by
    calc
      payload = List.ofFn root ++
          ((polynomials.flatten.map fun coefficient => coefficient.val) ++
            statementBinding).flatMap (encodeLE 8) := payloadPrefix
      _ = (List.ofFn root ++ coefficientBytes) ++
          statementBinding.flatMap (encodeLE 8) := by
        simp only [coefficientBytes, List.flatMap_append, List.append_assoc]
  have payloadSuffix : payload.drop 16304 = statementBinding.flatMap (encodeLE 8) := by
    rw [payloadParts, show 16304 = (List.ofFn root ++ coefficientBytes).length from
      fixedPrefixLength.symm]
    rw [List.drop_append_of_le_length (Nat.le_refl _)]
    simp
  exact ⟨input, payload, programEq, parsed, normalized, rootEdge, payloadSuffix⟩

end HegemonCrypto.SmallWood.SmzaRp05CurrentFppFrameReadback

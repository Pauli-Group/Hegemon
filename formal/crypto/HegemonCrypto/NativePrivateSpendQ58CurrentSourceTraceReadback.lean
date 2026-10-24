import HegemonCrypto.NativePrivateSpendQ58CurrentFullLogReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentTracePiopMass
import SmzaRp05CurrentDecsFrameReadback

/-! Actual current FPP and final PIOP source edges and trace readback.
The FPP edge is derived from currentTranscript restoration and the literal
65950-word request. Full-log coverage here cannot be substituted for a prior
selected challenge cut. A missing prior input is charged by PrequeryEvents.
SOURCE ONLY; no kernel result or whole accepted-invalid mass theorem. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceTraceReadback
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutableChallengeStage (digestWords FieldWord)
open SmzaRecordedTracePath
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open scoped Classical
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope
  (RawInput RawDigest rawNext rawPayload payloadNext payloadBytes raw_payload_frame frame roleName)
end F
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Transcript transcriptWords finalInput)
end E
namespace RR
export NativePrivateSpendQ58CurrentRetainedResponseReadback
  (sourceHashProgram responseInput responseHeader encodedWords priorInput)
end RR
namespace AD
export NativePrivateSpendQ58CurrentAcceptedDecs
  (currentTranscript current_transcript_derives_opened_checks)
end AD
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
local instance : DecidableEq F.RawInput :=
  (inferInstance : LinearOrder F.RawInput).toDecidableEq

private theorem rectangular_flatten_length {α : Type*}
    (rows : List (List α)) (width : Nat)
    (shapes : ∀ values, values ∈ rows → values.length = width) :
    rows.flatten.length = width * rows.length := by
  revert shapes
  induction rows with
  | nil => intro _; rfl
  | cons values rest ih =>
      intro shapes
      have first : values.length = width := shapes values (by simp)
      have restShapes : ∀ row, row ∈ rest → row.length = width := by
        intro row member
        exact shapes row (by simp [member])
      have restLength := ih restShapes
      simp only [List.flatten_cons, List.length_append, List.length_cons, first, restLength, Nat.mul_succ]
      omega

private theorem encoded_length (words : List Nat) :
    (words.flatMap (encodeLE 8)).length = 8 * words.length := by
  induction words with
  | nil => rfl
  | cons word rest ih =>
      simp only [List.flatMap_cons, List.length_append,
        HegemonCrypto.CanonicalBytes.encodeLE_length, List.length_cons, ih]
      omega

private theorem flatten_encode (words : List Nat) :
    words.flatMap (encodeLE 8) = (words.map (encodeLE 8)).flatten := by
  induction words with
  | nil => rfl
  | cons word rest ih => simp only [List.flatMap_cons, List.map_cons, List.flatten_cons, ih]

theorem response_input_is_current_frame (words : List Nat) :
    RR.responseInput words = F.frame (F.roleName .fpp) words.length
      (words.flatMap (encodeLE 8)) := by
  have profile : NativePrivateSpendQ58CurrentLeafInput.currentProfile.length = 70 := by decide
  simp only [RR.responseInput, RR.responseHeader, RR.encodedWords,
    F.frame, F.roleName, profile, flatten_encode, List.append_assoc]

theorem current_fpp_frame_has_literal_root_edge (root : F.RawDigest) (tail : List Nat)
    (tailLength : tail.length = 65942) :
    F.rawNext .fpp (RR.responseInput (digestWords root ++ tail)) = some [(.root, root)] := by
  have wordLength : (digestWords root ++ tail).length = 65950 := by
    simp [digestWords, tailLength]
  have byteLength := encoded_length (digestWords root ++ tail)
  rw [wordLength] at byteLength
  have parsed := F.raw_payload_frame .fpp 65950
    ((digestWords root ++ tail).flatMap (encodeLE 8)) (by decide) byteLength
    (by simpa only [F.payloadBytes] using byteLength)
  rw [response_input_is_current_frame, wordLength]
  simp only [F.rawNext, parsed, Option.bind_some, F.payloadNext]
  rw [List.flatMap_append, SmzaRp05CurrentDecsFrameReadback.digest_words_encode_exact,
    SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append]

/-- Actual successful current restoration computes the required exact raw
shape and hash-stage edge. No desired prior membership is assumed. -/
theorem successful_source_hash_has_literal_current_root_edge
    (oracle : Oracle) (root target : F.RawDigest)
    (fields : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (rows gamma : List (List FieldWord)) (points : List FieldWord)
    (common : List Nat) (commonLength : common.length = 77)
    (success : (RR.sourceHashProgram (digestWords root) fields rows gamma points common).eval
      oracle = some target) :
    ∃ input, (input, target) ∈
        ((RR.sourceHashProgram (digestWords root) fields rows gamma points common).record oracle).2 ∧
      F.rawNext .fpp input = some [(.root, root)] := by
  cases built : AD.currentTranscript (digestWords root) fields rows gamma points with
  | none => simp [RR.sourceHashProgram, built, Program.eval] at success
  | some words =>
      have actualHash : oracle (RR.responseInput (words ++ common)) = target :=
        Option.some.inj (by simpa only [RR.sourceHashProgram, built, ask, Program.eval] using success)
      obtain ⟨polynomials, _restore, wordsEq, rowCount, lengths, _degrees, _equations⟩ :=
        AD.current_transcript_derives_opened_checks (digestWords root) fields rows gamma points words built
      have shapes : ∀ values, values ∈ polynomials → values.length = 13173 := by
        intro values member
        obtain ⟨index, bound, rfl⟩ := List.mem_iff_getElem.mp member
        have small : index < 5 := by rw [rowCount] at bound; exact bound
        have length := lengths index small
        simpa only [List.getD_eq_getElem polynomials [] bound] using length
      have flat := rectangular_flatten_length polynomials 13173 shapes
      have tailLength : (polynomials.flatten.map (fun value => value.val) ++ common).length = 65942 := by
        simp only [List.length_append, List.length_map, flat, rowCount, commonLength]
      refine ⟨RR.responseInput (words ++ common), ?_, ?_⟩
      · simp [RR.sourceHashProgram, built, ask, Program.record, actualHash]
      · rw [wordsEq, List.append_assoc]
        exact current_fpp_frame_has_literal_root_edge root _ tailLength

theorem current_final_frame_has_literal_fpp_edge (transcript : E.Transcript) :
    F.rawNext .piop (E.finalInput transcript) = some [(.fpp, transcript.hashFpp)] := by
  have wordLength := NativePrivateSpendQ58CurrentPiopRecordJoin.current_final_word_length transcript
  have byteLength := encoded_length (E.transcriptWords transcript)
  rw [wordLength] at byteLength
  have parsed := F.raw_payload_frame .piop 1043
    ((E.transcriptWords transcript).flatMap (encodeLE 8)) (by decide) byteLength
    (by simpa only [F.payloadBytes] using byteLength)
  simp only [F.rawNext, E.finalInput, parsed, Option.bind_some, F.payloadNext]
  rw [E.transcriptWords, List.flatMap_append,
    SmzaRp05CurrentDecsFrameReadback.digest_words_encode_exact,
    SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append]

/-- Full collision-free records DERIVE the parsed FPP trace and its actual
root subtree. This does not assume a trace readback at an earlier role cut. -/
theorem recorded_current_fpp_trace_readback
    (records : RawRecords) (free : RecordsCollisionFree records)
    (input : F.RawInput) (target root : F.RawDigest)
    (recorded : (input, target) ∈ records)
    (edge : F.rawNext .fpp input = some [(.root, root)]) :
    extract F.rawNext records 26 .fpp target =
      .record input [extract F.rawNext records 25 .root root] := by
  have selected := selected_input_of_recorded F.rawNext records free .fpp target input
    recorded (by simp [edge])
  simp only [extract, selected, edge, List.map_cons, List.map_nil]

theorem recorded_current_piop_trace_readback
    (records : RawRecords) (free : RecordsCollisionFree records)
    (transcript : E.Transcript) (target : F.RawDigest)
    (recorded : (E.finalInput transcript, target) ∈ records) :
    extract F.rawNext records 27 .piop target =
      .record (E.finalInput transcript)
        [extract F.rawNext records 26 .fpp transcript.hashFpp] := by
  have edge := current_final_frame_has_literal_fpp_edge transcript
  have selected := selected_input_of_recorded F.rawNext records free .piop target
    (E.finalInput transcript) recorded (by simp [edge])
  simp only [extract, selected, edge, List.map_cons, List.map_nil]

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceTraceReadback

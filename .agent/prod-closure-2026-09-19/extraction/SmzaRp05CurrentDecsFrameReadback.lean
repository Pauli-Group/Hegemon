import SmzaRp05PcsWireProjection
import SmzaRp05ExecutableMerklePaths
import SmzaRp05ExecutablePcsClosureCodec
import SmzaRp05LeafNamespace
import SmzaRp05FilteredDecoderInstability
import HegemonCrypto.SmallWoodV8Smz9CappedRawSampler
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-! # Current DECS-opening frame readback

The source-generated canonical opening call is framed as the current DECS
role.  Its exact source payload length and digest prefix determine the parser's
single causal child, without accepting an independently supplied parsed
payload.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentDecsFrameReadback

open HegemonCrypto.CanonicalBytes
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload globalOnlineNext)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open SmzaRp04RawRecordedTranscript (digestPrefix)
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler (typedWordPayload)

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

theorem openingRowsWords_length
    (count cols tailCount : Nat) (heads : List (List HegemonCrypto.SmallWood.Goldilocks))
    (tails : List (List FieldWord)) (words : List Nat)
    (success : SmzaRp05PcsWireProjection.openingRowsWords count cols tailCount
      heads tails = some words) :
    words.length = count * (cols + tailCount) := by
  induction count generalizing heads tails words with
  | zero =>
      cases heads with
      | nil =>
          cases tails with
          | nil =>
              have emptyWords : words = [] := by
                simpa [SmzaRp05PcsWireProjection.openingRowsWords] using success
              subst words
              simp
          | cons tail tails =>
              simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
      | cons head heads =>
          simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
  | succ count ih =>
      cases heads with
      | nil => simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
      | cons head heads =>
          cases tails with
          | nil => simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
          | cons tail tails =>
              simp only [SmzaRp05PcsWireProjection.openingRowsWords] at success
              by_cases shape : head.length ≠ cols ∨ tail.length ≠ tailCount
              · simp [shape] at success
              ·
                simp only [if_neg shape] at success
                have headLength : head.length = cols := by
                  simp only [not_or] at shape
                  omega
                have tailLength : tail.length = tailCount := by
                  simp only [not_or] at shape
                  omega
                cases restEq : SmzaRp05PcsWireProjection.openingRowsWords
                    count cols tailCount heads tails with
                | none => simp [restEq] at success
                | some rest =>
                    have restLength := ih heads tails rest restEq
                    have wordEq :
                        head.map (fun word => word.val) ++
                          (tail.map (fun word => word.val) ++ rest) = words := by
                      simpa [restEq] using success
                    rw [← wordEq]
                    simp only [List.length_append, List.length_map, headLength, tailLength,
                      restLength]
                    ring

private theorem encode_words_bytes_length (words : List Nat) :
    (words.flatMap (encodeLE 8)).length = words.length * 8 := by
  induction words with
  | nil => simp
  | cons word words ih =>
      simp only [List.flatMap_cons, List.length_append, List.length_cons,
        encodeLE_length, ih]
      ring

private theorem typed_word_payload_flatMap
    (words : List (Fin (2 ^ 64))) :
    typedWordPayload words = words.flatMap (fun word => encodeLE 8 word.val) := by
  induction words with
  | nil => rfl
  | cons word words ih =>
      simp only [HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler.typedWordPayload,
        List.flatMap_cons, ih]

theorem digest_words_encode_exact (digest : RawDigest) :
    (SmzaRp05ExecutableChallengeStage.digestWords digest).flatMap (encodeLE 8) =
      List.ofFn digest := by
  have wordsEq : SmzaRp05ExecutableChallengeStage.digestWords digest =
      (List.ofFn (digestPrefix digest)).map Fin.val := by
    simpa [SmzaRp05ExecutableChallengeStage.digestWords,
      V8Smz9WholeViewObservation.Sha512Digest.rawWords,
      HegemonCrypto.SmallWood.V8Smz9CappedRawSampler.sourceDigestOfByteBlock,
      digestPrefix, Nat.mul_comm] using
      HegemonCrypto.SmallWood.V8Smz9CappedRawSampler.source_digest_words_are_exact_byte_block_words
        digest
  rw [wordsEq]
  have payloadBytes :=
    HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureCodec.digest_prefix_payload digest
  rw [typed_word_payload_flatMap] at payloadBytes
  simpa only [List.flatMap_map] using payloadBytes

/-- Every successful 12×(368+38) opening constructor normalizes as a DECS
payload of 39,040 bytes, and its current online DECS edge is precisely the
PIOP digest that was passed to the constructor. -/
theorem current_decs_opening_edge406
    (ns : Namespace) (hPiop : RawDigest)
    (heads : List (List HegemonCrypto.SmallWood.Goldilocks))
    (tails : List (List FieldWord))
    (input : RawInput)
    (built : SmzaRp05PcsWireProjection.decsOpeningInput hPiop 12 368 38
    heads tails = some input) :
    ∃ rows, SmzaRp05PcsWireProjection.openingRowsWords 12 368 38 heads tails =
        some rows ∧
      V8SmzaOracleParser.parseFramed input =
        some (SmallWoodTranscript.decsOpeningDomain,
          (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
            (encodeLE 8)) ∧
      globalNormalizedPayload ns input =
        some ⟨.decs, (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++
          rows).flatMap (encodeLE 8)⟩ ∧
      globalOnlineNext ns .decs input = some [(.piop, hPiop)] := by
  classical
  unfold SmzaRp05PcsWireProjection.decsOpeningInput
    SmzaRp05PcsWireProjection.decsOpeningWords at built
  cases rowWords : SmzaRp05PcsWireProjection.openingRowsWords
      12 368 38 heads tails with
  | none => simp [rowWords] at built
  | some rows =>
      have rowsLength := openingRowsWords_length 12 368 38 heads tails rows rowWords
      simp only [rowWords] at built
      change some (V8SmzaOracleParser.framedInput SmallWoodTranscript.decsOpeningDomain
        ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
          (encodeLE 8))) = some input at built
      have frameEq : input = V8SmzaOracleParser.framedInput
          SmallWoodTranscript.decsOpeningDomain
          ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
            (encodeLE 8)) := by
        exact (Option.some.inj built).symm
      subst input
      have payloadLength :
          ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
              (encodeLE 8)).length = 39040 := by
        rw [encode_words_bytes_length]
        have digestWordsLength :
            (SmzaRp05ExecutableChallengeStage.digestWords hPiop).length = 8 := by
          simp [SmzaRp05ExecutableChallengeStage.digestWords]
        rw [List.length_append, digestWordsLength, rowsLength]
      have payloadPrefix :
          ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
              (encodeLE 8)) =
            List.ofFn hPiop ++ rows.flatMap (encodeLE 8) := by
        rw [List.flatMap_append]
        rw [digest_words_encode_exact]
      have parsed :=
        SmzaRp05ExecutableMerkleVerifier.global_nonleaf_frame ns .decs
          ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
            (encodeLE 8)) (by decide) payloadLength
      have parsedDomain : globalNormalizedPayload ns
          (V8SmzaOracleParser.framedInput SmallWoodTranscript.decsOpeningDomain
            ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
              (encodeLE 8))) =
          some ⟨.decs,
            (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
              (encodeLE 8)⟩ := by
        simpa only [V8SmzaOracleParser.roleName] using parsed
      have aligned : 8 *
          (((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
            (encodeLE 8)).length / 8) =
            ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
              (encodeLE 8)).length := by
        rw [payloadLength]
      have countBound :
          ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
            (encodeLE 8)).length / 8 < 256 ^ 8 := by
        rw [payloadLength]
        norm_num
      have framed := V8SmzaOracleParser.frame_roundtrip
        SmallWoodTranscript.decsOpeningDomain
        ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
          (encodeLE 8)) (by decide) countBound aligned
      have framedRole : V8SmzaOracleParser.parseFramed
          (V8SmzaOracleParser.framedInput SmallWoodTranscript.decsOpeningDomain
            ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
              (encodeLE 8))) =
          some (SmallWoodTranscript.decsOpeningDomain,
            (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
              (encodeLE 8)) := by
        simpa only [V8SmzaOracleParser.roleName] using framed
      refine ⟨rows, rfl, framedRole, parsedDomain, ?_⟩
      unfold globalOnlineNext
      rw [parsedDomain]
      change V8SmzaOnlineParser.payloadNext .decs
        ⟨.decs,
          (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
            (encodeLE 8)⟩ = _
      simp only [V8SmzaOnlineParser.payloadNext, payloadPrefix,
        SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append]

end HegemonCrypto.SmallWood.SmzaRp05CurrentDecsFrameReadback

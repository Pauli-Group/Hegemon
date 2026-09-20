import SmzaRp04RecordedTranscript
import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewFinalInput
import HegemonCrypto.SmallWoodV8Smz9CappedRawSampler
import HegemonCrypto.FiniteOracleDatabase

/-!
# RP04 raw-input database bridge

The recorded PIOP table is useful only after it is identified with the actual raw
SHA-512 input domain.  This file supplies that typed identification; it does not
silently identify the two databases or assume a hash collision theorem.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04RawRecordedTranscript

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.SmzaRp04RecordedTranscript
open V8Smz9EagerPrivacy V8Smz9HonestWholeViewFinalInput
open HegemonCrypto.SmallWood.V8Smz9CappedRawSampler
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open V8SmzaOracleParser
open V8Smz9PiopSoundness V8Smz9PiopReconstruction SmzaQ38Recovery
open SmzaRp04PublicContext SmzaRp04ScalarCheckTransport
open SmzaRp04ActualProgram
open SmzaRp04RestoredTranscriptChecks V8Smz9ZeroKnowledge V8Smz9EagerSimulator

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Prefix := V8Smz9HonestWholeViewFinalInput.Prefix
abbrev CanonicalCoefficients := PiopCoefficients Goldilocks

/-- The parser's 64 digest bytes become the canonical eight little-endian words. -/
def digestPrefix (digest : RawDigest) : Prefix :=
  byteBlockWordsEquiv digest

def canonicalCoefficients (input : PiopInput) : CanonicalCoefficients :=
  (input.nonlinear, input.linearHigh)

/-- Reuse the unchanged coefficient ordering, but frame it with the actual
SMZA profile. The old `sourceFinalRawInput` hardcodes the SMZ9 profile and
must not be substituted here merely because both headers have equal length. -/
def rawPiopInput (commitmentPrefix : Prefix) (coefficients : CanonicalCoefficients) : RawInput :=
  V8SmzaOracleParser.framedInput SmallWoodTranscript.piopTranscriptDomain
    (typedWordPayload (sourceFinalWords commitmentPrefix coefficients))

theorem raw_piop_input_roundtrip (commitmentPrefix : Prefix) (coefficients : CanonicalCoefficients) :
    V8SmzaOracleParser.parseFramed (rawPiopInput commitmentPrefix coefficients) =
      some (SmallWoodTranscript.piopTranscriptDomain,
        typedWordPayload (sourceFinalWords commitmentPrefix coefficients)) := by
  apply V8SmzaOracleParser.frame_roundtrip
  · decide
  · rw [typed_word_payload_length, source_final_word_count]
    norm_num
  · rw [typed_word_payload_length, source_final_word_count]

theorem raw_piop_input_injective (commitmentPrefix : Prefix) :
    Function.Injective (rawPiopInput commitmentPrefix) := by
  intro left right same
  have parsed := congrArg V8SmzaOracleParser.parseFramed same
  rw [raw_piop_input_roundtrip, raw_piop_input_roundtrip] at parsed
  have payloads := congrArg Prod.snd (Option.some.inj parsed)
  exact source_final_words_injective commitmentPrefix
    (typed_word_payload_injective payloads)

def rawInputOf (input : PiopInput) : RawInput :=
  rawPiopInput (digestPrefix input.commitmentPrefix) (canonicalCoefficients input)

def pullbackDatabase (rawDatabase : Database RawInput RawDigest) :
    Database PiopInput RawDigest :=
  fun input => rawDatabase (rawInputOf input)

attribute [local irreducible] batchingWidth recoveredCandidate nonlinearAt linearAt

theorem raw_recorded_transcripts_same_components
    (rawDatabase : Database RawInput RawDigest)
    (collisionFree : CollisionFree rawDatabase)
    (commitmentPrefix digest : RawDigest) (left right : ClaimedTranscript)
    (recordedLeft : rawDatabase (rawInputOf (transcriptInput commitmentPrefix left)) = some digest)
    (recordedRight : rawDatabase (rawInputOf (transcriptInput commitmentPrefix right)) = some digest) :
    (∀ row, left.nonlinear row = right.nonlinear row) ∧
      left.linearHigh = right.linearHigh := by
  have sameRaw := input_unique_of_same_recorded_output collisionFree recordedLeft recordedRight
  have sameInput := raw_piop_input_injective (digestPrefix commitmentPrefix) sameRaw
  have sameCoefficients :
      canonicalCoefficients (transcriptInput commitmentPrefix left) =
        canonicalCoefficients (transcriptInput commitmentPrefix right) := by
    exact congrArg id sameInput
  constructor
  · intro row
    exact bounded_polynomial_eq_of_coefficients _ _
      (left.nonlinearDegree row) (right.nonlinearDegree row)
      (fun index => congrArg (fun coeff => coeff.1 row index) sameCoefficients)
  · exact congrArg Prod.snd sameCoefficients

theorem raw_recorded_reconstruction
    (rawDatabase : Database RawInput RawDigest)
    (collisionFree : CollisionFree rawDatabase)
    (commitmentPrefix : RawDigest) (digest : RawDigest)
    (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (high : ProofHighs)
    (recordedBefore : rawDatabase (rawInputOf (transcriptInput commitmentPrefix response)) = some digest)
    (recordedAfter : rawDatabase (rawInputOf (transcriptInput commitmentPrefix
      (reconstructedTranscript opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)
        (batchedTarget (recoveredCandidate publicWords rows) matrix)))) = some digest) :
    SameRestoredTranscript publicWords rows matrix response opening witness masks
      (fun row => nonlinearHighPart (high.nonlinear row))
      (fun row => linearHighPart (high.linear row))
      (verifierCorrection publicWords rows matrix opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)) := by
  let trace := verifierEvaluationTrace publicWords matrix opening witness masks
  let rebuilt := reconstructedTranscript opening high trace
    (batchedTarget (recoveredCandidate publicWords rows) matrix)
  have same := raw_recorded_transcripts_same_components rawDatabase collisionFree commitmentPrefix digest
    response rebuilt recordedBefore recordedAfter
  constructor
  · intro row
    exact (same.1 row).trans
      (verifier_nonlinear_restore publicWords matrix opening witness masks high row)
  · intro row
    have linearSame : claimedLinear (recoveredCandidate publicWords rows) matrix response row =
        claimedLinear (recoveredCandidate publicWords rows) matrix rebuilt row := by
      unfold claimedLinear
      rw [same.2]
    calc
      claimedLinear (recoveredCandidate publicWords rows) matrix response row =
          claimedLinear (recoveredCandidate publicWords rows) matrix rebuilt row := linearSame
      _ = reconstructedLinear opening (high.linear row) (trace.linear row)
          (batchedTarget (recoveredCandidate publicWords rows) matrix row) :=
        reconstructed_claimed_linear _ _ _ _ _ _
      _ = _ := verifier_linear_restore publicWords rows matrix opening witness masks high row

end
end HegemonCrypto.SmallWood.SmzaRp04RawRecordedTranscript

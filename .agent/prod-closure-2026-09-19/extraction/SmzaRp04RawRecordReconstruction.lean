import SmzaRp04PublicTargetReadback
import SmzaRecordedTracePath

/-! PIOP reconstruction from the same raw record relation used by the
extractor. No second hash database or equality between two databases is
required. The separately bounded raw-record collision event is sufficient. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawRecordReconstruction

open SmzaRecordedTracePath V8Smz9CoherentMerkleGeometry
open SmzaRp04RecordedTranscript SmzaRp04RawRecordedTranscript
open SmzaRp04PublicTargetReadback SmzaRp04RestoredTranscriptChecks
open SmzaRp04PublicContext SmzaRp04ActualProgram SmzaQ38Recovery
open SmzaRp04ScalarCheckTransport
open V8Smz9PiopSoundness V8Smz9PiopReconstruction V8Smz9AdaptiveFiniteAccounting
open V8Smz9ZeroKnowledge V8Smz9EagerSimulator V8Smz9EagerPrivacy
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 500000
set_option Elab.async false
attribute [local irreducible] batchingWidth recoveredCandidate nonlinearAt linearAt
attribute [local irreducible] rawPiopInput

theorem recorded_inputs_bind_components
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (free : RecordsCollisionFree records)
    (commitmentPrefix digest : V8SmzaOracleParser.RawDigest)
    (left right : ClaimedTranscript)
    (before : (rawInputOf (transcriptInput commitmentPrefix left), digest) ∈ records)
    (after : (rawInputOf (transcriptInput commitmentPrefix right), digest) ∈ records) :
    (∀ row, left.nonlinear row = right.nonlinear row) ∧
      left.linearHigh = right.linearHigh := by
  have sameRaw : rawInputOf (transcriptInput commitmentPrefix left) =
      rawInputOf (transcriptInput commitmentPrefix right) :=
    free (rawInputOf (transcriptInput commitmentPrefix left))
      (rawInputOf (transcriptInput commitmentPrefix right)) digest before after
  have sameCoefficients :
      canonicalCoefficients (transcriptInput commitmentPrefix left) =
        canonicalCoefficients (transcriptInput commitmentPrefix right) := by
    exact @raw_piop_input_injective (digestPrefix commitmentPrefix)
      (canonicalCoefficients (transcriptInput commitmentPrefix left))
      (canonicalCoefficients (transcriptInput commitmentPrefix right)) sameRaw
  constructor
  · intro row
    exact bounded_polynomial_eq_of_coefficients _ _
      (left.nonlinearDegree row) (right.nonlinearDegree row)
      (fun index => congrArg (fun coefficients => coefficients.1 row index) sameCoefficients)
  · exact congrArg Prod.snd sameCoefficients

theorem one_raw_record_reconstruction_binds_every_source
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (free : RecordsCollisionFree records)
    (commitmentPrefix digest : V8SmzaOracleParser.RawDigest)
    (publicWords : List Nat) (matrix : Matrix (batchingWidth publicWords))
    (response : ClaimedTranscript) (opening : Opening)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (high : ProofHighs)
    (before : (rawInputOf (transcriptInput commitmentPrefix response), digest) ∈ records)
    (after : (rawInputOf (transcriptInput commitmentPrefix
      (reconstructedTranscript opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)
        (publicBatchedTarget publicWords matrix))), digest) ∈ records) :
    ∀ rows : RecoveredRows,
      SameRestoredTranscript publicWords rows matrix response opening witness masks
        (fun row => nonlinearHighPart (high.nonlinear row))
        (fun row => linearHighPart (high.linear row))
        (publicCorrection publicWords matrix opening high
          (verifierEvaluationTrace publicWords matrix opening witness masks)) := by
  intro rows
  let trace := verifierEvaluationTrace publicWords matrix opening witness masks
  let rebuilt := reconstructedTranscript opening high trace
    (publicBatchedTarget publicWords matrix)
  have same := recorded_inputs_bind_components records free commitmentPrefix digest
    response rebuilt before after
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
      _ = claimedLinear (recoveredCandidate publicWords rows) matrix rebuilt row := linearSame
      _ = reconstructedLinear opening (high.linear row) (trace.linear row)
          (batchedTarget (recoveredCandidate publicWords rows) matrix row) := by
        have restored := reconstructed_claimed_linear
          (recoveredCandidate publicWords rows) matrix opening high trace row
        rw [recovered_batched_target_is_public] at restored
        rw [recovered_batched_target_is_public]
        exact restored
      _ = _ := by
        have restored := verifier_linear_restore
          publicWords rows matrix opening witness masks high row
        rw [verifier_correction_is_public] at restored
        exact restored

end
end HegemonCrypto.SmallWood.SmzaRp04RawRecordReconstruction

import SmzaRp04RawRecordedTranscript

/-! A single verifier reconstruction binds every possible recovered source.
The omitted linear constant depends on the public target, never on the
unknown recovered witness. Thus accepted readback does not need a separately
recorded reconstruction for every candidate extracted by MCA. -/
namespace HegemonCrypto.SmallWood.SmzaRp04PublicTargetReadback

open HegemonCrypto.FiniteOracleDatabase
open SmzaRp04PublicContext SmzaRp04ActualProgram SmzaQ38Recovery
open SmzaRp04RecordedTranscript SmzaRp04RawRecordedTranscript
open SmzaRp04RestoredTranscriptChecks
open V8Smz9PiopSoundness V8Smz9PiopReconstruction
open V8Smz9AdaptiveFiniteAccounting
open V8Smz9ZeroKnowledge V8Smz9EagerSimulator
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

def publicBatchedTarget (publicWords : List Nat)
    (matrix : Matrix (batchingWidth publicWords)) (row : Fin 5) : Goldilocks :=
  ∑ check, matrix row check * SmzaRp04DecodedPolynomialSource.paddedTarget publicWords check

theorem recovered_batched_target_is_public (publicWords : List Nat)
    (rows : RecoveredRows) (matrix : Matrix (batchingWidth publicWords)) :
    batchedTarget (recoveredCandidate publicWords rows) matrix =
      publicBatchedTarget publicWords matrix := by
  rfl

def publicCorrection (publicWords : List Nat)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening)
    (high : ProofHighs) (trace : EvaluationTrace) (row : Fin 5) : Goldilocks :=
  (publicBatchedTarget publicWords matrix row -
    V8Smz9PiopOpeningRecovery.packingSum packingPoint
      (restoredLinearBase opening (high.linear row) (trace.linear row))) /
        linearPiopCorrectionFactor (points opening)

theorem verifier_correction_is_public (publicWords : List Nat)
    (rows : RecoveredRows) (matrix : Matrix (batchingWidth publicWords))
    (opening : Opening) (high : ProofHighs) (trace : EvaluationTrace) :
    verifierCorrection publicWords rows matrix opening high trace =
      publicCorrection publicWords matrix opening high trace := by
  rfl

theorem one_recorded_reconstruction_binds_every_recovered_source
    (rawDatabase : Database RawInput RawDigest)
    (collisionFree : CollisionFree rawDatabase)
    (commitmentPrefix digest : RawDigest) (publicWords : List Nat)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (high : ProofHighs)
    (recordedBefore : rawDatabase (rawInputOf
      (transcriptInput commitmentPrefix response)) = some digest)
    (recordedAfter : rawDatabase (rawInputOf (transcriptInput commitmentPrefix
      (reconstructedTranscript opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)
        (publicBatchedTarget publicWords matrix)))) = some digest) :
    ∀ rows : RecoveredRows,
      SameRestoredTranscript publicWords rows matrix response opening witness masks
        (fun row => nonlinearHighPart (high.nonlinear row))
        (fun row => linearHighPart (high.linear row))
        (publicCorrection publicWords matrix opening high
          (verifierEvaluationTrace publicWords matrix opening witness masks)) := by
  intro rows
  have after : rawDatabase (rawInputOf (transcriptInput commitmentPrefix
      (reconstructedTranscript opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)
        (batchedTarget (recoveredCandidate publicWords rows) matrix)))) = some digest := by
    rw [recovered_batched_target_is_public]
    exact recordedAfter
  have bound := raw_recorded_reconstruction rawDatabase collisionFree commitmentPrefix
    digest publicWords rows matrix response opening witness masks high recordedBefore after
  rw [verifier_correction_is_public] at bound
  exact bound

end
end HegemonCrypto.SmallWood.SmzaRp04PublicTargetReadback

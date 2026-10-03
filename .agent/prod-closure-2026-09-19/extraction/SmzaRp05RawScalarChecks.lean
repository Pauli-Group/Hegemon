import SmzaRp05RelationRefinement
import SmzaRp04RawRecordedTranscript
import SmzaRp05AbstractReconstructionProjection

/-! # Current RP05 scalar checks from the actual reconstructed hash input

Only the relation-neutral raw SMZA final-input injectivity is reused from
the RP04 namespace. The scalar evaluations, width and public targets below
come from the current RP05 DSL, not the RP04 relation program.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05RawScalarChecks

open Polynomial
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05RelationRefinement SmzaRp05StatementNamespace
open SmzaRp04RawRecordedTranscript SmzaRp04RecordedTranscript
open SmzaQ38Recovery
open V8Smz9PiopSoundness V8Smz9PiopReconstruction
open V8Smz9AdaptiveFiniteAccounting V8Smz9ZeroKnowledge V8Smz9EagerSimulator
open scoped Classical BigOperators

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false

def publicBatchedTarget (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (row : Fin 5) : Goldilocks :=
  ∑ check, matrix row check * paddedTarget dsl statement check

def verifierEvaluationTrace (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks) :
    EvaluationTrace where
  nonlinear row coordinate :=
    (∑ check, matrix row check * paddedNonlinearScalar dsl statement
      (witness coordinate) check) /
      SmzaRp04RestoredTranscriptChecks.denominator (baseOpeningPoints opening.1 coordinate) +
        masks.1 coordinate row
  linear row coordinate :=
    (∑ check, matrix row check * paddedLinearScalar dsl statement
      (witness coordinate) (baseOpeningPoints opening.1 coordinate) check) +
        masks.2 coordinate row

theorem batched_target_eq_public
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows)
    (matrix : Matrix (dsl.width statement)) :
    batchedTarget (candidate dsl certificates statement rows) matrix =
      publicBatchedTarget dsl statement matrix := by
  rfl

/-- A single recorded before/after final hash forces all current scalar
checks for every recovered row candidate. The public omitted-constant
correction is reconstructed exactly and does not assume a valid witness. -/
theorem one_recorded_reconstruction_supplies_current_scalar_checks
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement)
    (database : Database RawInput RawDigest) (collisionFree : CollisionFree database)
    (commitmentPrefix digest : RawDigest)
    (matrix : Matrix (dsl.width statement)) (response : ClaimedTranscript)
    (opening : Opening) (message : SmzaRp04ChronologicalAlgebra.OpeningMessage)
    (high : ProofHighs)
    (recordedBefore : database (rawInputOf (transcriptInput commitmentPrefix response)) = some digest)
    (recordedAfter : database (rawInputOf (transcriptInput commitmentPrefix
      (reconstructedTranscript opening high
        (verifierEvaluationTrace dsl statement matrix opening message.witness message.masks)
        (publicBatchedTarget dsl statement matrix)))) = some digest) :
    ∀ rows : RecoveredRows,
      SmzaRp05RelationRefinement.ScalarChecks dsl certificates statement rows
        matrix response opening message := by
  let evaluation := verifierEvaluationTrace dsl statement matrix opening message.witness message.masks
  let rebuilt := reconstructedTranscript opening high evaluation (publicBatchedTarget dsl statement matrix)
  have same := raw_recorded_transcripts_same_components database collisionFree
    commitmentPrefix digest response rebuilt recordedBefore recordedAfter
  intro rows row coordinate
  -- `OpeningIndex` is definitionally `Fin 6`; expose that small carrier before
  -- matching the restoration lemmas, whose indices are written as `Fin 6`.
  change Fin 6 at coordinate
  constructor
  · have restoredAtPoint : (response.nonlinear row).eval
        (baseOpeningPoints opening.1 coordinate) =
        evaluation.nonlinear row coordinate := by
      have projected :=
        SmzaRp05AbstractReconstructionProjection.reconstructed_nonlinear_evaluation
          opening high evaluation (publicBatchedTarget dsl statement matrix)
          row coordinate
      have projectedAtPoint : (rebuilt.nonlinear row).eval
          (baseOpeningPoints opening.1 coordinate) =
          evaluation.nonlinear row coordinate := by
        simpa only [rebuilt, points] using projected
      rw [same.1 row]
      exact projectedAtPoint
    have traceAtPoint : evaluation.nonlinear row coordinate =
        (∑ check, matrix row check * paddedNonlinearScalar dsl statement
          (message.witness coordinate) check) /
            SmzaRp04RestoredTranscriptChecks.denominator
              (baseOpeningPoints opening.1 coordinate) +
          message.masks.1 coordinate row := rfl
    have denominatorEq :
        SmzaRp04RestoredTranscriptChecks.denominator
          (baseOpeningPoints opening.1 coordinate) =
        (Interactive.packingVanishing (Finset.univ : Finset (Fin 64))
          V8Smz9EagerSimulator.canonicalPacking).eval
            (baseOpeningPoints opening.1 coordinate) := rfl
    rw [← denominatorEq, restoredAtPoint, traceAtPoint]
    rw [add_sub_cancel_right, mul_div_cancel₀ _
      (SmzaRp04RestoredTranscriptChecks.admissible_denominator_nonzero opening coordinate)]
  · have linearSame : claimedLinear (candidate dsl certificates statement rows) matrix response row =
        claimedLinear (candidate dsl certificates statement rows) matrix rebuilt row := by
      unfold claimedLinear
      rw [same.2]
    rw [linearSame]
    have restored : claimedLinear (candidate dsl certificates statement rows) matrix rebuilt row =
        reconstructedLinear opening (high.linear row) (evaluation.linear row)
          (publicBatchedTarget dsl statement matrix row) := by
      have targetEq := batched_target_eq_public dsl certificates statement rows matrix
      simpa only [rebuilt, targetEq] using
        (reconstructed_claimed_linear (candidate dsl certificates statement rows)
          matrix opening high evaluation row)
    have restoredAtPoint :
        (reconstructedLinear opening (high.linear row) (evaluation.linear row)
          (publicBatchedTarget dsl statement matrix row)).eval
            (baseOpeningPoints opening.1 coordinate) =
          evaluation.linear row coordinate := by
      unfold reconstructedLinear
      have corrected := corrected_linear_evaluation opening
        (restoredLinearBase opening (high.linear row) (evaluation.linear row))
        (publicBatchedTarget dsl statement matrix row) coordinate
      have base := restored_linear_base_evaluation opening
        (high.linear row) (evaluation.linear row) coordinate
      have correctedAtPoint :
          (correctedLinear opening
            (restoredLinearBase opening (high.linear row) (evaluation.linear row))
            (publicBatchedTarget dsl statement matrix row)).eval
              (baseOpeningPoints opening.1 coordinate) =
          (restoredLinearBase opening (high.linear row)
            (evaluation.linear row)).eval
              (baseOpeningPoints opening.1 coordinate) := by
        simpa only [points] using corrected
      have baseAtPoint :
          (restoredLinearBase opening (high.linear row)
            (evaluation.linear row)).eval
              (baseOpeningPoints opening.1 coordinate) =
          evaluation.linear row coordinate := by
        simpa only [points] using base
      exact correctedAtPoint.trans baseAtPoint
    rw [restored, restoredAtPoint]
    have traceAtPoint : evaluation.linear row coordinate =
        (∑ check, matrix row check * paddedLinearScalar dsl statement
          (message.witness coordinate) (baseOpeningPoints opening.1 coordinate) check) +
          message.masks.2 coordinate row := rfl
    rw [traceAtPoint, add_sub_cancel_right]

end
end HegemonCrypto.SmallWood.SmzaRp05RawScalarChecks

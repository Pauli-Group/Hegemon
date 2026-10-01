import SmzaRp04RestoredTranscriptChecks
import HegemonCrypto.SmallWoodV8Smz9PiopReconstruction
import HegemonCrypto.FiniteOracleDatabase
import SmallWoodV8SmzaOracleParserR2

/-!
# Recorded RP04 PIOP transcript binding

The PIOP hash commits to a preceding 512-bit digest, 489 nonlinear coefficients
and 132 nonconstant linear coefficients per repetition.  It does NOT commit to
the omitted linear constant.  This file uses the actual restore-and-correct
construction to recover that constant from the public target, then derives
`SameRestoredTranscript` from two recorded inputs with the accepted digest.

The database here is the typed PIOP subtable.  Recording the two claims in the
same raw oracle execution and transporting its collision event are separate
execution obligations; no probability or global hash injectivity is assumed.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04RecordedTranscript

open Polynomial HegemonCrypto.FiniteOracleDatabase
open V8Smz9PiopSoundness V8Smz9PiopReconstruction
open V8Smz9AdaptiveFiniteAccounting SmzaQ38Recovery
open SmzaRp04PublicContext SmzaRp04ScalarCheckTransport
open SmzaRp04ActualProgram
open SmzaRp04RestoredTranscriptChecks V8Smz9ZeroKnowledge
open V8Smz9EagerSimulator
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

structure PiopInput where
  commitmentPrefix : V8SmzaOracleParser.RawDigest
  nonlinear : Fin 5 → Fin 489 → Goldilocks
  linearHigh : Fin 5 → Fin 132 → Goldilocks

def transcriptInput (commitmentPrefix : V8SmzaOracleParser.RawDigest)
    (response : ClaimedTranscript) : PiopInput where
  commitmentPrefix := commitmentPrefix
  nonlinear row index := (response.nonlinear row).coeff index.val
  linearHigh := response.linearHigh

theorem bounded_polynomial_eq_of_coefficients
    (left right : Goldilocks[X])
    (leftDegree : left.natDegree ≤ 488) (rightDegree : right.natDegree ≤ 488)
    (same : ∀ index : Fin 489, left.coeff index.val = right.coeff index.val) :
    left = right := by
  ext degree
  by_cases within : degree < 489
  · exact same ⟨degree, within⟩
  · rw [coeff_eq_zero_of_natDegree_lt (by omega : left.natDegree < degree),
      coeff_eq_zero_of_natDegree_lt (by omega : right.natDegree < degree)]

theorem recorded_transcripts_same_components
    (database : Database PiopInput V8SmzaOracleParser.RawDigest)
    (collisionFree : CollisionFree database)
    (prefixLeft prefixRight digest : V8SmzaOracleParser.RawDigest)
    (left right : ClaimedTranscript)
    (recordedLeft : database (transcriptInput prefixLeft left) = some digest)
    (recordedRight : database (transcriptInput prefixRight right) = some digest) :
    (∀ row, left.nonlinear row = right.nonlinear row) ∧
      left.linearHigh = right.linearHigh := by
  have same := input_unique_of_same_recorded_output collisionFree recordedLeft recordedRight
  constructor
  · intro row
    apply bounded_polynomial_eq_of_coefficients _ _
      (left.nonlinearDegree row) (right.nonlinearDegree row)
    intro index
    exact congrArg (fun input : PiopInput => input.nonlinear row index) same
  · exact congrArg PiopInput.linearHigh same

/-- Literal arithmetic used to restore the hashed polynomials from six opened
witness/mask evaluations; relation satisfaction is not a premise. -/
def verifierEvaluationTrace (publicWords : List Nat)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks) :
    EvaluationTrace where
  nonlinear row coordinate :=
    (∑ check, matrix row check * nonlinearAt publicWords (witness coordinate) check) /
      denominator (baseOpeningPoints opening.1 coordinate) + masks.1 coordinate row
  linear row coordinate :=
    (∑ check, matrix row check * linearAt publicWords (witness coordinate)
      (baseOpeningPoints opening.1 coordinate) check) + masks.2 coordinate row

def verifierCorrection (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening)
    (high : ProofHighs) (trace : EvaluationTrace) (row : Fin 5) : Goldilocks :=
  (batchedTarget (recoveredCandidate publicWords rows) matrix row -
    V8Smz9PiopOpeningRecovery.packingSum packingPoint
      (restoredLinearBase opening (high.linear row) (trace.linear row))) /
        linearPiopCorrectionFactor (points opening)

attribute [local irreducible] batchingWidth recoveredCandidate nonlinearAt linearAt

theorem verifier_nonlinear_restore (publicWords : List Nat)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (high : ProofHighs) (row : Fin 5) :
    restoredNonlinear opening (high.nonlinear row)
      ((verifierEvaluationTrace publicWords matrix opening witness masks).nonlinear row) =
    nonlinearRestored publicWords matrix opening witness masks
      (fun row => nonlinearHighPart (high.nonlinear row)) row := by
  unfold restoredNonlinear nonlinearRestored points
  congr 1

theorem verifier_linear_values (publicWords : List Nat)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (row : Fin 5) :
    augmentedValues ((verifierEvaluationTrace publicWords matrix opening witness masks).linear row) =
      linearValues publicWords matrix opening witness masks row := by
  funext index
  cases index <;> rfl

theorem verifier_linear_restore (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (high : ProofHighs) (row : Fin 5) :
    reconstructedLinear opening (high.linear row)
      ((verifierEvaluationTrace publicWords matrix opening witness masks).linear row)
      (batchedTarget (recoveredCandidate publicWords rows) matrix row) =
    linearRestored publicWords matrix opening witness masks
      (fun row => linearHighPart (high.linear row))
      (verifierCorrection publicWords rows matrix opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)) row := by
  unfold reconstructedLinear correctedLinear linearRestored verifierCorrection
  apply congrArg₂ (fun left right : Goldilocks[X] => left + right)
  · unfold restoredLinearBase points
    rw [verifier_linear_values]
  · rfl

/-- Hash equality supplies the nonlinear polynomial and all nonconstant
linear coefficients; the checked correction supplies the missing constant.
No `SameRestoredTranscript` or scalar-check premise is used. -/
theorem recorded_reconstruction_supplies_restored_transcript
    (database : Database PiopInput V8SmzaOracleParser.RawDigest)
    (collisionFree : CollisionFree database)
    (commitmentPrefix digest : V8SmzaOracleParser.RawDigest)
    (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (high : ProofHighs)
    (recordedBefore : database (transcriptInput commitmentPrefix response) = some digest)
    (recordedAfter : database (transcriptInput commitmentPrefix
      (reconstructedTranscript opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)
        (batchedTarget (recoveredCandidate publicWords rows) matrix))) = some digest) :
    SameRestoredTranscript publicWords rows matrix response opening witness masks
      (fun row => nonlinearHighPart (high.nonlinear row))
      (fun row => linearHighPart (high.linear row))
      (verifierCorrection publicWords rows matrix opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)) := by
  let trace := verifierEvaluationTrace publicWords matrix opening witness masks
  let rebuilt := reconstructedTranscript opening high trace
    (batchedTarget (recoveredCandidate publicWords rows) matrix)
  have same := recorded_transcripts_same_components database collisionFree commitmentPrefix commitmentPrefix
    digest response rebuilt recordedBefore recordedAfter
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
end HegemonCrypto.SmallWood.SmzaRp04RecordedTranscript

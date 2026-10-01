import SmzaRp04ActualProgram
import SmzaQ38OpeningFieldReadbackR3

/-! Actual generated nonlinear DAG and normalized CSR field checks transport
through recovered witness/mask scalars. No recovered OpeningAccepts premise.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04ScalarCheckTransport

open Polynomial V8Smz9ZeroKnowledge
open SmzaQ38Recovery SmzaRp04ActualProgram SmzaQ38LvcsOpening
open SmzaQ38OpeningFieldReadback
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open SmzaRp04PublicContext SmzaRp04ProgramPiop
open V8Smz9EagerSimulator V8Smz9EagerPrivacy
open scoped BigOperators
noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

def nonlinearAt (publicWords : List Nat) (witness : Fin 686 → Goldilocks)
    (check : Fin (batchingWidth publicWords)) : Goldilocks :=
  if bound : check.val < 773 then
    currentConstraintOpenings (publicParameters publicWords 0) witness ⟨check.val, bound⟩
  else 0

def linearAt (publicWords : List Nat) (witness : Fin 686 → Goldilocks)
    (point : Goldilocks) (check : Fin (batchingWidth publicWords)) : Goldilocks :=
  if bound : check.val < (retainedAttempts publicWords).length then
    V8Smz9PiopOpeningRecovery.publicLinearOpening
      (SmzaRp04DecodedPolynomialSource.retainedLinearWeights publicWords ⟨check.val, bound⟩)
      (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking) witness point
  else 0

theorem recovered_nonlinear_evaluation (publicWords : List Nat) (rows : RecoveredRows)
    (check : Fin (batchingWidth publicWords)) (point : Goldilocks) :
    ((recoveredCandidate publicWords rows).nonlinear check).eval point =
      nonlinearAt publicWords (fun row => (recoveredWitnessPolynomial rows row).eval point) check := by
  change (SmzaRp04DecodedPolynomialSource.paddedNonlinear publicWords
    (headCoordinateAdapter rows) check).eval point = _
  by_cases bound : check.val < 773
  · simp only [SmzaRp04DecodedPolynomialSource.paddedNonlinear, nonlinearAt, dif_pos bound]
    rw [current_constraint_evaluation _ _
      (SmzaRp04DecodedPolynomialSource.witness_polynomials_degree _)]
    simp only [adapted_witness_polynomial_is_exact_q38]
  · simp only [SmzaRp04DecodedPolynomialSource.paddedNonlinear, nonlinearAt, dif_neg bound, eval_zero]

theorem recovered_linear_evaluation (publicWords : List Nat) (rows : RecoveredRows)
    (check : Fin (batchingWidth publicWords)) (point : Goldilocks) :
    ((recoveredCandidate publicWords rows).linear check).eval point =
      linearAt publicWords (fun row => (recoveredWitnessPolynomial rows row).eval point) point check := by
  change (SmzaRp04DecodedPolynomialSource.paddedLinear publicWords
    (headCoordinateAdapter rows) check).eval point = _
  by_cases bound : check.val < (retainedAttempts publicWords).length
  · simp only [SmzaRp04DecodedPolynomialSource.paddedLinear, linearAt, dif_pos bound]
    unfold SmzaRp04DecodedPolynomialSource.retainedLinearPolynomial
    rw [V8Smz9PiopOpeningRecovery.source_linear_unmasked_evaluation]
    simp only [adapted_witness_polynomial_is_exact_q38]
  · simp only [SmzaRp04DecodedPolynomialSource.paddedLinear, linearAt, dif_neg bound, eval_zero]

theorem adapted_column_polynomial_is_recovered_column (rows : RecoveredRows) (column : Fin 736) :
    SmzaRp04DecodedPolynomialSource.columnPolynomial (headCoordinateAdapter rows) column =
      recoveredColumn rows column := by
  unfold SmzaRp04DecodedPolynomialSource.columnPolynomial recoveredColumn
  apply Finset.sum_congr rfl
  intro coefficient _
  rw [adapted_unstacked_cell_is_exact_q38_cell]

theorem recovered_nonlinear_mask_evaluation (publicWords : List Nat) (rows : RecoveredRows)
    (row : Fin 5) (point : Goldilocks) :
    ((recoveredCandidate publicWords rows).nonlinearMask row).eval point =
      nonlinearScalar point (fun column => (recoveredColumn rows column).eval point) row := by
  change (SmzaRp04DecodedPolynomialSource.nonlinearMasks (headCoordinateAdapter rows) row).eval point = _
  rw [SmzaRp04DecodedPolynomialSource.nonlinear_masks_evaluate]
  unfold nonlinearScalar
  apply congrArg (sourceNonlinearReconstruction point)
  funext column
  change (SmzaRp04DecodedPolynomialSource.columnPolynomial (headCoordinateAdapter rows)
      (Fin.natAdd 686 (Fin.castAdd 10 (finProdFinEquiv (row, column))))).eval point = _
  rw [adapted_column_polynomial_is_recovered_column]

theorem recovered_linear_mask_evaluation (publicWords : List Nat) (rows : RecoveredRows)
    (row : Fin 5) (point : Goldilocks) :
    ((recoveredCandidate publicWords rows).linearMask row).eval point =
      linearScalar point (fun column => (recoveredColumn rows column).eval point) row := by
  change (SmzaRp04DecodedPolynomialSource.linearMasks (headCoordinateAdapter rows) row).eval point = _
  rw [SmzaRp04DecodedPolynomialSource.linear_masks_evaluate]
  change
    (SmzaRp04DecodedPolynomialSource.columnPolynomial (headCoordinateAdapter rows)
      (Fin.natAdd 686 (Fin.natAdd 40 (finProdFinEquiv (row, (0 : Fin 2)))))).eval point +
    point ^ 63 * (SmzaRp04DecodedPolynomialSource.columnPolynomial (headCoordinateAdapter rows)
      (Fin.natAdd 686 (Fin.natAdd 40 (finProdFinEquiv (row, (1 : Fin 2)))))).eval point = _
  simp only [adapted_column_polynomial_is_recovered_column, linearScalar]

/-- Multiplied form of the actual public mask reconstruction equations.
The nonlinear equation uses the packing vanishing factor; no arbitrary
candidate-polynomial evaluation is supplied as the constraint opening. -/
def ScalarChecks (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) : Prop :=
  ∀ row coordinate,
    (Interactive.packingVanishing (Finset.univ : Finset (Fin 64)) packingPoint).eval
        (baseOpeningPoints opening.1 coordinate) *
      ((response.nonlinear row).eval (baseOpeningPoints opening.1 coordinate) -
        masks.1 coordinate row) =
      ∑ check, matrix row check * nonlinearAt publicWords (witness coordinate) check ∧
    (claimedLinear (recoveredCandidate publicWords rows) matrix response row).eval
        (baseOpeningPoints opening.1 coordinate) - masks.2 coordinate row =
      ∑ check, matrix row check * linearAt publicWords (witness coordinate)
        (baseOpeningPoints opening.1 coordinate) check

theorem recovered_scalars_and_actual_checks_imply_opening_acceptance
    (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks)
    (witnessEqual : ∀ coordinate row, witness coordinate row =
      (recoveredWitnessPolynomial rows row).eval (baseOpeningPoints opening.1 coordinate))
    (nonlinearEqual : ∀ coordinate row, masks.1 coordinate row =
      ((recoveredCandidate publicWords rows).nonlinearMask row).eval
        (baseOpeningPoints opening.1 coordinate))
    (linearEqual : ∀ coordinate row, masks.2 coordinate row =
      ((recoveredCandidate publicWords rows).linearMask row).eval
        (baseOpeningPoints opening.1 coordinate))
    (checked : ScalarChecks publicWords rows matrix response opening witness masks) :
    OpeningAccepts (recoveredCandidate publicWords rows) matrix response opening := by
  have witnessFunctions : ∀ coordinate, witness coordinate =
      (fun row => (recoveredWitnessPolynomial rows row).eval
        (baseOpeningPoints opening.1 coordinate)) := by
    intro coordinate
    funext row
    exact witnessEqual coordinate row
  intro row coordinate
  obtain ⟨nonlinear, linear⟩ := checked row coordinate
  rw [witnessFunctions coordinate, nonlinearEqual coordinate row] at nonlinear
  rw [witnessFunctions coordinate, linearEqual coordinate row] at linear
  constructor
  · unfold nonlinearDiscrepancy V8Smz9AdmissibleRootProbability.smz9ConsistencyDiscrepancy
      PiopEvaluation.consistencyDiscrepancy
    simp only [eval_sub, eval_mul, PiopExtraction.nonlinearBatch, Interactive.batch,
      Candidate.system, eval_finsetSum, eval_C, recovered_nonlinear_evaluation]
    exact sub_eq_zero.mpr nonlinear
  · unfold linearDiscrepancy
    simp only [eval_sub, PiopExtraction.linearBatch, Interactive.batch,
      Candidate.system, eval_finsetSum, eval_mul, eval_C, recovered_linear_evaluation]
    exact sub_eq_zero.mpr linear

theorem reconstructed_columns_and_actual_checks_imply_opening_acceptance
    (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (partials : SourcePcsView Goldilocks)
    (columns : reconstructedColumnEvaluations (baseOpeningPoints opening.1) witness masks partials =
      (fun coordinate column => (recoveredColumn rows column).eval
        (baseOpeningPoints opening.1 coordinate)))
    (checked : ScalarChecks publicWords rows matrix response opening witness masks) :
    OpeningAccepts (recoveredCandidate publicWords rows) matrix response opening := by
  obtain ⟨witnessReadback, nonlinearReadback, linearReadback⟩ :=
    column_agreement_forces_witness_and_mask_scalars rows (baseOpeningPoints opening.1)
      witness masks partials columns
  apply recovered_scalars_and_actual_checks_imply_opening_acceptance
    publicWords rows matrix response opening witness masks
  · intro coordinate row
    exact witnessReadback coordinate row
  · intro coordinate row
    rw [recovered_nonlinear_mask_evaluation]
    exact nonlinearReadback coordinate row
  · intro coordinate row
    rw [recovered_linear_mask_evaluation]
    exact linearReadback coordinate row
  · exact checked

end
end HegemonCrypto.SmallWood.SmzaRp04ScalarCheckTransport

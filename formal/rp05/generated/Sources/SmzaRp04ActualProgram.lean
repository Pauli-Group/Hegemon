import SmzaQ38Recovery
import SmzaPiopGoodOutcomeR2
import SmzaRp04SourceAcceptance

/-! q38 recovered rows to the actual HGV8RP04 executable relation.

The translation P(X+18) is ONLY a coordinate adapter for the existing
20+j head decoder: its value there is P(38+j). It does not translate DECS
opening points, commitments, query schedules, or probability bounds.
The PIOP candidate below is calculated from recovered rows before gamma;
the claimed transcript is fixed before the six PIOP opening challenges.
No evaluator-success or extraction-success premise is accepted.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04ActualProgram

open Polynomial
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaQ38OracleExtraction SmzaQ38Recovery
open V8Smz9PiopSoundness SmzaPiopGoodOutcome
open SmzaRp04Components
open scoped BigOperators

noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

/-- Pure head-coordinate transport. DECS mask rows are not consumed by the
downstream head decoder; they are not being asserted to be zero in the proof. -/
def headCoordinateAdapter (rows : RecoveredRows) :
    SmzaRp04DecodedPolynomialSource.SourcePolynomials where
  data row := (rows row).comp (X + C 18)
  masks _ := 0

theorem adapted_head_is_exact_q38_head (rows : RecoveredRows)
    (row : Fin 140) (column : Fin 368) :
    SmzaRp04DecodedPolynomialSource.rowHead (headCoordinateAdapter rows) row column =
      (rows row).eval (lvcsDataPoint column) := by
  simp only [SmzaRp04DecodedPolynomialSource.rowHead, headCoordinateAdapter,
    eval_comp, eval_add, eval_X, eval_C]
  congr 1
  change ((20 + column.val : Nat) : Goldilocks) + 18 =
    ((38 + column.val : Nat) : Goldilocks)
  push_cast
  ring

theorem adapted_unstacked_cell_is_exact_q38_cell (rows : RecoveredRows)
    (coefficient : Fin 70) (column : Fin 736) :
    SmzaRp04DecodedPolynomialSource.unstackedCell (headCoordinateAdapter rows)
      coefficient column = recoveredUnstackedCell rows coefficient column := by
  unfold SmzaRp04DecodedPolynomialSource.unstackedCell
  rw [adapted_head_is_exact_q38_head]
  unfold recoveredUnstackedCell
  have rowIndex :
      finProdFinEquiv
        (((finProdFinEquiv : Fin 2 × Fin 368 ≃ Fin 736).symm column).1,
          coefficient) = stackedRowIndex coefficient column := by
    apply Fin.ext
    change coefficient.val + 70 * (column.val / 368) =
      (column.val / 368) * 70 + coefficient.val
    omega
  have columnIndex :
      ((finProdFinEquiv : Fin 2 × Fin 368 ≃ Fin 736).symm column).2 =
        stackedColumnIndex column := by rfl
  rw [rowIndex, columnIndex]

theorem adapted_witness_polynomial_is_exact_q38 (rows : RecoveredRows)
    (column : Fin 686) :
    SmzaRp04DecodedPolynomialSource.witnessPolynomials (headCoordinateAdapter rows) column =
      recoveredWitnessPolynomial rows column := by
  change SmzaRp04DecodedPolynomialSource.columnPolynomial (headCoordinateAdapter rows)
      (witnessColumnIndex column) = _
  unfold SmzaRp04DecodedPolynomialSource.columnPolynomial recoveredWitnessPolynomial
  apply Finset.sum_congr rfl
  intro coefficient _
  rw [adapted_unstacked_cell_is_exact_q38_cell]

theorem adapted_packed_witness_is_exact_q38 (rows : RecoveredRows) :
    SmzaRp04DecodedPolynomialSource.packedWitness (headCoordinateAdapter rows) =
      packedFromRows rows := by
  unfold SmzaRp04DecodedPolynomialSource.packedWitness packedFromRows
  apply congrArg (fun f : Fin 43904 → Nat => List.ofFn f)
  funext index
  change ((SmzaRp04DecodedPolynomialSource.witnessPolynomials (headCoordinateAdapter rows)
      ((finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index).1).eval
        (V8Smz9EagerSimulator.canonicalPacking
          ((finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index).2)).val =
    ((recoveredWitnessPolynomial rows
      ((finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index).1).eval
        (V8Smz9EagerSimulator.canonicalPacking
          ((finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index).2)).val
  rw [adapted_witness_polynomial_is_exact_q38]

/-- Concrete generated nonlinear roots and retained normalized CSR rows,
including the exact arbitrary recovered PCS mask columns. -/
def recoveredCandidate (publicWords : List Nat) (rows : RecoveredRows) :
    Candidate (SmzaRp04PublicContext.batchingWidth publicWords) :=
  SmzaRp04DecodedPolynomialSource.sourcePiopCandidate publicWords (headCoordinateAdapter rows)

/-- The source's auxiliary DECS masking polynomials are not PCS mask columns.
Changing the former cannot alter the candidate calculated from the 140 data
rows; the latter remain present among all 736 recovered head columns. -/
theorem auxiliary_decs_masks_do_not_change_candidate
    (publicWords : List Nat) (rows : RecoveredRows)
    (auxiliaryMasks : Fin 5 → Goldilocks[X]) :
    SmzaRp04DecodedPolynomialSource.sourcePiopCandidate publicWords
      { headCoordinateAdapter rows with masks := auxiliaryMasks } =
        recoveredCandidate publicWords rows := by
  rfl

theorem recovered_candidate_satisfaction_supplies_actual_program
    (publicWords : List Nat) (rows : RecoveredRows)
    (canonicalPublic : CanonicalPublicWords publicWords)
    (satisfied : PiopExtraction.FullySatisfied (recoveredCandidate publicWords rows).system) :
    program.AcceptsPacked publicWords (packedFromRows rows) := by
  rw [← adapted_packed_witness_is_exact_q38]
  exact SmzaRp04SourceAcceptance.fully_satisfied_decoded_candidate_supplies_packed_acceptance
    publicWords (headCoordinateAdapter rows) canonicalPublic satisfied

/-- Deterministic endpoint. The two detection predicates refer to the actual
calculated q38 candidate, not an existential valid witness or success flag.
Their probability bounds and the preceding commitment/recovery linkage remain
separate obligations with their original sampling chronology. -/
theorem accepted_recovered_q38_piop_supplies_actual_program
    (publicWords : List Nat) (rows : RecoveredRows)
    (canonicalPublic : CanonicalPublicWords publicWords)
    (matrix : Matrix (SmzaRp04PublicContext.batchingWidth publicWords))
    (response : ClaimedTranscript) (opening : Opening)
    (accepted : OpeningAccepts (recoveredCandidate publicWords rows) matrix response opening)
    (rootDetection : DiscrepanciesDetected (recoveredCandidate publicWords rows)
      matrix response opening)
    (residualDetection : ResidualsDetected (recoveredCandidate publicWords rows) matrix) :
    program.AcceptsPacked publicWords (packedFromRows rows) :=
  recovered_candidate_satisfaction_supplies_actual_program publicWords rows canonicalPublic
    (accepted_piop_outside_named_algebraic_events_satisfies_candidate
      (recoveredCandidate publicWords rows) matrix response opening accepted
      rootDetection residualDetection)

theorem selected_support_good_piop_supplies_actual_program
    (publicWords : List Nat) (support : RecoverySupport) (oracle : CommittedOracle)
    (rows : RecoveredRows) (canonicalPublic : CanonicalPublicWords publicWords)
    (degreeBound : ∀ row, (rows row).degree < (406 : WithBot Nat))
    (agreement : ∀ row index,
      (rows row).eval (smz9EvaluationPoint (support index)) =
        committedColumnValue oracle row (support index))
    (matrix : Matrix (SmzaRp04PublicContext.batchingWidth publicWords))
    (response : ClaimedTranscript) (opening : Opening)
    (accepted : OpeningAccepts (recoveredCandidate publicWords rows) matrix response opening)
    (rootDetection : DiscrepanciesDetected (recoveredCandidate publicWords rows)
      matrix response opening)
    (residualDetection : ResidualsDetected (recoveredCandidate publicWords rows) matrix) :
    program.AcceptsPacked publicWords
      (packedFromRows (interpolateRowsOn support oracle)) := by
  rw [selected_support_recovers_exact_q38_packed_witness support oracle rows degreeBound agreement]
  exact accepted_recovered_q38_piop_supplies_actual_program publicWords rows canonicalPublic
    matrix response opening accepted rootDetection residualDetection

end
end HegemonCrypto.SmallWood.SmzaRp04ActualProgram

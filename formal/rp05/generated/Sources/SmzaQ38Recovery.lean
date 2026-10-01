import SmzaQ38OracleExtraction

/-! Exact q38 inverse on a recovered polynomial family. Agreement is required
only on 406 distinct selected points, not the complete oracle table. Choosing
that support from an accepted proof and bounding a bad choice remain separate. -/

namespace HegemonCrypto.SmallWood.SmzaQ38Recovery

open Polynomial
open HegemonCrypto.SmallWood
open SmzaQ38OracleExtraction

noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

abbrev RecoveredRows := Fin lvcsRowCount → Goldilocks[X]
abbrev RecoverySupport := Fin 406 ↪ Fin decsDomainSize

def interpolateRowsOn (support : RecoverySupport) (oracle : CommittedOracle) : RecoveredRows :=
  fun row => Lagrange.interpolate (Finset.univ : Finset (Fin 406))
    (fun index => smz9EvaluationPoint (support index))
    (fun index => committedColumnValue oracle row (support index))

theorem selected_support_recovers_degree405_row
    (support : RecoverySupport) (oracle : CommittedOracle)
    (row : Fin lvcsRowCount) (polynomial : Goldilocks[X])
    (degreeBound : polynomial.degree < (406 : WithBot Nat))
    (agreement : ∀ index : Fin 406,
      polynomial.eval (smz9EvaluationPoint (support index)) =
        committedColumnValue oracle row (support index)) :
    interpolateRowsOn support oracle row = polynomial := by
  have injective : Function.Injective (fun index : Fin 406 =>
      smz9EvaluationPoint (support index)) :=
    smz9_evaluation_point_injective.comp support.injective
  have degreeCard : polynomial.degree <
      ((Finset.univ : Finset (Fin 406)).card : WithBot Nat) := by
    simpa using degreeBound
  exact (Lagrange.eq_interpolate_of_eval_eq
    (r := fun index : Fin 406 => committedColumnValue oracle row (support index))
    (s := (Finset.univ : Finset (Fin 406))) injective.injOn degreeCard
    (fun index _ => agreement index)).symm

def recoveredUnstackedCell (rows : RecoveredRows)
    (coefficient : Fin unstackedRowCount) (column : Fin unstackedColumnCount) : Goldilocks :=
  (rows (stackedRowIndex coefficient column)).eval
    (lvcsDataPoint (stackedColumnIndex column))

def recoveredWitnessPolynomial (rows : RecoveredRows) (column : Fin relationRows) : Goldilocks[X] :=
  ∑ coefficient : Fin unstackedRowCount,
    C (recoveredUnstackedCell rows coefficient (witnessColumnIndex column)) * X ^ coefficient.val

def packedFromRows (rows : RecoveredRows) : List Nat :=
  List.ofFn fun index : Fin (relationRows * packingFactor) =>
    fromGoldilocks ((recoveredWitnessPolynomial rows (packedWitnessRowIndex index)).eval
      (witnessPackingPoint (packedWitnessLaneIndex index)))

theorem full_table_inverse_is_recovered_rows_inverse (oracle : CommittedOracle) :
    extractPackedWitness oracle = packedFromRows (interpolatedCommittedRow oracle) := by
  rfl

theorem selected_support_recovers_exact_q38_packed_witness
    (support : RecoverySupport) (oracle : CommittedOracle) (rows : RecoveredRows)
    (degreeBound : ∀ row, (rows row).degree < (406 : WithBot Nat))
    (agreement : ∀ row index,
      (rows row).eval (smz9EvaluationPoint (support index)) =
        committedColumnValue oracle row (support index)) :
    packedFromRows (interpolateRowsOn support oracle) = packedFromRows rows := by
  apply congrArg packedFromRows
  funext row
  exact selected_support_recovers_degree405_row support oracle row (rows row)
    (degreeBound row) (agreement row)

theorem selected_support_choice_does_not_change_recovered_witness
    (left right : RecoverySupport) (oracle : CommittedOracle) (rows : RecoveredRows)
    (degreeBound : ∀ row, (rows row).degree < (406 : WithBot Nat))
    (leftAgreement : ∀ row index,
      (rows row).eval (smz9EvaluationPoint (left index)) =
        committedColumnValue oracle row (left index))
    (rightAgreement : ∀ row index,
      (rows row).eval (smz9EvaluationPoint (right index)) =
        committedColumnValue oracle row (right index)) :
    packedFromRows (interpolateRowsOn left oracle) =
      packedFromRows (interpolateRowsOn right oracle) := by
  rw [selected_support_recovers_exact_q38_packed_witness left oracle rows degreeBound leftAgreement,
    selected_support_recovers_exact_q38_packed_witness right oracle rows degreeBound rightAgreement]

end
end HegemonCrypto.SmallWood.SmzaQ38Recovery

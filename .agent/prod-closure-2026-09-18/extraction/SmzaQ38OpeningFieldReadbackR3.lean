import SmzaQ38LvcsOpening
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator

/-! Reverse readback of the actual opened witness/mask scalar reconstruction.
No honest-witness, mask-zero, or evaluator-success hypothesis is used.
-/
namespace HegemonCrypto.SmallWood.SmzaQ38OpeningFieldReadback

open V8Smz9ZeroKnowledge
open SmzaQ38OracleExtraction SmzaQ38Recovery SmzaQ38LvcsOpening
open V8Smz9EagerSimulator V8Smz9EagerPrivacy V8Smz9RuntimeFieldLayout
noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

def nonlinearScalar (point : Goldilocks) (columns : Fin 736 → Goldilocks)
    (row : Fin 5) : Goldilocks :=
  sourceNonlinearReconstruction point (fun column : Fin 8 =>
    columns (Fin.natAdd 686 (Fin.castAdd 10 (finProdFinEquiv (row, column)))))

def linearScalar (point : Goldilocks) (columns : Fin 736 → Goldilocks)
    (row : Fin 5) : Goldilocks :=
  columns (Fin.natAdd 686 (Fin.natAdd 40 (finProdFinEquiv (row, (0 : Fin 2))))) +
    point ^ 63 *
      columns (Fin.natAdd 686 (Fin.natAdd 40 (finProdFinEquiv (row, (1 : Fin 2)))))

theorem nonlinear_reconstruction_reads_back_scalar (point scalar : Goldilocks)
    (partials : Fin 7 → Goldilocks) :
    sourceNonlinearReconstruction point (reconstructNonlinearColumns point scalar partials) = scalar := by
  change (scalar - (point ^ 64 * partials 0 + point ^ 128 * partials 1 +
      point ^ 192 * partials 2 + point ^ 256 * partials 3 + point ^ 320 * partials 4 +
      point ^ 384 * partials 5 + point ^ 419 * partials 6)) +
    point ^ 64 * partials 0 + point ^ 128 * partials 1 + point ^ 192 * partials 2 +
    point ^ 256 * partials 3 + point ^ 320 * partials 4 + point ^ 384 * partials 5 +
    point ^ 419 * partials 6 = scalar
  ring

theorem reconstructed_witness_readback
    (points : Fin 6 → Goldilocks) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (partials : SourcePcsView Goldilocks)
    (opening : Fin 6) (row : Fin 686) :
    reconstructedColumnEvaluations points witness masks partials opening (Fin.castAdd 50 row) =
      witness opening row := by
  exact Fin.append_left (witness opening : Fin 686 → Goldilocks) _ row

theorem reconstructed_nonlinear_mask_readback
    (points : Fin 6 → Goldilocks) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (partials : SourcePcsView Goldilocks)
    (opening : Fin 6) (row : Fin 5) :
    nonlinearScalar (points opening)
      (reconstructedColumnEvaluations points witness masks partials opening) row =
      masks.1 opening row := by
  have readColumn (column : Fin 8) :
      reconstructedColumnEvaluations points witness masks partials opening
        (Fin.natAdd 686 (Fin.castAdd 10 (finProdFinEquiv (row, column)))) =
      reconstructNonlinearColumns (points opening) (masks.1 opening row)
        (partials.1 row opening) column := by
    exact (Fin.append_right (witness opening : Fin 686 → Goldilocks) _
      (Fin.castAdd 10 (finProdFinEquiv (row, column)))).trans
      ((Fin.append_left _ _ (finProdFinEquiv (row, column))).trans
        (matrix_equiv_symm_apply 5 8 Goldilocks _ row column))
  unfold nonlinearScalar
  rw [funext readColumn]
  exact nonlinear_reconstruction_reads_back_scalar _ _ _

theorem reconstructed_linear_mask_readback
    (points : Fin 6 → Goldilocks) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (partials : SourcePcsView Goldilocks)
    (opening : Fin 6) (row : Fin 5) :
    linearScalar (points opening)
      (reconstructedColumnEvaluations points witness masks partials opening) row =
      masks.2 opening row := by
  have readColumn (column : Fin 2) :
      reconstructedColumnEvaluations points witness masks partials opening
        (Fin.natAdd 686 (Fin.natAdd 40 (finProdFinEquiv (row, column)))) =
      reconstructLinearColumns (points opening) (masks.2 opening row)
        (partials.2 row opening) column := by
    exact (Fin.append_right (witness opening : Fin 686 → Goldilocks) _
      (Fin.natAdd 40 (finProdFinEquiv (row, column)))).trans
      ((Fin.append_right _ _ (finProdFinEquiv (row, column))).trans
        (matrix_equiv_symm_apply 5 2 Goldilocks _ row column))
  unfold linearScalar
  rw [readColumn, readColumn]
  change masks.2 opening row - points opening ^ 63 * partials.2 row opening +
    points opening ^ 63 * partials.2 row opening = masks.2 opening row
  exact sub_add_cancel _ _

/-- The actual claimed head is reconstructed from public witness/mask scalars
and partial PCS fields. This is a deterministic message equation, not a
relation-validity or extraction-success predicate. -/
def ClaimedHeadsReconstructed
    (points : Fin 6 → Goldilocks) (claimed : ClaimedPolynomials)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (partials : SourcePcsView Goldilocks) : Prop :=
  ∀ opening block column,
    (claimed (opening, block)).eval (lvcsDataPoint column) =
      reconstructedColumnEvaluations points witness masks partials opening (columnIndex block column)

theorem accepted_heads_force_every_reconstructed_column
    (oracle : CommittedOracle) (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials) (query : SmzaQ38McaSourceBinding.Query)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (partials : SourcePcsView Goldilocks)
    (headBinding : ClaimedHeadsReconstructed points claimed witness masks partials)
    (rowAgreement : ∀ row index, index ∈ query.val →
      (rows row).eval (smz9EvaluationPoint index) = committedColumnValue oracle row index)
    (checked : OracleOpeningChecks oracle points claimed query)
    (detected : SmzaQ38LvcsOpening.DiscrepanciesDetected rows points claimed query) :
    reconstructedColumnEvaluations points witness masks partials =
      (fun opening column => (recoveredColumn rows column).eval (points opening)) := by
  funext opening column
  let block : Fin 2 := ⟨column.val / 368, by omega⟩
  let localColumn : Fin 368 := ⟨column.val % 368, Nat.mod_lt _ (by decide)⟩
  have same : columnIndex block localColumn = column := by
    apply Fin.ext
    change (column.val / 368) * 368 + column.val % 368 = column.val
    omega
  rw [← same, ← headBinding opening block localColumn]
  exact accepted_lvcs_heads_are_actual_recovered_openings oracle rows points claimed query
    rowAgreement checked detected opening block localColumn

/-- All686 witness scalars and both five-mask scalar families follow from
the recovered736-column evaluations, including the shortened nonlinear419 shift. -/
theorem column_agreement_forces_witness_and_mask_scalars
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (partials : SourcePcsView Goldilocks)
    (columns : reconstructedColumnEvaluations points witness masks partials =
      (fun opening column => (recoveredColumn rows column).eval (points opening))) :
    (∀ opening row, witness opening row =
      (recoveredColumn rows (Fin.castAdd 50 row)).eval (points opening)) ∧
    (∀ opening row, masks.1 opening row = nonlinearScalar (points opening)
      (fun column => (recoveredColumn rows column).eval (points opening)) row) ∧
    (∀ opening row, masks.2 opening row = linearScalar (points opening)
      (fun column => (recoveredColumn rows column).eval (points opening)) row) := by
  constructor
  · intro opening row
    rw [← reconstructed_witness_readback points witness masks partials opening row, columns]
  · constructor
    · intro opening row
      rw [← reconstructed_nonlinear_mask_readback points witness masks partials opening row, columns]
    · intro opening row
      rw [← reconstructed_linear_mask_readback points witness masks partials opening row, columns]

end
end HegemonCrypto.SmallWood.SmzaQ38OpeningFieldReadback

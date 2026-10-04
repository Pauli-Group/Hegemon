import SmzaQ38McaSourceBindingR2

/-! The q38 LVCS opening implication, before any probability bound.
Recovered rows are fixed before the six PIOP points; the twelve claimed
combination polynomials are fixed after those points but before the38 DECS
query positions. A nonzero fixed degree405 discrepancy must be detected.
This event is not an assumption that witness extraction already succeeded.
-/
namespace HegemonCrypto.SmallWood.SmzaQ38LvcsOpening

open Polynomial SmzaQ38OracleExtraction SmzaQ38Recovery
open scoped BigOperators
noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

abbrev Combination := Fin 6 × Fin 2
abbrev ClaimedPolynomials := Combination → Goldilocks[X]

def blockRow (block : Fin 2) (coefficient : Fin 70) : Fin 140 :=
  ⟨block.val * 70 + coefficient.val, by omega⟩

/-- Twelve deterministic power combinations of the140 recovered rows. -/
def rowCombination (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (combination : Combination) : Goldilocks[X] :=
  ∑ coefficient : Fin 70,
    C ((points combination.1) ^ coefficient.val) *
      rows (blockRow combination.2 coefficient)

def discrepancy (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials) (combination : Combination) : Goldilocks[X] :=
  claimed combination - rowCombination rows points combination

theorem row_combination_degree405 (rows : RecoveredRows)
    (points : Fin 6 → Goldilocks) (bounded : ∀ row, (rows row).natDegree ≤ 405)
    (combination : Combination) :
    (rowCombination rows points combination).natDegree ≤ 405 := by
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  exact (natDegree_C_mul_le _ _).trans (bounded _)

theorem discrepancy_degree405 (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials) (bounded : ∀ row, (rows row).natDegree ≤ 405)
    (claimedBounded : ∀ combination, (claimed combination).natDegree ≤ 405)
    (combination : Combination) :
    (discrepancy rows points claimed combination).natDegree ≤ 405 := by
  exact (natDegree_sub_le _ _).trans
    (max_le (claimedBounded combination) (row_combination_degree405 rows points bounded combination))

/-- Only the twelve fixed discrepancies are tested, not every polynomial. -/
def DiscrepanciesDetected (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials) (query : SmzaQ38McaSourceBinding.Query) : Prop :=
  ∀ combination, discrepancy rows points claimed combination ≠ 0 →
    ∃ index ∈ query.val,
      (discrepancy rows points claimed combination).eval (smz9EvaluationPoint index) ≠ 0

/-- Direct LVCS equations against the same140 committed row values. -/
def OracleOpeningChecks (oracle : CommittedOracle) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials) (query : SmzaQ38McaSourceBinding.Query) : Prop :=
  ∀ combination index, index ∈ query.val →
    (claimed combination).eval (smz9EvaluationPoint index) =
      ∑ coefficient : Fin 70, points combination.1 ^ coefficient.val *
        committedColumnValue oracle (blockRow combination.2 coefficient) index

theorem accepted_detected_combinations_are_recovered_combinations
    (oracle : CommittedOracle) (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials) (query : SmzaQ38McaSourceBinding.Query)
    (rowAgreement : ∀ row index, index ∈ query.val →
      (rows row).eval (smz9EvaluationPoint index) = committedColumnValue oracle row index)
    (checked : OracleOpeningChecks oracle points claimed query)
    (detected : DiscrepanciesDetected rows points claimed query) :
    ∀ combination, claimed combination = rowCombination rows points combination := by
  intro combination
  apply sub_eq_zero.mp
  change discrepancy rows points claimed combination = 0
  by_contra nonzero
  obtain ⟨index, member, mismatch⟩ := detected combination nonzero
  apply mismatch
  simp only [discrepancy, eval_sub, rowCombination, eval_finsetSum, eval_mul, eval_C]
  rw [checked combination index member]
  apply sub_eq_zero.mpr
  apply Finset.sum_congr rfl
  intro coefficient _
  rw [rowAgreement _ index member]

def recoveredColumn (rows : RecoveredRows) (column : Fin 736) : Goldilocks[X] :=
  ∑ coefficient : Fin 70, C (recoveredUnstackedCell rows coefficient column) * X ^ coefficient.val

def columnIndex (block : Fin 2) (column : Fin 368) : Fin 736 :=
  ⟨block.val * 368 + column.val, by omega⟩

theorem combination_head_is_individual_column_opening
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    (rowCombination rows points (opening, block)).eval (lvcsDataPoint column) =
      (recoveredColumn rows (columnIndex block column)).eval (points opening) := by
  simp only [rowCombination, recoveredColumn, eval_finsetSum, eval_mul, eval_C,
    eval_pow, eval_X]
  apply Finset.sum_congr rfl
  intro coefficient _
  have stackedRow : stackedRowIndex coefficient (columnIndex block column) =
      blockRow block coefficient := by
    apply Fin.ext
    change ((block.val * 368 + column.val) / 368) * 70 + coefficient.val =
      block.val * 70 + coefficient.val
    have bound := column.isLt
    omega
  have stackedColumn : stackedColumnIndex (columnIndex block column) = column := by
    apply Fin.ext
    change (block.val * 368 + column.val) % 368 = column.val
    have bound := column.isLt
    omega
  simp only [recoveredUnstackedCell, stackedRow, stackedColumn]
  ring

/-- Individual recovered column evaluation follows from actual oracle checks
and detection of the twelve pre-query LVCS discrepancy polynomials. -/
theorem accepted_lvcs_heads_are_actual_recovered_openings
    (oracle : CommittedOracle) (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : ClaimedPolynomials) (query : SmzaQ38McaSourceBinding.Query)
    (rowAgreement : ∀ row index, index ∈ query.val →
      (rows row).eval (smz9EvaluationPoint index) = committedColumnValue oracle row index)
    (checked : OracleOpeningChecks oracle points claimed query)
    (detected : DiscrepanciesDetected rows points claimed query)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    (claimed (opening, block)).eval (lvcsDataPoint column) =
      (recoveredColumn rows (columnIndex block column)).eval (points opening) := by
  rw [accepted_detected_combinations_are_recovered_combinations
    oracle rows points claimed query rowAgreement checked detected]
  exact combination_head_is_individual_column_opening rows points opening block column

end
end HegemonCrypto.SmallWood.SmzaQ38LvcsOpening

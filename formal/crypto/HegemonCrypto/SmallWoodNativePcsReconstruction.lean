import HegemonCrypto.SmallWoodLvcsOpening
import HegemonCrypto.SmallWoodNativePackedPolynomial

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact native PCS opening reconstruction

This module mirrors the deterministic data path between `pcs_reconstruct_combi_heads` and
`piop_recompute_transcript`. It starts from the 10 combination heads reconstructed from the
proof's 709 row scalars and 40 auxiliary evaluations, identifies those heads with the committed
unstacked PCS matrix under `ProductionCombinationsMatch`, and then recovers the exact polynomial
evaluations consumed by the native PIOP verifier.
-/

namespace HegemonCrypto.SmallWood.NativePcsReconstruction

open Polynomial
open HegemonCrypto.SmallWood.LvcsOpening
open HegemonCrypto.SmallWood.NativePackedPolynomial
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open scoped BigOperators

noncomputable section

/-- Interpolation index containing one unrotated 375-word combination head value. -/
def lvcsDataIndex (column : Fin lvcsColumnCount) :
    Fin (lvcsColumnCount + decsOpenedEvaluations) :=
  ⟨decsOpenedEvaluations + column.val, by
    have columnBound := column.isLt
    change column.val < 375 at columnBound
    change 23 + column.val < 375 + 23
    omega⟩

/-- Wire index of one of the first 375, unrotated combination-head words. -/
def lvcsHeadIndex (column : Fin lvcsColumnCount) :
    Fin (lvcsColumnCount + decsOpenedEvaluations) :=
  Fin.castAdd decsOpenedEvaluations column

theorem lvcs_interpolation_point_data_index
    (column : Fin lvcsColumnCount) :
    lvcsInterpolationPoint (lvcsDataIndex column) = lvcsDataPoint column := by
  rfl

/-- Evaluating a claimed combination at a data node recovers the transmitted head word. -/
theorem claimed_combination_polynomial_eval_data
    (message : PcsCombinationMessage)
    (combination : Fin openedCombinationCount)
    (column : Fin lvcsColumnCount) :
    (claimedCombinationPolynomial message combination).eval
        (lvcsDataPoint column) =
      wordToGoldilocks (message combination (lvcsHeadIndex column)) := by
  rw [← lvcs_interpolation_point_data_index column]
  unfold claimedCombinationPolynomial
  rw [Lagrange.eval_interpolate_at_node
    _ lvcs_interpolation_point_injective.injOn (Finset.mem_univ _)]
  simp [rotatedCombinationValue, lvcsDataIndex, lvcsHeadIndex]
  congr 2

/-- A matching combination head is the exact weighted committed stacked-row value. -/
theorem matching_combination_head
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (combination : Fin openedCombinationCount)
    (column : Fin lvcsColumnCount) :
    wordToGoldilocks (message combination (lvcsHeadIndex column)) =
      ∑ row : Fin lvcsRowCount,
        productionCombinationCoefficient opening combination row *
          stackedHeadCell oracle row column := by
  have polynomialEquality := matching combination
  have evaluationEquality :=
    congrArg (fun polynomial : Goldilocks[X] =>
      polynomial.eval (lvcsDataPoint column)) polynomialEquality
  rw [claimed_combination_polynomial_eval_data] at evaluationEquality
  unfold committedCombinationPolynomial at evaluationEquality
  rw [eval_finsetSum] at evaluationEquality
  simpa only [eval_mul, eval_C, stackedHeadCell] using evaluationEquality

/-- Canonical block-major enumeration of the 138 stacked LVCS rows. -/
def lvcsBlockRowEquiv :
    Fin beta × Fin unstackedRowCount ≃ Fin lvcsRowCount :=
  finProdFinEquiv.trans (finCongr (by decide))

theorem lvcs_block_row_equiv_value
    (block : Fin beta)
    (row : Fin unstackedRowCount) :
    (lvcsBlockRowEquiv (block, row)).val =
      block.val * unstackedRowCount + row.val := by
  change row.val + unstackedRowCount * block.val =
    block.val * unstackedRowCount + row.val
  ac_rfl

/-- One of the 749 unstacked values represented by the concatenated combination heads. -/
def combinationHeadValue
    (message : PcsCombinationMessage)
    (openingIndex : Fin openedEvaluations)
    (column : Fin unstackedColumnCount) : Goldilocks :=
  let block : Fin beta :=
    ⟨column.val / lvcsColumnCount, by
      have columnBound := column.isLt
      change column.val < 749 at columnBound
      change column.val / 375 < 2
      omega⟩
  let localColumn : Fin lvcsColumnCount :=
    ⟨column.val % lvcsColumnCount, Nat.mod_lt _ (by decide)⟩
  wordToGoldilocks
    (message (productionCombinationIndex openingIndex block)
      (lvcsHeadIndex localColumn))

theorem lvcs_row_block_index_block_row
    (block : Fin beta)
    (row : Fin unstackedRowCount) :
    lvcsRowBlockIndex (lvcsBlockRowEquiv (block, row)) = block := by
  apply Fin.ext
  change (lvcsBlockRowEquiv (block, row)).val / unstackedRowCount = block.val
  rw [lvcs_block_row_equiv_value]
  have rowBound := row.isLt
  change row.val < 69 at rowBound
  change (block.val * 69 + row.val) / 69 = block.val
  omega

theorem lvcs_row_exponent_block_row
    (block : Fin beta)
    (row : Fin unstackedRowCount) :
    lvcsRowExponent (lvcsBlockRowEquiv (block, row)) = row := by
  apply Fin.ext
  change (lvcsBlockRowEquiv (block, row)).val % unstackedRowCount = row.val
  rw [lvcs_block_row_equiv_value]
  have rowBound := row.isLt
  change row.val < 69 at rowBound
  change (block.val * 69 + row.val) % 69 = row.val
  omega

theorem stacked_head_cell_block_row
    (oracle : CommittedOracle)
    (block : Fin beta)
    (row : Fin unstackedRowCount)
    (localColumn : Fin lvcsColumnCount)
    (globalColumn : Fin unstackedColumnCount)
    (blockEquation : globalColumn.val / lvcsColumnCount = block.val)
    (columnEquation : globalColumn.val % lvcsColumnCount = localColumn.val) :
    stackedHeadCell oracle (lvcsBlockRowEquiv (block, row)) localColumn =
      unstackedCell oracle row globalColumn := by
  unfold unstackedCell
  congr 2
  · apply Fin.ext
    rw [lvcs_block_row_equiv_value]
    simp only [stackedRowIndex]
    rw [blockEquation]
  · apply Fin.ext
    simpa [stackedColumnIndex] using columnEquation.symm

/--
Under a matching polynomial commitment, one concatenated head cell is exactly the evaluation at
the selected opening point of its 69-value unstacked column.
-/
theorem matching_combination_head_value
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (column : Fin unstackedColumnCount) :
    combinationHeadValue message openingIndex column =
      ∑ row : Fin unstackedRowCount,
        unstackedCell oracle row column *
          openingEvaluationPoint opening openingIndex ^ row.val := by
  let block : Fin beta :=
    ⟨column.val / lvcsColumnCount, by
      have columnBound := column.isLt
      change column.val < 749 at columnBound
      change column.val / 375 < 2
      omega⟩
  let localColumn : Fin lvcsColumnCount :=
    ⟨column.val % lvcsColumnCount, Nat.mod_lt _ (by decide)⟩
  rw [show
    combinationHeadValue message openingIndex column =
      wordToGoldilocks
        (message (productionCombinationIndex openingIndex block)
          (lvcsHeadIndex localColumn)) by
      rfl]
  rw [matching_combination_head opening message oracle matching
    (productionCombinationIndex openingIndex block) localColumn]
  have reindexed :
      (∑ stackedRow : Fin lvcsRowCount,
        productionCombinationCoefficient opening
            (productionCombinationIndex openingIndex block) stackedRow *
          stackedHeadCell oracle stackedRow localColumn) =
        ∑ pair : Fin beta × Fin unstackedRowCount,
          productionCombinationCoefficient opening
              (productionCombinationIndex openingIndex block)
              (lvcsBlockRowEquiv pair) *
            stackedHeadCell oracle (lvcsBlockRowEquiv pair) localColumn := by
    exact
      (Fintype.sum_equiv lvcsBlockRowEquiv
        (fun pair =>
          productionCombinationCoefficient opening
              (productionCombinationIndex openingIndex block)
              (lvcsBlockRowEquiv pair) *
            stackedHeadCell oracle (lvcsBlockRowEquiv pair) localColumn)
        (fun stackedRow =>
          productionCombinationCoefficient opening
              (productionCombinationIndex openingIndex block) stackedRow *
            stackedHeadCell oracle stackedRow localColumn)
        (fun _ => rfl)).symm
  rw [reindexed, Fintype.sum_prod_type]
  rw [Finset.sum_eq_single block]
  · apply Finset.sum_congr rfl
    intro row _
    rw [production_combination_coefficient_selected_block]
    · rw [combination_opening_index_production_combination_index,
        lvcs_row_exponent_block_row]
      rw [stacked_head_cell_block_row oracle block row localColumn column]
      · rw [mul_comm]
        rfl
      · rfl
      · rfl
    · rw [lvcs_row_block_index_block_row,
        combination_block_index_production_combination_index]
  · intro other _ otherNe
    apply Finset.sum_eq_zero
    intro row _
    rw [production_combination_coefficient_other_block]
    · simp
    · rw [lvcs_row_block_index_block_row,
        combination_block_index_production_combination_index]
      exact otherNe
  · simp

/-- Valid finite indexes make the fail-closed natural lookup definitionally exact. -/
theorem unstacked_cell_at_valid
    (oracle : CommittedOracle)
    (row : Fin unstackedRowCount)
    (column : Fin unstackedColumnCount) :
    unstackedCellAt oracle row.val column.val =
      unstackedCell oracle row column := by
  simp [unstackedCellAt, row.isLt, column.isLt]

theorem matching_combination_head_value_cell_at
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (column : Fin unstackedColumnCount) :
    combinationHeadValue message openingIndex column =
      ∑ row : Fin unstackedRowCount,
        unstackedCellAt oracle row.val column.val *
          openingEvaluationPoint opening openingIndex ^ row.val := by
  rw [matching_combination_head_value
    opening message oracle matching openingIndex column]
  apply Finset.sum_congr rfl
  intro row _
  rw [unstacked_cell_at_valid]

/-- Each of the first 699 one-column PCS values is the exact witness-polynomial evaluation. -/
theorem matching_witness_opening_evaluation
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (witness : Fin rowCount) :
    combinationHeadValue message openingIndex (witnessColumnIndex witness) =
      (witnessPolynomial oracle witness).eval
        (openingEvaluationPoint opening openingIndex) := by
  rw [matching_combination_head_value
    opening message oracle matching openingIndex (witnessColumnIndex witness)]
  unfold witnessPolynomial
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro row _
  rw [eval_mul, eval_C, eval_X_pow]

def nonlinearMaskColumn
    (repetition : Fin rho)
    (column : Fin 8) : Fin unstackedColumnCount :=
  ⟨nonlinearMaskOffset repetition + column.val, by
    have repetitionBound := repetition.isLt
    have columnBound := column.isLt
    change repetition.val < 5 at repetitionBound
    change column.val < 8 at columnBound
    change 699 + 8 * repetition.val + column.val < 749
    omega⟩

def linearMaskColumn
    (repetition : Fin rho)
    (column : Fin 2) : Fin unstackedColumnCount :=
  ⟨linearMaskOffset repetition + column.val, by
    have repetitionBound := repetition.isLt
    have columnBound := column.isLt
    change repetition.val < 5 at repetitionBound
    change column.val < 2 at columnBound
    change 699 + 8 * 5 + 2 * repetition.val + column.val < 749
    omega⟩

/-- Nonlinear mask value computed from the eight native combination-head columns. -/
def nonlinearMaskEvaluationFromHeads
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (openingIndex : Fin openedEvaluations)
    (repetition : Fin rho) : Goldilocks :=
  ∑ column : Fin 8,
    combinationHeadValue message openingIndex
        (nonlinearMaskColumn repetition column) *
      openingEvaluationPoint opening openingIndex ^
        packedColumnShift 8 36 column

/-- Sparse-linear mask value computed from the two native combination-head columns. -/
def linearMaskEvaluationFromHeads
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (openingIndex : Fin openedEvaluations)
    (repetition : Fin rho) : Goldilocks :=
  ∑ column : Fin 2,
    combinationHeadValue message openingIndex
        (linearMaskColumn repetition column) *
      openingEvaluationPoint opening openingIndex ^
        packedColumnShift 2 1 column

theorem matching_nonlinear_mask_opening_evaluation
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (repetition : Fin rho) :
    nonlinearMaskEvaluationFromHeads opening message openingIndex repetition =
      (NativePackedPolynomial.nonlinearMaskPolynomial oracle repetition).eval
        (openingEvaluationPoint opening openingIndex) := by
  rw [NativePackedPolynomial.nonlinearMaskPolynomial,
    packed_polynomial_eval]
  unfold nonlinearMaskEvaluationFromHeads
  apply Finset.sum_congr rfl
  intro column _
  rw [matching_combination_head_value_cell_at
    opening message oracle matching openingIndex
      (nonlinearMaskColumn repetition column)]
  rfl

theorem matching_linear_mask_opening_evaluation
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (repetition : Fin rho) :
    linearMaskEvaluationFromHeads opening message openingIndex repetition =
      (NativePackedPolynomial.linearMaskPolynomial oracle repetition).eval
        (openingEvaluationPoint opening openingIndex) := by
  rw [NativePackedPolynomial.linearMaskPolynomial,
    packed_polynomial_eval]
  unfold linearMaskEvaluationFromHeads
  apply Finset.sum_congr rfl
  intro column _
  rw [matching_combination_head_value_cell_at
    opening message oracle matching openingIndex
      (linearMaskColumn repetition column)]
  rfl

end

end HegemonCrypto.SmallWood.NativePcsReconstruction

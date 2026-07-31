import HegemonCrypto.SmallWoodNativeLvcsReconstruction
import HegemonCrypto.SmallWoodNativePcsReconstruction

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact native PCS message reconstruction

This module mirrors `pcs_reconstruct_combi_heads` for the active packing profile. The first 699
row scalars are one-column witness polynomials. The five nonlinear masks occupy eight columns
each, and the five linear masks occupy two columns each. Their 40 non-leading values are carried
by `partial_evals`; the leading value is recovered from the row scalar at the selected opening
point. The 749 recovered values are then split into two 375-word combination heads, with one
canonical zero padding cell.
-/

namespace HegemonCrypto.SmallWood.NativePcsMessageReconstruction

open HegemonCrypto.SmallWood.CompactMerkleExtraction
open HegemonCrypto.SmallWood.LvcsOpening
open HegemonCrypto.SmallWood.NativeLvcsReconstruction
open HegemonCrypto.SmallWood.NativePackedPolynomial
open HegemonCrypto.SmallWood.NativePcsReconstruction
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open scoped BigOperators

noncomputable section

abbrev NativeOpenedRowScalars :=
  Matrix openedEvaluations polynomialCount

abbrev NativePartialEvaluations :=
  Matrix openedEvaluations (unstackedColumnCount - polynomialCount)

abbrev NativePcsCombinationTails :=
  Matrix openedCombinationCount decsOpenedEvaluations

abbrev NativeSubsetEvaluations :=
  Matrix decsOpenedEvaluations (lvcsRowCount - openedCombinationCount)

theorem active_native_partial_count :
    unstackedColumnCount - polynomialCount = 40 := by
  decide

theorem active_native_subset_count :
    lvcsRowCount - openedCombinationCount = 128 := by
  decide

def nonlinearPartialIndex
    (repetition : Fin rho)
    (localIndex : Fin 7) :
    Fin (unstackedColumnCount - polynomialCount) :=
  ⟨7 * repetition.val + localIndex.val, by
    have repetitionBound := repetition.isLt
    have localBound := localIndex.isLt
    change repetition.val < 5 at repetitionBound
    change localIndex.val < 7 at localBound
    change 7 * repetition.val + localIndex.val < 40
    omega⟩

def linearPartialIndex
    (repetition : Fin rho) :
    Fin (unstackedColumnCount - polynomialCount) :=
  ⟨35 + repetition.val, by
    have repetitionBound := repetition.isLt
    change repetition.val < 5 at repetitionBound
    change 35 + repetition.val < 40
    omega⟩

def nonlinearScalarIndex
    (repetition : Fin rho) : Fin polynomialCount :=
  ⟨rowCount + repetition.val, by
    have repetitionBound := repetition.isLt
    change repetition.val < 5 at repetitionBound
    change 699 + repetition.val < 709
    omega⟩

def linearScalarIndex
    (repetition : Fin rho) : Fin polynomialCount :=
  ⟨rowCount + rho + repetition.val, by
    have repetitionBound := repetition.isLt
    change repetition.val < 5 at repetitionBound
    change 699 + 5 + repetition.val < 709
    omega⟩

def reconstructedNonlinearLeadingValue
    (opening : PiopOpeningChallenge)
    (rowScalars : NativeOpenedRowScalars)
    (partialEvaluations : NativePartialEvaluations)
    (openingIndex : Fin openedEvaluations)
    (repetition : Fin rho) : Goldilocks :=
  wordToGoldilocks (rowScalars openingIndex (nonlinearScalarIndex repetition)) -
    ∑ localIndex : Fin 7,
      wordToGoldilocks
          (partialEvaluations openingIndex
            (nonlinearPartialIndex repetition localIndex)) *
        wordToGoldilocks (opening.val openingIndex) ^
          packedColumnShift 8 36
            ⟨localIndex.val + 1, by
              have localBound := localIndex.isLt
              omega⟩

def reconstructedLinearLeadingValue
    (opening : PiopOpeningChallenge)
    (rowScalars : NativeOpenedRowScalars)
    (partialEvaluations : NativePartialEvaluations)
    (openingIndex : Fin openedEvaluations)
    (repetition : Fin rho) : Goldilocks :=
  wordToGoldilocks (rowScalars openingIndex (linearScalarIndex repetition)) -
    wordToGoldilocks
        (partialEvaluations openingIndex (linearPartialIndex repetition)) *
      wordToGoldilocks (opening.val openingIndex) ^
        packedColumnShift 2 1 ⟨1, by decide⟩

/-- One of the 749 unstacked head values recovered by the native verifier. -/
def reconstructedUnstackedValue
    (opening : PiopOpeningChallenge)
    (rowScalars : NativeOpenedRowScalars)
    (partialEvaluations : NativePartialEvaluations)
    (openingIndex : Fin openedEvaluations)
    (column : Fin unstackedColumnCount) : Goldilocks := by
  if witnessColumn : column.val < rowCount then
    exact wordToGoldilocks
      (rowScalars openingIndex ⟨column.val, witnessColumn.trans (by decide)⟩)
  else if nonlinearColumn : column.val < rowCount + 8 * rho then
    let relative := column.val - rowCount
    let repetition : Fin rho :=
      ⟨relative / 8, by
        have columnBound := column.isLt
        change column.val < 749 at columnBound
        change column.val < 699 + 8 * 5 at nonlinearColumn
        change (column.val - 699) / 8 < 5
        omega⟩
    let localIndex := relative % 8
    if leading : localIndex = 0 then
      exact reconstructedNonlinearLeadingValue
        opening rowScalars partialEvaluations openingIndex repetition
    else
      let partialLocal : Fin 7 :=
        ⟨localIndex - 1, by
          have localBound : localIndex < 8 := Nat.mod_lt _ (by decide)
          omega⟩
      exact wordToGoldilocks
        (partialEvaluations openingIndex
          (nonlinearPartialIndex repetition partialLocal))
  else
    let relative := column.val - (rowCount + 8 * rho)
    let repetition : Fin rho :=
      ⟨relative / 2, by
        have columnBound := column.isLt
        change column.val < 749 at columnBound
        change (column.val - (699 + 8 * 5)) / 2 < 5
        omega⟩
    let localIndex := relative % 2
    if leading : localIndex = 0 then
      exact reconstructedLinearLeadingValue
        opening rowScalars partialEvaluations openingIndex repetition
    else
      exact wordToGoldilocks
        (partialEvaluations openingIndex (linearPartialIndex repetition))

/-- Exact 10-by-398 PCS message reconstructed from proof fields. -/
def reconstructNativePcsMessage
    (opening : PiopOpeningChallenge)
    (rowScalars : NativeOpenedRowScalars)
    (partialEvaluations : NativePartialEvaluations)
    (tails : NativePcsCombinationTails) :
    PcsCombinationMessage :=
  fun combination column =>
    if head : column.val < lvcsColumnCount then
      let openingIndex := combinationOpeningIndex combination
      let block := combinationBlockIndex combination
      if inRange :
          block.val * lvcsColumnCount + column.val < unstackedColumnCount then
        let unstackedColumn : Fin unstackedColumnCount :=
          ⟨block.val * lvcsColumnCount + column.val, inRange⟩
        fieldWordGoldilocksEquiv.symm
          (reconstructedUnstackedValue
            opening rowScalars partialEvaluations openingIndex unstackedColumn)
      else
        fieldWordGoldilocksEquiv.symm 0
    else
      tails combination
        ⟨column.val - lvcsColumnCount, by
          have columnBound := column.isLt
          change column.val < 375 + 23 at columnBound
          change column.val < 398 at columnBound
          change column.val - 375 < 23
          omega⟩

theorem reconstructed_native_pcs_message_head
    (opening : PiopOpeningChallenge)
    (rowScalars : NativeOpenedRowScalars)
    (partialEvaluations : NativePartialEvaluations)
    (tails : NativePcsCombinationTails)
    (combination : Fin openedCombinationCount)
    (column : Fin lvcsColumnCount)
    (inRange :
      (combinationBlockIndex combination).val * lvcsColumnCount + column.val <
        unstackedColumnCount) :
    wordToGoldilocks
        (reconstructNativePcsMessage opening rowScalars partialEvaluations tails
          combination (Fin.castAdd decsOpenedEvaluations column)) =
      reconstructedUnstackedValue opening rowScalars partialEvaluations
        (combinationOpeningIndex combination)
        ⟨(combinationBlockIndex combination).val * lvcsColumnCount + column.val,
          inRange⟩ := by
  simp only [reconstructNativePcsMessage, Fin.val_castAdd, column.isLt, ↓reduceDIte]
  rw [dif_pos inRange]
  exact fieldWordGoldilocksEquiv.apply_symm_apply _

/-- The only head cell beyond the 749-column unstacked matrix is canonical zero padding. -/
theorem reconstructed_native_pcs_message_padding
    (opening : PiopOpeningChallenge)
    (rowScalars : NativeOpenedRowScalars)
    (partialEvaluations : NativePartialEvaluations)
    (tails : NativePcsCombinationTails)
    (combination : Fin openedCombinationCount)
    (column : Fin lvcsColumnCount)
    (outOfRange :
      ¬(combinationBlockIndex combination).val * lvcsColumnCount + column.val <
        unstackedColumnCount) :
    wordToGoldilocks
        (reconstructNativePcsMessage opening rowScalars partialEvaluations tails
          combination (Fin.castAdd decsOpenedEvaluations column)) =
      0 := by
  simp only [reconstructNativePcsMessage, Fin.val_castAdd, column.isLt, ↓reduceDIte]
  rw [dif_neg outOfRange]
  exact fieldWordGoldilocksEquiv.apply_symm_apply 0

theorem reconstructed_native_pcs_message_tail
    (opening : PiopOpeningChallenge)
    (rowScalars : NativeOpenedRowScalars)
    (partialEvaluations : NativePartialEvaluations)
    (tails : NativePcsCombinationTails)
    (combination : Fin openedCombinationCount)
    (column : Fin decsOpenedEvaluations) :
    reconstructNativePcsMessage opening rowScalars partialEvaluations tails
        combination
        ⟨lvcsColumnCount + column.val, by
          have columnBound := column.isLt
          omega⟩ =
      tails combination column := by
  simp only [reconstructNativePcsMessage]
  have notHead : ¬lvcsColumnCount + column.val < lvcsColumnCount := by omega
  rw [dif_neg notHead]
  congr
  omega

/-- Row-major index of a transmitted non-selected LVCS value. -/
def nativeSubsetIndex
    (row : Fin lvcsRowCount)
    (notSelected : row.val % unstackedRowCount ≥ openedEvaluations) :
    Fin (lvcsRowCount - openedCombinationCount) :=
  ⟨(row.val / unstackedRowCount) *
      (unstackedRowCount - openedEvaluations) +
      (row.val % unstackedRowCount - openedEvaluations), by
    have rowBound := row.isLt
    change row.val < 138 at rowBound
    change 5 ≤ row.val % 69 at notSelected
    have blockBound : row.val / 69 < 2 := by omega
    have localBound : row.val % 69 < 69 := Nat.mod_lt _ (by decide)
    change
      (row.val / 69) * (69 - 5) + (row.val % 69 - 5) <
        138 - 10
    omega⟩

/-- The 128 wire values embedded in the 138-row LVCS space with zero pivot placeholders. -/
def nativeLvcsBaseRowsFromSubset
    (subset : NativeSubsetEvaluations) :
    NativeLvcsBaseRows :=
  fun opening row =>
    if selected : row.val % unstackedRowCount < openedEvaluations then
      0
    else
      wordToGoldilocks
        (subset opening (nativeSubsetIndex row (Nat.le_of_not_gt selected)))

theorem native_lvcs_base_rows_selected_zero
    (subset : NativeSubsetEvaluations)
    (opening : OpeningIndex)
    (block : Fin beta)
    (exponent : Fin openedEvaluations) :
    nativeLvcsBaseRowsFromSubset subset opening
        (selectedLvcsRow block exponent) = 0 := by
  have exponentBound := exponent.isLt
  change exponent.val < 5 at exponentBound
  have selectedModulo :
      (selectedLvcsRow block exponent).val % unstackedRowCount <
        openedEvaluations := by
    have exponentEquation :=
      lvcs_row_exponent_selected_lvcs_row block exponent
    rw [show
      (selectedLvcsRow block exponent).val % unstackedRowCount =
        exponent.val by exact exponentEquation]
    exact exponentBound
  simp [nativeLvcsBaseRowsFromSubset, selectedModulo]

end

end HegemonCrypto.SmallWood.NativePcsMessageReconstruction

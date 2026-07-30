import HegemonCrypto.SmallWoodOpenedRowRefinement

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact native LVCS row reconstruction

`lvcs_recompute_rows` receives 448 transmitted row values and solves for the 35 omitted values.
The omitted coordinates are the first five rows of each of seven stacking blocks.  Their production
coefficient matrix is seven independent five-by-five Vandermonde systems.

This file defines that solve without assuming the resulting LVCS equations.  Injectivity follows
from the existing Vandermonde theorem; equal finite dimensions then give surjectivity.  The
reconstructed row therefore satisfies all 35 equations by construction.
-/

namespace HegemonCrypto.SmallWood.NativeLvcsReconstruction

open Polynomial
open HegemonCrypto.SmallWood.CompactMerkleExtraction
open HegemonCrypto.SmallWood.LvcsOpening
open HegemonCrypto.SmallWood.OpenedRowRefinement
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open scoped BigOperators

noncomputable section

abbrev SelectedLvcsValues :=
  Fin beta -> Fin openedEvaluations -> Goldilocks

/-- The seven independent production Vandermonde systems. -/
def selectedLvcsTransform
    (opening : PiopOpeningChallenge)
    (values : SelectedLvcsValues) : SelectedLvcsValues :=
  fun block openingIndex =>
    ∑ exponent : Fin openedEvaluations,
      productionCombinationCoefficient opening
          (productionCombinationIndex openingIndex block)
          (selectedLvcsRow block exponent) *
        values block exponent

theorem selected_lvcs_transform_injective
    (opening : PiopOpeningChallenge) :
    Function.Injective (selectedLvcsTransform opening) := by
  intro left right sameTransform
  apply selected_lvcs_reconstruction_unique opening left right
  intro openingIndex block
  exact congrFun (congrFun sameTransform block) openingIndex

theorem selected_lvcs_transform_surjective
    (opening : PiopOpeningChallenge) :
    Function.Surjective (selectedLvcsTransform opening) := by
  exact
    ((Fintype.bijective_iff_injective_and_card
      (selectedLvcsTransform opening)).2
        ⟨selected_lvcs_transform_injective opening, rfl⟩).2

/-- Canonical mathematical result of the successful native five-by-five solves. -/
def selectedLvcsPreimage
    (opening : PiopOpeningChallenge)
    (target : SelectedLvcsValues) : SelectedLvcsValues :=
  Classical.choose (selected_lvcs_transform_surjective opening target)

theorem selected_lvcs_transform_preimage
    (opening : PiopOpeningChallenge)
    (target : SelectedLvcsValues) :
    selectedLvcsTransform opening (selectedLvcsPreimage opening target) = target :=
  Classical.choose_spec (selected_lvcs_transform_surjective opening target)

/-- Embed 35 selected values into the complete 483-row space. -/
def liftSelectedLvcsValues
    (values : SelectedLvcsValues)
    (row : Fin lvcsRowCount) : Goldilocks :=
  ∑ block : Fin beta,
    ∑ exponent : Fin openedEvaluations,
      if row = selectedLvcsRow block exponent then
        values block exponent
      else
        0

private theorem selected_lvcs_row_injective :
    Function.Injective
      (fun pair : Fin beta × Fin openedEvaluations =>
        selectedLvcsRow pair.1 pair.2) := by
  intro left right sameRow
  have sameValue := congrArg Fin.val sameRow
  have leftBlockBound := left.1.isLt
  have rightBlockBound := right.1.isLt
  have leftExponentBound := left.2.isLt
  have rightExponentBound := right.2.isLt
  change left.1.val < 7 at leftBlockBound
  change right.1.val < 7 at rightBlockBound
  change left.2.val < 5 at leftExponentBound
  change right.2.val < 5 at rightExponentBound
  change
    left.1.val * 69 + left.2.val =
      right.1.val * 69 + right.2.val at sameValue
  have sameBlock : left.1.val = right.1.val := by omega
  have sameExponent : left.2.val = right.2.val := by omega
  exact Prod.ext (Fin.ext sameBlock) (Fin.ext sameExponent)

private theorem selected_lvcs_row_eq_iff
    (leftBlock rightBlock : Fin beta)
    (leftExponent rightExponent : Fin openedEvaluations) :
    selectedLvcsRow leftBlock leftExponent =
        selectedLvcsRow rightBlock rightExponent ↔
      leftBlock = rightBlock ∧ leftExponent = rightExponent := by
  constructor
  · intro same
    have pairSame :=
      selected_lvcs_row_injective
        (show
          selectedLvcsRow (leftBlock, leftExponent).1 (leftBlock, leftExponent).2 =
            selectedLvcsRow (rightBlock, rightExponent).1
              (rightBlock, rightExponent).2 by
          exact same)
    exact ⟨congrArg Prod.fst pairSame, congrArg Prod.snd pairSame⟩
  · rintro ⟨rfl, rfl⟩
    rfl

theorem lift_selected_lvcs_values_at_selected
    (values : SelectedLvcsValues)
    (block : Fin beta)
    (exponent : Fin openedEvaluations) :
    liftSelectedLvcsValues values (selectedLvcsRow block exponent) =
      values block exponent := by
  classical
  unfold liftSelectedLvcsValues
  rw [Finset.sum_eq_single block]
  · rw [Finset.sum_eq_single exponent]
    · simp
    · intro other _ otherNe
      have rowsNe :
          selectedLvcsRow block exponent ≠
            selectedLvcsRow block other := by
        intro same
        exact otherNe
          ((selected_lvcs_row_eq_iff block block exponent other).mp same).2.symm
      simp [rowsNe]
    · simp
  · intro other _ otherNe
    apply Finset.sum_eq_zero
    intro candidate _
    have rowsNe :
        selectedLvcsRow block exponent ≠
          selectedLvcsRow other candidate := by
      intro same
      exact otherNe
        ((selected_lvcs_row_eq_iff block other exponent candidate).mp same).1.symm
    simp [rowsNe]
  · simp

private theorem weighted_selected_indicator
    (opening : PiopOpeningChallenge)
    (combination : Fin openedCombinationCount)
    (block : Fin beta)
    (exponent : Fin openedEvaluations)
    (value : Goldilocks) :
    (∑ row : Fin lvcsRowCount,
      productionCombinationCoefficient opening combination row *
        (if row = selectedLvcsRow block exponent then value else 0)) =
      productionCombinationCoefficient opening combination
          (selectedLvcsRow block exponent) * value := by
  classical
  rw [Finset.sum_eq_single (selectedLvcsRow block exponent)]
  · simp
  · intro other _ otherNe
    simp [otherNe]
  · simp

theorem weighted_lift_selected_lvcs_values
    (opening : PiopOpeningChallenge)
    (openingIndex : Fin openedEvaluations)
    (selectedBlock : Fin beta)
    (values : SelectedLvcsValues) :
    (∑ row : Fin lvcsRowCount,
      productionCombinationCoefficient opening
          (productionCombinationIndex openingIndex selectedBlock) row *
        liftSelectedLvcsValues values row) =
      selectedLvcsTransform opening values selectedBlock openingIndex := by
  classical
  unfold liftSelectedLvcsValues
  simp_rw [Finset.mul_sum]
  rw [Finset.sum_comm]
  simp_rw [Finset.sum_comm (s := (Finset.univ : Finset (Fin lvcsRowCount)))]
  simp_rw [weighted_selected_indicator]
  unfold selectedLvcsTransform
  rw [Finset.sum_eq_single selectedBlock]
  · intro other _ otherNe
    apply Finset.sum_eq_zero
    intro exponent _
    rw [production_combination_coefficient_other_block]
    · simp
    · rw [lvcs_row_block_index_selected_lvcs_row,
        combination_block_index_production_combination_index]
      exact otherNe
  · simp

/-- Combination value demanded by one transmitted polynomial at one opened DECS coordinate. -/
def nativeLvcsTarget
    (_opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinate : Fin decsEvaluationCount) :
    SelectedLvcsValues :=
  fun block openingIndex =>
    (claimedCombinationPolynomial message
      (productionCombinationIndex openingIndex block)).eval
        (activeEvaluationPoint coordinate)

def nativeLvcsBaseContribution
    (opening : PiopOpeningChallenge)
    (baseRow : Fin lvcsRowCount -> Goldilocks) :
    SelectedLvcsValues :=
  fun block openingIndex =>
    ∑ row : Fin lvcsRowCount,
      productionCombinationCoefficient opening
          (productionCombinationIndex openingIndex block) row *
        baseRow row

def nativeLvcsResidual
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinate : Fin decsEvaluationCount)
    (baseRow : Fin lvcsRowCount -> Goldilocks) :
    SelectedLvcsValues :=
  fun block openingIndex =>
    nativeLvcsTarget opening message coordinate block openingIndex -
      nativeLvcsBaseContribution opening baseRow block openingIndex

/--
Exact mathematical row returned by the native linear solve.  `baseRow` carries the 448 transmitted
values (and arbitrary placeholders in selected slots); the selected correction is uniquely solved.
-/
def reconstructNativeLvcsRow
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinate : Fin decsEvaluationCount)
    (baseRow : Fin lvcsRowCount -> Goldilocks) :
    Fin lvcsRowCount -> Goldilocks :=
  fun row =>
    baseRow row +
      liftSelectedLvcsValues
        (selectedLvcsPreimage opening
          (nativeLvcsResidual opening message coordinate baseRow))
        row

theorem reconstructed_native_lvcs_row_equation
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinate : Fin decsEvaluationCount)
    (baseRow : Fin lvcsRowCount -> Goldilocks)
    (openingIndex : Fin openedEvaluations)
    (block : Fin beta) :
    (∑ row : Fin lvcsRowCount,
      productionCombinationCoefficient opening
          (productionCombinationIndex openingIndex block) row *
        reconstructNativeLvcsRow opening message coordinate baseRow row) =
      (claimedCombinationPolynomial message
        (productionCombinationIndex openingIndex block)).eval
          (activeEvaluationPoint coordinate) := by
  classical
  rw [show
    (fun row =>
      productionCombinationCoefficient opening
          (productionCombinationIndex openingIndex block) row *
        reconstructNativeLvcsRow opening message coordinate baseRow row) =
      (fun row =>
        productionCombinationCoefficient opening
            (productionCombinationIndex openingIndex block) row * baseRow row +
          productionCombinationCoefficient opening
            (productionCombinationIndex openingIndex block) row *
              liftSelectedLvcsValues
                (selectedLvcsPreimage opening
                  (nativeLvcsResidual opening message coordinate baseRow))
                row) by
      funext row
      simp [reconstructNativeLvcsRow, mul_add]]
  rw [Finset.sum_add_distrib,
    weighted_lift_selected_lvcs_values]
  have solved := congrFun
    (congrFun
      (selected_lvcs_transform_preimage opening
        (nativeLvcsResidual opening message coordinate baseRow))
      block)
    openingIndex
  rw [solved]
  simp [nativeLvcsResidual, nativeLvcsTarget, nativeLvcsBaseContribution]

/-- Every production combination index is exactly its opening/block decomposition. -/
theorem production_combination_index_roundtrip
    (combination : Fin openedCombinationCount) :
    productionCombinationIndex
        (combinationOpeningIndex combination)
        (combinationBlockIndex combination) =
      combination := by
  apply Fin.ext
  have combinationBound := combination.isLt
  change combination.val < 35 at combinationBound
  simp [productionCombinationIndex, combinationOpeningIndex,
    combinationBlockIndex, beta]
  omega

/-- The 448 transmitted LVCS values, with arbitrary placeholders in the 35 solved positions. -/
abbrev NativeLvcsBaseRows :=
  OpeningIndex -> Fin lvcsRowCount -> Goldilocks

/-- The 33 proof-supplied masking values appended to every authenticated leaf. -/
abbrev NativeMaskingRows :=
  OpeningIndex -> Fin decsEta -> FieldWord

/--
Exact 516-word row authenticated by `decs_recompute_root`: the 483 reconstructed LVCS values
followed by the 33 proof-supplied masking values.
-/
def reconstructNativeProductionRow
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinate : Fin decsEvaluationCount)
    (baseRow : Fin lvcsRowCount -> Goldilocks)
    (maskingRow : Fin decsEta -> FieldWord) :
    ProductionRow :=
  Fin.addCases
    (fun row =>
      fieldWordGoldilocksEquiv.symm
        (reconstructNativeLvcsRow opening message coordinate baseRow row))
    maskingRow

/-- Exact row array returned by native LVCS reconstruction before compact Merkle verification. -/
def reconstructNativeProductionRows
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinates : ProductionOpeningCoordinates)
    (baseRows : NativeLvcsBaseRows)
    (maskingRows : NativeMaskingRows) :
    ProductionOpeningRows :=
  fun index =>
    reconstructNativeProductionRow opening message
      (coordinates index) (baseRows index) (maskingRows index)

theorem production_row_lvcs_value_reconstructed
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinate : Fin decsEvaluationCount)
    (baseRow : Fin lvcsRowCount -> Goldilocks)
    (maskingRow : Fin decsEta -> FieldWord)
    (column : Fin lvcsRowCount) :
    productionRowLvcsValue
        (reconstructNativeProductionRow
          opening message coordinate baseRow maskingRow)
        column =
      reconstructNativeLvcsRow opening message coordinate baseRow column := by
  have embeddedColumn :
      (⟨column.val, by
        have columnBound := column.isLt
        omega⟩ : Fin (lvcsRowCount + decsEta)) =
        Fin.castAdd decsEta column := by
    apply Fin.ext
    rfl
  rw [productionRowLvcsValue, embeddedColumn]
  simp only [reconstructNativeProductionRow, Fin.addCases_left]
  change
    fieldWordGoldilocksEquiv
        (fieldWordGoldilocksEquiv.symm
          (reconstructNativeLvcsRow opening message coordinate baseRow column)) =
      reconstructNativeLvcsRow opening message coordinate baseRow column
  exact fieldWordGoldilocksEquiv.apply_symm_apply _

/--
The exact rows reconstructed by the native verifier satisfy every LVCS equation by construction;
the acceptance closure therefore does not need to receive those checks as a premise.
-/
theorem reconstructed_native_production_rows_checks
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (coordinates : ProductionOpeningCoordinates)
    (baseRows : NativeLvcsBaseRows)
    (maskingRows : NativeMaskingRows) :
    NativeLvcsOpeningChecks opening message coordinates
      (reconstructNativeProductionRows
        opening message coordinates baseRows maskingRows) := by
  intro index combination
  let openingIndex := combinationOpeningIndex combination
  let block := combinationBlockIndex combination
  have combinationRoundtrip :
      productionCombinationIndex openingIndex block = combination := by
    exact production_combination_index_roundtrip combination
  rw [← combinationRoundtrip]
  symm
  simpa [reconstructNativeProductionRows,
    production_row_lvcs_value_reconstructed] using
    reconstructed_native_lvcs_row_equation
      opening message (coordinates index) (baseRows index) openingIndex block

end

end HegemonCrypto.SmallWood.NativeLvcsReconstruction

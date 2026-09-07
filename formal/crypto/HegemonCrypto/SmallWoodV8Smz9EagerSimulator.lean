import HegemonCrypto.SmallWoodV8Smz9EagerPrivacy
import HegemonCrypto.SmallWoodV8Smz9PiopOpeningRecovery

/-!
# Witness-free eager SMZ9 algebraic output

The constructor below consumes public response coefficients and uniform opening
coordinates. It reconstructs the source PCS columns and DECS opened masks; high
coefficients are projections of the same full responses, never fresh draws.
Witness-dependent inverse coins occur only in the accompanying coupling.
-/

namespace HegemonCrypto.SmallWood.V8Smz9EagerSimulator

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy V8Smz9HonestHybrid
open V8Smz9EagerPrivacy V8Smz9JointAlgebraicLaw
open Polynomial
open scoped BigOperators ENNReal Classical

noncomputable section

set_option maxRecDepth 5000
set_option maxHeartbeats 2000000

abbrev MaskOpeningValues (F : Type*) :=
  (Fin 6 → Fin 5 → F) × (Fin 6 → Fin 5 → F)
abbrev PublicCombinationHeads (F : Type*) := Fin 12 → Fin 368 → F
abbrev OpenedRows (F : Type*) := Fin 20 → Fin 140 → F
abbrev OpenedDecsMasks (F : Type*) := Fin 20 → Fin 5 → F

structure EagerAlgebraicFields (F : Type*) where
  rowScalars : Fin 6 → Fin 696 → F
  partialEvaluations : Fin 6 → Fin 40 → F
  combinationTails : Fin 12 → Fin 20 → F
  subsetEvaluations : Fin 20 → Fin 128 → F
  decsMaskEvaluations : OpenedDecsMasks F
  decsHighs : Fin 5 → Fin 368 → F
  nonlinearHighs : Fin 5 → Fin 483 → F
  linearHighs : Fin 5 → Fin 126 → F

def sourceRowScalars {F : Type*}
    (witness : WitnessOpeningView F) (masks : MaskOpeningValues F) : Fin 6 → Fin 696 → F :=
  fun opening => Fin.append (witness opening)
    (Fin.append (masks.1 opening) (masks.2 opening))

def sourcePartialEvaluations {F : Type*} (partials : SourcePcsView F) : Fin 6 → Fin 40 → F :=
  fun opening => Fin.append
    ((matrixEquiv 5 7 F).symm (fun polynomial column => partials.1 polynomial opening column))
    (fun polynomial => partials.2 polynomial opening)

theorem source_row_scalar_witness_index {F : Type*}
    (witness : WitnessOpeningView F) (masks : MaskOpeningValues F)
    (opening : Fin 6) (row : Fin 686) :
    sourceRowScalars witness masks opening (Fin.castAdd 10 row) = witness opening row := by
  exact Fin.append_left _ _ _

theorem source_row_scalar_nonlinear_index {F : Type*}
    (witness : WitnessOpeningView F) (masks : MaskOpeningValues F)
    (opening : Fin 6) (polynomial : Fin 5) :
    sourceRowScalars witness masks opening
      (Fin.natAdd 686 (Fin.castAdd 5 polynomial)) = masks.1 opening polynomial := by
  exact (Fin.append_right (witness opening) (Fin.append (masks.1 opening) (masks.2 opening))
    (Fin.castAdd 5 polynomial)).trans (Fin.append_left _ _ _)

theorem source_row_scalar_linear_index {F : Type*}
    (witness : WitnessOpeningView F) (masks : MaskOpeningValues F)
    (opening : Fin 6) (polynomial : Fin 5) :
    sourceRowScalars witness masks opening
      (Fin.natAdd 686 (Fin.natAdd 5 polynomial)) = masks.2 opening polynomial := by
  exact (Fin.append_right (witness opening) (Fin.append (masks.1 opening) (masks.2 opening))
    (Fin.natAdd 5 polynomial)).trans (Fin.append_right _ _ _)

theorem source_partial_nonlinear_index {F : Type*}
    (partials : SourcePcsView F) (opening : Fin 6) (polynomial : Fin 5) (column : Fin 7) :
    sourcePartialEvaluations partials opening
      (Fin.castAdd 5 (finProdFinEquiv (polynomial, column))) =
        partials.1 polynomial opening column := by
  simp only [sourcePartialEvaluations, Fin.append_left, matrix_equiv_symm_apply]

theorem source_partial_linear_index {F : Type*}
    (partials : SourcePcsView F) (opening : Fin 6) (polynomial : Fin 5) :
    sourcePartialEvaluations partials opening (Fin.natAdd 35 polynomial) =
      partials.2 polynomial opening := by
  simp only [sourcePartialEvaluations, Fin.append_right]

def reconstructNonlinearColumns {F : Type*} [Field F]
    (point scalar : F) (partials : Fin 7 → F) : Fin 8 → F :=
  Fin.cons (sourceRecoveredNonlinearFirstColumn point scalar partials) partials

theorem reconstruct_nonlinear_columns_roundtrip {F : Type*} [Field F]
    (point : F) (columns : Fin 8 → F) :
    reconstructNonlinearColumns point (sourceNonlinearReconstruction point columns)
        (fun column => columns column.succ) = columns := by
  funext column
  refine Fin.cases ?_ (fun index => ?_) column
  · simp [reconstructNonlinearColumns, sourceRecoveredNonlinearFirstColumn,
      sourceNonlinearReconstruction]
  · rfl

def reconstructLinearColumns {F : Type*} [Field F]
    (point scalar partialValue : F) : Fin 2 → F :=
  ![scalar - point ^ 63 * partialValue, partialValue]

theorem reconstruct_linear_columns_roundtrip {F : Type*} [Field F]
    (point : F) (columns : Fin 2 → F) :
    reconstructLinearColumns point (columns 0 + point ^ 63 * columns 1) (columns 1) =
      columns := by
  funext column
  fin_cases column <;> simp [reconstructLinearColumns]

def reconstructedColumnEvaluations {F : Type*} [Field F]
    (points : Fin 6 → F) (witness : WitnessOpeningView F)
    (masks : MaskOpeningValues F) (partials : SourcePcsView F) : Fin 6 → Fin 736 → F :=
  fun opening => Fin.append (witness opening)
    (Fin.append
      ((matrixEquiv 5 8 F).symm (fun polynomial =>
        reconstructNonlinearColumns (points opening) (masks.1 opening polynomial)
          (partials.1 polynomial opening)))
      ((matrixEquiv 5 2 F).symm (fun polynomial =>
        reconstructLinearColumns (points opening) (masks.2 opening polynomial)
          (partials.2 polynomial opening))))

/-- Exactly the two consecutive 368-column halves used by pcs_reconstruct_combi_heads. -/
def reconstructedCombinationHeads {F : Type*} [Field F]
    (points : Fin 6 → F) (witness : WitnessOpeningView F)
    (masks : MaskOpeningValues F) (partials : SourcePcsView F) : PublicCombinationHeads F :=
  fun combination column =>
    let position := (finProdFinEquiv : Fin 6 × Fin 2 ≃ Fin 12).symm combination
    reconstructedColumnEvaluations points witness masks partials position.1
      (finProdFinEquiv (position.2, column))

theorem reconstructed_combination_head_index {F : Type*} [Field F]
    (points : Fin 6 → F) (witness : WitnessOpeningView F)
    (masks : MaskOpeningValues F) (partials : SourcePcsView F)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    reconstructedCombinationHeads points witness masks partials
        (finProdFinEquiv (opening, block)) column =
      reconstructedColumnEvaluations points witness masks partials opening
        (finProdFinEquiv (block, column)) := by
  simp only [reconstructedCombinationHeads, Equiv.symm_apply_apply]

abbrev SourceColumnLayout (F : Type*) :=
  (Fin 686 → F) × ((Fin 5 → Fin 8 → F) × (Fin 5 → Fin 2 → F))

def sourceColumnLayoutEquiv (F : Type*) : (Fin 736 → F) ≃ SourceColumnLayout F :=
  (splitEquiv 686 50 F).trans
    (Equiv.prodCongr (Equiv.refl _)
      ((splitEquiv 40 10 F).trans (Equiv.prodCongr (matrixEquiv 5 8 F) (matrixEquiv 5 2 F))))

def sourceColumnWitness {F : Type*} (columns : Fin 6 → SourceColumnLayout F) :
    WitnessOpeningView F := fun opening => (columns opening).1

def sourceColumnMasks {F : Type*} [Field F]
    (points : Fin 6 → F) (columns : Fin 6 → SourceColumnLayout F) : MaskOpeningValues F :=
  (fun opening polynomial => sourceNonlinearReconstruction (points opening)
      ((columns opening).2.1 polynomial),
    fun opening polynomial => (columns opening).2.2 polynomial 0 +
      points opening ^ 63 * (columns opening).2.2 polynomial 1)

def sourceColumnPartials {F : Type*} (columns : Fin 6 → SourceColumnLayout F) : SourcePcsView F :=
  (fun polynomial opening column => (columns opening).2.1 polynomial column.succ,
    fun polynomial opening => (columns opening).2.2 polynomial 1)

theorem reconstructed_column_evaluations_roundtrip
    {F : Type*} [Field F]
    (points : Fin 6 → F) (columns : Fin 6 → SourceColumnLayout F) :
    reconstructedColumnEvaluations points (sourceColumnWitness columns)
        (sourceColumnMasks points columns) (sourceColumnPartials columns) =
      (fun opening => (sourceColumnLayoutEquiv F).symm (columns opening)) := by
  funext opening
  change Fin.append (columns opening).1
      (Fin.append
        ((matrixEquiv 5 8 F).symm (fun polynomial =>
          reconstructNonlinearColumns (points opening)
            (sourceNonlinearReconstruction (points opening) ((columns opening).2.1 polynomial))
            (fun column => (columns opening).2.1 polynomial column.succ)))
        ((matrixEquiv 5 2 F).symm (fun polynomial =>
          reconstructLinearColumns (points opening)
            ((columns opening).2.2 polynomial 0 + points opening ^ 63 *
              (columns opening).2.2 polynomial 1) ((columns opening).2.2 polynomial 1)))) =
    Fin.append (columns opening).1
      (Fin.append ((matrixEquiv 5 8 F).symm (columns opening).2.1)
        ((matrixEquiv 5 2 F).symm (columns opening).2.2))
  simp only [reconstruct_nonlinear_columns_roundtrip, reconstruct_linear_columns_roundtrip]

theorem reconstructed_combination_heads_roundtrip
    {F : Type*} [Field F]
    (points : Fin 6 → F) (columns : Fin 6 → Fin 736 → F)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    let grouped := fun index => sourceColumnLayoutEquiv F (columns index)
    reconstructedCombinationHeads points (sourceColumnWitness grouped)
        (sourceColumnMasks points grouped) (sourceColumnPartials grouped)
        (finProdFinEquiv (opening, block)) column =
      columns opening (finProdFinEquiv (block, column)) := by
  dsimp only
  rw [reconstructed_combination_head_index, reconstructed_column_evaluations_roundtrip]
  exact congrFun ((sourceColumnLayoutEquiv F).symm_apply_apply (columns opening)) _

def rowCombination {F : Type*} [Field F]
    (points : Fin 6 → F) (rows : Fin 140 → F) : Fin 12 → F :=
  fun combination => ∑ row : Fin 140,
    smz9LvcsCombinationCoefficient points combination row * rows row

def rowSubset {F : Type*} (rows : Fin 140 → F) : Fin 128 → F :=
  fun subset => rows (smz9LvcsSubsetRow subset)

def rowObservation {F : Type*} [Field F]
    (points : Fin 6 → F) (rows : Fin 140 → F) : (Fin 12 → F) × (Fin 128 → F) :=
  (rowCombination points rows, rowSubset rows)

theorem row_combination_partition {F : Type*} [Field F]
    (points : Fin 6 → F) (rows : Fin 140 → F) (combination : Fin 12) :
    rowCombination points rows combination =
      smz9LvcsSelectedBlockMap points (fun index => rows (smz9LvcsSelectedRow index)) combination +
        ∑ subset : Fin 128, smz9LvcsCombinationCoefficient points combination
          (smz9LvcsSubsetRow subset) * rowSubset rows subset := by
  have reindexed := lvcsRowPartitionEquiv.sum_comp
    (fun row => smz9LvcsCombinationCoefficient points combination row * rows row)
  simp only [lvcsRowPartitionEquiv, lvcsRowPartition, Fintype.sum_sum_type] at reindexed
  exact reindexed.symm

theorem row_observation_injective {F : Type*} [Field F]
    (points : Fin 6 → F)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points)) :
    Function.Injective (rowObservation points) := by
  intro left right equal
  have subsets : rowSubset left = rowSubset right := congrArg Prod.snd equal
  have combinations : rowCombination points left = rowCombination points right := congrArg Prod.fst equal
  have selected : (fun index => left (smz9LvcsSelectedRow index)) =
      (fun index => right (smz9LvcsSelectedRow index)) := by
    apply selectedInjective
    funext combination
    have equation := congrFun combinations combination
    simp only [row_combination_partition, subsets] at equation
    exact add_right_cancel equation
  funext row
  rcases every_lvcs_row_is_selected_or_subset row with ⟨index, rfl⟩ | ⟨index, rfl⟩
  · exact congrFun selected index
  · exact congrFun subsets index

def rowObservationEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points)) :
    (Fin 140 → F) ≃ ((Fin 12 → F) × (Fin 128 → F)) :=
  Equiv.ofBijective (rowObservation points)
    ((Fintype.bijective_iff_injective_and_card _).2
      ⟨row_observation_injective points selectedInjective, by
        simp only [Fintype.card_fun, Fintype.card_prod, Fintype.card_fin]
        rw [← pow_add]⟩)

def consecutiveInterpolation {F : Type*} [Field F]
    (values : Fin 388 → F) (point : F) : F :=
  ∑ node : Fin 388,
    (Lagrange.basis (Finset.univ : Finset (Fin 388))
      (fun index => (index.val : F)) node).eval point * values node

def fullRowEvaluations {F : Type*} [Field F]
    (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (targets : Fin 20 → F) : OpenedRows F :=
  fun opening row => consecutiveInterpolation (lvcsRotatedRow heads tails row) (targets opening)

def combinationEvaluations {F : Type*} [Field F]
    (heads : PublicCombinationHeads F) (tails : LvcsEarlierTails F)
    (targets : Fin 20 → F) : Fin 20 → Fin 12 → F :=
  fun opening combination => consecutiveInterpolation
    (Fin.append (tails combination) (heads combination)) (targets opening)

def reconstructOpenedRows {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (heads : PublicCombinationHeads F) (early : LvcsEarlierTails F)
    (targets : Fin 20 → F) (subset : LvcsLaterSubset F) : OpenedRows F :=
  fun opening => (rowObservationEquiv points selectedInjective).symm
    (combinationEvaluations heads early targets opening, subset opening)

set_option backward.isDefEq.respectTransparency false in
theorem combined_rotated_values_match_matrix_product
    {F : Type*} [Field F]
    (points : Fin 6 → F) (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (combination : Fin 12) (node : Fin 388) :
    Fin.append (lvcsEarlierOutput points tails combination)
        (lvcsPublicCombinationHeads points heads combination) node =
      ∑ row : Fin 140, smz9LvcsCombinationCoefficient points combination row *
        lvcsRotatedRow heads tails row node := by
  refine Fin.addCases (m := 20) (n := 368) ?_ ?_ node
  · intro tail
    calc
      _ = lvcsEarlierOutput points tails combination tail := Fin.append_left _ _ tail
      _ = ∑ row : Fin 140, smz9LvcsCombinationCoefficient points combination row * tails row tail :=
        lvcs_earlier_output_is_full_row_matrix_product points tails combination tail
      _ = _ := by
        apply Finset.sum_congr rfl
        intro row _
        exact congrArg (fun value => smz9LvcsCombinationCoefficient points combination row * value)
          (Fin.append_left (tails row) (heads row) tail).symm
  · intro column
    calc
      _ = lvcsPublicCombinationHeads points heads combination column := Fin.append_right _ _ column
      _ = _ := by
        apply Finset.sum_congr rfl
        intro row _
        exact congrArg (fun value => smz9LvcsCombinationCoefficient points combination row * value)
          (Fin.append_right (tails row) (heads row) column).symm

set_option backward.isDefEq.respectTransparency false in
theorem combination_evaluations_match_full_row_combinations
    {F : Type*} [Field F]
    (points : Fin 6 → F) (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (targets : Fin 20 → F) (opening : Fin 20) :
    combinationEvaluations (lvcsPublicCombinationHeads points heads)
        (lvcsEarlierOutput points tails) targets opening =
      rowCombination points (fullRowEvaluations heads tails targets opening) := by
  funext combination
  unfold combinationEvaluations consecutiveInterpolation
  simp_rw [combined_rotated_values_match_matrix_product, Finset.mul_sum]
  rw [Finset.sum_comm]
  unfold rowCombination fullRowEvaluations consecutiveInterpolation
  apply Finset.sum_congr rfl
  intro row _
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro node _
  ring

theorem subset_evaluations_match_full_row_subset
    {F : Type*} [Field F]
    (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (targets : Fin 20 → F) (opening : Fin 20) :
    lvcsFullSubsetInterpolation heads tails targets opening =
      rowSubset (fullRowEvaluations heads tails targets opening) := rfl

theorem reconstruct_opened_rows_roundtrip
    {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (targets : Fin 20 → F) :
    reconstructOpenedRows points selectedInjective (lvcsPublicCombinationHeads points heads)
        (lvcsEarlierOutput points tails) targets (lvcsFullSubsetInterpolation heads tails targets) =
      fullRowEvaluations heads tails targets := by
  funext opening
  unfold reconstructOpenedRows
  rw [combination_evaluations_match_full_row_combinations,
    subset_evaluations_match_full_row_subset]
  exact (rowObservationEquiv points selectedInjective).symm_apply_apply
    (fullRowEvaluations heads tails targets opening)

def recoverDecsMaskOpenings {F : Type*} [Field F]
    (gamma : DecsGamma F) (response : DecsFullCoefficients F)
    (targets : Fin 20 → F) (rows : OpenedRows F) : OpenedDecsMasks F :=
  fun opening polynomial => (coefficientPolynomial (response polynomial)).eval (targets opening) -
    ∑ row : Fin 140, gamma polynomial row * rows opening row

def decsUnmaskedPolynomial {F : Type*} [Field F]
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (polynomial : Fin 5) : F[X] :=
  ∑ node : Fin 388,
    C (∑ row : Fin 140, gamma polynomial row * lvcsRotatedRow heads tails row node) *
    Lagrange.basis (Finset.univ : Finset (Fin 388)) (fun index => (index.val : F)) node

theorem decs_unmasked_polynomial_degree {F : Type*} [Field F]
    (nodesInjective : Function.Injective (fun index : Fin 388 => (index.val : F)))
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (polynomial : Fin 5) :
    (decsUnmaskedPolynomial gamma heads tails polynomial).natDegree < 388 := by
  have bound : (decsUnmaskedPolynomial gamma heads tails polynomial).natDegree ≤ 387 := by
    unfold decsUnmaskedPolynomial
    apply natDegree_sum_le_of_forall_le
    intro node _
    apply natDegree_mul_le.trans
    rw [natDegree_C, zero_add,
      Lagrange.natDegree_basis nodesInjective.injOn (Finset.mem_univ node)]
    decide
  omega

theorem decs_unmasked_coefficients_reassemble
    {F : Type*} [Field F]
    (nodesInjective : Function.Injective (fun index : Fin 388 => (index.val : F)))
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (polynomial : Fin 5) :
    coefficientPolynomial (exactDecsUnmaskedCoefficients gamma heads tails polynomial) =
      decsUnmaskedPolynomial gamma heads tails polynomial := by
  exact coefficient_polynomial_of_coefficients _
    (decs_unmasked_polynomial_degree nodesInjective gamma heads tails polynomial)

theorem decs_unmasked_polynomial_evaluation
    {F : Type*} [Field F]
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (targets : Fin 20 → F) (opening : Fin 20) (polynomial : Fin 5) :
    (decsUnmaskedPolynomial gamma heads tails polynomial).eval (targets opening) =
      ∑ row : Fin 140, gamma polynomial row * fullRowEvaluations heads tails targets opening row := by
  unfold decsUnmaskedPolynomial
  rw [eval_finsetSum]
  simp only [eval_mul, eval_C, Finset.sum_mul]
  rw [Finset.sum_comm]
  unfold fullRowEvaluations consecutiveInterpolation
  apply Finset.sum_congr rfl
  intro row _
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro node _
  ring

theorem coefficient_polynomial_add {F : Type*} [Semiring F] {count : ℕ}
    (left right : Fin count → F) :
    coefficientPolynomial (left + right) = coefficientPolynomial left + coefficientPolynomial right := by
  simp [coefficientPolynomial, add_mul, Finset.sum_add_distrib]

theorem recover_decs_mask_openings_roundtrip
    {F : Type*} [Field F]
    (nodesInjective : Function.Injective (fun index : Fin 388 => (index.val : F)))
    (gamma : DecsGamma F) (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (mask : DecsFullCoefficients F) (targets : Fin 20 → F) :
    recoverDecsMaskOpenings gamma (exactDecsResponse gamma heads tails mask) targets
        (fullRowEvaluations heads tails targets) =
      (fun opening polynomial => (coefficientPolynomial (mask polynomial)).eval (targets opening)) := by
  funext opening polynomial
  unfold recoverDecsMaskOpenings exactDecsResponse
  change (coefficientPolynomial
      (exactDecsUnmaskedCoefficients gamma heads tails polynomial + mask polynomial)).eval _ - _ = _
  rw [coefficient_polynomial_add, eval_add,
    decs_unmasked_coefficients_reassemble nodesInjective,
    decs_unmasked_polynomial_evaluation]
  ring

def eagerAlgebraicFields {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma F) (response : DecsFullCoefficients F)
    (transcript : PiopCoefficients F) (targets : Fin 20 → F)
    (masks : MaskOpeningValues F) (view : SourceRemainingView F) : EagerAlgebraicFields F where
  rowScalars := sourceRowScalars view.1 masks
  partialEvaluations := sourcePartialEvaluations view.2.1
  combinationTails := view.2.2.1
  subsetEvaluations := view.2.2.2
  decsMaskEvaluations := recoverDecsMaskOpenings gamma response targets
    (reconstructOpenedRows points selectedInjective
      (reconstructedCombinationHeads points view.1 masks view.2.1)
      view.2.2.1 targets view.2.2.2)
  decsHighs := fun polynomial coefficient => response polynomial (Fin.natAdd 20 coefficient)
  nonlinearHighs := fun polynomial coefficient => transcript.1 polynomial (Fin.natAdd 6 coefficient)
  linearHighs := fun polynomial coefficient => transcript.2 polynomial (Fin.natAdd 6 coefficient)

theorem eager_high_fields_are_same_response_projections
    {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma F) (response : DecsFullCoefficients F)
    (transcript : PiopCoefficients F) (targets : Fin 20 → F)
    (masks : MaskOpeningValues F) (view : SourceRemainingView F) :
    (eagerAlgebraicFields points selectedInjective gamma response transcript targets masks view).decsHighs =
        (fun polynomial coefficient => response polynomial (Fin.natAdd 20 coefficient)) ∧
    (eagerAlgebraicFields points selectedInjective gamma response transcript targets masks view).nonlinearHighs =
        (fun polynomial coefficient => transcript.1 polynomial (Fin.natAdd 6 coefficient)) ∧
    (eagerAlgebraicFields points selectedInjective gamma response transcript targets masks view).linearHighs =
        (fun polynomial coefficient => transcript.2 polynomial (Fin.natAdd 6 coefficient)) := ⟨rfl, rfl, rfl⟩

/-- Public statement/program and already derived batching data; no witness or mask coins. -/
structure PublicPiopParameters where
  publicValues : List Nat
  expressions : List ProductionConstraintExpression
  roots : Fin 830 → Nat
  nonlinearGamma : Fin 5 → Fin 830 → Goldilocks
  linearWeights : Fin 5 → Fin 686 → Fin 64 → Goldilocks
  linearTargets : Fin 5 → Goldilocks

def canonicalPacking : Fin 64 → Goldilocks := fun lane => (lane.val : Goldilocks)

def openedWitnessAtNat (opened : Fin 686 → Goldilocks) (row : Nat) : Goldilocks :=
  if bound : row < 686 then opened ⟨row, bound⟩ else 0

/-- Deterministic source PIOP reconstruction, using the generated arithmetic program
and public CSR weights. There is no supplied mask-opening callback. -/
def publicMaskOpenings (parameters : PublicPiopParameters)
    (points : Fin 6 → Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (opened : WitnessOpeningView Goldilocks) : MaskOpeningValues Goldilocks :=
  (fun opening polynomial =>
    V8Smz9PiopOpeningRecovery.recoverNonlinearMaskOpening canonicalPacking
      (coefficientPolynomial (transcript.1 polynomial))
      (∑ check : Fin 830, parameters.nonlinearGamma polynomial check *
        V8Smz9PiopOpeningRecovery.generatedConstraintOpenings parameters.publicValues
          (openedWitnessAtNat (opened opening)) parameters.expressions parameters.roots check)
      (points opening),
    fun opening polynomial =>
      V8Smz9PiopOpeningRecovery.recoverLinearMaskOpening canonicalPacking
        (parameters.linearTargets polynomial) (transcript.2 polynomial)
        (parameters.linearWeights polynomial)
        (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking)
        (opened opening) (points opening))

def witnessPolynomialAtNat (polynomials : Fin 686 → Goldilocks[X]) (row : Nat) : Goldilocks[X] :=
  if bound : row < 686 then polynomials ⟨row, bound⟩ else 0

theorem opened_witness_extension_matches_polynomial_evaluation
    (polynomials : Fin 686 → Goldilocks[X]) (point : Goldilocks) :
    openedWitnessAtNat (fun row => (polynomials row).eval point) =
      (fun row => (witnessPolynomialAtNat polynomials row).eval point) := by
  funext row
  by_cases bound : row < 686 <;> simp [openedWitnessAtNat, witnessPolynomialAtNat, bound]

def sourceNonlinearResponsePolynomial (parameters : PublicPiopParameters)
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (polynomial : Fin 5) : Goldilocks[X] :=
  V8Smz9PiopOpeningRecovery.sourceNonlinearTranscript canonicalPacking
    (V8Smz9PiopOpeningRecovery.nonlinearBatch (parameters.nonlinearGamma polynomial)
      (V8Smz9PiopOpeningRecovery.generatedConstraintPolynomials parameters.publicValues
        (witnessPolynomialAtNat witness) parameters.expressions parameters.roots))
    (coefficientPolynomial (masks.1 polynomial))

def sourceLinearResponsePolynomial (parameters : PublicPiopParameters)
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (polynomial : Fin 5) : Goldilocks[X] :=
  V8Smz9PiopOpeningRecovery.sourceLinearUnmasked (parameters.linearWeights polynomial)
    (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking) witness +
      V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking (masks.2 polynomial)

def sourcePiopResponseCoefficients (parameters : PublicPiopParameters)
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks) :
    PiopCoefficients Goldilocks :=
  (fun polynomial coefficient =>
      (sourceNonlinearResponsePolynomial parameters witness masks polynomial).coeff coefficient.val,
    fun polynomial coefficient =>
      (sourceLinearResponsePolynomial parameters witness masks polynomial).coeff (coefficient.val + 1))

/-- Directly source-instantiated mask openings, with validity and degree obligations
on the arithmetic program rather than any supplied observation or privacy equality. -/
theorem public_mask_openings_match_source_masks
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (packingInjective : Function.Injective canonicalPacking)
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (masks : PiopCoefficients Goldilocks)
    (validNonlinear : ∀ check lane,
      (V8Smz9PiopOpeningRecovery.generatedConstraintPolynomials parameters.publicValues
        (witnessPolynomialAtNat witness) parameters.expressions parameters.roots check).eval
          (canonicalPacking lane) = 0)
    (nonlinearDegree : ∀ polynomial,
      (V8Smz9PiopOpeningRecovery.nonlinearBatch (parameters.nonlinearGamma polynomial)
        (V8Smz9PiopOpeningRecovery.generatedConstraintPolynomials parameters.publicValues
          (witnessPolynomialAtNat witness) parameters.expressions parameters.roots)).natDegree ≤ 552)
    (validLinear : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64, parameters.linearWeights polynomial row lane *
        (witness row).eval (canonicalPacking lane)) = parameters.linearTargets polynomial)
    (outside : ∀ opening lane, points opening ≠ canonicalPacking lane) :
    publicMaskOpenings parameters points (sourcePiopResponseCoefficients parameters witness masks)
        (fun opening row => (witness row).eval (points opening)) =
      (fun opening polynomial => (coefficientPolynomial (masks.1 polynomial)).eval (points opening),
        fun opening polynomial =>
          (V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking (masks.2 polynomial)).eval
            (points opening)) := by
  apply Prod.ext
  · funext opening polynomial
    have transcriptDegree :
        (sourceNonlinearResponsePolynomial parameters witness masks polynomial).natDegree < 489 := by
      have quotientDegree := V8Smz9PiopOpeningRecovery.nonlinear_quotient_degree
        canonicalPacking _ (nonlinearDegree polynomial)
      have maskDegree := coefficient_polynomial_nat_degree_le (masks.1 polynomial)
      have bound := (natDegree_add_le _ _).trans (max_le quotientDegree maskDegree)
      change (V8Smz9PiopOpeningRecovery.sourceNonlinearQuotient canonicalPacking _ +
        coefficientPolynomial (masks.1 polynomial)).natDegree < 489
      omega
    change V8Smz9PiopOpeningRecovery.recoverNonlinearMaskOpening canonicalPacking
      (coefficientPolynomial (fun coefficient : Fin 489 =>
        (sourceNonlinearResponsePolynomial parameters witness masks polynomial).coeff coefficient.val))
      (∑ check : Fin 830, parameters.nonlinearGamma polynomial check *
        V8Smz9PiopOpeningRecovery.generatedConstraintOpenings parameters.publicValues
          (openedWitnessAtNat (fun row => (witness row).eval (points opening)))
          parameters.expressions parameters.roots check) (points opening) = _
    rw [coefficient_polynomial_of_coefficients _ transcriptDegree,
      opened_witness_extension_matches_polynomial_evaluation]
    exact V8Smz9PiopOpeningRecovery.generated_nonlinear_mask_recovered_from_opened_rows
      canonicalPacking packingInjective parameters.publicValues (witnessPolynomialAtNat witness)
      parameters.expressions parameters.roots (parameters.nonlinearGamma polynomial)
      (coefficientPolynomial (masks.1 polynomial)) validNonlinear (points opening) (outside opening)
  · funext opening polynomial
    exact V8Smz9PiopOpeningRecovery.source_linear_coins_recovered_from_opened_rows
      canonicalPacking packingInjective packingCardNonzero (parameters.linearWeights polynomial)
      witness witnessDegree (masks.2 polynomial) (parameters.linearTargets polynomial)
      (validLinear polynomial) (points opening)

def eagerPublicAlgebraicFields
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (targets : Fin 20 → Goldilocks)
    (view : SourceRemainingView Goldilocks) : EagerAlgebraicFields Goldilocks :=
  eagerAlgebraicFields points selectedInjective gamma response transcript targets
    (publicMaskOpenings parameters points transcript view.1) view

def eagerPublicOutcome
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points))
    (view : SourceRemainingView Goldilocks) : Option (EagerAlgebraicFields Goldilocks) :=
  (chooseTargets view.1 view.2.1 view.2.2.1).map fun targets =>
    eagerPublicAlgebraicFields parameters points selectedInjective gamma response transcript targets.val view

def eagerPartialOutcome
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points))
    (view : SourcePartialRemainingView Goldilocks) : Option (EagerAlgebraicFields Goldilocks) :=
  view.2.2.2.bind fun subset =>
    (chooseTargets view.1 view.2.1 view.2.2.1).map fun targets =>
      eagerPublicAlgebraicFields parameters points selectedInjective gamma response transcript targets.val
        (view.1, view.2.1, view.2.2.1, subset)

theorem eager_abort_projection_is_exact
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points)) :
    eagerPartialOutcome parameters points selectedInjective gamma response transcript chooseTargets ∘
        sourceRemainingAbortProjection chooseTargets =
      eagerPublicOutcome parameters points selectedInjective gamma response transcript chooseTargets := by
  funext view
  cases selected : chooseTargets view.1 view.2.1 view.2.2.1 with
  | none => simp [eagerPartialOutcome, sourceRemainingAbortProjection, eagerPublicOutcome, selected]
  | some targets =>
    simp [eagerPartialOutcome, sourceRemainingAbortProjection, eagerPublicOutcome, selected]

/-- A witness-free simulator law derived from the actual dependent coin inverses.
The earlier uniform D,T law is supplied by chronological_joint_mask_transport,
not by an assumed real/simulated equality. The selector remains the parameters hash
stage whose byte-level implementation is integrated separately. -/
theorem chronological_eager_algebraic_output_law
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (witnessValues : WitnessPackingValues Goldilocks)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (pcsBase : WitnessInterpolationCoins Goldilocks → SourcePcsView Goldilocks)
    (heads : WitnessInterpolationCoins Goldilocks → SourcePcsCoins Goldilocks →
      LvcsCommittedHeads Goldilocks)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points)) :
    pmfMap (uniformFintypePMF (SourceRemainingCoins Goldilocks))
        (eagerPartialOutcome parameters points selectedInjective gamma response transcript chooseTargets ∘
          sourceRemainingPartialChronologicalView witnessValues points pcsBase heads chooseTargets) =
      pmfMap (uniformFintypePMF (SourceRemainingView Goldilocks))
        (eagerPublicOutcome parameters points selectedInjective gamma response transcript chooseTargets) := by
  have baseLaw := source_remaining_partial_chronological_joint_law witnessValues points
    witnessAdmissible pointsNonzero pcsBase heads fallback chooseTargets
  have pushed := congrArg (fun law => pmfMap law
    (eagerPartialOutcome parameters points selectedInjective gamma response transcript chooseTargets)) baseLaw
  rw [pmfMap_comp, pmfMap_comp, eager_abort_projection_is_exact] at pushed
  exact pushed

/-- The inverse Q = T - F is evaluated at the fixed public batching data.
It depends on W, but never on later PCS or LVCS random coins. -/
def sourceRecoveredPiopMasks (parameters : PublicPiopParameters)
    (witness : Fin 686 → Goldilocks[X]) (transcript : PiopCoefficients Goldilocks) :
    PiopCoefficients Goldilocks :=
  transcript - sourcePiopResponseCoefficients parameters witness 0

theorem coefficient_polynomial_coefficient {F : Type*} [Field F] {count : Nat}
    (coefficients : Fin count → F) (selected : Fin count) :
    (coefficientPolynomial coefficients).coeff selected.val = coefficients selected := by
  unfold coefficientPolynomial
  change lcoeff F selected.val (∑ coefficient : Fin count,
    C (coefficients coefficient) * X ^ coefficient.val) = _
  rw [map_sum]
  simp only [lcoeff_apply]
  rw [Finset.sum_eq_single selected]
  · simp
  · intro other _ different
    have differentValues : selected.val ≠ other.val := by
      intro equal
      exact different (Fin.ext equal.symm)
    simp [differentValues]
  · simp

theorem source_linear_mask_nonconstant_coefficient {F : Type*} [Field F]
    (packing : Fin 64 → F) (coefficients : Fin 132 → F) (selected : Fin 132) :
    (V8Smz9PiopOpeningRecovery.sourceLinearMask packing coefficients).coeff
        (selected.val + 1) = coefficients selected := by
  unfold V8Smz9PiopOpeningRecovery.sourceLinearMask
  change lcoeff F (selected.val + 1) (∑ coefficient : Fin 132,
    C (coefficients coefficient) * (X ^ (coefficient.val + 1) -
      C ((∑ lane : Fin 64, packing lane ^ (coefficient.val + 1)) / 64))) = coefficients selected
  rw [map_sum]
  simp only [lcoeff_apply]
  rw [Finset.sum_eq_single selected]
  · simp
  · intro other _ different
    have differentValues : selected.val ≠ other.val := by
      intro equal
      exact different (Fin.ext equal.symm)
    simp [differentValues]
  · simp

theorem source_piop_response_is_actual_affine_mask_map
    (parameters : PublicPiopParameters) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) :
    sourcePiopResponseCoefficients parameters witness masks =
      sourcePiopResponseCoefficients parameters witness 0 + masks := by
  apply Prod.ext
  · funext polynomial coefficient
    simp only [sourcePiopResponseCoefficients, sourceNonlinearResponsePolynomial,
      V8Smz9PiopOpeningRecovery.sourceNonlinearTranscript, coeff_add,
      coefficient_polynomial_coefficient, Prod.fst_add, Prod.fst_zero, Pi.add_apply, Pi.zero_apply]
    simp
  · funext polynomial coefficient
    simp only [sourcePiopResponseCoefficients, sourceLinearResponsePolynomial, coeff_add,
      source_linear_mask_nonconstant_coefficient, Prod.snd_add, Prod.snd_zero,
      Pi.add_apply, Pi.zero_apply]
    simp

theorem source_recovered_piop_masks_reproduce_same_full_transcript
    (parameters : PublicPiopParameters) (witness : Fin 686 → Goldilocks[X])
    (transcript : PiopCoefficients Goldilocks) :
    sourcePiopResponseCoefficients parameters witness
        (sourceRecoveredPiopMasks parameters witness transcript) = transcript := by
  rw [source_piop_response_is_actual_affine_mask_map, sourceRecoveredPiopMasks]
  abel

def sourceRecoveredMasksAtCoins (parameters : PublicPiopParameters)
    (values : WitnessPackingValues Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (coins : WitnessInterpolationCoins Goldilocks) : PiopCoefficients Goldilocks :=
  sourceRecoveredPiopMasks parameters (sourceWitnessPolynomials values coins) transcript

def sourceLinearMaskFullCoefficients (coins : Fin 132 → Goldilocks) : Fin 133 → Goldilocks :=
  fun coefficient =>
    (V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking coins).coeff coefficient.val

theorem source_linear_mask_models_agree (coins : Fin 132 → Goldilocks) :
    V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking coins =
      sourceLinearMaskPolynomial coins := by
  unfold V8Smz9PiopOpeningRecovery.sourceLinearMask sourceLinearMaskPolynomial
  apply Finset.sum_congr rfl
  intro coefficient _
  have meanEquality :
      (∑ lane : Fin 64, canonicalPacking lane ^ (coefficient.val + 1)) / 64 =
        packingPowerMean (F := Goldilocks) (coefficient.val + 1) := by
    unfold packingPowerMean
    change _ = (64 : Goldilocks)⁻¹ * ∑ lane : Fin 64, canonicalPacking lane ^ (coefficient.val + 1)
    rw [div_eq_mul_inv, mul_comm]
  rw [meanEquality]

def sourcePcsBaseForTranscript (parameters : PublicPiopParameters)
    (values : WitnessPackingValues Goldilocks) (points : Fin 6 → Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (coins : WitnessInterpolationCoins Goldilocks) :
    SourcePcsView Goldilocks :=
  let masks := sourceRecoveredMasksAtCoins parameters values transcript coins
  (fun polynomial opening column =>
      (sourceNonlinearBaseColumns (masks.1 polynomial) column.succ).eval (points opening),
    fun polynomial opening =>
      (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)) 1).eval
        (points opening))

def sourcePcsColumnPolynomialsForTranscript (parameters : PublicPiopParameters)
    (values : WitnessPackingValues Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (witnessCoins : WitnessInterpolationCoins Goldilocks) (pcsCoins : SourcePcsCoins Goldilocks) :
    Fin 736 → Goldilocks[X] :=
  let masks := sourceRecoveredMasksAtCoins parameters values transcript witnessCoins
  Fin.append (sourceWitnessPolynomials values witnessCoins)
    (Fin.append
      ((matrixEquiv 5 8 Goldilocks[X]).symm (fun polynomial =>
        sourceNonlinearPcsColumnPolynomials (sourceNonlinearBaseColumns (masks.1 polynomial))
          (pcsCoins.1 polynomial)))
      ((matrixEquiv 5 2 Goldilocks[X]).symm (fun polynomial =>
        sourceLinearColumnValues X
          (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)))
          (coefficientPolynomial (pcsCoins.2 polynomial)))))

def sourceCommittedHeadsForTranscript (parameters : PublicPiopParameters)
    (values : WitnessPackingValues Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (witnessCoins : WitnessInterpolationCoins Goldilocks) (pcsCoins : SourcePcsCoins Goldilocks) :
    LvcsCommittedHeads Goldilocks :=
  sourceStackedHeads (fun column coefficient =>
    (sourcePcsColumnPolynomialsForTranscript parameters values transcript witnessCoins pcsCoins column).coeff
      coefficient.val)

/-- The source-instantiated algebraic simulator theorem has no witness or old mask
among its right-hand-side inputs. Its left side uses actual source-sized Q recovery,
column chunks, cross-column randomization and physical 70-by-736 head reshaping. -/
theorem source_instantiated_eager_algebraic_output_law
    (parameters : PublicPiopParameters) (points : Fin 6 → Goldilocks)
    (witnessValues : WitnessPackingValues Goldilocks)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points)) :
    pmfMap (uniformFintypePMF (SourceRemainingCoins Goldilocks))
        (eagerPartialOutcome parameters points selectedInjective gamma response transcript chooseTargets ∘
          sourceRemainingPartialChronologicalView witnessValues points
            (sourcePcsBaseForTranscript parameters witnessValues points transcript)
            (sourceCommittedHeadsForTranscript parameters witnessValues transcript) chooseTargets) =
      pmfMap (uniformFintypePMF (SourceRemainingView Goldilocks))
        (eagerPublicOutcome parameters points selectedInjective gamma response transcript chooseTargets) :=
  chronological_eager_algebraic_output_law parameters points witnessValues witnessAdmissible
    pointsNonzero selectedInjective gamma response transcript
    (sourcePcsBaseForTranscript parameters witnessValues points transcript)
    (sourceCommittedHeadsForTranscript parameters witnessValues transcript) fallback chooseTargets

end

end HegemonCrypto.SmallWood.V8Smz9EagerSimulator

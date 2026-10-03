import HegemonCrypto.SmallWoodV8Smz9CurrentProgramPiop
import HegemonCrypto.SmallWoodV8Smz9EagerOracleGame

/-! # Actual current-program PCS and opened-leaf binding

The source column polynomials, their published auxiliary openings, and their
physical coefficient reshape are constructed below. The public reconstruction
is compared to those source polynomials, not to an assumed row-equality premise.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding

open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy V8Smz9HonestHybrid
open V8Smz9EagerPrivacy V8Smz9JointAlgebraicLaw V8Smz9EagerSimulator
open V8Smz9CurrentProgramPiop V8Smz9EagerOracleGame
open Polynomial
open scoped BigOperators ENNReal Classical

noncomputable section
set_option maxRecDepth 5000
set_option maxHeartbeats 300000
set_option backward.isDefEq.respectTransparency false

def physicalColumnPolynomials (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks) :
    Fin 736 → Goldilocks[X] :=
  Fin.append witness
    (Fin.append
      ((matrixEquiv 5 8 Goldilocks[X]).symm (fun polynomial =>
        sourceNonlinearPcsColumnPolynomials (sourceNonlinearBaseColumns (masks.1 polynomial))
          (pcs.1 polynomial)))
      ((matrixEquiv 5 2 Goldilocks[X]).symm (fun polynomial =>
        sourceLinearColumnValues X
          (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)))
          (coefficientPolynomial (pcs.2 polynomial)))))

theorem physical_columns_are_current_source_columns
    (parameters : CurrentPublicParameters) (values : WitnessPackingValues Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (witnessCoins : WitnessInterpolationCoins Goldilocks)
    (pcs : SourcePcsCoins Goldilocks) :
    physicalColumnPolynomials (sourceWitnessPolynomials values witnessCoins)
        (currentRecoveredMasksAtCoins parameters values transcript witnessCoins) pcs =
      currentPcsColumnPolynomialsForTranscript parameters values transcript witnessCoins pcs := rfl

def physicalColumnOpenings (points : Fin 6 → Goldilocks)
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (pcs : SourcePcsCoins Goldilocks) : Fin 6 → SourceColumnLayout Goldilocks :=
  fun opening =>
    ((fun row => (witness row).eval (points opening)),
      (fun polynomial column =>
        (sourceNonlinearPcsColumnPolynomials (sourceNonlinearBaseColumns (masks.1 polynomial))
          (pcs.1 polynomial) column).eval (points opening)),
      (fun polynomial column =>
        (sourceLinearColumnValues X
          (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)))
          (coefficientPolynomial (pcs.2 polynomial)) column).eval (points opening)))

def sourceMaskEvaluations (points : Fin 6 → Goldilocks)
    (masks : PiopCoefficients Goldilocks) : MaskOpeningValues Goldilocks :=
  (fun opening polynomial => (coefficientPolynomial (masks.1 polynomial)).eval (points opening),
    fun opening polynomial =>
      (V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking (masks.2 polynomial)).eval
        (points opening))

def physicalPartialBase (points : Fin 6 → Goldilocks)
    (masks : PiopCoefficients Goldilocks) : SourcePcsView Goldilocks :=
  (fun polynomial opening column =>
      (sourceNonlinearBaseColumns (masks.1 polynomial) column.succ).eval (points opening),
    fun polynomial opening =>
      (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)) 1).eval
        (points opening))

theorem source_pcs_coin_evaluation_is_polynomial
    (points : Fin 6 → Goldilocks) (coins : Fin 6 → Goldilocks) (opening : Fin 6) :
    sourcePcsCoinEvaluation points coins opening =
      (coefficientPolynomial coins).eval (points opening) :=
  (coefficient_polynomial_evaluation coins (points opening)).symm

theorem nonlinear_reconstruction_commutes_evaluation
    (polynomials : Fin 8 → Goldilocks[X]) (point : Goldilocks) :
    sourceNonlinearReconstruction point (fun column => (polynomials column).eval point) =
      (sourceNonlinearReconstruction X polynomials).eval point := by
  simp only [sourceNonlinearReconstruction, eval_add, eval_mul, eval_pow, eval_X]

theorem linear_mask_coefficients_reassemble (coins : Fin 132 → Goldilocks) :
    coefficientPolynomial (sourceLinearMaskFullCoefficients coins) =
      V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking coins := by
  apply coefficient_polynomial_of_coefficients
  have bound := V8Smz9PiopOpeningRecovery.source_linear_mask_degree canonicalPacking coins
  omega

theorem physical_column_masks_are_source_mask_evaluations
    (points : Fin 6 → Goldilocks) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks) :
    sourceColumnMasks points (physicalColumnOpenings points witness masks pcs) =
      sourceMaskEvaluations points masks := by
  apply Prod.ext
  · funext opening polynomial
    change sourceNonlinearReconstruction (points opening)
      (fun column => (sourceNonlinearPcsColumnPolynomials
        (sourceNonlinearBaseColumns (masks.1 polynomial)) (pcs.1 polynomial) column).eval
          (points opening)) = _
    simp_rw [source_nonlinear_column_polynomial_evaluation]
    rw [source_nonlinear_reconstruction_cancels_pcs_randomness,
      nonlinear_reconstruction_commutes_evaluation,
      source_nonlinear_chunks_reconstruct_full_polynomial]
    rfl
  · funext opening polynomial
    change (sourceLinearColumnValues X
      (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)))
      (coefficientPolynomial (pcs.2 polynomial)) 0).eval (points opening) +
      points opening ^ 63 * (sourceLinearColumnValues X
      (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)))
      (coefficientPolynomial (pcs.2 polynomial)) 1).eval (points opening) = _
    have chunks := congrArg (fun polynomial : Goldilocks[X] => polynomial.eval (points opening))
      (source_linear_chunks_reconstruct_full_polynomial
        (sourceLinearMaskFullCoefficients (masks.2 polynomial)))
    rw [linear_mask_coefficients_reassemble] at chunks
    simp only [eval_add, eval_mul, eval_pow, eval_X] at chunks
    simp only [sourceLinearColumnValues, Matrix.cons_val_zero, Matrix.cons_val_one,
      eval_add, eval_sub, eval_mul, eval_pow, eval_X]
    change _ = (V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking
      (masks.2 polynomial)).eval (points opening)
    linear_combination chunks

theorem physical_column_partials_are_source_pcs_view
    (points : Fin 6 → Goldilocks) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks) :
    sourceColumnPartials (physicalColumnOpenings points witness masks pcs) =
      sourcePcsFullView points (physicalPartialBase points masks) pcs := by
  apply Prod.ext
  · funext polynomial opening column
    change (sourceNonlinearPcsColumnPolynomials
      (sourceNonlinearBaseColumns (masks.1 polynomial)) (pcs.1 polynomial) column.succ).eval
        (points opening) = _
    rw [source_nonlinear_column_polynomial_evaluation]
    have equality := congrFun (source_nonlinear_partials_match_point_map (points opening)
      (fun index => (sourceNonlinearBaseColumns (masks.1 polynomial) index).eval (points opening))
      (fun index => sourcePcsCoinEvaluation points (pcs.1 polynomial index) opening)) column
    exact equality
  · funext polynomial opening
    change (sourceLinearColumnValues X
      (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)))
      (coefficientPolynomial (pcs.2 polynomial)) 1).eval (points opening) = _
    simp only [sourceLinearColumnValues, Matrix.cons_val_one, Matrix.cons_val_zero,
      eval_sub, eval_mul, eval_X,
      sourcePcsFullView, physicalPartialBase, Prod.snd_add, Pi.add_apply, sourceLinearPcsMap,
      source_pcs_coin_evaluation_is_polynomial]
    ring

theorem physical_column_openings_evaluate_source_polynomials
    (points : Fin 6 → Goldilocks) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks) :
    (fun opening => (sourceColumnLayoutEquiv Goldilocks).symm
      (physicalColumnOpenings points witness masks pcs opening)) =
      (fun opening column => (physicalColumnPolynomials witness masks pcs column).eval
        (points opening)) := by
  funext opening column
  refine Fin.addCases (n := 50) (m := 686) (fun row => ?_) (fun remaining => ?_) column
  · simp [physicalColumnPolynomials, physicalColumnOpenings, sourceColumnLayoutEquiv,
      splitEquiv, Fin.appendEquiv]
  · refine Fin.addCases (n := 10) (m := 40) (fun nonlinear => ?_) (fun linear => ?_) remaining
    · simp [physicalColumnPolynomials, physicalColumnOpenings, sourceColumnLayoutEquiv,
        splitEquiv, matrixEquiv, Fin.appendEquiv, Function.uncurry]
    · simp [physicalColumnPolynomials, physicalColumnOpenings, sourceColumnLayoutEquiv,
        splitEquiv, matrixEquiv, Fin.appendEquiv, Function.uncurry]

def physicalHeads (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks) :
    LvcsCommittedHeads Goldilocks :=
  sourceStackedHeads (fun column coefficient =>
    (physicalColumnPolynomials witness masks pcs column).coeff coefficient.val)

theorem physical_heads_are_current_source_heads
    (parameters : CurrentPublicParameters) (values : WitnessPackingValues Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (witnessCoins : WitnessInterpolationCoins Goldilocks)
    (pcs : SourcePcsCoins Goldilocks) :
    physicalHeads (sourceWitnessPolynomials values witnessCoins)
        (currentRecoveredMasksAtCoins parameters values transcript witnessCoins) pcs =
      currentCommittedHeadsForTranscript parameters values transcript witnessCoins pcs := rfl

theorem polynomial_add_degree_69 (left right : Goldilocks[X])
    (leftBound : left.natDegree ≤ 69) (rightBound : right.natDegree ≤ 69) :
    (left + right).natDegree ≤ 69 :=
  (natDegree_add_le _ _).trans (max_le leftBound rightBound)

theorem polynomial_sub_degree_69 (left right : Goldilocks[X])
    (leftBound : left.natDegree ≤ 69) (rightBound : right.natDegree ≤ 69) :
    (left - right).natDegree ≤ 69 :=
  (natDegree_sub_le _ _).trans (max_le leftBound rightBound)

theorem shifted_coefficient_polynomial_degree {count : Nat}
    (coefficients : Fin count → Goldilocks) (shift : Nat) :
    (X ^ shift * coefficientPolynomial coefficients).natDegree ≤ shift + (count - 1) := by
  exact natDegree_mul_le.trans (by
    rw [natDegree_X_pow]
    exact Nat.add_le_add_left (coefficient_polynomial_nat_degree_le coefficients) shift)

theorem nonlinear_base_column_degree (masks : Fin 489 → Goldilocks) (column : Fin 8) :
    (sourceNonlinearBaseColumns masks column).natDegree ≤ 69 := by
  have low : ∀ index : Fin 7, (sourceNonlinearLowChunk masks index).natDegree ≤ 69 := by
    intro index
    exact (coefficient_polynomial_nat_degree_le (fun coefficient : Fin 64 =>
      masks (Fin.castAdd 41 (finProdFinEquiv (index, coefficient))))).trans (by decide : 63 ≤ 69)
  have last : (sourceNonlinearLastChunk masks).natDegree ≤ 69 :=
    shifted_coefficient_polynomial_degree (fun index : Fin 41 => masks (Fin.natAdd 448 index)) 29
  fin_cases column
  · exact low 0
  · exact low 1
  · exact low 2
  · exact low 3
  · exact low 4
  · exact low 5
  · exact low 6
  · exact last

theorem nonlinear_physical_column_degree
    (masks : Fin 489 → Goldilocks) (pcs : Fin 7 → Fin 6 → Goldilocks) (column : Fin 8) :
    (sourceNonlinearPcsColumnPolynomials (sourceNonlinearBaseColumns masks) pcs column).natDegree ≤ 69 := by
  have plain : ∀ index, (coefficientPolynomial (pcs index)).natDegree ≤ 69 := by
    intro index
    exact (coefficient_polynomial_nat_degree_le (pcs index)).trans (by decide : 5 ≤ 69)
  have shifted : ∀ index, (X ^ 64 * coefficientPolynomial (pcs index)).natDegree ≤ 69 := by
    intro index
    exact shifted_coefficient_polynomial_degree (pcs index) 64
  have last : (X ^ 29 * coefficientPolynomial (pcs 6)).natDegree ≤ 69 :=
    (shifted_coefficient_polynomial_degree (pcs 6) 29).trans (by decide : 34 ≤ 69)
  fin_cases column <;>
    dsimp only [sourceNonlinearPcsColumnPolynomials, sourceNonlinearColumnValues,
      Matrix.cons_val_zero, Matrix.cons_val_succ, Matrix.head_cons]
  · exact polynomial_add_degree_69 _ _ (nonlinear_base_column_degree masks 0) (shifted 0)
  · exact polynomial_sub_degree_69 _ _
      (polynomial_add_degree_69 _ _ (nonlinear_base_column_degree masks 1) (shifted 1)) (plain 0)
  · exact polynomial_sub_degree_69 _ _
      (polynomial_add_degree_69 _ _ (nonlinear_base_column_degree masks 2) (shifted 2)) (plain 1)
  · exact polynomial_sub_degree_69 _ _
      (polynomial_add_degree_69 _ _ (nonlinear_base_column_degree masks 3) (shifted 3)) (plain 2)
  · exact polynomial_sub_degree_69 _ _
      (polynomial_add_degree_69 _ _ (nonlinear_base_column_degree masks 4) (shifted 4)) (plain 3)
  · exact polynomial_sub_degree_69 _ _
      (polynomial_add_degree_69 _ _ (nonlinear_base_column_degree masks 5) (shifted 5)) (plain 4)
  · exact polynomial_sub_degree_69 _ _
      (polynomial_add_degree_69 _ _ (nonlinear_base_column_degree masks 6) (shifted 6)) (plain 5)
  · exact polynomial_sub_degree_69 _ _ (nonlinear_base_column_degree masks 7) last

theorem linear_physical_column_degree
    (masks : Fin 133 → Goldilocks) (pcs : Fin 6 → Goldilocks) (column : Fin 2) :
    (sourceLinearColumnValues X (sourceLinearBaseColumns masks)
      (coefficientPolynomial pcs) column).natDegree ≤ 69 := by
  have first : (sourceLinearBaseColumns masks 0).natDegree ≤ 69 :=
    (coefficient_polynomial_nat_degree_le
      (fun index : Fin 64 => masks (Fin.castAdd 69 index))).trans (by decide : 63 ≤ 69)
  have last : (sourceLinearBaseColumns masks 1).natDegree ≤ 69 := by
    change (X * coefficientPolynomial _).natDegree ≤ 69
    simpa only [pow_one] using shifted_coefficient_polynomial_degree
      (fun index : Fin 69 => masks (Fin.natAdd 64 index)) 1
  have shifted : (X ^ 64 * coefficientPolynomial pcs).natDegree ≤ 69 :=
    shifted_coefficient_polynomial_degree pcs 64
  have small : (X * coefficientPolynomial pcs).natDegree ≤ 69 := by
    have bound := shifted_coefficient_polynomial_degree pcs 1
    simp only [pow_one] at bound
    exact bound.trans (by decide : 6 ≤ 69)
  fin_cases column <;> dsimp only [sourceLinearColumnValues, Matrix.cons_val_zero,
    Matrix.cons_val_one]
  · exact polynomial_add_degree_69 _ _ first shifted
  · exact polynomial_sub_degree_69 _ _ last small

theorem physical_column_degree
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (pcs : SourcePcsCoins Goldilocks)
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69) :
    ∀ column, (physicalColumnPolynomials witness masks pcs column).natDegree < 70 := by
  intro column
  refine Fin.addCases (n := 50) (m := 686) (fun row => ?_) (fun remaining => ?_) column
  · simpa only [physicalColumnPolynomials, Fin.append_left] using
      Nat.lt_succ_of_le (witnessDegree row)
  · refine Fin.addCases (n := 10) (m := 40) (fun nonlinear => ?_) (fun linear => ?_) remaining
    · let position := (finProdFinEquiv : Fin 5 × Fin 8 ≃ Fin 40).symm nonlinear
      simpa [physicalColumnPolynomials, matrixEquiv, position, Function.uncurry, finProdFinEquiv] using
        Nat.lt_succ_of_le (nonlinear_physical_column_degree
          (masks.1 position.1) (pcs.1 position.1) position.2)
    · let position := (finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm linear
      simpa [physicalColumnPolynomials, matrixEquiv, position, Function.uncurry, finProdFinEquiv] using
        Nat.lt_succ_of_le (linear_physical_column_degree
          (sourceLinearMaskFullCoefficients (masks.2 position.1)) (pcs.2 position.1) position.2)

theorem physical_combination_heads_are_publicly_reconstructed
    (points : Fin 6 → Goldilocks) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks)
    (degreeBounds : ∀ column, (physicalColumnPolynomials witness masks pcs column).natDegree < 70) :
    reconstructedCombinationHeads points
        (fun opening row => (witness row).eval (points opening))
        (sourceMaskEvaluations points masks)
        (sourcePcsFullView points (physicalPartialBase points masks) pcs) =
      lvcsPublicCombinationHeads points (physicalHeads witness masks pcs) := by
  change reconstructedCombinationHeads points
    (sourceColumnWitness (physicalColumnOpenings points witness masks pcs)) _ _ = _
  rw [← physical_column_masks_are_source_mask_evaluations points witness masks pcs,
    ← physical_column_partials_are_source_pcs_view points witness masks pcs]
  funext combination column
  obtain ⟨⟨opening, block⟩, rfl⟩ :=
    (finProdFinEquiv : Fin 6 × Fin 2 ≃ Fin 12).surjective combination
  rw [reconstructed_combination_head_index, reconstructed_column_evaluations_roundtrip]
  have evaluations := congrFun (congrFun
    (physical_column_openings_evaluate_source_polynomials points witness masks pcs) opening)
    (finProdFinEquiv (block, column))
  exact evaluations.trans (source_public_combination_heads_equal_source_polynomials points
    (physicalColumnPolynomials witness masks pcs) degreeBounds opening block column).symm

def physicalView (points : Fin 6 → Goldilocks)
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (pcs : SourcePcsCoins Goldilocks) (tails : LvcsRandomTailCoins Goldilocks)
    (targets : Fin 20 → Goldilocks) : SourceRemainingView Goldilocks :=
  ((fun opening row => (witness row).eval (points opening)),
    sourcePcsFullView points (physicalPartialBase points masks) pcs,
    lvcsEarlierOutput points tails,
    lvcsFullSubsetInterpolation (physicalHeads witness masks pcs) tails targets)

theorem physical_opened_rows_are_publicly_reconstructed
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (pcs : SourcePcsCoins Goldilocks) (tails : LvcsRandomTailCoins Goldilocks)
    (targets : Fin 20 → Goldilocks)
    (degreeBounds : ∀ column, (physicalColumnPolynomials witness masks pcs column).natDegree < 70) :
    reconstructOpenedRows points selected
        (reconstructedCombinationHeads points
          (fun opening row => (witness row).eval (points opening))
          (sourceMaskEvaluations points masks)
          (sourcePcsFullView points (physicalPartialBase points masks) pcs))
        (lvcsEarlierOutput points tails) targets
        (lvcsFullSubsetInterpolation (physicalHeads witness masks pcs) tails targets) =
      fullRowEvaluations (physicalHeads witness masks pcs) tails targets := by
  rw [physical_combination_heads_are_publicly_reconstructed points witness masks pcs degreeBounds]
  exact reconstruct_opened_rows_roundtrip points selected _ tails targets

/-- Actual current-program public fields evaluated on the source coefficient,
column-randomness and tail coins. The response objects are the same full source
objects whose high projections are serialized. -/
def currentPhysicalFields (parameters : CurrentPublicParameters)
    (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (pcs : SourcePcsCoins Goldilocks) (tails : LvcsRandomTailCoins Goldilocks)
    (gamma : DecsGamma Goldilocks) (decsMask : DecsFullCoefficients Goldilocks)
    (targets : Fin 20 → Goldilocks) : EagerAlgebraicFields Goldilocks :=
  currentEagerAlgebraicFields parameters points selected gamma
    (exactDecsResponse gamma (physicalHeads witness masks pcs) tails decsMask)
    (currentResponseCoefficients parameters witness masks) targets
    (physicalView points witness masks pcs tails targets)

theorem current_source_opened_rows_and_masks_are_reconstructed
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingInjective : Function.Injective canonicalPacking)
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks)
    (tails : LvcsRandomTailCoins Goldilocks) (gamma : DecsGamma Goldilocks)
    (decsMask : DecsFullCoefficients Goldilocks) (targets : Fin 20 → Goldilocks)
    (validNonlinear : ∀ constraint lane,
      (currentConstraints parameters witness constraint).eval (canonicalPacking lane) = 0)
    (validLinear : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64, parameters.linearWeights polynomial row lane *
        (witness row).eval (canonicalPacking lane)) = parameters.linearTargets polynomial)
    (outside : ∀ opening lane, points opening ≠ canonicalPacking lane) :
    let fields := currentPhysicalFields parameters points selected witness masks pcs tails gamma decsMask targets
    rowsFromFields points selected targets fields =
        fullRowEvaluations (physicalHeads witness masks pcs) tails targets ∧
      fields.decsMaskEvaluations =
        (fun opening polynomial => (coefficientPolynomial (decsMask polynomial)).eval (targets opening)) := by
  have maskRecovery := current_public_mask_openings_match_source_masks parameters points
    packingInjective packingCardNonzero witness witnessDegree masks validNonlinear validLinear outside
  change currentPublicMaskOpenings parameters points (currentResponseCoefficients parameters witness masks)
    (fun opening row => (witness row).eval (points opening)) = sourceMaskEvaluations points masks at maskRecovery
  have rowRecovery := physical_opened_rows_are_publicly_reconstructed points selected witness masks pcs
    tails targets (physical_column_degree witness masks pcs witnessDegree)
  constructor
  · dsimp only [currentPhysicalFields, currentEagerAlgebraicFields]
    rw [rows_from_eager_fields]
    dsimp only [physicalView]
    erw [maskRecovery]
    exact rowRecovery
  · change recoverDecsMaskOpenings gamma
      (exactDecsResponse gamma (physicalHeads witness masks pcs) tails decsMask) targets
      (reconstructOpenedRows points selected
        (reconstructedCombinationHeads points _ _ _) _ targets _) = _
    dsimp only [physicalView]
    erw [maskRecovery, rowRecovery]
    exact recover_decs_mask_openings_roundtrip nodesInjective gamma _ tails decsMask targets

/-- The complete 1,184-byte suffix is equal to the source suffix. This includes
the row/mask count words, all 145 canonical field words, and the zero counter. -/
theorem current_source_opened_leaf_suffix_is_publicly_reconstructed
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingInjective : Function.Injective canonicalPacking)
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks)
    (tails : LvcsRandomTailCoins Goldilocks) (gamma : DecsGamma Goldilocks)
    (decsMask : DecsFullCoefficients Goldilocks) (targets : Fin 20 → Goldilocks)
    (validNonlinear : ∀ constraint lane,
      (currentConstraints parameters witness constraint).eval (canonicalPacking lane) = 0)
    (validLinear : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64, parameters.linearWeights polynomial row lane *
        (witness row).eval (canonicalPacking lane)) = parameters.linearTargets polynomial)
    (outside : ∀ opening lane, points opening ≠ canonicalPacking lane)
    (opening : Fin 20) :
    let fields := currentPhysicalFields parameters points selected witness masks pcs tails gamma decsMask targets
    canonicalLeafSuffix (rowsFromFields points selected targets fields opening)
        (fields.decsMaskEvaluations opening) =
      canonicalLeafSuffix (fullRowEvaluations (physicalHeads witness masks pcs) tails targets opening)
        (fun polynomial => (coefficientPolynomial (decsMask polynomial)).eval (targets opening)) := by
  obtain ⟨rows, masks⟩ := current_source_opened_rows_and_masks_are_reconstructed parameters points selected
    packingInjective packingCardNonzero nodesInjective witness witnessDegree masks pcs tails gamma decsMask
    targets validNonlinear validLinear outside
  dsimp only
  rw [rows, masks]
  rfl

theorem source_witness_polynomials_degree
    (points : Fin 6 → Goldilocks) (admissible : Smz9WitnessInterpolationAdmissible points)
    (values : WitnessPackingValues Goldilocks) (coins : WitnessInterpolationCoins Goldilocks) :
    ∀ row, (sourceWitnessPolynomials values coins row).natDegree ≤ 69 := by
  intro row
  have baseDegree : (sourceWitnessBasePolynomial (values row)).natDegree ≤ 69 := by
    unfold sourceWitnessBasePolynomial
    apply natDegree_sum_le_of_forall_le
    intro lane _
    apply natDegree_mul_le.trans
    rw [natDegree_C, zero_add]
    change (Lagrange.basis Finset.univ smz9PackingPoint lane).natDegree ≤ 69
    rw [Lagrange.natDegree_basis admissible.packingPointsInjective.injOn (Finset.mem_univ lane)]
    decide
  exact polynomial_add_degree_69 _ _ baseDegree
    (witness_randomness_polynomial_degree_le admissible (coins row))

theorem source_witness_polynomials_evaluate_at_packing
    (points : Fin 6 → Goldilocks) (admissible : Smz9WitnessInterpolationAdmissible points)
    (values : WitnessPackingValues Goldilocks) (coins : WitnessInterpolationCoins Goldilocks)
    (row : Fin 686) (lane : Fin 64) :
    (sourceWitnessPolynomials values coins row).eval (canonicalPacking lane) = values row lane := by
  have base := Lagrange.eval_interpolate_at_node (s := (Finset.univ : Finset (Fin 64)))
    (v := canonicalPacking) (r := values row) admissible.packingPointsInjective.injOn
    (Finset.mem_univ lane)
  have randomness := witness_randomness_polynomial_eval_packing admissible (coins row) lane
  change (witnessRandomnessPolynomial (coins row)).eval (canonicalPacking lane) = 0 at randomness
  simp only [sourceWitnessPolynomials, eval_add, randomness, add_zero]
  exact base

def sourcePackingRows (values : WitnessPackingValues Goldilocks) (lane : Fin 64) : List Nat :=
  List.ofFn (fun row : Fin 686 => (values row lane).val)

theorem source_witness_extension_evaluates_to_exact_packing_rows
    (points : Fin 6 → Goldilocks) (admissible : Smz9WitnessInterpolationAdmissible points)
    (values : WitnessPackingValues Goldilocks) (coins : WitnessInterpolationCoins Goldilocks)
    (lane : Fin 64) (row : Nat) :
    (witnessPolynomialAtNat (sourceWitnessPolynomials values coins) row).eval (canonicalPacking lane) =
      ((sourcePackingRows values lane).getD row 0 : Goldilocks) := by
  by_cases bound : row < 686
  · rw [witnessPolynomialAtNat, dif_pos bound,
      source_witness_polynomials_evaluate_at_packing points admissible]
    simp only [sourcePackingRows, List.getD_eq_getElem?_getD, List.getElem?_ofFn,
      dif_pos bound, Option.getD_some, ZMod.natCast_zmod_val]
  · simp only [witnessPolynomialAtNat, eval_zero, sourcePackingRows,
      List.getD_eq_getElem?_getD, List.getElem?_ofFn, dif_neg bound, Option.getD_none, Nat.cast_zero]

/-- Actual successful fixed-program acceptance on the source 64 packing rows now
discharges the nonlinear-validity premise used by public mask/suffix recovery. -/
theorem accepted_source_witness_constraints_vanish
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (values : WitnessPackingValues Goldilocks) (coins : WitnessInterpolationCoins Goldilocks)
    (accepted : ∀ lane,
      V8Smz9RelationProgramComponentsGenerated.hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
        parameters.publicValues (sourcePackingRows values lane)) :
    ∀ constraint lane,
      (currentConstraints parameters (sourceWitnessPolynomials values coins) constraint).eval
        (canonicalPacking lane) = 0 :=
  accepted_current_packing_constraints_vanish parameters (sourceWitnessPolynomials values coins)
    (source_witness_polynomials_degree points admissible values coins) (sourcePackingRows values)
    (source_witness_extension_evaluates_to_exact_packing_rows points admissible values coins) accepted

/-- The full DECS response is unchanged after its triangular inverse, including
all coefficients later used to reconstruct the final Fiat--Shamir input. -/
theorem recovered_decs_mask_reproduces_same_response
    (gamma : DecsGamma Goldilocks) (heads : LvcsCommittedHeads Goldilocks)
    (tails : LvcsRandomTailCoins Goldilocks) (response : DecsFullCoefficients Goldilocks) :
    exactDecsResponse gamma heads tails (response - exactDecsUnmaskedCoefficients gamma heads tails) =
      response := by
  unfold exactDecsResponse
  abel

/-- Source fields after both exact mask inverses use the originally sampled D,T,
not newly generated high coefficients or replacement responses. -/
theorem inverse_current_physical_fields_keep_original_responses
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (witness : Fin 686 → Goldilocks[X]) (transcript : PiopCoefficients Goldilocks)
    (pcs : SourcePcsCoins Goldilocks) (tails : LvcsRandomTailCoins Goldilocks)
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (targets : Fin 20 → Goldilocks) :
    let masks := currentRecoveredMasks parameters witness transcript
    let heads := physicalHeads witness masks pcs
    currentPhysicalFields parameters points selected witness masks pcs tails gamma
        (response - exactDecsUnmaskedCoefficients gamma heads tails) targets =
      currentEagerAlgebraicFields parameters points selected gamma response transcript targets
        (physicalView points witness masks pcs tails targets) := by
  dsimp only
  unfold currentPhysicalFields
  rw [recovered_decs_mask_reproduces_same_response,
    current_recovered_masks_reproduce_full_transcript]

/-- The source-witness specialization derives degree and nonlinear validity
from the actual interpolation and accepted fixed-program packing assignments. -/
theorem accepted_source_witness_opened_suffix_is_reconstructed
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (selected : Function.Injective (smz9LvcsSelectedBlockMap points))
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (nodesInjective : Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)))
    (values : WitnessPackingValues Goldilocks) (witnessCoins : WitnessInterpolationCoins Goldilocks)
    (masks : PiopCoefficients Goldilocks) (pcs : SourcePcsCoins Goldilocks)
    (tails : LvcsRandomTailCoins Goldilocks) (gamma : DecsGamma Goldilocks)
    (decsMask : DecsFullCoefficients Goldilocks) (targets : Fin 20 → Goldilocks)
    (accepted : ∀ lane,
      V8Smz9RelationProgramComponentsGenerated.hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
        parameters.publicValues (sourcePackingRows values lane))
    (validLinearValues : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64,
        parameters.linearWeights polynomial row lane * values row lane) =
          parameters.linearTargets polynomial)
    (opening : Fin 20) :
    let witness := sourceWitnessPolynomials values witnessCoins
    let fields := currentPhysicalFields parameters points selected witness masks pcs tails gamma decsMask targets
    canonicalLeafSuffix (rowsFromFields points selected targets fields opening)
        (fields.decsMaskEvaluations opening) =
      canonicalLeafSuffix (fullRowEvaluations (physicalHeads witness masks pcs) tails targets opening)
        (fun polynomial => (coefficientPolynomial (decsMask polynomial)).eval (targets opening)) := by
  have linearValid : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64, parameters.linearWeights polynomial row lane *
        (sourceWitnessPolynomials values witnessCoins row).eval (canonicalPacking lane)) =
          parameters.linearTargets polynomial := by
    intro polynomial
    simpa only [source_witness_polynomials_evaluate_at_packing points admissible] using
      validLinearValues polynomial
  exact current_source_opened_leaf_suffix_is_publicly_reconstructed parameters points selected
    admissible.packingPointsInjective packingCardNonzero nodesInjective
    (sourceWitnessPolynomials values witnessCoins)
    (source_witness_polynomials_degree points admissible values witnessCoins) masks pcs tails gamma decsMask
    targets (accepted_source_witness_constraints_vanish parameters points admissible values witnessCoins accepted)
    linearValid admissible.openingsOutsidePacking opening

end
end HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding

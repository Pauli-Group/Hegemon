import HegemonCrypto.SmallWoodV8Smz9ProgramPolynomials
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator

/-!
# Current HGV8RP03 program in the eager PIOP simulator

Unlike the older generic expression interface, every nonlinear expression and
root below is fixed to the actual 8,271-node, 830-root FieldExpression program.
Its checked safe-operation certificate supplies both evaluation commutation and
the degree-552 bound. Public mask recovery is computed from those actual roots.
The output law uses the already established dependent source-coin inverses;
no program adapter, assumed degree bound, or real/simulated equality is supplied.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CurrentProgramPiop

open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy V8Smz9HonestHybrid
open V8Smz9EagerPrivacy V8Smz9JointAlgebraicLaw V8Smz9EagerSimulator
open Polynomial
open scoped BigOperators ENNReal Classical

noncomputable section

set_option maxRecDepth 5000
set_option maxHeartbeats 2000000

/-- Only public data and batching values; the actual program is not a parameter. -/
structure CurrentPublicParameters where
  publicValues : List Nat
  nonlinearGamma : Fin 5 → Fin 830 → Goldilocks
  linearWeights : Fin 5 → Fin 686 → Fin 64 → Goldilocks
  linearTargets : Fin 5 → Goldilocks

def publicWords (parameters : CurrentPublicParameters) : Nat → Goldilocks :=
  fun word => (parameters.publicValues.getD word 0 : Goldilocks)

def currentConstraints (parameters : CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) : Fin 830 → Goldilocks[X] :=
  V8Smz9ProgramPolynomials.constraintPolynomials (publicWords parameters)
    (witnessPolynomialAtNat witness)

def currentConstraintOpenings (parameters : CurrentPublicParameters)
    (opened : Fin 686 → Goldilocks) : Fin 830 → Goldilocks :=
  V8Smz9ProgramPolynomials.constraintOpenings (publicWords parameters)
    (openedWitnessAtNat opened)

theorem witness_extension_degree (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69) :
    ∀ row, (witnessPolynomialAtNat witness row).natDegree ≤ 69 := by
  intro row
  by_cases bound : row < 686
  · simpa only [witnessPolynomialAtNat, dif_pos bound] using degreeBound ⟨row, bound⟩
  · simp [witnessPolynomialAtNat, bound]

theorem current_constraint_evaluation
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69)
    (constraint : Fin 830) (point : Goldilocks) :
    (currentConstraints parameters witness constraint).eval point =
      currentConstraintOpenings parameters (fun row => (witness row).eval point) constraint := by
  unfold currentConstraints currentConstraintOpenings
  rw [opened_witness_extension_matches_polynomial_evaluation]
  exact V8Smz9ProgramPolynomials.constraint_polynomials_commute _ _
    (witness_extension_degree witness degreeBound) constraint point

theorem current_constraint_degree
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69) (constraint : Fin 830) :
    (currentConstraints parameters witness constraint).natDegree ≤ 552 :=
  V8Smz9ProgramPolynomials.constraint_polynomials_degree_le _ _
    (witness_extension_degree witness degreeBound) constraint

def currentNonlinearBatch (parameters : CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) (polynomial : Fin 5) : Goldilocks[X] :=
  V8Smz9PiopOpeningRecovery.nonlinearBatch (parameters.nonlinearGamma polynomial)
    (currentConstraints parameters witness)

theorem current_nonlinear_batch_degree
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69) (polynomial : Fin 5) :
    (currentNonlinearBatch parameters witness polynomial).natDegree ≤ 552 :=
  V8Smz9PiopOpeningRecovery.nonlinear_batch_degree _ _
    (current_constraint_degree parameters witness degreeBound)

theorem current_nonlinear_batch_evaluation
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69)
    (polynomial : Fin 5) (point : Goldilocks) :
    (currentNonlinearBatch parameters witness polynomial).eval point =
      ∑ constraint : Fin 830, parameters.nonlinearGamma polynomial constraint *
        currentConstraintOpenings parameters (fun row => (witness row).eval point) constraint := by
  exact (V8Smz9PiopOpeningRecovery.nonlinear_batch_eval
    (parameters.nonlinearGamma polynomial) (currentConstraints parameters witness) point).trans
    (Finset.sum_congr rfl (fun constraint _ =>
      congrArg (fun value => parameters.nonlinearGamma polynomial constraint * value)
        (current_constraint_evaluation parameters witness degreeBound constraint point)))

/-- Actual successful interpreter acceptance at every packing assignment supplies
all 830 zero identities. The conclusion is not an assumption about abstract roots. -/
theorem accepted_current_packing_constraints_vanish
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (degreeBound : ∀ row, (witness row).natDegree ≤ 69)
    (packingRows : Fin 64 → List Nat)
    (rowOpenings : ∀ lane row,
      (witnessPolynomialAtNat witness row).eval (canonicalPacking lane) =
        ((packingRows lane).getD row 0 : Goldilocks))
    (accepted : ∀ lane,
      V8Smz9RelationProgramComponentsGenerated.hgv8rp03ProgramComponents.nonlinearExecutable.Accepts
        parameters.publicValues (packingRows lane)) :
    ∀ constraint lane,
      (currentConstraints parameters witness constraint).eval (canonicalPacking lane) = 0 := by
  intro constraint lane
  exact V8Smz9ProgramPolynomials.accepted_source_constraints_vanish parameters.publicValues
    (packingRows lane) (witnessPolynomialAtNat witness)
    (witness_extension_degree witness degreeBound) (canonicalPacking lane)
    (rowOpenings lane) (accepted lane) constraint

def currentNonlinearResponsePolynomial (parameters : CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (polynomial : Fin 5) : Goldilocks[X] :=
  V8Smz9PiopOpeningRecovery.sourceNonlinearTranscript canonicalPacking
    (currentNonlinearBatch parameters witness polynomial)
    (coefficientPolynomial (masks.1 polynomial))

def currentLinearResponsePolynomial (parameters : CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks)
    (polynomial : Fin 5) : Goldilocks[X] :=
  V8Smz9PiopOpeningRecovery.sourceLinearUnmasked (parameters.linearWeights polynomial)
    (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking) witness +
      V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking (masks.2 polynomial)

def currentResponseCoefficients (parameters : CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) (masks : PiopCoefficients Goldilocks) :
    PiopCoefficients Goldilocks :=
  (fun polynomial coefficient =>
      (currentNonlinearResponsePolynomial parameters witness masks polynomial).coeff coefficient.val,
    fun polynomial coefficient =>
      (currentLinearResponsePolynomial parameters witness masks polynomial).coeff (coefficient.val + 1))

/-- Public reconstruction executes the actual fixed current program on W(r). -/
def currentPublicMaskOpenings (parameters : CurrentPublicParameters)
    (points : Fin 6 → Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (opened : WitnessOpeningView Goldilocks) : MaskOpeningValues Goldilocks :=
  (fun opening polynomial =>
    V8Smz9PiopOpeningRecovery.recoverNonlinearMaskOpening canonicalPacking
      (coefficientPolynomial (transcript.1 polynomial))
      (∑ constraint : Fin 830, parameters.nonlinearGamma polynomial constraint *
        currentConstraintOpenings parameters (opened opening) constraint)
      (points opening),
    fun opening polynomial =>
      V8Smz9PiopOpeningRecovery.recoverLinearMaskOpening canonicalPacking
        (parameters.linearTargets polynomial) (transcript.2 polynomial)
        (parameters.linearWeights polynomial)
        (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking)
        (opened opening) (points opening))

private theorem recover_nonlinear_response_coefficients {F : Type*} [Field F]
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (batch : F[X]) (mask : Fin 489 → F) (degreeBound : batch.natDegree ≤ 552)
    (valid : ∀ lane, batch.eval (packing lane) = 0)
    (point opening : F) (outside : ∀ lane, point ≠ packing lane)
    (openingCorrect : opening = batch.eval point) :
    V8Smz9PiopOpeningRecovery.recoverNonlinearMaskOpening packing
      (coefficientPolynomial (fun coefficient : Fin 489 =>
        (V8Smz9PiopOpeningRecovery.sourceNonlinearTranscript packing batch
          (coefficientPolynomial mask)).coeff coefficient.val)) opening point =
      (coefficientPolynomial mask).eval point := by
  have transcriptDegree :
      (V8Smz9PiopOpeningRecovery.sourceNonlinearTranscript packing batch
        (coefficientPolynomial mask)).natDegree < 489 := by
    have quotientDegree := V8Smz9PiopOpeningRecovery.nonlinear_quotient_degree
      packing batch degreeBound
    have maskDegree := coefficient_polynomial_nat_degree_le mask
    have bound := (natDegree_add_le _ _).trans (max_le quotientDegree maskDegree)
    change (V8Smz9PiopOpeningRecovery.sourceNonlinearQuotient packing batch +
      coefficientPolynomial mask).natDegree < 489
    omega
  rw [coefficient_polynomial_of_coefficients _ transcriptDegree, openingCorrect]
  exact V8Smz9PiopOpeningRecovery.recover_nonlinear_mask_opening packing injective
    batch (coefficientPolynomial mask) valid point outside

private theorem public_nonlinear_mask_opening_matches_source
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (packingInjective : Function.Injective canonicalPacking)
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (masks : PiopCoefficients Goldilocks)
    (validNonlinear : ∀ constraint lane,
      (currentConstraints parameters witness constraint).eval (canonicalPacking lane) = 0)
    (outside : ∀ opening lane, points opening ≠ canonicalPacking lane)
    (opening : Fin 6) (polynomial : Fin 5) :
    (currentPublicMaskOpenings parameters points (currentResponseCoefficients parameters witness masks)
      (fun opening row => (witness row).eval (points opening))).1 opening polynomial =
      (coefficientPolynomial (masks.1 polynomial)).eval (points opening) := by
  exact recover_nonlinear_response_coefficients canonicalPacking packingInjective
    (currentNonlinearBatch parameters witness polynomial) (masks.1 polynomial)
    (current_nonlinear_batch_degree parameters witness witnessDegree polynomial)
    (V8Smz9PiopOpeningRecovery.nonlinear_batch_valid canonicalPacking
      (parameters.nonlinearGamma polynomial) (currentConstraints parameters witness) validNonlinear)
    (points opening) _ (outside opening)
    (current_nonlinear_batch_evaluation parameters witness witnessDegree polynomial (points opening)).symm

private theorem public_linear_mask_opening_shape
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (opened : WitnessOpeningView Goldilocks)
    (opening : Fin 6) (polynomial : Fin 5) :
    (currentPublicMaskOpenings parameters points transcript opened).2 opening polynomial =
      V8Smz9PiopOpeningRecovery.recoverLinearMaskOpening canonicalPacking
        (parameters.linearTargets polynomial) (transcript.2 polynomial)
        (parameters.linearWeights polynomial)
        (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking)
        (opened opening) (points opening) := rfl

private theorem source_linear_response_coefficients_shape
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (polynomial : Fin 5) :
    (currentResponseCoefficients parameters witness masks).2 polynomial =
      (fun coefficient : Fin 132 =>
        (currentLinearResponsePolynomial parameters witness masks polynomial).coeff
          (coefficient.val + 1)) := rfl

private theorem source_linear_response_function_shape :
    currentLinearResponsePolynomial = fun parameters witness masks polynomial =>
      V8Smz9PiopOpeningRecovery.sourceLinearUnmasked (parameters.linearWeights polynomial)
        (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking) witness +
      V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking (masks.2 polynomial) := rfl

private theorem source_linear_response_polynomial_shape
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (polynomial : Fin 5) :
    currentLinearResponsePolynomial parameters witness masks polynomial =
      V8Smz9PiopOpeningRecovery.sourceLinearUnmasked (parameters.linearWeights polynomial)
        (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking) witness +
      V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking (masks.2 polynomial) := by
  exact congrFun (congrFun (congrFun (congrFun source_linear_response_function_shape
    parameters) witness) masks) polynomial

private theorem public_linear_mask_opening_matches_source
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (packingInjective : Function.Injective canonicalPacking)
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (masks : PiopCoefficients Goldilocks)
    (validLinear : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64, parameters.linearWeights polynomial row lane *
        (witness row).eval (canonicalPacking lane)) = parameters.linearTargets polynomial)
    (opening : Fin 6) (polynomial : Fin 5) :
    (currentPublicMaskOpenings parameters points (currentResponseCoefficients parameters witness masks)
      (fun opening row => (witness row).eval (points opening))).2 opening polynomial =
      (V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking (masks.2 polynomial)).eval
        (points opening) := by
  have coefficients := (source_linear_response_coefficients_shape parameters witness masks
    polynomial).trans (congrArg (fun response : Goldilocks[X] =>
      fun coefficient : Fin 132 => response.coeff (coefficient.val + 1))
      (source_linear_response_polynomial_shape parameters witness masks polynomial))
  exact (public_linear_mask_opening_shape parameters points
    (currentResponseCoefficients parameters witness masks)
    (fun opening row => (witness row).eval (points opening)) opening polynomial).trans
    ((congrArg (fun responseCoefficients : Fin 132 → Goldilocks =>
      V8Smz9PiopOpeningRecovery.recoverLinearMaskOpening canonicalPacking
        (parameters.linearTargets polynomial) responseCoefficients
        (parameters.linearWeights polynomial)
        (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking)
        (fun row => (witness row).eval (points opening)) (points opening)) coefficients).trans
      (V8Smz9PiopOpeningRecovery.source_linear_coins_recovered_from_opened_rows
        canonicalPacking packingInjective packingCardNonzero (parameters.linearWeights polynomial)
        witness witnessDegree (masks.2 polynomial) (parameters.linearTargets polynomial)
        (validLinear polynomial) (points opening)))

private theorem nonlinear_response_coefficient_affine {F : Type*} [Field F]
    {count : Nat} (base : F[X]) (mask baseline : Fin count → F) (selected : Fin count)
    (baselineZero : baseline selected = 0) :
    (base + coefficientPolynomial mask).coeff selected.val =
      (base + coefficientPolynomial baseline).coeff selected.val + mask selected := by
  rw [coeff_add, coeff_add, coefficient_polynomial_coefficient,
    coefficient_polynomial_coefficient, baselineZero, add_zero]

private theorem linear_response_coefficient_affine {F : Type*} [Field F]
    (packing : Fin 64 → F) (base : F[X]) (mask baseline : Fin 132 → F)
    (selected : Fin 132) (baselineZero : baseline selected = 0) :
    (base + V8Smz9PiopOpeningRecovery.sourceLinearMask packing mask).coeff
        (selected.val + 1) =
      (base + V8Smz9PiopOpeningRecovery.sourceLinearMask packing baseline).coeff
        (selected.val + 1) + mask selected := by
  rw [coeff_add, coeff_add, source_linear_mask_nonconstant_coefficient,
    source_linear_mask_nonconstant_coefficient, baselineZero, add_zero]

private theorem source_linear_response_affine_at
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) (polynomial : Fin 5) (coefficient : Fin 132) :
    (currentResponseCoefficients parameters witness masks).2 polynomial coefficient =
      (currentResponseCoefficients parameters witness 0).2 polynomial coefficient +
        masks.2 polynomial coefficient := by
  have maskCoefficients := (source_linear_response_coefficients_shape parameters witness masks
    polynomial).trans (congrArg (fun response : Goldilocks[X] =>
      fun selected : Fin 132 => response.coeff (selected.val + 1))
      (source_linear_response_polynomial_shape parameters witness masks polynomial))
  have zeroCoefficients := (source_linear_response_coefficients_shape parameters witness 0
    polynomial).trans (congrArg (fun response : Goldilocks[X] =>
      fun selected : Fin 132 => response.coeff (selected.val + 1))
      (source_linear_response_polynomial_shape parameters witness 0 polynomial))
  exact (congrFun maskCoefficients coefficient).trans
    ((linear_response_coefficient_affine canonicalPacking
      (V8Smz9PiopOpeningRecovery.sourceLinearUnmasked (parameters.linearWeights polynomial)
        (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking) witness)
      (masks.2 polynomial) ((0 : PiopCoefficients Goldilocks).2 polynomial) coefficient rfl).trans
      (congrArg (fun value => value + masks.2 polynomial coefficient)
        (congrFun zeroCoefficients coefficient).symm))

theorem current_public_mask_openings_match_source_masks
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (packingInjective : Function.Injective canonicalPacking)
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (masks : PiopCoefficients Goldilocks)
    (validNonlinear : ∀ constraint lane,
      (currentConstraints parameters witness constraint).eval (canonicalPacking lane) = 0)
    (validLinear : ∀ polynomial,
      (∑ row : Fin 686, ∑ lane : Fin 64, parameters.linearWeights polynomial row lane *
        (witness row).eval (canonicalPacking lane)) = parameters.linearTargets polynomial)
    (outside : ∀ opening lane, points opening ≠ canonicalPacking lane) :
    currentPublicMaskOpenings parameters points (currentResponseCoefficients parameters witness masks)
        (fun opening row => (witness row).eval (points opening)) =
      (fun opening polynomial => (coefficientPolynomial (masks.1 polynomial)).eval (points opening),
        fun opening polynomial =>
          (V8Smz9PiopOpeningRecovery.sourceLinearMask canonicalPacking (masks.2 polynomial)).eval
            (points opening)) := by
  apply Prod.ext
  · funext opening polynomial
    exact public_nonlinear_mask_opening_matches_source parameters points packingInjective
      witness witnessDegree masks validNonlinear outside opening polynomial
  · funext opening polynomial
    exact public_linear_mask_opening_matches_source parameters points packingInjective
      packingCardNonzero witness witnessDegree masks validLinear opening polynomial

theorem current_response_is_affine_mask_map
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (masks : PiopCoefficients Goldilocks) :
    currentResponseCoefficients parameters witness masks =
      currentResponseCoefficients parameters witness 0 + masks := by
  apply Prod.ext
  · funext polynomial coefficient
    exact nonlinear_response_coefficient_affine
      (V8Smz9PiopOpeningRecovery.sourceNonlinearQuotient canonicalPacking
        (currentNonlinearBatch parameters witness polynomial))
      (masks.1 polynomial) ((0 : PiopCoefficients Goldilocks).1 polynomial) coefficient rfl
  · funext polynomial coefficient
    exact source_linear_response_affine_at parameters witness masks polynomial coefficient

def currentRecoveredMasks (parameters : CurrentPublicParameters)
    (witness : Fin 686 → Goldilocks[X]) (transcript : PiopCoefficients Goldilocks) :
    PiopCoefficients Goldilocks :=
  transcript - currentResponseCoefficients parameters witness 0

theorem current_recovered_masks_reproduce_full_transcript
    (parameters : CurrentPublicParameters) (witness : Fin 686 → Goldilocks[X])
    (transcript : PiopCoefficients Goldilocks) :
    currentResponseCoefficients parameters witness
        (currentRecoveredMasks parameters witness transcript) = transcript := by
  rw [current_response_is_affine_mask_map, currentRecoveredMasks]
  abel

/-- The recovered old masks depend on W alone, not on later PCS/LVCS coins. -/
def currentRecoveredMasksAtCoins (parameters : CurrentPublicParameters)
    (values : WitnessPackingValues Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (coins : WitnessInterpolationCoins Goldilocks) : PiopCoefficients Goldilocks :=
  currentRecoveredMasks parameters (sourceWitnessPolynomials values coins) transcript

def currentPcsBaseForTranscript (parameters : CurrentPublicParameters)
    (values : WitnessPackingValues Goldilocks) (points : Fin 6 → Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (coins : WitnessInterpolationCoins Goldilocks) :
    SourcePcsView Goldilocks :=
  let masks := currentRecoveredMasksAtCoins parameters values transcript coins
  (fun polynomial opening column =>
      (sourceNonlinearBaseColumns (masks.1 polynomial) column.succ).eval (points opening),
    fun polynomial opening =>
      (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)) 1).eval
        (points opening))

def currentPcsColumnPolynomialsForTranscript (parameters : CurrentPublicParameters)
    (values : WitnessPackingValues Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (witnessCoins : WitnessInterpolationCoins Goldilocks) (pcsCoins : SourcePcsCoins Goldilocks) :
    Fin 736 → Goldilocks[X] :=
  let masks := currentRecoveredMasksAtCoins parameters values transcript witnessCoins
  Fin.append (sourceWitnessPolynomials values witnessCoins)
    (Fin.append
      ((matrixEquiv 5 8 Goldilocks[X]).symm (fun polynomial =>
        sourceNonlinearPcsColumnPolynomials (sourceNonlinearBaseColumns (masks.1 polynomial))
          (pcsCoins.1 polynomial)))
      ((matrixEquiv 5 2 Goldilocks[X]).symm (fun polynomial =>
        sourceLinearColumnValues X
          (sourceLinearBaseColumns (sourceLinearMaskFullCoefficients (masks.2 polynomial)))
          (coefficientPolynomial (pcsCoins.2 polynomial)))))

def currentCommittedHeadsForTranscript (parameters : CurrentPublicParameters)
    (values : WitnessPackingValues Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (witnessCoins : WitnessInterpolationCoins Goldilocks) (pcsCoins : SourcePcsCoins Goldilocks) :
    LvcsCommittedHeads Goldilocks :=
  sourceStackedHeads (fun column coefficient =>
    (currentPcsColumnPolynomialsForTranscript parameters values transcript witnessCoins pcsCoins column).coeff
      coefficient.val)

/-- Actual-program public eager fields; there is no witness/mask argument. -/
def currentEagerAlgebraicFields
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (targets : Fin 20 → Goldilocks)
    (view : SourceRemainingView Goldilocks) : EagerAlgebraicFields Goldilocks :=
  eagerAlgebraicFields points selectedInjective gamma response transcript targets
    (currentPublicMaskOpenings parameters points transcript view.1) view

def currentEagerOutcome
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points))
    (view : SourceRemainingView Goldilocks) : Option (EagerAlgebraicFields Goldilocks) :=
  (chooseTargets view.1 view.2.1 view.2.2.1).map fun targets =>
    currentEagerAlgebraicFields parameters points selectedInjective gamma response transcript targets.val view

def currentPartialOutcome
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points))
    (view : SourcePartialRemainingView Goldilocks) : Option (EagerAlgebraicFields Goldilocks) :=
  view.2.2.2.bind fun subset =>
    (chooseTargets view.1 view.2.1 view.2.2.1).map fun targets =>
      currentEagerAlgebraicFields parameters points selectedInjective gamma response transcript targets.val
        (view.1, view.2.1, view.2.2.1, subset)

theorem current_abort_projection_is_exact
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points)) :
    currentPartialOutcome parameters points selectedInjective gamma response transcript chooseTargets ∘
        sourceRemainingAbortProjection chooseTargets =
      currentEagerOutcome parameters points selectedInjective gamma response transcript chooseTargets := by
  funext view
  cases selected : chooseTargets view.1 view.2.1 view.2.2.1 with
  | none => simp [currentPartialOutcome, sourceRemainingAbortProjection, currentEagerOutcome, selected]
  | some targets =>
    simp [currentPartialOutcome, sourceRemainingAbortProjection, currentEagerOutcome, selected]

/-- The witness-free right side now computes the actual current grammar. The
left side uses the corresponding recovered Q, corrected cross-column PCS map,
and exact physical head reshape. Abort is retained, not conditioned away. -/
theorem current_program_eager_algebraic_output_law
    (parameters : CurrentPublicParameters) (points : Fin 6 → Goldilocks)
    (witnessValues : WitnessPackingValues Goldilocks)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (selectedInjective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : DecsGamma Goldilocks) (response : DecsFullCoefficients Goldilocks)
    (transcript : PiopCoefficients Goldilocks) (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points)) :
    pmfMap (uniformFintypePMF (SourceRemainingCoins Goldilocks))
        (currentPartialOutcome parameters points selectedInjective gamma response transcript chooseTargets ∘
          sourceRemainingPartialChronologicalView witnessValues points
            (currentPcsBaseForTranscript parameters witnessValues points transcript)
            (currentCommittedHeadsForTranscript parameters witnessValues transcript) chooseTargets) =
      pmfMap (uniformFintypePMF (SourceRemainingView Goldilocks))
        (currentEagerOutcome parameters points selectedInjective gamma response transcript chooseTargets) := by
  have baseLaw := source_remaining_partial_chronological_joint_law witnessValues points
    witnessAdmissible pointsNonzero
    (currentPcsBaseForTranscript parameters witnessValues points transcript)
    (currentCommittedHeadsForTranscript parameters witnessValues transcript) fallback chooseTargets
  have pushed := congrArg (fun law => pmfMap law
    (currentPartialOutcome parameters points selectedInjective gamma response transcript chooseTargets)) baseLaw
  rw [pmfMap_comp, pmfMap_comp, current_abort_projection_is_exact] at pushed
  exact pushed

end
end HegemonCrypto.SmallWood.V8Smz9CurrentProgramPiop

import HegemonCrypto.SmallWoodCompiledAcceptance

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Native PIOP equation refinement

`piop_recompute_transcript` reconstructs the nonlinear quotient and sparse-linear polynomials
from five off-domain evaluations plus transmitted high coefficients.  This module states those
field equations without reference to Rust containers and proves they are exactly the
`ProductionPiopOpeningPasses` event consumed by the third interactive soundness round.

No probability or cryptographic assumption appears below.
-/

namespace HegemonCrypto.SmallWood.NativePiopRefinement

open Polynomial
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.PiopEvaluation
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.ProductionPolynomials
open HegemonCrypto.SmallWood.RoundByRound

noncomputable section

/-- The five native PIOP opening points, interpreted in the proof field. -/
def nativeOpeningPoint
    (opening : PiopOpeningChallenge)
    (index : Fin openedEvaluations) : Goldilocks :=
  wordToGoldilocks (opening.val index)

/--
The Lagrange polynomial used by `piop_recompute_transcript` for the appended point zero.
It vanishes at all five opening points and evaluates to one at zero.  The executable verifier
constructs the same polynomial with `poly_set_lagrange(eval_points ++ [0], 5)`.
-/
def nativeLinearCorrectionPolynomial
    (opening : PiopOpeningChallenge) : Goldilocks[X] :=
  (∏ index : Fin openedEvaluations,
      (X - C (nativeOpeningPoint opening index))) *
    C ((∏ index : Fin openedEvaluations,
        -nativeOpeningPoint opening index)⁻¹)

/-- Packing-node sum used as the divisor in the native linear-target correction. -/
def nativeLinearCorrectionFactor
    (opening : PiopOpeningChallenge) : Goldilocks :=
  nodeSum
    (Finset.range packingFactor)
    packingNodePoint
    (nativeLinearCorrectionPolynomial opening)

/--
Exact polynomial returned by the native linear correction after restoration from transmitted
high coefficients and the five opened evaluations.
-/
def nativeCorrectedLinearPolynomial
    (opening : PiopOpeningChallenge)
    (base : Goldilocks[X])
    (target : Goldilocks) : Goldilocks[X] :=
  base +
    C ((target -
        nodeSum (Finset.range packingFactor) packingNodePoint base) /
      nativeLinearCorrectionFactor opening) *
      nativeLinearCorrectionPolynomial opening

theorem node_sum_add
    (left right : Goldilocks[X]) :
    nodeSum (Finset.range packingFactor) packingNodePoint (left + right) =
      nodeSum (Finset.range packingFactor) packingNodePoint left +
        nodeSum (Finset.range packingFactor) packingNodePoint right := by
  simp [nodeSum, eval_add, Finset.sum_add_distrib]

theorem node_sum_constant_mul
    (scalar : Goldilocks)
    (polynomial : Goldilocks[X]) :
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (C scalar * polynomial) =
      scalar *
        nodeSum
          (Finset.range packingFactor)
          packingNodePoint
          polynomial := by
  simp [nodeSum, eval_mul, Finset.mul_sum]

/--
Fail-closed nonzero-divisor admission makes the exact Rust correction force the public target
sum.  Prior to the matching Rust check, a zero factor would panic in `div_mod` and this theorem
could not describe all verifier inputs.
-/
theorem native_corrected_linear_polynomial_node_sum
    (opening : PiopOpeningChallenge)
    (base : Goldilocks[X])
    (target : Goldilocks)
    (factorNonzero : nativeLinearCorrectionFactor opening ≠ 0) :
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (nativeCorrectedLinearPolynomial opening base target) =
      target := by
  rw [nativeCorrectedLinearPolynomial, node_sum_add, node_sum_constant_mul]
  rw [show
    nodeSum
        (Finset.range packingFactor)
        packingNodePoint
        (nativeLinearCorrectionPolynomial opening) =
      nativeLinearCorrectionFactor opening by rfl]
  rw [div_mul_cancel₀ _ factorNonzero]
  ring

/--
Low-level result of the native restoration/correction loop.  `base` is the polynomial reconstructed
from the transmitted high coefficients and opened evaluations before the target correction.
-/
def NativeLinearTargetReconstruction
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge)
    (base : Fin rho -> Goldilocks[X]) : Prop :=
  nativeLinearCorrectionFactor opening ≠ 0 ∧
    ∀ repetition,
      claimedLinearPolynomial message repetition =
        nativeCorrectedLinearPolynomial opening (base repetition)
          (productionLinearBatchTarget statement challenge repetition)

theorem native_linear_target_reconstruction_implies_claimed_target
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge)
    (base : Fin rho -> Goldilocks[X])
    (reconstruction :
      NativeLinearTargetReconstruction
        statement challenge message opening base) :
    ClaimedLinearTarget statement challenge message := by
  intro repetition
  rw [reconstruction.2 repetition]
  exact native_corrected_linear_polynomial_node_sum
    opening (base repetition)
      (productionLinearBatchTarget statement challenge repetition)
      reconstruction.1

/-- Exact cross-multiplied nonlinear equations reconstructed by the native verifier. -/
def NativeNonlinearOpeningChecks
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge) : Prop :=
  ∀ repetition index,
    let point := wordToGoldilocks (opening.val index)
    (packingVanishing
        (Finset.range statement.lppcPackingFactor)
        packingNodePoint).eval point *
        ((claimedNonlinearPolynomial message repetition).eval point -
          (nonlinearMaskPolynomial oracle repetition).eval point) =
      (productionNonlinearBatch
        statement oracle challenge repetition).eval point

/-- Exact sparse-linear equations reconstructed by the native verifier. -/
def NativeLinearOpeningChecks
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge) : Prop :=
  ∀ repetition index,
    let point := wordToGoldilocks (opening.val index)
    (claimedLinearPolynomial message repetition).eval point =
      (productionLinearBatch statement oracle challenge repetition).eval point +
        (linearMaskPolynomial oracle repetition).eval point

def NativePiopOpeningChecks
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge) : Prop :=
  NativeNonlinearOpeningChecks statement oracle challenge message opening ∧
    NativeLinearOpeningChecks statement oracle challenge message opening

theorem native_nonlinear_checks_imply_production_opening_passes
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge)
    (nativeChecks :
      NativeNonlinearOpeningChecks statement oracle challenge message opening) :
    ProductionNonlinearOpeningPasses
      statement oracle challenge message opening := by
  intro repetition index
  have checked := nativeChecks repetition index
  unfold productionNonlinearDiscrepancy consistencyDiscrepancy
  simp only [eval_sub, eval_mul]
  exact sub_eq_zero.mpr checked

theorem native_linear_checks_imply_production_opening_passes
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge)
    (nativeChecks :
      NativeLinearOpeningChecks statement oracle challenge message opening) :
    ProductionLinearOpeningPasses
      statement oracle challenge message opening := by
  intro repetition index
  have checked := nativeChecks repetition index
  unfold productionLinearDiscrepancy
  simp only [eval_sub]
  rw [checked]
  ring

/-- The native field equations are sufficient for the exact third-round predicate. -/
theorem native_piop_checks_imply_production_opening_passes
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (opening : PiopOpeningChallenge)
    (nativeChecks :
      NativePiopOpeningChecks statement oracle challenge message opening) :
    ProductionPiopOpeningPasses
      statement oracle challenge message opening :=
  ⟨native_nonlinear_checks_imply_production_opening_passes
      statement oracle challenge message opening nativeChecks.1,
    native_linear_checks_imply_production_opening_passes
      statement oracle challenge message opening nativeChecks.2⟩

end

end HegemonCrypto.SmallWood.NativePiopRefinement

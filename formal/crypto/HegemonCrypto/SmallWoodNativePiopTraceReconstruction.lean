import HegemonCrypto.SmallWoodNativePcsReconstruction
import HegemonCrypto.SmallWoodNativePiopReconstruction

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Proof-derived native PIOP evaluation trace

This module removes the final handoff assumption between the native PCS and PIOP models.  It
constructs every value consumed by `piop_recompute_transcript` from the 35 reconstructed
combination heads, then proves that a matching PCS opening makes those values equal the exact
polynomial evaluations used by the interactive soundness proof.
-/

namespace HegemonCrypto.SmallWood.NativePiopTraceReconstruction

open Polynomial
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWood.LvcsOpening
open HegemonCrypto.SmallWood.NativePcsReconstruction
open HegemonCrypto.SmallWood.NativePiopRefinement
open HegemonCrypto.SmallWood.NativePiopReconstruction
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.PiopEvaluation
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.ProductionPolynomials
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped BigOperators

noncomputable section

/-- One witness-row evaluation recovered from the proof's reconstructed combination heads. -/
def witnessEvaluationFromHeads
    (message : PcsCombinationMessage)
    (openingIndex : Fin openedEvaluations)
    (row : Nat) : Goldilocks :=
  if rowBound : row < rowCount then
    combinationHeadValue message openingIndex
      (witnessColumnIndex ⟨row, rowBound⟩)
  else
    0

theorem matching_witness_evaluation_from_heads
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (row : Nat) :
    witnessEvaluationFromHeads message openingIndex row =
      (extractedWitnessPolynomialAt oracle row).eval
        (nativeOpeningPoint opening openingIndex) := by
  unfold witnessEvaluationFromHeads extractedWitnessPolynomialAt
  split_ifs with rowBound
  · exact matching_witness_opening_evaluation
      opening message oracle matching openingIndex ⟨row, rowBound⟩
  · simp

/--
One generated nonlinear constraint evaluated exactly as Rust does over the proof-derived witness
row evaluations.
-/
def nonlinearConstraintEvaluationFromHeads
    (statement : Statement)
    (message : PcsCombinationMessage)
    (openingIndex : Fin openedEvaluations)
    (constraint : Nat) : Goldilocks :=
  (goldilocksProgram
      statement.publicValues
      (witnessEvaluationFromHeads message openingIndex)
      productionNonlinearExpressions).getD
    (productionNonlinearConstraintRoots.getD constraint 0) 0

theorem matching_nonlinear_constraint_evaluation_from_heads
    (statement : Statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (constraint : Nat) :
    nonlinearConstraintEvaluationFromHeads
        statement message openingIndex constraint =
      (productionNonlinearPolynomial statement oracle constraint).eval
        (nativeOpeningPoint opening openingIndex) := by
  unfold nonlinearConstraintEvaluationFromHeads productionNonlinearPolynomial
  rw [(program_evaluation_invariant
    statement.publicValues
    (extractedWitnessPolynomialAt oracle)
    productionNonlinearExpressions
    (nativeOpeningPoint opening openingIndex)).2
      (productionNonlinearConstraintRoots.getD constraint 0)]
  congr 3
  funext row
  exact matching_witness_evaluation_from_heads
    opening message oracle matching openingIndex row

/-- The exact nonlinear challenge batch evaluated from reconstructed combination heads. -/
def nonlinearBatchEvaluationFromHeads
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (message : PcsCombinationMessage)
    (repetition : Fin rho)
    (openingIndex : Fin openedEvaluations) : Goldilocks :=
  ∑ constraint : Fin statement.nonlinearConstraintCount,
    wordToGoldilocks
        (challenge repetition (nonlinearChallengeIndex statement constraint)) *
      nonlinearConstraintEvaluationFromHeads
        statement message openingIndex constraint.val

theorem matching_nonlinear_batch_evaluation_from_heads
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (repetition : Fin rho)
    (openingIndex : Fin openedEvaluations) :
    nonlinearBatchEvaluationFromHeads
        statement challenge message repetition openingIndex =
      (productionNonlinearBatch statement oracle challenge repetition).eval
        (nativeOpeningPoint opening openingIndex) := by
  unfold nonlinearBatchEvaluationFromHeads productionNonlinearBatch
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro constraint _
  rw [eval_mul, eval_C,
    matching_nonlinear_constraint_evaluation_from_heads
      statement opening message oracle matching openingIndex constraint.val]

/-- One sparse-linear term evaluated from the proof-derived witness row values. -/
def linearTermEvaluationFromHeads
    (statement : Statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (openingIndex : Fin openedEvaluations)
    (term : Nat) : Goldilocks :=
  productionLinearTermCoefficient statement term *
      witnessEvaluationFromHeads message openingIndex
        (productionLinearTermIndex statement term / packingFactor) *
    (Lagrange.basis
      (Finset.range packingFactor)
      packingNodePoint
      (productionLinearTermIndex statement term % packingFactor)).eval
        (nativeOpeningPoint opening openingIndex)

theorem matching_linear_term_evaluation_from_heads
    (statement : Statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (term : Nat) :
    linearTermEvaluationFromHeads statement opening message openingIndex term =
      (productionLinearTermPolynomial statement oracle term).eval
        (nativeOpeningPoint opening openingIndex) := by
  unfold linearTermEvaluationFromHeads productionLinearTermPolynomial
  rw [eval_mul, eval_mul, eval_C,
    matching_witness_evaluation_from_heads
      opening message oracle matching openingIndex
        (productionLinearTermIndex statement term / packingFactor)]

/-- One sparse-linear constraint evaluated from reconstructed combination heads. -/
def linearConstraintEvaluationFromHeads
    (statement : Statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (openingIndex : Fin openedEvaluations)
    (constraint : Nat) : Goldilocks :=
  let start := statement.linearTermOffsets.getD constraint 0
  let stop := statement.linearTermOffsets.getD (constraint + 1) start
  ∑ relativeTerm ∈ Finset.range (stop - start),
    linearTermEvaluationFromHeads
      statement opening message openingIndex (start + relativeTerm)

theorem matching_linear_constraint_evaluation_from_heads
    (statement : Statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (openingIndex : Fin openedEvaluations)
    (constraint : Nat) :
    linearConstraintEvaluationFromHeads
        statement opening message openingIndex constraint =
      (productionLinearConstraintPolynomial statement oracle constraint).eval
        (nativeOpeningPoint opening openingIndex) := by
  unfold linearConstraintEvaluationFromHeads productionLinearConstraintPolynomial
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro relativeTerm _
  exact matching_linear_term_evaluation_from_heads
    statement opening message oracle matching openingIndex _

/-- The exact sparse-linear challenge batch evaluated from reconstructed combination heads. -/
def linearBatchEvaluationFromHeads
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (repetition : Fin rho)
    (openingIndex : Fin openedEvaluations) : Goldilocks :=
  ∑ constraint : Fin statement.linearConstraintCount,
    wordToGoldilocks
        (challenge repetition (linearChallengeIndex statement constraint)) *
      linearConstraintEvaluationFromHeads
        statement opening message openingIndex constraint.val

theorem matching_linear_batch_evaluation_from_heads
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle)
    (repetition : Fin rho)
    (openingIndex : Fin openedEvaluations) :
    linearBatchEvaluationFromHeads
        statement challenge opening message repetition openingIndex =
      (productionLinearBatch statement oracle challenge repetition).eval
        (nativeOpeningPoint opening openingIndex) := by
  unfold linearBatchEvaluationFromHeads productionLinearBatch
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro constraint _
  rw [eval_mul, eval_C,
    matching_linear_constraint_evaluation_from_heads
      statement opening message oracle matching openingIndex constraint.val]

/--
The two matrices consumed by native polynomial restoration, constructed solely from the statement,
challenges, and proof-derived combination heads.
-/
def nativePiopEvaluationTraceFromHeads
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage) :
    NativePiopEvaluationTrace where
  nonlinear repetition openingIndex :=
    nonlinearBatchEvaluationFromHeads
        statement challenge message repetition openingIndex /
      (packingVanishing
        (Finset.range statement.lppcPackingFactor)
        packingNodePoint).eval (nativeOpeningPoint opening openingIndex) +
      nonlinearMaskEvaluationFromHeads
        opening message openingIndex repetition
  linear repetition openingIndex :=
    linearBatchEvaluationFromHeads
        statement challenge opening message repetition openingIndex +
      linearMaskEvaluationFromHeads
        opening message openingIndex repetition

/--
Matching PCS combination polynomials identify the proof-derived native trace with the exact
oracle-derived PIOP trace.  This is the deterministic PCS-to-PIOP handoff formerly supplied as an
acceptance premise.
-/
theorem native_piop_evaluation_trace_from_heads_eq_expected
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (message : PcsCombinationMessage)
    (oracle : CommittedOracle)
    (matching : ProductionCombinationsMatch opening message oracle) :
    nativePiopEvaluationTraceFromHeads statement challenge opening message =
      expectedNativePiopEvaluationTrace statement oracle challenge opening := by
  apply congrArg₂ NativePiopEvaluationTrace.mk
  · funext repetition openingIndex
    unfold nativeNonlinearOpeningEvaluation
    rw [matching_nonlinear_batch_evaluation_from_heads
      statement challenge opening message oracle matching repetition openingIndex]
    rw [matching_nonlinear_mask_opening_evaluation
      opening message oracle matching openingIndex repetition]
    rfl
  · funext repetition openingIndex
    rw [matching_linear_batch_evaluation_from_heads
      statement challenge opening message oracle matching repetition openingIndex]
    rw [matching_linear_mask_opening_evaluation
      opening message oracle matching openingIndex repetition]
    rfl

end

end HegemonCrypto.SmallWood.NativePiopTraceReconstruction

import HegemonCrypto.SmallWoodV8Smz9PiopOpeningRecovery
import HegemonCrypto.SmallWoodV8Smz9AdmissibleRootProbability
import HegemonCrypto.SmallWoodPiopExtraction
import HegemonCrypto.SmallWoodV8Smz9RobustQueryMismatch

/-!
# Fixed-candidate SMZ9 PIOP soundness

A candidate and its masks are fixed before five uniform batching rows. Claimed
transcripts may depend on the entire batching matrix, but precede the six fresh,
fully admissible opening points. The linear constant is reconstructed from the
public batched target. No mask-zero-sum premise is needed. This is an ideal finite
experiment, not a Rust-verifier refinement or Fiat--Shamir/QROM theorem.
-/

namespace HegemonCrypto.SmallWood.V8Smz9PiopSoundness

open Polynomial
open scoped BigOperators
open V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdaptiveFiniteAccounting.Historical
open V8Smz9AdmissibleRootProbability
open V8Smz9RobustQueryMismatch
open HegemonCrypto.SmallWoodPowerBatching

noncomputable section

set_option maxHeartbeats 800000
set_option maxRecDepth 10000

abbrev Matrix (width : Nat) := CoefficientMatrix (F := Goldilocks) width 5
abbrev Opening := FullAdmissibleOpeningTuple

/-- Constraint families may be zero-padded to a common finite width. All fields
are fixed before the PIOP batching matrix, though they may depend on prior DECS. -/
structure Candidate (width : Nat) where
  nonlinear : Fin width → Goldilocks[X]
  linear : Fin width → Goldilocks[X]
  target : Fin width → Goldilocks
  nonlinearMask : Fin 5 → Goldilocks[X]
  linearMask : Fin 5 → Goldilocks[X]
  nonlinearDegree : ∀ check, (nonlinear check).natDegree ≤ 552
  linearDegree : ∀ check, (linear check).natDegree ≤ 132
  nonlinearMaskDegree : ∀ row, (nonlinearMask row).natDegree ≤ 488
  linearMaskDegree : ∀ row, (linearMask row).natDegree ≤ 132

def Candidate.system {width : Nat} (candidate : Candidate width) :
    Interactive.System (F := Goldilocks) (Node := Fin 64)
      (Nonlinear := Fin width) (Linear := Fin width) where
  nodes := Finset.univ
  point := packingPoint
  pointInjective := packingPoint_injective.injOn
  nonlinearIndices := Finset.univ
  nonlinearPolynomial := candidate.nonlinear
  linearIndices := Finset.univ
  linearPolynomial := candidate.linear
  linearTarget := candidate.target

def maskSum {width : Nat} (candidate : Candidate width) (row : Fin 5) : Goldilocks :=
  V8Smz9PiopOpeningRecovery.packingSum packingPoint (candidate.linearMask row)

def batchedTarget {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (row : Fin 5) : Goldilocks :=
  ∑ check, matrix row check * candidate.target check

/-- The adversarial response is selected after gamma, before the opening tuple.
Only the transmitted 132 nonconstant linear coefficients are free. -/
structure ClaimedTranscript where
  nonlinear : Fin 5 → Goldilocks[X]
  nonlinearDegree : ∀ row, (nonlinear row).natDegree ≤ 488
  linearHigh : Fin 5 → Fin 132 → Goldilocks

def claimedLinear {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (row : Fin 5) : Goldilocks[X] :=
  V8Smz9PiopOpeningRecovery.restoredLinearTranscript packingPoint
    (batchedTarget candidate matrix row) (response.linearHigh row)

/-- Reconstructing the omitted constant enforces the public target for every
adversarial choice of the high coefficients. -/
theorem claimed_linear_target {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (row : Fin 5) :
    V8Smz9PiopOpeningRecovery.packingSum packingPoint
      (claimedLinear candidate matrix response row) = batchedTarget candidate matrix row := by
  have nonzero : (64 : Goldilocks) ≠ 0 := by decide
  unfold claimedLinear V8Smz9PiopOpeningRecovery.restoredLinearTranscript
  rw [V8Smz9PiopOpeningRecovery.packing_sum_constant_add]
  unfold V8Smz9PiopOpeningRecovery.omittedLinearConstant
  rw [mul_div_cancel₀ _ nonzero]
  ring

theorem nonconstant_degree (high : Fin 132 → Goldilocks) :
    (V8Smz9PiopOpeningRecovery.nonconstantPolynomial high).natDegree ≤ 132 := by
  unfold V8Smz9PiopOpeningRecovery.nonconstantPolynomial
  apply natDegree_sum_le_of_forall_le
  intro index _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, zero_add, natDegree_X_pow]
  omega

theorem claimed_linear_degree {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (row : Fin 5) :
    (claimedLinear candidate matrix response row).natDegree ≤ 132 := by
  unfold claimedLinear V8Smz9PiopOpeningRecovery.restoredLinearTranscript
  exact natDegree_add_le_of_degree_le (by simp) (nonconstant_degree _)

def nonlinearDiscrepancy {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (row : Fin 5) : Goldilocks[X] :=
  smz9ConsistencyDiscrepancy (PiopExtraction.nonlinearBatch candidate.system (matrix row))
    (response.nonlinear row) (candidate.nonlinearMask row)

def linearDiscrepancy {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (row : Fin 5) : Goldilocks[X] :=
  claimedLinear candidate matrix response row - candidate.linearMask row -
    PiopExtraction.linearBatch candidate.system (matrix row)

theorem batch_degree {width bound : Nat} (polynomials : Fin width → Goldilocks[X])
    (coefficients : Fin width → Goldilocks)
    (bounded : ∀ check, (polynomials check).natDegree ≤ bound) :
    (Interactive.batch Finset.univ coefficients polynomials).natDegree ≤ bound := by
  unfold Interactive.batch
  apply natDegree_sum_le_of_forall_le
  intro check _
  refine natDegree_mul_le.trans ?_
  simpa using bounded check

theorem nonlinear_discrepancy_degree {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (row : Fin 5) :
    (nonlinearDiscrepancy candidate matrix response row).natDegree ≤ 552 := by
  apply smz9_consistency_discrepancy_degree_le
  · exact response.nonlinearDegree row
  · exact candidate.nonlinearMaskDegree row
  · exact batch_degree candidate.nonlinear (matrix row) candidate.nonlinearDegree

theorem linear_discrepancy_degree {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (row : Fin 5) :
    (linearDiscrepancy candidate matrix response row).natDegree ≤ 132 := by
  unfold linearDiscrepancy
  apply (natDegree_sub_le _ _).trans
  apply max_le
  · exact (natDegree_sub_le _ _).trans (max_le
      (claimed_linear_degree candidate matrix response row) (candidate.linearMaskDegree row))
  · exact batch_degree candidate.linear (matrix row) candidate.linearDegree

/-- Algebraic equations checked at all five rows and six openings. The nonlinear
equation is cross-multiplied by Z; full admissibility excludes its zero divisor. -/
def OpeningAccepts {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (opening : Opening) : Prop :=
  ∀ row coordinate,
    (nonlinearDiscrepancy candidate matrix response row).eval
        (baseOpeningPoints opening.1 coordinate) = 0 ∧
    (linearDiscrepancy candidate matrix response row).eval
        (baseOpeningPoints opening.1 coordinate) = 0

theorem linear_discrepancy_ne_zero {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (row : Fin 5)
    (failure : Interactive.nodeSum candidate.system.nodes candidate.system.point
      (PiopExtraction.linearBatch candidate.system (matrix row)) + maskSum candidate row ≠
        batchedTarget candidate matrix row) :
    linearDiscrepancy candidate matrix response row ≠ 0 := by
  intro zero
  have summed := congrArg (V8Smz9PiopOpeningRecovery.packingSum packingPoint) zero
  have target := claimed_linear_target candidate matrix response row
  simp only [linearDiscrepancy, V8Smz9PiopOpeningRecovery.packingSum, eval_sub,
    Finset.sum_sub_distrib, eval_zero, Finset.sum_const_zero] at summed
  unfold V8Smz9PiopOpeningRecovery.packingSum at target
  rw [target] at summed
  apply failure
  change (∑ lane : Fin 64, (PiopExtraction.linearBatch candidate.system (matrix row)).eval
    (packingPoint lane)) +
      (∑ lane : Fin 64, (candidate.linearMask row).eval (packingPoint lane)) = _
  linear_combination -summed

/-- Failure of the pre-opening affine equations selects a nonzero polynomial
before the six points. No post-opening polynomial selection is permitted. -/
theorem discrepancy_of_affine_failure {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript)
    (failure : ¬ PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix) :
    ∃ discrepancy : Goldilocks[X], discrepancy ≠ 0 ∧ discrepancy.natDegree ≤ 552 ∧
      ∀ opening, OpeningAccepts candidate matrix response opening →
        ∀ coordinate, discrepancy.eval (baseOpeningPoints opening.1 coordinate) = 0 := by
  classical
  unfold PiopExtraction.AffineBatchAccepts at failure
  push Not at failure
  obtain ⟨row, failure⟩ := failure
  by_cases nonlinear : ∀ node ∈ candidate.system.nodes,
      (PiopExtraction.nonlinearBatch candidate.system (matrix row)).eval
        (candidate.system.point node) = 0
  · refine ⟨linearDiscrepancy candidate matrix response row,
      linear_discrepancy_ne_zero candidate matrix response row (failure nonlinear),
      (linear_discrepancy_degree candidate matrix response row).trans (by decide), ?_⟩
    intro opening accepted coordinate
    exact (accepted row coordinate).2
  · push Not at nonlinear
    obtain ⟨node, membership, fails⟩ := nonlinear
    refine ⟨nonlinearDiscrepancy candidate matrix response row, ?_,
      nonlinear_discrepancy_degree candidate matrix response row, ?_⟩
    · exact PiopEvaluation.consistency_discrepancy_ne_zero_of_batch_failure
        (Finset.univ : Finset (Fin 64)) packingPoint _ _ _ node membership fails
    · intro opening accepted coordinate
      exact (accepted row coordinate).1

def openingEvent {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) : Finset Opening := by
  classical
  exact Finset.univ.filter (OpeningAccepts candidate matrix response)

def epsilon3 : Rat := (correctedEpsilon3.numerator : Rat) / correctedEpsilon3.denominator

/-- The actual fully admissible six-tuple counting bound applies separately for
every matrix-dependent response, provided its selection precedes the tuple. -/
theorem opening_probability_le_of_affine_failure {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript)
    (failure : ¬ PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix) :
    FiniteEvents.probability (openingEvent candidate matrix response) ≤ epsilon3 := by
  classical
  obtain ⟨discrepancy, nonzero, degree, contained⟩ :=
    discrepancy_of_affine_failure candidate matrix response failure
  have embedding : { opening // opening ∈ openingEvent candidate matrix response } ↪
      AdmissibleRootTuple discrepancy :=
    ⟨fun opening => ⟨opening.1, contained opening.1
        (by simpa only [openingEvent, Finset.mem_filter, Finset.mem_univ, true_and]
          using opening.2)⟩,
      fun left right same => Subtype.ext
        (congrArg (fun value : AdmissibleRootTuple discrepancy => value.val) same)⟩
  apply (show FiniteEvents.probability (openingEvent candidate matrix response) ≤
    uniformAdmissibleRootProbability discrepancy from ?_).trans
    (uniform_admissible_root_probability_le_corrected_epsilon3 nonzero degree)
  unfold FiniteEvents.probability uniformAdmissibleRootProbability
  apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
  exact_mod_cast (show (openingEvent candidate matrix response).card ≤
    Fintype.card (AdmissibleRootTuple discrepancy) by
      simpa only [Fintype.card_coe] using Fintype.card_le_of_embedding embedding)

/-- Exact probability in the independent uniform matrix/admissible-tuple product.
The response is any function of the matrix, never of the final tuple. -/
def soundnessProbability {width : Nat} (candidate : Candidate width)
    (response : Matrix width → ClaimedTranscript) : Rat :=
  FiniteEvents.jointProbability fun matrix => openingEvent candidate matrix (response matrix)

theorem opening_probability_le_one {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) :
    FiniteEvents.probability (openingEvent candidate matrix response) ≤ 1 := by
  unfold FiniteEvents.probability
  apply (div_le_one (by exact_mod_cast full_admissible_opening_tuple_card_positive)).mpr
  exact_mod_cast Finset.card_le_univ (openingEvent candidate matrix response)

/-- Five affine rows hide an invalid fixed candidate with probability at most
p^-5. Otherwise a response fixed before the six points incurs the corrected
degree-552 admissible-root bound. Candidate masks need not sum to zero. -/
theorem invalid_candidate_soundness_probability_le {width : Nat}
    (candidate : Candidate width) (response : Matrix width → ClaimedTranscript)
    (invalid : ¬ PiopExtraction.FullySatisfied candidate.system) :
    soundnessProbability candidate response ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 + epsilon3 := by
  classical
  have epsilonNonnegative : 0 ≤ epsilon3 := by unfold epsilon3; positivity
  have pointwise (matrix : Matrix width) :
      FiniteEvents.probability (openingEvent candidate matrix (response matrix)) ≤
        (if PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix
          then (1 : Rat) else 0) + epsilon3 := by
    by_cases affine : PiopExtraction.AffineBatchAccepts candidate.system
        (maskSum candidate) matrix
    · simpa only [if_pos affine] using
        (opening_probability_le_one candidate matrix (response matrix)).trans
          (le_add_of_nonneg_right epsilonNonnegative)
    · simpa only [if_neg affine, zero_add] using
        opening_probability_le_of_affine_failure candidate matrix (response matrix) affine
  have indicatorCount : (∑ matrix : Matrix width,
      if PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix
        then (1 : Rat) else 0) =
      (PiopExtraction.affineBatchFailureSet candidate.system (maskSum candidate)).card := by
    simp only [Finset.sum_boole, PiopExtraction.affineBatchFailureSet]
  have matrixPositive : (0 : Rat) < Fintype.card (Matrix width) := by
    exact_mod_cast Fintype.card_pos (α := Matrix width)
  have averaged : soundnessProbability candidate response ≤
      PiopExtraction.affineBatchFailureProbability candidate.system (maskSum candidate) +
        epsilon3 := by
    unfold soundnessProbability
    rw [FiniteEvents.joint_probability_eq_average]
    apply (div_le_iff₀ matrixPositive).mpr
    have sumBound := Finset.sum_le_sum
      (fun matrix (_ : matrix ∈ (Finset.univ : Finset (Matrix width))) => pointwise matrix)
    simp only [Finset.sum_add_distrib, Finset.sum_const, Finset.card_univ,
      nsmul_eq_mul, indicatorCount] at sumBound
    apply sumBound.trans_eq
    unfold PiopExtraction.affineBatchFailureProbability
    change _ = ((_ : Rat) / Fintype.card (Matrix width) + epsilon3) *
      Fintype.card (Matrix width)
    field_simp
  exact averaged.trans (add_le_add
    (PiopExtraction.unsatisfied_affine_batch_failure_probability_le
      candidate.system (maskSum candidate) invalid) (le_refl epsilon3))

/-- Explicit chronology: arbitrary prior DECS state may choose the candidate and
the response strategy, but each candidate is fixed before its fresh PIOP matrix. -/
theorem prior_decs_indexed_soundness {Prior : Type*} {width : Nat}
    (candidate : Prior → Candidate width)
    (response : Prior → Matrix width → ClaimedTranscript)
    (invalid : ∀ prior, ¬ PiopExtraction.FullySatisfied (candidate prior).system) :
    ∀ prior, soundnessProbability (candidate prior) (response prior) ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 + epsilon3 := by
  intro prior
  exact invalid_candidate_soundness_probability_le (candidate prior) (response prior) (invalid prior)

end
end HegemonCrypto.SmallWood.V8Smz9PiopSoundness

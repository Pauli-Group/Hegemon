import HegemonCrypto.SmallWoodV8Smz9PiopSoundness
import HegemonCrypto.SmallWoodDecsRestore
import HegemonCrypto.SmallWoodV8Smz9DecodedPolynomialSource

/-!
# Current six-opening PIOP restoration

The proof carries 483 nonlinear and 126 linear high coefficients per repetition.
The verifier reconstructs full polynomials, corrects the linear packing sum,
and hashes all 489 nonlinear and 132 nonconstant linear coefficients. This
module constructs those steps at the current geometry. Its source evaluation
trace is explicit; binding arbitrary proof scalars to a decoded PCS source and
binding the reconstructed transcript to a pre-opening oracle record are
separate obligations, not premises disguised as an acceptance theorem.
-/

namespace HegemonCrypto.SmallWood.V8Smz9PiopReconstruction

open Polynomial
open V8Smz9AdaptiveFiniteAccounting V8Smz9PiopSoundness
open V8Smz9PiopOpeningRecovery V8Smz9AdmissibleRootProbability
open DecsRestore
open scoped BigOperators Classical

noncomputable section
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
set_option backward.isDefEq.respectTransparency false

abbrev F := Goldilocks

def points (opening : Opening) : Fin 6 → F := baseOpeningPoints opening.1

def nonlinearHighPart (high : Fin 483 → F) : F[X] :=
  ∑ index : Fin 483, C (high index) * X ^ (6 + index.val)

def linearHighPart (high : Fin 126 → F) : F[X] :=
  ∑ index : Fin 126, C (high index) * X ^ (7 + index.val)

structure EvaluationTrace where
  nonlinear : Fin 5 → Fin 6 → F
  linear : Fin 5 → Fin 6 → F

structure ProofHighs where
  nonlinear : Fin 5 → Fin 483 → F
  linear : Fin 5 → Fin 126 → F

def restoredNonlinear (opening : Opening) (high : Fin 483 → F)
    (values : Fin 6 → F) : F[X] :=
  restorePolynomial Finset.univ (points opening) (nonlinearHighPart high) values

def augmentedValues (values : Fin 6 → F) : Option (Fin 6) → F
  | none => 0
  | some index => values index

def restoredLinearBase (opening : Opening) (high : Fin 126 → F)
    (values : Fin 6 → F) : F[X] :=
  restorePolynomial Finset.univ (LinearPiopExact.augmentedPoint (points opening))
    (linearHighPart high) (augmentedValues values)

def correctedLinear (opening : Opening) (base : F[X]) (target : F) : F[X] :=
  base + C ((target - packingSum packingPoint base) /
    V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (points opening)) *
      LinearPiopExact.normalizedRootPolynomial (points opening)

theorem nonlinear_high_degree (high : Fin 483 → F) :
    (nonlinearHighPart high).natDegree ≤ 488 := by
  unfold nonlinearHighPart
  apply natDegree_sum_le_of_forall_le
  intro index _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  omega

theorem linear_high_degree (high : Fin 126 → F) :
    (linearHighPart high).natDegree ≤ 132 := by
  unfold linearHighPart
  apply natDegree_sum_le_of_forall_le
  intro index _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  omega

theorem restored_nonlinear_degree (opening : Opening) (high : Fin 483 → F)
    (values : Fin 6 → F) : (restoredNonlinear opening high values).natDegree ≤ 488 := by
  apply restore_polynomial_natDegree_le
    (baseOpeningPoints_injective opening.1).injOn
  · decide
  · exact nonlinear_high_degree high

theorem restored_nonlinear_evaluation (opening : Opening) (high : Fin 483 → F)
    (values : Fin 6 → F) (index : Fin 6) :
    (restoredNonlinear opening high values).eval (points opening index) = values index :=
  restore_polynomial_eval (baseOpeningPoints_injective opening.1).injOn
    (Finset.mem_univ index)

theorem augmented_points_injective (opening : Opening) :
    Function.Injective (LinearPiopExact.augmentedPoint (points opening)) :=
  LinearPiopExact.augmentedPoint_injective
    (full_admissible_linear_piop_exact opening).pointsInjective
    (full_admissible_linear_piop_exact opening).pointsNonzero

theorem restored_linear_base_degree (opening : Opening) (high : Fin 126 → F)
    (values : Fin 6 → F) : (restoredLinearBase opening high values).natDegree ≤ 132 := by
  apply restore_polynomial_natDegree_le (augmented_points_injective opening).injOn
  · simp
  · exact linear_high_degree high

theorem restored_linear_base_evaluation (opening : Opening) (high : Fin 126 → F)
    (values : Fin 6 → F) (index : Fin 6) :
    (restoredLinearBase opening high values).eval (points opening index) = values index := by
  exact restore_polynomial_eval (augmented_points_injective opening).injOn
    (Finset.mem_univ (some index))

theorem correction_packing_sum (opening : Opening) :
    packingSum packingPoint (LinearPiopExact.normalizedRootPolynomial (points opening)) =
      V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (points opening) := by
  have same := V8Smz9ZeroKnowledge.linear_piop_generic_correction_factor_eq
    (F := Goldilocks) (points opening)
  convert same using 1
  rfl

theorem corrected_linear_target (opening : Opening) (base : F[X]) (target : F) :
    packingSum packingPoint (correctedLinear opening base target) = target := by
  have factorNonzero := (full_admissible_linear_piop_exact opening).correctionFactorNonzero
  change V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (points opening) ≠ 0 at factorNonzero
  unfold correctedLinear
  simp only [packingSum, eval_add, eval_mul, eval_C, Finset.sum_add_distrib,
    ← Finset.mul_sum]
  change packingSum packingPoint base +
    ((target - packingSum packingPoint base) /
      V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (points opening)) *
        packingSum packingPoint (LinearPiopExact.normalizedRootPolynomial (points opening)) = _
  rw [correction_packing_sum, div_mul_cancel₀ _ factorNonzero]
  ring

theorem corrected_linear_evaluation (opening : Opening) (base : F[X])
    (target : F) (index : Fin 6) :
    (correctedLinear opening base target).eval (points opening index) =
      base.eval (points opening index) := by
  simp only [correctedLinear, eval_add, eval_mul, eval_C,
    LinearPiopExact.normalizedRootPolynomial_eval_opening, mul_zero, add_zero]

theorem corrected_linear_degree (opening : Opening) (base : F[X])
    (target : F) (bounded : base.natDegree ≤ 132) :
    (correctedLinear opening base target).natDegree ≤ 132 := by
  apply natDegree_add_le_of_degree_le bounded
  refine natDegree_mul_le.trans ?_
  simpa only [natDegree_C, zero_add] using
    (LinearPiopExact.normalizedRootPolynomial_natDegree_le (points opening)).trans
      (by decide : 6 ≤ 132)

def reconstructedLinear (opening : Opening) (high : Fin 126 → F)
    (values : Fin 6 → F) (target : F) : F[X] :=
  correctedLinear opening (restoredLinearBase opening high values) target

def reconstructedTranscript (opening : Opening) (high : ProofHighs)
    (trace : EvaluationTrace) (target : Fin 5 → F) : ClaimedTranscript where
  nonlinear row := restoredNonlinear opening (high.nonlinear row) (trace.nonlinear row)
  nonlinearDegree _ := restored_nonlinear_degree opening _ _
  linearHigh row index :=
    (reconstructedLinear opening (high.linear row) (trace.linear row) (target row)).coeff
      (index.val + 1)

/-- The coefficient omitted from the hash is uniquely recovered from the
same public target enforced by the actual zero-point correction. -/
theorem reconstructed_linear_omitted_constant (opening : Opening) (high : Fin 126 → F)
    (values : Fin 6 → F) (target : F) :
    restoredLinearTranscript packingPoint target
        (fun index => (reconstructedLinear opening high values target).coeff (index.val + 1)) =
      reconstructedLinear opening high values target := by
  let polynomial := reconstructedLinear opening high values target
  have degreeBound : polynomial.natDegree ≤ 132 :=
    corrected_linear_degree opening _ target (restored_linear_base_degree opening high values)
  have expanded := polynomial_eq_constant_add_nonconstant polynomial degreeBound
  have targetSum : packingSum packingPoint polynomial = target :=
    corrected_linear_target opening _ target
  rw [expanded] at targetSum
  exact (restored_linear_transcript_exact packingPoint (by decide : (64 : F) ≠ 0)
    (polynomial.coeff 0) target (fun index => polynomial.coeff (index.val + 1)) targetSum).trans
      expanded.symm

theorem reconstructed_claimed_linear {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (opening : Opening) (high : ProofHighs)
    (trace : EvaluationTrace) (row : Fin 5) :
    claimedLinear candidate matrix
        (reconstructedTranscript opening high trace (batchedTarget candidate matrix)) row =
      reconstructedLinear opening (high.linear row) (trace.linear row)
        (batchedTarget candidate matrix row) :=
  reconstructed_linear_omitted_constant opening _ _ _

/-- These evaluations are calculated from the decoded polynomial candidate.
No relation satisfaction is assumed; a false candidate can still reconstruct
a transcript at selected points, which is why pre-opening hash binding matters. -/
def candidateEvaluationTrace {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (opening : Opening) : EvaluationTrace where
  nonlinear row index :=
    (PiopExtraction.nonlinearBatch candidate.system (matrix row)).eval (points opening index) /
        (packingVanishing packingPoint).eval (points opening index) +
      (candidate.nonlinearMask row).eval (points opening index)
  linear row index :=
    (PiopExtraction.linearBatch candidate.system (matrix row)).eval (points opening index) +
      (candidate.linearMask row).eval (points opening index)

theorem packing_divisor_nonzero (opening : Opening) (index : Fin 6) :
    (packingVanishing packingPoint).eval (points opening index) ≠ 0 :=
  packing_vanishing_eval_nonzero packingPoint (points opening index)
    ((full_admissible_linear_piop_exact opening).pointsOutsidePacking index)

/-- Executing restore and correction on the candidate's computed evaluation
trace yields the exact six-opening equations, with no caller-supplied check. -/
theorem reconstructed_candidate_opening_accepts {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (opening : Opening) (high : ProofHighs) :
    OpeningAccepts candidate matrix
      (reconstructedTranscript opening high (candidateEvaluationTrace candidate matrix opening)
        (batchedTarget candidate matrix)) opening := by
  intro row coordinate
  constructor
  · change (PiopEvaluation.consistencyDiscrepancy Finset.univ packingPoint
      (PiopExtraction.nonlinearBatch candidate.system (matrix row))
      (restoredNonlinear opening (high.nonlinear row)
        ((candidateEvaluationTrace candidate matrix opening).nonlinear row))
      (candidate.nonlinearMask row)).eval (points opening coordinate) = 0
    simp only [PiopEvaluation.consistencyDiscrepancy, eval_sub, eval_mul,
      restored_nonlinear_evaluation, candidateEvaluationTrace]
    change (packingVanishing packingPoint).eval (points opening coordinate) *
      (_ / (packingVanishing packingPoint).eval (points opening coordinate) + _ - _) - _ = 0
    rw [add_sub_cancel_right, mul_div_cancel₀ _ (packing_divisor_nonzero opening coordinate), sub_self]
  · unfold linearDiscrepancy
    rw [reconstructed_claimed_linear]
    simp only [eval_sub]
    change (reconstructedLinear opening (high.linear row)
        ((candidateEvaluationTrace candidate matrix opening).linear row)
        (batchedTarget candidate matrix row)).eval (points opening coordinate) -
      (candidate.linearMask row).eval (points opening coordinate) -
      (PiopExtraction.linearBatch candidate.system (matrix row)).eval
        (points opening coordinate) = 0
    simp only [reconstructedLinear, corrected_linear_evaluation,
      restored_linear_base_evaluation, candidateEvaluationTrace]
    ring

/-- Specialization has the actual generated nonlinear and retained CSR
candidate; arbitrary source polynomials remain allowed. -/
theorem reconstructed_decoded_source_opening_accepts
    (publicValues : List Nat) (source : V8Smz9DecodedPolynomialSource.SourcePolynomials)
    (matrix : Matrix (V8Smz9CurrentPublicContext.batchingWidth publicValues))
    (opening : Opening) (high : ProofHighs) :
    let candidate := V8Smz9DecodedPolynomialSource.sourcePiopCandidate publicValues source
    OpeningAccepts candidate matrix
      (reconstructedTranscript opening high (candidateEvaluationTrace candidate matrix opening)
        (batchedTarget candidate matrix)) opening :=
  reconstructed_candidate_opening_accepts _ _ _ _

end
end HegemonCrypto.SmallWood.V8Smz9PiopReconstruction

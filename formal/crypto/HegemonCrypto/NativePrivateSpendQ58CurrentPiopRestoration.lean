import HegemonCrypto.NativePrivateSpendQ58CurrentExecutableVerifier
import HegemonCrypto.NativePrivateSpendQ58CurrentDecodedRelation

/-! Raw current-opening reconstruction algebra. The current predicate alone
supplies the restoration and correction facts. Actual executable proof scalars
remain arbitrary. The final discrepancy identities expose their difference
from a decoded candidate; they do not assume or prove that difference zero.
SOURCE PROPOSAL: kernel pending, no native-acceptance or mass claim. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPiopRestoration

open Polynomial
open V8Smz9PiopOpeningRecovery
open V8Smz9PiopSoundness (Matrix ClaimedTranscript)
open NativePrivateSpendQ58CurrentPublicOpening (Relation packing)
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Opening points PiopFields evaluation target nonlinearPolynomial linearPolynomial reconstruct)
end E
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded candidate)
end D

def linearBase (opening : E.Opening) (high : Fin 126 → Goldilocks)
    (values : Fin 6 → Goldilocks) : Goldilocks[X] :=
  DecsRestore.restorePolynomial Finset.univ
    (LinearPiopExact.augmentedPoint (E.points opening))
    (V8Smz9PiopReconstruction.linearHighPart high)
    (V8Smz9PiopReconstruction.augmentedValues values)

def correctedLinear (opening : E.Opening) (base : Goldilocks[X])
    (target : Goldilocks) : Goldilocks[X] :=
  base + C ((target - packingSum packing base) /
    V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (E.points opening)) *
      LinearPiopExact.normalizedRootPolynomial (E.points opening)

theorem augmented_points_injective (opening : E.Opening) :
    Function.Injective (LinearPiopExact.augmentedPoint (E.points opening)) :=
  LinearPiopExact.augmentedPoint_injective opening.2.1 opening.2.2.1

theorem linear_base_degree (opening : E.Opening) (high : Fin 126 → Goldilocks)
    (values : Fin 6 → Goldilocks) : (linearBase opening high values).natDegree ≤ 132 := by
  apply DecsRestore.restore_polynomial_natDegree_le
    (augmented_points_injective opening).injOn
  · simp
  · exact V8Smz9PiopReconstruction.linear_high_degree high

theorem linear_base_evaluation (opening : E.Opening) (high : Fin 126 → Goldilocks)
    (values : Fin 6 → Goldilocks) (coordinate : Fin 6) :
    (linearBase opening high values).eval (E.points opening coordinate) = values coordinate :=
  DecsRestore.restore_polynomial_eval (augmented_points_injective opening).injOn
    (Finset.mem_univ (some coordinate))

theorem correction_packing_sum (opening : E.Opening) :
    packingSum packing (LinearPiopExact.normalizedRootPolynomial (E.points opening)) =
      V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (E.points opening) := by
  have same := V8Smz9ZeroKnowledge.linear_piop_generic_correction_factor_eq
    (F := Goldilocks) (E.points opening)
  convert same using 1
  rfl

theorem corrected_linear_target (opening : E.Opening) (base : Goldilocks[X])
    (target : Goldilocks) : packingSum packing (correctedLinear opening base target) = target := by
  have factorNonzero := opening.2.2.2.2
  change V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (E.points opening) ≠ 0 at factorNonzero
  unfold correctedLinear
  simp only [packingSum, eval_add, eval_mul, eval_C, Finset.sum_add_distrib,
    ← Finset.mul_sum]
  change packingSum packing base +
    ((target - packingSum packing base) /
      V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (E.points opening)) *
        packingSum packing (LinearPiopExact.normalizedRootPolynomial (E.points opening)) = _
  rw [correction_packing_sum, div_mul_cancel₀ _ factorNonzero]
  ring

theorem corrected_linear_evaluation (opening : E.Opening) (base : Goldilocks[X])
    (target : Goldilocks) (coordinate : Fin 6) :
    (correctedLinear opening base target).eval (E.points opening coordinate) =
      base.eval (E.points opening coordinate) := by
  simp only [correctedLinear, eval_add, eval_mul, eval_C,
    LinearPiopExact.normalizedRootPolynomial_eval_opening, mul_zero, add_zero]

theorem corrected_linear_degree (opening : E.Opening) (base : Goldilocks[X])
    (target : Goldilocks) (bounded : base.natDegree ≤ 132) :
    (correctedLinear opening base target).natDegree ≤ 132 := by
  apply natDegree_add_le_of_degree_le bounded
  refine natDegree_mul_le.trans ?_
  simpa only [natDegree_C, zero_add] using
    (LinearPiopExact.normalizedRootPolynomial_natDegree_le (E.points opening)).trans
      (by decide : 6 ≤ 132)

theorem linear_polynomial_degree (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594)
    (opening : E.Opening) (proof : E.PiopFields)
    (trace : V8Smz9PiopReconstruction.EvaluationTrace) (row : Fin 5) :
    (E.linearPolynomial relation matrix opening proof trace row).natDegree ≤ 132 :=
  corrected_linear_degree opening _ _ (linear_base_degree opening _ _)

theorem linear_polynomial_target (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594)
    (opening : E.Opening) (proof : E.PiopFields)
    (trace : V8Smz9PiopReconstruction.EvaluationTrace) (row : Fin 5) :
    packingSum packing (E.linearPolynomial relation matrix opening proof trace row) =
      E.target relation matrix row := corrected_linear_target opening _ _

theorem linear_polynomial_evaluation (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594)
    (opening : E.Opening) (proof : E.PiopFields)
    (trace : V8Smz9PiopReconstruction.EvaluationTrace) (row : Fin 5) (coordinate : Fin 6) :
    (E.linearPolynomial relation matrix opening proof trace row).eval
      (E.points opening coordinate) = trace.linear row coordinate := by
  change (correctedLinear opening (linearBase opening _ _) _).eval _ = _
  rw [corrected_linear_evaluation, linear_base_evaluation]

/-- The omitted constant follows from the executed public correction. -/
theorem linear_omitted_constant (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594)
    (opening : E.Opening) (proof : E.PiopFields)
    (trace : V8Smz9PiopReconstruction.EvaluationTrace) (row : Fin 5) :
    restoredLinearTranscript packing (E.target relation matrix row)
      (fun index => (E.linearPolynomial relation matrix opening proof trace row).coeff
        (index.val + 1)) = E.linearPolynomial relation matrix opening proof trace row := by
  let polynomial := E.linearPolynomial relation matrix opening proof trace row
  have degreeBound : polynomial.natDegree ≤ 132 := linear_polynomial_degree _ _ _ _ _ _
  have expanded := polynomial_eq_constant_add_nonconstant polynomial degreeBound
  have targetSum : packingSum packing polynomial = E.target relation matrix row :=
    linear_polynomial_target _ _ _ _ _ _
  rw [expanded] at targetSum
  exact (restored_linear_transcript_exact packing (by decide : (64 : Goldilocks) ≠ 0)
    (polynomial.coeff 0) (E.target relation matrix row)
    (fun index => polynomial.coeff (index.val + 1)) targetSum).trans expanded.symm

theorem packing_divisor_nonzero (opening : E.Opening) (coordinate : Fin 6) :
    (packingVanishing packing).eval (E.points opening coordinate) ≠ 0 :=
  packing_vanishing_eval_nonzero packing (E.points opening coordinate)
    (opening.2.2.2.1 coordinate)

/-- Exact polynomials whose coefficients the current executable serializes.
No decoded-row agreement or pre-opening response binding is included. -/
def response (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594) (opening : E.Opening)
    (proof : E.PiopFields) : ClaimedTranscript where
  nonlinear row := E.nonlinearPolynomial opening proof
    (E.evaluation relation matrix opening proof) row
  nonlinearDegree row :=
    (NativePrivateSpendQ58CurrentExecutableVerifier.nonlinear_polynomial_degree
      opening proof _ row).trans (by decide)
  linearHigh row index :=
    (E.linearPolynomial relation matrix opening proof
      (E.evaluation relation matrix opening proof) row).coeff (index.val + 1)

theorem claimed_linear_is_executable (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : D.Decoded)
    (matrix : Matrix 1344594) (opening : E.Opening) (proof : E.PiopFields) (row : Fin 5) :
    V8Smz9PiopSoundness.claimedLinear (D.candidate relation source) matrix
      (response relation matrix opening proof) row =
        E.linearPolynomial relation matrix opening proof
          (E.evaluation relation matrix opening proof) row :=
  linear_omitted_constant relation matrix opening proof _ row

theorem serialized_coefficients (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (matrix : Matrix 1344594)
    (opening : E.Opening) (proof : E.PiopFields) (hash : V8SmzaOracleParser.RawDigest)
    (pending : Bool) :
    (∀ row index, (E.reconstruct relation matrix opening proof hash pending).nonlinear row index =
      SmzaRp05ExecutableReconstruction.toWord
        (((response relation matrix opening proof).nonlinear row).coeff index.val)) ∧
    (∀ row index, (E.reconstruct relation matrix opening proof hash pending).linearHigh row index =
      SmzaRp05ExecutableReconstruction.toWord
        ((response relation matrix opening proof).linearHigh row index)) := by
  exact ⟨fun _ _ => rfl, fun _ _ => rfl⟩

private theorem nonlinear_discrepancy_eval_of_readback {width : Nat}
    (candidate : V8Smz9PiopSoundness.Candidate width) (matrix : Matrix width)
    (claimed : ClaimedTranscript) (row : Fin 5) (point value : Goldilocks)
    (readback : (claimed.nonlinear row).eval point = value) :
    (V8Smz9PiopSoundness.nonlinearDiscrepancy candidate matrix claimed row).eval point =
      (Interactive.packingVanishing Finset.univ
        V8Smz9AdaptiveFiniteAccounting.packingPoint).eval point *
        (value - (candidate.nonlinearMask row).eval point) -
      (PiopExtraction.nonlinearBatch candidate.system (matrix row)).eval point := by
  simp only [V8Smz9PiopSoundness.nonlinearDiscrepancy,
    V8Smz9AdmissibleRootProbability.smz9ConsistencyDiscrepancy,
    PiopEvaluation.consistencyDiscrepancy, eval_sub, eval_mul, readback]

private theorem linear_discrepancy_eval_of_readback {width : Nat}
    (candidate : V8Smz9PiopSoundness.Candidate width) (matrix : Matrix width)
    (claimed : ClaimedTranscript) (row : Fin 5) (point value : Goldilocks)
    (readback : (V8Smz9PiopSoundness.claimedLinear candidate matrix claimed row).eval point =
      value) :
    (V8Smz9PiopSoundness.linearDiscrepancy candidate matrix claimed row).eval point =
      value - (candidate.linearMask row).eval point -
        (PiopExtraction.linearBatch candidate.system (matrix row)).eval point := by
  simp only [V8Smz9PiopSoundness.linearDiscrepancy, eval_sub, readback]

/-- Residual formulas, not equality certificates. These expose the remaining
PCS opened-witness and two-mask scalar joins without assuming their conclusion. -/
theorem nonlinear_discrepancy_evaluation (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : D.Decoded)
    (matrix : Matrix 1344594) (opening : E.Opening) (proof : E.PiopFields)
    (row : Fin 5) (coordinate : Fin 6) :
    (V8Smz9PiopSoundness.nonlinearDiscrepancy (D.candidate relation source) matrix
      (response relation matrix opening proof) row).eval (E.points opening coordinate) =
    (Interactive.packingVanishing Finset.univ
      V8Smz9AdaptiveFiniteAccounting.packingPoint).eval (E.points opening coordinate) *
      ((E.evaluation relation matrix opening proof).nonlinear row coordinate -
        ((D.candidate relation source).nonlinearMask row).eval (E.points opening coordinate)) -
      (PiopExtraction.nonlinearBatch (D.candidate relation source).system (matrix row)).eval
        (E.points opening coordinate) := by
  have responsePolynomial :
      (response relation matrix opening proof).nonlinear row =
        E.nonlinearPolynomial opening proof (E.evaluation relation matrix opening proof) row :=
    rfl
  have readback :=
    (congrArg (fun polynomial : Goldilocks[X] =>
      polynomial.eval (E.points opening coordinate)) responsePolynomial).trans
      (NativePrivateSpendQ58CurrentExecutableVerifier.nonlinear_polynomial_evaluation
        opening proof (E.evaluation relation matrix opening proof) row coordinate)
  exact nonlinear_discrepancy_eval_of_readback (D.candidate relation source) matrix
    (response relation matrix opening proof) row (E.points opening coordinate)
    ((E.evaluation relation matrix opening proof).nonlinear row coordinate) readback

theorem linear_discrepancy_evaluation (relation : HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : D.Decoded)
    (matrix : Matrix 1344594) (opening : E.Opening) (proof : E.PiopFields)
    (row : Fin 5) (coordinate : Fin 6) :
    (V8Smz9PiopSoundness.linearDiscrepancy (D.candidate relation source) matrix
      (response relation matrix opening proof) row).eval (E.points opening coordinate) =
    (E.evaluation relation matrix opening proof).linear row coordinate -
      ((D.candidate relation source).linearMask row).eval (E.points opening coordinate) -
      (PiopExtraction.linearBatch (D.candidate relation source).system (matrix row)).eval
        (E.points opening coordinate) := by
  have responsePolynomial :=
    claimed_linear_is_executable relation source matrix opening proof row
  have readback :=
    (congrArg (fun polynomial : Goldilocks[X] =>
      polynomial.eval (E.points opening coordinate)) responsePolynomial).trans
      (linear_polynomial_evaluation relation matrix opening proof
        (E.evaluation relation matrix opening proof) row coordinate)
  exact linear_discrepancy_eval_of_readback (D.candidate relation source) matrix
    (response relation matrix opening proof) row (E.points opening coordinate)
    ((E.evaluation relation matrix opening proof).linear row coordinate) readback

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPiopRestoration

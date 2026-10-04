import HegemonCrypto.SmallWoodDecsRestore
import HegemonCrypto.SmallWoodNativePiopRefinement

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact native PIOP reconstruction

This module models the successful return path of `piop_recompute_transcript`.  Its inputs are the
typed high-coefficient matrices decoded from the proof and the exact opened-row evaluations used
by the Rust verifier.  A successful result derives the nonlinear opening checks, the sparse-linear
opening checks, and the public linear-target equation; none of those facts is supplied separately.

The only exceptional branch is the executable verifier's fail-closed zero correction-factor check.
-/

namespace HegemonCrypto.SmallWood.NativePiopReconstruction

open Polynomial
open HegemonCrypto.SmallWood.DecsRestore
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWood.NativePiopRefinement
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.PiopOpeningSampling
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.ProductionPolynomials
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript

noncomputable section

/-- Exact number of nonlinear coefficients transmitted from degree five through degree 480. -/
abbrev NativeNonlinearHighCount :=
  nonlinearMaskPolynomialDegree + 1 - openedEvaluations

/-- Exact number of sparse-linear coefficients transmitted from degree six through degree 131. -/
abbrev NativeLinearHighCount :=
  linearMaskPolynomialDegree + 1 - (openedEvaluations + 1)

abbrev NativeNonlinearHighCoefficients :=
  Matrix rho NativeNonlinearHighCount

abbrev NativeLinearHighCoefficients :=
  Matrix rho NativeLinearHighCount

/-- Place a native coefficient vector at its real polynomial degrees. -/
def shiftedFieldWordPolynomial
    (offset count : Nat)
    (coefficients : Fin count -> FieldWord) : Goldilocks[X] :=
  ∑ coefficient : Fin count,
    C (wordToGoldilocks (coefficients coefficient)) *
      X ^ (offset + coefficient.val)

def nativeNonlinearHighPart
    (high : NativeNonlinearHighCoefficients)
    (repetition : Fin rho) : Goldilocks[X] :=
  shiftedFieldWordPolynomial openedEvaluations NativeNonlinearHighCount
    (high repetition)

def nativeLinearHighPart
    (high : NativeLinearHighCoefficients)
    (repetition : Fin rho) : Goldilocks[X] :=
  shiftedFieldWordPolynomial (openedEvaluations + 1) NativeLinearHighCount
    (high repetition)

theorem native_nonlinear_high_part_degree_le
    (high : NativeNonlinearHighCoefficients)
    (repetition : Fin rho) :
    (nativeNonlinearHighPart high repetition).natDegree ≤
      nonlinearMaskPolynomialDegree := by
  unfold nativeNonlinearHighPart shiftedFieldWordPolynomial
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  have coefficientBound := coefficient.isLt
  change coefficient.val < 476 at coefficientBound
  change 5 + coefficient.val ≤ 480
  omega

theorem native_linear_high_part_degree_le
    (high : NativeLinearHighCoefficients)
    (repetition : Fin rho) :
    (nativeLinearHighPart high repetition).natDegree ≤
      linearMaskPolynomialDegree := by
  unfold nativeLinearHighPart shiftedFieldWordPolynomial
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  have coefficientBound := coefficient.isLt
  change coefficient.val < 126 at coefficientBound
  change 6 + coefficient.val ≤ 131
  omega

theorem native_opening_point_injective
    (opening : PiopOpeningChallenge) :
    Function.Injective (nativeOpeningPoint opening) :=
  fieldWordGoldilocksEquiv.injective.comp opening.property.1

private def packingFieldWord
    (lane : Nat)
    (laneBound : lane < packingFactor) : FieldWord :=
  ⟨lane, laneBound.trans (by decide)⟩

private theorem packing_field_word_mem
    (lane : Nat)
    (laneBound : lane < packingFactor) :
    packingFieldWord lane laneBound ∈ packingPoints := by
  simp [packingFieldWord, packingPoints, laneBound]

theorem native_opening_point_ne_packing_node
    (opening : PiopOpeningChallenge)
    (index : Fin openedEvaluations)
    (lane : Nat)
    (laneBound : lane < packingFactor) :
    nativeOpeningPoint opening index ≠ packingNodePoint lane := by
  intro equal
  have wordEqual :
      opening.val index = packingFieldWord lane laneBound := by
    apply fieldWordGoldilocksEquiv.injective
    calc
      wordToGoldilocks (opening.val index) =
          packingNodePoint lane := equal
      _ = wordToGoldilocks (packingFieldWord lane laneBound) := by
        rfl
  exact opening.property.2 index
    (wordEqual ▸ packing_field_word_mem lane laneBound)

theorem native_opening_point_ne_zero
    (opening : PiopOpeningChallenge)
    (index : Fin openedEvaluations) :
    nativeOpeningPoint opening index ≠ 0 := by
  change nativeOpeningPoint opening index ≠ toGoldilocks 0
  exact native_opening_point_ne_packing_node opening index 0 (by decide)

theorem packing_vanishing_eval_native_opening_ne_zero
    (opening : PiopOpeningChallenge)
    (index : Fin openedEvaluations) :
    (packingVanishing
        (Finset.range packingFactor)
        packingNodePoint).eval (nativeOpeningPoint opening index) ≠ 0 := by
  classical
  unfold packingVanishing
  rw [eval_prod]
  apply Finset.prod_ne_zero_iff.mpr
  intro lane laneMembership
  simp only [eval_sub, eval_X, eval_C, sub_ne_zero]
  exact native_opening_point_ne_packing_node opening index lane
    (Finset.mem_range.mp laneMembership)

/-- Nonlinear values computed by the native verifier before polynomial restoration. -/
def nativeNonlinearOpeningEvaluation
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (repetition : Fin rho)
    (index : Fin openedEvaluations) : Goldilocks :=
  (productionNonlinearBatch statement oracle challenge repetition).eval
      (nativeOpeningPoint opening index) /
    (packingVanishing
      (Finset.range statement.lppcPackingFactor)
      packingNodePoint).eval (nativeOpeningPoint opening index) +
    (nonlinearMaskPolynomial oracle repetition).eval
      (nativeOpeningPoint opening index)

/-- Exact polynomial returned by native nonlinear `poly_restore`. -/
def nativeRestoredNonlinearPolynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeNonlinearHighCoefficients)
    (repetition : Fin rho) : Goldilocks[X] :=
  restorePolynomial
    (Finset.univ : Finset (Fin openedEvaluations))
    (nativeOpeningPoint opening)
    (nativeNonlinearHighPart high repetition)
    (nativeNonlinearOpeningEvaluation
      statement oracle challenge opening repetition)

theorem native_restored_nonlinear_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeNonlinearHighCoefficients)
    (repetition : Fin rho) :
    (nativeRestoredNonlinearPolynomial
      statement oracle challenge opening high repetition).natDegree ≤
        nonlinearMaskPolynomialDegree := by
  apply restore_polynomial_natDegree_le
  · exact (native_opening_point_injective opening).injOn
  · change 5 ≤ 481
    decide
  · exact native_nonlinear_high_part_degree_le high repetition

theorem native_restored_nonlinear_eval
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeNonlinearHighCoefficients)
    (repetition : Fin rho)
    (index : Fin openedEvaluations) :
    (nativeRestoredNonlinearPolynomial
        statement oracle challenge opening high repetition).eval
        (nativeOpeningPoint opening index) =
      nativeNonlinearOpeningEvaluation
        statement oracle challenge opening repetition index := by
  apply restore_polynomial_eval
  · exact (native_opening_point_injective opening).injOn
  · simp

/-- Six restoration nodes: the five opening points followed by the native omitted zero node. -/
abbrev NativeLinearRestoreIndex := Option (Fin openedEvaluations)

def nativeLinearRestorePoint
    (opening : PiopOpeningChallenge) :
    NativeLinearRestoreIndex -> Goldilocks
  | none => 0
  | some index => nativeOpeningPoint opening index

def nativeLinearRestoreEvaluation
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (repetition : Fin rho) :
    NativeLinearRestoreIndex -> Goldilocks
  | none => 0
  | some index =>
      (productionLinearBatch statement oracle challenge repetition).eval
          (nativeOpeningPoint opening index) +
        (linearMaskPolynomial oracle repetition).eval
          (nativeOpeningPoint opening index)

theorem native_linear_restore_point_injective
    (opening : PiopOpeningChallenge) :
    Function.Injective (nativeLinearRestorePoint opening) := by
  intro left right equal
  cases left with
  | none =>
      cases right with
      | none => rfl
      | some right =>
          exfalso
          exact native_opening_point_ne_zero opening right equal.symm
  | some left =>
      cases right with
      | none =>
          exfalso
          exact native_opening_point_ne_zero opening left equal
      | some right =>
          congr
          exact native_opening_point_injective opening equal

/-- Exact sparse-linear polynomial before the public-target correction. -/
def nativeRestoredLinearBase
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (repetition : Fin rho) : Goldilocks[X] :=
  restorePolynomial
    (Finset.univ : Finset NativeLinearRestoreIndex)
    (nativeLinearRestorePoint opening)
    (nativeLinearHighPart high repetition)
    (nativeLinearRestoreEvaluation
      statement oracle challenge opening repetition)

theorem native_restored_linear_base_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (repetition : Fin rho) :
    (nativeRestoredLinearBase
      statement oracle challenge opening high repetition).natDegree ≤
        linearMaskPolynomialDegree := by
  apply restore_polynomial_natDegree_le
  · exact (native_linear_restore_point_injective opening).injOn
  · rw [Finset.card_univ, Fintype.card_option, Fintype.card_fin,
      active_geometry.2.1, active_geometry.2.2.2.2.1]
    decide
  · exact native_linear_high_part_degree_le high repetition

theorem native_restored_linear_base_eval
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (repetition : Fin rho)
    (index : Fin openedEvaluations) :
    (nativeRestoredLinearBase
        statement oracle challenge opening high repetition).eval
        (nativeOpeningPoint opening index) =
      (productionLinearBatch statement oracle challenge repetition).eval
          (nativeOpeningPoint opening index) +
        (linearMaskPolynomial oracle repetition).eval
          (nativeOpeningPoint opening index) := by
  unfold nativeRestoredLinearBase
  simpa [nativeLinearRestorePoint, nativeLinearRestoreEvaluation] using
    (restore_polynomial_eval
      (support := (Finset.univ : Finset NativeLinearRestoreIndex))
      (point := nativeLinearRestorePoint opening)
      (highPart := nativeLinearHighPart high repetition)
      (evaluations :=
        nativeLinearRestoreEvaluation
          statement oracle challenge opening repetition)
      (native_linear_restore_point_injective opening).injOn
      (Finset.mem_univ (some index)))

theorem native_linear_correction_polynomial_eval_opening
    (opening : PiopOpeningChallenge)
    (index : Fin openedEvaluations) :
    (nativeLinearCorrectionPolynomial opening).eval
        (nativeOpeningPoint opening index) = 0 := by
  classical
  unfold nativeLinearCorrectionPolynomial
  rw [eval_mul, eval_prod]
  have zeroFactor :
      ∏ candidate : Fin openedEvaluations,
          ((X - C (nativeOpeningPoint opening candidate)) :
            Goldilocks[X]).eval (nativeOpeningPoint opening index) = 0 := by
    apply Finset.prod_eq_zero (Finset.mem_univ index)
    simp
  rw [zeroFactor, zero_mul]

def nativeRestoredLinearPolynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (repetition : Fin rho) : Goldilocks[X] :=
  nativeCorrectedLinearPolynomial opening
    (nativeRestoredLinearBase
      statement oracle challenge opening high repetition)
    (productionLinearBatchTarget statement challenge repetition)

theorem native_linear_correction_polynomial_degree_le
    (opening : PiopOpeningChallenge) :
    (nativeLinearCorrectionPolynomial opening).natDegree ≤ openedEvaluations := by
  unfold nativeLinearCorrectionPolynomial
  calc
    ((∏ index : Fin openedEvaluations,
        (X - C (nativeOpeningPoint opening index))) *
        C ((∏ index : Fin openedEvaluations,
          -nativeOpeningPoint opening index)⁻¹)).natDegree ≤
        (∏ index : Fin openedEvaluations,
          (X - C (nativeOpeningPoint opening index))).natDegree +
          (C ((∏ index : Fin openedEvaluations,
            -nativeOpeningPoint opening index)⁻¹)).natDegree :=
      natDegree_mul_le
    _ ≤ openedEvaluations + 0 := by
      apply Nat.add_le_add
      · calc
          (∏ index : Fin openedEvaluations,
              (X - C (nativeOpeningPoint opening index))).natDegree ≤
              ∑ index : Fin openedEvaluations,
                (X - C (nativeOpeningPoint opening index)).natDegree := by
                  exact natDegree_prod_le Finset.univ _
          _ = openedEvaluations := by simp
      · simp
    _ = openedEvaluations := by omega

theorem native_restored_linear_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (repetition : Fin rho) :
    (nativeRestoredLinearPolynomial
      statement oracle challenge opening high repetition).natDegree ≤
        linearMaskPolynomialDegree := by
  unfold nativeRestoredLinearPolynomial nativeCorrectedLinearPolynomial
  refine (natDegree_add_le _ _).trans (max_le ?_ ?_)
  · exact native_restored_linear_base_degree_le
      statement oracle challenge opening high repetition
  · refine (natDegree_mul_le).trans ?_
    simp only [natDegree_C, zero_add]
    exact (native_linear_correction_polynomial_degree_le opening).trans (by decide)

theorem native_restored_linear_eval
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (repetition : Fin rho)
    (index : Fin openedEvaluations) :
    (nativeRestoredLinearPolynomial
        statement oracle challenge opening high repetition).eval
        (nativeOpeningPoint opening index) =
      (productionLinearBatch statement oracle challenge repetition).eval
          (nativeOpeningPoint opening index) +
        (linearMaskPolynomial oracle repetition).eval
          (nativeOpeningPoint opening index) := by
  rw [nativeRestoredLinearPolynomial, nativeCorrectedLinearPolynomial,
    eval_add, eval_mul, eval_C,
    native_linear_correction_polynomial_eval_opening, mul_zero, add_zero]
  exact native_restored_linear_base_eval
    statement oracle challenge opening high repetition index

/--
The two matrices actually consumed by native `poly_restore`: quotient-plus-mask values and
linear-batch-plus-mask values.  They are proof-derived data, not oracle-derived values.
-/
structure NativePiopEvaluationTrace where
  nonlinear : Matrix rho openedEvaluations
  linear : Matrix rho openedEvaluations

def traceRestoredNonlinearPolynomial
    (opening : PiopOpeningChallenge)
    (high : NativeNonlinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (repetition : Fin rho) : Goldilocks[X] :=
  restorePolynomial
    (Finset.univ : Finset (Fin openedEvaluations))
    (nativeOpeningPoint opening)
    (nativeNonlinearHighPart high repetition)
    (trace.nonlinear repetition)

theorem trace_restored_nonlinear_degree_le
    (opening : PiopOpeningChallenge)
    (high : NativeNonlinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (repetition : Fin rho) :
    (traceRestoredNonlinearPolynomial opening high trace repetition).natDegree ≤
      nonlinearMaskPolynomialDegree := by
  apply restore_polynomial_natDegree_le
  · exact (native_opening_point_injective opening).injOn
  · change 5 ≤ 481
    decide
  · exact native_nonlinear_high_part_degree_le high repetition

def traceLinearRestoreEvaluation
    (trace : NativePiopEvaluationTrace)
    (repetition : Fin rho) :
    NativeLinearRestoreIndex -> Goldilocks
  | none => 0
  | some index => trace.linear repetition index

def traceRestoredLinearBase
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (repetition : Fin rho) : Goldilocks[X] :=
  restorePolynomial
    (Finset.univ : Finset NativeLinearRestoreIndex)
    (nativeLinearRestorePoint opening)
    (nativeLinearHighPart high repetition)
    (traceLinearRestoreEvaluation trace repetition)

theorem trace_restored_linear_base_degree_le
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (repetition : Fin rho) :
    (traceRestoredLinearBase opening high trace repetition).natDegree ≤
      linearMaskPolynomialDegree := by
  apply restore_polynomial_natDegree_le
  · exact (native_linear_restore_point_injective opening).injOn
  · rw [Finset.card_univ, Fintype.card_option, Fintype.card_fin,
      active_geometry.2.1, active_geometry.2.2.2.2.1]
    decide
  · exact native_linear_high_part_degree_le high repetition

def traceRestoredLinearPolynomial
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (repetition : Fin rho) : Goldilocks[X] :=
  nativeCorrectedLinearPolynomial opening
    (traceRestoredLinearBase opening high trace repetition)
    (productionLinearBatchTarget statement challenge repetition)

theorem trace_restored_linear_degree_le
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (high : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (repetition : Fin rho) :
    (traceRestoredLinearPolynomial
      statement challenge opening high trace repetition).natDegree ≤
        linearMaskPolynomialDegree := by
  unfold traceRestoredLinearPolynomial nativeCorrectedLinearPolynomial
  refine (natDegree_add_le _ _).trans (max_le ?_ ?_)
  · exact trace_restored_linear_base_degree_le opening high trace repetition
  · refine natDegree_mul_le.trans ?_
    simp only [natDegree_C, zero_add]
    exact (native_linear_correction_polynomial_degree_le opening).trans (by decide)

/-- Exact successful-return model over the proof-derived PIOP evaluation trace. -/
def reconstructNativePiopMessageFromTrace
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace) :
    Option PiopPolynomialMessage :=
  if nativeLinearCorrectionFactor opening = 0 then
    none
  else
    some <| piopPolynomialMessageOf
      (traceRestoredNonlinearPolynomial opening nonlinearHigh trace)
      (traceRestoredLinearPolynomial
        statement challenge opening linearHigh trace)

theorem reconstruct_native_piop_message_from_trace_factor_nonzero
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (message : PiopPolynomialMessage)
    (reconstructed :
      reconstructNativePiopMessageFromTrace
        statement challenge opening nonlinearHigh linearHigh trace =
          some message) :
    nativeLinearCorrectionFactor opening ≠ 0 := by
  intro factorZero
  simp [reconstructNativePiopMessageFromTrace, factorZero] at reconstructed

theorem reconstruct_native_piop_message_from_trace_eq
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (message : PiopPolynomialMessage)
    (reconstructed :
      reconstructNativePiopMessageFromTrace
        statement challenge opening nonlinearHigh linearHigh trace =
          some message) :
    message =
      piopPolynomialMessageOf
        (traceRestoredNonlinearPolynomial opening nonlinearHigh trace)
        (traceRestoredLinearPolynomial
          statement challenge opening linearHigh trace) := by
  have factorNonzero :=
    reconstruct_native_piop_message_from_trace_factor_nonzero
      statement challenge opening nonlinearHigh linearHigh trace message reconstructed
  simpa [reconstructNativePiopMessageFromTrace, factorNonzero] using reconstructed.symm

/-- The native correction forces the public target independently of PCS agreement. -/
theorem reconstruct_native_piop_message_from_trace_implies_target
    (statement : Statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (message : PiopPolynomialMessage)
    (reconstructed :
      reconstructNativePiopMessageFromTrace
        statement challenge opening nonlinearHigh linearHigh trace =
          some message) :
    ClaimedLinearTarget statement challenge message := by
  have factorNonzero :=
    reconstruct_native_piop_message_from_trace_factor_nonzero
      statement challenge opening nonlinearHigh linearHigh trace message reconstructed
  have messageEquation :=
    reconstruct_native_piop_message_from_trace_eq
      statement challenge opening nonlinearHigh linearHigh trace message reconstructed
  subst message
  intro repetition
  rw [claimed_linear_polynomial_piopPolynomialMessageOf
    _ _
    (trace_restored_linear_degree_le
      statement challenge opening linearHigh trace)]
  exact native_corrected_linear_polynomial_node_sum
    opening
    (traceRestoredLinearBase opening linearHigh trace repetition)
    (productionLinearBatchTarget statement challenge repetition)
    factorNonzero

/-- Oracle-derived values expected once the PCS opening equations identify the supplied rows. -/
def expectedNativePiopEvaluationTrace
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge) :
    NativePiopEvaluationTrace where
  nonlinear repetition index :=
    nativeNonlinearOpeningEvaluation
      statement oracle challenge opening repetition index
  linear repetition index :=
    (productionLinearBatch statement oracle challenge repetition).eval
        (nativeOpeningPoint opening index) +
      (linearMaskPolynomial oracle repetition).eval
        (nativeOpeningPoint opening index)

/-- Exact successful-return model of `piop_recompute_transcript`. -/
def reconstructNativePiopMessage
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients) :
    Option PiopPolynomialMessage :=
  if nativeLinearCorrectionFactor opening = 0 then
    none
  else
    some <| piopPolynomialMessageOf
      (nativeRestoredNonlinearPolynomial
        statement oracle challenge opening nonlinearHigh)
      (nativeRestoredLinearPolynomial
        statement oracle challenge opening linearHigh)

theorem reconstruct_native_piop_message_factor_nonzero
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients)
    (message : PiopPolynomialMessage)
    (reconstructed :
      reconstructNativePiopMessage
        statement oracle challenge opening nonlinearHigh linearHigh =
          some message) :
    nativeLinearCorrectionFactor opening ≠ 0 := by
  intro factorZero
  simp [reconstructNativePiopMessage, factorZero] at reconstructed

theorem reconstruct_native_piop_message_eq
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients)
    (message : PiopPolynomialMessage)
    (reconstructed :
      reconstructNativePiopMessage
        statement oracle challenge opening nonlinearHigh linearHigh =
          some message) :
    message =
      piopPolynomialMessageOf
        (nativeRestoredNonlinearPolynomial
          statement oracle challenge opening nonlinearHigh)
        (nativeRestoredLinearPolynomial
          statement oracle challenge opening linearHigh) := by
  have factorNonzero :=
    reconstruct_native_piop_message_factor_nonzero
      statement oracle challenge opening nonlinearHigh linearHigh message reconstructed
  simpa [reconstructNativePiopMessage, factorNonzero] using reconstructed.symm

/-- Successful native reconstruction forces every PIOP equation consumed by the extractor. -/
theorem reconstruct_native_piop_message_implies_checks
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients)
    (message : PiopPolynomialMessage)
    (reconstructed :
      reconstructNativePiopMessage
        statement oracle challenge opening nonlinearHigh linearHigh =
          some message) :
    ClaimedLinearTarget statement challenge message ∧
      NativePiopOpeningChecks statement oracle challenge message opening := by
  have factorNonzero :=
    reconstruct_native_piop_message_factor_nonzero
      statement oracle challenge opening nonlinearHigh linearHigh message reconstructed
  have messageEquation :=
    reconstruct_native_piop_message_eq
      statement oracle challenge opening nonlinearHigh linearHigh message reconstructed
  subst message
  constructor
  · intro repetition
    rw [claimed_linear_polynomial_piopPolynomialMessageOf
      _ _
      (native_restored_linear_degree_le
        statement oracle challenge opening linearHigh)]
    exact native_corrected_linear_polynomial_node_sum
      opening
      (nativeRestoredLinearBase
        statement oracle challenge opening linearHigh repetition)
      (productionLinearBatchTarget statement challenge repetition)
      factorNonzero
  constructor
  · intro repetition index
    rw [claimed_nonlinear_polynomial_piopPolynomialMessageOf
      _ _
      (native_restored_nonlinear_degree_le
        statement oracle challenge opening nonlinearHigh)]
    change
      (packingVanishing
          (Finset.range statement.lppcPackingFactor)
          packingNodePoint).eval (nativeOpeningPoint opening index) *
          ((nativeRestoredNonlinearPolynomial
              statement oracle challenge opening nonlinearHigh repetition).eval
              (nativeOpeningPoint opening index) -
            (nonlinearMaskPolynomial oracle repetition).eval
              (nativeOpeningPoint opening index)) =
        (productionNonlinearBatch
          statement oracle challenge repetition).eval
            (nativeOpeningPoint opening index)
    rw [native_restored_nonlinear_eval]
    have denominatorNonzero :
        (packingVanishing
          (Finset.range statement.lppcPackingFactor)
          packingNodePoint).eval (nativeOpeningPoint opening index) ≠ 0 := by
      simpa [active.2.1] using
        packing_vanishing_eval_native_opening_ne_zero opening index
    unfold nativeNonlinearOpeningEvaluation
    rw [add_sub_cancel_right, mul_div_cancel₀ _ denominatorNonzero]
  · intro repetition index
    rw [claimed_linear_polynomial_piopPolynomialMessageOf
      _ _
      (native_restored_linear_degree_le
        statement oracle challenge opening linearHigh)]
    exact native_restored_linear_eval
      statement oracle challenge opening linearHigh repetition index

theorem reconstruct_from_expected_trace_eq
    (statement : Statement)
    (oracle : CommittedOracle)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients) :
    reconstructNativePiopMessageFromTrace
        statement challenge opening nonlinearHigh linearHigh
          (expectedNativePiopEvaluationTrace statement oracle challenge opening) =
      reconstructNativePiopMessage
        statement oracle challenge opening nonlinearHigh linearHigh := by
  rfl

theorem reconstruct_native_piop_message_from_trace_implies_checks
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (opening : PiopOpeningChallenge)
    (nonlinearHigh : NativeNonlinearHighCoefficients)
    (linearHigh : NativeLinearHighCoefficients)
    (trace : NativePiopEvaluationTrace)
    (message : PiopPolynomialMessage)
    (traceMatches :
      trace = expectedNativePiopEvaluationTrace
        statement oracle challenge opening)
    (reconstructed :
      reconstructNativePiopMessageFromTrace
        statement challenge opening nonlinearHigh linearHigh trace =
          some message) :
    NativePiopOpeningChecks statement oracle challenge message opening := by
  subst trace
  rw [reconstruct_from_expected_trace_eq] at reconstructed
  exact
    (reconstruct_native_piop_message_implies_checks
      statement oracle active challenge opening nonlinearHigh linearHigh
        message reconstructed).2

end

end HegemonCrypto.SmallWood.NativePiopReconstruction

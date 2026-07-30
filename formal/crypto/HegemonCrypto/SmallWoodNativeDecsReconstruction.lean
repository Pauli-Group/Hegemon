import HegemonCrypto.SmallWoodDecsRestore
import HegemonCrypto.SmallWoodOpenedRowRefinement
import HegemonCrypto.SmallWoodProductionAccumulatedExtraction

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact native DECS response reconstruction

The production verifier receives 107 high coefficients for each of the 33 DECS response
polynomials. It reconstructs the missing 20 low coefficients from the 20 authenticated row
evaluations selected by the fixed sampler. This module models that exact `poly_restore` call and
proves that the reconstructed message satisfies every DECS row equation consumed by extraction.
-/

namespace HegemonCrypto.SmallWood.NativeDecsReconstruction

open Polynomial
open HegemonCrypto.SmallWood.CompactMerkleExtraction
open HegemonCrypto.SmallWood.DecsRestore
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.OpenedRowRefinement
open HegemonCrypto.SmallWood.ProductionAccumulatedExtraction
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.RoundByRound
open scoped BigOperators

noncomputable section

/-- Number of coefficients transmitted at degrees 20 through 126. -/
abbrev NativeDecsHighCount :=
  decsPolynomialDegree + 1 - decsOpenedEvaluations

abbrev NativeDecsHighCoefficients :=
  Matrix decsEta NativeDecsHighCount

theorem native_decs_high_count_is_107 :
    NativeDecsHighCount = 107 := by
  decide

/-- Transmitted DECS coefficients placed at their actual polynomial degrees. -/
def nativeDecsHighPart
    (high : NativeDecsHighCoefficients)
    (repetition : Fin decsEta) : Goldilocks[X] :=
  ∑ coefficient : Fin NativeDecsHighCount,
    C (wordToGoldilocks (high repetition coefficient)) *
      X ^ (decsOpenedEvaluations + coefficient.val)

theorem native_decs_high_part_degree_le
    (high : NativeDecsHighCoefficients)
    (repetition : Fin decsEta) :
    (nativeDecsHighPart high repetition).natDegree ≤
      decsPolynomialDegree := by
  unfold nativeDecsHighPart
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  have coefficientBound := coefficient.isLt
  change coefficient.val < 107 at coefficientBound
  change 20 + coefficient.val ≤ 126
  omega

/-- Exact response value computed from one reconstructed authenticated row. -/
def nativeDecsResponseEvaluation
    (challenge : Matrix decsEta lvcsRowCount)
    (rows : ProductionOpeningRows)
    (repetition : Fin decsEta)
    (opening : OpeningIndex) : Goldilocks :=
  (∑ column : Fin lvcsRowCount,
      wordToGoldilocks (challenge repetition column) *
        rowCommittedValue (rows opening) column) +
    rowMaskValue (rows opening) repetition

def nativeDecsOpeningPoint
    (coordinates : ProductionOpeningCoordinates)
    (opening : OpeningIndex) : Goldilocks :=
  activeEvaluationPoint (coordinates opening)

theorem native_decs_opening_point_injective
    (coordinates : ProductionOpeningCoordinates)
    (challenge : DecsOpeningChallenge)
    (exact : CoordinatesExactlyChallenge coordinates challenge) :
    Function.Injective (nativeDecsOpeningPoint coordinates) :=
  active_evaluation_point_injective.comp exact.1

/-- Exact polynomial returned by the native DECS `poly_restore` call. -/
def restoredNativeDecsPolynomial
    (challenge : Matrix decsEta lvcsRowCount)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (high : NativeDecsHighCoefficients)
    (repetition : Fin decsEta) : Goldilocks[X] :=
  restorePolynomial
    (Finset.univ : Finset OpeningIndex)
    (nativeDecsOpeningPoint coordinates)
    (nativeDecsHighPart high repetition)
    (nativeDecsResponseEvaluation challenge rows repetition)

theorem restored_native_decs_polynomial_degree_le
    (challenge : Matrix decsEta lvcsRowCount)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (high : NativeDecsHighCoefficients)
    (decsOpening : DecsOpeningChallenge)
    (exact : CoordinatesExactlyChallenge coordinates decsOpening)
    (repetition : Fin decsEta) :
    (restoredNativeDecsPolynomial
      challenge coordinates rows high repetition).natDegree ≤
        decsPolynomialDegree := by
  apply restore_polynomial_natDegree_le
  · exact (native_decs_opening_point_injective coordinates decsOpening exact).injOn
  · change 20 ≤ 126 + 1
    decide
  · exact native_decs_high_part_degree_le high repetition

/-- Typed interactive DECS message reconstructed from the exact native proof fields. -/
def reconstructNativeDecsMessage
    (challenge : Matrix decsEta lvcsRowCount)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (high : NativeDecsHighCoefficients) :
    DecsPolynomialMessage :=
  fun repetition =>
    polynomialFieldWords (degree := decsPolynomialDegree)
      (restoredNativeDecsPolynomial challenge coordinates rows high repetition)

/--
Successful fixed-sampler coordinates and native restoration force every row equation. No
cryptographic assumption is used.
-/
theorem reconstructed_native_decs_message_checks
    (challenge : Matrix decsEta lvcsRowCount)
    (decsOpening : DecsOpeningChallenge)
    (coordinates : ProductionOpeningCoordinates)
    (rows : ProductionOpeningRows)
    (high : NativeDecsHighCoefficients)
    (exact : CoordinatesExactlyChallenge coordinates decsOpening) :
    NativeDecsOpeningChecks challenge
      (reconstructNativeDecsMessage challenge coordinates rows high)
      coordinates rows := by
  intro opening repetition
  rw [responsePolynomial, reconstructNativeDecsMessage,
    field_word_polynomial_polynomialFieldWords
      (restoredNativeDecsPolynomial challenge coordinates rows high repetition)
      (restored_native_decs_polynomial_degree_le
        challenge coordinates rows high decsOpening exact repetition)]
  exact restore_polynomial_eval
    (native_decs_opening_point_injective coordinates decsOpening exact).injOn
    (Finset.mem_univ opening)

end

end HegemonCrypto.SmallWood.NativeDecsReconstruction

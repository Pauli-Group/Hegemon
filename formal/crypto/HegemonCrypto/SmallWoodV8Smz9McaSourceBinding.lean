import HegemonCrypto.SmallWoodV8Smz9McaDecoder

/-! Source-layout adapter for the calculated MCA decoder. The actual source
matrix is transposed into the decoder's column-indexed coefficient array. -/

namespace HegemonCrypto.SmallWood.V8Smz9McaDecoder.SourceBinding

open Polynomial V8Smz9McaRecovery
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped BigOperators

noncomputable section

set_option maxRecDepth 5000
set_option backward.isDefEq.respectTransparency false

open V8Smz9RobustQueryMismatch

def sourceData (source : Source) (column : ℕ) :
    V8Smz9RobustQueryMismatch.Position → Goldilocks :=
  if bounded : column < 140 then source.data ⟨column, bounded⟩ else 0

def columnCoefficients (matrix : V8Smz9RobustQueryMismatch.Matrix) : Smz9Coefficients :=
  fun column row => matrix row column

def rowMatrix (coefficients : Smz9Coefficients) : V8Smz9RobustQueryMismatch.Matrix :=
  fun row column => coefficients column row

theorem matrix_column_roundtrip (matrix : V8Smz9RobustQueryMismatch.Matrix) :
    rowMatrix (columnCoefficients matrix) = matrix := rfl

def matrixCoefficientEquiv : V8Smz9RobustQueryMismatch.Matrix ≃ Smz9Coefficients where
  toFun := columnCoefficients
  invFun := rowMatrix
  left_inv _ := rfl
  right_inv _ := rfl

theorem mixture_is_source_combination (source : Source)
    (matrix : V8Smz9RobustQueryMismatch.Matrix)
    (row : MaskRow) (index : V8Smz9RobustQueryMismatch.Position) :
    mixedWord (sourceData source) source.masks (extendCoefficients (columnCoefficients matrix))
        140 row index = sourceCombination source matrix row index := by
  rw [mixed_word_eq_sum]
  unfold sourceCombination
  rw [add_comm _ (source.masks row index)]
  congr 1

def boundedMatrixResponse (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387)
    (coefficients : Smz9Coefficients) : BoundedResponse Goldilocks (Fin 5) 387 :=
  boundedResponseOfPolynomials (response (rowMatrix coefficients)) (bounded (rowMatrix coefficients))

def decodeMatrixSource (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387)
    (matrix : V8Smz9RobustQueryMismatch.Matrix) : Option (DecodedSource Goldilocks (Fin 5) 140) :=
  responseDecoder V8Smz9DisjointCoset.evaluationPoint 387 (sourceData source) source.masks
    (boundedMatrixResponse response bounded) (columnCoefficients matrix)

def decodedCandidate (candidate : DecodedSource Goldilocks (Fin 5) 140) : Candidate where
  data := candidate.data
  masks := candidate.masks

/-- The equations checked at the exact twenty-subset are precisely membership
in the response's full, pre-query agreement set. -/
theorem query_accepts_iff_subset (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387)
    (matrix : V8Smz9RobustQueryMismatch.Matrix) (query : Challenge) :
    QueryAccepts source response matrix query ↔
      query.val ⊆ responseSupport V8Smz9DisjointCoset.evaluationPoint 387
        (sourceData source) source.masks (boundedMatrixResponse response bounded)
        (columnCoefficients matrix) := by
  constructor
  · intro accepted index member
    rw [responseSupport, mem_agreement]
    intro row
    simpa only [boundedMatrixResponse, responsePolynomials, boundedResponseOfPolynomials, matrix_column_roundtrip,
      mixture_is_source_combination] using (accepted index member row).symm
  · intro subset index member row
    have equation := (mem_agreement V8Smz9DisjointCoset.evaluationPoint _ _ index).mp
      (subset member) row
    simpa only [boundedMatrixResponse, responsePolynomials, boundedResponseOfPolynomials, matrix_column_roundtrip,
      mixture_is_source_combination] using equation.symm

set_option backward.isDefEq.respectTransparency false in
/-- A successful computed lift reproduces the entire DECS response, before
the later PIOP batching matrix. No prefix-fixed-before-DECS claim is made. -/
theorem decoded_matrix_response_consistent (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387)
    (matrix : V8Smz9RobustQueryMismatch.Matrix)
    (candidate : DecodedSource Goldilocks (Fin 5) 140)
    (decoded : decodeMatrixSource source response bounded matrix = some candidate) :
    ResponseConsistent (decodedCandidate candidate) response matrix := by
  intro row
  have consistent := decoded_response_equals_projection V8Smz9DisjointCoset.evaluationPoint
    V8Smz9DisjointCoset.evaluation_point_injective 387 (sourceData source) source.masks
    (boundedMatrixResponse response bounded) (columnCoefficients matrix) candidate decoded row
  simp only [boundedMatrixResponse, responsePolynomials, boundedResponseOfPolynomials,
    matrix_column_roundtrip, projectedSource, columnCoefficients] at consistent
  rw [consistent]
  unfold combined decodedCandidate
  rw [add_comm]
  congr 1

theorem decoded_matrix_candidate_agrees_at_queries (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387)
    (matrix : V8Smz9RobustQueryMismatch.Matrix)
    (candidate : DecodedSource Goldilocks (Fin 5) 140)
    (decoded : decodeMatrixSource source response bounded matrix = some candidate)
    (query : Challenge) (accepted : QueryAccepts source response matrix query) :
    (∀ row, (candidate.masks row).natDegree ≤ 387) ∧
      (∀ column, (candidate.data column).natDegree ≤ 387) ∧
      ∀ index ∈ query.val, ¬ Mismatch source (decodedCandidate candidate) index := by
  have recovered := decoded_source_agrees_and_has_bounded_degree
    V8Smz9DisjointCoset.evaluationPoint V8Smz9DisjointCoset.evaluation_point_injective 387
    (responseSupport V8Smz9DisjointCoset.evaluationPoint 387
      (sourceData source) source.masks (boundedMatrixResponse response bounded)
      (columnCoefficients matrix))
    (sourceData source) source.masks candidate decoded
  refine ⟨recovered.2.2.1, recovered.2.2.2, ?_⟩
  intro index member mismatch
  have inSupport := (query_accepts_iff_subset source response bounded matrix query).mp accepted member
  rcases mismatch with ⟨column, different⟩ | ⟨row, different⟩
  · apply different
    have same := recovered.2.1.2 column index inSupport
    have columnBound : column.val < 140 := column.isLt
    simpa only [sourceData, dif_pos columnBound, decodedCandidate] using same.symm
  · exact different (recovered.2.1.1 row index inSupport).symm

/-- The literal accepted-query/computed-decoder-failure event for source matrices. -/
def matrixDecoderFailureEvent (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387)
    (matrix : V8Smz9RobustQueryMismatch.Matrix) : Finset Challenge := by
  classical
  exact Finset.univ.filter fun query => QueryAccepts source response matrix query ∧
    decodeMatrixSource source response bounded matrix = none

theorem matrix_decoder_failure_iff (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387)
    (matrix : V8Smz9RobustQueryMismatch.Matrix) (query : Challenge) :
    query ∈ matrixDecoderFailureEvent source response bounded matrix ↔
      query ∈ decoderFailureEvent V8Smz9DisjointCoset.evaluationPoint 387 20
        (sourceData source) source.masks (boundedMatrixResponse response bounded)
        (columnCoefficients matrix) := by
  classical
  simp only [matrixDecoderFailureEvent, decoderFailureEvent, Finset.mem_filter,
    Finset.mem_univ, true_and, decodeMatrixSource,
    query_accepts_iff_subset source response bounded matrix query]

def matrixFailureEquiv (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387) :
    FiniteEvents.Accepted (matrixDecoderFailureEvent source response bounded) ≃
      FiniteEvents.Accepted (decoderFailureEvent V8Smz9DisjointCoset.evaluationPoint
        387 20 (sourceData source) source.masks (boundedMatrixResponse response bounded)) where
  toFun accepted := ⟨columnCoefficients accepted.1, ⟨accepted.2.val,
    (matrix_decoder_failure_iff source response bounded accepted.1 accepted.2.val).mp
      accepted.2.property⟩⟩
  invFun accepted := ⟨rowMatrix accepted.1, ⟨accepted.2.val,
    (matrix_decoder_failure_iff source response bounded (rowMatrix accepted.1)
      accepted.2.val).mpr accepted.2.property⟩⟩
  left_inv _ := rfl
  right_inv _ := rfl

/-- Actual source-layout matrix and exact twenty-subset probability. The
calculated candidate may depend on all DECS coefficients and responses, but
neither the final subset nor later PIOP batching is a decoder input. -/
theorem source_decoder_failure_probability_le (source : Source) (response : Response)
    (bounded : ∀ matrix row, (response matrix row).natDegree ≤ 387) :
    FiniteEvents.jointProbability (matrixDecoderFailureEvent source response bounded) ≤
      (Nat.choose 415 20 : Rat) / Nat.choose (2 ^ 23) 20 +
        140 * (smz9LineBudget : Rat) /
          ((goldilocksModulus : Rat) ^ 5 * Nat.choose (2 ^ 23) 20) := by
  have sameProbability :
      FiniteEvents.jointProbability (matrixDecoderFailureEvent source response bounded) =
        FiniteEvents.jointProbability (decoderFailureEvent V8Smz9DisjointCoset.evaluationPoint
          387 20 (sourceData source) source.masks (boundedMatrixResponse response bounded)) := by
    unfold FiniteEvents.jointProbability
    rw [Fintype.card_congr (matrixFailureEquiv source response bounded),
      Fintype.card_congr matrixCoefficientEquiv]
    congr 1
  rw [sameProbability]
  have sameEvents : decoderFailureEvent V8Smz9DisjointCoset.evaluationPoint
      387 20 (sourceData source) source.masks (boundedMatrixResponse response bounded) =
      unrecoveredQueryEvent V8Smz9DisjointCoset.evaluationPoint
        387 20 (sourceData source) source.masks (boundedMatrixResponse response bounded) := by
    funext coefficients
    exact decoder_failure_event_eq_unrecovered_event V8Smz9DisjointCoset.evaluationPoint
      V8Smz9DisjointCoset.evaluation_point_injective 387 20 (sourceData source) source.masks
      (boundedMatrixResponse response bounded) coefficients
  rw [sameEvents]
  exact smz9_arbitrary_source_recovery_probability_le (sourceData source) source.masks
    (boundedMatrixResponse response bounded)

end

end HegemonCrypto.SmallWood.V8Smz9McaDecoder.SourceBinding

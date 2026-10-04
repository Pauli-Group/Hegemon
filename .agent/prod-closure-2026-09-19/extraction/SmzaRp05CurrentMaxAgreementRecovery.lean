import SmzaRp05Q38CurrentRebinding
import SmzaRp05CurrentUniversalMatrixLoss
import HegemonCrypto.SmallWoodV8Smz9McaDecoder

/-!
# Current-map maximum-agreement extraction failure event

The decoder is fixed from the pre-query table and the five response
polynomials selected by the matrix challenge.  It interpolates on the actual
agreement support, rather than assuming a canonical 406-point interpolation
is the extractor.  An accepted query is charged either to a small agreement
support or to a bad random-combination line; arbitrary tables, including
tables close to a codeword, are covered.

This is the exact finite matrix-by-q38 experiment.  It does not assert that a
SHA/QROM challenge has this independent uniform law or transport it to Born
weights.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementRecovery

open HegemonCrypto.SmallWood
open HegemonCrypto.SmallWood.V8Smz9McaRecovery
open HegemonCrypto.SmallWood.V8Smz9McaDecoder
open SmzaRp05Q38CurrentRebinding
open SmzaRp05CurrentUniversalMatrixLoss
open HegemonCrypto.FiniteFieldSampling
open HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev Position := Fin SmzaQ38OracleExtraction.decsDomainSize
abbrev Query := QuerySample Position 38
abbrev Coefficients := Fin 140 → Fin 5 → Goldilocks
abbrev ResponseRule := Coefficients → BoundedResponse Goldilocks (Fin 5) 405

attribute [local irreducible] querySampleFintype

noncomputable local instance currentQueryNonempty : Nonempty Query := by
  classical
  let embedding : Fin 38 ↪ Position :=
    { toFun := fun index => ⟨index.val, index.isLt.trans (by decide)⟩
      inj' := by
        intro left right equal
        apply Fin.ext
        exact congrArg (fun position : Position => position.val) equal }
  exact ⟨⟨Finset.univ.map embedding, by simp⟩⟩

/-- The current-map universal matrix receipt is proved at support 65,536.
This is an analysis cutoff, not a claim that an accepted native transcript
has this agreement-support size. -/
def currentAgreementThreshold : Nat := 65536

/-- Same-query acceptance of all five bounded responses and failure of the
pre-query maximum-agreement decoder.  The response family depends on the
matrix, but not on the later query. -/
def currentAcceptedExtractionFailureEvent
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients) : Finset Query :=
  decoderFailureEvent smz9EvaluationPoint 405 38 data masks response coefficients

theorem mem_current_accepted_extraction_failure_event
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients) (query : Query) :
    query ∈ currentAcceptedExtractionFailureEvent data masks response coefficients ↔
      query.val ⊆ responseSupport smz9EvaluationPoint 405 data masks response coefficients ∧
        responseDecoder smz9EvaluationPoint 405 data masks response coefficients = none := by
  simp [currentAcceptedExtractionFailureEvent, decoderFailureEvent]

/-- Pointwise accepted-query plus extractor-failure inclusion into the fixed
matrix/query event.  The accepted predicate is represented by the exact
five-response agreement support used by the soundness decoder. -/
theorem accepted_query_and_failed_extraction_mem_event
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients) (query : Query)
    (accepted : query.val ⊆
      responseSupport smz9EvaluationPoint 405 data masks response coefficients)
    (failed : responseDecoder smz9EvaluationPoint 405 data masks response coefficients = none) :
    query ∈ currentAcceptedExtractionFailureEvent data masks response coefficients := by
  exact (mem_current_accepted_extraction_failure_event data masks response coefficients query).2
    ⟨accepted, failed⟩

/-- For a fixed matrix outside the checked current universal bad-matrix
event, the accepted-query/extraction-failure event has at most the number of
q38 subsets of a 65,535-element set. -/
theorem current_good_matrix_failure_card_le
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients)
    (notBad : ¬ currentMatrixBad data masks coefficients) :
    (currentAcceptedExtractionFailureEvent data masks response coefficients).card ≤
      Nat.choose (currentAgreementThreshold - 1) 38 := by
  exact Mca38UniversalMatrixEvent.nonexceptional_decoder_failure_card_bound
    smz9EvaluationPoint smz9_evaluation_point_injective 405
    currentAgreementThreshold 38 (by decide) data masks response coefficients notBad

/-- The current-map finite matrix-by-q38 failure probability is bounded by
the checked current matrix loss plus the small-support q38 sampling loss.
This remains an experiment over an independently uniform matrix and query;
it does not assert a SHA/QROM or Born-weight transport. -/
theorem current_q38_max_agreement_failure_probability_le
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
      (currentAcceptedExtractionFailureEvent data masks response) ≤
        currentMatrixLoss +
          (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
            Nat.choose (Fintype.card Position) 38 := by
  classical
  let smallLoss : Rat :=
    (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
      Nat.choose (Fintype.card Position) 38
  have queryCard : Fintype.card Query = Nat.choose (Fintype.card Position) 38 := by
    exact query_sample_card (Position := Position) 38
  have coeffCardPositive : (0 : Rat) < Fintype.card Coefficients := by
    exact_mod_cast Fintype.card_pos
  have perMatrix : ∀ coefficients,
      V8Smz9RobustQueryMismatch.FiniteEvents.probability
        (currentAcceptedExtractionFailureEvent data masks response coefficients) ≤
        (if currentMatrixBad data masks coefficients then 1 else smallLoss) := by
    intro coefficients
    by_cases bad : currentMatrixBad data masks coefficients
    · have cardBound :
          (currentAcceptedExtractionFailureEvent data masks response coefficients).card ≤
            Fintype.card Query := Finset.card_le_univ _
      unfold V8Smz9RobustQueryMismatch.FiniteEvents.probability
      rw [if_pos bad]
      change
        ((currentAcceptedExtractionFailureEvent data masks response coefficients).card : Rat) /
          Fintype.card Query ≤ 1
      have denominatorPositive : (0 : Rat) < Fintype.card Query := by
        exact_mod_cast Fintype.card_pos
      apply (div_le_iff₀ denominatorPositive).2
      rw [one_mul]
      exact_mod_cast cardBound
    · have cardBound := current_good_matrix_failure_card_le
        data masks response coefficients bad
      unfold V8Smz9RobustQueryMismatch.FiniteEvents.probability
      rw [if_neg bad, queryCard]
      exact div_le_div_of_nonneg_right (by exact_mod_cast cardBound)
        (Nat.cast_nonneg _)
  rw [V8Smz9RobustQueryMismatch.FiniteEvents.joint_probability_eq_average]
  have sumBound :
      (∑ coefficients : Coefficients,
        V8Smz9RobustQueryMismatch.FiniteEvents.probability
          (currentAcceptedExtractionFailureEvent data masks response coefficients)) ≤
        ((Finset.univ.filter (currentMatrixBad data masks)).card : Rat) +
          Fintype.card Coefficients * smallLoss := by
    calc
      _ ≤ ∑ coefficients : Coefficients,
          ((if currentMatrixBad data masks coefficients then 1 else 0 : Rat) + smallLoss) :=
        Finset.sum_le_sum fun coefficients _ => by
          have bound := perMatrix coefficients
          by_cases bad : currentMatrixBad data masks coefficients
          · have boundAt := bound
            rw [if_pos bad] at boundAt
            have smallLossNonnegative : (0 : Rat) ≤ smallLoss := by
              exact div_nonneg (Nat.cast_nonneg _) (Nat.cast_nonneg _)
            change
              V8Smz9RobustQueryMismatch.FiniteEvents.probability
                  (currentAcceptedExtractionFailureEvent data masks response coefficients) ≤
                (if currentMatrixBad data masks coefficients then 1 else 0) + smallLoss
            rw [if_pos bad]
            exact boundAt.trans (le_add_of_nonneg_right smallLossNonnegative)
          · simpa [bad] using bound
      _ = _ := by
        rw [Finset.sum_add_distrib]
        have indicatorCount :
            ((Finset.univ.filter (currentMatrixBad data masks)).card : Rat) =
              ∑ coefficients : Coefficients,
                (if currentMatrixBad data masks coefficients then (1 : Rat) else 0) := by
          have indicatorCountNat :
              (Finset.univ.filter (currentMatrixBad data masks)).card =
                ∑ coefficients : Coefficients,
                  (if currentMatrixBad data masks coefficients then 1 else 0) := by
            exact Finset.card_filter _ _
          exact_mod_cast indicatorCountNat
        rw [← indicatorCount]
        simp only [Finset.sum_const, Finset.card_univ, nsmul_eq_mul]
  calc
    _ ≤ (((Finset.univ.filter (currentMatrixBad data masks)).card : Rat) +
          Fintype.card Coefficients * smallLoss) /
        Fintype.card Coefficients := by
      apply div_le_div_of_nonneg_right sumBound
      exact_mod_cast (Nat.zero_le (Fintype.card Coefficients))
    _ = HegemonCrypto.CmsClassicalDatabase.outputEventProbability
          (currentMatrixBad data masks) + smallLoss := by
      unfold HegemonCrypto.CmsClassicalDatabase.outputEventProbability
      rw [add_div, mul_div_cancel_left₀ _ (ne_of_gt coeffCardPositive)]
    _ ≤ currentMatrixLoss + smallLoss := by
      exact add_le_add (current_matrix_bad_output_density data masks) le_rfl

/-- A successful maximum-agreement extraction recovers codewords only on its
actual pre-query agreement support; sampled acceptance transports that
recovery to the query without requiring all-domain codeword agreement. -/
theorem decoded_source_agrees_on_accepted_query
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients)
    (candidate : DecodedSource Goldilocks (Fin 5) 140)
    (query : Query)
    (decoded : responseDecoder smz9EvaluationPoint 405 data masks response coefficients =
      some candidate)
    (accepted : query.val ⊆
      responseSupport smz9EvaluationPoint 405 data masks response coefficients) :
    ∀ column index, index ∈ query.val →
      (candidate.data column).eval (smz9EvaluationPoint index) = data column.val index := by
  have decodedFacts := decoded_source_agrees_and_has_bounded_degree
    smz9EvaluationPoint smz9_evaluation_point_injective 405
    (responseSupport smz9EvaluationPoint 405 data masks response coefficients)
    data masks candidate decoded
  intro column index member
  exact decodedFacts.2.1.2 column index (accepted member)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementRecovery

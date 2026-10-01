import HegemonCrypto.SmallWoodV8Smz9McaDecoder

/-!
# A response-universal exceptional DECS matrix

Source draft, not kernel checked. No compilation is permitted in the current
work phase. This separates the matrix event from the later q38 sample: using
queryCount = 0 in the retained weighted recovery theorem gives an indicator,
not a query-sampling loss. The line-count premise below is explicit and must
be supplied by the concrete finite-Hensel count; it is not an axiom.
-/

namespace HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent

set_option linter.unusedSectionVars false

open Polynomial
open scoped BigOperators
open scoped Classical
open HegemonCrypto.SmallWood.V8Smz9McaRecovery
open HegemonCrypto.SmallWood.V8Smz9McaDecoder

noncomputable section

variable {F Position Row : Type*} [Field F] [Fintype F]
  [Fintype Position] [Fintype Row]

/-- A line is exceptional for some bounded response, before sampling queries. -/
def badLineLabels (point : Position → F) (degree threshold : ℕ)
    (prior : Row → Position → F) (direction : Position → F) : Finset (Row → F) := by
  classical
  exact Finset.univ.filter fun coefficient =>
    ¬ LineGood point degree threshold prior direction coefficient

/-- The old query-weight definition at zero queries is exactly a bad-line bit. -/
theorem zero_query_weight_eq_bad_line_indicator
    (point : Position → F) (degree threshold : ℕ)
    (prior : Row → Position → F) (direction : Position → F)
    (coefficient : Row → F) :
    badCoefficientWeight point degree threshold 0 prior direction coefficient =
      if LineGood point degree threshold prior direction coefficient then 0 else 1 := by
  classical
  have upper : badCoefficientWeight point degree threshold 0
      prior direction coefficient ≤ 1 := by
    unfold badCoefficientWeight
    apply Finset.sup_le
    intro response _
    dsimp [badResponseWeight]
    split <;> simp
  by_cases good : LineGood point degree threshold prior direction coefficient
  · rw [if_pos good]
    apply Nat.eq_zero_of_le_zero
    unfold badCoefficientWeight
    apply Finset.sup_le
    intro response _
    have impossible : ¬ (threshold ≤
        (agreement point (lineWord prior direction coefficient)
          (responsePolynomials response)).card ∧
        ¬ CodeOn point degree direction
          (agreement point (lineWord prior direction coefficient)
            (responsePolynomials response))) := by
      rintro ⟨large, notCoded⟩
      exact notCoded (good _ (bounded_response_degree response) large)
    simp only [badResponseWeight, if_neg impossible, le_refl]
  · rw [if_neg good]
    apply Nat.le_antisymm upper
    simp only [LineGood, not_forall] at good
    obtain ⟨response, bounded, large, notCoded⟩ := good
    have lower := retained_bad_support_weight_le point degree threshold 0
      prior direction coefficient
      (agreement point (lineWord prior direction coefficient) response)
      large notCoded (fun row => ⟨response row, bounded row,
        fun index member => (mem_agreement point _ _ index).mp member row⟩)
    simpa only [Nat.choose_zero_right] using lower

/-- Therefore the zero-query line budget is a cardinality, with no sample factor. -/
theorem zero_query_line_budget_eq_card
    (point : Position → F) (degree threshold : ℕ)
    (prior : Row → Position → F) (direction : Position → F) :
    lineCoefficientBudget point degree threshold 0 prior direction =
      (badLineLabels point degree threshold prior direction).card := by
  classical
  unfold lineCoefficientBudget badLineLabels
  simp only [zero_query_weight_eq_bad_line_indicator]
  simp only [Finset.card_eq_sum_ones, Finset.sum_filter]
  apply Finset.sum_congr rfl
  intro coefficient _
  by_cases good : LineGood point degree threshold prior direction coefficient <;> simp [good]

/-- Existential quantification includes every response and support, not a
response chosen by an independent sampler or a fixed candidate family. -/
def BadMatrix (point : Position → F) (degree threshold : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (coefficients : Fin count → Row → F) : Prop :=
  ∃ support : Finset Position, threshold ≤ support.card ∧
    VectorCodeOn point degree
      (mixedWord data masks (extendCoefficients coefficients) count) support ∧
    ¬ (VectorCodeOn point degree masks support ∧
      ∀ column < count, CodeOn point degree (data column) support)

def badMatrices (point : Position → F) (degree threshold : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) (count : ℕ) :
    Finset (Fin count → Row → F) := by
  classical
  exact Finset.univ.filter (BadMatrix point degree threshold data masks)

theorem bad_matrix_indicator_le_column_sum
    (point : Position → F) (degree threshold : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (coefficients : Fin count → Row → F) :
    (if BadMatrix point degree threshold data masks coefficients then 1 else 0) ≤
      ∑ column : Fin count,
        columnWeight point degree threshold 0 data masks column coefficients := by
  classical
  by_cases bad : BadMatrix point degree threshold data masks coefficients
  · rw [if_pos bad]
    obtain ⟨support, large, combined, notRecovered⟩ := bad
    have bound := unrecovered_support_weight_le_column_sum point degree threshold 0
      data masks (extendCoefficients coefficients) count support large combined notRecovered
    have sumEq : (∑ column : Fin count,
        columnWeight point degree threshold 0 data masks column coefficients) =
        ∑ column ∈ Finset.range count,
          badCoefficientWeight point degree threshold 0
            (mixedWord data masks (extendCoefficients coefficients) column)
            (data column) (extendCoefficients coefficients column) := by
      rw [← Fin.sum_univ_eq_sum_range]
      apply Finset.sum_congr rfl
      intro column _
      simp only [columnWeight, extendCoefficients, dif_pos column.isLt]
    rw [sumEq]
    simpa only [Nat.choose_zero_right] using bound
  · rw [if_neg bad]
    exact Nat.zero_le _

/-- Exact unnormalized matrix probability bound. In the q38 instance the
denominator is p^5, count is140, and the proposed line budget is12310499043179.
This theorem is independent of any response selector and any final query. -/
theorem universal_bad_matrix_card_bound
    (point : Position → F) (degree threshold : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) (count budget : ℕ)
    (lineBound : ∀ (column : Fin count) (prior : Row → Position → F),
      (badLineLabels point degree threshold prior (data column.val)).card ≤ budget) :
    (badMatrices point degree threshold data masks count).card *
        Fintype.card (Row → F) ≤
      Fintype.card (Fin count → Row → F) * (count * budget) := by
  classical
  have indicatorSum : (badMatrices point degree threshold data masks count).card =
      ∑ coefficients : Fin count → Row → F,
        if BadMatrix point degree threshold data masks coefficients then 1 else 0 := by
    simp only [badMatrices, Finset.card_eq_sum_ones, Finset.sum_filter]
  rw [indicatorSum]
  have pointwise := Finset.sum_le_sum
    (s := (Finset.univ : Finset (Fin count → Row → F)))
    (fun coefficients _ => bad_matrix_indicator_le_column_sum
      point degree threshold data masks coefficients)
  apply (Nat.mul_le_mul_right (Fintype.card (Row → F)) pointwise).trans
  apply all_column_weights_sum_bound point degree threshold 0 data masks budget
  intro column prior
  rw [zero_query_line_budget_eq_card]
  exact lineBound column prior

/-- A nonexceptional matrix works for every later response. No independence
assumption is imposed on the response or its full agreement support. -/
theorem nonexceptional_matrix_recovers_every_large_response
    (point : Position → F) (degree threshold : ℕ)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (coefficients : Fin count → Row → F)
    (notBad : ¬ BadMatrix point degree threshold data masks coefficients)
    (response : Row → F[X])
    (bounded : ∀ row, (response row).natDegree ≤ degree)
    (large : threshold ≤ (agreement point
      (mixedWord data masks (extendCoefficients coefficients) count) response).card) :
    VectorCodeOn point degree masks (agreement point
      (mixedWord data masks (extendCoefficients coefficients) count) response) ∧
    ∀ column < count, CodeOn point degree (data column) (agreement point
      (mixedWord data masks (extendCoefficients coefficients) count) response) := by
  letI propDecidable : ∀ p : Prop, Decidable p := fun p => Classical.propDecidable p
  by_contra notRecovered
  apply notBad
  refine ⟨_, large, ?_, notRecovered⟩
  intro row
  exact ⟨response row, bounded row,
    fun index member => (mem_agreement point _ _ index).mp member row⟩

/-- The actual calculated decoder, not just an existential source, obeys the
two-stage partition. A failed accepted sample outside the universal matrix
event must lie in a strictly small full agreement support. -/
theorem accepted_decoder_failure_implies_bad_matrix_or_small_support
    [LinearOrder Position] (point : Position → F) (injective : Function.Injective point)
    (degree threshold queryCount : ℕ) (thresholdValid : degree < threshold)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) (query : QuerySample Position queryCount)
    (failed : query ∈ decoderFailureEvent point degree queryCount data masks
      response coefficients) :
    BadMatrix point degree threshold data masks coefficients ∨
      ((responseSupport point degree data masks response coefficients).card < threshold ∧
        query.val ⊆ responseSupport point degree data masks response coefficients) := by
  classical
  by_cases bad : BadMatrix point degree threshold data masks coefficients
  · exact Or.inl bad
  · right
    have failure := (Finset.mem_filter.mp failed).2
    refine ⟨?_, failure.1⟩
    by_contra notSmall
    have large := Nat.le_of_not_gt notSmall
    have coded := nonexceptional_matrix_recovers_every_large_response
      point degree threshold data masks coefficients bad
      (responsePolynomials (response coefficients))
      (bounded_response_degree (response coefficients)) large
    have notRecovered := (decode_source_none_iff point injective degree
      (responseSupport point degree data masks response coefficients) data masks).mp failure.2
    exact notRecovered ⟨thresholdValid.trans_le large, coded⟩

/-- The later sampling loss is charged once, for each fixed nonexceptional
matrix and its already fixed response. This is a per-stage cardinality bound;
it does not claim that a quantum response was selected independently. -/
theorem nonexceptional_decoder_failure_card_bound
    [LinearOrder Position] (point : Position → F) (injective : Function.Injective point)
    (degree threshold queryCount : ℕ) (thresholdValid : degree < threshold)
    (data : ℕ → Position → F) (masks : Row → Position → F) {count : ℕ}
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F)
    (notBad : ¬ BadMatrix point degree threshold data masks coefficients) :
    (decoderFailureEvent point degree queryCount data masks response coefficients).card ≤
      Nat.choose (threshold - 1) queryCount := by
  letI propDecidable : ∀ p : Prop, Decidable p := fun p => Classical.propDecidable p
  by_cases small : (responseSupport point degree data masks response coefficients).card < threshold
  · have subset : decoderFailureEvent point degree queryCount data masks response coefficients ⊆
        sampleWithinEvent (responseSupport point degree data masks response coefficients)
          queryCount := by
      intro query member
      have member' := member
      simp only [decoderFailureEvent, Finset.mem_filter, Finset.mem_univ, true_and] at member'
      simpa only [sampleWithinEvent, Finset.mem_filter, Finset.mem_univ, true_and] using member'.1
    have bound := Finset.card_le_card subset
    rw [sample_within_event_card] at bound
    exact bound.trans (Nat.choose_le_choose queryCount (Nat.le_pred_of_lt small))
  · have empty : decoderFailureEvent point degree queryCount data masks response coefficients = ∅ := by
      apply Finset.eq_empty_iff_forall_notMem.mpr
      intro query member
      rcases accepted_decoder_failure_implies_bad_matrix_or_small_support
        point injective degree threshold queryCount thresholdValid data masks response
        coefficients query member with bad | smallSupport
      · exact notBad bad
      · exact small smallSupport.1
    rw [empty, Finset.card_empty]
    exact Nat.zero_le _

end

end HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent

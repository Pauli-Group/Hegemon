import HegemonCrypto.SmallWoodV8Smz9McaRecovery
import Mathlib.Data.Finset.Sort

/-!
# A specified decoder on the response's pre-query agreement

The decoder scans the full supplied source table to form agreement, takes the
first degree-plus-one positions in canonical index order, interpolates each
source word, and checks that interpolation on the full agreement. Its inputs
do not include the subsequent DECS query or PIOP challenge. This is a finite
table algorithm, not an extractor from a quantum Merkle commitment.
-/

namespace HegemonCrypto.SmallWood.V8Smz9McaDecoder

open Polynomial V8Smz9McaRecovery
open scoped BigOperators

noncomputable section

set_option maxRecDepth 5000

variable {F Position : Type*} [Field F] [Fintype Position] [LinearOrder Position]

/-- The canonical first degree-plus-one retained positions, not a chosen polynomial witness. -/
def interpolationNodes (degree : ℕ) (support : Finset Position) : Finset Position :=
  ((support.sort (· ≤ ·)).take (degree + 1)).toFinset

omit [Field F] [Fintype Position] in
theorem interpolation_nodes_subset (degree : ℕ) (support : Finset Position) :
    interpolationNodes degree support ⊆ support := by
  intro index member
  have inTake := List.mem_toFinset.mp member
  have inSort := List.mem_of_mem_take inTake
  exact (Finset.mem_sort (· ≤ ·)).mp inSort

omit [Field F] [Fintype Position] in
theorem interpolation_nodes_card (degree : ℕ) (support : Finset Position)
    (large : degree < support.card) :
    (interpolationNodes degree support).card = degree + 1 := by
  unfold interpolationNodes
  rw [List.toFinset_card_of_nodup ((support.sort_nodup (· ≤ ·)).take),
    List.length_take, Finset.length_sort]
  exact Nat.min_eq_left (by omega)

def decodeWord (point : Position → F) (degree : ℕ) (support : Finset Position)
    (word : Position → F) : F[X] :=
  Lagrange.interpolate (interpolationNodes degree support) point word

omit [Fintype Position] in
theorem decode_word_equals_any_codeword
    (point : Position → F) (injective : Function.Injective point)
    (degree : ℕ) (support : Finset Position) (word : Position → F)
    (large : degree < support.card) (polynomial : F[X])
    (bounded : polynomial.natDegree ≤ degree)
    (agrees : ∀ index ∈ support, polynomial.eval (point index) = word index) :
    decodeWord point degree support word = polynomial := by
  apply (Lagrange.eq_interpolate_of_eval_eq word injective.injOn _ _).symm
  · rw [interpolation_nodes_card degree support large]
    exact degree_le_natDegree.trans_lt (by exact_mod_cast Nat.lt_succ_of_le bounded)
  · intro index member
    exact agrees index (interpolation_nodes_subset degree support member)

omit [Fintype Position] in
theorem decode_word_degree
    (point : Position → F) (injective : Function.Injective point)
    (degree : ℕ) (support : Finset Position) (word : Position → F)
    (large : degree < support.card) :
    (decodeWord point degree support word).natDegree ≤ degree := by
  have bounded := Lagrange.degree_interpolate_le word injective.injOn
    (s := interpolationNodes degree support)
  rw [interpolation_nodes_card degree support large, Nat.add_sub_cancel] at bounded
  exact natDegree_le_of_degree_le bounded

omit [Fintype Position] in
/-- Coding existence is equivalent to success of this particular polynomial calculation. -/
theorem code_on_iff_decoded_agreement
    (point : Position → F) (injective : Function.Injective point)
    (degree : ℕ) (support : Finset Position) (word : Position → F)
    (large : degree < support.card) :
    CodeOn point degree word support ↔
      ∀ index ∈ support, (decodeWord point degree support word).eval (point index) = word index := by
  constructor
  · rintro ⟨polynomial, bounded, agrees⟩
    rw [decode_word_equals_any_codeword point injective degree support word large
      polynomial bounded agrees]
    exact agrees
  · intro agrees
    exact ⟨decodeWord point degree support word,
      decode_word_degree point injective degree support word large, agrees⟩

variable {Row : Type*} [Fintype Row]

structure DecodedSource (F Row : Type*) [Semiring F] (count : ℕ) where
  data : Fin count → F[X]
  masks : Row → F[X]

def interpolateSource (point : Position → F) (degree : ℕ) (support : Finset Position)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F) :
    DecodedSource F Row count where
  data column := decodeWord point degree support (data column.val)
  masks row := decodeWord point degree support (masks row)

def CandidateAgrees (point : Position → F) (support : Finset Position)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (candidate : DecodedSource F Row count) : Prop :=
  (∀ row index, index ∈ support → (candidate.masks row).eval (point index) = masks row index) ∧
    ∀ column index, index ∈ support → (candidate.data column).eval (point index) = data column.val index

/-- The only search is the finite comparison of calculated evaluations; no existential
polynomial, precomputed candidate family, or later challenge is supplied to the decoder. -/
def decodeSource (point : Position → F) (degree : ℕ) (support : Finset Position)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F) :
    Option (DecodedSource F Row count) := by
  classical
  let candidate : DecodedSource F Row count := interpolateSource point degree support data masks
  exact if degree < support.card ∧ CandidateAgrees point support data masks candidate
    then some candidate else none

omit [Fintype Position] [Fintype Row] in
theorem interpolate_source_agrees_iff_all_words_coded
    (point : Position → F) (injective : Function.Injective point)
    (degree : ℕ) (support : Finset Position) (large : degree < support.card)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F) :
    CandidateAgrees point support data masks
        (interpolateSource point degree support data masks : DecodedSource F Row count) ↔
      VectorCodeOn point degree masks support ∧
        ∀ column < count, CodeOn point degree (data column) support := by
  constructor
  · rintro ⟨maskAgrees, dataAgrees⟩
    constructor
    · intro row
      exact (code_on_iff_decoded_agreement point injective degree support (masks row) large).2
        (maskAgrees row)
    · intro column bounded
      exact (code_on_iff_decoded_agreement point injective degree support (data column) large).2
        (dataAgrees ⟨column, bounded⟩)
  · rintro ⟨maskCode, dataCode⟩
    constructor
    · intro row
      exact (code_on_iff_decoded_agreement point injective degree support (masks row) large).1
        (maskCode row)
    · intro column
      exact (code_on_iff_decoded_agreement point injective degree support (data column.val) large).1
        (dataCode column.val column.isLt)

omit [Fintype Position] [Fintype Row] in
/-- Exact failure criterion, including too few distinct interpolation positions. -/
theorem decode_source_none_iff
    (point : Position → F) (injective : Function.Injective point)
    (degree : ℕ) (support : Finset Position)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F) :
    decodeSource point degree support data masks (count := count) = none ↔
      ¬ (degree < support.card ∧ (VectorCodeOn point degree masks support ∧
        ∀ column < count, CodeOn point degree (data column) support)) := by
  classical
  by_cases large : degree < support.card
  · simp only [decodeSource, large, true_and, ite_eq_right_iff, Option.some_ne_none,
      imp_false, interpolate_source_agrees_iff_all_words_coded point injective degree support large]
  · simp only [decodeSource, large, false_and, if_false, not_false_eq_true]

omit [Fintype Position] [Fintype Row] in
theorem decoded_source_agrees_and_has_bounded_degree
    (point : Position → F) (injective : Function.Injective point)
    (degree : ℕ) (support : Finset Position)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (candidate : DecodedSource F Row count)
    (decoded : decodeSource point degree support data masks = some candidate) :
    degree < support.card ∧ CandidateAgrees point support data masks candidate ∧
      (∀ row, (candidate.masks row).natDegree ≤ degree) ∧
        ∀ column, (candidate.data column).natDegree ≤ degree := by
  classical
  dsimp only [decodeSource] at decoded
  split at decoded
  · rename_i passed
    have same := Option.some.inj decoded
    subst candidate
    refine ⟨passed.1, passed.2, ?_, ?_⟩
    · intro row
      exact decode_word_degree point injective degree support (masks row) passed.1
    · intro column
      exact decode_word_degree point injective degree support (data column.val) passed.1
  · cases decoded

variable [Fintype F] [DecidableEq Row]

def projectedSource {count : ℕ} (candidate : DecodedSource F Row count)
    (coefficients : Fin count → Row → F) (row : Row) : F[X] :=
  candidate.masks row + ∑ column, C (coefficients column row) * candidate.data column

omit [Fintype Position] [LinearOrder Position] [Fintype Row] [Fintype F] [DecidableEq Row] in
theorem projected_source_degree {count : ℕ} (candidate : DecodedSource F Row count)
    (coefficients : Fin count → Row → F) (degree : ℕ)
    (masksBounded : ∀ row, (candidate.masks row).natDegree ≤ degree)
    (dataBounded : ∀ column, (candidate.data column).natDegree ≤ degree) (row : Row) :
    (projectedSource candidate coefficients row).natDegree ≤ degree := by
  apply (natDegree_add_le _ _).trans
  refine max_le (masksBounded row) (natDegree_sum_le_of_forall_le _ _ ?_)
  intro column _
  exact (natDegree_C_mul_le _ _).trans (dataBounded column)

omit [Fintype Position] [LinearOrder Position] [Fintype Row] [Fintype F] [DecidableEq Row] in
theorem projected_source_agrees_with_mixture
    (point : Position → F) (support : Finset Position)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (candidate : DecodedSource F Row count) (coefficients : Fin count → Row → F)
    (agrees : CandidateAgrees point support data masks candidate)
    (index : Position) (member : index ∈ support) (row : Row) :
    (projectedSource candidate coefficients row).eval (point index) =
      mixedWord data masks (extendCoefficients coefficients) count row index := by
  simp only [projectedSource, eval_add, eval_finsetSum, eval_mul, eval_C,
    agrees.1 row index member, agrees.2 _ index member, mixed_word_eq_sum]
  congr 1
  rw [← Fin.sum_univ_eq_sum_range]
  apply Finset.sum_congr rfl
  intro column _
  simp only [extendCoefficients, dif_pos column.isLt]

def responseSupport (point : Position → F) (degree : ℕ)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) : Finset Position :=
  agreement point (mixedWord data masks (extendCoefficients coefficients) count)
    (responsePolynomials (response coefficients))

def responseDecoder (point : Position → F) (degree : ℕ)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) : Option (DecodedSource F Row count) :=
  decodeSource point degree (responseSupport point degree data masks response coefficients) data masks

omit [Fintype Row] [Fintype F] [DecidableEq Row] in
/-- The computed candidate reproduces the complete response polynomial, not just
its queried values. It is chosen after DECS coefficients/response and before all
later challenges. -/
theorem decoded_response_equals_projection
    (point : Position → F) (injective : Function.Injective point) (degree : ℕ)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) (candidate : DecodedSource F Row count)
    (decoded : responseDecoder point degree data masks response coefficients = some candidate)
    (row : Row) :
    responsePolynomials (response coefficients) row = projectedSource candidate coefficients row := by
  have recovered := decoded_source_agrees_and_has_bounded_degree point injective degree
    (responseSupport point degree data masks response coefficients) data masks candidate decoded
  let word := mixedWord data masks (extendCoefficients coefficients) count row
  have responseAgrees : ∀ index ∈ responseSupport point degree data masks response coefficients,
      (responsePolynomials (response coefficients) row).eval (point index) = word index := by
    intro index member
    exact (mem_agreement point _ _ index).mp member row
  have responseDecoded := decode_word_equals_any_codeword point injective degree _ word
    recovered.1 (responsePolynomials (response coefficients) row)
    (bounded_response_degree (response coefficients) row) responseAgrees
  have projectedDecoded := decode_word_equals_any_codeword point injective degree _ word
    recovered.1 (projectedSource candidate coefficients row)
    (projected_source_degree candidate coefficients degree recovered.2.2.1 recovered.2.2.2 row)
    (fun index member => projected_source_agrees_with_mixture point _ data masks candidate
      coefficients recovered.2.1 index member row)
  exact responseDecoded.symm.trans projectedDecoded

/-- Actual accepted-query/decoder-failure event, with no query input to `responseDecoder`. -/
def decoderFailureEvent (point : Position → F) (degree queryCount : ℕ)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) : Finset (QuerySample Position queryCount) := by
  classical
  exact Finset.univ.filter fun query =>
    query.val ⊆ responseSupport point degree data masks response coefficients ∧
      responseDecoder point degree data masks response coefficients = none

omit [Fintype F] [DecidableEq Row] [Fintype Row] in
theorem decoder_failure_event_eq_unrecovered_event
    (point : Position → F) (injective : Function.Injective point) (degree queryCount : ℕ)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (response : (Fin count → Row → F) → BoundedResponse F Row degree)
    (coefficients : Fin count → Row → F) :
    decoderFailureEvent point degree queryCount data masks response coefficients =
      unrecoveredQueryEvent point degree queryCount data masks response coefficients := by
  classical
  ext query
  simp only [decoderFailureEvent, Finset.mem_filter, Finset.mem_univ, true_and,
    responseDecoder, decode_source_none_iff point injective]
  dsimp only [unrecoveredQueryEvent]
  split
  · rename_i recovered
    simp only [Finset.notMem_empty, iff_false]
    intro member
    exact member.2 recovered
  · rename_i notRecovered
    simp only [sampleWithinEvent, Finset.mem_filter, Finset.mem_univ, true_and]
    exact and_iff_left notRecovered

/-- Efficient-in-table-size interpolation replaces the prior existential recovery predicate.
The numerical MCA constant and quantum access/extraction bridge remain separate obligations. -/
theorem decoder_failure_probability_le
    (point : Position → F) (injective : Function.Injective point)
    (degree threshold queryCount : ℕ) (thresholdValid : degree < threshold)
    (sampleFits : queryCount ≤ Fintype.card Position)
    {count : ℕ} (data : ℕ → Position → F) (masks : Row → Position → F)
    (response : (Fin count → Row → F) → BoundedResponse F Row degree) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (decoderFailureEvent point degree queryCount data masks response) ≤
      (Nat.choose (threshold - 1) queryCount : Rat) /
          Nat.choose (Fintype.card Position) queryCount +
        (count * (universalLineBudget (Row := Row) point degree threshold queryCount : Rat)) /
          ((Fintype.card (Row → F) : Rat) *
            Nat.choose (Fintype.card Position) queryCount) := by
  have same : decoderFailureEvent point degree queryCount data masks response =
      unrecoveredQueryEvent point degree queryCount data masks response := by
    funext coefficients
    exact decoder_failure_event_eq_unrecovered_event point injective degree queryCount
      data masks response coefficients
  rw [same]
  exact arbitrary_source_recovery_probability_le point degree threshold queryCount
    thresholdValid sampleFits data masks response
end

end HegemonCrypto.SmallWood.V8Smz9McaDecoder

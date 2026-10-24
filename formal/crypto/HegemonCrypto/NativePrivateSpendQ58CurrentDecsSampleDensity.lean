import HegemonCrypto.NativePrivateSpendQ58CurrentSuccessfulFiber
import HegemonCrypto.NativePrivateSpendQ58CurrentLvcsEventJoin
import SmzaRp04RawRoleSampling

/-! Current58-subset DECS density. A small support and twelve fixed
nonzero degree13172 discrepancies are counted on the8388608-position domain.
The actual14-block capped field sampler precedes the current80-to58 decoder;
failed/exhausted samples stay in the denominator. SOURCE ONLY, not typed. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsSampleDensity
open Polynomial V8Smz9McaRecovery
open V8Smz9CoherentVectorMerkle V8Smz9CoherentMerkleInstrument
open V8Smz9RawCounterCompiler V8Smz9RuntimeRandomness
open HegemonCrypto.CmsClassicalDatabase
open V8Smz9RobustQueryMismatch
open SmzaRp04RawRoleSampling
open scoped Classical BigOperators
namespace U
export NativePrivateSpendQ58CurrentSuccessfulFiber
  (Query rawDecoder raw_bad_and_success_probability_le query_card)
end U
namespace L
export NativePrivateSpendQ58CurrentLvcsEventJoin
  (Combination currentRootIndices current_root_indices_card)
end L
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
abbrev Position := Fin 8388608
abbrev Discrepancies := L.Combination → Goldilocks[X]

def smallSupportEvent (support : Finset Position) : Finset U.Query :=
  if support.card < 360448 then sampleWithinEvent support 58 else ∅

def rootEvent (point : Position → Goldilocks) (polynomial : Goldilocks[X]) : Finset U.Query :=
  if polynomial ≠ 0 then sampleWithinEvent (L.currentRootIndices point polynomial) 58 else ∅

def sampleEvent (point : Position → Goldilocks) (support : Finset Position)
    (discrepancies : Discrepancies) : Finset U.Query :=
  smallSupportEvent support ∪ Finset.univ.biUnion (fun combination => rootEvent point (discrepancies combination))

private def sampleUnionBound (smallBound rootBound : Nat) : Nat := smallBound + 12 * rootBound

private theorem sample_union_bound_eq (smallBound rootBound : Nat) :
    sampleUnionBound smallBound rootBound = smallBound + 12 * rootBound := rfl

def numerator : Nat := sampleUnionBound (Nat.choose 360447 58) (Nat.choose 13172 58)
def loss : Rat := (numerator : Rat) / (Nat.choose 8388608 58 : Rat)

theorem small_support_event_card (support : Finset Position) :
    (smallSupportEvent support).card ≤ Nat.choose 360447 58 := by
  change (if support.card < 360448 then sampleWithinEvent support 58 else ∅ :
    Finset (QuerySample Position 58)).card ≤ Nat.choose 360447 58
  by_cases small : support.card < 360448
  · rw [if_pos small]
    exact (sample_within_event_card support 58).le.trans
      (Nat.choose_le_choose 58 (by omega))
  · rw [if_neg small, Finset.card_empty]
    exact Nat.zero_le _

theorem root_event_card (point : Position → Goldilocks) (injective : Function.Injective point)
    (polynomial : Goldilocks[X]) (degree : polynomial.natDegree ≤ 13172) :
    (rootEvent point polynomial).card ≤ Nat.choose 13172 58 := by
  change (if polynomial ≠ 0 then sampleWithinEvent (L.currentRootIndices point polynomial) 58 else ∅ :
    Finset (QuerySample NativePrivateSpendQ58CurrentOrdinaryRecovery.Position 58)).card ≤ Nat.choose 13172 58
  by_cases nonzero : polynomial ≠ 0
  · rw [if_pos nonzero]
    exact (sample_within_event_card (L.currentRootIndices point polynomial) 58).le.trans
      (Nat.choose_le_choose 58
        ((L.current_root_indices_card point injective polynomial nonzero).trans degree))
  · rw [if_neg nonzero, Finset.card_empty]
    exact Nat.zero_le _

private theorem combination_sum_constant (value : Nat) :
    (∑ _combination : L.Combination, value) = 12 * value := by
  simp [L.Combination]

private theorem sample_union_card_le {Outcome : Type} [DecidableEq Outcome]
    (small : Finset Outcome) (events : L.Combination → Finset Outcome)
    (smallBound rootBound : Nat) (smallCard : small.card ≤ smallBound)
    (rootCard : ∀ combination, (events combination).card ≤ rootBound) :
    (small ∪ Finset.univ.biUnion events).card ≤ sampleUnionBound smallBound rootBound := by
  rw [sample_union_bound_eq]
  have roots : (Finset.univ.biUnion events).card ≤ 12 * rootBound := by
    calc
      _ ≤ ∑ combination : L.Combination, (events combination).card := Finset.card_biUnion_le
      _ ≤ ∑ _combination : L.Combination, rootBound := by
        exact Finset.sum_le_sum (fun combination _ => rootCard combination)
      _ = 12 * rootBound := combination_sum_constant rootBound
  have combined : small.card + (Finset.univ.biUnion events).card ≤
      smallBound + 12 * rootBound := Nat.add_le_add smallCard roots
  exact (Finset.card_union_le small (Finset.univ.biUnion events)).trans combined

/-- The twelve alternatives are actual Fin6 times Fin2, not fourteen blocks. -/
theorem current_decs_sample_event_card (point : Position → Goldilocks)
    (injective : Function.Injective point) (support : Finset Position)
    (discrepancies : Discrepancies) (degree : ∀ combination, (discrepancies combination).natDegree ≤ 13172) :
    (sampleEvent point support discrepancies).card ≤ numerator := by
  delta sampleEvent numerator
  with_reducible
    exact sample_union_card_le (smallSupportEvent support)
      (fun combination => rootEvent point (discrepancies combination))
      (Nat.choose 360447 58) (Nat.choose 13172 58)
      (small_support_event_card support)
      (fun combination => root_event_card point injective _ (degree combination))

theorem current_sample_event_probability (point : Position → Goldilocks)
    (injective : Function.Injective point) (support : Finset Position)
    (discrepancies : Discrepancies) (degree : ∀ combination, (discrepancies combination).natDegree ≤ 13172) :
    FiniteEvents.probability (sampleEvent point support discrepancies) ≤ loss := by
  unfold FiniteEvents.probability loss
  rw [U.query_card, Fintype.card_fin]
  exact div_le_div_of_nonneg_right
    (Nat.cast_le.mpr (current_decs_sample_event_card point injective support discrepancies degree))
    (Nat.cast_nonneg (Nat.choose 8388608 58))

/-- Exhaustion and rejection remain none and are not conditioned away. -/
theorem current_raw_decs_success_and_bad_probability (point : Position → Goldilocks)
    (injective : Function.Injective point) (support : Finset Position)
    (discrepancies : Discrepancies) (degree : ∀ combination, (discrepancies combination).natDegree ≤ 13172) :
    outputEventProbability (fun raw : Fin (digestCallCap 80) → V8Smz9CappedRawSampler.RawByteBlock =>
      ∃ query, U.rawDecoder raw = some query ∧ query ∈ sampleEvent point support discrepancies) ≤ loss :=
  (U.raw_bad_and_success_probability_le _).trans
    (current_sample_event_probability point injective support discrepancies degree)

/-- Injective restriction of the actual whole vector to its14 raw blocks;
no independent field-word or uniform-sample premise is introduced. -/
theorem current_vector_decs_success_and_bad_probability {Counter : Type}
    [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap 80) ↪ Counter)
    (point : Position → Goldilocks) (injective : Function.Injective point) (support : Finset Position)
    (discrepancies : Discrepancies) (degree : ∀ combination, (discrepancies combination).natDegree ≤ 13172) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ query, U.rawDecoder (selectedRawBlocks select vector) = some query ∧
        query ∈ sampleEvent point support discrepancies) ≤ loss := by
  exact (selected_raw_blocks_event_probability select
    (fun raw : Fin (digestCallCap 80) → V8Smz9CappedRawSampler.RawByteBlock =>
      ∃ query, U.rawDecoder raw = some query ∧ query ∈ sampleEvent point support discrepancies)).trans_le
    (current_raw_decs_success_and_bad_probability point injective support discrepancies degree)

private theorem sample_within_mem_iff {Index : Type} [Fintype Index]
    (support : Finset Index) (queryCount : Nat) (query : QuerySample Index queryCount) :
    query ∈ sampleWithinEvent support queryCount ↔ query.val ⊆ support := by
  classical
  simp only [sampleWithinEvent, Finset.mem_filter, Finset.mem_univ, true_and]

private theorem sample_within_filter_mem_iff {Index : Type} [Fintype Index]
    (queryCount : Nat) (predicate : Index → Prop) [DecidablePred predicate]
    (query : QuerySample Index queryCount) :
    query ∈ sampleWithinEvent (Finset.univ.filter predicate) queryCount ↔
      ∀ index ∈ query.val, predicate index := by
  classical
  rw [sample_within_mem_iff]
  simp only [Finset.subset_iff, Finset.mem_filter, Finset.mem_univ, true_and]

/-- Named event membership has only literal support or root conditions. -/
theorem mem_sample_event_iff (point : Position → Goldilocks) (support : Finset Position)
    (discrepancies : Discrepancies) (query : U.Query) :
    query ∈ sampleEvent point support discrepancies ↔
      (support.card < 360448 ∧ query.val ⊆ support) ∨
      ∃ combination, discrepancies combination ≠ 0 ∧
        ∀ index ∈ query.val, (discrepancies combination).eval (point index) = 0 := by
  simp only [sampleEvent, Finset.mem_union, Finset.mem_biUnion, Finset.mem_univ, true_and]
  have small : query ∈ smallSupportEvent support ↔ support.card < 360448 ∧ query.val ⊆ support := by
    let sample : QuerySample Position 58 := query
    change sample ∈ (if support.card < 360448 then sampleWithinEvent support 58 else ∅ :
      Finset (QuerySample Position 58)) ↔ support.card < 360448 ∧ sample.val ⊆ support
    by_cases h : support.card < 360448
    · rw [if_pos h]
      constructor
      · intro member
        exact ⟨h, (sample_within_mem_iff support 58 sample).mp member⟩
      · intro member
        exact (sample_within_mem_iff support 58 sample).mpr member.2
    · rw [if_neg h]
      constructor
      · intro member
        exact (Finset.notMem_empty sample member).elim
      · intro member
        exact (h member.1).elim
  rw [small]
  apply or_congr_right
  apply exists_congr
  intro combination
  let sample : QuerySample NativePrivateSpendQ58CurrentOrdinaryRecovery.Position 58 := query
  change sample ∈ (if discrepancies combination ≠ 0 then
    sampleWithinEvent (L.currentRootIndices point (discrepancies combination)) 58 else ∅ :
    Finset (QuerySample NativePrivateSpendQ58CurrentOrdinaryRecovery.Position 58)) ↔
    discrepancies combination ≠ 0 ∧
      ∀ index ∈ sample.val, (discrepancies combination).eval (point index) = 0
  by_cases h : discrepancies combination ≠ 0
  · rw [if_pos h]
    have roots : sample ∈ sampleWithinEvent (L.currentRootIndices point (discrepancies combination)) 58 ↔
        ∀ index ∈ sample.val, (discrepancies combination).eval (point index) = 0 := by
      delta L.currentRootIndices
      exact sample_within_filter_mem_iff 58
        (fun index => (discrepancies combination).eval (point index) = 0) sample
    constructor
    · intro member
      exact ⟨h, roots.mp member⟩
    · intro member
      exact roots.mpr member.2
  · rw [if_neg h]
    constructor
    · intro member
      exact (Finset.notMem_empty sample member).elim
    · intro member
      exact (h member.1).elim

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsSampleDensity

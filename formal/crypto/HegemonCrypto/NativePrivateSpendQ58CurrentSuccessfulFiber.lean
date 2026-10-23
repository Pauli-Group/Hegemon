import HegemonCrypto.NativePrivateSpendQ58CurrentGeometry
import SmzaRp04RawRoleSamplingQ38
import Mathlib.Data.Finset.Sort

/-! Current SMZD 80-candidate/58-opening deterministic sampling.
Only the inherited one-coordinate Goldilocks/domain permutation is reused;
the historical 50-candidate/38-opening decoder is not used. The source returns
sorted indices, hence canonical 58-subsets, not arbitrary ordered injections.
F1 interprets the literal reject/first-distinct/sort postprocessor. F4 supplies
the ideal uniform raw-block law; neither is a desired equal-fiber premise. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSuccessfulFiber

open SmzaRp04RawRoleSampling
open HegemonCrypto.CmsClassicalDatabase V8Smz9RobustQueryMismatch
open SmzaQ38McaSourceBinding
open V8Smz9RuntimeRandomness V8Smz9CappedRawSampler V8Smz9RawCounterCompiler
open V8Smz9CoherentMerkleInstrument V8Smz9CoherentVectorMerkle
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev CandidateStream := FieldOutput sourceFieldSize 80
abbrev Query := V8Smz9McaRecovery.QuerySample SmzaQ38McaSourceBinding.Position 58

/-- Current and retained q38 share only the single-coordinate index domain. -/
theorem current_domain_eq_coordinate_domain :
    NativePrivateSpendQ58CurrentGeometry.domain = q38DomainSize := by
  rw [q38_sampling_geometry.1]
  rfl

/-- The reused coordinate predicate has the literal current native bound. -/
theorem current_accepted_bound_is_native :
    q38AcceptedFactorBound =
      (fieldModulus / NativePrivateSpendQ58CurrentGeometry.domain) *
        NativePrivateSpendQ58CurrentGeometry.domain := by
  rw [current_domain_eq_coordinate_domain, q38_accepted_factor_bound_eq_source]
  rfl

/-- Reverse/dedup/reverse keeps first occurrences; take58 implements the
source break after its58th successful seen.insert. Rejected words are skipped. -/
def firstDistinct (candidates : List IdealFieldCoin) : List SmzaQ38McaSourceBinding.Position :=
  ((candidates.filterMap q38CandidateIndex).reverse.dedup.reverse).take 58

def selectedSet (candidates : List IdealFieldCoin) : Finset SmzaQ38McaSourceBinding.Position :=
  (firstDistinct candidates).toFinset

def streamCandidates (stream : CandidateStream) : List IdealFieldCoin :=
  List.ofFn stream

theorem first_distinct_nodup (candidates : List IdealFieldCoin) :
    (firstDistinct candidates).Nodup := by
  unfold firstDistinct
  have deduplicated :
      ((candidates.filterMap q38CandidateIndex).reverse.dedup).Nodup :=
    List.nodup_dedup ((candidates.filterMap q38CandidateIndex).reverse)
  have reversed :
      ((candidates.filterMap q38CandidateIndex).reverse.dedup.reverse).Nodup :=
    List.nodup_reverse.mpr deduplicated
  exact List.Pairwise.take (i := 58) reversed

/-- Cardinality failure is exactly the native selected-vector length failure. -/
theorem selected_card_eq_length (candidates : List IdealFieldCoin) :
    (selectedSet candidates).card = (firstDistinct candidates).length := by
  exact List.toFinset_card_of_nodup (first_distinct_nodup candidates)

theorem first_distinct_permutation (permutation : Equiv.Perm SmzaQ38McaSourceBinding.Position)
    (candidates : List IdealFieldCoin) :
    firstDistinct (candidates.map (q38CandidatePermutation permutation)) =
      (firstDistinct candidates).map permutation := by
  unfold firstDistinct
  rw [q38_filterMap_candidate_permutation, ← List.map_reverse,
    List.dedup_map_of_injective permutation.injective, ← List.map_reverse]
  simp

theorem selected_set_permutation (permutation : Equiv.Perm SmzaQ38McaSourceBinding.Position)
    (candidates : List IdealFieldCoin) :
    selectedSet (candidates.map (q38CandidatePermutation permutation)) =
      (selectedSet candidates).map permutation.toEmbedding := by
  ext index
  simp only [selectedSet, first_distinct_permutation,
    List.mem_toFinset, List.mem_map, Finset.mem_map]
  constructor
  · rintro ⟨source, member, equal⟩
    exact ⟨source, member, by simpa using equal⟩
  · rintro ⟨source, member, equal⟩
    exact ⟨source, member, by simpa using equal⟩

noncomputable def streamPermutation (permutation : Equiv.Perm SmzaQ38McaSourceBinding.Position) :
    Equiv.Perm CandidateStream :=
  Equiv.piCongrRight fun _ => q38CandidatePermutation permutation

theorem stream_selected_set_permutation (permutation : Equiv.Perm SmzaQ38McaSourceBinding.Position)
    (stream : CandidateStream) :
    selectedSet (streamCandidates (streamPermutation permutation stream)) =
      (selectedSet (streamCandidates stream)).map permutation.toEmbedding := by
  have candidates : streamCandidates (streamPermutation permutation stream) =
      (streamCandidates stream).map (q38CandidatePermutation permutation) :=
    List.ofFn_comp' stream (q38CandidatePermutation permutation)
  rw [candidates, selected_set_permutation]

def SelectingStreams (sample : Finset SmzaQ38McaSourceBinding.Position) :=
  { stream : CandidateStream // selectedSet (streamCandidates stream) = sample }

private theorem candidateStream_finite : Finite CandidateStream := inferInstance

noncomputable instance selectingStreamsFintype (sample : Finset SmzaQ38McaSourceBinding.Position) :
    Fintype (SelectingStreams sample) := by
  letI : Finite CandidateStream := candidateStream_finite
  letI : Finite (SelectingStreams sample) :=
    Finite.of_injective (fun stream : SelectingStreams sample =>
      (stream.val : CandidateStream)) Subtype.val_injective
  exact Fintype.ofFinite (SelectingStreams sample)

attribute [local irreducible]
  selectingStreamsFintype successfulFiberFintype V8Smz9McaRecovery.querySampleFintype

noncomputable def selectingStreamsEquiv (permutation : Equiv.Perm SmzaQ38McaSourceBinding.Position)
    (source target : Finset SmzaQ38McaSourceBinding.Position)
    (mapped : source.map permutation.toEmbedding = target) :
    SelectingStreams source ≃ SelectingStreams target :=
  (streamPermutation permutation).subtypeEquiv (by
    intro stream
    rw [stream_selected_set_permutation]
    constructor
    · intro same
      rw [same, mapped]
    · intro same
      apply Finset.map_injective permutation.toEmbedding
      exact same.trans mapped.symm)

theorem selecting_streams_nat_card_equal (source target : Finset SmzaQ38McaSourceBinding.Position)
    (sameCard : source.card = target.card) :
    Nat.card (SelectingStreams source) = Nat.card (SelectingStreams target) := by
  obtain ⟨permutation, mapped⟩ :=
    Equiv.Perm.exists_map_finset_eq source target sameCard
  exact Nat.card_congr (selectingStreamsEquiv permutation source target mapped)

/-- Exact partial postprocessor: fail on fewer than58 distinct accepted
indices. Sorting is represented by canonicalSorted below. -/
def decoder (stream : CandidateStream) : Option Query :=
  let selected := selectedSet (streamCandidates stream)
  if enough : selected.card = 58 then some ⟨selected, enough⟩ else none

theorem decoder_eq_some_iff (stream : CandidateStream) (query : Query) :
    decoder stream = some query ↔ selectedSet (streamCandidates stream) = query.val := by
  dsimp only [decoder]
  split_ifs with enough
  · constructor
    · intro equal
      exact congrArg Subtype.val (Option.some.inj equal)
    · intro equal
      apply congrArg some
      exact Subtype.ext equal
  · constructor
    · intro impossible
      simp at impossible
    · intro equal
      exfalso
      apply enough
      rw [equal]
      exact query.property

/-- No equal-fiber premise: a lifted domain permutation constructs the bijection. -/
theorem decoder_fibers_nat_card_equal (left right : Query) :
    Nat.card (SuccessfulFiber decoder left) =
      Nat.card (SuccessfulFiber decoder right) := by
  calc
    _ = Nat.card (SelectingStreams left.val) := by
      apply Nat.card_congr
      exact Equiv.subtypeEquivRight fun stream => decoder_eq_some_iff stream left
    _ = Nat.card (SelectingStreams right.val) :=
      selecting_streams_nat_card_equal left.val right.val
        (left.property.trans right.property.symm)
    _ = _ := by
      symm
      apply Nat.card_congr
      exact Equiv.subtypeEquivRight fun stream => decoder_eq_some_iff stream right

theorem decoder_fibers_equal (left right : Query) :
    Fintype.card (SuccessfulFiber decoder left) =
      Fintype.card (SuccessfulFiber decoder right) := by
  simpa only [Nat.card_eq_fintype_card] using decoder_fibers_nat_card_equal left right

/-- Native sort_unstable's unique ascending serialization of one58-subset. -/
def canonicalSorted (query : Query) : List SmzaQ38McaSourceBinding.Position := query.val.sort (· ≤ ·)

theorem canonical_sorted_geometry (query : Query) :
    (canonicalSorted query).length = 58 ∧
    (canonicalSorted query).Nodup ∧
    (canonicalSorted query).Pairwise (· ≤ ·) := by
  refine ⟨?_, ?_, ?_⟩
  · simpa only [canonicalSorted, Finset.length_sort] using query.property
  · exact Finset.sort_nodup _ _
  · exact Finset.pairwise_sort _ _

def sortedDecoder (stream : CandidateStream) : Option (List SmzaQ38McaSourceBinding.Position) :=
  (decoder stream).map canonicalSorted

theorem sorted_decoder_eq_some_iff (stream : CandidateStream) (query : Query) :
    sortedDecoder stream = some (canonicalSorted query) ↔ decoder stream = some query := by
  cases decoded : decoder stream with
  | none => simp [sortedDecoder, decoded]
  | some selected =>
      simp only [sortedDecoder, decoded, Option.map_some, Option.some.injEq]
      constructor
      · intro same
        apply Subtype.ext
        have sets := congrArg List.toFinset same
        simpa only [canonicalSorted, Finset.sort_toFinset] using sets
      · rintro rfl
        rfl

/-- Equal successful fibers for ACTUAL canonical ascending58 outputs. -/
theorem canonical_sorted_fibers_equal (left right : Query) :
    Fintype.card (SuccessfulFiber sortedDecoder (canonicalSorted left)) =
      Fintype.card (SuccessfulFiber sortedDecoder (canonicalSorted right)) := by
  have natEqual :
      Nat.card (SuccessfulFiber sortedDecoder (canonicalSorted left)) =
        Nat.card (SuccessfulFiber sortedDecoder (canonicalSorted right)) := by
    calc
      _ = Nat.card (SuccessfulFiber decoder left) := by
        apply Nat.card_congr
        exact Equiv.subtypeEquivRight fun stream => sorted_decoder_eq_some_iff stream left
      _ = Nat.card (SuccessfulFiber decoder right) := decoder_fibers_nat_card_equal left right
      _ = _ := by
        symm
        apply Nat.card_congr
        exact Equiv.subtypeEquivRight fun stream => sorted_decoder_eq_some_iff stream right
  simpa only [Nat.card_eq_fintype_card] using natEqual

/-- The success space has choose(8388608,58) outputs, not58! extra orderings. -/
theorem query_card : Fintype.card Query = Nat.choose (Fintype.card SmzaQ38McaSourceBinding.Position) 58 :=
  V8Smz9McaRecovery.query_sample_card 58

private noncomputable instance queryNonempty : Nonempty Query := by
  let embedding : Fin 58 ↪ SmzaQ38McaSourceBinding.Position :=
    { toFun := fun index => ⟨index.val, index.isLt.trans (by decide)⟩
      inj' := by
        intro left right same
        exact Fin.ext (congrArg
          (fun index : SmzaQ38McaSourceBinding.Position => index.val) same) }
  exact ⟨⟨Finset.univ.map embedding, by simp⟩⟩

/-- Capped SHA512 field rejection precedes the current80→58 postprocessor.
This is a uniform finite-block statement; failure remains in the denominator. -/
def rawDecoder (raw : Fin (digestCallCap 80) → RawByteBlock) : Option Query :=
  (rawFieldSample (digestCallCap 80) 80 raw).bind decoder

theorem current_raw_digest_cap : digestCallCap 80 = 14 := rfl

theorem raw_bad_and_success_probability_le (bad : Finset Query) :
    outputEventProbability (fun raw : Fin (digestCallCap 80) → RawByteBlock =>
      ∃ query, rawDecoder raw = some query ∧ query ∈ bad) ≤
      FiniteEvents.probability bad := by
  simpa only [rawDecoder] using
    (raw_field_then_partial_decoder_bad_le (digestCallCap 80) 80 decoder
      decoder_fibers_equal bad)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSuccessfulFiber

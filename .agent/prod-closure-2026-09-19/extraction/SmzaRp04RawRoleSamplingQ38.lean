import SmzaRp04RawRoleSamplingQ38Arithmetic

/-!
# Actual RP04 q38 raw-role decoder

This module contains the exact 50-word, first-38-distinct decoder and its
successful-fiber symmetry.  Rejected field residues and exhausted streams
remain represented by `none`.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling

open HegemonCrypto.CmsClassicalDatabase
open V8Smz9RuntimeDistribution V8Smz9RuntimeRandomness
open V8Smz9RuntimeFieldLayout V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8Smz9HiddenLeafQrom
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdmissibleRootProbability
open SmzaQ38OracleExtraction SmzaQ38McaSourceBinding
open scoped BigOperators Classical

noncomputable section

set_option maxHeartbeats 1500000
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024
set_option Elab.async false

attribute [local irreducible]
  V8Smz9McaRecovery.querySampleFintype

/-! ## The current 50-word, first-38-distinct DECS decoder -/

/-- The source's accepted-candidate bound, represented by the checked
Goldilocks factorization rather than re-evaluating the closed natural-number
division inside every executable predicate and subtype instance. -/
def q38AcceptedFactorBound : Nat :=
  q38GoldilocksFactor * q38DomainSize

theorem q38_accepted_factor_bound_eq_source :
    q38AcceptedFactorBound = q38AcceptedCandidateCount := by
  rw [q38AcceptedFactorBound, q38AcceptedCandidateCount,
    q38_quotient_eq_factor]

theorem q38_accepted_factor_bound_is_modulus_minus_one :
    q38AcceptedFactorBound = fieldModulus - 1 :=
  q38_accepted_factor_bound_eq_source.trans
    q38_accepted_candidate_count_is_modulus_minus_one

def q38CandidateIndex (candidate : IdealFieldCoin) : Option Position :=
  if _accepted : candidate.val < q38AcceptedFactorBound then
    some ⟨candidate.val % q38DomainSize,
      Nat.mod_lt _ q38_domain_size_positive⟩
  else none

def Q38AcceptedFiber (index : Position) :=
  { candidate : IdealFieldCoin //
      candidate.val < q38AcceptedFactorBound ∧
        candidate.val % q38DomainSize = index.val }

def q38EncodeFiber (index : Position)
    (part : Fin q38GoldilocksFactor) : Q38AcceptedFiber index := by
  let value := part.val * q38DomainSize + index.val
  have belowNextPart : value < (part.val + 1) * q38DomainSize := by
    calc
      value = part.val * q38DomainSize + index.val := rfl
      _ < part.val * q38DomainSize + q38DomainSize :=
        Nat.add_lt_add_left index.isLt _
      _ = (part.val + 1) * q38DomainSize := by
        rw [Nat.add_mul, Nat.one_mul]
  have nextPartBound :
      (part.val + 1) * q38DomainSize ≤
        q38GoldilocksFactor * q38DomainSize :=
    Nat.mul_le_mul_right q38DomainSize (Nat.succ_le_iff.mpr part.isLt)
  have accepted : value < q38AcceptedFactorBound := by
    rw [q38AcceptedFactorBound]
    exact belowNextPart.trans_le nextPartBound
  have belowModulus : value < fieldModulus := by
    have acceptedCommuted :
        value < q38DomainSize * q38GoldilocksFactor := by
      simpa [q38AcceptedFactorBound, Nat.mul_comm] using accepted
    rw [q38_goldilocks_factorization]
    exact acceptedCommuted.trans (Nat.lt_succ_self _)
  refine ⟨⟨value, belowModulus⟩, accepted, ?_⟩
  simp [value, Nat.add_mod,
    Nat.mod_eq_of_lt (position_lt_q38_domain index)]

def q38DecodeFiber (index : Position)
    (candidate : Q38AcceptedFiber index) : Fin q38GoldilocksFactor :=
  ⟨candidate.val.val / q38DomainSize,
    (Nat.div_lt_iff_lt_mul q38_domain_size_positive).2 (by
      simpa [q38AcceptedFactorBound, Nat.mul_comm] using candidate.property.1)⟩

theorem q38_decode_encode_fiber (index : Position)
    (part : Fin q38GoldilocksFactor) :
    q38DecodeFiber index (q38EncodeFiber index part) = part := by
  apply Fin.ext
  change (part.val * q38DomainSize + index.val) / q38DomainSize = part.val
  rw [Nat.add_comm,
    Nat.add_mul_div_right index.val part.val q38_domain_size_positive,
    Nat.div_eq_of_lt (position_lt_q38_domain index), Nat.zero_add]

theorem q38_encode_decode_fiber (index : Position)
    (candidate : Q38AcceptedFiber index) :
    q38EncodeFiber index (q38DecodeFiber index candidate) = candidate := by
  apply Subtype.ext
  apply Fin.ext
  change candidate.val.val / q38DomainSize * q38DomainSize + index.val =
    candidate.val.val
  calc
    candidate.val.val / q38DomainSize * q38DomainSize + index.val =
        index.val + q38DomainSize * (candidate.val.val / q38DomainSize) := by
      ac_rfl
    _ = candidate.val.val % q38DomainSize +
        q38DomainSize * (candidate.val.val / q38DomainSize) := by
      exact congrArg
        (fun remainder => remainder +
          q38DomainSize * (candidate.val.val / q38DomainSize))
        candidate.property.2.symm
    _ = candidate.val.val := Nat.mod_add_div _ _

def q38AcceptedCoordinateMap
    (coordinate : Fin q38GoldilocksFactor × Position) :
    { candidate : IdealFieldCoin //
      candidate.val < q38AcceptedFactorBound } :=
  ⟨(q38EncodeFiber coordinate.2 coordinate.1).val,
    (q38EncodeFiber coordinate.2 coordinate.1).property.1⟩

/-- Project the already proved finite-fiber inverse to its quotient value.
Keeping this equation opaque avoids unfolding the dependent fiber inverse
inside the global coordinates equivalence. -/
theorem q38_encoded_quotient (index : Position)
    (part : Fin q38GoldilocksFactor) :
    (q38EncodeFiber index part).val.val / q38DomainSize = part.val := by
  exact congrArg Fin.val (q38_decode_encode_fiber index part)

theorem q38AcceptedCoordinateMap_injective :
    Function.Injective q38AcceptedCoordinateMap := by
  intro left right same
  have values :
      (q38EncodeFiber left.2 left.1).val.val =
        (q38EncodeFiber right.2 right.1).val.val :=
    congrArg (fun candidate => candidate.val.val) same
  apply Prod.ext
  · apply Fin.ext
    calc
      left.1.val =
          (q38EncodeFiber left.2 left.1).val.val / q38DomainSize :=
        (q38_encoded_quotient left.2 left.1).symm
      _ = (q38EncodeFiber right.2 right.1).val.val / q38DomainSize :=
        congrArg (fun value => value / q38DomainSize) values
      _ = right.1.val := q38_encoded_quotient right.2 right.1
  · apply Fin.ext
    calc
      left.2.val =
          (q38EncodeFiber left.2 left.1).val.val % q38DomainSize :=
        (q38EncodeFiber left.2 left.1).property.2.symm
      _ = (q38EncodeFiber right.2 right.1).val.val % q38DomainSize :=
        congrArg (fun value => value % q38DomainSize) values
      _ = right.2.val := (q38EncodeFiber right.2 right.1).property.2

theorem q38AcceptedCoordinateMap_surjective :
    Function.Surjective q38AcceptedCoordinateMap := by
  intro candidate
  let index : Position :=
    ⟨candidate.val.val % q38DomainSize,
      Nat.mod_lt _ q38_domain_size_positive⟩
  let fiber : Q38AcceptedFiber index :=
    ⟨candidate.val, candidate.property, rfl⟩
  refine ⟨(q38DecodeFiber index fiber, index), ?_⟩
  apply Subtype.ext
  change (q38EncodeFiber index (q38DecodeFiber index fiber)).val = candidate.val
  exact congrArg (fun chosen : Q38AcceptedFiber index => chosen.val)
    (q38_encode_decode_fiber index fiber)

/-- The forward map is the same concrete quotient/residue encoding.
Construct the inverse from its proved bijectivity rather than elaborating
a dependent inverse inside the equivalence structure. -/
noncomputable def q38AcceptedCoordinatesEquiv :
    (Fin q38GoldilocksFactor × Position) ≃
      { candidate : IdealFieldCoin //
        candidate.val < q38AcceptedFactorBound } :=
  Equiv.ofBijective q38AcceptedCoordinateMap
    ⟨q38AcceptedCoordinateMap_injective, q38AcceptedCoordinateMap_surjective⟩

noncomputable def q38CandidatePermutation
    (permutation : Equiv.Perm Position) : Equiv.Perm IdealFieldCoin :=
  Equiv.Perm.extendDomain
    ((Equiv.refl (Fin q38GoldilocksFactor)).prodCongr permutation)
    q38AcceptedCoordinatesEquiv

theorem q38_candidate_permutation_encode_fiber
    (permutation : Equiv.Perm Position) (index : Position)
    (part : Fin q38GoldilocksFactor) :
    q38CandidatePermutation permutation (q38EncodeFiber index part).val =
      (q38EncodeFiber (permutation index) part).val := by
  exact Equiv.Perm.extendDomain_apply_image
    ((Equiv.refl (Fin q38GoldilocksFactor)).prodCongr permutation)
    q38AcceptedCoordinatesEquiv (part, index)

theorem q38_candidate_permutation_rejected
    (permutation : Equiv.Perm Position) (candidate : IdealFieldCoin)
    (rejected : ¬candidate.val < q38AcceptedFactorBound) :
    q38CandidatePermutation permutation candidate = candidate := by
  exact Equiv.Perm.extendDomain_apply_not_subtype
    ((Equiv.refl (Fin q38GoldilocksFactor)).prodCongr permutation)
    q38AcceptedCoordinatesEquiv rejected

theorem q38_candidate_index_permutation
    (permutation : Equiv.Perm Position) (candidate : IdealFieldCoin) :
    q38CandidateIndex (q38CandidatePermutation permutation candidate) =
      (q38CandidateIndex candidate).map permutation := by
  by_cases accepted : candidate.val < q38AcceptedFactorBound
  · let index : Position :=
      ⟨candidate.val % q38DomainSize, Nat.mod_lt _ q38_domain_size_positive⟩
    let fiber : Q38AcceptedFiber index := ⟨candidate, accepted, rfl⟩
    let part : Fin q38GoldilocksFactor := q38DecodeFiber index fiber
    have represented : (q38EncodeFiber index part).val = candidate := by
      have restored := q38_encode_decode_fiber index fiber
      exact congrArg (fun selected => selected.val) restored
    rw [← represented, q38_candidate_permutation_encode_fiber]
    simp [q38CandidateIndex, (q38EncodeFiber index part).property.1,
      (q38EncodeFiber index part).property.2,
      (q38EncodeFiber (permutation index) part).property.1,
      (q38EncodeFiber (permutation index) part).property.2]
  · rw [q38_candidate_permutation_rejected permutation candidate accepted]
    simp [q38CandidateIndex, accepted]

theorem q38_filterMap_candidate_permutation
    (permutation : Equiv.Perm Position) (candidates : List IdealFieldCoin) :
    (candidates.map (q38CandidatePermutation permutation)).filterMap
        q38CandidateIndex =
      (candidates.filterMap q38CandidateIndex).map permutation := by
  induction candidates with
  | nil => rfl
  | cons candidate candidates inductionHypothesis =>
      rw [List.map_cons, List.filterMap_cons,
        q38_candidate_index_permutation, List.filterMap_cons,
        inductionHypothesis]
      cases q38CandidateIndex candidate <;> rfl

def q38FirstDistinctIndices (candidates : List IdealFieldCoin) : List Position :=
  -- `List.dedup` keeps the last occurrence. Reverse twice to match the
  -- source's left-to-right `seen.insert` before taking the first38.
  ((candidates.filterMap q38CandidateIndex).reverse.dedup.reverse).take q38OpeningCount

def q38SelectedIndexSet (candidates : List IdealFieldCoin) : Finset Position :=
  (q38FirstDistinctIndices candidates).toFinset

theorem q38_first_distinct_indices_permutation
    (permutation : Equiv.Perm Position) (candidates : List IdealFieldCoin) :
    q38FirstDistinctIndices
        (candidates.map (q38CandidatePermutation permutation)) =
      (q38FirstDistinctIndices candidates).map permutation := by
  unfold q38FirstDistinctIndices
  rw [q38_filterMap_candidate_permutation, ← List.map_reverse,
    List.dedup_map_of_injective permutation.injective, ← List.map_reverse]
  simp

theorem q38_selected_index_set_permutation
    (permutation : Equiv.Perm Position) (candidates : List IdealFieldCoin) :
    q38SelectedIndexSet
        (candidates.map (q38CandidatePermutation permutation)) =
      (q38SelectedIndexSet candidates).map permutation.toEmbedding := by
  ext index
  simp only [q38SelectedIndexSet, q38_first_distinct_indices_permutation,
    List.mem_toFinset, List.mem_map, Finset.mem_map]
  constructor
  · rintro ⟨source, sourceMembership, sourceImage⟩
    exact ⟨source, sourceMembership, by simpa using sourceImage⟩
  · rintro ⟨source, sourceMembership, sourceImage⟩
    exact ⟨source, sourceMembership, by simpa using sourceImage⟩

abbrev Q38CandidateStream :=
  FieldOutput sourceFieldSize q38CandidateCount

def q38StreamCandidates (stream : Q38CandidateStream) : List IdealFieldCoin :=
  List.ofFn stream

noncomputable def q38CandidateStreamPermutation
    (permutation : Equiv.Perm Position) : Equiv.Perm Q38CandidateStream :=
  Equiv.piCongrRight fun _ => q38CandidatePermutation permutation

theorem q38_stream_candidates_permutation
    (permutation : Equiv.Perm Position) (stream : Q38CandidateStream) :
    q38StreamCandidates (q38CandidateStreamPermutation permutation stream) =
      (q38StreamCandidates stream).map (q38CandidatePermutation permutation) := by
  exact List.ofFn_comp' stream (q38CandidatePermutation permutation)

theorem q38_stream_selected_set_permutation
    (permutation : Equiv.Perm Position) (stream : Q38CandidateStream) :
    q38SelectedIndexSet
        (q38StreamCandidates (q38CandidateStreamPermutation permutation stream)) =
      (q38SelectedIndexSet (q38StreamCandidates stream)).map
        permutation.toEmbedding := by
  rw [q38_stream_candidates_permutation,
    q38_selected_index_set_permutation]

def Q38SelectingStreams (sample : Finset Position) :=
  { stream : Q38CandidateStream //
      q38SelectedIndexSet (q38StreamCandidates stream) = sample }

/-- Keep finiteness of the 50-coordinate input in an opaque proposition.
The fiber symmetry below needs a bijection, not an enumeration of this
function space or evaluation of the decoder on its elements. -/
private theorem q38CandidateStream_finite : Finite Q38CandidateStream :=
  inferInstance

noncomputable instance q38SelectingStreamsFintype
    (sample : Finset Position) : Fintype (Q38SelectingStreams sample) := by
  letI : Finite Q38CandidateStream := q38CandidateStream_finite
  letI : Finite (Q38SelectingStreams sample) :=
    Finite.of_injective
      (fun stream : Q38SelectingStreams sample =>
        (stream.val : Q38CandidateStream)) Subtype.val_injective
  exact Fintype.ofFinite (Q38SelectingStreams sample)

-- Cardinality is independent of these enumeration dictionaries. In
-- particular, elaborating an equivalence must not unfold the concrete
-- classical subtype filter over all 50-word field streams.
attribute [local irreducible]
  q38SelectingStreamsFintype successfulFiberFintype

noncomputable def q38SelectingStreamsEquiv
    (permutation : Equiv.Perm Position)
    (source target : Finset Position)
    (mapped : source.map permutation.toEmbedding = target) :
    Q38SelectingStreams source ≃ Q38SelectingStreams target :=
  (q38CandidateStreamPermutation permutation).subtypeEquiv (by
    intro stream
    rw [q38_stream_selected_set_permutation]
    constructor
    · intro sourceEquation
      rw [sourceEquation, mapped]
    · intro targetEquation
      apply Finset.map_injective permutation.toEmbedding
      exact targetEquation.trans mapped.symm)

theorem q38_selecting_streams_nat_card_eq_of_card_eq
    (source target : Finset Position) (sameCardinality : source.card = target.card) :
    Nat.card (Q38SelectingStreams source) =
      Nat.card (Q38SelectingStreams target) := by
  obtain ⟨permutation, mapped⟩ :=
    Equiv.Perm.exists_map_finset_eq source target sameCardinality
  exact Nat.card_congr
    (q38SelectingStreamsEquiv permutation source target mapped)

theorem q38_selecting_streams_card_eq_of_card_eq
    (source target : Finset Position) (sameCardinality : source.card = target.card) :
    Fintype.card (Q38SelectingStreams source) =
      Fintype.card (Q38SelectingStreams target) := by
  simpa only [Nat.card_eq_fintype_card] using
    q38_selecting_streams_nat_card_eq_of_card_eq source target sameCardinality

/-- The exact deployed deterministic postprocessor: reject the top field
residue, keep first distinct indices, take 38, and fail closed on exhaustion.
Sorting affects serialization only, not the `Query` finset. -/
def q38Decoder (stream : Q38CandidateStream) : Option Query :=
  let selected := q38SelectedIndexSet (q38StreamCandidates stream)
  if enough : selected.card = q38OpeningCount then
    some ⟨selected, by simpa [q38OpeningCount] using enough⟩
  else none

theorem q38_decoder_eq_some_iff (stream : Q38CandidateStream) (query : Query) :
    q38Decoder stream = some query ↔
      q38SelectedIndexSet (q38StreamCandidates stream) = query.val := by
  dsimp only [q38Decoder]
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
      simpa [q38OpeningCount] using query.property

theorem q38_decoder_fibers_nat_card_equal (left right : Query) :
    Nat.card (SuccessfulFiber q38Decoder left) =
      Nat.card (SuccessfulFiber q38Decoder right) := by
  calc
    Nat.card (SuccessfulFiber q38Decoder left) =
        Nat.card (Q38SelectingStreams left.val) := by
      apply Nat.card_congr
      exact Equiv.subtypeEquivRight fun stream =>
        q38_decoder_eq_some_iff stream left
    _ = Nat.card (Q38SelectingStreams right.val) :=
      q38_selecting_streams_nat_card_eq_of_card_eq left.val right.val
        (left.property.trans right.property.symm)
    _ = Nat.card (SuccessfulFiber q38Decoder right) := by
      symm
      apply Nat.card_congr
      exact Equiv.subtypeEquivRight fun stream =>
        q38_decoder_eq_some_iff stream right

theorem q38_decoder_fibers_equal (left right : Query) :
    Fintype.card (SuccessfulFiber q38Decoder left) =
      Fintype.card (SuccessfulFiber q38Decoder right) := by
  simpa only [Nat.card_eq_fintype_card] using
    q38_decoder_fibers_nat_card_equal left right

/-- This explicitly uses the current q38 output type, whose size is the
38-subset count from `UniformSubsetSampling`, rather than the legacy logical
twenty-subset. -/
theorem q38_query_card :
    Fintype.card Query = Nat.choose (Fintype.card Position) 38 := by
  exact V8Smz9McaRecovery.query_sample_card (Position := Position) 38

end
end HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling

import HegemonCrypto.SmallWoodTranscript
import HegemonCrypto.Goldilocks
import Mathlib.Data.Fintype.Card
import Mathlib.Data.Fintype.OfMap
import Mathlib.Data.Fintype.Pi
import Mathlib.Data.Fintype.Sets
import Mathlib.Data.Finset.Image
import Mathlib.Data.List.Dedup
import Mathlib.Data.List.Nodup
import Mathlib.Data.List.OfFn
import Mathlib.Logic.Equiv.Fintype

/-!
# Fixed-work SmallWood DECS sampling

The active Level-5 transcript draws 50 canonical Goldilocks words, rejects the unique top residue
that would bias reduction modulo `2^20`, keeps the first 20 distinct indices, and sorts them.
There is no prover-selected DECS nonce.

This file proves the deterministic sampler properties and the exact equal-fiber arithmetic behind
unbiased reduction.  It also checks a conservative integer envelope for fixed-pool exhaustion.
-/

namespace HegemonCrypto.SmallWood.FixedSampling

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

def domainSize : Nat := 2 ^ 20
def openingCount : Nat := SmallWoodTranscript.activeParameters.decsOpenedEvaluations
def candidateCount : Nat := SmallWoodTranscript.activeDecsFixedCandidateCount
def quotient : Nat := goldilocksModulus / domainSize
def acceptedCandidateCount : Nat := quotient * domainSize

theorem active_sampling_geometry :
    domainSize = 1048576 ∧ openingCount = 20 ∧ candidateCount = 50 := by
  decide

theorem goldilocks_mod_domain_is_one :
    goldilocksModulus % domainSize = 1 := by
  decide

theorem accepted_candidate_count_is_modulus_minus_one :
    acceptedCandidateCount = goldilocksModulus - 1 := by
  decide

theorem domain_size_positive : 0 < domainSize := by
  decide

theorem quotient_positive : 0 < quotient := by
  decide

abbrev FieldWord := SmallWoodTranscript.FieldWord
abbrev DomainIndex := Fin domainSize

/-- Canonical unbiased reduction, rejecting only the final Goldilocks representative. -/
def candidateIndex (candidate : FieldWord) : Option DomainIndex :=
  if _accepted : candidate.val < acceptedCandidateCount then
    some ⟨candidate.val % domainSize, Nat.mod_lt _ domain_size_positive⟩
  else
    none

/-- All accepted field words that reduce to one fixed DECS index. -/
def AcceptedFiber (index : DomainIndex) :=
  { candidate : FieldWord //
      candidate.val < acceptedCandidateCount ∧
        candidate.val % domainSize = index.val }

def encodeFiber
    (index : DomainIndex)
    (part : Fin quotient) : AcceptedFiber index := by
  let value := part.val * domainSize + index.val
  have belowNextPart :
      value < (part.val + 1) * domainSize := by
    calc
      value = part.val * domainSize + index.val := rfl
      _ < part.val * domainSize + domainSize :=
        Nat.add_lt_add_left index.isLt (part.val * domainSize)
      _ = (part.val + 1) * domainSize := by
        rw [Nat.add_mul, Nat.one_mul]
  have nextPartBound :
      (part.val + 1) * domainSize ≤ quotient * domainSize := by
    exact Nat.mul_le_mul_right domainSize (Nat.succ_le_iff.mpr part.isLt)
  have accepted : value < acceptedCandidateCount := by
    exact belowNextPart.trans_le nextPartBound
  have belowModulus : value < goldilocksModulus := by
    rw [accepted_candidate_count_is_modulus_minus_one] at accepted
    omega
  refine ⟨⟨value, belowModulus⟩, accepted, ?_⟩
  simp [value, Nat.add_mod, Nat.mod_eq_of_lt index.isLt]

def decodeFiber
    (index : DomainIndex)
    (candidate : AcceptedFiber index) : Fin quotient :=
  ⟨candidate.val.val / domainSize,
    (Nat.div_lt_iff_lt_mul domain_size_positive).2 (by
      simpa [acceptedCandidateCount, Nat.mul_comm] using candidate.property.1)⟩

theorem decode_encode_fiber
    (index : DomainIndex)
    (part : Fin quotient) :
    decodeFiber index (encodeFiber index part) = part := by
  apply Fin.ext
  change
    (part.val * domainSize + index.val) / domainSize = part.val
  rw [Nat.add_comm, Nat.add_mul_div_right index.val part.val domain_size_positive,
    Nat.div_eq_of_lt index.isLt, Nat.zero_add]

theorem encode_decode_fiber
    (index : DomainIndex)
    (candidate : AcceptedFiber index) :
    encodeFiber index (decodeFiber index candidate) = candidate := by
  apply Subtype.ext
  apply Fin.ext
  change
    candidate.val.val / domainSize * domainSize + index.val =
      candidate.val.val
  calc
    candidate.val.val / domainSize * domainSize + index.val =
        index.val + domainSize * (candidate.val.val / domainSize) := by
      ac_rfl
    _ = candidate.val.val % domainSize +
        domainSize * (candidate.val.val / domainSize) := by
      exact congrArg
        (fun remainder =>
          remainder + domainSize * (candidate.val.val / domainSize))
        candidate.property.2.symm
    _ = candidate.val.val :=
      Nat.mod_add_div candidate.val.val domainSize

/-- Every DECS index has exactly the same number of accepted Goldilocks preimages. -/
def acceptedFiberEquiv (index : DomainIndex) :
    Fin quotient ≃ AcceptedFiber index where
  toFun := encodeFiber index
  invFun := decodeFiber index
  left_inv := decode_encode_fiber index
  right_inv := encode_decode_fiber index

noncomputable instance acceptedFiberFintype (index : DomainIndex) :
    Fintype (AcceptedFiber index) :=
  Fintype.ofEquiv (Fin quotient) (acceptedFiberEquiv index)

theorem accepted_fiber_cardinality_is_constant (index : DomainIndex) :
    Fintype.card (AcceptedFiber index) = quotient := by
  rw [← Fintype.card_congr (acceptedFiberEquiv index)]
  simp

/-- Accepted field words are exactly a quotient coordinate paired with a DECS index. -/
def acceptedCoordinatesEquiv :
    (Fin quotient × DomainIndex) ≃
      { candidate : FieldWord // candidate.val < acceptedCandidateCount } where
  toFun coordinate :=
    ⟨(encodeFiber coordinate.2 coordinate.1).val,
      (encodeFiber coordinate.2 coordinate.1).property.1⟩
  invFun candidate := by
    let index : DomainIndex :=
      ⟨candidate.val.val % domainSize, Nat.mod_lt _ domain_size_positive⟩
    let fiber : AcceptedFiber index :=
      ⟨candidate.val, candidate.property, rfl⟩
    exact ⟨decodeFiber index fiber, index⟩
  left_inv coordinate := by
    rcases coordinate with ⟨part, index⟩
    apply Prod.ext
    · apply Fin.ext
      change
        (part.val * domainSize + index.val) / domainSize = part.val
      rw [Nat.add_comm, Nat.add_mul_div_right index.val part.val domain_size_positive,
        Nat.div_eq_of_lt index.isLt, Nat.zero_add]
    · apply Fin.ext
      exact (encodeFiber index part).property.2
  right_inv candidate := by
    apply Subtype.ext
    apply Fin.ext
    let index : DomainIndex :=
      ⟨candidate.val.val % domainSize, Nat.mod_lt _ domain_size_positive⟩
    let fiber : AcceptedFiber index :=
      ⟨candidate.val, candidate.property, rfl⟩
    have restored := encode_decode_fiber index fiber
    exact congrArg (fun selected => selected.val.val) restored

/--
A permutation of DECS indices lifts to a permutation of canonical Goldilocks candidates while
leaving the quotient coordinate, and therefore every candidate's probability mass, unchanged.
-/
noncomputable def candidatePermutation
    (permutation : Equiv.Perm DomainIndex) : Equiv.Perm FieldWord :=
  Equiv.Perm.extendDomain
    ((Equiv.refl (Fin quotient)).prodCongr permutation)
    acceptedCoordinatesEquiv

theorem candidate_permutation_encode_fiber
    (permutation : Equiv.Perm DomainIndex)
    (index : DomainIndex)
    (part : Fin quotient) :
    candidatePermutation permutation (encodeFiber index part).val =
      (encodeFiber (permutation index) part).val := by
  simpa [candidatePermutation, acceptedCoordinatesEquiv] using
    Equiv.Perm.extendDomain_apply_image
      ((Equiv.refl (Fin quotient)).prodCongr permutation)
      acceptedCoordinatesEquiv
      (part, index)

theorem candidate_permutation_rejected
    (permutation : Equiv.Perm DomainIndex)
    (candidate : FieldWord)
    (rejected : ¬candidate.val < acceptedCandidateCount) :
    candidatePermutation permutation candidate = candidate := by
  exact Equiv.Perm.extendDomain_apply_not_subtype
    ((Equiv.refl (Fin quotient)).prodCongr permutation)
    acceptedCoordinatesEquiv rejected

theorem candidate_index_permutation
    (permutation : Equiv.Perm DomainIndex)
    (candidate : FieldWord) :
    candidateIndex (candidatePermutation permutation candidate) =
      (candidateIndex candidate).map permutation := by
  set_option maxRecDepth 10000 in
  by_cases accepted : candidate.val < acceptedCandidateCount
  · let index : DomainIndex :=
      ⟨candidate.val % domainSize, Nat.mod_lt _ domain_size_positive⟩
    let fiber : AcceptedFiber index :=
      ⟨candidate, accepted, rfl⟩
    let part : Fin quotient := decodeFiber index fiber
    have represented :
        (encodeFiber index part).val = candidate := by
      have restored := encode_decode_fiber index fiber
      exact congrArg (fun selected => selected.val) restored
    rw [← represented, candidate_permutation_encode_fiber]
    simp [candidateIndex, (encodeFiber index part).property.1,
      (encodeFiber index part).property.2,
      (encodeFiber (permutation index) part).property.1,
      (encodeFiber (permutation index) part).property.2]
  · rw [candidate_permutation_rejected permutation candidate accepted]
    simp [candidateIndex, accepted]

theorem filterMap_candidate_permutation
    (permutation : Equiv.Perm DomainIndex)
    (candidates : List FieldWord) :
    (candidates.map (candidatePermutation permutation)).filterMap candidateIndex =
      (candidates.filterMap candidateIndex).map permutation := by
  induction candidates with
  | nil => rfl
  | cons candidate candidates inductionHypothesis =>
      rw [List.map_cons, List.filterMap_cons, candidate_index_permutation,
        List.filterMap_cons, inductionHypothesis]
      cases candidateIndex candidate <;> rfl

/-- First distinct accepted indices, before the verifier's canonical sort. -/
def firstDistinctIndices (candidates : List FieldWord) : List DomainIndex :=
  ((candidates.filterMap candidateIndex).dedup).take openingCount

/-- Exact first-distinct, then sorted, sampler used by the Level-5 verifier. -/
def selectedIndices (candidates : List FieldWord) : List DomainIndex :=
  ((firstDistinctIndices candidates).mergeSort
    (fun left right => decide (left ≤ right)))

/-- Order-independent sample selected by the verifier. -/
def selectedIndexSet (candidates : List FieldWord) : Finset DomainIndex :=
  (firstDistinctIndices candidates).toFinset

theorem first_distinct_indices_permutation
    (permutation : Equiv.Perm DomainIndex)
    (candidates : List FieldWord) :
    firstDistinctIndices
        (candidates.map (candidatePermutation permutation)) =
      (firstDistinctIndices candidates).map permutation := by
  unfold firstDistinctIndices
  rw [filterMap_candidate_permutation,
    List.dedup_map_of_injective permutation.injective]
  simp

theorem selected_index_set_permutation
    (permutation : Equiv.Perm DomainIndex)
    (candidates : List FieldWord) :
    selectedIndexSet
        (candidates.map (candidatePermutation permutation)) =
      (selectedIndexSet candidates).map permutation.toEmbedding := by
  ext index
  simp only [selectedIndexSet, first_distinct_indices_permutation,
    List.mem_toFinset, List.mem_map, Finset.mem_map]
  constructor
  · rintro ⟨source, sourceMembership, sourceImage⟩
    exact ⟨source, sourceMembership, by simpa using sourceImage⟩
  · rintro ⟨source, sourceMembership, sourceImage⟩
    exact ⟨source, sourceMembership, by simpa using sourceImage⟩

/-- The finite uniform sample space of the 40 field words consumed by the active sampler. -/
abbrev CandidateStream := Fin candidateCount -> FieldWord

noncomputable instance candidateStreamFintype : Fintype CandidateStream :=
  inferInstance

def streamCandidates (stream : CandidateStream) : List FieldWord :=
  List.ofFn stream

noncomputable def candidateStreamPermutation
    (permutation : Equiv.Perm DomainIndex) : Equiv.Perm CandidateStream :=
  Equiv.piCongrRight fun _ => candidatePermutation permutation

theorem stream_candidates_permutation
    (permutation : Equiv.Perm DomainIndex)
    (stream : CandidateStream) :
    streamCandidates (candidateStreamPermutation permutation stream) =
      (streamCandidates stream).map (candidatePermutation permutation) := by
  change
    List.ofFn
        (fun index => candidatePermutation permutation (stream index)) =
      (List.ofFn stream).map (candidatePermutation permutation)
  exact List.ofFn_comp' stream (candidatePermutation permutation)

theorem stream_selected_index_set_permutation
    (permutation : Equiv.Perm DomainIndex)
    (stream : CandidateStream) :
    selectedIndexSet
        (streamCandidates (candidateStreamPermutation permutation stream)) =
      (selectedIndexSet (streamCandidates stream)).map
        permutation.toEmbedding := by
  rw [stream_candidates_permutation,
    selected_index_set_permutation]

/-- Candidate streams whose successful sample is one exact subset. -/
def SelectingStreams (sample : Finset DomainIndex) :=
  { stream : CandidateStream //
      selectedIndexSet (streamCandidates stream) = sample }

noncomputable instance selectingStreamsFintype
    (sample : Finset DomainIndex) : Fintype (SelectingStreams sample) := by
  exact Fintype.ofInjective Subtype.val Subtype.val_injective

noncomputable def selectingStreamsEquiv
    (permutation : Equiv.Perm DomainIndex)
    (source target : Finset DomainIndex)
    (mapped : source.map permutation.toEmbedding = target) :
    SelectingStreams source ≃ SelectingStreams target :=
  (candidateStreamPermutation permutation).subtypeEquiv (by
    intro stream
    rw [stream_selected_index_set_permutation]
    constructor
    · intro sourceEquation
      rw [sourceEquation, mapped]
    · intro targetEquation
      apply Finset.map_injective permutation.toEmbedding
      exact targetEquation.trans mapped.symm)

/--
Any two fixed-cardinality output subsets have exactly the same number of 50-word preimages. This
is the finite counting statement behind conditional uniformity of first-distinct sampling.
-/
theorem selecting_streams_card_eq_of_card_eq
    (source target : Finset DomainIndex)
    (sameCardinality : source.card = target.card) :
    Fintype.card (SelectingStreams source) =
      Fintype.card (SelectingStreams target) := by
  obtain ⟨permutation, mapped⟩ :=
    Equiv.Perm.exists_map_finset_eq source target sameCardinality
  exact Fintype.card_congr
    (selectingStreamsEquiv permutation source target mapped)

/-- Canonical embedding of the first 26 positions into the active DECS domain. -/
def openingIndexEmbedding : Fin openingCount ↪ DomainIndex where
  toFun index :=
    ⟨index.val, index.isLt.trans (by decide)⟩
  inj' := by
    intro left right equal
    apply Fin.ext
    simpa using congrArg Fin.val equal

def referenceSample : Finset DomainIndex :=
  Finset.univ.map openingIndexEmbedding

theorem reference_sample_card :
    referenceSample.card = openingCount := by
  simp [referenceSample]

def rejectedCandidate : FieldWord :=
  ⟨acceptedCandidateCount, by decide⟩

theorem rejected_candidate_is_rejected :
    candidateIndex rejectedCandidate = none := by
  simp [candidateIndex, rejectedCandidate]

def zeroQuotientPart : Fin quotient :=
  ⟨0, quotient_positive⟩

/-- Concrete successful stream used only to prove that the uniform fiber is nonempty. -/
def referenceStream : CandidateStream :=
  fun position =>
    if bounded : position.val < openingCount then
      (encodeFiber (openingIndexEmbedding ⟨position.val, bounded⟩)
        zeroQuotientPart).val
    else
      rejectedCandidate

theorem reference_stream_selects_reference_sample :
    selectedIndexSet (streamCandidates referenceStream) = referenceSample := by
  decide

theorem reference_selecting_streams_nonempty :
    Nonempty (SelectingStreams referenceSample) :=
  ⟨⟨referenceStream, reference_stream_selects_reference_sample⟩⟩

theorem reference_selecting_streams_card_positive :
    0 < Fintype.card (SelectingStreams referenceSample) := by
  exact Fintype.card_pos_iff.mpr reference_selecting_streams_nonempty

theorem every_opening_sample_has_reference_fiber_card
    (sample : Finset DomainIndex)
    (sampleCard : sample.card = openingCount) :
    Fintype.card (SelectingStreams sample) =
      Fintype.card (SelectingStreams referenceSample) := by
  exact selecting_streams_card_eq_of_card_eq sample referenceSample
    (sampleCard.trans reference_sample_card.symm)

/-- All successful 50-word streams. Exhausted streams are excluded because the verifier rejects. -/
def SuccessfulStreams :=
  { stream : CandidateStream //
      (selectedIndexSet (streamCandidates stream)).card = openingCount }

/-- All possible successful output subsets. -/
def OpeningSamples :=
  { sample : Finset DomainIndex // sample.card = openingCount }

noncomputable instance successfulStreamsFintype : Fintype SuccessfulStreams := by
  exact Fintype.ofInjective Subtype.val Subtype.val_injective

noncomputable instance openingSamplesFintype : Fintype OpeningSamples := by
  exact Fintype.ofInjective Subtype.val Subtype.val_injective

/-- A successful stream is exactly its output sample paired with one stream in that sample's fiber. -/
def successfulSample (stream : SuccessfulStreams) : OpeningSamples :=
  ⟨selectedIndexSet (streamCandidates stream.val), stream.property⟩

def successfulFiberEquiv
    (sample : OpeningSamples) :
    { stream : SuccessfulStreams // successfulSample stream = sample } ≃
      SelectingStreams sample.val where
  toFun stream :=
    ⟨stream.val.val, congrArg Subtype.val stream.property⟩
  invFun stream :=
    ⟨⟨stream.val, by
        rw [stream.property]
        exact sample.property⟩,
      by
        apply Subtype.ext
        exact stream.property⟩
  left_inv stream := by
    apply Subtype.ext
    apply Subtype.ext
    rfl
  right_inv stream := by
    apply Subtype.ext
    rfl

def successfulStreamDecomposition :
    SuccessfulStreams ≃
      Σ sample : OpeningSamples, SelectingStreams sample.val :=
  (Equiv.sigmaFiberEquiv successfulSample).symm.trans
    (Equiv.sigmaCongrRight successfulFiberEquiv)

def openingSamplesEquiv :
    OpeningSamples ≃
      { sample : Finset DomainIndex //
          sample ∈ (Finset.univ : Finset DomainIndex).powersetCard openingCount } where
  toFun sample :=
    ⟨sample.val,
      Finset.mem_powersetCard.mpr
        ⟨Finset.subset_univ _, sample.property⟩⟩
  invFun sample :=
    ⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩
  left_inv sample := by
    apply Subtype.ext
    rfl
  right_inv sample := by
    apply Subtype.ext
    rfl

theorem opening_samples_card :
    Fintype.card OpeningSamples =
      Nat.choose domainSize openingCount := by
  rw [Fintype.card_congr openingSamplesEquiv]
  change
    Fintype.card
        (↥((Finset.univ : Finset DomainIndex).powersetCard openingCount)) =
      Nat.choose domainSize openingCount
  rw [Fintype.card_coe, Finset.card_powersetCard]
  simp [domainSize]

theorem successful_streams_card :
    Fintype.card SuccessfulStreams =
      Nat.choose domainSize openingCount *
        Fintype.card (SelectingStreams referenceSample) := by
  calc
    Fintype.card SuccessfulStreams =
        Fintype.card
          (Σ sample : OpeningSamples, SelectingStreams sample.val) :=
      Fintype.card_congr successfulStreamDecomposition
    _ = ∑ sample : OpeningSamples,
          Fintype.card (SelectingStreams sample.val) := by
      exact Fintype.card_sigma
    _ = ∑ _sample : OpeningSamples,
          Fintype.card (SelectingStreams referenceSample) := by
      apply Finset.sum_congr rfl
      intro sample _
      exact every_opening_sample_has_reference_fiber_card
        sample.val sample.property
    _ = Fintype.card OpeningSamples *
          Fintype.card (SelectingStreams referenceSample) := by
      simp
    _ = Nat.choose domainSize openingCount *
          Fintype.card (SelectingStreams referenceSample) := by
      rw [opening_samples_card]

/-- Successful output subsets lying entirely inside one designated bad set. -/
def BadOpeningSamples (bad : Finset DomainIndex) :=
  { sample : OpeningSamples // sample.val ⊆ bad }

/-- Successful streams whose complete selected set lies in one designated bad set. -/
def BadSuccessfulStreams (bad : Finset DomainIndex) :=
  { stream : SuccessfulStreams //
      selectedIndexSet (streamCandidates stream.val) ⊆ bad }

noncomputable instance badOpeningSamplesFintype
    (bad : Finset DomainIndex) : Fintype (BadOpeningSamples bad) := by
  exact Fintype.ofInjective Subtype.val Subtype.val_injective

noncomputable instance badSuccessfulStreamsFintype
    (bad : Finset DomainIndex) : Fintype (BadSuccessfulStreams bad) := by
  exact Fintype.ofInjective Subtype.val Subtype.val_injective

def badOpeningSamplesEquiv
    (bad : Finset DomainIndex) :
    BadOpeningSamples bad ≃
      { sample : Finset DomainIndex //
          sample ∈ bad.powersetCard openingCount } where
  toFun sample :=
    ⟨sample.val.val,
      Finset.mem_powersetCard.mpr
        ⟨sample.property, sample.val.property⟩⟩
  invFun sample :=
    ⟨⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩,
      (Finset.mem_powersetCard.mp sample.property).1⟩
  left_inv sample := by
    apply Subtype.ext
    apply Subtype.ext
    rfl
  right_inv sample := by
    apply Subtype.ext
    rfl

theorem bad_opening_samples_card
    (bad : Finset DomainIndex) :
    Fintype.card (BadOpeningSamples bad) =
      Nat.choose bad.card openingCount := by
  rw [Fintype.card_congr (badOpeningSamplesEquiv bad)]
  change
    Fintype.card (↥(bad.powersetCard openingCount)) =
      Nat.choose bad.card openingCount
  rw [Fintype.card_coe, Finset.card_powersetCard]

def badSuccessfulSample
    (bad : Finset DomainIndex)
    (stream : BadSuccessfulStreams bad) : BadOpeningSamples bad :=
  ⟨⟨selectedIndexSet (streamCandidates stream.val.val),
      stream.val.property⟩, stream.property⟩

def badSuccessfulFiberEquiv
    (bad : Finset DomainIndex)
    (sample : BadOpeningSamples bad) :
    { stream : BadSuccessfulStreams bad //
        badSuccessfulSample bad stream = sample } ≃
      SelectingStreams sample.val.val where
  toFun stream :=
    ⟨stream.val.val.val,
      congrArg (fun selected : BadOpeningSamples bad => selected.val.val)
        stream.property⟩
  invFun stream :=
    ⟨⟨⟨stream.val, by
          rw [stream.property]
          exact sample.val.property⟩,
        by
          rw [stream.property]
          exact sample.property⟩,
      by
        apply Subtype.ext
        apply Subtype.ext
        exact stream.property⟩
  left_inv stream := by
    apply Subtype.ext
    apply Subtype.ext
    apply Subtype.ext
    rfl
  right_inv stream := by
    apply Subtype.ext
    rfl

def badSuccessfulStreamDecomposition
    (bad : Finset DomainIndex) :
    BadSuccessfulStreams bad ≃
      Σ sample : BadOpeningSamples bad,
        SelectingStreams sample.val.val :=
  (Equiv.sigmaFiberEquiv (badSuccessfulSample bad)).symm.trans
    (Equiv.sigmaCongrRight (badSuccessfulFiberEquiv bad))

theorem bad_successful_streams_card
    (bad : Finset DomainIndex) :
    Fintype.card (BadSuccessfulStreams bad) =
      Nat.choose bad.card openingCount *
        Fintype.card (SelectingStreams referenceSample) := by
  calc
    Fintype.card (BadSuccessfulStreams bad) =
        Fintype.card
          (Σ sample : BadOpeningSamples bad,
            SelectingStreams sample.val.val) :=
      Fintype.card_congr (badSuccessfulStreamDecomposition bad)
    _ = ∑ sample : BadOpeningSamples bad,
          Fintype.card (SelectingStreams sample.val.val) := by
      exact Fintype.card_sigma
    _ = ∑ _sample : BadOpeningSamples bad,
          Fintype.card (SelectingStreams referenceSample) := by
      apply Finset.sum_congr rfl
      intro sample _
      exact every_opening_sample_has_reference_fiber_card
        sample.val.val sample.val.property
    _ = Fintype.card (BadOpeningSamples bad) *
          Fintype.card (SelectingStreams referenceSample) := by
      simp
    _ = Nat.choose bad.card openingCount *
          Fintype.card (SelectingStreams referenceSample) := by
      rw [bad_opening_samples_card]

/-- Exact bad-subset probability conditioned on the fixed sampler succeeding. -/
noncomputable def conditionalBadSubsetProbability
    (bad : Finset DomainIndex) : Rat :=
  Fintype.card (BadSuccessfulStreams bad) /
    Fintype.card SuccessfulStreams

theorem conditional_bad_subset_probability_exact
    (bad : Finset DomainIndex) :
    conditionalBadSubsetProbability bad =
      (Nat.choose bad.card openingCount : Rat) /
        Nat.choose domainSize openingCount := by
  rw [conditionalBadSubsetProbability, bad_successful_streams_card,
    successful_streams_card]
  have fiberNonzero :
      (Fintype.card (SelectingStreams referenceSample) : Rat) ≠ 0 := by
    exact_mod_cast (Nat.ne_of_gt reference_selecting_streams_card_positive)
  have sampleCountPositive :
      0 < Nat.choose domainSize openingCount := by
    exact Nat.choose_pos (by decide)
  have sampleCountNonzero :
      (Nat.choose domainSize openingCount : Rat) ≠ 0 := by
    exact_mod_cast sampleCountPositive.ne'
  push_cast
  field_simp

theorem selected_indices_nodup (candidates : List FieldWord) :
    (selectedIndices candidates).Nodup := by
  apply (List.nodup_mergeSort).2
  exact (List.nodup_dedup _).take

theorem selected_indices_length_at_most_opening_count
    (candidates : List FieldWord) :
    (selectedIndices candidates).length ≤ openingCount := by
  simp [selectedIndices, firstDistinctIndices]

theorem selected_index_set_card_eq_selected_indices_length
    (candidates : List FieldWord) :
    (selectedIndexSet candidates).card = (selectedIndices candidates).length := by
  rw [selectedIndexSet, List.toFinset_card_of_nodup]
  · simp [selectedIndices]
  · exact (List.nodup_dedup _).take

theorem selected_indices_are_in_domain
    (candidates : List FieldWord)
    (index : DomainIndex)
    (_membership : index ∈ selectedIndices candidates) :
    index.val < domainSize := by
  exact index.isLt

/-- Exact 50-word candidate stream selected by the active transcript. -/
def activeCandidates
    (oracle : SmallWoodTranscript.Oracle)
    (transcript : SmallWoodTranscript.Transcript) : List FieldWord :=
  SmallWoodTranscript.fieldHashWords oracle
    SmallWoodTranscript.decsFixedSamplingDomain
    (transcript.decsHash oracle)
    candidateCount

def activeSelectedIndices
    (oracle : SmallWoodTranscript.Oracle)
    (transcript : SmallWoodTranscript.Transcript) : List DomainIndex :=
  selectedIndices (activeCandidates oracle transcript)

def ActiveSamplerSucceeds
    (oracle : SmallWoodTranscript.Oracle)
    (transcript : SmallWoodTranscript.Transcript) : Prop :=
  (activeSelectedIndices oracle transcript).length = openingCount

theorem active_candidate_count_is_exact
    (oracle : SmallWoodTranscript.Oracle)
    (transcript : SmallWoodTranscript.Transcript) :
    (activeCandidates oracle transcript).length = candidateCount := by
  exact SmallWoodTranscript.fieldHashWords_length _ _ _ _

theorem active_sampler_success_yields_exact_distinct_openings
    (oracle : SmallWoodTranscript.Oracle)
    (transcript : SmallWoodTranscript.Transcript)
    (success : ActiveSamplerSucceeds oracle transcript) :
    (activeSelectedIndices oracle transcript).length = 20 ∧
      (activeSelectedIndices oracle transcript).Nodup := by
  constructor
  · unfold ActiveSamplerSucceeds at success
    exact success.trans active_sampling_geometry.2.1
  · exact selected_indices_nodup _

/-- The Level-5 fixed sampler carries no selectable DECS nonce. -/
def fixedDecsNonce : SmallWoodTranscript.Word := 0

theorem fixed_decs_nonce_is_zero :
    fixedDecsNonce.val = 0 := by
  rfl

/--
Conservative fixed-pool exhaustion envelope. If 50 candidates yield at most 19 accepted distinct
indices, at least 31 draw positions are rejections or repeats. There are at most `2^50` choices of
positions and each such event has conditional probability at most `50 / 2^20`.
-/
def exhaustionBadDrawCount : Nat := candidateCount - (openingCount - 1)
def exhaustionEnvelopeNumerator : Nat :=
  2 ^ candidateCount * candidateCount ^ exhaustionBadDrawCount
def exhaustionEnvelopeDenominator : Nat :=
  domainSize ^ exhaustionBadDrawCount

theorem exhaustion_bad_draw_count_is_31 :
    exhaustionBadDrawCount = 31 := by
  decide

theorem fixed_sampler_exhaustion_envelope_below_2pow128 :
    2 ^ 128 * exhaustionEnvelopeNumerator < exhaustionEnvelopeDenominator := by
  decide

/--
The same conservative envelope retains more than 260 bits of liveness margin.  Exhaustion causes
the verifier to reject, so this is a completeness/liveness bound rather than an additive
knowledge-soundness error.
-/
theorem fixed_sampler_exhaustion_envelope_below_2pow260 :
    2 ^ 260 * exhaustionEnvelopeNumerator < exhaustionEnvelopeDenominator := by
  set_option exponentiation.threshold 512 in
    decide

end HegemonCrypto.SmallWood.FixedSampling

import HegemonCrypto.SmallWoodPiopEvaluation
import Mathlib.Data.Fintype.CardEmbedding
import Mathlib.Data.Fintype.EquivFin
import Mathlib.Data.Fintype.Perm
import Mathlib.Tactic.FieldSimp

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

/-!
# Canonical SmallWood PIOP opening sampling

The production verifier derives five field elements for each of at most sixteen nonce values and
accepts the first tuple whose elements are distinct and outside the 64-point packing domain.  This
file proves that this retry rule does not bias the accepted five-element set.

The proof is finite and exact.  A permutation of the valid field domain extends to a permutation
of the whole field that fixes every excluded packing point.  Applying that permutation to every
oracle answer preserves which nonce is first valid and maps the selected set accordingly.  Hence
all fixed-cardinality output sets have equal-size preimages.  Conditioning on verifier acceptance,
the output is exactly uniform over five-element subsets of the valid domain.
-/

namespace HegemonCrypto.SmallWood.PiopOpeningSampling

open HegemonCrypto.UniformSubsetSampling

noncomputable section

variable {F : Type*} [Fintype F] [DecidableEq F]

local instance classicalPropDecidable (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

/-- Field elements on which the quotient equation is allowed to be evaluated. -/
abbrev Outside (forbidden : Finset F) := { value : F // value ∉ forbidden }

/-- One raw tuple emitted for one nonce. -/
abbrev OpeningTuple (sampleSize : Nat) := Fin sampleSize -> F

/-- Exact validity rule applied before a PIOP opening nonce can be accepted. -/
def TupleValid
    (forbidden : Finset F)
    {sampleSize : Nat}
    (tuple : OpeningTuple (F := F) sampleSize) : Prop :=
  Function.Injective tuple ∧ ∀ index, tuple index ∉ forbidden

/-- A raw tuple together with the evidence needed to interpret it as an outside-domain subset. -/
def ValidTuple
    (forbidden : Finset F)
    (sampleSize : Nat) :=
  { tuple : OpeningTuple (F := F) sampleSize // TupleValid forbidden tuple }

noncomputable instance validTupleFintype
    (forbidden : Finset F)
    (sampleSize : Nat) :
    Fintype (ValidTuple forbidden sampleSize) := by
  unfold ValidTuple
  infer_instance

/-- First valid tuple in nonce order.  `none` is verifier rejection after exhausting all trials. -/
def firstValid
    (forbidden : Finset F)
    {sampleSize : Nat} :
    List (OpeningTuple (F := F) sampleSize) ->
      Option (ValidTuple forbidden sampleSize)
  | [] => none
  | tuple :: remaining =>
      if valid : TupleValid forbidden tuple then
        some ⟨tuple, valid⟩
      else
        firstValid forbidden remaining

namespace ValidTuple

/-- A valid tuple is an embedding of tuple coordinates into the valid field domain. -/
def outsideEmbedding
    {forbidden : Finset F}
    {sampleSize : Nat}
    (tuple : ValidTuple forbidden sampleSize) :
    Fin sampleSize ↪ Outside forbidden where
  toFun index := ⟨tuple.val index, tuple.property.2 index⟩
  inj' := fun left right equal =>
    tuple.property.1 (congrArg Subtype.val equal)

/-- Order-independent opening set selected by one valid tuple. -/
def sample
    {forbidden : Finset F}
    {sampleSize : Nat}
    (tuple : ValidTuple forbidden sampleSize) :
    Finset (Outside forbidden) :=
  Finset.univ.map tuple.outsideEmbedding

theorem sample_card
    {forbidden : Finset F}
    {sampleSize : Nat}
    (tuple : ValidTuple forbidden sampleSize) :
    tuple.sample.card = sampleSize := by
  simp [sample]

end ValidTuple

/-! ## Uniform valid tuples -/

/-- Valid ordered tuples are exactly embeddings into the outside-domain type. -/
def validTupleEquivEmbedding
    (forbidden : Finset F)
    (sampleSize : Nat) :
    ValidTuple forbidden sampleSize ≃
      (Fin sampleSize ↪ Outside forbidden) where
  toFun := ValidTuple.outsideEmbedding
  invFun embedding :=
    ⟨fun index => (embedding index).val, by
      constructor
      · intro left right equal
        apply embedding.injective
        exact Subtype.ext equal
      · intro index
        exact (embedding index).property⟩
  left_inv tuple := by
    apply Subtype.ext
    funext index
    rfl
  right_inv embedding := by
    ext index
    rfl

/-- Ordered valid tuples whose complete image lies in `bad` are embeddings into `bad`. -/
def badValidTupleEquivEmbedding
    (forbidden : Finset F)
    (sampleSize : Nat)
    (bad : Finset (Outside forbidden)) :
    { tuple : ValidTuple forbidden sampleSize //
        tuple.sample ⊆ bad } ≃
      (Fin sampleSize ↪ bad) where
  toFun tuple :=
    { toFun := fun index =>
        ⟨tuple.val.outsideEmbedding index, by
          apply tuple.property
          simp [ValidTuple.sample]⟩
      inj' := fun left right equal =>
        tuple.val.outsideEmbedding.injective
          (congrArg (fun value : bad => value.val) equal) }
  invFun embedding :=
    ⟨⟨fun index => (embedding index).val.val, by
        constructor
        · intro left right equal
          apply embedding.injective
          apply Subtype.ext
          apply Subtype.ext
          exact equal
        · intro index
          exact (embedding index).val.property⟩,
      by
        intro value valueMembership
        rcases Finset.mem_map.mp valueMembership with
          ⟨index, _indexMembership, valueEqual⟩
        have selectedMembership : (embedding index).val ∈ bad :=
          (embedding index).property
        simpa only [ValidTuple.outsideEmbedding] using
          valueEqual ▸ selectedMembership⟩
  left_inv tuple := by
    apply Subtype.ext
    apply Subtype.ext
    funext index
    rfl
  right_inv embedding := by
    ext index
    rfl

theorem valid_tuple_card
    (forbidden : Finset F)
    (sampleSize : Nat) :
    Fintype.card (ValidTuple forbidden sampleSize) =
      (Fintype.card (Outside forbidden)).descFactorial sampleSize := by
  rw [Fintype.card_congr (validTupleEquivEmbedding forbidden sampleSize),
    Fintype.card_embedding_eq, Fintype.card_fin]

theorem bad_valid_tuple_card
    (forbidden : Finset F)
    (sampleSize : Nat)
    (bad : Finset (Outside forbidden)) :
    Fintype.card
        { tuple : ValidTuple forbidden sampleSize //
          tuple.sample ⊆ bad } =
      bad.card.descFactorial sampleSize := by
  rw [Fintype.card_congr
      (badValidTupleEquivEmbedding forbidden sampleSize bad),
    Fintype.card_embedding_eq, Fintype.card_fin, Fintype.card_coe]

/-- Uniform probability that an ordered valid tuple lies entirely in one bad outside-domain set. -/
def uniformValidTupleBadProbability
    (forbidden : Finset F)
    (sampleSize : Nat)
    (bad : Finset (Outside forbidden)) : Rat :=
  Fintype.card
      { tuple : ValidTuple forbidden sampleSize //
        tuple.sample ⊆ bad } /
    Fintype.card (ValidTuple forbidden sampleSize)

/--
Ordering carries the same `sampleSize!` multiplicity in numerator and denominator, so exact
uniform sampling of valid tuples has the standard hypergeometric bad-set probability.
-/
theorem uniform_valid_tuple_bad_probability_exact
    (forbidden : Finset F)
    (sampleSize : Nat)
    (bad : Finset (Outside forbidden))
    (sampleFits : sampleSize ≤ Fintype.card (Outside forbidden)) :
    uniformValidTupleBadProbability forbidden sampleSize bad =
      (Nat.choose bad.card sampleSize : Rat) /
        Nat.choose (Fintype.card (Outside forbidden)) sampleSize := by
  rw [uniformValidTupleBadProbability,
    bad_valid_tuple_card, valid_tuple_card]
  exact desc_factorial_ratio_eq_choose_ratio sampleFits

/--
A permutation of valid field points extends to a permutation of the whole field while fixing the
excluded packing points.
-/
def pointPermutation
    (forbidden : Finset F)
    (permutation : Equiv.Perm (Outside forbidden)) : Equiv.Perm F :=
  Equiv.Perm.extendDomain permutation (Equiv.refl (Outside forbidden))

theorem point_permutation_outside
    (forbidden : Finset F)
    (permutation : Equiv.Perm (Outside forbidden))
    (value : F)
    (outside : value ∉ forbidden) :
    pointPermutation forbidden permutation value =
      (permutation ⟨value, outside⟩).val := by
  simpa [pointPermutation] using
    Equiv.Perm.extendDomain_apply_image
      permutation (Equiv.refl (Outside forbidden)) ⟨value, outside⟩

theorem point_permutation_forbidden
    (forbidden : Finset F)
    (permutation : Equiv.Perm (Outside forbidden))
    (value : F)
    (inside : value ∈ forbidden) :
    pointPermutation forbidden permutation value = value := by
  apply Equiv.Perm.extendDomain_apply_not_subtype
    permutation (Equiv.refl (Outside forbidden))
  simpa using inside

/-- Pointwise action of a valid-domain permutation on one raw nonce tuple. -/
def openingTuplePermutation
    (forbidden : Finset F)
    (sampleSize : Nat)
    (permutation : Equiv.Perm (Outside forbidden)) :
    Equiv.Perm (OpeningTuple (F := F) sampleSize) :=
  Equiv.piCongrRight fun _ => pointPermutation forbidden permutation

theorem tuple_valid_permutation_iff
    (forbidden : Finset F)
    {sampleSize : Nat}
    (permutation : Equiv.Perm (Outside forbidden))
    (tuple : OpeningTuple (F := F) sampleSize) :
    TupleValid forbidden
        (openingTuplePermutation forbidden sampleSize permutation tuple) ↔
      TupleValid forbidden tuple := by
  constructor
  · intro transformedValid
    constructor
    · intro left right equal
      apply transformedValid.1
      exact congrArg (pointPermutation forbidden permutation) equal
    · intro index
      by_contra inside
      have fixed :=
        point_permutation_forbidden forbidden permutation (tuple index) (by simpa using inside)
      exact transformedValid.2 index (by simpa [openingTuplePermutation, fixed] using inside)
  · intro originalValid
    constructor
    · exact (pointPermutation forbidden permutation).injective.comp originalValid.1
    · intro index
      rw [show
        openingTuplePermutation forbidden sampleSize permutation tuple index =
          pointPermutation forbidden permutation (tuple index) by rfl]
      rw [point_permutation_outside forbidden permutation
        (tuple index) (originalValid.2 index)]
      exact (permutation ⟨tuple index, originalValid.2 index⟩).property

/-- The raw tuple permutation restricts to an equivalence on valid tuples. -/
def validTupleEquiv
    (forbidden : Finset F)
    (sampleSize : Nat)
    (permutation : Equiv.Perm (Outside forbidden)) :
    ValidTuple forbidden sampleSize ≃ ValidTuple forbidden sampleSize :=
  (openingTuplePermutation forbidden sampleSize permutation).subtypeEquiv (by
    intro tuple
    exact (tuple_valid_permutation_iff forbidden permutation tuple).symm)

theorem valid_tuple_sample_permutation
    (forbidden : Finset F)
    {sampleSize : Nat}
    (permutation : Equiv.Perm (Outside forbidden))
    (tuple : ValidTuple forbidden sampleSize) :
    (validTupleEquiv forbidden sampleSize permutation tuple).sample =
      tuple.sample.map permutation.toEmbedding := by
  have embeddingEqual :
      (validTupleEquiv forbidden sampleSize permutation tuple).outsideEmbedding =
        tuple.outsideEmbedding.trans permutation.toEmbedding := by
    ext index
    exact point_permutation_outside forbidden permutation
      (tuple.val index) (tuple.property.2 index)
  rw [ValidTuple.sample, ValidTuple.sample, embeddingEqual, Finset.map_map]

theorem first_valid_permutation
    (forbidden : Finset F)
    {sampleSize : Nat}
    (permutation : Equiv.Perm (Outside forbidden))
    (tuples : List (OpeningTuple (F := F) sampleSize)) :
    firstValid forbidden
        (tuples.map (openingTuplePermutation forbidden sampleSize permutation)) =
      (firstValid forbidden tuples).map
        (validTupleEquiv forbidden sampleSize permutation) := by
  induction tuples with
  | nil =>
      rfl
  | cons tuple remaining inductionHypothesis =>
      rw [List.map_cons]
      by_cases valid : TupleValid forbidden tuple
      · have transformedValid :
          TupleValid forbidden
            (openingTuplePermutation forbidden sampleSize permutation tuple) :=
          (tuple_valid_permutation_iff forbidden permutation tuple).2 valid
        rw [firstValid, dif_pos transformedValid, firstValid, dif_pos valid]
        rfl
      · have transformedInvalid :
          ¬TupleValid forbidden
            (openingTuplePermutation forbidden sampleSize permutation tuple) := by
          exact fun transformedValid =>
            valid ((tuple_valid_permutation_iff forbidden permutation tuple).1
              transformedValid)
        rw [firstValid, dif_neg transformedInvalid, firstValid, dif_neg valid]
        exact inductionHypothesis

/-- The finite oracle-output surface consumed by all nonce attempts. -/
abbrev CandidateStream
    (attemptCount sampleSize : Nat) :=
  Fin attemptCount -> OpeningTuple (F := F) sampleSize

def streamTuples
    {attemptCount sampleSize : Nat}
    (stream : CandidateStream (F := F) attemptCount sampleSize) :
    List (OpeningTuple (F := F) sampleSize) :=
  List.ofFn stream

/-- Pointwise action of a valid-domain permutation on every nonce and every output coordinate. -/
def candidateStreamPermutation
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (permutation : Equiv.Perm (Outside forbidden)) :
    Equiv.Perm (CandidateStream (F := F) attemptCount sampleSize) :=
  Equiv.piCongrRight fun _ =>
    openingTuplePermutation forbidden sampleSize permutation

theorem stream_tuples_permutation
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (permutation : Equiv.Perm (Outside forbidden))
    (stream : CandidateStream (F := F) attemptCount sampleSize) :
    streamTuples
        (candidateStreamPermutation forbidden attemptCount sampleSize permutation stream) =
      (streamTuples stream).map
        (openingTuplePermutation forbidden sampleSize permutation) := by
  exact List.ofFn_comp' stream
    (openingTuplePermutation forbidden sampleSize permutation)

/-- Selected opening set; `none` is the exact reject-on-exhaustion outcome. -/
def selectedSample
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (stream : CandidateStream (F := F) attemptCount sampleSize) :
    Option (Finset (Outside forbidden)) :=
  (firstValid forbidden (streamTuples stream)).map ValidTuple.sample

theorem selected_sample_permutation
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (permutation : Equiv.Perm (Outside forbidden))
    (stream : CandidateStream (F := F) attemptCount sampleSize) :
    selectedSample forbidden
        (candidateStreamPermutation forbidden attemptCount sampleSize permutation stream) =
      (selectedSample forbidden stream).map
        (fun sample => sample.map permutation.toEmbedding) := by
  unfold selectedSample
  rw [stream_tuples_permutation, first_valid_permutation]
  cases selected : firstValid forbidden (streamTuples stream) with
  | none =>
      simp
  | some tuple =>
      simp [valid_tuple_sample_permutation]

/-- Candidate streams whose first valid tuple selects one exact subset. -/
def SelectingStreams
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (sample : Finset (Outside forbidden)) :=
  { stream : CandidateStream (F := F) attemptCount sampleSize //
      selectedSample forbidden stream = some sample }

noncomputable instance selectingStreamsFintype
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (sample : Finset (Outside forbidden)) :
    Fintype (SelectingStreams
      (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
      forbidden sample) :=
  Fintype.ofInjective Subtype.val Subtype.val_injective

def selectingStreamsEquiv
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (permutation : Equiv.Perm (Outside forbidden))
    (source target : Finset (Outside forbidden))
    (mapped : source.map permutation.toEmbedding = target) :
    SelectingStreams
        (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
        forbidden source ≃
      SelectingStreams
        (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
        forbidden target :=
  (candidateStreamPermutation forbidden attemptCount sampleSize permutation).subtypeEquiv (by
    intro stream
    rw [selected_sample_permutation]
    cases selectedEquation : selectedSample forbidden stream with
    | none =>
        simp
    | some selected =>
        simp only [Option.map_some, Option.some.injEq]
        constructor
        · intro selectedSource
          rw [selectedSource]
          exact mapped
        · intro selectedMapped
          exact (Finset.map_injective permutation.toEmbedding)
            (selectedMapped.trans mapped.symm))

/-- Equal-cardinality output subsets have exactly the same number of accepted stream preimages. -/
theorem selecting_streams_card_eq_of_card_eq
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (source target : Finset (Outside forbidden))
    (sameCardinality : source.card = target.card) :
    Fintype.card
        (SelectingStreams
          (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
          forbidden source) =
      Fintype.card
        (SelectingStreams
          (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
          forbidden target) := by
  obtain ⟨permutation, mapped⟩ :=
    Equiv.Perm.exists_map_finset_eq source target sameCardinality
  exact Fintype.card_congr
    (selectingStreamsEquiv forbidden permutation source target mapped)

/-- All possible accepted opening subsets. -/
def OpeningSamples
    (forbidden : Finset F)
    (sampleSize : Nat) :=
  { sample : Finset (Outside forbidden) // sample.card = sampleSize }

noncomputable instance openingSamplesFintype
    (forbidden : Finset F)
    (sampleSize : Nat) :
    Fintype (OpeningSamples forbidden sampleSize) :=
  Fintype.ofInjective Subtype.val Subtype.val_injective

/-- Accepted streams paired with their unique selected opening subset. -/
def SuccessfulSelections
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat) :=
  Σ sample : OpeningSamples forbidden sampleSize,
    SelectingStreams
      (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
      forbidden sample.val

noncomputable instance successfulSelectionsFintype
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat) :
    Fintype (SuccessfulSelections forbidden attemptCount sampleSize) := by
  unfold SuccessfulSelections
  infer_instance

/-- Accepted streams whose selected subset lies entirely in one designated bad set. -/
def BadSuccessfulSelections
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (bad : Finset (Outside forbidden)) :=
  Σ sample : { sample : OpeningSamples forbidden sampleSize // sample.val ⊆ bad },
    SelectingStreams
      (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
      forbidden sample.val.val

noncomputable instance badOpeningSamplesFintype
    (forbidden : Finset F)
    (sampleSize : Nat)
    (bad : Finset (Outside forbidden)) :
    Fintype
      { sample : OpeningSamples forbidden sampleSize // sample.val ⊆ bad } :=
  Fintype.ofInjective Subtype.val Subtype.val_injective

noncomputable instance badSuccessfulSelectionsFintype
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (bad : Finset (Outside forbidden)) :
    Fintype
      (BadSuccessfulSelections forbidden attemptCount sampleSize bad) := by
  unfold BadSuccessfulSelections
  infer_instance

def openingSamplesEquiv
    (forbidden : Finset F)
    (sampleSize : Nat) :
    OpeningSamples forbidden sampleSize ≃
      { sample : Finset (Outside forbidden) //
          sample ∈ (Finset.univ : Finset (Outside forbidden)).powersetCard sampleSize } where
  toFun sample :=
    ⟨sample.val,
      Finset.mem_powersetCard.mpr ⟨Finset.subset_univ _, sample.property⟩⟩
  invFun sample :=
    ⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩
  left_inv sample := Subtype.ext rfl
  right_inv sample := Subtype.ext rfl

theorem opening_samples_card
    (forbidden : Finset F)
    (sampleSize : Nat) :
    Fintype.card (OpeningSamples forbidden sampleSize) =
      Nat.choose (Fintype.card (Outside forbidden)) sampleSize := by
  rw [Fintype.card_congr (openingSamplesEquiv forbidden sampleSize)]
  change
    Fintype.card
        (↥((Finset.univ : Finset (Outside forbidden)).powersetCard sampleSize)) =
      Nat.choose (Fintype.card (Outside forbidden)) sampleSize
  rw [Fintype.card_coe, Finset.card_powersetCard, Finset.card_univ]

/-- Canonical enumeration of one fixed-size outside-domain subset. -/
def sampleEquiv
    {forbidden : Finset F}
    {sampleSize : Nat}
    (sample : OpeningSamples forbidden sampleSize) :
    Fin sampleSize ≃ sample.val :=
  (sample.val.equivFinOfCardEq sample.property).symm

/-- Every fixed-size outside-domain subset has a valid tuple enumeration. -/
def validTupleOfSample
    {forbidden : Finset F}
    {sampleSize : Nat}
    (sample : OpeningSamples forbidden sampleSize) :
    ValidTuple forbidden sampleSize :=
  ⟨fun index => (sampleEquiv sample index).val.val, by
    constructor
    · intro left right equal
      apply (sampleEquiv sample).injective
      apply Subtype.ext
      apply Subtype.ext
      exact equal
    · intro index
      exact (sampleEquiv sample index).val.property⟩

theorem valid_tuple_of_sample_selects
    {forbidden : Finset F}
    {sampleSize : Nat}
    (sample : OpeningSamples forbidden sampleSize) :
    (validTupleOfSample sample).sample = sample.val := by
  ext value
  constructor
  · intro membership
    rcases Finset.mem_map.mp membership with ⟨index, _, equal⟩
    have enumeratedMembership :
        (sampleEquiv sample index).val ∈ sample.val :=
      (sampleEquiv sample index).property
    simpa [ValidTuple.outsideEmbedding, validTupleOfSample] using
      equal ▸ enumeratedMembership
  · intro membership
    obtain ⟨index, equal⟩ :=
      (sampleEquiv sample).surjective ⟨value, membership⟩
    apply Finset.mem_map.mpr
    refine ⟨index, Finset.mem_univ index, ?_⟩
    apply Subtype.ext
    exact congrArg (fun selected => selected.val.val) equal

/-- Constant trial stream used to exhibit one accepted preimage for every opening subset. -/
def constantSampleStream
    {forbidden : Finset F}
    (attemptCount : Nat)
    {sampleSize : Nat}
    (sample : OpeningSamples forbidden sampleSize) :
    CandidateStream (F := F) attemptCount sampleSize :=
  fun _ => (validTupleOfSample sample).val

theorem constant_sample_stream_selects
    {forbidden : Finset F}
    {attemptCount sampleSize : Nat}
    (attemptPositive : 0 < attemptCount)
    (sample : OpeningSamples forbidden sampleSize) :
    selectedSample forbidden (constantSampleStream attemptCount sample) =
      some sample.val := by
  obtain ⟨remainingCount, attemptEquation⟩ :=
    Nat.exists_eq_succ_of_ne_zero (Nat.ne_of_gt attemptPositive)
  subst attemptCount
  unfold selectedSample streamTuples constantSampleStream
  rw [List.ofFn_const]
  simp only [List.replicate_succ, firstValid]
  rw [dif_pos (validTupleOfSample sample).property]
  exact congrArg some (valid_tuple_of_sample_selects sample)

/-- A sample's finite fiber serves as the common accepted-stream multiplicity. -/
def commonFiberCard
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (reference : OpeningSamples forbidden sampleSize) : Nat :=
  Fintype.card
    (SelectingStreams
      (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
      forbidden reference.val)

theorem common_fiber_card_positive
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (attemptPositive : 0 < attemptCount)
    (reference : OpeningSamples forbidden sampleSize) :
    0 < commonFiberCard forbidden attemptCount sampleSize reference := by
  apply Fintype.card_pos_iff.mpr
  exact ⟨⟨constantSampleStream attemptCount reference,
    constant_sample_stream_selects attemptPositive reference⟩⟩

theorem successful_selections_card
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (reference : OpeningSamples forbidden sampleSize) :
    Fintype.card (SuccessfulSelections forbidden attemptCount sampleSize) =
      Nat.choose (Fintype.card (Outside forbidden)) sampleSize *
        commonFiberCard forbidden attemptCount sampleSize reference := by
  calc
    Fintype.card (SuccessfulSelections forbidden attemptCount sampleSize) =
        ∑ sample : OpeningSamples forbidden sampleSize,
          Fintype.card
            (SelectingStreams
              (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
              forbidden sample.val) := Fintype.card_sigma
    _ = ∑ _sample : OpeningSamples forbidden sampleSize,
          commonFiberCard forbidden attemptCount sampleSize reference := by
      apply Finset.sum_congr rfl
      intro sample _
      exact selecting_streams_card_eq_of_card_eq forbidden
        sample.val reference.val (sample.property.trans reference.property.symm)
    _ = Fintype.card (OpeningSamples forbidden sampleSize) *
          commonFiberCard forbidden attemptCount sampleSize reference := by
      simp
    _ = Nat.choose (Fintype.card (Outside forbidden)) sampleSize *
          commonFiberCard forbidden attemptCount sampleSize reference := by
      rw [opening_samples_card]

def badOpeningSamplesEquiv
    (forbidden : Finset F)
    (sampleSize : Nat)
    (bad : Finset (Outside forbidden)) :
    { sample : OpeningSamples forbidden sampleSize // sample.val ⊆ bad } ≃
      { sample : Finset (Outside forbidden) //
          sample ∈ bad.powersetCard sampleSize } where
  toFun sample :=
    ⟨sample.val.val,
      Finset.mem_powersetCard.mpr ⟨sample.property, sample.val.property⟩⟩
  invFun sample :=
    ⟨⟨sample.val, (Finset.mem_powersetCard.mp sample.property).2⟩,
      (Finset.mem_powersetCard.mp sample.property).1⟩
  left_inv sample := by
    apply Subtype.ext
    exact Subtype.ext rfl
  right_inv sample := Subtype.ext rfl

theorem bad_opening_samples_card
    (forbidden : Finset F)
    (sampleSize : Nat)
    (bad : Finset (Outside forbidden)) :
    Fintype.card
        { sample : OpeningSamples forbidden sampleSize // sample.val ⊆ bad } =
      Nat.choose bad.card sampleSize := by
  rw [Fintype.card_congr (badOpeningSamplesEquiv forbidden sampleSize bad)]
  change
    Fintype.card (↥(bad.powersetCard sampleSize)) =
      Nat.choose bad.card sampleSize
  rw [Fintype.card_coe, Finset.card_powersetCard]

theorem bad_successful_selections_card
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (reference : OpeningSamples forbidden sampleSize)
    (bad : Finset (Outside forbidden)) :
    Fintype.card
        (BadSuccessfulSelections forbidden attemptCount sampleSize bad) =
      Nat.choose bad.card sampleSize *
        commonFiberCard forbidden attemptCount sampleSize reference := by
  calc
    Fintype.card
        (BadSuccessfulSelections forbidden attemptCount sampleSize bad) =
        ∑ sample :
            { sample : OpeningSamples forbidden sampleSize // sample.val ⊆ bad },
          Fintype.card
            (SelectingStreams
              (F := F) (attemptCount := attemptCount) (sampleSize := sampleSize)
              forbidden sample.val.val) := Fintype.card_sigma
    _ = ∑ _sample :
            { sample : OpeningSamples forbidden sampleSize // sample.val ⊆ bad },
          commonFiberCard forbidden attemptCount sampleSize reference := by
      apply Finset.sum_congr rfl
      intro sample _
      exact selecting_streams_card_eq_of_card_eq forbidden
        sample.val.val reference.val
        (sample.val.property.trans reference.property.symm)
    _ = Fintype.card
          { sample : OpeningSamples forbidden sampleSize // sample.val ⊆ bad } *
          commonFiberCard forbidden attemptCount sampleSize reference := by
      simp
    _ = Nat.choose bad.card sampleSize *
          commonFiberCard forbidden attemptCount sampleSize reference := by
      rw [bad_opening_samples_card]

/-- Exact conditional failure probability of the canonical first-valid nonce sampler. -/
def conditionalBadSubsetProbability
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (bad : Finset (Outside forbidden)) : Rat :=
  Fintype.card
      (BadSuccessfulSelections forbidden attemptCount sampleSize bad) /
    Fintype.card
      (SuccessfulSelections forbidden attemptCount sampleSize)

theorem conditional_bad_subset_probability_exact
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (reference : OpeningSamples forbidden sampleSize)
    (referenceFiberPositive :
      0 < commonFiberCard forbidden attemptCount sampleSize reference)
    (sampleFits : sampleSize ≤ Fintype.card (Outside forbidden))
    (bad : Finset (Outside forbidden)) :
    conditionalBadSubsetProbability forbidden attemptCount sampleSize bad =
      (Nat.choose bad.card sampleSize : Rat) /
        Nat.choose (Fintype.card (Outside forbidden)) sampleSize := by
  rw [conditionalBadSubsetProbability,
    bad_successful_selections_card forbidden attemptCount sampleSize reference,
    successful_selections_card forbidden attemptCount sampleSize reference]
  have fiberNonzero :
      (commonFiberCard forbidden attemptCount sampleSize reference : Rat) ≠ 0 := by
    exact_mod_cast referenceFiberPositive.ne'
  have sampleCountNonzero :
      (Nat.choose (Fintype.card (Outside forbidden)) sampleSize : Rat) ≠ 0 := by
    exact_mod_cast Nat.choose_ne_zero sampleFits
  push_cast
  field_simp

/--
The canonical first-valid retry sampler is exactly uniform conditional on acceptance, with no
retry-count factor.  Reject-on-exhaustion contributes no adversarial acceptance event.
-/
theorem conditional_bad_subset_probability_exact_of_positive_attempts
    (forbidden : Finset F)
    (attemptCount sampleSize : Nat)
    (attemptPositive : 0 < attemptCount)
    (sampleFits : sampleSize ≤ Fintype.card (Outside forbidden))
    (reference : OpeningSamples forbidden sampleSize)
    (bad : Finset (Outside forbidden)) :
    conditionalBadSubsetProbability forbidden attemptCount sampleSize bad =
      (Nat.choose bad.card sampleSize : Rat) /
        Nat.choose (Fintype.card (Outside forbidden)) sampleSize := by
  exact conditional_bad_subset_probability_exact
    forbidden attemptCount sampleSize reference
    (common_fiber_card_positive forbidden attemptPositive reference)
    sampleFits bad

theorem outside_card
    (forbidden : Finset F) :
    Fintype.card (Outside forbidden) =
      Fintype.card F - forbidden.card := by
  rw [Fintype.card_subtype_compl]
  simp [Fintype.card_subtype]

theorem first_valid_append_of_invalid_prefix
    (forbidden : Finset F)
    {sampleSize : Nat}
    (prior suffix : List (OpeningTuple (F := F) sampleSize))
    (selected : OpeningTuple (F := F) sampleSize)
    (priorInvalid : ∀ tuple ∈ prior, ¬TupleValid forbidden tuple)
    (selectedValid : TupleValid forbidden selected) :
    firstValid forbidden (prior ++ selected :: suffix) =
      some ⟨selected, selectedValid⟩ := by
  induction prior with
  | nil =>
      rw [List.nil_append, firstValid, dif_pos selectedValid]
  | cons head tail inductionHypothesis =>
      have headInvalid : ¬TupleValid forbidden head :=
        priorInvalid head (List.mem_cons_self)
      have tailInvalid : ∀ tuple ∈ tail, ¬TupleValid forbidden tuple := by
        intro tuple membership
        exact priorInvalid tuple (List.mem_cons_of_mem head membership)
      rw [List.cons_append, firstValid, dif_neg headInvalid]
      exact inductionHypothesis tailInvalid

/-- A tuple valid at one index and invalid at every earlier index is the selected first tuple. -/
theorem first_valid_stream_of_canonical_index
    (forbidden : Finset F)
    {attemptCount sampleSize : Nat}
    (stream : CandidateStream (F := F) attemptCount sampleSize)
    (selected : Fin attemptCount)
    (selectedValid : TupleValid forbidden (stream selected))
    (earlierInvalid : ∀ earlier : Fin attemptCount,
      earlier.val < selected.val -> ¬TupleValid forbidden (stream earlier)) :
    firstValid forbidden (streamTuples stream) =
      some ⟨stream selected, selectedValid⟩ := by
  let tuples := streamTuples stream
  have selectedBound : selected.val < tuples.length := by
    simp [tuples, streamTuples]
  have selectedGet :
      tuples[selected.val] = stream selected := by
    simp [tuples, streamTuples]
  have decomposition :
      tuples =
        tuples.take selected.val ++
          stream selected :: tuples.drop (selected.val + 1) := by
    calc
      tuples = tuples.take selected.val ++ tuples.drop selected.val :=
        (List.take_append_drop selected.val tuples).symm
      _ = tuples.take selected.val ++
          tuples[selected.val] :: tuples.drop (selected.val + 1) := by
        rw [List.drop_eq_getElem_cons selectedBound]
      _ = tuples.take selected.val ++
          stream selected :: tuples.drop (selected.val + 1) := by
        rw [selectedGet]
  change firstValid forbidden tuples = _
  rw [decomposition]
  apply first_valid_append_of_invalid_prefix
  · intro tuple tupleMembership tupleValid
    rcases List.mem_take_iff_getElem.mp tupleMembership with
      ⟨index, indexBound, tupleEquation⟩
    have indexBefore : index < selected.val :=
      indexBound.trans_le (Nat.min_le_left _ _)
    have indexInStream : index < attemptCount :=
      indexBefore.trans selected.isLt
    let earlier : Fin attemptCount := ⟨index, indexInStream⟩
    apply earlierInvalid earlier indexBefore
    have streamEquation : tuples[index] = stream earlier := by
      simp [tuples, streamTuples, earlier]
    rw [← streamEquation, tupleEquation]
    exact tupleValid

section ActiveTranscript

open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.CanonicalBytes

/-- Canonical 64-bit nonce word for one of the sixteen production retry positions. -/
def activeNonceWord (nonce : Fin piopNonceTrialBound) : Word :=
  ⟨nonce.val, nonce.isLt.trans (by decide)⟩

/-- Exact 16-by-5 field-oracle surface consumed by production PIOP opening selection. -/
def activeOpeningCandidateStream
    (oracle : Oracle)
    (piopHash : List Word) :
    CandidateStream
      (F := FieldWord) piopNonceTrialBound activeParameters.openedEvaluations :=
  fun nonce outputIndex =>
    oracle
      (sha512BlockPreimage piopOpeningDomain
        (activeNonceWord nonce :: piopHash) 0)
      outputIndex.val

/-- The transcript's range/map implementation is extensionally the finite tuple view used above. -/
theorem field_hash_words_eq_ofFn
    (oracle : Oracle)
    (domain : List CanonicalBytes.Byte)
    (words : List Word)
    (outputWords : Nat) :
    fieldHashWords oracle domain words outputWords =
      List.ofFn fun index : Fin outputWords =>
        oracle (sha512BlockPreimage domain words 0) index.val := by
  apply List.ext_getElem
  · simp [fieldHashWords]
  · intro index leftBound rightBound
    simp [fieldHashWords]

/-- Exact production opening list for one nonce, expressed through the finite candidate stream. -/
theorem active_opening_points_eq_stream_tuple
    (oracle : Oracle)
    (piopHash : List Word)
    (nonce : Fin piopNonceTrialBound) :
    openingPoints oracle activeParameters (activeNonceWord nonce) piopHash =
      (List.ofFn (activeOpeningCandidateStream oracle piopHash nonce)).map
        fieldWordAsWord := by
  unfold openingPoints hashWords activeOpeningCandidateStream
  rw [field_hash_words_eq_ofFn]
  rfl

/-- Distinct retry coordinates address distinct random-oracle cells. -/
def activeOpeningOracleRequest
    (piopHash : List Word)
    (coordinate :
      Fin piopNonceTrialBound × Fin activeParameters.openedEvaluations) :
    List CanonicalBytes.Byte × Nat :=
  (sha512BlockPreimage piopOpeningDomain
      (activeNonceWord coordinate.1 :: piopHash) 0,
    coordinate.2.val)

theorem active_nonce_word_injective :
    Function.Injective activeNonceWord := by
  intro left right equal
  apply Fin.ext
  exact congrArg (fun word : Word => word.val) equal

theorem word_bytes_active_nonce_injective :
    Function.Injective (fun nonce : Fin piopNonceTrialBound =>
      wordBytes (activeNonceWord nonce)) := by
  decide

theorem active_opening_nonce_preimage_injective
    (piopHash : List Word) :
    Function.Injective (fun nonce : Fin piopNonceTrialBound =>
      sha512BlockPreimage piopOpeningDomain
        (activeNonceWord nonce :: piopHash) 0) := by
  intro left right equal
  have flattenedEqual :
      flattenWordBytes (activeNonceWord left :: piopHash) =
        flattenWordBytes (activeNonceWord right :: piopHash) := by
    have normalized :
        (encodeLE 8 piopOpeningDomain.length ++
            piopOpeningDomain ++
            encodeLE 8 (activeNonceWord left :: piopHash).length) ++
              flattenWordBytes (activeNonceWord left :: piopHash) ++
              encodeLE 8 0 =
          (encodeLE 8 piopOpeningDomain.length ++
            piopOpeningDomain ++
            encodeLE 8 (activeNonceWord right :: piopHash).length) ++
              flattenWordBytes (activeNonceWord right :: piopHash) ++
              encodeLE 8 0 := by
      simpa [sha512BlockPreimage, List.append_assoc] using equal
    have withoutSuffix := List.append_cancel_right normalized
    exact List.append_cancel_left withoutSuffix
  have nonceBytesEqual :
      wordBytes (activeNonceWord left) =
        wordBytes (activeNonceWord right) := by
    simpa [flattenWordBytes, List.append_assoc] using
      List.append_cancel_right flattenedEqual
  exact word_bytes_active_nonce_injective nonceBytesEqual

theorem active_opening_oracle_request_injective
    (piopHash : List Word) :
    Function.Injective (activeOpeningOracleRequest piopHash) := by
  intro left right equal
  apply Prod.ext
  · apply active_opening_nonce_preimage_injective piopHash
    exact congrArg Prod.fst equal
  · apply Fin.ext
    exact congrArg Prod.snd equal

theorem field_word_as_word_injective :
    Function.Injective fieldWordAsWord := by
  intro left right equal
  apply Fin.ext
  exact congrArg (fun word : Word => word.val) equal

/--
The finite stream validity predicate is exactly the production transcript's nonce-validity rule
when packing points are represented canonically as Goldilocks words.
-/
theorem active_tuple_valid_iff_valid_opening_nonce
    (oracle : Oracle)
    (piopHash : List Word)
    (packingFieldWords : List FieldWord)
    (nonce : Fin piopNonceTrialBound) :
    TupleValid packingFieldWords.toFinset
        (activeOpeningCandidateStream oracle piopHash nonce) ↔
      ValidOpeningNonce oracle activeParameters
        (packingFieldWords.map fieldWordAsWord) piopHash
        (activeNonceWord nonce) := by
  rw [ValidOpeningNonce, active_opening_points_eq_stream_tuple]
  simp only [activeNonceWord, nonceBound, piopNonceTrialBound,
    Fin.is_lt, true_and, CollisionFree, TupleValid]
  rw [List.nodup_map_iff field_word_as_word_injective, List.nodup_ofFn]
  constructor
  · intro validity
    refine ⟨validity.1, ?_⟩
    intro point pointMembership
    rcases List.mem_map.mp pointMembership with
      ⟨fieldPoint, fieldMembership, pointEqual⟩
    subst point
    rcases List.mem_ofFn.mp fieldMembership with ⟨index, pointEqual⟩
    subst fieldPoint
    simpa [List.mem_map_of_injective field_word_as_word_injective] using
      validity.2 index
  · intro validity
    refine ⟨validity.1, ?_⟩
    intro index
    have outside :=
      validity.2
        (fieldWordAsWord
          (activeOpeningCandidateStream oracle piopHash nonce index))
        (List.mem_map.mpr
          ⟨activeOpeningCandidateStream oracle piopHash nonce index,
            List.mem_ofFn.mpr ⟨index, rfl⟩, rfl⟩)
    simpa [List.mem_map_of_injective field_word_as_word_injective] using outside

/--
The transcript's canonical nonce selects exactly the same first valid tuple as the finite sampler.
This is the ordering bridge needed to transfer the equal-fiber theorem to the deployed verifier.
-/
theorem active_canonical_nonce_selects_stream_sample
    (oracle : Oracle)
    (piopHash : List Word)
    (packingFieldWords : List FieldWord)
    (nonce : Fin piopNonceTrialBound)
    (canonical :
      CanonicalOpeningNonce oracle activeParameters
        (packingFieldWords.map fieldWordAsWord) piopHash
        (activeNonceWord nonce)) :
    selectedSample packingFieldWords.toFinset
        (activeOpeningCandidateStream oracle piopHash) =
      some
        (ValidTuple.sample
          (⟨activeOpeningCandidateStream oracle piopHash nonce,
          (active_tuple_valid_iff_valid_opening_nonce
            oracle piopHash packingFieldWords nonce).2 canonical.1⟩ :
          ValidTuple packingFieldWords.toFinset
            activeParameters.openedEvaluations)) := by
  let selectedValid :
      TupleValid packingFieldWords.toFinset
        (activeOpeningCandidateStream oracle piopHash nonce) :=
    (active_tuple_valid_iff_valid_opening_nonce
      oracle piopHash packingFieldWords nonce).2 canonical.1
  have earlierInvalid :
      ∀ earlier : Fin piopNonceTrialBound,
        earlier.val < nonce.val ->
          ¬TupleValid packingFieldWords.toFinset
            (activeOpeningCandidateStream oracle piopHash earlier) := by
    intro earlier earlierBefore earlierValid
    apply canonical.2 (activeNonceWord earlier)
    · simpa [activeNonceWord] using earlierBefore
    · exact (active_tuple_valid_iff_valid_opening_nonce
        oracle piopHash packingFieldWords earlier).1 earlierValid
  unfold selectedSample
  rw [first_valid_stream_of_canonical_index
    packingFieldWords.toFinset
    (activeOpeningCandidateStream oracle piopHash)
    nonce selectedValid earlierInvalid]
  rfl

open Hegemon.Transaction.SmallWoodNoGrindingSoundness

/--
For the exact Goldilocks field, 64 excluded packing points, sixteen canonical nonce attempts, and
five distinct openings, the deployed first-valid sampler realizes exactly epsilon3.
-/
theorem active_first_valid_bad_probability_eq_epsilon3
    (packingFieldWords : List FieldWord)
    (packingCard : packingFieldWords.toFinset.card = activePackingFactor)
    (bad : Finset (Outside packingFieldWords.toFinset))
    (badCard : bad.card = activePiopConsistencyDiscrepancyDegree) :
    conditionalBadSubsetProbability packingFieldWords.toFinset
        piopNonceTrialBound activeParameters.openedEvaluations bad =
      (epsilon3Numerator : Rat) / epsilon3Denominator := by
  have outsideCard :
      Fintype.card (Outside packingFieldWords.toFinset) =
        activePiopOpeningDomainSize := by
    rw [outside_card, packingCard]
    simp [activePiopOpeningDomainSize, goldilocksOrder,
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]
  have sampleFits :
      activeParameters.openedEvaluations ≤
        Fintype.card (Outside packingFieldWords.toFinset) := by
    rw [outsideCard]
    decide
  obtain ⟨referenceSet, _referenceSubset, referenceCard⟩ :=
    Finset.exists_subset_card_eq
      (s := (Finset.univ : Finset (Outside packingFieldWords.toFinset)))
      (n := activeParameters.openedEvaluations)
      (by simpa using sampleFits)
  let reference :
      OpeningSamples packingFieldWords.toFinset
        activeParameters.openedEvaluations :=
    ⟨referenceSet, referenceCard⟩
  rw [conditional_bad_subset_probability_exact_of_positive_attempts
    packingFieldWords.toFinset piopNonceTrialBound
    activeParameters.openedEvaluations (by decide) sampleFits reference bad,
    badCard, outsideCard]
  exact active_epsilon3_is_uniform_root_subset_bound.symm

end ActiveTranscript

end

end HegemonCrypto.SmallWood.PiopOpeningSampling

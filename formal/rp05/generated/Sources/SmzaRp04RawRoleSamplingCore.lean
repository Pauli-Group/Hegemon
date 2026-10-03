import HegemonCrypto.SmallWoodV8Smz9CappedRawSampler
import HegemonCrypto.SmallWoodPiopOpeningSampling
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle
import HegemonCrypto.SmallWoodV8Smz9PiopSoundness
import HegemonCrypto.SmallWoodV8Smz9RobustQueryMismatch

/-!
# Actual RP04 raw-role sampling core

This module connects one injectively selected portion of an actual
`VectorOutput Counter` to the three chronological RP04 algebra cells.  The
512-bit blocks are parsed by the capped rejection sampler.  Exhaustion, an
inadmissible six-point opening, and failure to collect 38 distinct DECS
positions are all represented by `none`.

Consequently the endpoints below bound only the event "decode succeeds and
the decoded role output is bad".  They do not assert that a finite vector of
512-bit blocks has an exactly uniform total image in a Goldilocks vector (that
would be false by divisibility), and they do not condition away rejection.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling

open HegemonCrypto.CmsClassicalDatabase
open V8Smz9RuntimeDistribution V8Smz9RuntimeRandomness
open V8Smz9RuntimeFieldLayout V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8Smz9HiddenLeafQrom
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdaptiveFiniteAccounting.Historical
open V8Smz9AdmissibleRootProbability V8Smz9RobustQueryMismatch
open scoped ENNReal BigOperators Classical

noncomputable section

set_option maxHeartbeats 1500000
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024
set_option Elab.async false

attribute [local irreducible]
  V8Smz9AdaptiveFiniteAccounting.instFintypeFullAdmissibleOpeningTuple

/-! ## Finite partial-uniform accounting -/

abbrev SuccessfulFiber {Input Output : Type*}
    (sample : Input → Option Output) (output : Output) :=
  { input : Input // sample input = some output }

/-- Fix the predicate dictionary for successful fibers once.  Without this
instance, concrete outputs with their own `DecidableEq` produce a different
`Subtype.fintype` tree from the classical finite-pushforward theorem. -/
noncomputable instance (priority := 2000) successfulFiberFintype
    {Input Output : Type*} [Fintype Input]
    (sample : Input → Option Output) (output : Output) :
    Fintype (SuccessfulFiber sample output) :=
  @Subtype.fintype Input (fun input => sample input = some output)
    (fun input => Classical.propDecidable (sample input = some output)) inferInstance

theorem output_event_probability_membership_core {OutputType : Type*}
    [Fintype OutputType] [DecidableEq OutputType] (event : Finset OutputType) :
    outputEventProbability (fun output => output ∈ event) =
      FiniteEvents.probability event := by
  classical
  unfold outputEventProbability FiniteEvents.probability
  apply congrArg (fun outputs : Finset OutputType =>
    (outputs.card : Rat) / Fintype.card OutputType)
  ext output
  simp

/-- Equal successful fibers suffice for a subprobability bound.  Failed
inputs are left in the denominator, so this is stronger than a conditional
uniformity statement and requires no success-probability premise. -/
theorem partial_uniform_bad_probability_le
    {Input Output : Type*} [Fintype Input] [Nonempty Input]
    [Fintype Output] [Nonempty Output] [DecidableEq Output]
    (sample : Input → Option Output)
    (fiberEqual : ∀ left right,
      Fintype.card (SuccessfulFiber sample left) =
        Fintype.card (SuccessfulFiber sample right))
    (bad : Finset Output) :
    outputEventProbability
        (fun input => ∃ output, sample input = some output ∧ output ∈ bad) ≤
      FiniteEvents.probability bad := by
  classical
  let reference : Output := Classical.choice (inferInstance : Nonempty Output)
  let multiplicity := Fintype.card (SuccessfulFiber sample reference)
  let cylinder (output : Output) : Finset Input :=
    Finset.univ.filter fun input => sample input = some output
  let event : Finset Input :=
    Finset.univ.filter fun input =>
      ∃ output, sample input = some output ∧ output ∈ bad
  have each (output : Output) : (cylinder output).card = multiplicity := by
    change (Finset.univ.filter fun input => sample input = some output).card = _
    rw [← Fintype.card_subtype]
    exact fiberEqual output reference
  have eventUnion : event = bad.biUnion cylinder := by
    ext input
    simp only [event, cylinder, Finset.mem_filter, Finset.mem_univ, true_and,
      Finset.mem_biUnion]
    constructor
    · rintro ⟨output, sampled, badOutput⟩
      exact ⟨output, badOutput, sampled⟩
    · rintro ⟨output, badOutput, sampled⟩
      exact ⟨output, sampled, badOutput⟩
  have eventCardBound : event.card ≤ bad.card * multiplicity := by
    calc
      event.card = (bad.biUnion cylinder).card := congrArg Finset.card eventUnion
      _ ≤ ∑ output ∈ bad, (cylinder output).card := Finset.card_biUnion_le
      _ = ∑ _output ∈ bad, multiplicity := by
        apply Finset.sum_congr rfl
        intro output _
        exact each output
      _ = bad.card * multiplicity := by simp
  let Packed := Sigma fun output : Output => SuccessfulFiber sample output
  let forget : Packed → Input := fun packed => packed.2.val
  have forgetInjective : Function.Injective forget := by
    rintro ⟨leftOutput, leftInput⟩ ⟨rightOutput, rightInput⟩ same
    have outputSame : leftOutput = rightOutput := by
      apply Option.some.inj
      calc
        some leftOutput = sample leftInput.val := leftInput.property.symm
        _ = sample rightInput.val := congrArg sample same
        _ = some rightOutput := rightInput.property
    subst rightOutput
    exact Sigma.ext rfl (heq_of_eq (Subtype.ext same))
  have packedBound : Fintype.card Output * multiplicity ≤ Fintype.card Input := by
    have bound := Fintype.card_le_of_injective forget forgetInjective
    have packedCard : Fintype.card Packed = Fintype.card Output * multiplicity := by
      rw [Fintype.card_sigma]
      calc
        (∑ output : Output, Fintype.card (SuccessfulFiber sample output)) =
            ∑ _output : Output, multiplicity := by
          apply Finset.sum_congr rfl
          intro output _
          exact fiberEqual output reference
        _ = Fintype.card Output * multiplicity := by simp
    rwa [packedCard] at bound
  have inputPositive : (0 : Rat) < Fintype.card Input := by
    exact_mod_cast Fintype.card_pos (α := Input)
  have outputPositive : (0 : Rat) < Fintype.card Output := by
    exact_mod_cast Fintype.card_pos (α := Output)
  have eventRat : (event.card : Rat) ≤ (bad.card * multiplicity : Nat) := by
    exact_mod_cast eventCardBound
  have packedRat : (Fintype.card Output * multiplicity : Nat) ≤
      (Fintype.card Input : Rat) := by
    exact_mod_cast packedBound
  have eventProbability :
      outputEventProbability
          (fun input => ∃ output, sample input = some output ∧ output ∈ bad) =
        (event.card : Rat) / Fintype.card Input := by
    unfold outputEventProbability
    apply congrArg (fun outputs : Finset Input =>
      (outputs.card : Rat) / Fintype.card Input)
    ext input
    simp only [event, Finset.mem_filter, Finset.mem_univ, true_and]
  rw [eventProbability]
  unfold FiniteEvents.probability
  apply (div_le_div_iff₀ inputPositive outputPositive).2
  calc
    (event.card : Rat) * Fintype.card Output ≤
        (bad.card * multiplicity : Nat) * Fintype.card Output :=
      mul_le_mul_of_nonneg_right eventRat (by positivity)
    _ = (bad.card : Rat) * (Fintype.card Output * multiplicity : Nat) := by
      push_cast
      ring
    _ ≤ (bad.card : Rat) * Fintype.card Input :=
      mul_le_mul_of_nonneg_left packedRat (by positivity)

/-! ## Actual 512-bit blocks and capped field words -/

def digestBlocksEquiv (blocks : Nat) :
    (Fin blocks → DigestRegister) ≃ (Fin blocks → RawByteBlock) :=
  Equiv.piCongrRight fun _ => rawDigestBits.symm

def selectedRawBlocks {Counter : Type*} {blocks : Nat}
    (select : Fin blocks ↪ Counter) (vector : VectorOutput Counter) :
    Fin blocks → RawByteBlock :=
  fun index => rawDigestBits.symm (vector (select index))

/-- Transport an injective restriction through a coordinate equivalence while
all finite universes are still abstract.  Keeping this proof generic prevents
the elaborator from normalizing the enormous concrete `DigestRegister` table
instance used below. -/
theorem uniform_table_injective_restriction_map_equiv
    {Raw Full Input Output : Type*}
    [Fintype Raw] [Fintype Full] [Fintype Input] [Nonempty Input]
    [Fintype Output] [Nonempty Output]
    (select : Raw ↪ Full) (allocation : Input ≃ Output) :
    pmfMap (uniformFintypePMF (Full → Input))
        (fun table input => allocation (table (select input))) =
      uniformFintypePMF (Raw → Output) := by
  have restricted :
      pmfMap (uniformFintypePMF (Full → Input))
          (fun table input => table (select input)) =
        uniformFintypePMF (Raw → Input) :=
    uniform_table_injective_restriction select select.injective
  let coordinatewise : (Raw → Input) ≃ (Raw → Output) :=
    Equiv.piCongrRight fun _ => allocation
  have mapped := congrArg (fun law => pmfMap law coordinatewise) restricted
  rw [pmfMap_comp, uniform_pmf_map_equiv] at mapped
  have transportFunction :
      (coordinatewise ∘
          (fun table : Full → Input => fun input : Raw => table (select input))) =
        (fun table : Full → Input => fun input : Raw =>
          allocation (table (select input))) := by
    funext table input
    rfl
  rw [transportFunction] at mapped
  exact mapped

/-- Pin the concrete coordinate instances behind opaque names.  The theorem
below transports separately synthesized table instances by subsingleton
equality, so these definitions never need to normalize the 512-bit enum. -/
private structure ExactFintype (α : Type*) where
  value : Fintype α

private noncomputable def exactDigestRegisterFintype :
    ExactFintype DigestRegister :=
  ⟨inferInstance⟩

private noncomputable def exactRawByteBlockFintype :
    ExactFintype RawByteBlock :=
  ⟨inferInstance⟩

attribute [local irreducible] Pi.instFintype exactDigestRegisterFintype
  exactRawByteBlockFintype rawDigestBits

theorem uniform_table_injective_restriction_map_equiv_with_instances
    {Raw Full Input Output : Type*}
    [Fintype Raw] [Fintype Full] [Fintype Input] [Nonempty Input]
    [Fintype Output] [Nonempty Output]
    (fullTableFintype : Fintype (Full → Input))
    (outputTableFintype : Fintype (Raw → Output))
    (select : Raw ↪ Full) (allocation : Input ≃ Output) :
    @pmfMap (Full → Input) (Raw → Output)
        (@uniformFintypePMF (Full → Input) fullTableFintype inferInstance)
        (fun table input => allocation (table (select input))) =
      @uniformFintypePMF (Raw → Output) outputTableFintype inferInstance := by
  have fullTableFintypeEq :
      fullTableFintype = (Pi.instFintype : Fintype (Full → Input)) :=
    Subsingleton.elim _ _
  have outputTableFintypeEq :
      outputTableFintype = (Pi.instFintype : Fintype (Raw → Output)) :=
    Subsingleton.elim _ _
  rw [fullTableFintypeEq, outputTableFintypeEq]
  exact uniform_table_injective_restriction_map_equiv select allocation

theorem selected_raw_blocks_uniform {Counter : Type*}
    [counterFintype : Fintype Counter]
    {blocks : Nat} (select : Fin blocks ↪ Counter) :
    pmfMap (uniformFintypePMF (VectorOutput Counter)) (selectedRawBlocks select) =
      uniformFintypePMF (Fin blocks → RawByteBlock) := by
  let fullTableFintype : Fintype (VectorOutput Counter) := inferInstance
  let outputTableFintype : Fintype (Fin blocks → RawByteBlock) := inferInstance
  unfold selectedRawBlocks
  exact
    @uniform_table_injective_restriction_map_equiv_with_instances
      (Fin blocks) Counter DigestRegister RawByteBlock
      (inferInstance : Fintype (Fin blocks))
      counterFintype
      exactDigestRegisterFintype.value
      (inferInstance : Nonempty DigestRegister)
      exactRawByteBlockFintype.value
      (inferInstance : Nonempty RawByteBlock)
      fullTableFintype outputTableFintype select rawDigestBits.symm

def rawFieldSample (blocks requested : Nat)
    (raw : Fin blocks → RawByteBlock) :
    Option (FieldOutput sourceFieldSize requested) :=
  sourceScan (blocks * 8) requested
    (blockWordsEquiv blocks (byteBlockVectorEquiv blocks raw))

theorem raw_field_sample_law (blocks requested : Nat) :
    pmfMap (uniformFintypePMF (Fin blocks → RawByteBlock))
        (rawFieldSample blocks requested) =
      byteBlockCappedLaw blocks requested := rfl

/-- Cancel the common finite-uniform point mass before any concrete raw block
or field-vector type is substituted. -/
theorem successful_fiber_card_eq_of_uniform_mass
    {Input Output : Type*} [Fintype Input] [Nonempty Input]
    (sample : Input → Option Output) (left right : Output)
    (sameMass :
      pmfMap (uniformFintypePMF Input) sample (some left) =
        pmfMap (uniformFintypePMF Input) sample (some right)) :
    Fintype.card (SuccessfulFiber sample left) =
      Fintype.card (SuccessfulFiber sample right) := by
  have leftMass := finite_uniform_pushforward_fiber_mass sample (some left)
  have rightMass := finite_uniform_pushforward_fiber_mass sample (some right)
  have multiplied :
      (Fintype.card (SuccessfulFiber sample left) : ENNReal) *
          (Fintype.card Input : ENNReal)⁻¹ =
        (Fintype.card (SuccessfulFiber sample right) : ENNReal) *
          (Fintype.card Input : ENNReal)⁻¹ := by
    exact leftMass.symm.trans (sameMass.trans rightMass)
  have scalarNonzero : (Fintype.card Input : ENNReal)⁻¹ ≠ 0 := by simp
  have scalarFinite : (Fintype.card Input : ENNReal)⁻¹ ≠ ∞ := by simp
  exact_mod_cast (ENNReal.mul_left_inj scalarNonzero scalarFinite).mp multiplied

theorem raw_field_success_fibers_equal (blocks requested : Nat)
    (left right : FieldOutput sourceFieldSize requested) :
    Fintype.card (SuccessfulFiber (rawFieldSample blocks requested) left) =
      Fintype.card (SuccessfulFiber (rawFieldSample blocks requested) right) := by
  have sameMass : byteBlockCappedLaw blocks requested (some left) =
      byteBlockCappedLaw blocks requested (some right) := by
    rw [same_uniform_byte_blocks_capped_law, same_uniform_blocks_capped_law,
      literal_u64_capped_law, same_finite_vector_successful_output_mass,
      same_finite_vector_successful_output_mass]
  have sampledSameMass :
      pmfMap (uniformFintypePMF (Fin blocks → RawByteBlock))
          (rawFieldSample blocks requested) (some left) =
        pmfMap (uniformFintypePMF (Fin blocks → RawByteBlock))
          (rawFieldSample blocks requested) (some right) := by
    rw [raw_field_sample_law]
    exact sameMass
  exact successful_fiber_card_eq_of_uniform_mass
    (rawFieldSample blocks requested) left right sampledSameMass

def decoderBadInputs {Middle Output : Type*} [Fintype Middle]
    [DecidableEq Middle] (decode : Middle → Option Output)
    (bad : Finset Output) : Finset Middle :=
  Finset.univ.filter fun middle =>
    ∃ output, decode middle = some output ∧ output ∈ bad

theorem raw_field_then_partial_decoder_bad_le
    {Output : Type*} [Fintype Output] [Nonempty Output] [DecidableEq Output]
    (blocks requested : Nat)
    (decode : FieldOutput sourceFieldSize requested → Option Output)
    (decodeFiberEqual : ∀ left right,
      Fintype.card (SuccessfulFiber decode left) =
        Fintype.card (SuccessfulFiber decode right))
    (bad : Finset Output) :
    outputEventProbability (fun raw : Fin blocks → RawByteBlock =>
        ∃ output,
          (rawFieldSample blocks requested raw).bind decode = some output ∧
            output ∈ bad) ≤
      FiniteEvents.probability bad := by
  classical
  let middleBad := decoderBadInputs decode bad
  have rawBound := partial_uniform_bad_probability_le
    (rawFieldSample blocks requested)
    (raw_field_success_fibers_equal blocks requested) middleBad
  have decodeBound := partial_uniform_bad_probability_le decode decodeFiberEqual bad
  have eventSame :
      outputEventProbability (fun raw : Fin blocks → RawByteBlock =>
          ∃ output,
            (rawFieldSample blocks requested raw).bind decode = some output ∧
              output ∈ bad) =
        outputEventProbability (fun raw : Fin blocks → RawByteBlock =>
          ∃ middle, rawFieldSample blocks requested raw = some middle ∧
            middle ∈ middleBad) := by
    apply congrArg outputEventProbability
    funext raw
    apply propext
    cases sampled : rawFieldSample blocks requested raw with
    | none => simp
    | some middle =>
        simp only [Option.bind_some]
        simp [middleBad, decoderBadInputs]
  calc
    _ = outputEventProbability (fun raw : Fin blocks → RawByteBlock =>
          ∃ middle, rawFieldSample blocks requested raw = some middle ∧
            middle ∈ middleBad) := eventSame
    _ ≤ FiniteEvents.probability middleBad := rawBound
    _ = outputEventProbability (fun middle =>
          ∃ output, decode middle = some output ∧ output ∈ bad) := by
      have decoderEvent :
          (fun middle => ∃ output, decode middle = some output ∧ output ∈ bad) =
            (fun middle => middle ∈ middleBad) := by
        funext middle
        apply propext
        simp [middleBad, decoderBadInputs]
      symm
      rw [decoderEvent, output_event_probability_membership_core]
    _ ≤ FiniteEvents.probability bad := decodeBound

/-! ## Exact six-point and matrix decoders -/

def matrixFieldEquiv (width : Nat) :
    FieldOutput sourceFieldSize (5 * width) ≃ Matrix width :=
  (Equiv.piCongrRight fun _ => idealFieldCoinEquivGoldilocks).trans
    (matrixEquiv 5 width Goldilocks)

def totalEquivDecoder {Input Output : Type*} (equivalence : Input ≃ Output) :
    Input → Option Output := fun input => some (equivalence input)

def openingPointsEmbedding : Opening ↪ OpeningTuple where
  toFun opening := baseOpeningPoints opening.1
  inj' := by
    intro left right same
    apply Subtype.ext
    apply DFunLike.ext _ _
    intro coordinate
    apply Subtype.ext
    exact congrFun same coordinate

abbrev RejectedOpeningPoints :=
  { points : OpeningTuple // points ∉ Set.range openingPointsEmbedding }

def openingPointPartition : Opening ⊕ RejectedOpeningPoints ≃ OpeningTuple :=
  (Equiv.sumCongr (Equiv.ofInjective openingPointsEmbedding
      openingPointsEmbedding.injective) (Equiv.refl _)).trans
    (Equiv.Set.sumCompl (Set.range openingPointsEmbedding))

@[simp] theorem opening_point_partition_on_opening (opening : Opening) :
    openingPointPartition (.inl opening) = openingPointsEmbedding opening := rfl

@[simp] theorem opening_point_partition_inverse_opening (opening : Opening) :
    openingPointPartition.symm (openingPointsEmbedding opening) = .inl opening :=
  openingPointPartition.symm_apply_apply (.inl opening)

def decodeFullOpening (points : OpeningTuple) : Option Opening :=
  match openingPointPartition.symm points with
  | .inl opening => some opening
  | .inr _ => none

theorem decode_full_opening_eq_some_iff (points : OpeningTuple)
    (opening : Opening) :
    decodeFullOpening points = some opening ↔
      points = openingPointsEmbedding opening := by
  constructor
  · intro decoded
    unfold decodeFullOpening at decoded
    cases partitioned : openingPointPartition.symm points with
    | inl selected =>
        simp only [partitioned, Option.some.injEq] at decoded
        subst selected
        calc
          points = openingPointPartition (openingPointPartition.symm points) :=
            (openingPointPartition.apply_symm_apply points).symm
          _ = openingPointsEmbedding opening := by rw [partitioned]; rfl
    | inr rejected => simp [partitioned] at decoded
  · intro equal
    subst points
    simp [decodeFullOpening]

def openingFieldEquiv :
    FieldOutput sourceFieldSize piopOpenings ≃ OpeningTuple :=
  Equiv.piCongrRight fun _ => idealFieldCoinEquivGoldilocks

def openingDecoder
    (coins : FieldOutput sourceFieldSize piopOpenings) : Option Opening :=
  decodeFullOpening (openingFieldEquiv coins)

theorem opening_decoder_eq_some_iff
    (coins : FieldOutput sourceFieldSize piopOpenings) (opening : Opening) :
    openingDecoder coins = some opening ↔
      coins = openingFieldEquiv.symm (openingPointsEmbedding opening) := by
  rw [openingDecoder, decode_full_opening_eq_some_iff]
  constructor
  · intro equal
    exact openingFieldEquiv.injective
      (equal.trans (openingFieldEquiv.apply_symm_apply _).symm)
  · intro equal
    subst coins
    exact openingFieldEquiv.apply_symm_apply _

def singletonDecoderFiberEquiv {Input Output : Type*}
    (decode : Input → Option Output) (encode : Output → Input)
    (exact : ∀ input output, decode input = some output ↔ input = encode output)
    (left right : Output) :
    SuccessfulFiber decode left ≃ SuccessfulFiber decode right where
  toFun _ := ⟨encode right, (exact _ _).2 rfl⟩
  invFun _ := ⟨encode left, (exact _ _).2 rfl⟩
  left_inv input := by
    apply Subtype.ext
    exact ((exact input.val left).1 input.property).symm
  right_inv input := by
    apply Subtype.ext
    exact ((exact input.val right).1 input.property).symm

theorem singleton_decoder_fibers_equal {Input Output : Type*}
    [Fintype Input] [Fintype Output]
    (decode : Input → Option Output) (encode : Output → Input)
    (exact : ∀ input output, decode input = some output ↔ input = encode output)
    (left right : Output) :
    Fintype.card (SuccessfulFiber decode left) =
      Fintype.card (SuccessfulFiber decode right) := by
  exact Fintype.card_congr
    (singletonDecoderFiberEquiv decode encode exact left right)

theorem total_equiv_decoder_fibers_equal {Input Output : Type*}
    [Fintype Input] [Fintype Output] (equivalence : Input ≃ Output) :
    ∀ left right,
      Fintype.card (SuccessfulFiber (totalEquivDecoder equivalence) left) =
        Fintype.card (SuccessfulFiber (totalEquivDecoder equivalence) right) := by
  apply singleton_decoder_fibers_equal
    (totalEquivDecoder equivalence) equivalence.symm
  intro input output
  unfold totalEquivDecoder
  simp only [Option.some.injEq]
  constructor
  · intro equal
    rw [← equal]
    exact (equivalence.symm_apply_apply input).symm
  · intro equal
    rw [equal]
    exact equivalence.apply_symm_apply output

theorem opening_decoder_fibers_equal : ∀ left right,
    Fintype.card (SuccessfulFiber openingDecoder left) =
      Fintype.card (SuccessfulFiber openingDecoder right) := by
  apply singleton_decoder_fibers_equal openingDecoder
    (fun opening => openingFieldEquiv.symm (openingPointsEmbedding opening))
  exact opening_decoder_eq_some_iff

theorem actual_piop_opening_count_is_six : piopOpenings = 6 := by decide

end
end HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling

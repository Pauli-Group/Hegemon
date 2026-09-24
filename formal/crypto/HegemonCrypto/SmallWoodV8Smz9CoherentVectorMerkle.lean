import HegemonCrypto.SmallWoodV8Smz9CoherentMerklePartition
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler

/-!
# Counter-vector source extraction

The output group is the entire vector of raw XOR digests. The extraction
partition reads one relevant coordinate per logical record, and its classical
instability is counted using that coordinate's exact uniform marginal.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CoherentVectorMerkle

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsFullOperatorProof HegemonCrypto.CmsFinitePhaseSystem
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentMerklePartition V8Smz9HiddenLeafQrom

noncomputable section

set_option maxRecDepth 4096
set_option maxHeartbeats 1000000
set_option exponentiation.threshold 1024

local instance : DecidableEq RawInput := (inferInstance : LinearOrder RawInput).toDecidableEq

section Counting

variable {Counter Output : Type*} [Fintype Counter] [DecidableEq Counter] [Fintype Output]

/-- Splitting a full vector at one coordinate also splits any event on that
coordinate. This is a finite bijection, not an independence hypothesis. -/
def coordinateEventEquiv (counter : Counter) (event : Output → Prop) :
    { vector : Counter → Output // event (vector counter) } ≃
      { output : Output // event output } × ({ other : Counter // other ≠ counter } → Output) where
  toFun vector := (⟨vector.val counter, vector.property⟩,
    (Equiv.piSplitAt counter (fun _ : Counter => Output) vector.val).2)
  invFun pair := ⟨(Equiv.piSplitAt counter (fun _ : Counter => Output)).symm
    (pair.1.val, pair.2), by simpa using pair.1.property⟩
  left_inv vector := by
    apply Subtype.ext
    exact (Equiv.piSplitAt counter (fun _ : Counter => Output)).symm_apply_apply vector.val
  right_inv pair := by
    apply Prod.ext
    · apply Subtype.ext
      exact congrArg Prod.fst
        ((Equiv.piSplitAt counter (fun _ : Counter => Output)).apply_symm_apply
          (pair.1.val, pair.2))
    · exact congrArg (fun value : Output × ({ other : Counter // other ≠ counter } → Output) => value.2)
        ((Equiv.piSplitAt counter (fun _ : Counter => Output)).apply_symm_apply
          (pair.1.val, pair.2))

theorem coordinate_event_card (counter : Counter) (event : Output → Prop) [DecidablePred event] :
    (Finset.univ.filter fun vector : Counter → Output => event (vector counter)).card =
      (Finset.univ.filter event).card *
        Fintype.card ({ other : Counter // other ≠ counter } → Output) := by
  have cardinal := Fintype.card_congr (coordinateEventEquiv counter event)
  simpa only [Fintype.card_prod, Fintype.card_subtype] using cardinal

/-- Exact event probability on one coordinate of a uniformly sampled vector. -/
theorem coordinate_event_probability [Nonempty Output]
    (counter : Counter) (event : Output → Prop) [DecidablePred event] :
    ((Finset.univ.filter fun vector : Counter → Output => event (vector counter)).card : ℚ) /
        Fintype.card (Counter → Output) =
      ((Finset.univ.filter event).card : ℚ) / Fintype.card Output := by
  have cardinal := Fintype.card_congr (Equiv.piSplitAt counter (fun _ : Counter => Output))
  rw [Fintype.card_prod] at cardinal
  rw [coordinate_event_card, cardinal, Nat.cast_mul, Nat.cast_mul]
  have nonzero : (Fintype.card ({ other : Counter // other ≠ counter } → Output) : ℚ) ≠ 0 := by
    exact_mod_cast Fintype.card_ne_zero
  exact mul_div_mul_right _ _ nonzero

theorem equiv_event_card {Other : Type*} [DecidableEq Other]
    (equivalence : Output ≃ Other) (event : Finset Other) :
    (Finset.univ.filter fun output : Output => equivalence output ∈ event).card = event.card := by
  apply Finset.card_bij (fun output _ => equivalence output)
  · intro output member
    exact (Finset.mem_filter.mp member).2
  · intro left _ right _ same
    exact equivalence.injective same
  · intro other member
    refine ⟨equivalence.symm other, Finset.mem_filter.mpr ⟨Finset.mem_univ _, ?_⟩, ?_⟩
    · simpa using member
    · simp

end Counting

section FullVectorPhase

variable {Counter : Type*} [Fintype Counter] [DecidableEq Counter]

abbrev VectorOutput (Counter : Type*) := Counter → DigestRegister

/-- Full product Walsh pairing: every counter and every output bit remains
part of the actual query operator. -/
def vectorCharacter (phase : VectorOutput Counter) : AddChar (VectorOutput Counter) ℂ where
  toFun output := ∏ counter, digestCharacter (phase counter) (output counter)
  map_zero_eq_one' := by simp
  map_add_eq_mul' := by
    intro left right
    simp only [Pi.add_apply, AddChar.map_add_eq_mul, Finset.prod_mul_distrib]

theorem vector_character_single (phase : VectorOutput Counter) (counter : Counter)
    (output : DigestRegister) :
    vectorCharacter phase (Pi.single counter output) = digestCharacter (phase counter) output := by
  simp only [vectorCharacter, AddChar.coe_mk]
  rw [Finset.prod_eq_single counter]
  · simp
  · intro other _ different
    simp [Ne.symm different]
  · simp

theorem vector_character_injective : Function.Injective (vectorCharacter (Counter := Counter)) := by
  intro left right same
  funext counter
  apply digest_character_injective
  ext output
  simpa only [vector_character_single] using DFunLike.congr_fun same (Pi.single counter output)

omit [DecidableEq Counter] in
theorem vector_character_zero : vectorCharacter (0 : VectorOutput Counter) = 0 := by
  ext output
  simp [vectorCharacter, digest_character_zero]

def vectorPhaseSystem : PhaseSystem (VectorOutput Counter) (VectorOutput Counter) where
  character := vectorCharacter
  zeroPhase := 0
  character_zero := vector_character_zero
  character_nonzero _ different same :=
    different (vector_character_injective (same.trans vector_character_zero.symm))

def vectorCompletePhaseSystem : CompletePhaseSystem (VectorOutput Counter) (VectorOutput Counter) where
  system := vectorPhaseSystem
  characterInjective := vector_character_injective
  phaseDimension := rfl

end FullVectorPhase

section VectorInstability

variable {Key Counter Answer : Type*}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]

def vectorOutputBytes (counter : Counter) (vector : VectorOutput Counter) : RawDigest :=
  rawDigestBits.symm (vector counter)

def vectorSourceLabel (keyBytes : Key → RawInput) (counter : Counter) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) (database : Database Key (VectorOutput Counter)) :=
  sourceLabel keyBytes (vectorOutputBytes counter) fuel targets database

/-- One fresh logical record contributes one uniform 512-bit graph digest,
even though the full query answer contains all counter blocks. -/
theorem vector_source_step_change_bound (keyBytes : Key → RawInput) (counter : Counter)
    (fuel : ℕ) (targets : List (SourceStage × RawDigest)) (queryBound : ℕ)
    (targetBudget : targets.length ≤ queryBound)
    (database : Database Key (VectorOutput Counter)) (recordBudget : size database < queryBound)
    (key : Key) (event : Property Key (VectorOutput Counter))
    (changed : ∀ output, event (query database key output) →
      vectorSourceLabel keyBytes counter fuel targets (query database key output) ≠
        vectorSourceLabel keyBytes counter fuel targets database) :
    stepProbability event database key ≤ (3 * queryBound : ℚ) / (2 ^ 512 : ℚ) := by
  by_cases absent : database key = none
  · let changedDigests := changedOutputs sourceNext
      (rawRecords keyBytes (vectorOutputBytes counter) database) (keyBytes key) fuel targets
    have subset : successfulAnswers event database key ⊆
        Finset.univ.filter (fun vector => rawDigestBits.symm (vector counter) ∈ changedDigests) := by
      intro output member
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ _, Finset.mem_filter.mpr ⟨Finset.mem_univ _, ?_⟩⟩
      have changes := changed output (Finset.mem_filter.mp member).2
      simpa only [vectorSourceLabel, query_of_absent absent, sourceLabel,
        raw_records_insert keyBytes (vectorOutputBytes counter) database key output absent,
        vectorOutputBytes] using changes
    have digestCard : (Finset.univ.filter fun output : DigestRegister =>
        rawDigestBits.symm output ∈ changedDigests).card = changedDigests.card :=
      equiv_event_card rawDigestBits.symm changedDigests
    calc
      stepProbability event database key ≤
          ((Finset.univ.filter fun vector : VectorOutput Counter =>
            rawDigestBits.symm (vector counter) ∈ changedDigests).card : ℚ) /
              Fintype.card (VectorOutput Counter) := by
        apply div_le_div_of_nonneg_right
        · exact_mod_cast Finset.card_le_card subset
        · positivity
      _ = (changedDigests.card : ℚ) / (2 ^ 512 : ℚ) := by
        rw [coordinate_event_probability counter (fun output => rawDigestBits.symm output ∈ changedDigests), digestCard,
          V8Smz9RawCounterCompiler.digest_register_cardinality]
        simp only [Nat.cast_pow, Nat.cast_ofNat]
      _ ≤ _ := by
        have bound := source_classical_instability_three_t
          (rawRecords keyBytes (vectorOutputBytes counter) database) (keyBytes key) fuel targets
          queryBound (lt_of_le_of_lt (raw_records_card_le _ _ _) recordBudget) targetBudget
        simpa only [uniformChangeProbability, raw_digest_cardinality, Nat.cast_pow,
          Nat.cast_ofNat, changedDigests] using bound
  · rw [step_probability_eq_zero_of_never event database key]
    · positivity
    · intro output eventTrue
      apply changed output eventTrue
      simp [query, absent]

theorem vector_source_value_instability (keyBytes : Key → RawInput) (counter : Counter)
    (fuel : ℕ) (targets : List (SourceStage × RawDigest)) (queryBound : ℕ)
    (targetBudget : targets.length ≤ queryBound)
    (value : Database Key (VectorOutput Counter) → Answer)
    (stable : ∀ left right, vectorSourceLabel keyBytes counter fuel targets left =
      vectorSourceLabel keyBytes counter fuel targets right → value left = value right)
    (test : Answer → Prop) :
    InstabilityBound (fun database => test (value database)) queryBound
      ((3 * queryBound : ℚ) / (2 ^ 512 : ℚ)) := by
  constructor
  · refine ⟨by positivity, ?_⟩
    intro database outside recordBudget key
    apply vector_source_step_change_bound keyBytes counter fuel targets queryBound targetBudget
      database recordBudget key _
    intro output accepted same
    apply outside
    change test (value (query database key output)) at accepted
    simpa only [stable _ _ same] using accepted
  · refine ⟨by positivity, ?_⟩
    intro database inside recordBudget key
    apply vector_source_step_change_bound keyBytes counter fuel targets queryBound targetBudget
      database recordBudget key _
    intro output rejected same
    apply rejected
    rw [stable _ _ same]
    exact inside

variable {Workspace : Type*} [Fintype Answer] [DecidableEq Answer] [AddGroup Answer]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Actual full-vector CMS query and actual full-answer extraction, with no
counter-cardinality penalty in the source instability numerator. -/
theorem vector_source_actual_full_extraction_bound
    (keyBytes : Key → RawInput) (counter : Counter) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) (queryBound supportBound : ℕ)
    (targetBudget : targets.length ≤ queryBound) (below : supportBound < queryBound)
    (value : Database Key (VectorOutput Counter) → Answer)
    (stable : ∀ left right, vectorSourceLabel keyBytes counter fuel targets left =
      vectorSourceLabel keyBytes counter fuel targets right → value left = value right)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) (Answer × Workspace))
    (bounded : BoundedState supportBound state) :
    normSquared (permute (answerShift value) (queryState vectorPhaseSystem queryBound state) -
      queryState vectorPhaseSystem queryBound (permute (answerShift value) state)) ≤
      (576 * queryBound / (2 ^ 512 : ℝ)) * normSquared state := by
  have result := full_answer_actual_query_bound vectorPhaseSystem queryBound supportBound value
    (((3 * queryBound : ℚ) / (2 ^ 512 : ℚ)) : ℝ)
    (fun test => by
      simpa only [Rat.cast_div] using
        (vector_source_value_instability keyBytes counter fuel targets queryBound
          targetBudget value stable test).toReal) state below bounded
  convert result using 1
  push_cast
  ring

end VectorInstability

section CoherentVectorTargets

variable {Key Counter Target Answer Workspace : Type*}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
variable [Fintype Target] [DecidableEq Target]
variable [Fintype Answer] [DecidableEq Answer] [AddGroup Answer]
variable [Fintype Workspace] [DecidableEq Workspace]

def VectorLabelRange (keyBytes : Key → RawInput) (counter : Counter) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) :=
  Set.range (fun pair : Target × Database Key (VectorOutput Counter) =>
    vectorSourceLabel keyBytes counter fuel (targets pair.1) pair.2)

instance (keyBytes : Key → RawInput) (counter : Counter) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) :
    Fintype (VectorLabelRange keyBytes counter fuel targets) :=
  Fintype.ofSurjective
    (fun pair : Target × Database Key (VectorOutput Counter) =>
      (⟨vectorSourceLabel keyBytes counter fuel (targets pair.1) pair.2,
        ⟨pair, rfl⟩⟩ : VectorLabelRange keyBytes counter fuel targets))
    (by rintro ⟨value, ⟨pair, rfl⟩⟩; exact ⟨pair, rfl⟩)

def vectorRangeValue (keyBytes : Key → RawInput) (counter : Counter) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) (target : Target)
    (database : Database Key (VectorOutput Counter)) : VectorLabelRange keyBytes counter fuel targets :=
  ⟨vectorSourceLabel keyBytes counter fuel (targets target) database, ⟨(target, database), rfl⟩⟩

/-- Full product-Walsh vector query with arbitrary superposed targets and
entangled answer/workspace, without a target-dimension factor. -/
theorem coherent_vector_source_commutator_bound
    (keyBytes : Key → RawInput) (counter : Counter) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest)) (queryBound supportBound : ℕ)
    (targetBudget : ∀ target, (targets target).length ≤ queryBound) (below : supportBound < queryBound)
    (value : Target → Database Key (VectorOutput Counter) → Answer)
    (stable : ∀ target left right, vectorSourceLabel keyBytes counter fuel (targets target) left =
      vectorSourceLabel keyBytes counter fuel (targets target) right → value target left = value target right)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) (Target × Answer × Workspace))
    (bounded : BoundedState supportBound state) :
    normSquared (extractionLinearEquiv value (queryState vectorPhaseSystem queryBound state) -
      queryState vectorPhaseSystem queryBound (extractionLinearEquiv value state)) ≤
      (576 * queryBound / (2 ^ 512 : ℝ)) * normSquared state := by
  rw [mass_eq_sum_target_slices, mass_eq_sum_target_slices state, Finset.mul_sum]
  apply Finset.sum_le_sum
  intro target _
  have sliceSub : ∀ left right :
      State Key (VectorOutput Counter) (VectorOutput Counter) (Target × Answer × Workspace),
      targetSlice (left - right) target = targetSlice left target - targetSlice right target := by
    intro left right
    rfl
  rw [sliceSub, target_slice_extraction, target_slice_query, target_slice_query, target_slice_extraction]
  exact vector_source_actual_full_extraction_bound keyBytes counter fuel (targets target)
    queryBound supportBound (targetBudget target) below (value target) (stable target)
    (targetSlice state target) (target_slice_bounded supportBound state bounded target)

/-- Faithful whole-source-trace endpoint for the vector oracle. The only codec
premise is injectivity of a finite representation, never extraction success. -/
theorem coherent_faithful_vector_source_commutator_bound
    (keyBytes : Key → RawInput) (counter : Counter) (fuel : ℕ)
    (targets : Target → List (SourceStage × RawDigest))
    (encoding : VectorLabelRange keyBytes counter fuel targets ↪ Answer)
    (queryBound supportBound : ℕ)
    (targetBudget : ∀ target, (targets target).length ≤ queryBound) (below : supportBound < queryBound)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) (Target × Answer × Workspace))
    (bounded : BoundedState supportBound state) :
    normSquared (extractionLinearEquiv
        (fun target database => encoding (vectorRangeValue keyBytes counter fuel targets target database))
        (queryState vectorPhaseSystem queryBound state) -
      queryState vectorPhaseSystem queryBound
        (extractionLinearEquiv
          (fun target database => encoding (vectorRangeValue keyBytes counter fuel targets target database)) state)) ≤
      (576 * queryBound / (2 ^ 512 : ℝ)) * normSquared state := by
  apply coherent_vector_source_commutator_bound keyBytes counter fuel targets queryBound supportBound
    targetBudget below _ _ state bounded
  intro target left right same
  exact congrArg encoding (Subtype.ext same)

end CoherentVectorTargets

section ExactRawProjection

open HegemonCrypto.CanonicalBytes
open V8Smz9RawCounterCompiler (counterInput sourcePrefix Complement fullRawDomainEquiv
  fullRawPaddedCoordinate paddedCoordinate full_raw_domain_inverse_counter
  full_raw_domain_inverse_complement)

/-- The source Merkle grammar excludes every nonzero counter of a canonical
source prefix. This does not claim that all SHA-512 uses have counter zero. -/
theorem parse_framed_counter_roundtrip (role : List HegemonCrypto.CanonicalBytes.Byte) (words : List ℕ)
    (counter : Fin (2 ^ 64)) (roleBound : role.length < 256 ^ 8)
    (wordBound : words.length < 256 ^ 8) :
    parseFramed (counterInput (sourcePrefix role words) counter) =
      if counter.val = 0 then some (role, (words.map (encodeLE 8)).flatten) else none := by
  have payloadLength : ((words.map (encodeLE 8)).flatten).length = 8 * words.length := by
    clear wordBound
    induction words with
    | nil => rfl
    | cons word words induction => simp [encodeLE_length, induction, Nat.mul_add, Nat.add_comm]
  have profileLength : V8Smz9WholeViewObservation.smz9ProfileDomain.length = 53 := by decide
  have roleMod : role.length % 18446744073709551616 = role.length := Nat.mod_eq_of_lt roleBound
  have wordMod : words.length % 18446744073709551616 = words.length := Nat.mod_eq_of_lt wordBound
  have counterMod : counter.val % 256 ^ 8 = counter.val := Nat.mod_eq_of_lt counter.isLt
  simp [parseFramed, counterInput, sourcePrefix, List.append_assoc, readFixed,
    encodeLE_length, decodeLE_encodeLE, roleMod, wordMod, profileLength,
    payloadLength]
  have counterTake : (encodeLE 8 counter.val).take 8 = encodeLE 8 counter.val := by
    simpa only [encodeLE_length] using (List.take_length (l := encodeLE 8 counter.val))
  rw [counterTake, decodeLE_encodeLE, counterMod]
  simp only [Fin.val_eq_zero_iff]

theorem source_next_nonzero_counter (role : List HegemonCrypto.CanonicalBytes.Byte) (words : List ℕ)
    (counter : Fin (2 ^ 64)) (roleBound : role.length < 256 ^ 8)
    (wordBound : words.length < 256 ^ 8) (nonzero : counter.val ≠ 0) (stage : SourceStage) :
    sourceNext stage (counterInput (sourcePrefix role words) counter) = none := by
  simp [sourceNext, parseSource,
    parse_framed_counter_roundtrip role words counter roleBound wordBound, nonzero]

variable {Raw Key Counter : Type*} [Fintype Raw] [Fintype Key] [Fintype Counter]
variable [DecidableEq Raw] [DecidableEq Key] [DecidableEq Counter]

/-- Expand every represented raw coordinate, including the retained raw
complement. This finite definition is semantic; no expanded table is built. -/
def expandedRawRecords (rawBytes : Raw → RawInput) (address : Raw → Key × Counter)
    (database : Database Key (VectorOutput Counter)) : Records RawInput RawDigest :=
  (Finset.univ.filter fun pair : Raw × VectorOutput Counter =>
    database (address pair.1).1 = some pair.2).image
      (fun pair => (rawBytes pair.1, rawDigestBits.symm (pair.2 (address pair.1).2)))

omit [DecidableEq Raw] [DecidableEq Key] in
/-- Exact equality of source candidates after projection. Relevant coordinates
must be the representative coordinate; all other raw records are retained by
the oracle but rejected by the source grammar. -/
theorem expanded_candidates_eq_projected
    (rawBytes : Raw → RawInput) (address : Raw → Key × Counter)
    (representative : Key → Raw) (counter : Counter)
    (representativeAddress : ∀ key, address (representative key) = (key, counter))
    (relevant : ∀ raw stage, (sourceNext stage (rawBytes raw)).isSome →
      rawBytes raw = rawBytes (representative (address raw).1) ∧ (address raw).2 = counter)
    (database : Database Key (VectorOutput Counter)) (stage : SourceStage) (target : RawDigest) :
    candidateInputs sourceNext (expandedRawRecords rawBytes address database) stage target =
      candidateInputs sourceNext
        (rawRecords (rawBytes ∘ representative) (vectorOutputBytes counter) database) stage target := by
  ext input
  constructor
  · intro member
    obtain ⟨record, recordMem, inputEq⟩ := Finset.mem_image.mp member
    obtain ⟨expandedMem, outputEq, parsed⟩ := Finset.mem_filter.mp recordMem
    obtain ⟨⟨raw, vector⟩, vectorMem, recordEq⟩ := Finset.mem_image.mp expandedMem
    subst record
    have projection := relevant raw stage parsed
    apply Finset.mem_image.mpr
    refine ⟨(rawBytes (representative (address raw).1), vectorOutputBytes counter vector),
      Finset.mem_filter.mpr ⟨?_, ?_, ?_⟩, ?_⟩
    · apply Finset.mem_image.mpr
      exact ⟨((address raw).1, vector),
        Finset.mem_filter.mpr ⟨Finset.mem_univ _, (Finset.mem_filter.mp vectorMem).2⟩, rfl⟩
    · simpa only [vectorOutputBytes, projection.2] using outputEq
    · simpa only [← projection.1] using parsed
    · exact projection.1.symm.trans inputEq
  · intro member
    obtain ⟨record, recordMem, inputEq⟩ := Finset.mem_image.mp member
    obtain ⟨projectedMem, outputEq, parsed⟩ := Finset.mem_filter.mp recordMem
    obtain ⟨⟨key, vector⟩, vectorMem, recordEq⟩ := Finset.mem_image.mp projectedMem
    subst record
    have route := representativeAddress key
    apply Finset.mem_image.mpr
    refine ⟨(rawBytes (representative key), vectorOutputBytes counter vector),
      Finset.mem_filter.mpr ⟨?_, outputEq, parsed⟩, inputEq⟩
    apply Finset.mem_image.mpr
    refine ⟨(representative key, vector), ?_, ?_⟩
    · apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ _, ?_⟩
      simpa only [route] using (Finset.mem_filter.mp vectorMem).2
    · simp only [route, vectorOutputBytes]

theorem source_extraction_eq_of_candidates
    (left right : Records RawInput RawDigest)
    (same : ∀ stage target, candidateInputs sourceNext left stage target =
      candidateInputs sourceNext right stage target)
    (fuel : ℕ) (stage : SourceStage) (target : RawDigest) :
    extract sourceNext left fuel stage target = extract sourceNext right fuel stage target := by
  induction fuel generalizing stage target with
  | zero => rfl
  | succ fuel induction =>
    have selected : selectedInput sourceNext left stage target =
        selectedInput sourceNext right stage target := by simp only [selectedInput, same]
    simp only [extract, selected]
    cases selectedInput sourceNext right stage target with
    | none => rfl
    | some input =>
      dsimp only
      cases sourceNext stage input with
      | none => rfl
      | some edges =>
        apply congrArg (ExtractionTrace.record input)
        apply List.map_congr_left
        intro edge _
        exact induction edge.1 edge.2

omit [DecidableEq Raw] [DecidableEq Key] in
theorem expanded_source_trace_eq_projected
    (rawBytes : Raw → RawInput) (address : Raw → Key × Counter)
    (representative : Key → Raw) (counter : Counter)
    (representativeAddress : ∀ key, address (representative key) = (key, counter))
    (relevant : ∀ raw stage, (sourceNext stage (rawBytes raw)).isSome →
      rawBytes raw = rawBytes (representative (address raw).1) ∧ (address raw).2 = counter)
    (database : Database Key (VectorOutput Counter)) (fuel : ℕ)
    (targets : List (SourceStage × RawDigest)) :
    extractTargets sourceNext (expandedRawRecords rawBytes address database) fuel targets =
      vectorSourceLabel (rawBytes ∘ representative) counter fuel targets database := by
  apply List.map_congr_left
  intro target _
  exact source_extraction_eq_of_candidates _ _
    (expanded_candidates_eq_projected rawBytes address representative counter representativeAddress
      relevant database) fuel target.1 target.2

end ExactRawProjection

section CanonicalRouting

open V8Smz9RawCounterCompiler (counterInput sourcePrefix Complement fullRawDomainEquiv
  fullRawPaddedCoordinate paddedCoordinate full_raw_domain_inverse_counter
  full_raw_domain_inverse_complement)

variable {Raw Prefix : Type*} {blocks : ℕ}

/-- Canonical-prefix keys use counter zero. Every complement key uses its own
raw bytes, regardless of their role, suffix, or framing validity. -/
def canonicalRepresentative (encode : Prefix × Fin blocks → Raw) (zero : Fin blocks) :
    Prefix ⊕ Complement encode → Raw
  | .inl leading => encode (leading, zero)
  | .inr other => other.val

theorem canonical_representative_address (encode : Prefix × Fin blocks → Raw)
    (injective : Function.Injective encode) (zero : Fin blocks)
    (key : Prefix ⊕ Complement encode) :
    fullRawPaddedCoordinate encode injective zero (canonicalRepresentative encode zero key) =
      (key, zero) := by
  cases key <;>
    simp [canonicalRepresentative, fullRawPaddedCoordinate, paddedCoordinate,
      full_raw_domain_inverse_counter, full_raw_domain_inverse_complement]

/-- Discharge source relevance for the *same* padded full-raw-domain routing
used by the two-query counter compiler. The byte law is literal framing;
there is no premise asserting an extraction probability or operator bound. -/
theorem canonical_routing_source_relevance
    (encode : Prefix × Fin blocks → Raw) (injective : Function.Injective encode)
    (rawBytes : Raw → RawInput) (zero : Fin blocks) (zeroValue : zero.val = 0)
    (blockBound : blocks ≤ 2 ^ 64) (role : Prefix → List HegemonCrypto.CanonicalBytes.Byte)
    (words : Prefix → List ℕ)
    (roleBound : ∀ leading, (role leading).length < 256 ^ 8)
    (wordBound : ∀ leading, (words leading).length < 256 ^ 8)
    (encodedBytes : ∀ leading counter, rawBytes (encode (leading, counter)) =
      counterInput (sourcePrefix (role leading) (words leading))
        ⟨counter.val, lt_of_lt_of_le counter.isLt blockBound⟩)
    (raw : Raw) (stage : SourceStage) (parsed : (sourceNext stage (rawBytes raw)).isSome) :
    rawBytes raw = rawBytes (canonicalRepresentative encode zero
      (fullRawPaddedCoordinate encode injective zero raw).1) ∧
      (fullRawPaddedCoordinate encode injective zero raw).2 = zero := by
  obtain ⟨index, rfl⟩ := (fullRawDomainEquiv encode injective).surjective raw
  cases index with
  | inl key =>
    rcases key with ⟨leading, counter⟩
    have same : counter = zero := by
      by_contra different
      have nonzero : counter.val ≠ 0 := by
        intro equal
        apply different
        exact Fin.ext (equal.trans zeroValue.symm)
      have absent := source_next_nonzero_counter (role leading) (words leading)
        ⟨counter.val, lt_of_lt_of_le counter.isLt blockBound⟩
        (roleBound leading) (wordBound leading) nonzero stage
      change (sourceNext stage (rawBytes (encode (leading, counter)))).isSome at parsed
      rw [encodedBytes, absent] at parsed
      exact Bool.false_ne_true parsed
    subst counter
    simp [fullRawPaddedCoordinate, paddedCoordinate, canonicalRepresentative]
  | inr other =>
    simp [fullRawPaddedCoordinate, paddedCoordinate, canonicalRepresentative]

variable [Fintype Raw] [DecidableEq Raw] [Fintype Prefix] [DecidableEq Prefix]

omit [DecidableEq Prefix] in
/-- Fully instantiated trace identity for the compiler's canonical-prefix plus
unchanged-complement address. No source-relevance premise remains. -/
theorem canonical_expanded_source_trace_eq_projected
    (encode : Prefix × Fin blocks → Raw) (injective : Function.Injective encode)
    (rawBytes : Raw ↪ RawInput) (zero : Fin blocks) (zeroValue : zero.val = 0)
    (blockBound : blocks ≤ 2 ^ 64) (role : Prefix → List HegemonCrypto.CanonicalBytes.Byte)
    (words : Prefix → List ℕ)
    (roleBound : ∀ leading, (role leading).length < 256 ^ 8)
    (wordBound : ∀ leading, (words leading).length < 256 ^ 8)
    (encodedBytes : ∀ leading counter, rawBytes (encode (leading, counter)) =
      counterInput (sourcePrefix (role leading) (words leading))
        ⟨counter.val, lt_of_lt_of_le counter.isLt blockBound⟩)
    (database : Database (Prefix ⊕ Complement encode) (VectorOutput (Fin blocks)))
    (fuel : ℕ) (targets : List (SourceStage × RawDigest)) :
    extractTargets sourceNext
        (expandedRawRecords rawBytes (fullRawPaddedCoordinate encode injective zero) database)
        fuel targets =
      vectorSourceLabel (rawBytes ∘ canonicalRepresentative encode zero) zero fuel targets database := by
  exact expanded_source_trace_eq_projected rawBytes
    (fullRawPaddedCoordinate encode injective zero) (canonicalRepresentative encode zero) zero
    (canonical_representative_address encode injective zero)
    (canonical_routing_source_relevance encode injective rawBytes zero zeroValue blockBound
      role words roleBound wordBound encodedBytes) database fuel targets

end CanonicalRouting

end
end HegemonCrypto.SmallWood.V8Smz9CoherentVectorMerkle

import HegemonCrypto.SmallWoodV8Smz9SemanticInactiveWitness
import HegemonCrypto.SmallWoodV8Smz9SemanticAssetMembership

/-!
Stablecoin consequences of arbitrary accepted HGV8RP03 assignments.
The endpoint below is explicitly the disabled branch of the existing full
stablecoin predicate. No enabled-branch or production claim is made.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
    (CsrExecutableAttempt FieldExpression evalFieldExpression fieldNormalize fieldAdd fieldSub fieldMul
    packedWitnessLaneRows relationRowCount packingFactor
    packed_witness_lane_index_is_in_exact_rectangle)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

def stableSourceIndex (slot : Nat) : Nat := 41408 + slot

def disabledSourceAttempt (slot : Nat) : CsrExecutableAttempt :=
  attempt (19168 + slot) 36 slot 1 [(stableSourceIndex slot, 307)] 0

theorem exact_disabled_source_attempts : ∀ slot, slot < 94 →
    disabledSourceAttempt slot ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 36) =
      (List.range 94).map disabledSourceAttempt := by decide
  intro slot bound
  have member : disabledSourceAttempt slot ∈
      exactCsrAttempts.filter (fun entry => entry.family == 36) := by
    rw [checked]
    exact List.mem_map.mpr ⟨slot, List.mem_range.mpr bound, rfl⟩
  exact (List.mem_filter.mp member).1

theorem disabled_gate_value {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    (disabled : publicWords.getD 83 0 = 0) : values[307]? = some 1 := by
  have constants := csr_trace_zero_one_values equations
  have publicFound := (canonical_public_coordinate canonical (index := 83) (by decide)).1
  rw [disabled] at publicFound
  have direction : values[87]? = some 0 := by
    simpa [evalFieldExpression, publicFound, fieldNormalize] using
      equations 87 (.publicWord 83) (by decide)
  have two : values[2]? = some 2 := by
    simpa [evalFieldExpression, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 2 (.constant 2) (by decide)
  have mint : values[304]? = some 0 := by
    simpa [evalFieldExpression, direction, constants.1, constants.2] using
      equations 304 (.selectEqual 87 1 1 0) (by decide)
  have burn : values[305]? = some 0 := by
    simpa [evalFieldExpression, direction, constants.1, two] using
      equations 305 (.selectEqual 87 2 1 0) (by decide)
  have enabled : values[306]? = some 0 := by
    simpa [evalFieldExpression, mint, burn, fieldAdd, fieldNormalize] using
      equations 306 (.add 304 305) (by decide)
  simpa [evalFieldExpression, constants.2, enabled, fieldSub, fieldNormalize,
    Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
    equations 307 (.sub 1 306) (by decide)

theorem accepted_disabled_source_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (disabled : publicWords.getD 83 0 = 0) {slot : Nat} (bound : slot < 94) :
    packedWord packed (stableSourceIndex slot) = 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have gate := disabled_gate_value equations accepted.1 disabled
  have constants := csr_trace_zero_one_values equations
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_disabled_source_attempts slot bound))
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
  simpa [disabledSourceAttempt, attempt, csrFieldSum, List.getD_eq_getElem?_getD,
    gate, constants.1, packedWord] using equation

def stableCopySource (word : Nat) : Nat :=
  if word < 55 then word else if word < 59 then 90 + (word - 55) else 83 + (word - 59)

def stableCopyDestination (word : Nat) : Nat :=
  if word < 55 then hashInitialIndex (106 + word / 14) (word % 14)
  else if word < 59 then hashInitialIndex 113 (7 + (word - 55))
  else hashInitialIndex 123 (word - 59)

def stableCopyAttempt (word : Nat) : CsrExecutableAttempt :=
  let global := if word < 55 then 19860 + 16 * (word / 14) + word % 14
    else if word < 59 then 19979 + (word - 55) else 20146 + (word - 59)
  let family := if word < 55 then 52 else if word < 59 then 54 else 57
  let localIndex := if word < 55 then 16 * (word / 14) + word % 14
    else if word < 59 then 7 + (word - 55) else word - 59
  attempt global family localIndex 0
    [(stableCopyDestination word, 1), (stableSourceIndex (stableCopySource word), 158)] 0

def isStableCopy (entry : CsrExecutableAttempt) : Bool :=
  (entry.family == 52 && entry.localIndex % 16 < 14 && entry.localIndex < 61) ||
  (entry.family == 54 && 7 ≤ entry.localIndex && entry.localIndex < 11) ||
  (entry.family == 57 && entry.localIndex < 7)

theorem exact_stable_copy_attempts : ∀ word, word < 66 →
    stableCopyAttempt word ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter isStableCopy =
      (List.range 66).map stableCopyAttempt := by decide
  intro word bound
  have member : stableCopyAttempt word ∈ exactCsrAttempts.filter isStableCopy := by
    rw [checked]
    exact List.mem_map.mpr ⟨word, List.mem_range.mpr bound, rfl⟩
  exact (List.mem_filter.mp member).1

theorem accepted_disabled_copy_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (disabled : publicWords.getD 83 0 = 0) {word : Nat} (bound : word < 66) :
    packedWord packed (stableCopyDestination word) = 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have sourceBound : stableCopySource word < 94 := by
    unfold stableCopySource
    split <;> (try split) <;> omega
  have sourceZero := accepted_disabled_source_zero accepted disabled sourceBound
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_stable_copy_attempts word bound))
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
  simp only [stableCopyAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil] at equation
  change _ * (packedWord packed (stableCopyDestination word) : F) +
    (_ * (packedWord packed (stableSourceIndex (stableCopySource word)) : F) + 0) = _ at equation
  rw [sourceZero] at equation
  simpa [List.getD_eq_getElem?_getD, constants.1, constants.2] using equation

/-- The 66 config/counter/issuer input copies hold in every direction. -/
theorem accepted_stable_copy_equality {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {word : Nat} (bound : word < 66) :
    packedWord packed (stableCopyDestination word) =
      packedWord packed (stableSourceIndex (stableCopySource word)) := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have negativeFound : values[158]? = some (fieldSub 0 1) := by
    simpa [evalFieldExpression, constants.1, constants.2] using
      equations 158 (.sub 0 1) (by decide)
  have negative : (values.getD 158 0 : F) = -1 := by
    simp only [List.getD_eq_getElem?_getD, negativeFound, Option.getD_some]
    rw [field_sub_cast 0 1 (by decide)]
    simp
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_stable_copy_attempts word bound))
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _)
  simp only [stableCopyAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil] at equation
  rw [oneValue, negative, zeroValue, one_mul, neg_one_mul, add_zero] at equation
  exact add_neg_eq_zero.mp equation

def stableSiblingAttempt (level limb : Nat) : CsrExecutableAttempt :=
  attempt (20011 + 32 * level + limb) 55 (7 + 32 * level + limb) 0
    [(hashInitialIndex (115 + 2 * level) (7 + limb), 1),
     (stableSourceIndex (55 + 7 * level + limb), 348 + 3 * level),
     (hashFinalIndex (113 + 2 * level) limb, 349 + 3 * level)] 0

theorem exact_stable_sibling_attempts : ∀ level, level < 4 → ∀ limb, limb < 7 →
    stableSiblingAttempt level limb ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 55 &&
      7 ≤ entry.localIndex % 32 && entry.localIndex % 32 < 14) =
      (List.range 4).flatMap (fun level => (List.range 7).map (stableSiblingAttempt level)) := by decide
  intro level levelBound limb limbBound
  have member : stableSiblingAttempt level limb ∈ exactCsrAttempts.filter
      (fun entry => entry.family == 55 && 7 ≤ entry.localIndex % 32 &&
        entry.localIndex % 32 < 14) := by
    rw [checked]
    exact List.mem_flatMap.mpr ⟨level, List.mem_range.mpr levelBound,
      List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩⟩
  exact (List.mem_filter.mp member).1

theorem zero_asset_bit_coefficient {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    (assetZero : publicWords.getD 84 0 = 0) {level : Nat} (levelBound : level < 4) :
    values[349 + 3 * level]? = some 0 := by
  have constants := csr_trace_zero_one_values equations
  have publicFound := (canonical_public_coordinate canonical (index := 84) (by decide)).1
  rw [assetZero] at publicFound
  have asset : values[88]? = some 0 := by
    simpa [evalFieldExpression, publicFound, fieldNormalize] using
      equations 88 (.publicWord 84) (by decide)
  have nodes : exactCsrExpressions[316 + level]? = some (.bit 88 level) ∧
      exactCsrExpressions[349 + 3 * level]? = some (.sub 0 (316 + level)) := by
    interval_cases level <;> decide
  have bitValue : values[316 + level]? = some 0 := by
    simpa [evalFieldExpression, asset] using equations _ _ nodes.1
  simpa [evalFieldExpression, constants.1, bitValue, fieldSub, fieldNormalize] using
    equations _ _ nodes.2

theorem accepted_disabled_sibling_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (disabled : publicWords.getD 83 0 = 0) (assetZero : publicWords.getD 84 0 = 0)
    {level limb : Nat} (levelBound : level < 4) (limbBound : limb < 7) :
    packedWord packed (hashInitialIndex (115 + 2 * level) (7 + limb)) = 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have sourceZero := accepted_disabled_source_zero accepted disabled
    (show 55 + 7 * level + limb < 94 by omega)
  have bitZero := zero_asset_bit_coefficient equations accepted.1 assetZero levelBound
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_stable_sibling_attempts level levelBound limb limbBound))
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
  simp only [stableSiblingAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil] at equation
  change _ * (packedWord packed (hashInitialIndex (115 + 2 * level) (7 + limb)) : F) +
    (_ * (packedWord packed (stableSourceIndex (55 + 7 * level + limb)) : F) + _) = _ at equation
  rw [sourceZero] at equation
  simpa [List.getD_eq_getElem?_getD, constants.1, constants.2, bitZero] using equation

theorem encoded_stable_public_word (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) (word : Nat) :
    (encodePublicStatement statement).getD (83 + word) 0 =
      (encodeStablecoinPublic statement.stablecoin).getD word 0 := by
  obtain ⟨inputLength, outputLength, nullifierLength, commitmentLength,
    ciphertextLength, rootLength, assetLength⟩ := admitted_public_lengths statement canonical
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, compatibility, _⟩ := canonical
  obtain ⟨_, _, _, legacyLength, legacyWords, _⟩ := compatibility
  have legacyFlat := flatten_length_uniform 6 statement.compatibility.reservedLegacyCommitments
    (by intro words member; exact (legacyWords words member).1.1)
  have legacyFlatLength : statement.compatibility.reservedLegacyCommitments.flatten.length = 18 := by
    simpa only [legacyLength] using legacyFlat
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten ++
    statement.commitments.flatten ++ statement.ciphertextCommitments.flatten ++
    [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
    statement.merkleRoot ++ statement.balanceAssets ++ encodeCompatibility statement.compatibility ++
    [statement.version, statement.cryptoSuite]
  have prefixLength : publicPrefix.length = 83 := by
    simp [publicPrefix, encodeCompatibility, inputLength, outputLength, nullifierLength,
      commitmentLength, ciphertextLength, rootLength, assetLength, legacyFlatLength]
  have encoded : encodePublicStatement statement = publicPrefix ++ encodeStablecoinPublic statement.stablecoin := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  simp

theorem admitted_disabled_projected_words_zero {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (disabled : statement.stablecoin.direction = .disabled) :
    ZeroWords (projectStablecoinWords statement packed) := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, compatibility, _⟩ := domain.2.1
  have disabledPublic := compatibility.2.2.2.2.2
  simp only [disabled] at disabledPublic
  have assetZero : statement.stablecoin.assetId = 0 := disabledPublic.2.2.2.2.2.1
  have rawDisabled : publicWords.getD 83 0 = 0 := by
    rw [← domain.1]
    simpa [encodeStablecoinPublic, disabled, StableDirection.word] using
      encoded_stable_public_word statement domain.2.1 0
  have rawAsset : publicWords.getD 84 0 = 0 := by
    rw [← domain.1]
    simpa [encodeStablecoinPublic, assetZero] using
      encoded_stable_public_word statement domain.2.1 1
  intro value member
  simp only [projectStablecoinWords, List.mem_append, List.mem_map, List.mem_flatMap] at member
  rcases member with ((⟨word, wordMember, rfl⟩ | ⟨counter, counterMember, rfl⟩) |
    ⟨level, levelMember, _, limbMember, rfl⟩) | ⟨limb, limbMember, rfl⟩
  · have bound := List.mem_range.mp wordMember
    simpa only [stableCopyDestination, if_pos bound] using
      accepted_disabled_copy_zero domain.2.2 rawDisabled (show word < 66 by omega)
  · have bound := List.mem_range.mp counterMember
    have result := accepted_disabled_copy_zero domain.2.2 rawDisabled
      (show 55 + counter < 66 by omega)
    simpa [stableCopyDestination, show ¬55 + counter < 55 by omega,
      show 55 + counter < 59 by omega] using result
  · have levelBound := List.mem_range.mp levelMember
    have limbBound := List.mem_range.mp limbMember
    simpa [assetZero] using accepted_disabled_sibling_zero domain.2.2 rawDisabled rawAsset
      levelBound limbBound
  · have bound := List.mem_range.mp limbMember
    have result := accepted_disabled_copy_zero domain.2.2 rawDisabled
      (show 59 + limb < 66 by omega)
    simpa [stableCopyDestination, show ¬59 + limb < 55 by omega,
      show ¬59 + limb < 59 by omega] using result

/-- Full unchanged stablecoin transition predicate, only on its disabled arm. -/
theorem admitted_disabled_stable_transition {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (disabled : statement.stablecoin.direction = .disabled) :
    exactV8StableTransition (derivedRelationContext statement) statement.stablecoin
      (projectTypedWitness statement packed).stablecoin := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, compatibility, _, _, height, _⟩ := domain.2.1
  have fields := compatibility.2.2.2.2.2
  simp only [disabled] at fields
  obtain ⟨_, _, _, _, _, asset, policy, magnitude, intent, roots,
    epoch, minted, debt, sequence, issuer⟩ := fields
  have shape := project_stable_words_shape domain.2.2.2.1 statement
  have zero := admitted_disabled_projected_words_zero domain disabled
  unfold exactV8StableTransition
  rw [disabled]
  change exactV8StablecoinDisabledValid (derivedRelationContext statement)
    statement.stablecoin ⟨projectStablecoinWords statement packed⟩
  refine ⟨rfl, height, asset, policy, magnitude, ?_, rfl, roots.symm,
    epoch, minted, debt, sequence, ?_, ?_, ?_⟩
  · exact List.all_eq_true.mpr (by intro word member; exact decide_eq_true (intent word member))
  · exact List.all_eq_true.mpr (by intro word member; exact decide_eq_true (issuer word member))
  · exact ⟨shape.1, List.all_eq_true.mpr (by intro word member; exact decide_eq_true (shape.2 word member))⟩
  · exact List.all_eq_true.mpr (by intro word member; exact decide_eq_true (zero word member))

def StableRadixFourNodes (slot : Nat) : Prop :=
  exactNonlinearExpressions[787 + slot]? = some (.witnessRow (663 + slot)) ∧
    exactNonlinearExpressions[8133 + 6 * slot]? = some (.sub (787 + slot) 1) ∧
    exactNonlinearExpressions[8134 + 6 * slot]? = some (.sub (787 + slot) 2) ∧
    exactNonlinearExpressions[8135 + 6 * slot]? = some (.sub (787 + slot) 829) ∧
    exactNonlinearExpressions[8136 + 6 * slot]? =
      some (.mul (787 + slot) (8133 + 6 * slot)) ∧
    exactNonlinearExpressions[8137 + 6 * slot]? =
      some (.mul (8134 + 6 * slot) (8136 + 6 * slot)) ∧
    exactNonlinearExpressions[8138 + 6 * slot]? =
      some (.mul (8135 + 6 * slot) (8137 + 6 * slot)) ∧
    8138 + 6 * slot ∈ exactNonlinearRoots

instance (slot : Nat) : Decidable (StableRadixFourNodes slot) := by
  unfold StableRadixFourNodes
  infer_instance

def stableRangeTailModel : List FieldExpression :=
  (List.range 23).flatMap fun slot =>
    [.sub (787 + slot) 1, .sub (787 + slot) 2, .sub (787 + slot) 829,
     .mul (787 + slot) (8133 + 6 * slot),
     .mul (8134 + 6 * slot) (8136 + 6 * slot),
     .mul (8135 + 6 * slot) (8137 + 6 * slot)]

private theorem stable_range_tail_certificate :
    exactNonlinearExpressions.drop 8133 = stableRangeTailModel := by decide

private theorem stable_range_source_certificate :
    (exactNonlinearExpressions.drop 787).take 23 =
      (List.range 23).map (fun slot => FieldExpression.witnessRow (663 + slot)) := by decide

private theorem stable_range_root_certificate : exactNonlinearRoots.drop 807 =
    (List.range 23).map (fun slot => 8138 + 6 * slot) := by decide

theorem exact_stable_radix_four_nodes : ∀ slot, slot < 23 → StableRadixFourNodes slot := by
  intro slot bound
  have source : exactNonlinearExpressions[787 + slot]? = some (.witnessRow (663 + slot)) := by
    have found := congrArg (fun xs : List FieldExpression => xs[slot]?) stable_range_source_certificate
    simpa [List.getElem?_take, bound, List.getElem?_drop] using found
  have tailAt (offset : Nat) : exactNonlinearExpressions[8133 + offset + 6 * slot]? =
      stableRangeTailModel[offset + 6 * slot]? := by
    rw [Nat.add_assoc, ← List.getElem?_drop, stable_range_tail_certificate]
  have model : stableRangeTailModel[6 * slot]? = some (.sub (787 + slot) 1) ∧
      stableRangeTailModel[1 + 6 * slot]? = some (.sub (787 + slot) 2) ∧
      stableRangeTailModel[2 + 6 * slot]? = some (.sub (787 + slot) 829) ∧
      stableRangeTailModel[3 + 6 * slot]? = some (.mul (787 + slot) (8133 + 6 * slot)) ∧
      stableRangeTailModel[4 + 6 * slot]? = some (.mul (8134 + 6 * slot) (8136 + 6 * slot)) ∧
      stableRangeTailModel[5 + 6 * slot]? = some (.mul (8135 + 6 * slot) (8137 + 6 * slot)) := by
    interval_cases slot <;> decide
  have root : 8138 + 6 * slot ∈ exactNonlinearRoots := by
    apply List.mem_of_mem_drop (i := 807)
    rw [stable_range_root_certificate]
    exact List.mem_map.mpr ⟨slot, List.mem_range.mpr bound, rfl⟩
  refine ⟨source, ?_, ?_, ?_, ?_, ?_, ?_, root⟩
  · simpa using (tailAt 0).trans (by simpa using model.1)
  · simpa using (tailAt 1).trans model.2.1
  · simpa using (tailAt 2).trans model.2.2.1
  · simpa using (tailAt 3).trans model.2.2.2.1
  · simpa using (tailAt 4).trans model.2.2.2.2.1
  · simpa using (tailAt 5).trans model.2.2.2.2.2

/-- All 1,472 stable range digits, without an activity or typed-range premise. -/
theorem accepted_stable_radix_four_rows
    {publicWords packedWitness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packedWitness)
    {slot lane : Nat} (slotBound : slot < 23) (laneBound : lane < packingFactor) :
    packedWitness.getD ((663 + slot) * packingFactor + lane) 0 < 4 := by
  have rowBound : 663 + slot < relationRowCount := by
    simp only [relationRowCount]
    omega
  have coordinateBound : (663 + slot) * packingFactor + lane < packedWitness.length := by
    rw [accepted.2.1.1]
    exact packed_witness_lane_index_is_in_exact_rectangle rowBound laneBound
  have packedFound : packedWitness[(663 + slot) * packingFactor + lane]? =
      some (packedWitness.getD ((663 + slot) * packingFactor + lane) 0) := by
    simp [List.getD, coordinateBound]
  have wordBound := accepted.2.1.2 _ (List.mem_of_getElem? packedFound)
  have rowFound : (packedWitnessLaneRows packedWitness lane)[663 + slot]? =
      some (packedWitness.getD ((663 + slot) * packingFactor + lane) 0) := by
    simp [packedWitnessLaneRows, rowBound]
  obtain ⟨src, sub1, sub2, sub3, mul1, mul2, mul3, rootMember⟩ :=
    exact_stable_radix_four_nodes slot slotBound
  obtain ⟨values, evaluated, rootZero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 lane laneBound) rootMember
  have equation : ∀ {index : Nat} {expression : FieldExpression},
      exactNonlinearExpressions[index]? = some expression →
        values[index]? = evalFieldExpression publicWords
          (packedWitnessLaneRows packedWitness lane) values expression := by
    intro index expression found
    exact evaluated_program_satisfies_each_node
      hgv8rp03_nonlinear_expression_program_is_canonical evaluated found
  have oneValue : values[1]? = some 1 := by
    simpa [evalFieldExpression, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equation exact_nonlinear_small_constant_nodes.1
  have twoValue : values[2]? = some 2 := by
    simpa [evalFieldExpression, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equation exact_nonlinear_small_constant_nodes.2.1
  have threeValue : values[829]? = some 3 := by
    simpa [evalFieldExpression, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equation exact_nonlinear_small_constant_nodes.2.2
  let word := packedWitness.getD ((663 + slot) * packingFactor + lane) 0
  have sourceValue : values[787 + slot]? = some word := by
    simpa only [evalFieldExpression, rowFound, Option.map_some,
      fieldNormalize, Nat.mod_eq_of_lt wordBound] using equation src
  have subOneValue : values[8133 + 6 * slot]? = some (fieldSub word 1) := by
    simpa [evalFieldExpression, sourceValue, oneValue] using equation sub1
  have subTwoValue : values[8134 + 6 * slot]? = some (fieldSub word 2) := by
    simpa [evalFieldExpression, sourceValue, twoValue] using equation sub2
  have subThreeValue : values[8135 + 6 * slot]? = some (fieldSub word 3) := by
    simpa [evalFieldExpression, sourceValue, threeValue] using equation sub3
  have mulOneValue : values[8136 + 6 * slot]? = some (fieldMul word (fieldSub word 1)) := by
    simpa [evalFieldExpression, sourceValue, subOneValue] using equation mul1
  have mulTwoValue : values[8137 + 6 * slot]? =
      some (fieldMul (fieldSub word 2) (fieldMul word (fieldSub word 1))) := by
    simpa [evalFieldExpression, subTwoValue, mulOneValue] using equation mul2
  have mulThreeValue : values[8138 + 6 * slot]? = some (fieldMul (fieldSub word 3)
      (fieldMul (fieldSub word 2) (fieldMul word (fieldSub word 1)))) := by
    simpa [evalFieldExpression, subThreeValue, mulTwoValue] using equation mul3
  exact canonical_radix_four_of_product_zero wordBound
    (Option.some.inj (mulThreeValue.symm.trans rootZero))

theorem accepted_stable_range_digit_bound {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {digit : Nat} (bound : digit < 1472) : packedWord packed (42432 + digit) < 4 := by
  have result := accepted_stable_radix_four_rows accepted
    (show digit / 64 < 23 by omega)
    (show digit % 64 < packingFactor by simp only [packingFactor]; omega)
  have address : (663 + digit / 64) * packingFactor + digit % 64 = 42432 + digit := by
    simp only [packingFactor]
    omega
  simpa only [address, packedWord] using result

structure StableEvenRange where
  localIndex : Nat
  isPublic : Bool
  sourceIndex : Nat
  targetRoot : Nat
  start : Nat
  digits : Nat
deriving DecidableEq, Repr

def stableEvenRanges : List StableEvenRange :=
  [⟨0, false, 41408, 0, 0, 16⟩, ⟨1, false, 41409, 0, 16, 16⟩,
   ⟨2, false, 41421, 0, 32, 16⟩, ⟨3, false, 41425, 0, 48, 16⟩,
   ⟨4, false, 41426, 0, 64, 16⟩, ⟨5, false, 41453, 0, 80, 16⟩,
   ⟨6, false, 42184, 0, 96, 16⟩,
   ⟨27, false, 41422, 0, 714, 28⟩, ⟨28, false, 41427, 0, 742, 28⟩,
   ⟨29, true, 86, 410, 770, 28⟩, ⟨30, false, 41499, 0, 798, 28⟩,
   ⟨31, false, 41500, 0, 826, 28⟩, ⟨32, true, 110, 411, 854, 28⟩,
   ⟨33, true, 111, 412, 882, 28⟩, ⟨34, false, 42185, 0, 910, 28⟩,
   ⟨35, false, 42186, 0, 938, 28⟩,
   ⟨36, false, 42188, 0, 966, 6⟩, ⟨37, false, 42176, 0, 972, 14⟩] ++
  (List.range 28).map (fun lane =>
    ⟨38 + lane, false, 42194 + lane, 0, 986 + 16 * lane, 16⟩)

def stableEvenNegativeTerms (spec : StableEvenRange) : List (Nat × Nat) :=
  (List.range spec.digits).map (fun digit => (42432 + spec.start + digit, 158 + digit))

def stableEvenAttempt (spec : StableEvenRange) : CsrExecutableAttempt :=
  attempt (20192 + spec.localIndex) 60 spec.localIndex 0
    ((if spec.isPublic then [] else [(spec.sourceIndex, 1)]) ++ stableEvenNegativeTerms spec)
    spec.targetRoot

def StableEvenRange.Valid (spec : StableEvenRange) : Prop :=
  spec.digits < 30 ∧ spec.start + spec.digits ≤ 1472 ∧
    spec.sourceIndex < (if spec.isPublic then 120 else 43904) ∧
    4 ^ spec.digits < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus ∧
    if spec.isPublic then
      exactCsrExpressions[spec.targetRoot]? = some (.sub 0 (4 + spec.sourceIndex)) ∧
      exactCsrExpressions[4 + spec.sourceIndex]? = some (.publicWord spec.sourceIndex)
    else spec.targetRoot = 0

instance (spec : StableEvenRange) : Decidable spec.Valid := by
  unfold StableEvenRange.Valid
  infer_instance

theorem exact_stable_even_ranges :
    (∀ spec, spec ∈ stableEvenRanges → spec.Valid) ∧
      (∀ spec, spec ∈ stableEvenRanges → stableEvenAttempt spec ∈ exactCsrAttempts) := by
  have checked : stableEvenRanges.all (fun spec => decide spec.Valid) = true := by decide
  have attempts : exactCsrAttempts.filter (fun entry => entry.family == 60 &&
      (entry.localIndex < 7 || 27 ≤ entry.localIndex)) =
      stableEvenRanges.map stableEvenAttempt := by decide
  constructor
  · simpa only [List.all_eq_true, decide_eq_true_eq] using checked
  · intro spec member
    have filtered : stableEvenAttempt spec ∈ exactCsrAttempts.filter
        (fun entry => entry.family == 60 && (entry.localIndex < 7 || 27 ≤ entry.localIndex)) := by
      rw [attempts]
      exact List.mem_map.mpr ⟨spec, member, rfl⟩
    exact (List.mem_filter.mp filtered).1

def stableEvenSource (publicWords packed : List Nat) (spec : StableEvenRange) : Nat :=
  if spec.isPublic then publicWords.getD spec.sourceIndex 0
  else packedWord packed spec.sourceIndex

def stableEvenNatural (packed : List Nat) (spec : StableEvenRange) : Nat :=
  radixFourSum (fun digit => packedWord packed (42432 + spec.start + digit)) spec.digits

theorem stable_even_negative_field_sum {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values) (packed : List Nat)
    (spec : StableEvenRange) (valid : spec.Valid) :
    csrFieldSum values packed (stableEvenNegativeTerms spec) = -(stableEvenNatural packed spec : F) := by
  have coefficients := (dense_negative_coefficient_values equations).1
  have digitMap :
      (List.range spec.digits).map (fun digit =>
        (values.getD (158 + digit) 0 : F) *
          (packedWord packed (42432 + spec.start + digit) : F)) =
      ((List.range spec.digits).map (fun digit =>
        4 ^ digit * packedWord packed (42432 + spec.start + digit))).map
          (fun (term : Nat) => -(term : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro digit member
    rw [coefficients digit (by have := List.mem_range.mp member; have := valid.1; omega)]
    simp only [Function.comp_apply, Nat.cast_mul, neg_mul]
  unfold csrFieldSum stableEvenNegativeTerms
  rw [List.map_map]
  change ((List.range spec.digits).map (fun digit =>
    (values.getD (158 + digit) 0 : F) *
      (packedWord packed (42432 + spec.start + digit) : F))).sum = _
  rw [digitMap, sum_neg_cast]
  rfl

/-- Exact Nat reconstruction and bit bound for all 46 even-width stable ranges.
This includes all nine 56-bit amount/cap/debt/slack values. -/
theorem accepted_stable_even_range {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {spec : StableEvenRange} (member : spec ∈ stableEvenRanges) :
    stableEvenSource publicWords packed spec = stableEvenNatural packed spec ∧
      stableEvenSource publicWords packed spec < 4 ^ spec.digits := by
  have valid := exact_stable_even_ranges.1 spec member
  have naturalBound : stableEvenNatural packed spec < 4 ^ spec.digits := by
    apply radix_four_sum_bound
    intro digit bound
    have raw := accepted_stable_range_digit_bound accepted
      (show spec.start + digit < 1472 by have := valid.2.1; omega)
    simpa only [Nat.add_assoc] using raw
  have sourceBound : stableEvenSource publicWords packed spec <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    cases publicCase : spec.isPublic with
    | false => simpa [stableEvenSource, publicCase,
        Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
        packed_word_canonical accepted.2.1 spec.sourceIndex
    | true =>
        have indexBound : spec.sourceIndex < 120 := by simpa [publicCase] using valid.2.2.1
        simpa [stableEvenSource, publicCase] using
          (canonical_public_coordinate accepted.1 indexBound).2
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have negative := stable_even_negative_field_sum equations packed spec valid
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_stable_even_ranges.2 spec member))
  have fieldEqual : (stableEvenSource publicWords packed spec : F) =
      (stableEvenNatural packed spec : F) := by
    cases publicCase : spec.isPublic with
    | false =>
      have targetZero : spec.targetRoot = 0 := by simpa only [publicCase, Bool.false_eq_true, if_false] using valid.2.2.2.2
      simp only [stableEvenAttempt, attempt, publicCase, Bool.false_eq_true, if_false,
        List.cons_append, List.nil_append] at equation
      rw [csr_field_sum_cons, oneValue, one_mul, negative, targetZero, zeroValue] at equation
      simpa only [stableEvenSource, publicCase, Bool.false_eq_true, if_false, packedWord,
        sub_eq_add_neg] using add_neg_eq_zero.mp equation
    | true =>
      have nodes : exactCsrExpressions[spec.targetRoot]? = some (.sub 0 (4 + spec.sourceIndex)) ∧
          exactCsrExpressions[4 + spec.sourceIndex]? = some (.publicWord spec.sourceIndex) := by
        simpa only [publicCase, if_true] using valid.2.2.2.2
      have publicBound : spec.sourceIndex < 120 := by simpa only [publicCase, if_true] using valid.2.2.1
      have coordinate := canonical_public_coordinate accepted.1 publicBound
      have publicValue : values[4 + spec.sourceIndex]? = some (publicWords.getD spec.sourceIndex 0) := by
        simpa only [evalFieldExpression, coordinate.1, Option.map_some, fieldNormalize,
          Nat.mod_eq_of_lt coordinate.2] using equations _ _ nodes.2
      have targetValue : values[spec.targetRoot]? = some (fieldSub 0 (publicWords.getD spec.sourceIndex 0)) := by
        simpa [evalFieldExpression, constants.1, publicValue] using equations _ _ nodes.1
      have targetField : (values.getD spec.targetRoot 0 : F) =
          -(publicWords.getD spec.sourceIndex 0 : F) := by
        have targetGetD : values.getD spec.targetRoot 0 =
            fieldSub 0 (publicWords.getD spec.sourceIndex 0) := by
          simp only [List.getD_eq_getElem?_getD, targetValue, Option.getD_some]
        rw [targetGetD, field_sub_cast 0 _ (by have := coordinate.2; omega)]
        simp
      simp only [stableEvenAttempt, attempt, publicCase, if_true, List.nil_append] at equation
      rw [negative, targetField] at equation
      simpa only [stableEvenSource, publicCase, if_true] using (neg_inj.mp equation).symm
  have naturalCanonical := naturalBound.trans valid.2.2.2.1
  have exactNat := canonical_nat_cast_injective sourceBound naturalCanonical fieldEqual
  exact ⟨exactNat, by rw [exactNat]; exact naturalBound⟩

/-- All nine live 56-bit range sources, named by their actual packed/public coordinates. -/
theorem accepted_stable_nine_value_bounds {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedWord packed 41422 < 2 ^ 56 ∧ packedWord packed 41427 < 2 ^ 56 ∧
      publicWords.getD 86 0 < 2 ^ 56 ∧ packedWord packed 41499 < 2 ^ 56 ∧
      packedWord packed 41500 < 2 ^ 56 ∧ publicWords.getD 110 0 < 2 ^ 56 ∧
      publicWords.getD 111 0 < 2 ^ 56 ∧ packedWord packed 42185 < 2 ^ 56 ∧
      packedWord packed 42186 < 2 ^ 56 := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact (accepted_stable_even_range accepted
      (spec := ⟨27, false, 41422, 0, 714, 28⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted
      (spec := ⟨28, false, 41427, 0, 742, 28⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted
      (spec := ⟨29, true, 86, 410, 770, 28⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted
      (spec := ⟨30, false, 41499, 0, 798, 28⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted
      (spec := ⟨31, false, 41500, 0, 826, 28⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted
      (spec := ⟨32, true, 110, 411, 854, 28⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted
      (spec := ⟨33, true, 111, 412, 882, 28⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted
      (spec := ⟨34, false, 42185, 0, 910, 28⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted
      (spec := ⟨35, false, 42186, 0, 938, 28⟩) (by decide)).2

#print axioms accepted_disabled_source_zero
#print axioms admitted_disabled_projected_words_zero
#print axioms admitted_disabled_stable_transition
#print axioms accepted_stable_copy_equality
#print axioms accepted_stable_range_digit_bound
#print axioms accepted_stable_even_range
#print axioms accepted_stable_nine_value_bounds

end HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin

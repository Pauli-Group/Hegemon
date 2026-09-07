import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness

/-!
Source-derived private-authorization structure and linkage. The target is the
existing V8AuthorizationValid, not authorization-mode one-hotness alone.
Cryptographic primitive equations must be derived from the exact source hash
schedule, and source/target mismatches must be corrected explicitly rather than
covered by an assumed authorization-validity premise.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (FieldExpression CanonicalPackedWitness CsrExecutableAttempt packedWitnessLaneRows)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex authorizationModeRow authorizationPolicyTagRow)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
  (actual_node_field_equation admitted_public_lengths)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
  (fieldAt expressionField canonical_getD)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

def authorizationRawWord (packed : List Nat) (row : Nat) : Nat := packedWord packed (row * 64)

theorem authorization_lane_zero_word (packed : List Nat) {row : Nat} (bound : row < 686) :
    (packedWitnessLaneRows packed 0).getD row 0 = authorizationRawWord packed row := by
  simp [packedWitnessLaneRows,
    Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount,
    Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor,
    List.getD_eq_getElem?_getD, bound, authorizationRawWord, packedWord]

theorem accepted_single_mode_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey) : authorizationWord packed 0 = 1 := by
  rcases accepted_project_authorization_mode accepted with single | approval | finalMode
  · exact single.1
  · cases mode.symm.trans approval.2
  · cases mode.symm.trans finalMode.2

def singleKeyZeroRows : List Nat :=
  (List.range 23).map (fun index => 138 + index) ++
    (List.range 30).map (fun index => 196 + index)

def singleKeyZeroRoot (row : Nat) : Nat :=
  if row < 145 then 1244 + 2 * (row - 138)
  else if row < 152 then 1245 + 2 * (row - 145)
  else if row < 155 then 1258 + (row - 152)
  else if row < 161 then 1264 + (row - 155)
  else 1308 + (row - 196)

def SingleKeyZeroSource (row : Nat) : Prop :=
  row < 686 ∧
    exactNonlinearExpressions[124 + row]? = some (.witnessRow row) ∧
    exactNonlinearExpressions[singleKeyZeroRoot row]? = some (.mul 216 (124 + row)) ∧
    singleKeyZeroRoot row ∈ exactNonlinearRoots

instance (row : Nat) : Decidable (SingleKeyZeroSource row) := by
  unfold SingleKeyZeroSource
  infer_instance

theorem exact_single_key_zero_sources : ∀ row, row ∈ singleKeyZeroRows → SingleKeyZeroSource row := by
  have checked : singleKeyZeroRows.all (fun row => decide (SingleKeyZeroSource row)) = true := by decide
  simpa only [List.all_eq_true, decide_eq_true_eq] using checked

theorem single_key_zero_source_of_range {row : Nat}
    (bound : (138 ≤ row ∧ row < 161) ∨ (196 ≤ row ∧ row < 226)) : SingleKeyZeroSource row := by
  apply exact_single_key_zero_sources
  apply List.mem_append.mpr
  rcases bound with opening | tags
  · left
    exact List.mem_map.mpr ⟨row - 138, List.mem_range.mpr (by omega), by omega⟩
  · right
    exact List.mem_map.mpr ⟨row - 196, List.mem_range.mpr (by omega), by omega⟩

theorem accepted_single_raw_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey) {row : Nat}
    (bound : (138 ≤ row ∧ row < 161) ∨ (196 ≤ row ∧ row < 226)) :
    authorizationRawWord packed row = 0 := by
  have valid := single_key_zero_source_of_range bound
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := singleKeyZeroRoot row) (by decide) valid.2.2.2
  have modeWord := accepted_single_mode_word accepted mode
  have rawMode : authorizationRawWord packed 92 = 1 := by
    simpa only [authorizationRawWord, authorizationWord, rawIndex, authorizationModeRow,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Nat.zero_add, Nat.add_zero] using modeWord
  have modeEquation := equations 216 (.witnessRow 92) (by decide)
  have rowEquation := equations (124 + row) (.witnessRow row) valid.2.1
  have rootEquation := equations (singleKeyZeroRoot row) (.mul 216 (124 + row)) valid.2.2.1
  simp only [expressionField, authorization_lane_zero_word packed (by decide : 92 < 686),
    rawMode, Nat.cast_one] at modeEquation
  simp only [expressionField, authorization_lane_zero_word packed valid.1] at rowEquation
  simp only [expressionField, modeEquation, rowEquation, rootZero, one_mul] at rootEquation
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide) rootEquation.symm

def currentOpeningExpectedAttempt (word : Nat) : CsrExecutableAttempt :=
  let block := word / 8
  let call := 98 + block
  attempt (18971 + 16 * block + word % 8) 29 (16 * block + word % 8) 0
    ([(hashInitialIndex call (word % 8), 1)] ++
      (if block = 0 then [] else [(hashFinalIndex (call - 1) (word % 8), 158)]) ++
      [(rawIndex (138 + word), 158)]) 0

theorem exact_current_opening_attempts : ∀ word, word < 23 →
    currentOpeningExpectedAttempt word ∈ exactCsrAttempts := by
  have checked : (exactCsrAttempts.filter (fun entry => entry.family == 29 &&
      (entry.localIndex < 8 || (16 ≤ entry.localIndex && entry.localIndex < 24) ||
        (32 ≤ entry.localIndex && entry.localIndex < 39)))) =
      (List.range 23).map currentOpeningExpectedAttempt := by decide
  intro word bound
  have member : currentOpeningExpectedAttempt word ∈ exactCsrAttempts.filter (fun entry =>
      entry.family == 29 && (entry.localIndex < 8 || (16 ≤ entry.localIndex && entry.localIndex < 24) ||
        (32 ≤ entry.localIndex && entry.localIndex < 39))) := by
    rw [checked]
    exact List.mem_map.mpr ⟨word, List.mem_range.mpr bound, rfl⟩
  exact (List.mem_filter.mp member).1

theorem accepted_current_opening_source_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {word : Nat} (bound : word < 23) :
    spongeSourceWord packed 98 word = authorizationRawWord packed (138 + word) := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp only [List.getD_eq_getElem?_getD, constants.1, Option.getD_some, Nat.cast_zero]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp only [List.getD_eq_getElem?_getD, constants.2, Option.getD_some, Nat.cast_one]
  have negativeOne : (values.getD 158 0 : F) = -1 := by
    simpa using (dense_negative_coefficient_values equations).1 0 (by decide)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_current_opening_attempts word bound))
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _)
    (packed_word_canonical accepted.2.1 _)
  by_cases firstBlock : word / 8 = 0
  · simp only [currentOpeningExpectedAttempt, attempt, firstBlock, if_true,
      List.append_nil, List.cons_append, List.nil_append, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, negativeOne, zeroValue, one_mul, neg_one_mul, add_zero] at equation
    have equality := sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using equation)
    simpa only [spongeSourceWord, firstBlock, if_true, Nat.add_zero,
      authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Nat.zero_add, packedWord] using equality
  · simp only [currentOpeningExpectedAttempt, attempt, firstBlock, if_false,
      List.cons_append, List.nil_append, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, negativeOne, zeroValue, one_mul, neg_one_mul, add_zero] at equation
    simp only [spongeSourceWord, firstBlock, if_false]
    rw [field_sub_cast _ _ (by
      have previous := packed_word_canonical accepted.2.1 (hashFinalIndex (98 + word / 8 - 1) (word % 8))
      change _ < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus at previous
      omega)]
    have equality : (packed.getD (hashInitialIndex (98 + word / 8) (word % 8)) 0 : F) -
        (packed.getD (hashFinalIndex (98 + word / 8 - 1) (word % 8)) 0 : F) =
        (packed.getD (rawIndex (138 + word)) 0 : F) := by
      exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg, add_assoc] using equation)
    simpa only [packedWord, authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using equality

theorem accepted_single_current_source_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey) {word : Nat} (bound : word < 23) :
    spongeSourceWord packed 98 word = 0 := by
  rw [accepted_current_opening_source_word accepted bound]
  exact accepted_single_raw_zero accepted mode (Or.inl ⟨by omega, by omega⟩)

theorem exact_zero_words_range_map (count : Nat) (word : Nat → Nat)
    (zero : ∀ index, index < count → word index = 0) :
    ExactWords count ((List.range count).map word) ∧ ZeroWords ((List.range count).map word) := by
  constructor
  · apply exact_words_range_map
    intro index bound
    rw [zero index bound]
    decide
  · intro value member
    obtain ⟨index, indexMember, equal⟩ := List.mem_map.mp member
    subst value
    exact zero index (List.mem_range.mp indexMember)

theorem project_accumulator_zero_of_source_words (packed : List Nat) (firstCall : Nat)
    (zero : ∀ word, word < 23 → spongeSourceWord packed firstCall word = 0) :
    ZeroAccumulator (projectAccumulator packed firstCall) := by
  have policy := exact_zero_words_range_map 7 (spongeSourceWord packed firstCall)
    (by intro limb bound; exact zero limb (by omega))
  have intent := exact_zero_words_range_map 7 (fun limb => spongeSourceWord packed firstCall (7 + limb))
    (by intro limb bound; exact zero (7 + limb) (by omega))
  have approved := exact_zero_words_range_map 6 (fun slot => spongeSourceWord packed firstCall (17 + slot))
    (by intro slot bound; exact zero (17 + slot) (by omega))
  exact ⟨policy.1, policy.2, intent.1, intent.2, zero 14 (by decide), zero 15 (by decide),
    zero 16 (by decide), by simp [projectAccumulator, signerCountMaximum], approved.2⟩

theorem fixed_zero_accumulator_valid : ZeroAccumulator zeroAccumulator := by
  simp [ZeroAccumulator, zeroAccumulator, ExactWords, ZeroWords, digestWords,
    signerCountMaximum, fieldModulus]

theorem accepted_single_current_accumulator_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey) :
    ZeroAccumulator (projectAuthorization packed).current := by
  apply project_accumulator_zero_of_source_words packed 98
  intro word bound
  exact accepted_single_current_source_zero accepted mode bound

theorem accepted_single_signer_tags_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey) :
    ZeroSignerTags (projectAuthorization packed).policySignerTags := by
  refine ⟨by simp [projectAuthorization, signerCountMaximum], ?_⟩
  intro tag member
  change tag ∈ (List.range 6).map (fun slot => (List.range 5).map (fun limb =>
    packedWord packed (rawIndex (authorizationPolicyTagRow slot limb)))) at member
  obtain ⟨slot, slotMember, equal⟩ := List.mem_map.mp member
  subst tag
  have slotBound := List.mem_range.mp slotMember
  apply exact_zero_words_range_map
  intro limb limbBound
  change limb < 5 at limbBound
  have zero := accepted_single_raw_zero accepted mode (row := 196 + slot * 5 + limb)
    (Or.inr ⟨by omega, by omega⟩)
  simpa only [authorizationRawWord, rawIndex, authorizationPolicyTagRow,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using zero

/-- The complete zero-opening/tag portion of single-key authorization follows from source roots. -/
theorem accepted_single_authorization_zero_shape {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey) :
    ZeroAccumulator (projectAuthorization packed).current ∧
      ZeroAccumulator (projectAuthorization packed).next ∧
      ZeroSignerTags (projectAuthorization packed).policySignerTags := by
  refine ⟨accepted_single_current_accumulator_zero accepted mode, ?_,
    accepted_single_signer_tags_zero accepted mode⟩
  simpa [projectAuthorization, mode] using fixed_zero_accumulator_valid

theorem accepted_approval_mode_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) : authorizationWord packed 1 = 1 := by
  rcases accepted_project_authorization_mode accepted with single | approval | finalMode
  · cases mode.symm.trans single.2
  · exact approval.1
  · cases mode.symm.trans finalMode.2

theorem accepted_final_mode_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) : authorizationWord packed 2 = 1 := by
  rcases accepted_project_authorization_mode accepted with single | approval | finalMode
  · cases mode.symm.trans single.2
  · cases mode.symm.trans approval.2
  · exact finalMode.1

structure ActivitySource where
  mode : Nat
  publicIndex : Nat
  root : Nat
deriving DecidableEq, Repr, Inhabited

def activitySources : List ActivitySource :=
  [⟨1, 0, 1418⟩, ⟨1, 1, 1419⟩, ⟨1, 2, 1420⟩, ⟨2, 0, 1421⟩, ⟨2, 1, 1422⟩]

def ActivitySource.Valid (entry : ActivitySource) : Prop :=
  entry.mode < 3 ∧ entry.publicIndex < 3 ∧
    exactNonlinearExpressions[216 + entry.mode]? = some (.witnessRow (92 + entry.mode)) ∧
    exactNonlinearExpressions[4 + entry.publicIndex]? = some (.publicWord entry.publicIndex) ∧
    exactNonlinearExpressions[810 + 2 * entry.publicIndex]? = some (.sub (4 + entry.publicIndex) 1) ∧
    exactNonlinearExpressions[entry.root]? = some (.mul (216 + entry.mode) (810 + 2 * entry.publicIndex)) ∧
    entry.root ∈ exactNonlinearRoots

instance (entry : ActivitySource) : Decidable entry.Valid := by
  unfold ActivitySource.Valid
  infer_instance

theorem exact_activity_sources_valid : ∀ entry, entry ∈ activitySources → entry.Valid := by
  have checked : activitySources.all (fun entry => decide entry.Valid) = true := by decide
  simpa only [List.all_eq_true, decide_eq_true_eq] using checked

theorem accepted_activity_flag_one {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (entry : ActivitySource) (valid : entry.Valid)
    (modeWord : authorizationWord packed entry.mode = 1) : publicWords.getD entry.publicIndex 0 = 1 := by
  obtain ⟨modeBound, publicBound, modeNode, publicNode, differenceNode, rootNode, rootMember⟩ := valid
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := entry.root) (by decide) rootMember
  have oneEquation := equations 1 (.constant 1) (by decide)
  have modeEquation := equations (216 + entry.mode) (.witnessRow (92 + entry.mode)) modeNode
  have publicEquation := equations (4 + entry.publicIndex) (.publicWord entry.publicIndex) publicNode
  have difference := equations (810 + 2 * entry.publicIndex) (.sub (4 + entry.publicIndex) 1) differenceNode
  have root := equations entry.root (.mul (216 + entry.mode) (810 + 2 * entry.publicIndex)) rootNode
  have rawMode : authorizationRawWord packed (92 + entry.mode) = 1 := by
    simpa only [authorizationWord, authorizationRawWord, rawIndex, authorizationModeRow,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using modeWord
  simp only [expressionField, Nat.cast_one] at oneEquation
  simp only [expressionField, authorization_lane_zero_word packed (by omega : 92 + entry.mode < 686),
    rawMode, Nat.cast_one] at modeEquation
  simp only [expressionField] at publicEquation difference root
  rw [modeEquation, one_mul, difference, publicEquation, oneEquation] at root
  have fieldOne : (publicWords.getD entry.publicIndex 0 : F) = 1 :=
    sub_eq_zero.mp (root.symm.trans rootZero)
  exact canonical_nat_cast_injective (canonical_getD publicWords accepted.1.2 _) (by decide) fieldOne

theorem accepted_approval_public_flags {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    publicWords.getD 0 0 = 1 ∧ publicWords.getD 1 0 = 1 ∧ publicWords.getD 2 0 = 1 := by
  have active := accepted_approval_mode_word accepted mode
  exact ⟨accepted_activity_flag_one accepted ⟨1, 0, 1418⟩
      (exact_activity_sources_valid _ (by simp [activitySources])) active,
    accepted_activity_flag_one accepted ⟨1, 1, 1419⟩
      (exact_activity_sources_valid _ (by simp [activitySources])) active,
    accepted_activity_flag_one accepted ⟨1, 2, 1420⟩
      (exact_activity_sources_valid _ (by simp [activitySources])) active⟩

theorem accepted_final_public_flags {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) :
    publicWords.getD 0 0 = 1 ∧ publicWords.getD 1 0 = 1 := by
  have active := accepted_final_mode_word accepted mode
  exact ⟨accepted_activity_flag_one accepted ⟨2, 0, 1421⟩
      (exact_activity_sources_valid _ (by simp [activitySources])) active,
    accepted_activity_flag_one accepted ⟨2, 1, 1422⟩
      (exact_activity_sources_valid _ (by simp [activitySources])) active⟩

theorem admitted_input_flags_both_one {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (first : publicWords.getD 0 0 = 1) (second : publicWords.getD 1 0 = 1) :
    statement.inputFlags = [1, 1] := by
  have firstFlag := (admitted_public_input_flag domain (input := 0) (by decide)).symm.trans first
  have secondFlag := (admitted_public_input_flag domain (input := 1) (by decide)).symm.trans second
  obtain ⟨left, right, flags⟩ := List.length_eq_two.mp (admitted_public_lengths statement domain.2.1).1
  have leftOne : left = 1 := by simpa [flagAt, flags] using firstFlag
  have rightOne : right = 1 := by simpa [flagAt, flags] using secondFlag
  simpa only [leftOne, rightOne] using flags

theorem admitted_approval_activity {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    statement.inputFlags = [1, 1] ∧ flagAt statement.outputFlags 0 = 1 := by
  have flags := accepted_approval_public_flags domain.2.2 mode
  exact ⟨admitted_input_flags_both_one domain flags.1 flags.2.1,
    (admitted_public_output_flag domain (output := 0) (by decide)).symm.trans flags.2.2⟩

theorem admitted_final_activity {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) : statement.inputFlags = [1, 1] := by
  have flags := accepted_final_public_flags domain.2.2 mode
  exact admitted_input_flags_both_one domain flags.1 flags.2

def nextOpeningRawRow (word : Nat) : Nat :=
  if word < 16 then 138 + word else 145 + word

def nextOpeningExpectedAttempt (word : Nat) : CsrExecutableAttempt :=
  let block := word / 8
  let call := 101 + block
  attempt (19026 + 16 * block + word % 8) 31 (16 * block + word % 8) 0
    ([(hashInitialIndex call (word % 8), 1)] ++
      (if block = 0 then [] else [(hashFinalIndex (call - 1) (word % 8), 158)]) ++
      [(rawIndex (nextOpeningRawRow word), 158)]) 0

theorem exact_next_opening_attempts : ∀ word, word < 23 →
    nextOpeningExpectedAttempt word ∈ exactCsrAttempts := by
  have checked : (exactCsrAttempts.filter (fun entry => entry.family == 31 &&
      (entry.localIndex < 8 || (16 ≤ entry.localIndex && entry.localIndex < 24) ||
        (32 ≤ entry.localIndex && entry.localIndex < 39)))) =
      (List.range 23).map nextOpeningExpectedAttempt := by decide
  intro word bound
  have member : nextOpeningExpectedAttempt word ∈ exactCsrAttempts.filter (fun entry =>
      entry.family == 31 && (entry.localIndex < 8 || (16 ≤ entry.localIndex && entry.localIndex < 24) ||
        (32 ≤ entry.localIndex && entry.localIndex < 39))) := by
    rw [checked]
    exact List.mem_map.mpr ⟨word, List.mem_range.mpr bound, rfl⟩
  exact (List.mem_filter.mp member).1

theorem accepted_next_opening_source_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {word : Nat} (bound : word < 23) :
    spongeSourceWord packed 101 word = authorizationRawWord packed (nextOpeningRawRow word) := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp only [List.getD_eq_getElem?_getD, constants.1, Option.getD_some, Nat.cast_zero]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp only [List.getD_eq_getElem?_getD, constants.2, Option.getD_some, Nat.cast_one]
  have negativeOne : (values.getD 158 0 : F) = -1 := by
    simpa using (dense_negative_coefficient_values equations).1 0 (by decide)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_next_opening_attempts word bound))
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _)
    (packed_word_canonical accepted.2.1 _)
  by_cases firstBlock : word / 8 = 0
  · simp only [nextOpeningExpectedAttempt, attempt, firstBlock, if_true,
      List.append_nil, List.cons_append, List.nil_append, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, negativeOne, zeroValue, one_mul, neg_one_mul, add_zero] at equation
    have equality := sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using equation)
    simpa only [spongeSourceWord, firstBlock, if_true, Nat.add_zero,
      authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Nat.zero_add, packedWord] using equality
  · simp only [nextOpeningExpectedAttempt, attempt, firstBlock, if_false,
      List.cons_append, List.nil_append, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, negativeOne, zeroValue, one_mul, neg_one_mul, add_zero] at equation
    simp only [spongeSourceWord, firstBlock, if_false]
    rw [field_sub_cast _ _ (by
      have previous := packed_word_canonical accepted.2.1 (hashFinalIndex (101 + word / 8 - 1) (word % 8))
      change _ < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus at previous
      omega)]
    have equality : (packed.getD (hashInitialIndex (101 + word / 8) (word % 8)) 0 : F) -
        (packed.getD (hashFinalIndex (101 + word / 8 - 1) (word % 8)) 0 : F) =
        (packed.getD (rawIndex (nextOpeningRawRow word)) 0 : F) := by
      exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg, add_assoc] using equation)
    simpa only [packedWord, authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using equality

theorem accepted_opening_shared_source_prefix {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {word : Nat} (bound : word < 16) :
    spongeSourceWord packed 101 word = spongeSourceWord packed 98 word := by
  rw [accepted_current_opening_source_word accepted (by omega),
    accepted_next_opening_source_word accepted (by omega)]
  simp only [nextOpeningRawRow, if_pos bound]

/-- Approval reuses exactly the current policy, intent, threshold, and signer count. -/
theorem accepted_approval_shared_opening_fields {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    (projectAuthorization packed).next.policyRoot = (projectAuthorization packed).current.policyRoot ∧
    (projectAuthorization packed).next.intentDigest = (projectAuthorization packed).current.intentDigest ∧
    (projectAuthorization packed).next.threshold = (projectAuthorization packed).current.threshold ∧
    (projectAuthorization packed).next.signerCount = (projectAuthorization packed).current.signerCount := by
  simp only [projectAuthorization, mode, if_true, projectAccumulator]
  refine ⟨?_, ?_, accepted_opening_shared_source_prefix accepted (by decide),
    accepted_opening_shared_source_prefix accepted (by decide)⟩
  · apply List.map_congr_left
    intro limb member
    exact accepted_opening_shared_source_prefix accepted (by
      have bound := List.mem_range.mp member
      omega)
  · apply List.map_congr_left
    intro limb member
    exact accepted_opening_shared_source_prefix accepted (by
      have bound := List.mem_range.mp member
      omega)

theorem accepted_final_next_accumulator_zero {publicWords packed : List Nat}
    (_accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) :
    ZeroAccumulator (projectAuthorization packed).next := by
  simpa [projectAuthorization, mode] using fixed_zero_accumulator_valid

end HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization

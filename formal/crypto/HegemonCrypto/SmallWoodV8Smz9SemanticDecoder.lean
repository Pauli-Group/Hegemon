import HegemonCrypto.SmallWoodV8Smz9SemanticDenseRange
import Hegemon.Transaction.Poseidon2V8DecoderRefinement

/-!
Source-bound typed projections from arbitrary packed HGV8RP03 assignments.
The total projection below is not the Rust validator: malformed assignments
still have a projection, and separately proved constraints establish its shape.
No decoder-success, honest-lowering, or typed-shape premise is introduced.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticDecoder

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (CanonicalPackedWitness CanonicalPublicWords CsrExecutableAttempt
    FieldExpression evalFieldExpression fieldSub fieldNormalize)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex inputNoteCall outputNoteCall
    inputMerkleCall inputDirectionRow authorizationModeRow authorizationPolicyTagRow)
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def packedWord (packed : List Nat) (index : Nat) : Nat := packed.getD index 0

def spongeSourceWord (packed : List Nat) (firstCall word : Nat) : Nat :=
  let block := word / 8
  let lane := word % 8
  let call := firstCall + block
  let initial := packedWord packed (hashInitialIndex call lane)
  if block = 0 then initial
  else fieldSub initial (packedWord packed (hashFinalIndex (call - 1) lane))

def projectNote (packed : List Nat) (firstCall : Nat) : V8NoteOpening :=
  { value := spongeSourceWord packed firstCall 0
    assetId := spongeSourceWord packed firstCall 1
    recipientKey := (List.range 4).map (fun limb => spongeSourceWord packed firstCall (2 + limb))
    authorizationKey := (List.range 4).map (fun limb => spongeSourceWord packed firstCall (14 + limb))
    rho := (List.range 4).map (fun limb => spongeSourceWord packed firstCall (6 + limb))
    randomness := (List.range 4).map (fun limb => spongeSourceWord packed firstCall (10 + limb)) }

def selectorIndex (assets : List Nat) (asset : Nat) : Option Nat :=
  assets.findIdx? (fun candidate => candidate == asset && candidate != balancePaddingAssetId)

def projectSelectors (active asset : Nat) (statement : V8PublicStatement) : List Nat :=
  (List.range 4).map (fun slot =>
    if active ≠ 0 ∧ selectorIndex statement.balanceAssets asset = some slot then 1 else 0)

def directionWord (packed : List Nat) (input bit : Nat) : Nat :=
  packedWord packed (rawIndex (inputDirectionRow input bit))

def projectPosition (packed : List Nat) (input : Nat) : Nat :=
  ((List.range 32).map (fun bit => 2 ^ bit * directionWord packed input bit)).sum

def projectInput (statement : V8PublicStatement) (packed : List Nat)
    (input : Nat) : V8InputWitness :=
  let active := flagAt statement.inputFlags input
  let note := projectNote packed (inputNoteCall input)
  { active
    spendKey := if active = 0 then List.replicate 4 0
      else (List.range 4).map (spongeSourceWord packed 0)
    note
    position := projectPosition packed input
    siblings := (List.range 32).map (fun level =>
      (List.range 7).map (fun limb =>
        packedWord packed (hashInitialIndex (inputMerkleCall input level)
          ((if directionWord packed input level = 0 then 7 else 0) + limb))))
    balanceSelectors := projectSelectors active note.assetId statement }

def projectOutput (statement : V8PublicStatement) (packed : List Nat)
    (output : Nat) : V8OutputWitness :=
  let active := flagAt statement.outputFlags output
  let note := projectNote packed (outputNoteCall output)
  { active, note, balanceSelectors := projectSelectors active note.assetId statement }

/-- The fallback is irrelevant only after accepted-mode one-hotness is proved. -/
def projectAuthorizationMode (packed : List Nat) : V8AuthorizationMode :=
  let single := packedWord packed (rawIndex (authorizationModeRow 0))
  let approval := packedWord packed (rawIndex (authorizationModeRow 1))
  let finalMode := packedWord packed (rawIndex (authorizationModeRow 2))
  if single = 0 ∧ approval = 1 ∧ finalMode = 0 then .approvalStep
  else if single = 0 ∧ approval = 0 ∧ finalMode = 1 then .finalThresholdSpend
  else .singleKey

def projectAccumulator (packed : List Nat) (firstCall : Nat) : V8AccumulatorOpening :=
  { policyRoot := (List.range 7).map (spongeSourceWord packed firstCall)
    intentDigest := (List.range 7).map (fun limb => spongeSourceWord packed firstCall (7 + limb))
    threshold := spongeSourceWord packed firstCall 14
    signerCount := spongeSourceWord packed firstCall 15
    approvalCount := spongeSourceWord packed firstCall 16
    approvedSlots := (List.range 6).map (fun slot => spongeSourceWord packed firstCall (17 + slot)) }

def zeroAccumulator : V8AccumulatorOpening :=
  { policyRoot := List.replicate 7 0, intentDigest := List.replicate 7 0,
    threshold := 0, signerCount := 0, approvalCount := 0, approvedSlots := List.replicate 6 0 }

def projectAuthorization (packed : List Nat) : V8AuthorizationWitness :=
  let mode := projectAuthorizationMode packed
  { mode
    current := projectAccumulator packed 98
    next := if mode = .approvalStep then projectAccumulator packed 101 else zeroAccumulator
    policySignerTags := (List.range 6).map (fun slot =>
      (List.range 5).map (fun limb => packedWord packed (rawIndex (authorizationPolicyTagRow slot limb)))) }

def projectStablecoinWords (statement : V8PublicStatement) (packed : List Nat) : List Nat :=
  (List.range 55).map (fun word =>
    packedWord packed (hashInitialIndex (106 + word / 14) (word % 14))) ++
  (List.range 4).map (fun counter => packedWord packed (hashInitialIndex 113 (7 + counter))) ++
  (List.range 4).flatMap (fun level =>
    (List.range 7).map (fun limb =>
      packedWord packed (hashInitialIndex (115 + 2 * level)
        ((if (statement.stablecoin.assetId / (2 ^ level)) % 2 = 0 then 7 else 0) + limb)))) ++
  (List.range 7).map (fun limb => packedWord packed (hashInitialIndex 123 limb))

def projectTypedWitness (statement : V8PublicStatement) (packed : List Nat) : V8Witness :=
  { inputs := (List.range 2).map (projectInput statement packed)
    outputs := (List.range 2).map (projectOutput statement packed)
    authorization := projectAuthorization packed
    stablecoin := ⟨projectStablecoinWords statement packed⟩ }

theorem packed_word_canonical {packed : List Nat}
    (canonical : CanonicalPackedWitness packed) (index : Nat) :
    packedWord packed index < fieldModulus := by
  cases found : packed[index]? with
  | none => simp [packedWord, List.getD_eq_getElem?_getD, found, fieldModulus]
  | some value =>
      simpa [packedWord, List.getD_eq_getElem?_getD, found, fieldModulus,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
        canonical.2 value (List.mem_of_getElem? found)

theorem sponge_source_word_canonical {packed : List Nat}
    (canonical : CanonicalPackedWitness packed) (firstCall word : Nat) :
    spongeSourceWord packed firstCall word < fieldModulus := by
  unfold spongeSourceWord
  dsimp
  split
  · exact packed_word_canonical canonical _
  · exact Nat.mod_lt _ (by decide)

theorem exact_words_range_map (count : Nat) (word : Nat → Nat)
    (canonical : ∀ index, index < count → word index < fieldModulus) :
    ExactWords count ((List.range count).map word) := by
  refine ⟨by simp, ?_⟩
  intro value member
  obtain ⟨index, indexMember, equal⟩ := List.mem_map.mp member
  subst value
  exact canonical index (List.mem_range.mp indexMember)

theorem project_note_field_shape {packed : List Nat}
    (canonical : CanonicalPackedWitness packed) (call : Nat) :
    (projectNote packed call).assetId < fieldModulus ∧
      ExactWords 4 (projectNote packed call).recipientKey ∧
      ExactWords 4 (projectNote packed call).authorizationKey ∧
      ExactWords 4 (projectNote packed call).rho ∧
      ExactWords 4 (projectNote packed call).randomness := by
  change spongeSourceWord packed call 1 < fieldModulus ∧ _
  refine ⟨sponge_source_word_canonical canonical _ _, ?_, ?_, ?_, ?_⟩ <;>
    exact exact_words_range_map 4 _ (by intro index _; exact sponge_source_word_canonical canonical _ _)

theorem project_input_spend_key_shape {packed : List Nat}
    (canonical : CanonicalPackedWitness packed) (statement : V8PublicStatement) (input : Nat) :
    ExactWords 4 (projectInput statement packed input).spendKey := by
  unfold projectInput
  dsimp
  split
  · simp [ExactWords, fieldModulus]
  · exact exact_words_range_map 4 _ (by intro index _; exact sponge_source_word_canonical canonical _ _)

theorem project_input_sibling_shape {packed : List Nat}
    (canonical : CanonicalPackedWitness packed) (statement : V8PublicStatement) (input : Nat) :
    (projectInput statement packed input).siblings.length = 32 ∧
      ∀ digest, digest ∈ (projectInput statement packed input).siblings → ExactWords 7 digest := by
  refine ⟨by simp [projectInput], ?_⟩
  intro digest member
  obtain ⟨level, _, rfl⟩ := List.mem_map.mp member
  exact exact_words_range_map 7 _ (by intro limb _; exact packed_word_canonical canonical _)

theorem project_shared_spend_key {packed : List Nat} (statement : V8PublicStatement)
    (firstActive : flagAt statement.inputFlags 0 = 1)
    (secondActive : flagAt statement.inputFlags 1 = 1) :
    (projectInput statement packed 0).spendKey = (projectInput statement packed 1).spendKey := by
  simp [projectInput, firstActive, secondActive]

theorem project_stable_words_shape {packed : List Nat}
    (canonical : CanonicalPackedWitness packed) (statement : V8PublicStatement) :
    ExactWords 94 (projectStablecoinWords statement packed) := by
  constructor
  · simp [projectStablecoinWords, List.length_flatMap]
  · intro value member
    simp only [projectStablecoinWords, List.mem_append, List.mem_map, List.mem_flatMap] at member
    rcases member with ((⟨_, _, rfl⟩ | ⟨_, _, rfl⟩) | ⟨_, _, _, member, rfl⟩) | ⟨_, _, rfl⟩
    all_goals try exact packed_word_canonical canonical _

theorem project_typed_witness_counts (statement : V8PublicStatement) (packed : List Nat) :
    (projectTypedWitness statement packed).inputs.length = 2 ∧
      (projectTypedWitness statement packed).outputs.length = 2 := by
  simp [projectTypedWitness]

theorem project_typed_input_at (statement : V8PublicStatement) (packed : List Nat)
    (fallback : V8InputWitness) {input : Nat} (bound : input < 2) :
    (projectTypedWitness statement packed).inputs.getD input fallback =
      projectInput statement packed input := by
  simp [projectTypedWitness, List.getD_eq_getElem?_getD, bound]

theorem project_typed_output_at (statement : V8PublicStatement) (packed : List Nat)
    (fallback : V8OutputWitness) {output : Nat} (bound : output < 2) :
    (projectTypedWitness statement packed).outputs.getD output fallback =
      projectOutput statement packed output := by
  simp [projectTypedWitness, List.getD_eq_getElem?_getD, bound]

theorem accepted_direction_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {input bit : Nat} (inputBound : input < 2) (bitBound : bit < 32) :
    directionWord packed input bit = 0 ∨ directionWord packed input bit = 1 := by
  have member : ∃ entry, entry ∈ exactBooleanWitnessRoots ∧ entry.row = inputDirectionRow input bit := by
    have inputCases : input = 0 ∨ input = 1 := by omega
    rcases inputCases with rfl | rfl
    · refine ⟨⟨2 + bit, 840 + 2 * bit, 841 + 2 * bit⟩, ?_, by simp [inputDirectionRow]⟩
      simp only [exactBooleanWitnessRoots, List.mem_append]
      left; left
      exact List.mem_map.mpr ⟨bit, List.mem_range.mpr bitBound, rfl⟩
    · refine ⟨⟨36 + bit, 917 + 2 * bit, 918 + 2 * bit⟩, ?_, by simp [inputDirectionRow]⟩
      simp only [exactBooleanWitnessRoots, List.mem_append]
      left; right
      exact List.mem_map.mpr ⟨bit, List.mem_range.mpr bitBound, rfl⟩
  obtain ⟨entry, member, row⟩ := member
  have boolean := accepted_packed_boolean_witness_rows accepted member (lane := 0) (by decide)
  simpa [directionWord, packedWord, rawIndex, row,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
    Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor] using boolean

theorem binary_natural_sum_bound (digits : Nat → Nat) (count : Nat)
    (bounds : ∀ index, index < count → digits index ≤ 1) :
    ((List.range count).map (fun index => 2 ^ index * digits index)).sum < 2 ^ count := by
  induction count with
  | zero => simp
  | succ count ih =>
      have prior := ih (by intro index bound; exact bounds index (by omega))
      have top := Nat.mul_le_mul_left (2 ^ count) (bounds count (by omega))
      simp only [List.range_succ, List.map_append, List.sum_append,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero, pow_succ] at prior ⊢
      omega

theorem accepted_project_position_bound {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {input : Nat} (inputBound : input < 2) : projectPosition packed input < 2 ^ 32 := by
  apply binary_natural_sum_bound
  intro bit bitBound
  rcases accepted_direction_boolean accepted inputBound bitBound with zero | one <;> omega

def noteBridgeCall (note : Nat) : Nat := [1, 37, 73, 76].getD note 0
def noteBridgeAttemptIndex (note : Nat) : Nat := [15806, 15836, 18326, 18356].getD note 0

def noteBridgeExpectedAttempt (note word : Nat) : CsrExecutableAttempt :=
  attempt (noteBridgeAttemptIndex note + word) (if note < 2 then 12 else 21)
    (30 * (note % 2) + word) 0
    [(hashInitialIndex (noteBridgeCall note) word, 1), (densePrivateAddress note + 64 * word, 158)] 0

theorem exact_note_bridge_attempts : ∀ note, note < 4 → ∀ word, word < 2 →
    exactCsrAttempts[noteBridgeAttemptIndex note + word]? =
      some (noteBridgeExpectedAttempt note word) := by
  have checked : (List.range 4).all (fun note => (List.range 2).all (fun word =>
      decide (exactCsrAttempts[noteBridgeAttemptIndex note + word]? =
        some (noteBridgeExpectedAttempt note word)))) = true := by decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

/-- The actual note value and asset sponge words equal the corresponding raw words. -/
theorem accepted_note_source_bridge {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {note word : Nat} (noteBound : note < 4) (wordBound : word < 2) :
    spongeSourceWord packed (noteBridgeCall note) word =
      packedWord packed (densePrivateAddress note + 64 * word) := by
  obtain ⟨values, evaluated, allAttempts⟩ := accepted.2.2.2
  have equations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows evaluated found
  have fieldEquation := accepted_csr_attempt_field_equality
    (allAttempts _ (List.mem_of_getElem? (exact_note_bridge_attempts note noteBound word wordBound)))
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have minusOne : (values.getD 158 0 : F) = -1 := by
    simpa using (dense_negative_coefficient_values equations).1 0 (by decide)
  simp only [noteBridgeExpectedAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, oneValue, minusOne, zeroValue, one_mul, neg_mul,
    add_zero] at fieldEquation
  have equality : (packed.getD (hashInitialIndex (noteBridgeCall note) word) 0 : F) =
      (packed.getD (densePrivateAddress note + 64 * word) 0 : F) := by
    exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using fieldEquation)
  have natural := canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (hashInitialIndex (noteBridgeCall note) word))
    (packed_word_canonical accepted.2.1 (densePrivateAddress note + 64 * word)) equality
  have divide : word / 8 = 0 := Nat.div_eq_of_lt (by omega)
  have modulo : word % 8 = word := Nat.mod_eq_of_lt (by omega)
  simpa [spongeSourceWord, divide, modulo] using natural

theorem accepted_project_note_value_bound {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {note : Nat} (noteBound : note < 4) :
    (projectNote packed (noteBridgeCall note)).value < valueBound := by
  change spongeSourceWord packed (noteBridgeCall note) 0 < 2 ^ 61
  rw [accepted_note_source_bridge accepted noteBound (by decide)]
  simpa [denseSourceValue, noteBound, packedWord] using
    accepted_dense_source_value_bound accepted (value := note) (by omega)

/-- Four decoded note values are bounded from accepted source equations, not parser success. -/
theorem accepted_input_output_note_value_bounds {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) :
    (∀ input, input < 2 → (projectInput statement packed input).note.value < valueBound) ∧
      (∀ output, output < 2 → (projectOutput statement packed output).note.value < valueBound) := by
  constructor
  · intro input bound
    have cases : input = 0 ∨ input = 1 := by omega
    rcases cases with rfl | rfl
    · simpa [projectInput, inputNoteCall, noteBridgeCall] using
        accepted_project_note_value_bound accepted (note := 0) (by decide)
    · simpa [projectInput, inputNoteCall, noteBridgeCall] using
        accepted_project_note_value_bound accepted (note := 1) (by decide)
  · intro output bound
    have cases : output = 0 ∨ output = 1 := by omega
    rcases cases with rfl | rfl
    · simpa [projectOutput, outputNoteCall, noteBridgeCall] using
        accepted_project_note_value_bound accepted (note := 2) (by decide)
    · simpa [projectOutput, outputNoteCall, noteBridgeCall] using
        accepted_project_note_value_bound accepted (note := 3) (by decide)

def authorizationWord (packed : List Nat) (mode : Nat) : Nat :=
  packedWord packed (rawIndex (authorizationModeRow mode))

theorem accepted_authorization_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {mode : Nat} (bound : mode < 3) :
    authorizationWord packed mode = 0 ∨ authorizationWord packed mode = 1 := by
  have member : ∀ mode, mode < 3 →
      BooleanWitnessRoot.mk (92 + mode) (1235 + 2 * mode) (1236 + 2 * mode) ∈
        exactBooleanWitnessRoots := by
    have checked : (List.range 3).all (fun mode => decide
        (BooleanWitnessRoot.mk (92 + mode) (1235 + 2 * mode) (1236 + 2 * mode) ∈
          exactBooleanWitnessRoots)) = true := by decide
    simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked
  have boolean := accepted_packed_boolean_witness_rows accepted (member mode bound)
    (lane := 0) (by decide)
  simpa [authorizationWord, packedWord, rawIndex, authorizationModeRow,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
    Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor] using boolean

set_option maxHeartbeats 1000000 in
/-- Root 1243 excludes all five invalid Boolean authorization triples. -/
theorem accepted_authorization_one_hot {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (authorizationWord packed 0 = 1 ∧ authorizationWord packed 1 = 0 ∧ authorizationWord packed 2 = 0) ∨
    (authorizationWord packed 0 = 0 ∧ authorizationWord packed 1 = 1 ∧ authorizationWord packed 2 = 0) ∨
    (authorizationWord packed 0 = 0 ∧ authorizationWord packed 1 = 0 ∧ authorizationWord packed 2 = 1) := by
  obtain ⟨values, evaluated, rootZero⟩ :=
    HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 0 (by decide)) (root := 1243) (by decide)
  have equations : ∀ (index : Nat) (expression : FieldExpression),
      exactNonlinearExpressions[index]? = some expression →
      values[index]? = evalFieldExpression publicWords
        (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0)
        values expression := by
    intro index expression found
    exact evaluated_program_satisfies_each_node hgv8rp03_nonlinear_expression_program_is_canonical
      evaluated found
  have sourceValues : ∀ mode, mode < 3 →
      values[216 + mode]? = some (authorizationWord packed mode) := by
    intro mode bound
    have sourceNodes : ∀ mode, mode < 3 →
        exactNonlinearExpressions[216 + mode]? = some (.witnessRow (92 + mode)) := by
      have checked : (List.range 3).all (fun mode => decide
          (exactNonlinearExpressions[216 + mode]? = some (.witnessRow (92 + mode)))) = true := by decide
      simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked
    have wordBound := packed_word_canonical accepted.2.1 (rawIndex (authorizationModeRow mode))
    have normalized : fieldNormalize (authorizationWord packed mode) = authorizationWord packed mode := by
      exact Nat.mod_eq_of_lt wordBound
    have rowBound : 92 + mode < Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount := by
      change 92 + mode < 686; omega
    have rowFound :
        (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 0)[92 + mode]? =
        some (authorizationWord packed mode) := by
      simp [Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows, rowBound,
        authorizationWord, packedWord, rawIndex, authorizationModeRow,
        Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
        Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
        Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor]
    simpa [evalFieldExpression, rowFound, normalized] using
      equations (216 + mode) (.witnessRow (92 + mode)) (sourceNodes mode bound)
  have oneValue : values[1]? = some 1 := by
    simpa [evalFieldExpression, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 1 (.constant 1) (by decide)
  have firstValue := sourceValues 0 (by decide)
  have secondValue := sourceValues 1 (by decide)
  have thirdValue := sourceValues 2 (by decide)
  have firstSum := equations 1241 (.add 216 217) (by decide)
  have totalSum := equations 1242 (.add 218 1241) (by decide)
  have finalDifference := equations 1243 (.sub 1242 1) (by decide)
  simp only [evalFieldExpression, firstValue, secondValue] at firstSum
  simp only [evalFieldExpression, thirdValue, firstSum] at totalSum
  simp only [evalFieldExpression, totalSum, oneValue] at finalDifference
  have finalZero := Option.some.inj (finalDifference.symm.trans rootZero)
  rcases accepted_authorization_boolean accepted (mode := 0) (by decide) with h0 | h0 <;>
    rcases accepted_authorization_boolean accepted (mode := 1) (by decide) with h1 | h1 <;>
    rcases accepted_authorization_boolean accepted (mode := 2) (by decide) with h2 | h2 <;>
    simp [h0, h1, h2, Hegemon.Transaction.Poseidon2V8RelationProgram.fieldAdd,
      fieldSub, fieldNormalize, Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus]
      at finalZero ⊢

/-- The total mode projection takes exactly the mode selected by accepted source flags. -/
theorem accepted_project_authorization_mode {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (authorizationWord packed 0 = 1 ∧ projectAuthorizationMode packed = .singleKey) ∨
    (authorizationWord packed 1 = 1 ∧ projectAuthorizationMode packed = .approvalStep) ∨
    (authorizationWord packed 2 = 1 ∧ projectAuthorizationMode packed = .finalThresholdSpend) := by
  rcases accepted_authorization_one_hot accepted with ⟨single, approval, finalMode⟩ |
      ⟨single, approval, finalMode⟩ | ⟨single, approval, finalMode⟩
  · left
    simp only [authorizationWord] at single approval finalMode
    exact ⟨single, by simp [projectAuthorizationMode, single, approval, finalMode]⟩
  · right; left
    simp only [authorizationWord] at single approval finalMode
    exact ⟨approval, by simp [projectAuthorizationMode, single, approval, finalMode]⟩
  · right; right
    simp only [authorizationWord] at single approval finalMode
    exact ⟨finalMode, by simp [projectAuthorizationMode, single, approval, finalMode]⟩

end HegemonCrypto.SmallWood.V8Smz9SemanticDecoder

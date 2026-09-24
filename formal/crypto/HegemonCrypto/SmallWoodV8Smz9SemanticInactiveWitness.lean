import HegemonCrypto.SmallWoodV8Smz9SemanticDecoder

/-!
Remaining source-derived canonical witness properties. The target semantic
predicate is unchanged. No decoder-success or typed-witness-shape premise is
introduced: inactive zeroing comes from the actual activity-gated equations.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (CanonicalPackedWitness CsrExecutableAttempt ExpressionProgram FieldExpression evalFieldExpression
    fieldNormalize fieldAdd fieldSub fieldMul)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex inputNoteCall outputNoteCall inputMerkleCall inputDirectionRow)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

def inactiveNegativeRoot (note : Nat) : Nat := [198, 273, 288, 296].getD note 0

theorem exact_inactive_coefficient_nodes : ∀ note, note < 4 →
    exactCsrExpressions[4 + note]? = some (.publicWord note) ∧
    exactCsrExpressions[124 + note]? = some (.sub 1 (4 + note)) ∧
    exactCsrExpressions[inactiveNegativeRoot note]? = some (.mul (124 + note) 158) := by
  have checked : (List.range 4).all (fun note => decide
      (exactCsrExpressions[4 + note]? = some (.publicWord note) ∧
       exactCsrExpressions[124 + note]? = some (.sub 1 (4 + note)) ∧
       exactCsrExpressions[inactiveNegativeRoot note]? = some (.mul (124 + note) 158))) = true := by decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

theorem inactive_coefficient_values {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    {note : Nat} (bound : note < 4) (inactive : publicWords.getD note 0 = 0) :
    (values.getD (124 + note) 0 : F) = 1 ∧
      (values.getD (inactiveNegativeRoot note) 0 : F) = -1 := by
  have nodes := exact_inactive_coefficient_nodes note bound
  have constants := csr_trace_zero_one_values equations
  have publicFound := (canonical_public_coordinate canonical (index := note) (by
    change note < 120; omega)).1
  rw [inactive] at publicFound
  have publicValue : values[4 + note]? = some 0 := by
    simpa [evalFieldExpression, publicFound, fieldNormalize] using
      equations (4 + note) (.publicWord note) nodes.1
  have positiveValue : values[124 + note]? = some 1 := by
    simpa [evalFieldExpression, constants.2, publicValue, fieldSub, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations (124 + note) (.sub 1 (4 + note)) nodes.2.1
  have minusOneValue : values[158]? = some (fieldSub 0 1) := by
    simpa [evalFieldExpression, constants.1, constants.2] using
      equations 158 (.sub 0 1) (by decide)
  have negativeValue : values[inactiveNegativeRoot note]? = some (fieldSub 0 1) := by
    simpa [evalFieldExpression, positiveValue, minusOneValue, fieldSub, fieldMul,
      fieldNormalize, Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations (inactiveNegativeRoot note) (.mul (124 + note) 158) nodes.2.2
  constructor
  · simp [List.getD_eq_getElem?_getD, positiveValue]
  · simp only [List.getD_eq_getElem?_getD, negativeValue, Option.getD_some]
    rw [field_sub_cast 0 1 (by decide)]
    simp

theorem accepted_trace_equations {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    ∃ values, CsrTraceEquations publicWords values ∧
      ∀ entry, entry ∈ exactCsrAttempts → entry.Accepts values packed := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  refine ⟨values, ?_, attempts⟩
  intro index expression found
  exact evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows evaluated found

def inactiveNoteAttemptIndex (note : Nat) : Nat := [15882, 15900, 18418, 18436].getD note 0

def inactiveNoteExpectedAttempt (note word : Nat) : CsrExecutableAttempt :=
  let call := noteBridgeCall note + word / 8
  attempt (inactiveNoteAttemptIndex note + word) (if note < 2 then 13 else 22)
    (18 * (note % 2) + word) 1
    ([(hashInitialIndex call (word % 8), 124 + note)] ++
      if word / 8 = 0 then [] else [(hashFinalIndex (call - 1) (word % 8), inactiveNegativeRoot note)]) 0

theorem exact_inactive_note_attempts : ∀ note, note < 4 → ∀ word, word < 18 →
    inactiveNoteExpectedAttempt note word ∈ exactCsrAttempts := by
  have checked : (exactCsrAttempts.filter (fun entry => entry.family == 13 || entry.family == 22)) =
      (List.range 4).flatMap (fun note => (List.range 18).map (inactiveNoteExpectedAttempt note)) := by decide
  intro note noteBound word wordBound
  have member : inactiveNoteExpectedAttempt note word ∈
      (exactCsrAttempts.filter (fun entry => entry.family == 13 || entry.family == 22)) := by
    rw [checked]
    exact List.mem_flatMap.mpr ⟨note, List.mem_range.mpr noteBound,
      List.mem_map.mpr ⟨word, List.mem_range.mpr wordBound, rfl⟩⟩
  exact (List.mem_filter.mp member).1

theorem accepted_inactive_note_source_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {note word : Nat} (noteBound : note < 4) (wordBound : word < 18)
    (inactive : publicWords.getD note 0 = 0) :
    spongeSourceWord packed (noteBridgeCall note) word = 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have coefficients := inactive_coefficient_values equations accepted.1 noteBound inactive
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have fieldEquation := accepted_csr_attempt_field_equality
    (attempts _ (exact_inactive_note_attempts note noteBound word wordBound))
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _) (by decide)
  by_cases firstBlock : word / 8 = 0
  · simp only [inactiveNoteExpectedAttempt, attempt, csrFieldSum, firstBlock, if_true,
      List.append_nil, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at fieldEquation
    rw [coefficients.1, zeroValue, one_mul, add_zero] at fieldEquation
    simpa only [spongeSourceWord, firstBlock, if_true, Nat.add_zero, packedWord, Nat.cast_zero] using fieldEquation
  · have previousBound := packed_word_canonical accepted.2.1
      (hashFinalIndex (noteBridgeCall note + word / 8 - 1) (word % 8))
    simp only [spongeSourceWord, firstBlock, if_false]
    rw [field_sub_cast
      (packedWord packed (hashInitialIndex (noteBridgeCall note + word / 8) (word % 8)))
      (packedWord packed (hashFinalIndex (noteBridgeCall note + word / 8 - 1) (word % 8))) (by
      change _ < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus at previousBound
      omega)]
    simp only [inactiveNoteExpectedAttempt, attempt, csrFieldSum, firstBlock, if_false,
      List.cons_append, List.nil_append, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil] at fieldEquation
    rw [coefficients.1, coefficients.2, zeroValue, one_mul, neg_one_mul, add_zero] at fieldEquation
    simpa only [packedWord, sub_eq_add_neg, Nat.cast_zero] using fieldEquation

theorem zero_note_of_source_words {packed : List Nat} (call : Nat)
    (canonical : CanonicalPackedWitness packed)
    (zero : ∀ word, word < 18 → spongeSourceWord packed call word = 0) :
    ZeroNoteOpening (projectNote packed call) := by
  have shape := project_note_field_shape canonical call
  refine ⟨zero 0 (by decide), zero 1 (by decide), shape.2.1, ?_, shape.2.2.1, ?_,
    shape.2.2.2.1, ?_, shape.2.2.2.2, ?_⟩
  all_goals
    intro value member
    obtain ⟨limb, limbMember, equal⟩ := List.mem_map.mp member
    subst value
    have limbBound := List.mem_range.mp limbMember
    exact zero _ (by omega)

theorem accepted_inactive_note_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {note : Nat} (noteBound : note < 4) (inactive : publicWords.getD note 0 = 0) :
    ZeroNoteOpening (projectNote packed (noteBridgeCall note)) := by
  apply zero_note_of_source_words _ accepted.2.1
  intro word bound
  exact accepted_inactive_note_source_zero accepted noteBound bound inactive

def inactiveRawExpectedAttempt (input row : Nat) : CsrExecutableAttempt :=
  attempt (15561 + 34 * input + row) 1 (34 * input + row) 1
    [(rawIndex (34 * input + row), 124 + input)] 0

theorem exact_inactive_raw_attempts : ∀ input, input < 2 → ∀ row, row < 34 →
    inactiveRawExpectedAttempt input row ∈ exactCsrAttempts := by
  have checked : (exactCsrAttempts.filter (fun entry => entry.family == 1)) =
      (List.range 2).flatMap (fun input => (List.range 34).map (inactiveRawExpectedAttempt input)) := by decide
  intro input inputBound row rowBound
  have member : inactiveRawExpectedAttempt input row ∈
      (exactCsrAttempts.filter (fun entry => entry.family == 1)) := by
    rw [checked]
    exact List.mem_flatMap.mpr ⟨input, List.mem_range.mpr inputBound,
      List.mem_map.mpr ⟨row, List.mem_range.mpr rowBound, rfl⟩⟩
  exact (List.mem_filter.mp member).1

theorem accepted_inactive_raw_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {input row : Nat} (inputBound : input < 2) (rowBound : row < 34)
    (inactive : publicWords.getD input 0 = 0) :
    packedWord packed (rawIndex (34 * input + row)) = 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have coefficients := inactive_coefficient_values equations accepted.1 (by omega : input < 4) inactive
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have fieldEquation := accepted_csr_attempt_field_equality
    (attempts _ (exact_inactive_raw_attempts input inputBound row rowBound))
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
  simp only [inactiveRawExpectedAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil] at fieldEquation
  rw [coefficients.1, zeroValue, one_mul, add_zero] at fieldEquation
  exact fieldEquation

theorem accepted_inactive_direction_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {input bit : Nat} (inputBound : input < 2) (bitBound : bit < 32)
    (inactive : publicWords.getD input 0 = 0) : directionWord packed input bit = 0 := by
  simpa [directionWord, inputDirectionRow, Nat.add_assoc, Nat.mul_comm] using
    accepted_inactive_raw_zero accepted inputBound (row := 2 + bit) (by omega) inactive

theorem accepted_inactive_position_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {input : Nat} (inputBound : input < 2) (inactive : publicWords.getD input 0 = 0) :
    projectPosition packed input = 0 := by
  apply List.sum_eq_zero
  intro term member
  obtain ⟨bit, bitMember, equal⟩ := List.mem_map.mp member
  subst term
  rw [accepted_inactive_direction_zero accepted inputBound (List.mem_range.mp bitMember) inactive]
  simp

def inlineRightAddress (input level limb : Nat) : Nat :=
  let index := 224 * input + 7 * level + limb
  16256 + 256 * (index / 64) + index % 64

def inactiveSiblingExpectedAttempt (input level limb : Nat) : CsrExecutableAttempt :=
  let index := 224 * input + 7 * level + limb
  attempt (17838 + index) 17 index 1 [(inlineRightAddress input level limb, 124 + input)] 0

def siblingBindingExpectedAttempt (input level limb : Nat) : CsrExecutableAttempt :=
  let index := 16 * (32 * input + level) + 7 + limb
  attempt (15918 + index) 14 index 0
    [(hashInitialIndex (inputMerkleCall input level) (7 + limb), 1),
     (inlineRightAddress input level limb, 158)] 0

theorem exact_inactive_sibling_attempts : ∀ input, input < 2 → ∀ level, level < 32 →
    ∀ limb, limb < 7 →
    inactiveSiblingExpectedAttempt input level limb ∈ exactCsrAttempts ∧
    siblingBindingExpectedAttempt input level limb ∈ exactCsrAttempts := by
  have zeroChecked : (exactCsrAttempts.filter (fun entry => entry.family == 17)) =
      (List.range 2).flatMap (fun input => (List.range 32).flatMap (fun level =>
        (List.range 7).map (inactiveSiblingExpectedAttempt input level))) := by decide
  have bindingChecked : (exactCsrAttempts.filter (fun entry => entry.family == 14 &&
      7 ≤ entry.localIndex % 16 && entry.localIndex % 16 < 14)) =
      (List.range 2).flatMap (fun input => (List.range 32).flatMap (fun level =>
        (List.range 7).map (siblingBindingExpectedAttempt input level))) := by decide
  intro input inputBound level levelBound limb limbBound
  constructor
  · have member : inactiveSiblingExpectedAttempt input level limb ∈
        (exactCsrAttempts.filter (fun entry => entry.family == 17)) := by
      rw [zeroChecked]
      exact List.mem_flatMap.mpr ⟨input, List.mem_range.mpr inputBound,
        List.mem_flatMap.mpr ⟨level, List.mem_range.mpr levelBound,
          List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩⟩⟩
    exact (List.mem_filter.mp member).1
  · have member : siblingBindingExpectedAttempt input level limb ∈
        (exactCsrAttempts.filter (fun entry => entry.family == 14 &&
          7 ≤ entry.localIndex % 16 && entry.localIndex % 16 < 14)) := by
      rw [bindingChecked]
      exact List.mem_flatMap.mpr ⟨input, List.mem_range.mpr inputBound,
        List.mem_flatMap.mpr ⟨level, List.mem_range.mpr levelBound,
          List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩⟩⟩
    exact (List.mem_filter.mp member).1

theorem accepted_inactive_sibling_source_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {input level limb : Nat} (inputBound : input < 2) (levelBound : level < 32) (limbBound : limb < 7)
    (inactive : publicWords.getD input 0 = 0) :
    packedWord packed (hashInitialIndex (inputMerkleCall input level) (7 + limb)) = 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have coefficients := inactive_coefficient_values equations accepted.1 (by omega : input < 4) inactive
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have source := exact_inactive_sibling_attempts input inputBound level levelBound limb limbBound
  have zeroEquation := accepted_csr_attempt_field_equality
    (attempts _ source.1)
  have bindingEquation := accepted_csr_attempt_field_equality
    (attempts _ source.2)
  have inlineZero : (packed.getD (inlineRightAddress input level limb) 0 : F) = 0 := by
    simp only [inactiveSiblingExpectedAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil] at zeroEquation
    simpa only [coefficients.1, zeroValue, one_mul, add_zero] using zeroEquation
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
  simp only [siblingBindingExpectedAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil] at bindingEquation
  simpa only [inlineZero, oneValue, zeroValue, one_mul, mul_zero, add_zero, packedWord,
    Nat.cast_zero] using bindingEquation

theorem accepted_inactive_siblings_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) {input : Nat} (inputBound : input < 2)
    (inactive : publicWords.getD input 0 = 0) :
    ∀ digest, digest ∈ (projectInput statement packed input).siblings →
      ExactWords 7 digest ∧ ZeroWords digest := by
  intro digest member
  refine ⟨(project_input_sibling_shape accepted.2.1 statement input).2 digest member, ?_⟩
  obtain ⟨level, levelMember, equal⟩ := List.mem_map.mp member
  subst digest
  intro value valueMember
  obtain ⟨limb, limbMember, equal⟩ := List.mem_map.mp valueMember
  subst value
  have levelBound := List.mem_range.mp levelMember
  have limbBound := List.mem_range.mp limbMember
  rw [accepted_inactive_direction_zero accepted inputBound levelBound inactive]
  simpa using accepted_inactive_sibling_source_zero accepted inputBound levelBound limbBound inactive

theorem admitted_public_input_flag {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {input : Nat} (bound : input < 2) :
    publicWords.getD input 0 = flagAt statement.inputFlags input := by
  have inputLength : statement.inputFlags.length = 2 := domain.2.1.1
  have inBound : input < statement.inputFlags.length := by omega
  rw [← domain.1]
  simp only [encodePublicStatement, List.append_assoc, flagAt, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_left inBound]

theorem admitted_public_output_flag {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {output : Nat} (bound : output < 2) :
    publicWords.getD (2 + output) 0 = flagAt statement.outputFlags output := by
  have inputLength : statement.inputFlags.length = 2 := domain.2.1.1
  have outputLength : statement.outputFlags.length = 2 := domain.2.1.2.1
  have inBound : output < statement.outputFlags.length := by omega
  rw [← domain.1]
  simp only [encodePublicStatement, List.append_assoc, flagAt, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_right (by omega : statement.inputFlags.length ≤ 2 + output)]
  rw [inputLength, Nat.add_sub_cancel_left, List.getElem?_append_left inBound]

theorem project_selectors_inactive (statement : V8PublicStatement) (asset : Nat) :
    (projectSelectors 0 asset statement).length = balanceSlotCount ∧
      ZeroWords (projectSelectors 0 asset statement) := by
  simp [projectSelectors, balanceSlotCount, ZeroWords]

theorem admitted_inactive_input_zero {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {input : Nat} (inputBound : input < 2) (inactive : flagAt statement.inputFlags input = 0) :
    ZeroInputWitness (projectInput statement packed input) := by
  have rawInactive : publicWords.getD input 0 = 0 := by
    rw [admitted_public_input_flag domain inputBound, inactive]
  have callEqual : noteBridgeCall input = inputNoteCall input := by
    interval_cases input <;> rfl
  have noteZero := accepted_inactive_note_zero domain.2.2 (by omega : input < 4) rawInactive
  rw [callEqual] at noteZero
  have siblingShape := project_input_sibling_shape domain.2.2.2.1 statement input
  have siblingZero := accepted_inactive_siblings_zero domain.2.2 statement inputBound rawInactive
  refine ⟨inactive, project_input_spend_key_shape domain.2.2.2.1 statement input, ?_, noteZero,
    accepted_inactive_position_zero domain.2.2 inputBound rawInactive, siblingShape.1, ?_, ?_, ?_⟩
  · simp [projectInput, inactive, ZeroWords]
  · simpa only [digestWords] using siblingZero
  · simp [projectInput, projectSelectors, balanceSlotCount]
  · simp [projectInput, projectSelectors, inactive, ZeroWords]

theorem admitted_inactive_output_zero {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {output : Nat} (outputBound : output < 2) (inactive : flagAt statement.outputFlags output = 0) :
    ZeroOutputWitness (projectOutput statement packed output) := by
  have rawInactive : publicWords.getD (2 + output) 0 = 0 := by
    rw [admitted_public_output_flag domain outputBound, inactive]
  have callEqual : noteBridgeCall (2 + output) = outputNoteCall output := by
    interval_cases output <;> rfl
  have noteZero := accepted_inactive_note_zero domain.2.2 (by omega : 2 + output < 4) rawInactive
  rw [callEqual] at noteZero
  refine ⟨inactive, noteZero, ?_, ?_⟩
  · simp [projectOutput, projectSelectors, balanceSlotCount]
  · simp [projectOutput, projectSelectors, inactive, ZeroWords]

theorem admitted_inactive_typed_input_zero {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {input : Nat} (inputBound : input < 2) (inactive : flagAt statement.inputFlags input = 0)
    (fallback : V8InputWitness) :
    ZeroInputWitness ((projectTypedWitness statement packed).inputs.getD input fallback) := by
  rw [project_typed_input_at statement packed fallback inputBound]
  exact admitted_inactive_input_zero domain inputBound inactive

theorem admitted_inactive_typed_output_zero {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {output : Nat} (outputBound : output < 2) (inactive : flagAt statement.outputFlags output = 0)
    (fallback : V8OutputWitness) :
    ZeroOutputWitness ((projectTypedWitness statement packed).outputs.getD output fallback) := by
  rw [project_typed_output_at statement packed fallback outputBound]
  exact admitted_inactive_output_zero domain outputBound inactive

end HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness

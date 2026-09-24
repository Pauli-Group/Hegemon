import HegemonCrypto.SmallWoodV8Smz9SemanticInactiveWitness
import HegemonCrypto.SmallWoodV8Smz9ProgramPolynomials
import HegemonCrypto.SmallWoodV8Smz9SemanticAssetMembership

/-!
Remaining source-derived canonical witness properties. The target semantic
predicate is unchanged. No decoder-success or typed-witness-shape premise is
introduced: inactive zeroing comes from the actual activity-gated equations.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness

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
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
  (expressionField source_go_canonical canonical_getD source_expression_refinement)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
  (admitted_input_flag_one admitted_input_asset_selectors admitted_output_asset_selectors)

open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

def FieldTraceEquations (publicWords rows values : List Nat) (expressions : List FieldExpression) : Prop :=
  ∀ (index : Nat) (expression : FieldExpression), expressions[index]? = some expression →
    (values.getD index 0 : F) = expressionField (fun index => (publicWords.getD index 0 : F))
      (fun index => (rows.getD index 0 : F)) (fun index => (values.getD index 0 : F)) expression

theorem evaluated_field_trace_equations {program : ExpressionProgram}
    {publicWords rows values : List Nat} (canonical : program.Canonical true)
    (evaluated : Hegemon.Transaction.Poseidon2V8RelationProgram.evalExpressionNodes
      publicWords rows program.expressions = some values) :
    FieldTraceEquations publicWords rows values program.expressions := by
  have valuesCanonical := source_go_canonical publicWords rows [] values program.expressions
    (by simp) evaluated
  obtain ⟨suffix, valueEqual, lengthEqual, equations⟩ := eval_go_equations
    publicWords rows [] values program.expressions (by simpa using canonical.1) evaluated
  have valuesLength : values.length = program.expressions.length := by
    simpa [valueEqual] using lengthEqual
  intro index expression found
  obtain ⟨indexBound, _⟩ := List.getElem?_eq_some_iff.mp found
  have valueBound : index < values.length := by omega
  have valueFound : values[index]? = some (values.getD index 0) := by simp [List.getD, valueBound]
  have equation := equations index expression found
  simp only [List.length_nil, Nat.zero_add] at equation
  rw [valueFound] at equation
  exact (source_expression_refinement publicWords rows values
    (canonical_getD values valuesCanonical) expression (values.getD index 0) equation.symm).2

theorem accepted_csr_field_trace {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    ∃ values, FieldTraceEquations publicWords [] values exactCsrExpressions ∧
      ∀ entry, entry ∈ exactCsrAttempts → entry.Accepts values packed := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  exact ⟨values, evaluated_field_trace_equations exact_csr_is_canonical_with_rows evaluated, attempts⟩

theorem active_key_coefficient_equalities {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (active : publicWords.getD 0 0 = 1 ∨ publicWords.getD 1 0 = 1) :
    (values.getD 1 0 : F) = 1 ∧ (values.getD 0 0 : F) = 0 ∧
      (values.getD 339 0 : F) = (values.getD 196 0 : F) ∧
      (values.getD 340 0 : F) = (values.getD 197 0 : F) ∧
      (values.getD 338 0 : F) = 0 := by
  have zeroValue := equations 0 (.constant 0) (by decide)
  have oneValue := equations 1 (.constant 1) (by decide)
  have first := equations 4 (.publicWord 0) (by decide)
  have second := equations 5 (.publicWord 1) (by decide)
  have inactiveFirst := equations 124 (.sub 1 4) (by decide)
  have bothActive := equations 193 (.mul 4 5) (by decide)
  have selectedSecond := equations 195 (.mul 5 124) (by decide)
  have negativeFirst := equations 196 (.sub 0 4) (by decide)
  have negativeSecond := equations 197 (.sub 0 195) (by decide)
  have sum := equations 334 (.add 4 5) (by decide)
  have anyActive := equations 335 (.sub 334 193) (by decide)
  have firstRole := equations 336 (.mul 4 335) (by decide)
  have secondRole := equations 337 (.mul 195 335) (by decide)
  have roleTarget := equations 338 (.sub 1 335) (by decide)
  have negativeFirstRole := equations 339 (.sub 0 336) (by decide)
  have negativeSecondRole := equations 340 (.sub 0 337) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at zeroValue oneValue first second inactiveFirst bothActive selectedSecond negativeFirst negativeSecond sum anyActive firstRole secondRole roleTarget negativeFirstRole negativeSecondRole
  have anyOne : (values.getD 335 0 : F) = 1 := by
    rw [anyActive, sum, bothActive, first, second]
    rcases active with firstActive | secondActive
    · rw [firstActive]; simp
    · rw [secondActive]; simp
  refine ⟨oneValue, zeroValue, ?_, ?_, ?_⟩
  · rw [negativeFirstRole, firstRole, anyOne, mul_one, negativeFirst]
  · rw [negativeSecondRole, secondRole, anyOne, mul_one, negativeSecond]
  · rw [roleTarget, oneValue, anyOne, sub_self]

def keyWordAddress (limb : Nat) : Nat := 18112 + 64 * limb
def keyDifferenceAddress (limb : Nat) : Nat := 41557 + 64 * limb

def decodedKeyExpectedAttempt (limb : Nat) : CsrExecutableAttempt :=
  attempt (15789 + limb) 10 limb 0
    [(keyWordAddress limb, 1), (41520 + limb, 196), (41524 + limb, 197)] 0

def roleKeyExpectedAttempt (limb : Nat) : CsrExecutableAttempt :=
  attempt (19491 + limb) 47 (147 + limb) 0
    ([(keyDifferenceAddress limb, 1)] ++
      if limb < 4 then [(41520 + limb, 339), (41524 + limb, 340)] else [])
    (if limb = 0 then 338 else 0)

theorem exact_key_bridge_attempts :
    (∀ limb, limb < 4 → decodedKeyExpectedAttempt limb ∈ exactCsrAttempts) ∧
    (∀ limb, limb < 7 → roleKeyExpectedAttempt limb ∈ exactCsrAttempts) := by
  have checkedKey : exactCsrAttempts.filter (fun entry =>
      15789 ≤ entry.globalIndex && entry.globalIndex < 15793) =
      (List.range 4).map decodedKeyExpectedAttempt := by decide
  have checkedRole : exactCsrAttempts.filter (fun entry =>
      19491 ≤ entry.globalIndex && entry.globalIndex < 19498) =
      (List.range 7).map roleKeyExpectedAttempt := by decide
  constructor
  · intro limb bound
    have member : decodedKeyExpectedAttempt limb ∈ exactCsrAttempts.filter (fun entry =>
        15789 ≤ entry.globalIndex && entry.globalIndex < 15793) := by
      rw [checkedKey]
      exact List.mem_map.mpr ⟨limb, List.mem_range.mpr bound, rfl⟩
    exact (List.mem_filter.mp member).1
  · intro limb bound
    have member : roleKeyExpectedAttempt limb ∈ exactCsrAttempts.filter (fun entry =>
        19491 ≤ entry.globalIndex && entry.globalIndex < 19498) := by
      rw [checkedRole]
      exact List.mem_map.mpr ⟨limb, List.mem_range.mpr bound, rfl⟩
    exact (List.mem_filter.mp member).1

theorem accepted_key_difference_binding {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (active : publicWords.getD 0 0 = 1 ∨ publicWords.getD 1 0 = 1) :
    (∀ limb, limb < 4 → (packed.getD (keyDifferenceAddress limb) 0 : F) =
      (packed.getD (keyWordAddress limb) 0 : F)) ∧
    (∀ limb, 4 ≤ limb → limb < 7 → (packed.getD (keyDifferenceAddress limb) 0 : F) = 0) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨oneValue, zeroValue, firstEqual, secondEqual, targetZero⟩ :=
    active_key_coefficient_equalities equations active
  have roleEquation : ∀ limb, limb < 7 →
      csrFieldSum values packed (roleKeyExpectedAttempt limb).terms = 0 := by
    intro limb bound
    have equation := accepted_csr_attempt_field_equality (attempts _ (exact_key_bridge_attempts.2 limb bound))
    have targetValue : (values.getD (roleKeyExpectedAttempt limb).targetRoot 0 : F) = 0 := by
      by_cases zero : limb = 0 <;> simp only [roleKeyExpectedAttempt, attempt, zero,
        if_true, if_false, targetZero, zeroValue]
    exact equation.trans targetValue
  constructor
  · intro limb bound
    have sourceEquation := accepted_csr_attempt_field_equality (attempts _ (exact_key_bridge_attempts.1 limb bound))
    have differenceEquation := roleEquation limb (by omega)
    simp only [decodedKeyExpectedAttempt, roleKeyExpectedAttempt, attempt, bound, if_true,
      List.cons_append, List.nil_append, csrFieldSum, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil] at sourceEquation differenceEquation
    rw [oneValue, one_mul, zeroValue] at sourceEquation
    rw [oneValue, one_mul, firstEqual, secondEqual] at differenceEquation
    exact add_right_cancel (differenceEquation.trans sourceEquation.symm)
  · intro limb lower upper
    have differenceEquation := roleEquation limb upper
    have notPrivate : ¬limb < 4 := by omega
    simpa only [roleKeyExpectedAttempt, attempt, notPrivate, if_false, List.append_nil,
      csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, one_mul, add_zero] using differenceEquation

theorem accepted_nonlinear_field_trace {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {lane root : Nat} (laneBound : lane < 64) (rootMember : root ∈ exactNonlinearRoots) :
    ∃ values, FieldTraceEquations publicWords
      (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed lane)
      values exactNonlinearExpressions ∧ (values.getD root 0 : F) = 0 := by
  obtain ⟨values, evaluated, rootZero⟩ :=
    HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 lane laneBound) rootMember
  refine ⟨values, evaluated_field_trace_equations
    hgv8rp03_nonlinear_expression_program_is_canonical evaluated, ?_⟩
  simp [List.getD_eq_getElem?_getD, rootZero]

def keyNonzeroNodes : List (Nat × FieldExpression) :=
  (List.range 7).map (fun limb => (773 + limb, .witnessRow (649 + limb))) ++
  [(1, .constant 1), (8028, .mul 773 8027), (8045, .mul 774 8044),
   (8046, .add 8028 8045), (8063, .mul 775 8062), (8064, .add 8046 8063),
   (8080, .mul 776 8079), (8081, .add 8064 8080), (8096, .mul 777 8095),
   (8097, .add 8081 8096), (8111, .mul 778 8110), (8112, .add 8097 8111),
   (8125, .mul 779 8124), (8126, .add 8112 8125), (8127, .mul 781 8126),
   (8128, .sub 8127 1)]

theorem exact_key_nonzero_node {index : Nat} {expression : FieldExpression}
    (member : (index, expression) ∈ keyNonzeroNodes) :
    exactNonlinearExpressions[index]? = some expression := by
  let checker := fun index expression =>
    match keyNonzeroNodes.find? (fun entry => entry.1 == index) with
    | none => true
    | some entry => decide (expression = entry.2)
  have lowChecked : checkIndexed checker 0 (exactNonlinearExpressions.take 780) = true := by decide
  have highChecked : checkIndexed checker 8028 ((exactNonlinearExpressions.drop 8028).take 101) = true := by decide
  have lookupChecked : keyNonzeroNodes.all (fun entry => decide
      (keyNonzeroNodes.find? (fun other => other.1 == entry.1) = some entry ∧
        (entry.1 < 780 ∨ 8028 ≤ entry.1 ∧ entry.1 < 8129))) = true := by decide
  have lookup := of_decide_eq_true
    (List.all_eq_true.mp lookupChecked (index, expression) member)
  have length : exactNonlinearExpressions.length = 8271 := by decide
  have bound : index < exactNonlinearExpressions.length := by
    rw [length]
    rcases lookup.2 with low | high <;> omega
  have actualFound := List.getElem?_eq_getElem bound
  have actualChecked : checker index exactNonlinearExpressions[index] = true := by
    rcases lookup.2 with low | high
    · have sliceFound : (exactNonlinearExpressions.take 780)[index]? =
          some exactNonlinearExpressions[index] := by
        simpa only [List.getElem?_take, if_pos low] using actualFound
      simpa only [Nat.zero_add] using
        (checkIndexed_eq_true checker (exactNonlinearExpressions.take 780) 0).mp lowChecked
          index exactNonlinearExpressions[index] sliceFound
    · have localBound : index - 8028 < 101 := by omega
      have indexEqual : 8028 + (index - 8028) = index := by omega
      have indexEqual' : index - 8028 + 8028 = index := by omega
      have sliceFound : ((exactNonlinearExpressions.drop 8028).take 101)[index - 8028]? =
          some exactNonlinearExpressions[index] := by
        simpa only [List.getElem?_take, if_pos localBound, List.getElem?_drop, indexEqual,
          indexEqual'] using actualFound
      simpa only [indexEqual] using
        (checkIndexed_eq_true checker ((exactNonlinearExpressions.drop 8028).take 101) 8028).mp
          highChecked (index - 8028) exactNonlinearExpressions[index] sliceFound
  simp only [checker, lookup.1, decide_eq_true_eq] at actualChecked
  simpa only [actualChecked] using actualFound

set_option maxRecDepth 1024 in
set_option maxHeartbeats 200000 in
/-- The actual selected-key inverse root rules out seven zero difference words. -/
theorem accepted_key_difference_nonzero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    ∃ limb, limb < 7 ∧ (packed.getD (keyDifferenceAddress limb) 0 : F) ≠ 0 := by
  by_contra absent
  push Not at absent
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 21) (root := 8128) (by decide) (by decide)
  have nodes : ∀ limb, limb < 7 →
      exactNonlinearExpressions[773 + limb]? = some (.witnessRow (649 + limb)) := by
    intro limb bound
    apply exact_key_nonzero_node
    apply List.mem_append_left
    exact List.mem_map.mpr ⟨limb, List.mem_range.mpr bound, rfl⟩
  have leaves : ∀ limb, limb < 7 → (values.getD (773 + limb) 0 : F) = 0 := by
    intro limb bound
    have equation := equations (773 + limb) (.witnessRow (649 + limb)) (nodes limb bound)
    have rowBound : 649 + limb < Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount := by
      change 649 + limb < 686; omega
    have rowFound :
        (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 21)[649 + limb]? =
        some (packed.getD ((649 + limb) * 64 + 21) 0) := by
      simp [Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows, rowBound,
        Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor]
    have rowSource :
        (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed 21).getD (649 + limb) 0 =
        packed.getD ((649 + limb) * 64 + 21) 0 := by
      simp [List.getD_eq_getElem?_getD, rowFound]
    simp only [expressionField, rowSource] at equation
    have address : (649 + limb) * 64 + 21 = keyDifferenceAddress limb := by
      unfold keyDifferenceAddress
      omega
    have source : (values.getD (773 + limb) 0 : F) =
        (packed.getD (keyDifferenceAddress limb) 0 : F) := by
      rw [address] at equation
      exact equation
    exact source.trans (absent limb bound)
  have leaf0 := leaves 0 (by decide)
  have leaf1 := leaves 1 (by decide)
  have leaf2 := leaves 2 (by decide)
  have leaf3 := leaves 3 (by decide)
  have leaf4 := leaves 4 (by decide)
  have leaf5 := leaves 5 (by decide)
  have leaf6 := leaves 6 (by decide)
  have product0 : (values.getD 8028 0 : F) = 0 := by
    simpa only [expressionField, leaf0, zero_mul] using equations 8028 (.mul 773 8027) (exact_key_nonzero_node (by decide))
  have product1 : (values.getD 8045 0 : F) = 0 := by
    simpa only [expressionField, leaf1, zero_mul] using equations 8045 (.mul 774 8044) (exact_key_nonzero_node (by decide))
  have sum1 : (values.getD 8046 0 : F) = 0 := by
    simpa only [expressionField, product0, product1, add_zero] using equations 8046 (.add 8028 8045) (exact_key_nonzero_node (by decide))
  have product2 : (values.getD 8063 0 : F) = 0 := by
    simpa only [expressionField, leaf2, zero_mul] using equations 8063 (.mul 775 8062) (exact_key_nonzero_node (by decide))
  have sum2 : (values.getD 8064 0 : F) = 0 := by
    simpa only [expressionField, sum1, product2, add_zero] using equations 8064 (.add 8046 8063) (exact_key_nonzero_node (by decide))
  have product3 : (values.getD 8080 0 : F) = 0 := by
    simpa only [expressionField, leaf3, zero_mul] using equations 8080 (.mul 776 8079) (exact_key_nonzero_node (by decide))
  have sum3 : (values.getD 8081 0 : F) = 0 := by
    simpa only [expressionField, sum2, product3, add_zero] using equations 8081 (.add 8064 8080) (exact_key_nonzero_node (by decide))
  have product4 : (values.getD 8096 0 : F) = 0 := by
    simpa only [expressionField, leaf4, zero_mul] using equations 8096 (.mul 777 8095) (exact_key_nonzero_node (by decide))
  have sum4 : (values.getD 8097 0 : F) = 0 := by
    simpa only [expressionField, sum3, product4, add_zero] using equations 8097 (.add 8081 8096) (exact_key_nonzero_node (by decide))
  have product5 : (values.getD 8111 0 : F) = 0 := by
    simpa only [expressionField, leaf5, zero_mul] using equations 8111 (.mul 778 8110) (exact_key_nonzero_node (by decide))
  have sum5 : (values.getD 8112 0 : F) = 0 := by
    simpa only [expressionField, sum4, product5, add_zero] using equations 8112 (.add 8097 8111) (exact_key_nonzero_node (by decide))
  have product6 : (values.getD 8125 0 : F) = 0 := by
    simpa only [expressionField, leaf6, zero_mul] using equations 8125 (.mul 779 8124) (exact_key_nonzero_node (by decide))
  have sum6 : (values.getD 8126 0 : F) = 0 := by
    simpa only [expressionField, sum5, product6, add_zero] using equations 8126 (.add 8112 8125) (exact_key_nonzero_node (by decide))
  have scaled : (values.getD 8127 0 : F) = 0 := by
    simpa only [expressionField, sum6, mul_zero] using equations 8127 (.mul 781 8126) (exact_key_nonzero_node (by decide))
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (exact_key_nonzero_node (by decide))
  have impossible : (0 : F) = -1 := by
    simpa only [expressionField, rootZero, scaled, oneValue, zero_sub] using
      equations 8128 (.sub 8127 1) (exact_key_nonzero_node (by decide))
  exact (neg_ne_zero.mpr (one_ne_zero : (1 : F) ≠ 0)) impossible.symm

theorem decoded_key_word_address {packed : List Nat} {limb : Nat} (bound : limb < 4) :
    spongeSourceWord packed 0 limb = packedWord packed (keyWordAddress limb) := by
  have division : limb / 8 = 0 := Nat.div_eq_of_lt (by omega)
  have modulo : limb % 8 = limb := Nat.mod_eq_of_lt (by omega)
  simp [spongeSourceWord, division, modulo, hashInitialIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, keyWordAddress, Nat.mul_comm]

/-- Nonzero decoded key, derived without a hash-security or decoder-success premise. -/
theorem accepted_active_spend_key_nonzero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (active : publicWords.getD 0 0 = 1 ∨ publicWords.getD 1 0 = 1) :
    NonzeroWords ((List.range 4).map (spongeSourceWord packed 0)) := by
  by_contra noKey
  have keyZero : ∀ limb, limb < 4 → (packed.getD (keyWordAddress limb) 0 : F) = 0 := by
    intro limb bound
    have zero : spongeSourceWord packed 0 limb = 0 := by
      by_contra nonzero
      exact noKey ⟨_, List.mem_map.mpr ⟨limb, List.mem_range.mpr bound, rfl⟩, nonzero⟩
    rw [decoded_key_word_address bound] at zero
    simpa only [packedWord, zero, Nat.cast_zero] using congrArg (fun word : Nat => (word : F)) zero
  have binding := accepted_key_difference_binding accepted active
  obtain ⟨limb, bound, nonzero⟩ := accepted_key_difference_nonzero accepted
  by_cases isPrivate : limb < 4
  · exact nonzero ((binding.1 limb isPrivate).trans (keyZero limb isPrivate))
  · exact nonzero (binding.2 limb (by omega) bound)

theorem admitted_active_input_spend_key_nonzero {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {input : Nat} (inputBound : input < 2) (active : flagAt statement.inputFlags input ≠ 0) :
    NonzeroWords (projectInput statement packed input).spendKey := by
  have flagOne := admitted_input_flag_one statement domain.2.1 inputBound active
  have rawOne : publicWords.getD input 0 = 1 :=
    (admitted_public_input_flag domain inputBound).trans flagOne
  have anyActive : publicWords.getD 0 0 = 1 ∨ publicWords.getD 1 0 = 1 := by
    have inputCases : input = 0 ∨ input = 1 := by omega
    rcases inputCases with rfl | rfl
    · exact Or.inl rawOne
    · exact Or.inr rawOne
  simpa only [projectInput, if_neg active] using
    accepted_active_spend_key_nonzero domain.2.2 anyActive

/--
Full unchanged canonical-witness predicate for the actual typed source
projection, on admitted public words and an arbitrary accepted packed witness.
No decoder-success, honest-lowering, or typed-shape premise is used.
-/
theorem admitted_packed_project_typed_witness_canonical {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    CanonicalWitnessShape statement (projectTypedWitness statement packed) := by
  have counts := project_typed_witness_counts statement packed
  have valueBounds := accepted_input_output_note_value_bounds domain.2.2 statement
  refine ⟨counts.1, counts.2, ?_, ?_, ?_, project_stable_words_shape domain.2.2.2.1 statement⟩
  · intro input bound
    have inputBound : input < 2 := bound
    dsimp only
    rw [project_typed_input_at statement packed _ inputBound]
    refine ⟨rfl, ?_⟩
    have activity : (projectInput statement packed input).active = flagAt statement.inputFlags input := rfl
    rw [activity]
    by_cases inactive : flagAt statement.inputFlags input = 0
    · rw [if_pos inactive]
      exact admitted_inactive_input_zero domain inputBound inactive
    · rw [if_neg inactive]
      have assets := admitted_input_asset_selectors domain inputBound inactive
      have noteShape := project_note_field_shape domain.2.2.2.1 (inputNoteCall input)
      have noteCanonical : CanonicalNoteOpening (projectInput statement packed input).note :=
        ⟨valueBounds.1 input inputBound, noteShape.1, assets.1, noteShape.2.1,
          noteShape.2.2.1, noteShape.2.2.2.1, noteShape.2.2.2.2⟩
      have siblings := project_input_sibling_shape domain.2.2.2.1 statement input
      exact ⟨noteCanonical, project_input_spend_key_shape domain.2.2.2.1 statement input,
        admitted_active_input_spend_key_nonzero domain inputBound inactive,
        accepted_project_position_bound domain.2.2 inputBound,
        siblings.1, siblings.2, assets.2⟩
  · intro output bound
    have outputBound : output < 2 := bound
    dsimp only
    rw [project_typed_output_at statement packed _ outputBound]
    refine ⟨rfl, ?_⟩
    have activity : (projectOutput statement packed output).active = flagAt statement.outputFlags output := rfl
    rw [activity]
    by_cases inactive : flagAt statement.outputFlags output = 0
    · rw [if_pos inactive]
      exact admitted_inactive_output_zero domain outputBound inactive
    · rw [if_neg inactive]
      have assets := admitted_output_asset_selectors domain outputBound inactive
      have noteShape := project_note_field_shape domain.2.2.2.1 (outputNoteCall output)
      exact ⟨⟨valueBounds.2 output outputBound, noteShape.1, assets.1, noteShape.2.1,
        noteShape.2.2.1, noteShape.2.2.2.1, noteShape.2.2.2.2⟩, assets.2⟩
  · intro firstActive secondActive
    rw [project_typed_input_at statement packed default (input := 0) (by decide),
      project_typed_input_at statement packed default (input := 1) (by decide)]
    exact project_shared_spend_key statement firstActive secondActive

end HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness

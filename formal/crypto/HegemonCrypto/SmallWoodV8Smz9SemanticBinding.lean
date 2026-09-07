import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality
import HegemonCrypto.Poseidon2V8ExpressionRootSemantics
import HegemonCrypto.Goldilocks
import Hegemon.Transaction.Poseidon2V8SemanticSpecification

/-!
Exact algebraic consequences of the HGV8RP03 packed relation.  This module does
not identify raw algebraic acceptance with frontend-admitted transaction bytes.
In particular, inactive public padding requires the independently checked public
admission boundary.  No proof-system extraction or production authority follows.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticBinding

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

open Hegemon.Transaction.Poseidon2V8SemanticSpecification in
/--
The semantic domain includes public admission and exact statement encoding.
The Rust frontend enforces public structural checks before proof verification;
proving its execution refines this predicate is an explicit separate obligation.
Raw `AcceptsPacked` alone intentionally does not claim all public padding rules.
-/
def CanonicalPublicPackedDomain (statement : V8PublicStatement)
    (publicWords packedWitness : List Nat) : Prop :=
  encodePublicStatement statement = publicWords ∧
    CanonicalPublicStatement exactV8SemanticPrimitives statement ∧
    hgv8rp03ProgramComponents.AcceptsPacked publicWords packedWitness

theorem expression_eval_append
    (publicWords rows values suffix : List Nat) (expression : FieldExpression)
    (canonical : expression.CanonicalAt true values.length) :
    evalFieldExpression publicWords rows (values ++ suffix) expression =
      evalFieldExpression publicWords rows values expression := by
  cases expression <;>
    simp only [FieldExpression.CanonicalAt] at canonical <;>
    simp_all [evalFieldExpression, List.getElem?_append_left]

/-- A successful canonical evaluation leaves a final trace satisfying each node equation. -/
theorem eval_go_equations
    (publicWords rows initial result : List Nat)
    (program : List FieldExpression)
    (canonical : ∀ (index : Nat) (expression : FieldExpression),
      program[index]? = some expression →
      expression.CanonicalAt true (initial.length + index))
    (evaluated : evalExpressionNodes.go publicWords rows program initial = some result) :
    ∃ suffix, result = initial ++ suffix ∧ suffix.length = program.length ∧
      ∀ (index : Nat) (expression : FieldExpression), program[index]? = some expression →
        result[initial.length + index]? =
          evalFieldExpression publicWords rows result expression := by
  induction program generalizing initial with
  | nil =>
      simp only [evalExpressionNodes.go, Option.some.injEq] at evaluated
      subst result
      exact ⟨[], by simp, by simp, by simp⟩
  | cons expression tail ih =>
      simp only [evalExpressionNodes.go] at evaluated
      cases found : evalFieldExpression publicWords rows initial expression with
      | none => simp [found] at evaluated
      | some value =>
          simp only [found] at evaluated
          have tailCanonical : ∀ (index : Nat) (next : FieldExpression),
              tail[index]? = some next →
              next.CanonicalAt true ((initial ++ [value]).length + index) := by
            intro index next member
            have h := canonical (index + 1) next (by simpa using member)
            simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using h
          obtain ⟨suffix, resultEq, suffixLength, equations⟩ :=
            ih (initial ++ [value]) tailCanonical evaluated
          refine ⟨value :: suffix, ?_, by simp [suffixLength], ?_⟩
          · simpa [List.append_assoc] using resultEq
          · intro index next member
            cases index with
            | zero =>
                simp only [List.getElem?_cons_zero, Option.some.injEq] at member
                subst next
                have headCanonical := canonical 0 expression (by simp)
                simp only [Nat.add_zero] at headCanonical ⊢
                rw [resultEq, List.append_assoc,
                  expression_eval_append publicWords rows initial ([value] ++ suffix)
                    expression headCanonical, found]
                simp
            | succ index =>
                simpa [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
                  equations index next member

/-- Interpreter acceptance supplies all graph equations, not only a trace existential. -/
theorem evaluated_program_satisfies_each_node
    {publicWords rows values : List Nat} {program : ExpressionProgram}
    (canonical : program.Canonical true)
    (evaluated : evalExpressionNodes publicWords rows program.expressions = some values)
    {index : Nat} {expression : FieldExpression}
    (member : program.expressions[index]? = some expression) :
    values[index]? = evalFieldExpression publicWords rows values expression := by
  obtain ⟨_, _, _, equations⟩ :=
    eval_go_equations publicWords rows [] values program.expressions
      (by simpa using canonical.1) evaluated
  simpa using equations index expression member

theorem canonical_without_rows_allows_rows
    {expression : FieldExpression} {index : Nat}
    (canonical : expression.CanonicalAt false index) :
    expression.CanonicalAt true index := by
  cases expression <;> simp_all [FieldExpression.CanonicalAt]

theorem exact_csr_is_canonical_with_rows :
    ({ expressions := exactCsrExpressions, roots := [] } :
      ExpressionProgram).Canonical true := by
  constructor
  · intro index expression found
    apply canonical_without_rows_allows_rows
    exact hgv8rp03_csr_expression_program_is_canonical.1 index expression found
  · simp

/-- Kernel-checked projection of the actual pinned equation list, not descriptor labels. -/
theorem exact_transparent_balance_attempts :
    exactCsrAttempts[15672]? = some (attempt 15672 5 0 0 [(41528, 1)] 49) ∧
    exactCsrAttempts[15673]? = some (attempt 15673 5 1 0 [(41528, 1)] 50) ∧
    exactCsrAttempts[19262]? = some (attempt 19262 39 0 0 [(41528, 1)] 0) := by
  decide

theorem exact_transparent_balance_expression_nodes :
    exactCsrExpressions[0]? = some (.constant 0) ∧
    exactCsrExpressions[49]? = some (.publicWord 45) ∧
    exactCsrExpressions[50]? = some (.publicWord 46) := by
  decide

theorem exact_csr_one_expression_node :
    exactCsrExpressions[1]? = some (.constant 1) := by
  decide

theorem canonical_public_mapped_zero
    {publicWords : List Nat} {index : Nat}
    (canonical : CanonicalPublicWords publicWords)
    (zero : publicWords[index]?.map fieldNormalize = some 0) :
    publicWords[index]? = some 0 := by
  cases found : publicWords[index]? with
  | none => simp [found] at zero
  | some word =>
      have bound := canonical.2 word (List.mem_of_getElem? found)
      simp [found, fieldNormalize, Nat.mod_eq_of_lt bound] at zero
      simp [zero]

/--
Every raw accepted packed assignment has canonical zero transparent sign and
magnitude.  This uses only the exact program's successful interpreter and three
actual CSR equations; it assumes no typed decoding or semantic refinement receipt.
-/
theorem accepted_packed_transparent_value_balance_is_zero
    {publicWords packedWitness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packedWitness) :
    publicWords[45]? = some 0 ∧ publicWords[46]? = some 0 := by
  obtain ⟨values, evaluated, allAttempts⟩ := accepted.2.2.2
  have node0 := evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows
    evaluated exact_transparent_balance_expression_nodes.1
  have node45 := evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows
    evaluated exact_transparent_balance_expression_nodes.2.1
  have node46 := evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows
    evaluated exact_transparent_balance_expression_nodes.2.2
  have zeroValue : values[0]? = some 0 := by
    simpa [evalFieldExpression, fieldNormalize] using node0
  have signValue : values[49]? = publicWords[45]?.map fieldNormalize := by
    simpa [evalFieldExpression] using node45
  have magnitudeValue : values[50]? = publicWords[46]?.map fieldNormalize := by
    simpa [evalFieldExpression] using node46
  obtain ⟨signLeft, signTarget, signEval, signFound, signEq⟩ :=
    allAttempts _ (List.mem_of_getElem? exact_transparent_balance_attempts.1)
  obtain ⟨magnitudeLeft, magnitudeTarget, magnitudeEval, magnitudeFound, magnitudeEq⟩ :=
    allAttempts _ (List.mem_of_getElem? exact_transparent_balance_attempts.2.1)
  obtain ⟨zeroLeft, zeroTarget, zeroEval, zeroFound, zeroEq⟩ :=
    allAttempts _ (List.mem_of_getElem? exact_transparent_balance_attempts.2.2)
  change values[49]? = some signTarget at signFound
  change values[50]? = some magnitudeTarget at magnitudeFound
  change values[0]? = some zeroTarget at zeroFound
  have zeroTargetEq : zeroTarget = 0 := by simpa [zeroValue] using zeroFound.symm
  have signLeftEq : signLeft = zeroLeft := Option.some.inj (signEval.symm.trans zeroEval)
  have magnitudeLeftEq : magnitudeLeft = zeroLeft :=
    Option.some.inj (magnitudeEval.symm.trans zeroEval)
  have signTargetEq : signTarget = 0 := by omega
  have magnitudeTargetEq : magnitudeTarget = 0 := by omega
  constructor
  · apply canonical_public_mapped_zero accepted.1
    rw [← signValue, signFound, signTargetEq]
  · apply canonical_public_mapped_zero accepted.1
    rw [← magnitudeValue, magnitudeFound, magnitudeTargetEq]

/-- Identify source equations that directly force a private packed coordinate to zero. -/
def unconditionalZeroAttempt (entry : CsrExecutableAttempt) : Bool :=
  entry.targetRoot == 0 &&
    match entry.terms with
    | [(_, 1)] => true
    | _ => false

/-- There are 849 such equations in the exact source, including canonical padding. -/
theorem exact_unconditional_zero_attempt_count :
    (exactCsrAttempts.filter unconditionalZeroAttempt).length = 849 := by
  decide

/--
Every exact singleton-one/zero-target CSR equation forces the corresponding
canonical private word to zero.  This covers all 849 matching equations, without
assuming that the accepted witness came from the honest typed lowerer.
-/
theorem accepted_packed_unconditional_zero_coordinate
    {publicWords packedWitness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packedWitness)
    {entry : CsrExecutableAttempt} (member : entry ∈ exactCsrAttempts)
    {index : Nat} (terms : entry.terms = [(index, 1)])
    (target : entry.targetRoot = 0) :
    packedWitness[index]? = some 0 := by
  obtain ⟨values, evaluated, allAttempts⟩ := accepted.2.2.2
  have node0 := evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows
    evaluated exact_transparent_balance_expression_nodes.1
  have node1 := evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows
    evaluated exact_csr_one_expression_node
  have zeroValue : values[0]? = some 0 := by
    simpa [evalFieldExpression, fieldNormalize] using node0
  have oneValue : values[1]? = some 1 := by
    simpa [evalFieldExpression, fieldNormalize, fieldModulus] using node1
  obtain ⟨left, targetValue, leftEval, targetFound, equal⟩ := allAttempts entry member
  rw [terms] at leftEval
  rw [target, zeroValue] at targetFound
  have targetZero : targetValue = 0 := Option.some.inj targetFound.symm
  cases found : packedWitness[index]? with
  | none => simp [evalCsrTerms, oneValue, found] at leftEval
  | some word =>
      have bound := accepted.2.1.2 word (List.mem_of_getElem? found)
      have leftWord : word = left := by
        simpa [evalCsrTerms, oneValue, found, fieldAdd, fieldMul, fieldNormalize,
          Nat.mod_eq_of_lt bound] using leftEval
      have wordZero : word = 0 := by omega
      simp [wordZero]

theorem accepted_packed_transparent_private_coordinate_is_zero
    {publicWords packedWitness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packedWitness) :
    packedWitness[41528]? = some 0 := by
  exact accepted_packed_unconditional_zero_coordinate accepted
    (List.mem_of_getElem? exact_transparent_balance_attempts.2.2) rfl rfl

theorem canonical_boolean_of_mul_sub_one_zero
    {word : Nat} (bound : word < fieldModulus)
    (zero : fieldMul word (fieldSub word 1) = 0) :
    word = 0 ∨ word = 1 := by
  have prime : Nat.Prime fieldModulus := HegemonCrypto.SmallWood.goldilocks_prime
  have divides : fieldModulus ∣ word * (word + fieldModulus - 1) := by
    apply Nat.dvd_of_mod_eq_zero
    simpa [fieldMul, fieldSub, fieldNormalize, Nat.mul_mod,
      Nat.mod_eq_of_lt bound] using zero
  rcases prime.dvd_mul.mp divides with left | right
  · exact Or.inl (Nat.eq_zero_of_dvd_of_lt left bound)
  · by_cases wordZero : word = 0
    · exact Or.inl wordZero
    · have rewriteSub : word + fieldModulus - 1 = fieldModulus + (word - 1) := by omega
      rw [rewriteSub] at right
      have dividesPred : fieldModulus ∣ word - 1 := by
        simpa using Nat.dvd_sub right (dvd_refl fieldModulus)
      have predZero := Nat.eq_zero_of_dvd_of_lt dividesPred (by omega : word - 1 < fieldModulus)
      right
      omega

/-- A root of the actual Boolean polynomial enforces a canonical private Boolean word. -/
theorem accepted_boolean_witness_node
    {program : ExpressionProgram} {publicWords rows : List Nat}
    (canonical : program.Canonical true) (accepted : program.Accepts publicWords rows)
    {source minus root row word : Nat}
    (oneNode : program.expressions[1]? = some (.constant 1))
    (sourceNode : program.expressions[source]? = some (.witnessRow row))
    (minusNode : program.expressions[minus]? = some (.sub source 1))
    (rootNode : program.expressions[root]? = some (.mul source minus))
    (rootMember : root ∈ program.roots)
    (found : rows[row]? = some word) (bound : word < fieldModulus) :
    word = 0 ∨ word = 1 := by
  obtain ⟨values, evaluated, rootZero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      accepted rootMember
  have oneEquation := evaluated_program_satisfies_each_node canonical evaluated oneNode
  have sourceEquation := evaluated_program_satisfies_each_node canonical evaluated sourceNode
  have minusEquation := evaluated_program_satisfies_each_node canonical evaluated minusNode
  have rootEquation := evaluated_program_satisfies_each_node canonical evaluated rootNode
  have oneValue : values[1]? = some 1 := by
    simpa [evalFieldExpression, fieldNormalize, fieldModulus] using oneEquation
  have sourceValue : values[source]? = some word := by
    simpa [evalFieldExpression, found, fieldNormalize, Nat.mod_eq_of_lt bound] using sourceEquation
  have minusValue : values[minus]? = some (fieldSub word 1) := by
    simpa [evalFieldExpression, sourceValue, oneValue] using minusEquation
  have rootValue : values[root]? = some (fieldMul word (fieldSub word 1)) := by
    simpa [evalFieldExpression, sourceValue, minusValue] using rootEquation
  exact canonical_boolean_of_mul_sub_one_zero bound
    (Option.some.inj (rootValue.symm.trans rootZero))

structure BooleanWitnessRoot where
  row : Nat
  minusNode : Nat
  rootNode : Nat
deriving DecidableEq, Repr

/-- 64 Merkle directions, the dense top bit, three authorization flags, and one stable flag. -/
def exactBooleanWitnessRoots : List BooleanWitnessRoot :=
  (List.range 32).map (fun bit => ⟨2 + bit, 840 + 2 * bit, 841 + 2 * bit⟩) ++
  (List.range 32).map (fun bit => ⟨36 + bit, 917 + 2 * bit, 918 + 2 * bit⟩) ++
  [⟨251, 1202, 1203⟩, ⟨92, 1235, 1236⟩, ⟨93, 1237, 1238⟩,
    ⟨94, 1239, 1240⟩, ⟨658, 8129, 8130⟩]

def BooleanWitnessRoot.Valid (entry : BooleanWitnessRoot) : Prop :=
  entry.row < relationRowCount ∧
    exactNonlinearExpressions[124 + entry.row]? = some (.witnessRow entry.row) ∧
    exactNonlinearExpressions[entry.minusNode]? = some (.sub (124 + entry.row) 1) ∧
    exactNonlinearExpressions[entry.rootNode]? = some (.mul (124 + entry.row) entry.minusNode) ∧
    entry.rootNode ∈ exactNonlinearRoots

instance (entry : BooleanWitnessRoot) : Decidable entry.Valid := by
  unfold BooleanWitnessRoot.Valid
  infer_instance

theorem exact_boolean_witness_roots_valid :
    ∀ entry, entry ∈ exactBooleanWitnessRoots → entry.Valid := by
  have checked : exactBooleanWitnessRoots.all (fun entry => decide entry.Valid) = true := by
    decide
  simpa only [List.all_eq_true, decide_eq_true_eq] using checked

theorem exact_boolean_witness_root_count : exactBooleanWitnessRoots.length = 69 := by decide

/--
All 69 source-bound Boolean row families are Boolean in every one of the 64
packed lanes.  These are 4,416 private coordinate constraints, not just checks
of the honest witness or the first lane.
-/
theorem accepted_packed_boolean_witness_rows
    {publicWords packedWitness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packedWitness)
    {entry : BooleanWitnessRoot} (member : entry ∈ exactBooleanWitnessRoots)
    {lane : Nat} (laneBound : lane < packingFactor) :
    let word := packedWitness.getD (entry.row * packingFactor + lane) 0
    word = 0 ∨ word = 1 := by
  have valid := exact_boolean_witness_roots_valid entry member
  have rowBound := valid.1
  have coordinateBound : entry.row * packingFactor + lane < packedWitness.length := by
    rw [accepted.2.1.1]
    exact packed_witness_lane_index_is_in_exact_rectangle rowBound laneBound
  have packedFound : packedWitness[entry.row * packingFactor + lane]? =
      some (packedWitness.getD (entry.row * packingFactor + lane) 0) := by
    simp [List.getD, coordinateBound]
  have wordBound := accepted.2.1.2 _ (List.mem_of_getElem? packedFound)
  have rowFound : (packedWitnessLaneRows packedWitness lane)[entry.row]? =
      some (packedWitness.getD (entry.row * packingFactor + lane) 0) := by
    simp [packedWitnessLaneRows, rowBound]
  exact accepted_boolean_witness_node hgv8rp03_nonlinear_expression_program_is_canonical
    (accepted.2.2.1 lane laneBound) (by decide)
    valid.2.1 valid.2.2.1 valid.2.2.2.1 valid.2.2.2.2 rowFound wordBound

theorem canonical_eq_of_divides_sub_factor
    {word offset : Nat} (wordBound : word < fieldModulus)
    (offsetBound : offset < fieldModulus)
    (divides : fieldModulus ∣ word + fieldModulus - offset) : word = offset := by
  by_cases ordered : offset ≤ word
  · have rewriteSub : word + fieldModulus - offset = fieldModulus + (word - offset) := by omega
    rw [rewriteSub] at divides
    have dividesDifference : fieldModulus ∣ word - offset := by
      simpa using Nat.dvd_sub divides (dvd_refl fieldModulus)
    have differenceZero := Nat.eq_zero_of_dvd_of_lt dividesDifference
      (by omega : word - offset < fieldModulus)
    omega
  · have factorZero := Nat.eq_zero_of_dvd_of_lt divides
      (by omega : word + fieldModulus - offset < fieldModulus)
    omega

theorem canonical_radix_four_of_product_zero
    {word : Nat} (bound : word < fieldModulus)
    (zero : fieldMul (fieldSub word 3)
      (fieldMul (fieldSub word 2) (fieldMul word (fieldSub word 1))) = 0) :
    word < 4 := by
  have prime : Nat.Prime fieldModulus := HegemonCrypto.SmallWood.goldilocks_prime
  have divides : fieldModulus ∣
      (word + fieldModulus - 3) *
        ((word + fieldModulus - 2) * (word * (word + fieldModulus - 1))) := by
    apply Nat.dvd_of_mod_eq_zero
    simpa [fieldMul, fieldSub, fieldNormalize, Nat.mul_mod,
      Nat.mod_eq_of_lt bound] using zero
  rcases prime.dvd_mul.mp divides with three | rest
  · have eqThree := canonical_eq_of_divides_sub_factor bound (by decide : 3 < fieldModulus) three
    omega
  · rcases prime.dvd_mul.mp rest with two | rest
    · have eqTwo := canonical_eq_of_divides_sub_factor bound (by decide : 2 < fieldModulus) two
      omega
    · rcases prime.dvd_mul.mp rest with wordZero | one
      · have eqZero := Nat.eq_zero_of_dvd_of_lt wordZero bound
        omega
      · have eqOne := canonical_eq_of_divides_sub_factor bound (by decide : 1 < fieldModulus) one
        omega

def DenseRadixFourNodes (slot : Nat) : Prop :=
  exactNonlinearExpressions[371 + slot]? = some (.witnessRow (247 + slot)) ∧
    exactNonlinearExpressions[1178 + 6 * slot]? = some (.sub (371 + slot) 1) ∧
    exactNonlinearExpressions[1179 + 6 * slot]? = some (.sub (371 + slot) 2) ∧
    exactNonlinearExpressions[1180 + 6 * slot]? = some (.sub (371 + slot) 829) ∧
    exactNonlinearExpressions[1181 + 6 * slot]? =
      some (.mul (371 + slot) (1178 + 6 * slot)) ∧
    exactNonlinearExpressions[1182 + 6 * slot]? =
      some (.mul (1179 + 6 * slot) (1181 + 6 * slot)) ∧
    exactNonlinearExpressions[1183 + 6 * slot]? =
      some (.mul (1180 + 6 * slot) (1182 + 6 * slot)) ∧
    1183 + 6 * slot ∈ exactNonlinearRoots

instance (slot : Nat) : Decidable (DenseRadixFourNodes slot) := by
  unfold DenseRadixFourNodes
  infer_instance

theorem exact_dense_radix_four_nodes : ∀ slot, slot < 4 → DenseRadixFourNodes slot := by
  have checked : (List.range 4).all (fun slot => decide (DenseRadixFourNodes slot)) = true := by
    decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

theorem exact_nonlinear_small_constant_nodes :
    exactNonlinearExpressions[1]? = some (.constant 1) ∧
    exactNonlinearExpressions[2]? = some (.constant 2) ∧
    exactNonlinearExpressions[829]? = some (.constant 3) := by decide

/-- Every dense range digit is in {0,1,2,3}; all 256 packed coordinates are covered. -/
theorem accepted_packed_dense_radix_four_rows
    {publicWords packedWitness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packedWitness)
    {slot lane : Nat} (slotBound : slot < 4) (laneBound : lane < packingFactor) :
    packedWitness.getD ((247 + slot) * packingFactor + lane) 0 < 4 := by
  have rowBound : 247 + slot < relationRowCount := by
    simp only [relationRowCount]
    omega
  have coordinateBound : (247 + slot) * packingFactor + lane < packedWitness.length := by
    rw [accepted.2.1.1]
    exact packed_witness_lane_index_is_in_exact_rectangle rowBound laneBound
  have packedFound : packedWitness[(247 + slot) * packingFactor + lane]? =
      some (packedWitness.getD ((247 + slot) * packingFactor + lane) 0) := by
    simp [List.getD, coordinateBound]
  have wordBound := accepted.2.1.2 _ (List.mem_of_getElem? packedFound)
  have rowFound : (packedWitnessLaneRows packedWitness lane)[247 + slot]? =
      some (packedWitness.getD ((247 + slot) * packingFactor + lane) 0) := by
    simp [packedWitnessLaneRows, rowBound]
  obtain ⟨src, sub1, sub2, sub3, mul1, mul2, mul3, rootMember⟩ :=
    exact_dense_radix_four_nodes slot slotBound
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
    simpa [evalFieldExpression, fieldNormalize, fieldModulus] using
      equation exact_nonlinear_small_constant_nodes.1
  have twoValue : values[2]? = some 2 := by
    simpa [evalFieldExpression, fieldNormalize, fieldModulus] using
      equation exact_nonlinear_small_constant_nodes.2.1
  have threeValue : values[829]? = some 3 := by
    simpa [evalFieldExpression, fieldNormalize, fieldModulus] using
      equation exact_nonlinear_small_constant_nodes.2.2
  let word := packedWitness.getD ((247 + slot) * packingFactor + lane) 0
  have sourceValue : values[371 + slot]? = some word := by
    simpa only [evalFieldExpression, rowFound, Option.map_some,
      fieldNormalize, Nat.mod_eq_of_lt wordBound]
      using equation src
  have subOneValue : values[1178 + 6 * slot]? = some (fieldSub word 1) := by
    simpa [evalFieldExpression, sourceValue, oneValue] using equation sub1
  have subTwoValue : values[1179 + 6 * slot]? = some (fieldSub word 2) := by
    simpa [evalFieldExpression, sourceValue, twoValue] using equation sub2
  have subThreeValue : values[1180 + 6 * slot]? = some (fieldSub word 3) := by
    simpa [evalFieldExpression, sourceValue, threeValue] using equation sub3
  have mulOneValue : values[1181 + 6 * slot]? = some (fieldMul word (fieldSub word 1)) := by
    simpa [evalFieldExpression, sourceValue, subOneValue] using equation mul1
  have mulTwoValue : values[1182 + 6 * slot]? =
      some (fieldMul (fieldSub word 2) (fieldMul word (fieldSub word 1))) := by
    simpa [evalFieldExpression, subTwoValue, mulOneValue] using equation mul2
  have mulThreeValue : values[1183 + 6 * slot]? = some (fieldMul (fieldSub word 3)
      (fieldMul (fieldSub word 2) (fieldMul word (fieldSub word 1)))) := by
    simpa [evalFieldExpression, subThreeValue, mulTwoValue] using equation mul3
  exact canonical_radix_four_of_product_zero wordBound
    (Option.some.inj (mulThreeValue.symm.trans rootZero))

end HegemonCrypto.SmallWood.V8Smz9SemanticBinding

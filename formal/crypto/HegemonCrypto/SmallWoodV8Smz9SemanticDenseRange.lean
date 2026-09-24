import HegemonCrypto.Goldilocks
import HegemonCrypto.SmallWoodV8Smz9RelationProgramComponentsGenerated
import HegemonCrypto.SmallWoodV8Smz9SemanticBinding
import Mathlib.Algebra.BigOperators.Group.List.Basic

/-!
The seven exact HGV8RP03 dense value reconstructions.  The objective is to
derive natural-number bounds from accepted equations and the already proved
private digit constraints, without assuming the decoded values were in range.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

abbrev F := HegemonCrypto.SmallWood.Goldilocks

def radixFourSum (digits : Nat → Nat) (count : Nat) : Nat :=
  ((List.range count).map fun index => 4 ^ index * digits index).sum

theorem radix_four_sum_bound (digits : Nat → Nat) (count : Nat)
    (digitBounds : ∀ index, index < count → digits index < 4) :
    radixFourSum digits count < 4 ^ count := by
  induction count with
  | zero => simp [radixFourSum]
  | succ count ih =>
      have prior := ih (by intro index bound; exact digitBounds index (by omega))
      have digit := digitBounds count (by omega)
      have termBound := Nat.mul_le_mul_left (4 ^ count) (by omega : digits count ≤ 3)
      simp only [radixFourSum, List.range_succ, List.map_append, List.sum_append,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero,
        pow_succ] at prior ⊢
      omega

theorem dense_natural_reconstruction_bound
    (digits : Nat → Nat) (top : Nat)
    (digitBounds : ∀ index, index < 30 → digits index < 4)
    (topBound : top ≤ 1) :
    radixFourSum digits 30 + 2 ^ 60 * top < 2 ^ 61 := by
  have lowBound := radix_four_sum_bound digits 30 digitBounds
  have highBound := Nat.mul_le_mul_left (2 ^ 60) topBound
  norm_num at lowBound highBound ⊢
  omega

theorem canonical_nat_cast_injective
    {left right : Nat} (leftBound : left < fieldModulus)
    (rightBound : right < fieldModulus) (equal : (left : F) = (right : F)) :
    left = right := by
  have representatives := congrArg (fun value : F => value.val) equal
  change left % fieldModulus = right % fieldModulus at representatives
  simpa [Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] using representatives

theorem field_add_cast (left right : Nat) :
    ((fieldAdd left right : Nat) : F) = (left : F) + (right : F) := by
  exact HegemonCrypto.SmallWood.toGoldilocks_fieldAdd left right

theorem field_mul_cast (left right : Nat) :
    ((fieldMul left right : Nat) : F) = (left : F) * (right : F) := by
  exact HegemonCrypto.SmallWood.toGoldilocks_fieldMul left right

theorem field_sub_cast (left right : Nat) (bound : right ≤ left + fieldModulus) :
    ((fieldSub left right : Nat) : F) = (left : F) - (right : F) := by
  change (((left + fieldModulus - right) % fieldModulus : Nat) : ZMod fieldModulus) =
    (left : ZMod fieldModulus) - (right : ZMod fieldModulus)
  simp only [ZMod.natCast_mod, Nat.cast_sub bound, Nat.cast_add, ZMod.natCast_self, add_zero]

def csrFieldSum (values witness : List Nat) (terms : List (Nat × Nat)) : F :=
  (terms.map fun term => (values.getD term.2 0 : F) * (witness.getD term.1 0 : F)).sum

/-- Successful sparse evaluation is the exact linear combination in Goldilocks. -/
theorem eval_csr_terms_field_sum
    {values witness : List Nat} {terms : List (Nat × Nat)} {value : Nat}
    (evaluated : evalCsrTerms values witness terms = some value) :
    (value : F) = csrFieldSum values witness terms := by
  induction terms generalizing value with
  | nil =>
      simp only [evalCsrTerms, Option.some.injEq] at evaluated
      simp [← evaluated, csrFieldSum]
  | cons term rest ih =>
      rcases term with ⟨index, coefficient⟩
      cases coefficientFound : values[coefficient]? with
      | none => simp [evalCsrTerms, coefficientFound] at evaluated
      | some coefficientValue =>
          cases witnessFound : witness[index]? with
          | none => simp [evalCsrTerms, coefficientFound, witnessFound] at evaluated
          | some witnessValue =>
              cases restFound : evalCsrTerms values witness rest with
              | none => simp [evalCsrTerms, coefficientFound, witnessFound, restFound] at evaluated
              | some restValue =>
                  simp [evalCsrTerms, coefficientFound, witnessFound, restFound] at evaluated
                  rw [← evaluated, field_add_cast, field_mul_cast, ih restFound]
                  simp [csrFieldSum, List.getD_eq_getElem?_getD, coefficientFound, witnessFound]

def denseDigitAddress (value digit : Nat) : Nat := 15808 + 30 * value + digit
def denseTopAddress (value : Nat) : Nat := 16064 + value
def densePrivateAddress (value : Nat) : Nat := [0, 2176, 4352, 5120].getD value 0
def densePublicIndex (value : Nat) : Nat := if value = 4 then 44 else if value = 5 then 46 else 62

def denseNegativeTerms (value : Nat) : List (Nat × Nat) :=
  (List.range 30).map (fun digit => (denseDigitAddress value digit, 158 + digit)) ++
    [(denseTopAddress value, 189)]

def denseExpectedAttempt (value : Nat) : CsrExecutableAttempt :=
  attempt (15665 + value) 4 value 0
    ((if value < 4 then [(densePrivateAddress value, 1)] else []) ++ denseNegativeTerms value)
    (if value < 4 then 0 else 186 + value)

theorem exact_dense_reconstruction_attempts :
    ∀ value, value < 7 →
      exactCsrAttempts[15665 + value]? = some (denseExpectedAttempt value) := by
  have checked : (List.range 7).all (fun value =>
      decide (exactCsrAttempts[15665 + value]? = some (denseExpectedAttempt value))) = true := by
    decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

def densePowerRoot (power : Nat) : Nat := if power = 0 then 1 else 127 + power

def DensePowerNode (power : Nat) : Prop :=
  exactCsrExpressions[densePowerRoot power]? =
    some (if power = 0 then .constant 1 else if power = 1 then .constant 4
      else .mul 128 (densePowerRoot (power - 1))) ∧ 4 ^ power < fieldModulus

instance (power : Nat) : Decidable (DensePowerNode power) := by
  unfold DensePowerNode
  infer_instance

theorem exact_dense_power_nodes : ∀ power, power < 30 → DensePowerNode power := by
  have checked : (List.range 30).all (fun power => decide (DensePowerNode power)) = true := by
    decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

theorem exact_dense_negative_power_nodes :
    ∀ power, power < 30 →
      exactCsrExpressions[158 + power]? = some (.sub 0 (densePowerRoot power)) := by
  have checked : (List.range 30).all (fun power => decide
      (exactCsrExpressions[158 + power]? = some (.sub 0 (densePowerRoot power)))) = true := by
    decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

theorem exact_dense_top_nodes :
    exactCsrExpressions[188]? = some (.constant (2 ^ 60)) ∧
    exactCsrExpressions[189]? = some (.sub 0 188) := by decide

theorem exact_dense_public_target_nodes :
    ∀ value, 4 ≤ value → value < 7 →
      exactCsrExpressions[186 + value]? = some (.sub 0 (4 + densePublicIndex value)) ∧
      exactCsrExpressions[4 + densePublicIndex value]? = some (.publicWord (densePublicIndex value)) := by
  have checked : (List.range 7).all (fun value => decide (4 ≤ value →
      exactCsrExpressions[186 + value]? = some (.sub 0 (4 + densePublicIndex value)) ∧
      exactCsrExpressions[4 + densePublicIndex value]? = some (.publicWord (densePublicIndex value)))) = true := by
    decide
  intro value lower upper
  have h := (List.all_eq_true.mp checked) value (List.mem_range.mpr upper)
  exact (of_decide_eq_true h) lower

def denseNaturalValue (witness : List Nat) (value : Nat) : Nat :=
  radixFourSum (fun digit => witness.getD (denseDigitAddress value digit) 0) 30 +
    2 ^ 60 * witness.getD (denseTopAddress value) 0

theorem sum_neg_cast (values : List Nat) :
    (values.map fun (value : Nat) => -(value : F)).sum = -(values.sum : F) := by
  induction values with
  | nil => simp only [List.map_nil, List.sum_nil, Nat.cast_zero, neg_zero]
  | cons head tail ih =>
      simp only [List.map_cons, List.sum_cons, Nat.cast_add, ih, neg_add]

set_option maxHeartbeats 1000000 in
theorem dense_negative_terms_field_sum
    (values witness : List Nat) (value : Nat)
    (coefficients : ∀ digit, digit < 30 →
      (values.getD (158 + digit) 0 : F) = -((4 ^ digit : Nat) : F))
    (topCoefficient : (values.getD 189 0 : F) = -((2 ^ 60 : Nat) : F)) :
    csrFieldSum values witness (denseNegativeTerms value) = -(denseNaturalValue witness value : F) := by
  have digitMap :
      (List.range 30).map (fun digit =>
        (values.getD (158 + digit) 0 : F) *
          (witness.getD (denseDigitAddress value digit) 0 : F)) =
      ((List.range 30).map (fun digit =>
        4 ^ digit * witness.getD (denseDigitAddress value digit) 0)).map
          (fun (term : Nat) => -(term : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro digit member
    rw [coefficients digit (List.mem_range.mp member)]
    simp only [Function.comp_apply, Nat.cast_mul, neg_mul]
  unfold csrFieldSum denseNegativeTerms
  rw [List.map_append, List.sum_append, List.map_map, List.map_singleton, List.sum_singleton]
  change ((List.range 30).map (fun digit =>
    (values.getD (158 + digit) 0 : F) *
      (witness.getD (denseDigitAddress value digit) 0 : F))).sum +
    (values.getD 189 0 : F) * (witness.getD (denseTopAddress value) 0 : F) = _
  rw [digitMap, sum_neg_cast, topCoefficient]
  change -(radixFourSum (fun digit => witness.getD (denseDigitAddress value digit) 0) 30 : F) +
    -((2 ^ 60 : Nat) : F) * (witness.getD (denseTopAddress value) 0 : F) = _
  simp only [denseNaturalValue, Nat.cast_add, Nat.cast_mul, neg_mul, neg_add]

theorem accepted_csr_attempt_field_equality
    {values witness : List Nat} {entry : CsrExecutableAttempt}
    (accepted : entry.Accepts values witness) :
    csrFieldSum values witness entry.terms = (values.getD entry.targetRoot 0 : F) := by
  obtain ⟨left, target, evaluated, found, equal⟩ := accepted
  have result := eval_csr_terms_field_sum evaluated
  rw [equal] at result
  simpa [List.getD_eq_getElem?_getD, found] using result.symm

def CsrTraceEquations (publicWords values : List Nat) : Prop :=
  ∀ (index : Nat) (expression : FieldExpression),
    exactCsrExpressions[index]? = some expression →
      values[index]? = evalFieldExpression publicWords [] values expression

theorem csr_trace_zero_one_values
    {publicWords values : List Nat} (equations : CsrTraceEquations publicWords values) :
    values[0]? = some 0 ∧ values[1]? = some 1 := by
  constructor
  · simpa [evalFieldExpression, fieldNormalize] using
      equations 0 (.constant 0) (by decide)
  · simpa [evalFieldExpression, fieldNormalize, fieldModulus] using
      equations 1 (.constant 1) (by decide)

theorem dense_power_values
    {publicWords values : List Nat} (equations : CsrTraceEquations publicWords values) :
    ∀ power, power < 30 → values[densePowerRoot power]? = some (4 ^ power) := by
  intro power
  induction power using Nat.strong_induction_on with
  | h power ih =>
      intro bound
      have node := exact_dense_power_nodes power bound
      by_cases isZero : power = 0
      · subst power
        simpa [densePowerRoot] using (csr_trace_zero_one_values equations).2
      · by_cases isOne : power = 1
        · subst power
          simpa [densePowerRoot, evalFieldExpression, fieldNormalize, fieldModulus] using
            equations 128 (.constant 4) (by decide)
        · have prior := ih (power - 1) (by omega) (by omega)
          have fourValue : values[128]? = some 4 := by
            simpa [evalFieldExpression, fieldNormalize, fieldModulus] using
              equations 128 (.constant 4) (by decide)
          have current := equations (densePowerRoot power)
            (.mul 128 (densePowerRoot (power - 1)))
            (by simpa [isZero, isOne] using node.1)
          have product : 4 * 4 ^ (power - 1) = 4 ^ power := by
            rw [← pow_succ']
            congr 1
            omega
          simpa [evalFieldExpression, fourValue, prior, fieldMul, fieldNormalize,
            product, Nat.mod_eq_of_lt node.2] using current

theorem dense_negative_coefficient_values
    {publicWords values : List Nat} (equations : CsrTraceEquations publicWords values) :
    (∀ power, power < 30 →
      (values.getD (158 + power) 0 : F) = -((4 ^ power : Nat) : F)) ∧
      (values.getD 189 0 : F) = -((2 ^ 60 : Nat) : F) := by
  have zeroValue := (csr_trace_zero_one_values equations).1
  constructor
  · intro power bound
    have powerValue := dense_power_values equations power bound
    have found : values[158 + power]? = some (fieldSub 0 (4 ^ power)) := by
      simpa [evalFieldExpression, zeroValue, powerValue] using
        equations (158 + power) (.sub 0 (densePowerRoot power))
          (exact_dense_negative_power_nodes power bound)
    simp only [List.getD_eq_getElem?_getD, found, Option.getD_some]
    rw [field_sub_cast 0 (4 ^ power) (by have := (exact_dense_power_nodes power bound).2; omega)]
    simp
  · have topValue : values[188]? = some (2 ^ 60) := by
      simpa [evalFieldExpression, fieldNormalize, fieldModulus] using
        equations 188 (.constant (2 ^ 60)) exact_dense_top_nodes.1
    have found : values[189]? = some (fieldSub 0 (2 ^ 60)) := by
      simpa [evalFieldExpression, zeroValue, topValue] using
        equations 189 (.sub 0 188) exact_dense_top_nodes.2
    simp only [List.getD_eq_getElem?_getD, found, Option.getD_some]
    rw [field_sub_cast 0 (2 ^ 60) (by decide)]
    simp

theorem canonical_public_coordinate
    {publicWords : List Nat} (canonical : CanonicalPublicWords publicWords)
    {index : Nat} (bound : index < publicStatementWordCount) :
    publicWords[index]? = some (publicWords.getD index 0) ∧
      publicWords.getD index 0 < fieldModulus := by
  have indexBound : index < publicWords.length := by rw [canonical.1]; exact bound
  have found : publicWords[index]? = some (publicWords.getD index 0) := by
    simp [List.getD, indexBound]
  exact ⟨found, canonical.2 _ (List.mem_of_getElem? found)⟩

theorem canonical_packed_coordinate
    {witness : List Nat} (canonical : CanonicalPackedWitness witness)
    {index : Nat} (bound : index < packedWitnessWordCount) :
    witness[index]? = some (witness.getD index 0) ∧ witness.getD index 0 < fieldModulus := by
  have indexBound : index < witness.length := by rw [canonical.1]; exact bound
  have found : witness[index]? = some (witness.getD index 0) := by
    simp [List.getD, indexBound]
  exact ⟨found, canonical.2 _ (List.mem_of_getElem? found)⟩

theorem dense_public_index_bound (value : Nat) : densePublicIndex value < publicStatementWordCount := by
  unfold densePublicIndex
  split_ifs <;> decide

theorem dense_public_target_value
    {publicWords values : List Nat} (equations : CsrTraceEquations publicWords values)
    (canonical : CanonicalPublicWords publicWords)
    {value : Nat} (lower : 4 ≤ value) (upper : value < 7) :
    (values.getD (186 + value) 0 : F) = -((publicWords.getD (densePublicIndex value) 0 : Nat) : F) := by
  have zeroValue := (csr_trace_zero_one_values equations).1
  have coordinate := canonical_public_coordinate canonical (dense_public_index_bound value)
  have nodes := exact_dense_public_target_nodes value lower upper
  have publicValue : values[4 + densePublicIndex value]? =
      some (publicWords.getD (densePublicIndex value) 0) := by
    simpa only [evalFieldExpression, coordinate.1, Option.map_some, fieldNormalize,
      Nat.mod_eq_of_lt coordinate.2] using
      equations _ (.publicWord (densePublicIndex value)) nodes.2
  have found : values[186 + value]? =
      some (fieldSub 0 (publicWords.getD (densePublicIndex value) 0)) := by
    simpa [evalFieldExpression, zeroValue, publicValue] using equations _ _ nodes.1
  have getValue : values.getD (186 + value) 0 =
      fieldSub 0 (publicWords.getD (densePublicIndex value) 0) := by
    simp only [List.getD_eq_getElem?_getD, found, Option.getD_some]
  rw [getValue, field_sub_cast 0 _ (by have := coordinate.2; omega)]
  simp

theorem accepted_dense_digit_bound
    {publicWords witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords witness)
    {value digit : Nat} (valueBound : value < 7) (digitBound : digit < 30) :
    witness.getD (denseDigitAddress value digit) 0 < 4 := by
  have totalBound : 30 * value + digit < 210 := by omega
  have rowBound : (30 * value + digit) / 64 < 4 := by omega
  have laneBound : (30 * value + digit) % 64 < packingFactor := by
    simp only [packingFactor]
    omega
  have result := accepted_packed_dense_radix_four_rows accepted rowBound laneBound
  have address :
      (247 + (30 * value + digit) / 64) * packingFactor + (30 * value + digit) % 64 =
        denseDigitAddress value digit := by
    simp only [packingFactor, denseDigitAddress]
    omega
  simpa only [address] using result

theorem accepted_dense_top_bound
    {publicWords witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords witness)
    {value : Nat} (valueBound : value < 7) :
    witness.getD (denseTopAddress value) 0 ≤ 1 := by
  have laneBound : value < packingFactor := by simp only [packingFactor]; omega
  have result := accepted_packed_boolean_witness_rows accepted
    (entry := ⟨251, 1202, 1203⟩) (by decide) laneBound
  simp only [packingFactor] at result
  change witness.getD (denseTopAddress value) 0 = 0 ∨
    witness.getD (denseTopAddress value) 0 = 1 at result
  omega

theorem accepted_dense_natural_reconstruction_bound
    {publicWords witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords witness)
    {value : Nat} (valueBound : value < 7) :
    denseNaturalValue witness value < 2 ^ 61 := by
  exact dense_natural_reconstruction_bound _ _
    (fun digit digitBound => accepted_dense_digit_bound accepted valueBound digitBound)
    (accepted_dense_top_bound accepted valueBound)

def denseSourceValue (publicWords witness : List Nat) (value : Nat) : Nat :=
  if value < 4 then witness.getD (densePrivateAddress value) 0
  else publicWords.getD (densePublicIndex value) 0

theorem dense_private_address_bound :
    ∀ value, value < 4 → densePrivateAddress value < packedWitnessWordCount := by
  have checked : (List.range 4).all (fun value =>
      decide (densePrivateAddress value < packedWitnessWordCount)) = true := by decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

theorem accepted_dense_source_canonical
    {publicWords witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords witness)
    (value : Nat) : denseSourceValue publicWords witness value < fieldModulus := by
  unfold denseSourceValue
  split_ifs with privateValue
  · exact (canonical_packed_coordinate accepted.2.1
      (dense_private_address_bound value privateValue)).2
  · exact (canonical_public_coordinate accepted.1 (dense_public_index_bound value)).2

theorem csr_field_sum_cons (values witness : List Nat) (index coefficient : Nat)
    (rest : List (Nat × Nat)) :
    csrFieldSum values witness ((index, coefficient) :: rest) =
      (values.getD coefficient 0 : F) * (witness.getD index 0 : F) +
        csrFieldSum values witness rest := by rfl

/-- The seven exact signed CSR equations give source/reconstruction equality in the field. -/
theorem accepted_dense_field_reconstruction
    {publicWords witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords witness)
    {value : Nat} (valueBound : value < 7) :
    (denseSourceValue publicWords witness value : F) = (denseNaturalValue witness value : F) := by
  obtain ⟨values, evaluated, allAttempts⟩ := accepted.2.2.2
  have equations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows evaluated found
  have coefficients := dense_negative_coefficient_values equations
  have negativeSum := dense_negative_terms_field_sum values witness value coefficients.1 coefficients.2
  have attemptAccepted := allAttempts _
    (List.mem_of_getElem? (exact_dense_reconstruction_attempts value valueBound))
  have fieldEquation := accepted_csr_attempt_field_equality attemptAccepted
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  by_cases privateValue : value < 4
  · simp only [denseExpectedAttempt, attempt, if_pos privateValue,
      List.cons_append, List.nil_append] at fieldEquation
    rw [csr_field_sum_cons, oneValue, one_mul, negativeSum, zeroValue] at fieldEquation
    have difference : (witness.getD (densePrivateAddress value) 0 : F) -
        (denseNaturalValue witness value : F) = 0 := by
      simpa only [sub_eq_add_neg] using fieldEquation
    simpa only [denseSourceValue, if_pos privateValue] using sub_eq_zero.mp difference
  · simp only [denseExpectedAttempt, attempt, if_neg privateValue, List.nil_append] at fieldEquation
    rw [negativeSum, dense_public_target_value equations accepted.1 (by omega) valueBound] at fieldEquation
    simpa only [denseSourceValue, if_neg privateValue] using (neg_injective fieldEquation).symm

/-- No wraparound: accepted field reconstruction equals the ordinary natural reconstruction. -/
theorem accepted_dense_natural_reconstruction
    {publicWords witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords witness)
    {value : Nat} (valueBound : value < 7) :
    denseSourceValue publicWords witness value = denseNaturalValue witness value := by
  have naturalBound := accepted_dense_natural_reconstruction_bound accepted valueBound
  have modulusBound : 2 ^ 61 < fieldModulus := by decide
  exact canonical_nat_cast_injective (accepted_dense_source_canonical accepted value)
    (by omega) (accepted_dense_field_reconstruction accepted valueBound)

/-- All seven actual source values are less than 2^61 for every accepted packed assignment. -/
theorem accepted_dense_source_value_bound
    {publicWords witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords witness)
    {value : Nat} (valueBound : value < 7) :
    denseSourceValue publicWords witness value < 2 ^ 61 := by
  rw [accepted_dense_natural_reconstruction accepted valueBound]
  exact accepted_dense_natural_reconstruction_bound accepted valueBound

/-- Explicit caller-facing source coordinates; no typed decoder/range premise is required. -/
theorem accepted_packed_seven_value_bounds
    {publicWords witness : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords witness) :
    witness.getD 0 0 < 2 ^ 61 ∧ witness.getD 2176 0 < 2 ^ 61 ∧
      witness.getD 4352 0 < 2 ^ 61 ∧ witness.getD 5120 0 < 2 ^ 61 ∧
      publicWords.getD 44 0 < 2 ^ 61 ∧ publicWords.getD 46 0 < 2 ^ 61 ∧
      publicWords.getD 62 0 < 2 ^ 61 := by
  have all := fun value bound => accepted_dense_source_value_bound accepted (value := value) bound
  exact ⟨by simpa [denseSourceValue, densePrivateAddress] using all 0 (by decide),
    by simpa [denseSourceValue, densePrivateAddress] using all 1 (by decide),
    by simpa [denseSourceValue, densePrivateAddress] using all 2 (by decide),
    by simpa [denseSourceValue, densePrivateAddress] using all 3 (by decide),
    by simpa [denseSourceValue, densePublicIndex] using all 4 (by decide),
    by simpa [denseSourceValue, densePublicIndex] using all 5 (by decide),
    by simpa [denseSourceValue, densePublicIndex] using all 6 (by decide)⟩

end HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

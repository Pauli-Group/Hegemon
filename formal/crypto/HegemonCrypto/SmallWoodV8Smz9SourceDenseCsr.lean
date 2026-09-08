import HegemonCrypto.SmallWoodV8Smz9SourceDenseRoots

/-!
Forward field interpretation of the exact seven dense CSR attempts. The
coefficient DAG is interpreted directly: no coefficient/evaluator equation
is a premise. The private raw-source difference remains explicit until the
assignment constructor supplies those four raw rows.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
  (fieldAt fieldAt_eq expressionField expressionField_congr_prior)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

noncomputable section

def actualCsrCoefficients (pub : Nat → F) : Nat → F :=
  fieldAt exactCsrExpressions pub (fun _ => 0)

theorem actual_csr_node_field_equation (pub : Nat → F) {node : Nat}
    {expression : FieldExpression}
    (found : exactCsrExpressions[node]? = some expression) :
    actualCsrCoefficients pub node =
      expressionField pub (fun _ => 0) (actualCsrCoefficients pub) expression := by
  unfold actualCsrCoefficients
  rw [fieldAt_eq, found]
  apply expressionField_congr_prior pub (fun _ => 0) _ _ node expression
    (exact_csr_is_canonical_with_rows.1 node expression found)
  intro i bound
  simp only [if_pos bound]

theorem actual_csr_zero_one (pub : Nat → F) :
    actualCsrCoefficients pub 0 = 0 ∧ actualCsrCoefficients pub 1 = 1 := by
  constructor
  · simpa only [expressionField, Nat.cast_zero] using
      actual_csr_node_field_equation pub exact_transparent_balance_expression_nodes.1
  · simpa only [expressionField, Nat.cast_one] using
      actual_csr_node_field_equation pub exact_csr_one_expression_node

theorem actual_dense_power_coefficient (pub : Nat → F) :
    ∀ power, power < 30 →
      actualCsrCoefficients pub (densePowerRoot power) = ((4 ^ power : Nat) : F) := by
  intro power
  induction power using Nat.strong_induction_on with
  | h power ih =>
      intro bound
      have node := exact_dense_power_nodes power bound
      by_cases isZero : power = 0
      · subst power
        exact (actual_csr_zero_one pub).2
      · by_cases isOne : power = 1
        · subst power
          have found : exactCsrExpressions[128]? = some (.constant 4) := by
            exact node.1
          exact actual_csr_node_field_equation pub found
        · have previous := ih (power - 1) (by omega) (by omega)
          have fourNode : exactCsrExpressions[128]? = some (.constant 4) := by
            exact (exact_dense_power_nodes 1 (by decide)).1
          have four := actual_csr_node_field_equation pub fourNode
          have current := actual_csr_node_field_equation pub
            (by simpa only [if_neg isZero, if_neg isOne] using node.1)
          simp only [expressionField] at four current
          rw [four, previous] at current
          have product : 4 * 4 ^ (power - 1) = 4 ^ power := by
            rw [← pow_succ']
            congr 1
            omega
          simpa only [← Nat.cast_mul, product] using current

theorem actual_dense_negative_coefficients (pub : Nat → F) :
    (∀ power, power < 30 →
      actualCsrCoefficients pub (158 + power) = -((4 ^ power : Nat) : F)) ∧
    actualCsrCoefficients pub 189 = -((2 ^ 60 : Nat) : F) := by
  constructor
  · intro power bound
    have equation := actual_csr_node_field_equation pub (exact_dense_negative_power_nodes power bound)
    simpa only [expressionField, (actual_csr_zero_one pub).1,
      actual_dense_power_coefficient pub power bound, zero_sub] using equation
  · have top := actual_csr_node_field_equation pub exact_dense_top_nodes.1
    have negative := actual_csr_node_field_equation pub exact_dense_top_nodes.2
    simpa only [expressionField, top, (actual_csr_zero_one pub).1, zero_sub] using negative

theorem actual_dense_public_target (pub : Nat → F) {value : Nat}
    (lower : 4 ≤ value) (upper : value < 7) :
    actualCsrCoefficients pub (186 + value) = -pub (densePublicIndex value) := by
  have nodes := exact_dense_public_target_nodes value lower upper
  have coordinate := actual_csr_node_field_equation pub nodes.2
  have target := actual_csr_node_field_equation pub nodes.1
  simpa only [expressionField, coordinate, (actual_csr_zero_one pub).1, zero_sub] using target

def actualCsrTerms (pub : Nat → F) (witness : List Nat) (terms : List (Nat × Nat)) : F :=
  (terms.map fun term => actualCsrCoefficients pub term.2 * (witness.getD term.1 0 : F)).sum

def actualCsrResidual (pub : Nat → F) (witness : List Nat) (entry : CsrExecutableAttempt) : F :=
  actualCsrTerms pub witness entry.terms - actualCsrCoefficients pub entry.targetRoot

theorem actual_csr_terms_cons (pub : Nat → F) (witness : List Nat)
    (index coefficient : Nat) (rest : List (Nat × Nat)) :
    actualCsrTerms pub witness ((index, coefficient) :: rest) =
      actualCsrCoefficients pub coefficient * (witness.getD index 0 : F) +
        actualCsrTerms pub witness rest := by rfl

theorem actual_dense_negative_terms (pub : Nat → F) (witness : List Nat) (value : Nat) :
    actualCsrTerms pub witness (denseNegativeTerms value) =
      -(denseNaturalValue witness value : F) := by
  have coefficients := actual_dense_negative_coefficients pub
  have digitMap :
      (List.range 30).map (fun digit =>
        actualCsrCoefficients pub (158 + digit) *
          (witness.getD (denseDigitAddress value digit) 0 : F)) =
      ((List.range 30).map (fun digit =>
        4 ^ digit * witness.getD (denseDigitAddress value digit) 0)).map
          (fun (term : Nat) => -(term : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro digit member
    rw [coefficients.1 digit (List.mem_range.mp member)]
    simp only [Function.comp_apply, Nat.cast_mul, neg_mul]
  unfold actualCsrTerms denseNegativeTerms
  rw [List.map_append, List.sum_append, List.map_map, List.map_singleton, List.sum_singleton]
  change ((List.range 30).map (fun digit =>
    actualCsrCoefficients pub (158 + digit) *
      (witness.getD (denseDigitAddress value digit) 0 : F))).sum +
    actualCsrCoefficients pub 189 * (witness.getD (denseTopAddress value) 0 : F) = _
  rw [digitMap, sum_neg_cast, coefficients.2]
  change -(radixFourSum (fun digit => witness.getD (denseDigitAddress value digit) 0) 30 : F) +
    -((2 ^ 60 : Nat) : F) * (witness.getD (denseTopAddress value) 0 : F) = _
  simp only [denseNaturalValue, Nat.cast_add, Nat.cast_mul, neg_mul, neg_add]

/-- The exact generated attempt's residual; private source cells remain explicit. -/
theorem actual_dense_expected_residual (pub : Nat → F) (witness : List Nat)
    (value : Nat) (valueBound : value < 7) :
    actualCsrResidual pub witness (denseExpectedAttempt value) =
      (if value < 4 then (witness.getD (densePrivateAddress value) 0 : F)
        else pub (densePublicIndex value)) - (denseNaturalValue witness value : F) := by
  unfold actualCsrResidual denseExpectedAttempt
  simp only [attempt]
  by_cases privateValue : value < 4
  · simp only [if_pos privateValue, List.cons_append, List.nil_append]
    rw [actual_csr_terms_cons, (actual_csr_zero_one pub).2, one_mul,
      actual_dense_negative_terms, (actual_csr_zero_one pub).1]
    ring
  · simp only [if_neg privateValue, List.nil_append]
    rw [actual_dense_negative_terms, actual_dense_public_target pub (by omega) valueBound]
    ring

theorem source_dense_embedded_reconstruction (before after : List Nat)
    (values : SourceValues) (prefixLength : before.length = 15808) (value : Fin 7) :
    denseNaturalValue (embedSourceDense before after values) value.val = values value := by
  have digitValues :
      radixFourSum (fun digit =>
        (embedSourceDense before after values).getD (denseDigitAddress value.val digit) 0) 30 =
        radixFourSum (sourceDigit (values value)) 30 := by
    unfold radixFourSum
    congr 1
    apply List.map_congr_left
    intro digit member
    have small : digit < 30 := List.mem_range.mp member
    dsimp only
    rw [show digit = (⟨digit, small⟩ : Fin 30).val from rfl,
      source_dense_global_digit_address before after values prefixLength value ⟨digit, small⟩]
  unfold denseNaturalValue
  rw [digitValues, source_dense_global_top_address before after values prefixLength value]
  have result := source_radix_reconstruction (values value) 30
  norm_num only [Nat.reducePow] at result ⊢
  exact result

/-- All seven actual list entries, interpreted with their actual coefficient DAG. -/
theorem source_dense_actual_csr_residual (before after : List Nat) (values : SourceValues)
    (prefixLength : before.length = 15808) (pub : Nat → F) (value : Fin 7) :
    (exactCsrAttempts[15665 + value.val]?).map
        (actualCsrResidual pub (embedSourceDense before after values)) =
      some ((if value.val < 4 then
          ((embedSourceDense before after values).getD (densePrivateAddress value.val) 0 : F)
        else pub (densePublicIndex value.val)) - (values value : F)) := by
  rw [exact_dense_reconstruction_attempts value.val value.isLt]
  simp only [Option.map_some]
  rw [actual_dense_expected_residual pub _ value.val value.isLt,
    source_dense_embedded_reconstruction before after values prefixLength value]

theorem typed_source_public_value (statement : V8PublicStatement) (witness : V8Witness)
    (value : Fin 7) (lower : 4 ≤ value.val) :
    typedSourceValues statement witness value =
      (encodePublicStatement statement).getD (densePublicIndex value.val) 0 := by
  fin_cases value <;> norm_num at lower <;> rfl

/-- Precisely the three public equations; no private raw-prefix binding is assumed. -/
theorem typed_source_dense_public_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (before after : List Nat) (prefixLength : before.length = 15808)
    (value : Fin 7) (lower : 4 ≤ value.val) :
    (exactCsrAttempts[15665 + value.val]?).map
        (actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (embedSourceDense before after (typedSourceValues statement witness))) = some 0 := by
  rw [source_dense_actual_csr_residual before after (typedSourceValues statement witness)
    prefixLength _ value]
  rw [if_neg (by omega), typed_source_public_value statement witness value lower]
  simp only [sub_self]


end
end HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr

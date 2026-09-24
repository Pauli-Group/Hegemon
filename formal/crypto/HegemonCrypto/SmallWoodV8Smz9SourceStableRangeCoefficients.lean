import HegemonCrypto.SmallWoodV8Smz9SourceDenseCsr
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabledCore

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRangeCoefficients

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

/- The actual coefficient DAG, independent of CsrTraceEquations or acceptance. -/
theorem actual_stable_odd_coefficient (pub : Nat → F) {digit : Nat}
    (bound : digit < 31) :
    actualCsrCoefficients pub (stableOddCoefficient digit) =
      -((4 ^ digit : Nat) : F) := by
  by_cases small : digit < 30
  · simpa only [stableOddCoefficient, if_pos small] using
      (actual_dense_negative_coefficients pub).1 digit small
  · have digitEq : digit = 30 := by omega
    subst digit
    have constants := actual_csr_zero_one pub
    have four := actual_csr_node_field_equation pub
      (show exactCsrExpressions[128]? = some (.constant 4) by decide)
    have prior : actualCsrCoefficients pub 156 = ((4^29 : Nat) : F) :=
      actual_dense_power_coefficient pub 29 (by decide)
    have current := actual_csr_node_field_equation pub
      (show exactCsrExpressions[157]? = some (.mul 128 156) by decide)
    simp only [expressionField] at four current
    rw [four, prior] at current
    have product : 4 * 4 ^ 29 = 4 ^ 30 := by decide
    have powerValue : actualCsrCoefficients pub 157 = ((4 ^ 30 : Nat) : F) := by
      simpa only [← Nat.cast_mul, product] using current
    have negative := actual_csr_node_field_equation pub
      (show exactCsrExpressions[402]? = some (.sub 0 157) by decide)
    simpa only [stableOddCoefficient, Nat.lt_irrefl, if_false, expressionField,
      constants.1, powerValue, zero_sub] using negative

theorem actual_stable_odd_top_coefficient (pub : Nat → F)
    (spec : StableOddRange) (valid : spec.Valid) :
    actualCsrCoefficients pub (stableOddTopNegativeRoot spec) =
      -((4 ^ spec.digits : Nat) : F) := by
  have constants := actual_csr_zero_one pub
  have powerValue := actual_csr_node_field_equation pub valid.2.2.2.2.2.1
  have negative := actual_csr_node_field_equation pub valid.2.2.2.2.2.2.1
  simpa only [expressionField, constants.1, powerValue, zero_sub] using negative

theorem actual_stable_odd_public_target (pub : Nat → F)
    (spec : StableOddRange) (valid : spec.Valid)
    (publicCase : spec.isPublic = true) :
    actualCsrCoefficients pub spec.targetRoot = -pub spec.sourceIndex := by
  have nodes : exactCsrExpressions[spec.targetRoot]? = some (.sub 0 (4 + spec.sourceIndex)) ∧
      exactCsrExpressions[4 + spec.sourceIndex]? = some (.publicWord spec.sourceIndex) := by
    simpa only [publicCase, if_true] using valid.2.2.2.2.2.2.2
  have coordinate := actual_csr_node_field_equation pub nodes.2
  have target := actual_csr_node_field_equation pub nodes.1
  simpa only [expressionField, coordinate, (actual_csr_zero_one pub).1, zero_sub] using target

theorem actual_stable_even_public_target (pub : Nat → F)
    (spec : StableEvenRange) (valid : spec.Valid)
    (publicCase : spec.isPublic = true) :
    actualCsrCoefficients pub spec.targetRoot = -pub spec.sourceIndex := by
  have nodes : exactCsrExpressions[spec.targetRoot]? = some (.sub 0 (4 + spec.sourceIndex)) ∧
      exactCsrExpressions[4 + spec.sourceIndex]? = some (.publicWord spec.sourceIndex) := by
    simpa only [publicCase, if_true] using valid.2.2.2.2
  have coordinate := actual_csr_node_field_equation pub nodes.2
  have target := actual_csr_node_field_equation pub nodes.1
  simpa only [expressionField, coordinate, (actual_csr_zero_one pub).1, zero_sub] using target

theorem actual_stable_even_negative_terms (pub : Nat → F) (witness : List Nat)
    (spec : StableEvenRange) (valid : spec.Valid) :
    actualCsrTerms pub witness (stableEvenNegativeTerms spec) =
      -(stableEvenNatural witness spec : F) := by
  have coefficients := actual_dense_negative_coefficients pub
  have digitMap :
      (List.range spec.digits).map (fun digit =>
        actualCsrCoefficients pub (158 + digit) *
          (witness.getD (42432 + spec.start + digit) 0 : F)) =
      ((List.range spec.digits).map (fun digit =>
        4 ^ digit * witness.getD (42432 + spec.start + digit) 0)).map
          (fun term : Nat => -(term : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro digit member
    have bound : digit < 30 := by
      have := List.mem_range.mp member
      exact lt_trans this valid.1
    rw [coefficients.1 digit bound]
    simp only [Function.comp_apply, Nat.cast_mul, neg_mul]
  unfold actualCsrTerms stableEvenNegativeTerms
  rw [List.map_map]
  change ((List.range spec.digits).map (fun digit =>
    actualCsrCoefficients pub (158+digit)*(witness.getD (42432+spec.start+digit) 0 : F))).sum = _
  rw [digitMap, sum_neg_cast]
  rfl

theorem actual_stable_odd_negative_terms (pub : Nat → F) (witness : List Nat)
    (spec : StableOddRange) (valid : spec.Valid) :
    actualCsrTerms pub witness (stableOddNegativeTerms spec) =
      -(stableOddNatural witness spec : F) := by
  have digitMap :
      (List.range spec.digits).map (fun digit =>
        actualCsrCoefficients pub (stableOddCoefficient digit) *
          (witness.getD (42432 + spec.start + digit) 0 : F)) =
      ((List.range spec.digits).map (fun digit =>
        4 ^ digit * witness.getD (42432 + spec.start + digit) 0)).map
          (fun term : Nat => -(term : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro digit member
    have bound : digit < 31 := by
      have := List.mem_range.mp member
      rcases valid.1 with width | width <;> omega
    rw [actual_stable_odd_coefficient pub bound]
    simp only [Function.comp_apply, Nat.cast_mul, neg_mul]
  unfold actualCsrTerms stableOddNegativeTerms
  rw [List.map_append, List.sum_append, List.map_map, List.map_singleton,
    List.sum_singleton]
  change ((List.range spec.digits).map (fun digit =>
    actualCsrCoefficients pub (stableOddCoefficient digit)*(witness.getD (42432+spec.start+digit) 0 : F))).sum +
    actualCsrCoefficients pub (stableOddTopNegativeRoot spec)*(witness.getD (42112+spec.topLane) 0 : F) = _
  rw [digitMap, sum_neg_cast,actual_stable_odd_top_coefficient pub spec valid]
  change -(radixFourSum (fun digit =>
      witness.getD (42432 + spec.start + digit) 0) spec.digits : F) +
    -((4 ^ spec.digits : Nat) : F) *
      (witness.getD (42112 + spec.topLane) 0 : F) = _
  simp only [stableOddNatural,V8Smz9SemanticDecoder.packedWord, Nat.cast_add, Nat.cast_mul, neg_mul, neg_add]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableRangeCoefficients

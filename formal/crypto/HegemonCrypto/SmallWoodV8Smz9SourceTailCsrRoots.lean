import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrReadbacks

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailCsrRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

theorem actual_tail_negative_one_coefficient (pub : Nat → F) :
    actualCsrCoefficients pub 3 = -1 := by
  have equation := actual_csr_node_field_equation pub
    (show exactCsrExpressions[3]? = some (.constant 18446744069414584320) by decide)
  have negative : (18446744069414584320 : F) = -1 := by
    change (18446744069414584320 : ZMod 18446744069414584321) = -1
    reduce_mod_char
  change actualCsrCoefficients pub 3 = (18446744069414584320 : F) at equation
  exact equation.trans negative

theorem actual_compatibility_target_coefficient (pub : Nat → F) (index : Fin 18) :
    actualCsrCoefficients pub (67 + index.val) = pub (63 + index.val) := by
  have found : ∀ i : Fin 18,
      exactCsrExpressions[67 + i.val]? = some (.publicWord (63 + i.val)) := by decide
  exact actual_csr_node_field_equation pub (found index)

/-- Each equation uses the actual coefficient DAG and exact original constructor. -/
theorem full_candidate_expected_tail_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (family : TailCsrFamily) (index : Fin family.count) :
    actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
      (fullTypedSourceCandidate statement witness) (expectedTailCsrAttempt family index.val) = 0 := by
  let pub : Nat → F := fun slot => ((encodePublicStatement statement).getD slot 0 : F)
  have constants := actual_csr_zero_one pub
  have negative := actual_tail_negative_one_coefficient pub
  change actualCsrResidual pub _ _ = 0
  cases family <;>
    simp only [expectedTailCsrAttempt, attempt, actualCsrResidual, actualCsrTerms,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, constants.1,constants.2,
      negative, one_mul, add_zero, sub_zero]
  · rw [actual_compatibility_target_coefficient pub index]
    have copy := congrArg (fun word : Nat => (word : F))
      (full_candidate_parent_public_readback statement witness index)
    exact sub_eq_zero.mpr copy
  · exact full_source_padding_field_zero statement witness index
  · rw [full_boolean_config_field_copy statement witness index]
    ring
  · exact full_boolean_padding_field_zero statement witness index
  · exact sub_eq_zero.mpr (full_role_padding_unit_field statement witness index)
  · exact full_role_padding_limbs_field statement witness index
  · exact full_role_padding_selector_field statement witness index
  · exact sub_eq_zero.mpr (full_role_padding_inverse_field statement witness index)
  · exact full_range_padding_field_zero statement witness index
  · exact full_multiplication_padding_field_zero statement witness index
  · exact full_numeric_padding_field_zero statement witness index

theorem full_candidate_actual_tail_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (family : TailCsrFamily) (index : Fin family.count) :
    (exactCsrAttempts[family.start + index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  rw [actual_tail_csr_entry, Option.map_some, full_candidate_expected_tail_csr_zero]

/-- Every one of the exact 496 distinct approved global indices, without semantic premises. -/
theorem full_candidate_all_selected_tail_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (global : Nat) (selected : global ∈ selectedTailCsrIndices) :
    (exactCsrAttempts[global]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  obtain ⟨family,_,member⟩ := List.mem_flatMap.mp selected
  obtain ⟨index,bound,equal⟩ := List.mem_map.mp member
  rw [← equal]
  exact full_candidate_actual_tail_csr_zero statement witness family ⟨index,List.mem_range.mp bound⟩

/-- Explicit count plus every actual result; no padded count or omitted Option result. -/
theorem full_candidate_exact_496_tail_csr_results (statement : V8PublicStatement) (witness : V8Witness) :
    selectedTailCsrIndices.length = 496 ∧ selectedTailCsrIndices.Nodup ∧
    (selectedTailCsrIndices.map fun global =>
      (exactCsrAttempts[global]?).map
        (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
          (fullTypedSourceCandidate statement witness))) = List.replicate 496 (some 0) := by
  refine ⟨selected_tail_csr_exact_count,selected_tail_csr_indices_distinct,?_⟩
  have equal := List.map_congr_left (fun global member =>
    full_candidate_all_selected_tail_csr_zero statement witness global member)
  simpa only [List.map_const', selected_tail_csr_exact_count] using equal

/-- Negative control: a unit-padding target rejects a zero source word. -/
theorem unit_padding_zero_word_rejected : (0 : F) - 1 ≠ 0 := by norm_num

end


end HegemonCrypto.SmallWood.V8Smz9SourceTailCsrRoots

import HegemonCrypto.SmallWoodV8Smz9SourceMerkleInitialReadback

namespace HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

theorem actual_merkle_capacity_nodes :
    exactCsrExpressions[128]? = some (.constant 4) ∧
    exactCsrExpressions[544]? = some (.constant poseidon2V8SuiteMarker) := by decide

noncomputable section

theorem actual_merkle_capacity_coefficients (pub : Nat → F) :
    actualCsrCoefficients pub 128 = (4 : F) ∧
    actualCsrCoefficients pub 544 = (poseidon2V8SuiteMarker : F) := by
  exact ⟨actual_csr_node_field_equation pub actual_merkle_capacity_nodes.1,
    actual_csr_node_field_equation pub actual_merkle_capacity_nodes.2⟩

/-- Interpret the actual descriptor and DAG, then use only constructor-derived
rate/capacity values. No desired evaluator equation or packed acceptance input. -/
theorem typed_merkle_initial_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (tail : List Nat)
    (pub : Nat → F) (offset : Fin 1024) :
    actualCsrResidual pub (typedAssignment statement witness tail)
      (V8Smz9InputMerkleSources.initialAttempt offset.val) = 0 := by
  by_cases rate : offset.val%16<14
  · have copied := typed_merkle_initial_rate statement witness valid tail
      ⟨offset.val/16, by omega⟩ ⟨offset.val%16, rate⟩
    simp only [V8Smz9InputMerkleSources.initialAttempt, if_pos rate,
      List.cons_append, List.nil_append]
    rw [actual_copy_residual_formula, copied, sub_self]
  · have capacity := typed_merkle_initial_capacity statement witness valid tail
      ⟨offset.val/16, by omega⟩ ⟨offset.val%16, by omega⟩
      (show 14 ≤ offset.val%16 by omega)
    simp only [V8Smz9InputMerkleSources.initialAttempt, if_neg rate,
      List.append_nil, actualCsrResidual, actualCsrTerms, attempt,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      (actual_csr_zero_one pub).2, one_mul, add_zero, capacity]
    split <;> simp only [actual_merkle_capacity_coefficients, Nat.cast_ofNat, sub_self]

/-- All 1024 consecutive actual family-14 entries, with a fixed internally
computed typed schedule and arbitrary public coefficient input and tail. -/
theorem typed_all_1024_actual_merkle_initial_csr_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (tail : List Nat)
    (pub : Nat → F) (offset : Fin 1024) :
    (exactCsrAttempts[15918+offset.val]?).map
      (actualCsrResidual pub (typedAssignment statement witness tail)) = some 0 := by
  rw [exact_initial_attempt_lookup, Option.map_some,
    typed_merkle_initial_attempt_zero statement witness valid tail pub offset]

end
end HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial

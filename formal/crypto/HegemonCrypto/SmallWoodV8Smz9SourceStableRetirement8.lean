import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceStableCounterArithmetic
import HegemonCrypto.SmallWoodV8Smz9SourceStablePolicyProjections
import HegemonCrypto.SmallWoodV8Smz9StableRetirementEndpoint
import HegemonCrypto.SmallWoodV8Smz9SourceParentMultiplication
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement8
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableCounterArithmetic
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication
open HegemonCrypto.SmallWood.V8Smz9SourceStablePolicyProjections
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRetirementEndpoint
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated (attempt exactCsrAttempts)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem retirement_gate_exact_lookup (index : Fin 4) :
    exactCsrAttempts[20413 + 2 * index.val]? = some (retirementGateAttempt index.val) :=
  exact_attempt_lookup _ (exact_retirement_gate_attempts index.val index.isLt).1

theorem retirement_zero_exact_lookup (index : Fin 4) :
    exactCsrAttempts[20414 + 2 * index.val]? = some (retirementZeroAttempt index.val) :=
  exact_attempt_lookup _ (exact_retirement_gate_attempts index.val index.isLt).2

noncomputable section
theorem full_candidate_retirement_gate_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 4) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (retirementGateAttempt index.val) = 0 := by
  have mint := (live_typed_direction_coefficients statement witness valid).1
  fin_cases index <;> simp only [retirementGateAttempt,actualCsrResidual,actualCsrTerms,attempt,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    live_coefficient_0,live_coefficient_1,live_coefficient_323,mint,one_mul,add_zero,sub_zero]
  all_goals rw [full_candidate_multiplication_a_absolute statement witness _ (by decide) (by decide),
    full_candidate_private_at statement witness 41412 (by decide) (by decide)]
  all_goals rw [source_retirement_gate_a statement witness _ _ (by decide) (by decide)]
  all_goals simp [sourcePrivateIndex,(source_config_retirement statement witness).2.1,
      decodeV8StablecoinConfig,typedMint]

theorem full_candidate_retirement_output_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 4) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (retirementZeroAttempt index.val) = 0 := by
  fin_cases index <;> simp only [retirementZeroAttempt,actualCsrResidual,actualCsrTerms,attempt,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    live_coefficient_0,live_coefficient_1,one_mul,add_zero,sub_zero]
  all_goals rw [full_candidate_multiplication_c_absolute statement witness _ (by decide) (by decide)]
  all_goals rw [source_policy_output_c statement witness _ _ (by decide) (by decide),Nat.cast_zero]

theorem full_candidate_actual_retirement_gates8_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 8) :
    (exactCsrAttempts[20413 + index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  have lane : index.val / 2 < 4 := by omega
  by_cases even : index.val % 2 = 0
  · have address : 20413 + index.val = 20413 + 2 * (index.val / 2) := by omega
    rw [address,retirement_gate_exact_lookup ⟨index.val/2,lane⟩]
    exact congrArg some (full_candidate_retirement_gate_zero statement witness valid ⟨index.val/2,lane⟩)
  · have address : 20413 + index.val = 20414 + 2 * (index.val / 2) := by omega
    rw [address,retirement_zero_exact_lookup ⟨index.val/2,lane⟩]
    exact congrArg some (full_candidate_retirement_output_zero statement witness ⟨index.val/2,lane⟩)
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement8

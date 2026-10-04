import HegemonCrypto.SmallWoodV8Smz9SourceStableRetirement8
import HegemonCrypto.SmallWoodV8Smz9SourceNonmintCsr40

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement15
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication
open HegemonCrypto.SmallWood.V8Smz9SourceStablePolicyProjections
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable (csr_chunks037_member)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def retirementBasicAttempt (index : Nat) : CsrExecutableAttempt :=
  match index with
  | 0 => attempt 20425 78 0 0 [(42264, 1), (41412, 265)] 1
  | 1 => attempt 20426 78 1 0 [(42328, 1), (41413, 158)] 0
  | 2 => attempt 20427 78 2 0 [(42392, 1)] 0
  | 3 => attempt 20428 79 0 0 [(42269, 1), (42265, 265)] 1
  | 4 => attempt 20429 79 1 0 [(42333, 1), (42178, 158)] 0
  | 5 => attempt 20430 79 2 0 [(42397, 1)] 0
  | 6 => attempt 20431 79 3 0 [(42270, 1), (42265, 265)] 1
  | 7 => attempt 20432 79 4 0 [(42334, 1), (42179, 158)] 0
  | 8 => attempt 20433 79 5 0 [(42398, 1)] 0
  | 9 => attempt 20434 79 6 0 [(42271, 1), (42265, 265)] 1
  | 10 => attempt 20435 79 7 0 [(42335, 1), (42139, 158)] 0
  | 11 => attempt 20436 79 8 0 [(42399, 1)] 0
  | 12 => attempt 20437 79 9 0 [(42272, 1), (42265, 265)] 1
  | 13 => attempt 20438 79 10 0 [(42336, 1), (42140, 158)] 0
  | _ => attempt 20439 79 11 0 [(42400, 1)] 0

theorem retirement_basic_chunk_member (index : Fin 15) :
    retirementBasicAttempt index.val ∈ V8Smz9ProgramCanonicalityCsr39.chunk014 := by
  fin_cases index <;> decide

theorem retirement_basic_chunk_in_complete : V8Smz9ProgramCanonicalityCsr39.chunk014 ∈ csrChunks000 := by
  have member : V8Smz9ProgramCanonicalityCsr39.chunk014 ∈ V8Smz9ProgramCanonicalityCsr39.chunkList := by
    simp only [V8Smz9ProgramCanonicalityCsr39.chunkList,List.mem_cons,List.not_mem_nil,or_false]
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl True.intro))))))))))))))
  exact csr_chunks037_member _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ member)))

theorem retirement_basic_exact_lookup (index : Fin 15) :
    exactCsrAttempts[20425 + index.val]? = some (retirementBasicAttempt index.val) := by
  have found := exact_attempt_lookup (retirementBasicAttempt index.val) (by
    rw [←csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,retirement_basic_chunk_in_complete,retirement_basic_chunk_member index⟩)
  have global : (retirementBasicAttempt index.val).globalIndex = 20425 + index.val := by
    fin_cases index <;> decide
  rwa [global] at found

noncomputable section
theorem full_candidate_retirement_basic_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 15) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (retirementBasicAttempt index.val) = 0 := by
  have retired := (valid_config_boolean statement witness valid).2.1
  change stableWitnessWord witness.stablecoin 4 = 0 ∨ stableWitnessWord witness.stablecoin 4 = 1 at retired
  fin_cases index <;>
    simp only [retirementBasicAttempt,actualCsrResidual,actualCsrTerms,attempt,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_1,live_coefficient_158,live_coefficient_265,
      one_mul,add_zero,sub_zero]
  all_goals repeat first
    | rw [full_candidate_private_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_boolean_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_a_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_b_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_c_absolute statement witness _ (by decide) (by decide)]
  all_goals repeat first
    | rw [source_retired_present_a statement witness _]
    | rw [source_retired_present_b statement witness _]
    | rw [source_retirement_gate_a statement witness _ _ (by decide) (by decide)]
    | rw [source_retirement_inactive_a statement witness _ _ (by decide) (by decide)]
    | rw [source_retirement_inactive_b statement witness _ _ (by decide) (by decide)]
    | rw [source_policy_output_c statement witness _ _ (by decide) (by decide)]
  all_goals simp [sourcePrivateIndex,sourceNumericValues,sourceBooleanValues,
    (source_config_retirement statement witness).2.1,(source_config_retirement statement witness).2.2,
    decodeV8StablecoinConfig,List.ofFn_succ]
  all_goals rcases retired with retired | retired
  all_goals by_cases mint : statement.stablecoin.direction = .mint
  all_goals simp [retired,mint]

theorem full_candidate_actual_retirement_basic15_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 15) :
    (exactCsrAttempts[20425 + index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [retirement_basic_exact_lookup,Option.map_some,
    full_candidate_retirement_basic_zero statement witness valid index]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement15

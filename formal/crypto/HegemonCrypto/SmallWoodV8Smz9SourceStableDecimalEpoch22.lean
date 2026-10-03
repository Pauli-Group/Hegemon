import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceStableLiveRoleCsr
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies
import HegemonCrypto.SmallWoodV8Smz9StableDecimalEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableDecimalEpoch22
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr (liveTypedPub)
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SemanticStableDecimalEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def decimalPowerAttempt (index : Nat) : CsrExecutableAttempt :=
  match index with
  | 0 => attempt 20376 73 0 0 [(42240,1)] 1
  | 1 => attempt 20377 73 1 0 [(42304,1),(42124,439)] 1
  | 2 => attempt 20378 73 2 0 [(42368,1),(42189,158)] 0
  | 3 => attempt 20379 73 3 0 [(42241,1),(42189,158)] 0
  | 4 => attempt 20380 73 4 0 [(42305,1),(42125,441)] 1
  | 5 => attempt 20381 73 5 0 [(42369,1),(42190,158)] 0
  | 6 => attempt 20382 73 6 0 [(42242,1),(42190,158)] 0
  | 7 => attempt 20383 73 7 0 [(42306,1),(42126,443)] 1
  | 8 => attempt 20384 73 8 0 [(42370,1),(42191,158)] 0
  | 9 => attempt 20385 73 9 0 [(42243,1),(42191,158)] 0
  | 10 => attempt 20386 73 10 0 [(42307,1),(42127,445)] 1
  | 11 => attempt 20387 73 11 0 [(42371,1),(42192,158)] 0
  | 12 => attempt 20388 73 12 0 [(42244,1),(42192,158)] 0
  | 13 => attempt 20389 73 13 0 [(42308,1),(42128,447)] 1
  | _ => attempt 20390 73 14 0 [(42372,1),(42193,158)] 0

def epochMuxAttempt (index : Nat) : CsrExecutableAttempt :=
  match index with
  | 0 => attempt 20391 74 0 0 [(42255,1),(42187,158)] 0
  | 1 => attempt 20392 74 1 0 [(42383,1),(42123,265)] 1
  | 2 => attempt 20393 74 2 0 [(42256,1),(42123,158)] 0
  | 3 => attempt 20394 74 3 0 [(42320,1),(41499,158)] 0
  | 4 => attempt 20395 74 4 0 [(42257,1),(42123,158)] 0
  | 5 => attempt 20396 74 5 0 [(42321,1),(42187,158)] 0
  | _ => attempt 20397 74 6 0 [(42385,1)] 0

theorem decimal_power_membership (index : Fin 15) : decimalPowerAttempt index.val ∈ stableDecimalAttempts := by
  fin_cases index <;> decide

theorem decimal_power_exact_lookup (index : Fin 15) :
    exactCsrAttempts[20376 + index.val]? = some (decimalPowerAttempt index.val) := by
  have found := exact_attempt_lookup _ (exact_stable_decimal_attempts _ (decimal_power_membership index))
  have global : (decimalPowerAttempt index.val).globalIndex = 20376 + index.val := by
    fin_cases index <;> decide
  rwa [global] at found

theorem epoch_mux_membership (index : Fin 7) : epochMuxAttempt index.val ∈ stableMuxAttempts := by
  fin_cases index <;> decide

theorem epoch_mux_exact_lookup (index : Fin 7) :
    exactCsrAttempts[20391 + index.val]? = some (epochMuxAttempt index.val) := by
  have found := exact_attempt_lookup _ (exact_stable_mux_attempts _ (epoch_mux_membership index))
  have global : (epochMuxAttempt index.val).globalIndex = 20391 + index.val := by
    fin_cases index <;> decide
  rwa [global] at found

theorem decimal_coefficient_nodes (lane : Fin 5) :
    exactCsrExpressions[438 + 2 * lane.val]? = some (.constant (10 ^ (2 ^ lane.val) - 1)) ∧
      exactCsrExpressions[439 + 2 * lane.val]? = some (.sub 0 (438 + 2 * lane.val)) := by
  fin_cases lane <;> decide

noncomputable section
theorem actual_decimal_negative_coefficient (pub : Nat → F) (lane : Fin 5) :
    actualCsrCoefficients pub (439 + 2 * lane.val) = -((10 ^ (2 ^ lane.val) - 1 : Nat) : F) := by
  have constant := actual_csr_node_field_equation pub (decimal_coefficient_nodes lane).1
  change actualCsrCoefficients pub (438 + 2 * lane.val) = ((10 ^ (2 ^ lane.val) - 1 : Nat) : F) at constant
  have negative := actual_csr_node_field_equation pub (decimal_coefficient_nodes lane).2
  simpa only [expressionField,(actual_csr_zero_one pub).1,constant,zero_sub] using negative

theorem full_candidate_decimal_power_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 15) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (decimalPowerAttempt index.val) = 0 := by
  have c0 := actual_decimal_negative_coefficient (liveTypedPub statement) ⟨0,by decide⟩
  have c1 := actual_decimal_negative_coefficient (liveTypedPub statement) ⟨1,by decide⟩
  have c2 := actual_decimal_negative_coefficient (liveTypedPub statement) ⟨2,by decide⟩
  have c3 := actual_decimal_negative_coefficient (liveTypedPub statement) ⟨3,by decide⟩
  have c4 := actual_decimal_negative_coefficient (liveTypedPub statement) ⟨4,by decide⟩
  norm_num only at c0 c1 c2 c3 c4
  fin_cases index <;>
    simp only [decimalPowerAttempt,actualCsrResidual,attempt,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_1,live_coefficient_158,c0,c1,c2,c3,c4,one_mul,add_zero,sub_zero]
  all_goals first
    | rw [full_candidate_multiplication_a_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_b_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_c_absolute statement witness _ (by decide) (by decide)]
  all_goals try rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
  all_goals try rw [full_candidate_boolean_absolute statement witness _ (by decide) (by decide)]
  all_goals simp [sourceMultiplication,sourceBaseMultiplication,sourceNumericValues,
    sourceBooleanValues,List.ofFn_succ,Nat.cast_add,Nat.cast_mul]
  all_goals ring

theorem full_candidate_epoch_mux_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 7) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (epochMuxAttempt index.val) = 0 := by
  have same := actual_source_same_epoch_boolean statement witness
  fin_cases index <;>
    simp only [epochMuxAttempt,actualCsrResidual,attempt,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_1,live_coefficient_158,live_coefficient_265,
      one_mul,add_zero,sub_zero]
  all_goals first
    | rw [full_candidate_multiplication_a_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_b_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_c_absolute statement witness _ (by decide) (by decide)]
  all_goals try rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
  all_goals try rw [full_candidate_boolean_absolute statement witness _ (by decide) (by decide)]
  all_goals try rw [full_candidate_private_at statement witness _ (by decide) (by decide)]
  all_goals simp [sourceMultiplication,sourceBaseMultiplication,sourceNumericValues,
    sourceBooleanValues,List.ofFn_succ,sourcePrivateIndex,decodeV8StablecoinBefore]
  all_goals rcases same with same | same <;> simp [same]

theorem full_candidate_actual_decimal15_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 15) :
    (exactCsrAttempts[20376 + index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [decimal_power_exact_lookup,Option.map_some,full_candidate_decimal_power_attempt_zero statement witness index]

theorem full_candidate_actual_epoch7_zero (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 7) :
    (exactCsrAttempts[20391 + index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [epoch_mux_exact_lookup,Option.map_some,full_candidate_epoch_mux_attempt_zero statement witness index]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableDecimalEpoch22

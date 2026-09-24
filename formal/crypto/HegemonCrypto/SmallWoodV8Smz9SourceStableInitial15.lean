import HegemonCrypto.SmallWoodV8Smz9SourceStableInitialValues15
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericCoefficients
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceNonmintCsr40
import HegemonCrypto.SmallWoodV8Smz9SourceStableLeafFrames
import HegemonCrypto.SmallWoodV8Smz9SourceParentMultiplication

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableInitial15
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableArithmetic04
open HegemonCrypto.SmallWood.V8Smz9SourceStableInitialValues15
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceNonmintCsr40
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLeafFrames
open HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def stableInitialAttempt (index : Nat) : CsrExecutableAttempt :=
  match index with
  | 0 => attempt 20320 63 0 0 [(42176,210),(42119,158),(42120,206),(42121,159),(42122,208)] 413
  | 1 => attempt 20321 64 0 0 [(41454,1),(42124,158),(42125,206),(42126,159),(42127,208),(42128,210)] 0
  | 2 => attempt 20322 65 0 0 [(41454,1),(42129,1),(42130,2),(42131,128),(42132,207),(42133,209)] 417
  | 3 => attempt 20323 66 0 1 [(41455,306),(42193,321)] 0
  | 4 => attempt 20324 67 0 1 [(41498,1),(42187,1)] 418
  | 5 => attempt 20325 67 1 1 [(42188,321)] 422
  | 6 => attempt 20326 67 2 1 [(41499,1),(42185,1),(41422,158)] 0
  | 7 => attempt 20327 67 3 1 [(42186,1),(41422,158)] 411
  | 8 => attempt 20328 67 4 1 [(42384,158)] 425
  | 9 => attempt 20329 67 5 1 [(41500,158)] 429
  | 10 => attempt 20330 67 6 1 [(41501,158)] 431
  | 11 => attempt 20331 68 0 1 [(41410,304)] 433
  | 12 => attempt 20332 68 1 1 [(41429,304)] 0
  | 13 => attempt 20333 68 2 1 [(41430,304)] 433
  | _ => attempt 20334 68 3 1 [(41421,304),(42184,432)] 437

theorem stable_initial_chunk_member (index : Fin 15) :
    stableInitialAttempt index.val ∈ V8Smz9ProgramCanonicalityCsr39.chunk011 := by
  fin_cases index <;> decide

theorem stable_initial_exact_lookup (index : Fin 15) :
    exactCsrAttempts[20320 + index.val]? = some (stableInitialAttempt index.val) := by
  have found := exact_attempt_lookup (stableInitialAttempt index.val) (by
    rw [←csr_chunks_equal_materialized_attempts]
    exact List.mem_flatten.mpr ⟨_,nonmint_chunks_in_complete _ (Or.inl rfl),
      stable_initial_chunk_member index⟩)
  have global : (stableInitialAttempt index.val).globalIndex = 20320 + index.val := by
    fin_cases index <;> decide
  rwa [global] at found

noncomputable section
theorem full_candidate_initial_attempt_value_group0 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (stableInitialAttempt (0 + index.val)) = sourceInitialValue statement witness (0 + index.val) := by
  have direction := live_typed_direction_coefficients statement witness valid
  have encoded := encoded_stable_public_scalars statement witness valid
  have height := encoded_parent_height statement witness valid
  have epoch := encoded_stable_after_counter statement witness valid ⟨0,by decide⟩
  have minted := encoded_stable_after_counter statement witness valid ⟨1,by decide⟩
  have debt := encoded_stable_after_counter statement witness valid ⟨2,by decide⟩
  have sequence := encoded_stable_after_counter statement witness valid ⟨3,by decide⟩
  change (encodePublicStatement statement).getD 109 0 = statement.stablecoin.after.epochId at epoch
  change (encodePublicStatement statement).getD 110 0 = statement.stablecoin.after.mintedInEpoch at minted
  change (encodePublicStatement statement).getD 111 0 = statement.stablecoin.after.totalDebt at debt
  change (encodePublicStatement statement).getD 112 0 = statement.stablecoin.after.sequence at sequence
  change (encodePublicStatement statement).getD 94 0 = statement.stablecoin.parentHeight at height
  fin_cases index <;>
    simp only [stableInitialAttempt,actualCsrResidual,attempt,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_1,live_coefficient_2,live_coefficient_158,actual_csr_coefficient_159,
      actual_csr_coefficient_128,actual_csr_coefficient_206,actual_csr_coefficient_207,
      actual_csr_coefficient_208,actual_csr_coefficient_209,actual_csr_coefficient_210,
      live_coefficient_306,live_coefficient_321,
      actual_csr_coefficient_413,actual_csr_coefficient_417,
      actual_csr_coefficient_418,
      
      
      direction.2.2,one_mul,add_zero,sub_zero]
  all_goals repeat first
    | rw [full_candidate_private_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_boolean_absolute statement witness _ (by decide) (by decide)]
  all_goals try simp only [liveTypedPub,encoded.2.1,epoch]
  all_goals simp [sourceInitialValue,sourceFourBits,sourceFiveBits,
    sourcePrivateIndex,decodeV8StablecoinConfig,decodeV8StablecoinBefore,
    sourceNumericValues,sourceBooleanValues,
    List.ofFn_succ,Nat.cast_add,Nat.cast_mul]
  all_goals ring

theorem full_candidate_initial_attempt_value_group1 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (stableInitialAttempt (5 + index.val)) = sourceInitialValue statement witness (5 + index.val) := by
  have direction := live_typed_direction_coefficients statement witness valid
  have encoded := encoded_stable_public_scalars statement witness valid
  have height := encoded_parent_height statement witness valid
  have epoch := encoded_stable_after_counter statement witness valid ⟨0,by decide⟩
  have minted := encoded_stable_after_counter statement witness valid ⟨1,by decide⟩
  have debt := encoded_stable_after_counter statement witness valid ⟨2,by decide⟩
  have sequence := encoded_stable_after_counter statement witness valid ⟨3,by decide⟩
  change (encodePublicStatement statement).getD 109 0 = statement.stablecoin.after.epochId at epoch
  change (encodePublicStatement statement).getD 110 0 = statement.stablecoin.after.mintedInEpoch at minted
  change (encodePublicStatement statement).getD 111 0 = statement.stablecoin.after.totalDebt at debt
  change (encodePublicStatement statement).getD 112 0 = statement.stablecoin.after.sequence at sequence
  change (encodePublicStatement statement).getD 94 0 = statement.stablecoin.parentHeight at height
  fin_cases index <;>
    simp only [stableInitialAttempt,actualCsrResidual,attempt,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_1,live_coefficient_158,
      
      
      live_coefficient_321,
      actual_csr_coefficient_411,
      actual_csr_coefficient_422,actual_csr_coefficient_425,
      actual_csr_coefficient_429,
      
      direction.1,direction.2.1,direction.2.2,one_mul,add_zero,sub_zero]
  all_goals repeat first
    | rw [full_candidate_private_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_c_absolute statement witness _ (by decide) (by decide)]
  all_goals try simp only [liveTypedPub,encoded.2.2.2,epoch,minted,debt,height]
  all_goals simp [sourceInitialValue,
    sourcePrivateIndex,decodeV8StablecoinConfig,decodeV8StablecoinBefore,
    sourceNumericValues,sourceMultiplication,sourceBaseMultiplication,
    List.ofFn_succ,Nat.cast_mul]
  all_goals ring

theorem full_candidate_initial_attempt_value_group2 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (stableInitialAttempt (10 + index.val)) = sourceInitialValue statement witness (10 + index.val) := by
  have direction := live_typed_direction_coefficients statement witness valid
  have encoded := encoded_stable_public_scalars statement witness valid
  have height := encoded_parent_height statement witness valid
  have epoch := encoded_stable_after_counter statement witness valid ⟨0,by decide⟩
  have minted := encoded_stable_after_counter statement witness valid ⟨1,by decide⟩
  have debt := encoded_stable_after_counter statement witness valid ⟨2,by decide⟩
  have sequence := encoded_stable_after_counter statement witness valid ⟨3,by decide⟩
  change (encodePublicStatement statement).getD 109 0 = statement.stablecoin.after.epochId at epoch
  change (encodePublicStatement statement).getD 110 0 = statement.stablecoin.after.mintedInEpoch at minted
  change (encodePublicStatement statement).getD 111 0 = statement.stablecoin.after.totalDebt at debt
  change (encodePublicStatement statement).getD 112 0 = statement.stablecoin.after.sequence at sequence
  change (encodePublicStatement statement).getD 94 0 = statement.stablecoin.parentHeight at height
  fin_cases index <;>
    simp only [stableInitialAttempt,actualCsrResidual,attempt,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_158,
      
      
      live_coefficient_304,
      
      
      actual_csr_coefficient_431,actual_csr_coefficient_432,
      actual_csr_coefficient_433,actual_csr_coefficient_437,
      direction.1,direction.2.2,add_zero,sub_zero]
  all_goals repeat first
    | rw [full_candidate_private_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
  all_goals try simp only [liveTypedPub,sequence]
  all_goals simp [sourceInitialValue,
    sourcePrivateIndex,decodeV8StablecoinConfig,decodeV8StablecoinBefore,
    sourceNumericValues,
    List.ofFn_succ]
  all_goals ring

theorem full_candidate_initial_attempt_value (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 15) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (stableInitialAttempt index.val) = sourceInitialValue statement witness index.val := by
  by_cases low : index.val < 5
  · simpa only [Nat.zero_add] using full_candidate_initial_attempt_value_group0 statement witness valid ⟨index.val,low⟩
  · by_cases middle : index.val < 10
    · have result := full_candidate_initial_attempt_value_group1 statement witness valid ⟨index.val - 5,by omega⟩
      have address : 5 + (index.val - 5) = index.val := by omega
      simpa only [address] using result
    · have result := full_candidate_initial_attempt_value_group2 statement witness valid ⟨index.val - 10,by omega⟩
      have address : 10 + (index.val - 10) = index.val := by omega
      simpa only [address] using result

theorem full_candidate_actual_initial15_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 15) :
    (exactCsrAttempts[20320 + index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [stable_initial_exact_lookup,Option.map_some,
    full_candidate_initial_attempt_value statement witness valid index,
    valid_source_initial_values_zero statement witness valid index]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableInitial15

import HegemonCrypto.SmallWoodV8Smz9SourceStableCollateralDifference
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericCoefficients
import HegemonCrypto.SmallWoodV8Smz9StableCollateralEndpoint
import HegemonCrypto.SmallWoodV8Smz9SourceStableLeafFrames
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableCollateral6
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableCollateralDifference
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLeafFrames
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def collateral6Attempt (index : Nat) : CsrExecutableAttempt :=
  collateralEndAttempts.getD (index+1) (attempt 0 0 0 0 [] 0)

def collateral6Global (index : Nat) : Nat := if index<2 then 20440+index else 20470+index

theorem collateral6_membership (index : Fin 6) : collateral6Attempt index.val ∈ collateralEndAttempts := by
  fin_cases index <;> decide

theorem collateral6_exact_lookup (index : Fin 6) :
    exactCsrAttempts[collateral6Global index.val]? = some (collateral6Attempt index.val) := by
  have found := exact_attempt_lookup _ (exact_collateral_end_attempts _ (collateral6_membership index))
  have global : (collateral6Attempt index.val).globalIndex = collateral6Global index.val := by
    fin_cases index <;> decide
  rwa [global] at found

noncomputable section
theorem source_mul3_input_field (x y z : Nat) :
    (x : F) - ((sourceMul3 x y z).x0 : F) - 4294967296 * ((sourceMul3 x y z).x1 : F) = 0 := by
  have equation := congrArg (fun value : Nat => (value : F)) (Nat.mod_add_div x limbBase)
  simp only [Nat.cast_add,Nat.cast_mul,limbBase,Nat.cast_pow,Nat.cast_ofNat] at equation
  simp only [sourceMul3,limbBase]
  linear_combination -equation

theorem full_candidate_collateral_input2_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 2) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (collateral6Attempt index.val) = 0 := by
  have direction := (live_typed_direction_coefficients statement witness valid).1
  have debt := encoded_stable_after_counter statement witness valid ⟨2,by decide⟩
  change (encodePublicStatement statement).getD 111 0 = statement.stablecoin.after.totalDebt at debt
  have left := source_mul3_input_field (decodeV8StablecoinConfig witness.stablecoin).collateralAmount
    (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator 1000000
  have right := source_mul3_input_field statement.stablecoin.after.totalDebt
    (decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator
    (decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm
  fin_cases index <;>
    norm_num only [collateral6Attempt,collateralEndAttempts,actualCsrResidual,attempt,actualCsrTerms,
      List.getD_cons_zero,List.getD_cons_succ,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_304,actual_csr_coefficient_432,actual_csr_coefficient_480,
      actual_csr_coefficient_540,Nat.reduceAdd,add_zero,sub_zero,direction,liveTypedPub,debt]
  all_goals repeat first
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_private_at statement witness _ (by decide) (by decide)]
  all_goals simp [sourceNumericValues,SourceMul3.rangeValues,List.ofFn_succ,sourcePrivateIndex]
  all_goals by_cases mint : statement.stablecoin.direction = .mint
  · have active : statement.stablecoin.direction ≠ .disabled := by rw [mint]; decide
    simp only [typedMint,if_pos mint,sourceAux,if_neg active,sourceCollateral,one_mul]
    simp only [sourceMul3,decodeV8StablecoinConfig] at left ⊢
    linear_combination left
  · simp [typedMint,mint]
  · have active : statement.stablecoin.direction ≠ .disabled := by rw [mint]; decide
    simp only [typedMint,if_pos mint,sourceAux,if_neg active,sourceCollateral,one_mul]
    simp only [sourceMul3] at right ⊢
    linear_combination right
  · simp [typedMint,mint]

theorem full_candidate_collateral_difference4_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 4) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (collateral6Attempt (2+index.val)) = 0 := by
  have direction := (live_typed_direction_coefficients statement witness valid).1
  have equation := actual_difference_field statement witness index.val
  fin_cases index <;>
    norm_num only [collateral6Attempt,collateralEndAttempts,actualCsrResidual,attempt,actualCsrTerms,
      List.getD_cons_zero,List.getD_cons_succ,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_304,actual_csr_coefficient_432,actual_csr_coefficient_541,
      Nat.reduceAdd,add_zero,sub_zero,direction]
  all_goals repeat first
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_boolean_absolute statement witness _ (by decide) (by decide)]
  all_goals simp [sourceNumericValues,SourceMul3.rangeValues,List.ofFn_succ,sourceBooleanValues]
  all_goals norm_num only [ite_true,ite_false,Nat.cast_zero,sub_zero,Nat.reduceSub] at equation
  all_goals linear_combination typedMint statement * equation

theorem full_candidate_actual_collateral6_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 6) :
    (exactCsrAttempts[collateral6Global index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [collateral6_exact_lookup,Option.map_some]
  congr 1
  by_cases small : index.val < 2
  · exact full_candidate_collateral_input2_zero statement witness valid ⟨index.val,small⟩
  · have address : 2+(index.val-2)=index.val := by omega
    have proof := full_candidate_collateral_difference4_zero statement witness valid ⟨index.val-2,by omega⟩
    simpa only [address] using proof
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableCollateral6

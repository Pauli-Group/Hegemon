import HegemonCrypto.SmallWoodV8Smz9SourceStableCollateralParts
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericCoefficients
import HegemonCrypto.SmallWoodV8Smz9StableCollateralBindings
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableProduct30
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableCollateralParts
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def productSpecAt (index : Nat) : ProductSpec := productSpecs.getD index ⟨0,0,0,0,0,0⟩

theorem product_spec_membership (index : Fin 10) : productSpecAt index.val ∈ productSpecs := by
  fin_cases index <;> decide

theorem product_exact_lookup (index : Fin 10) (part : Fin 3) :
    exactCsrAttempts[20442 + 3*index.val + part.val]? = some (productAttempt (productSpecAt index.val) part.val) := by
  have found := exact_attempt_lookup _ (exact_product_attempts _ (product_spec_membership index) _ part.isLt)
  have global : (productAttempt (productSpecAt index.val) part.val).globalIndex = 20442 + 3*index.val + part.val := by
    fin_cases index <;> fin_cases part <;> decide
  rwa [global] at found

theorem source_left_product_tuple (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (lane : Fin 5) :
    sourceMultiplication statement witness aux (5+lane.val) =
      sourceMul3Lane aux.collateral.left (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator
        1000000 lane.val := by
  simp only [sourceMultiplication,if_pos (show 5+lane.val < 18 by omega),
    sourceBaseMultiplication,if_neg (show ¬5+lane.val < 5 by omega),
    if_pos (show 5+lane.val < 10 by omega),Nat.add_sub_cancel_left]

theorem source_right_product_tuple (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (lane : Fin 5) :
    sourceMultiplication statement witness aux (10+lane.val) =
      sourceMul3Lane aux.collateral.right (decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator
        (decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm lane.val := by
  simp only [sourceMultiplication,if_pos (show 10+lane.val < 18 by omega),
    sourceBaseMultiplication,if_neg (show ¬10+lane.val < 5 by omega),
    if_neg (show ¬10+lane.val < 10 by omega),if_pos (show 10+lane.val < 15 by omega),Nat.add_sub_cancel_left]

noncomputable section
theorem full_candidate_left_product_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) (part : Fin 3) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (productAttempt (productSpecAt index.val) part.val) = 0 := by
  have e0 := actual_left_carry_field statement witness valid ⟨0,by decide⟩
  have e1 := actual_left_carry_field statement witness valid ⟨1,by decide⟩
  have e2 := actual_left_carry_field statement witness valid ⟨2,by decide⟩
  have e3 := actual_left_carry_field statement witness valid ⟨3,by decide⟩
  have e4 := actual_left_carry_field statement witness valid ⟨4,by decide⟩
  simp only [laneLow,laneHigh,lanePrevious,sourceMul3Lane,Nat.cast_zero,add_zero,
    Nat.cast_add,Nat.cast_mul,limbBase,Nat.cast_pow,Nat.cast_ofNat] at e0 e1 e2 e3 e4
  fin_cases index <;> fin_cases part <;>
    norm_num only [productSpecAt,productSpecs,productAttempt,actualCsrResidual,attempt,actualCsrTerms,
      List.getD_cons_zero,List.getD_cons_succ,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      List.cons_append,List.nil_append,List.append_nil,live_coefficient_0,live_coefficient_1,
      live_coefficient_158,live_coefficient_265,actual_csr_coefficient_434,actual_csr_coefficient_449,
      Nat.reduceAdd,Nat.reduceSub,Nat.reduceMul,ite_true,ite_false,
      one_mul,neg_one_mul,add_zero,sub_zero]
  all_goals repeat first
    | rw [full_candidate_multiplication_a_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_b_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_c_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_private_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
  all_goals simp [sourceMultiplication,sourceBaseMultiplication,sourceMul3Lane,sourceNumericValues,
    SourceMul3.rangeValues,List.ofFn_succ,sourcePrivateIndex,decodeV8StablecoinConfig]
  all_goals norm_num only [actual_csr_coefficient_434,limbBase,Nat.cast_pow,Nat.cast_ofNat]
  · linear_combination e0
  · linear_combination e1
  · linear_combination e2
  · linear_combination e3
  · linear_combination e4

theorem full_candidate_right_product_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) (part : Fin 3) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (productAttempt (productSpecAt (5+index.val)) part.val) = 0 := by
  have e0 := actual_right_carry_field statement witness valid ⟨0,by decide⟩
  have e1 := actual_right_carry_field statement witness valid ⟨1,by decide⟩
  have e2 := actual_right_carry_field statement witness valid ⟨2,by decide⟩
  have e3 := actual_right_carry_field statement witness valid ⟨3,by decide⟩
  have e4 := actual_right_carry_field statement witness valid ⟨4,by decide⟩
  simp only [laneLow,laneHigh,lanePrevious,sourceMul3Lane,Nat.cast_zero,add_zero,
    Nat.cast_add,Nat.cast_mul,limbBase,Nat.cast_pow,Nat.cast_ofNat] at e0 e1 e2 e3 e4
  fin_cases index <;> fin_cases part <;>
    norm_num only [productSpecAt,productSpecs,productAttempt,actualCsrResidual,attempt,actualCsrTerms,
      List.getD_cons_zero,List.getD_cons_succ,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      List.cons_append,List.nil_append,List.append_nil,live_coefficient_0,live_coefficient_1,
      live_coefficient_158,live_coefficient_265,actual_csr_coefficient_434,actual_csr_coefficient_449,
      Nat.reduceAdd,Nat.reduceSub,Nat.reduceMul,ite_true,ite_false,
      one_mul,neg_one_mul,add_zero,sub_zero]
  all_goals repeat first
    | rw [full_candidate_multiplication_a_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_b_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_c_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_private_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
  all_goals simp [sourceMultiplication,sourceBaseMultiplication,sourceMul3Lane,sourceNumericValues,
    SourceMul3.rangeValues,List.ofFn_succ,sourcePrivateIndex,decodeV8StablecoinConfig]
  all_goals norm_num only [actual_csr_coefficient_434,limbBase,Nat.cast_pow,Nat.cast_ofNat]
  · linear_combination e0
  · linear_combination e1
  · linear_combination e2
  · linear_combination e3
  · linear_combination e4

theorem full_candidate_actual_product30_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 10) (part : Fin 3) :
    (exactCsrAttempts[20442 + 3*index.val + part.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [product_exact_lookup,Option.map_some]
  congr 1
  by_cases left : index.val < 5
  · exact full_candidate_left_product_zero statement witness valid ⟨index.val,left⟩ part
  · have address : 5+(index.val-5) = index.val := by omega
    have right := full_candidate_right_product_zero statement witness valid ⟨index.val-5,by omega⟩ part
    simpa only [address] using right
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableProduct30

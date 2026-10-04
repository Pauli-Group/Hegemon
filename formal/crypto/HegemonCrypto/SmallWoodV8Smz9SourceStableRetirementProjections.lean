import HegemonCrypto.SmallWoodV8Smz9SourceStableTimeArithmetic
import HegemonCrypto.SmallWoodV8Smz9SourceParentMultiplication
import HegemonCrypto.SmallWoodV8Smz9StableRetirementEndpoint
import HegemonCrypto.SmallWoodV8Smz9SourceMulResiduals

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRetirementProjections
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldAdd fieldMul)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableTimeArithmetic
open HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication
open HegemonCrypto.SmallWood.V8Smz9SourceMulResiduals
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRetirementEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem retirement_source_b_list (statement : V8PublicStatement) (witness : V8Witness) (aux : SourceAux)
    (slot : Fin 4) :
    (sourceMultiplication statement witness aux (25+slot.val)).b =
      [sourceLowResidual (stableSourceWord statement witness 3) ((sourceNumericValues aux).getD 2 0)
          (stableSourceWord statement witness 5) ((sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 27 0),
       sourceHighResidual (stableSourceWord statement witness 3) ((sourceNumericValues aux).getD 2 0)
          (stableSourceWord statement witness 5) ((sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 27 0),
       sourceLowResidual (wordAt (encodePublicStatement statement) 94) ((sourceNumericValues aux).getD 3 0)
          (stableSourceWord statement witness 5) ((sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 28 0),
       sourceHighResidual (wordAt (encodePublicStatement statement) 94) ((sourceNumericValues aux).getD 3 0)
          (stableSourceWord statement witness 5) ((sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 28 0)].getD slot.val 0 := by
  simp only [sourceMultiplication,if_neg (show ¬25+slot.val < 18 by omega),
    if_neg (show ¬25+slot.val < 24 by omega),if_neg (show ¬25+slot.val = 24 by omega),
    if_pos (show 25+slot.val < 29 by omega),Nat.add_sub_cancel_left]

theorem retirement_boolean_carry (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (index : Fin 2) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD (retirementAddition index.val).carry 0 =
      aux.timeCarries (1+index.val) := by
  fin_cases index <;> rfl

attribute [local irreducible] sourceLowResidual sourceHighResidual

theorem retirement_source_b_low (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (aux : SourceAux) (index : Fin 2) :
    (sourceMultiplication statement witness aux (25+2*index.val)).b =
      sourceLowResidual (timeValue statement witness aux (retirementAddition index.val).x)
        (timeValue statement witness aux (retirementAddition index.val).y)
        (timeValue statement witness aux (retirementAddition index.val).z) (aux.timeCarries (1+index.val)) := by
  have height := encoded_parent_height statement witness valid
  change (encodePublicStatement statement).getD 94 0 = statement.stablecoin.parentHeight at height
  rw [retirement_source_b_list statement witness aux ⟨2*index.val,by omega⟩]
  have source3 : stableSourceWord statement witness 3 = (decodeV8StablecoinConfig witness.stablecoin).enabledAt := rfl
  have source5 : stableSourceWord statement witness 5 = (decodeV8StablecoinConfig witness.stablecoin).retiredAt := rfl
  have number2 : (sourceNumericValues aux).getD 2 0 = aux.retirementOrderGap := rfl
  have number3 : (sourceNumericValues aux).getD 3 0 = aux.retirementHeightGap := rfl
  have bool27 : (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 27 0 = aux.timeCarries 1 := rfl
  have bool28 : (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 28 0 = aux.timeCarries 2 := rfl
  fin_cases index <;>
    norm_num only [retirementAddition,timeValue,List.getD_cons_zero,List.getD_cons_succ,
      source3,source5,number2,number3,bool27,bool28,wordAt,height,Nat.reduceAdd,Nat.reduceMul,ite_true,ite_false]

theorem retirement_source_b_high (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (aux : SourceAux) (index : Fin 2) :
    (sourceMultiplication statement witness aux (26+2*index.val)).b =
      sourceHighResidual (timeValue statement witness aux (retirementAddition index.val).x)
        (timeValue statement witness aux (retirementAddition index.val).y)
        (timeValue statement witness aux (retirementAddition index.val).z) (aux.timeCarries (1+index.val)) := by
  have height := encoded_parent_height statement witness valid
  change (encodePublicStatement statement).getD 94 0 = statement.stablecoin.parentHeight at height
  rw [show 26+2*index.val=25+(1+2*index.val) by omega,
    retirement_source_b_list statement witness aux ⟨1+2*index.val,by omega⟩]
  have source3 : stableSourceWord statement witness 3 = (decodeV8StablecoinConfig witness.stablecoin).enabledAt := rfl
  have source5 : stableSourceWord statement witness 5 = (decodeV8StablecoinConfig witness.stablecoin).retiredAt := rfl
  have number2 : (sourceNumericValues aux).getD 2 0 = aux.retirementOrderGap := rfl
  have number3 : (sourceNumericValues aux).getD 3 0 = aux.retirementHeightGap := rfl
  have bool27 : (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 27 0 = aux.timeCarries 1 := rfl
  have bool28 : (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD 28 0 = aux.timeCarries 2 := rfl
  fin_cases index <;>
    norm_num only [retirementAddition,timeValue,List.getD_cons_zero,List.getD_cons_succ,
      source3,source5,number2,number3,bool27,bool28,wordAt,height,Nat.reduceAdd,Nat.reduceMul,ite_true,ite_false]

noncomputable section
theorem source_low_residual_cast (x y z carry : Nat) :
    (sourceLowResidual x y z carry : F) = ((x % limbBase : Nat) : F) + ((y % limbBase : Nat) : F) + 1 -
      ((z % limbBase : Nat) : F) - 4294967296 * (carry : F) := by
  rw [sourceLowResidual,field_sub_cast_normalized_right _
    (fieldAdd (z % limbBase) (fieldMul limbBase carry)) (by exact Nat.mod_lt _ (by decide))]
  simp only [field_add_cast,field_mul_cast,Nat.cast_one,limbBase,Nat.cast_pow,Nat.cast_ofNat]
  ring

theorem source_high_residual_cast (x y z carry : Nat) (bound : z < fieldModulus) :
    (sourceHighResidual x y z carry : F) = ((x / limbBase : Nat) : F) + ((y / limbBase : Nat) : F) +
      (carry : F) - ((z / limbBase : Nat) : F) := by
  rw [sourceHighResidual,field_sub_cast_normalized_right _ _ (lt_of_le_of_lt (Nat.div_le_self _ _) bound)]
  simp only [field_add_cast]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableRetirementProjections

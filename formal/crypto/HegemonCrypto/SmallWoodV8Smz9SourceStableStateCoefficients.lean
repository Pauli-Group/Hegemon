import HegemonCrypto.SmallWoodV8Smz9SourceStableLiveRoleCsr
import HegemonCrypto.SmallWoodV8Smz9StableStateHash

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableStateCoefficients
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_public_coefficient (pub : Nat → F) (index : Fin 120) :
    actualCsrCoefficients pub (4+index.val) = pub index.val := by
  have found : exactCsrExpressions[4+index.val]? = some (.publicWord index.val) := by
    fin_cases index <;> decide
  exact actual_csr_node_field_equation pub found

def sourceAssetBit (asset level : Nat) : Nat := (asset / 2^level) % 2

theorem actual_stable_bit_coefficient (pub : Nat → F) (level : Fin 4) :
    actualCsrCoefficients pub (316+level.val) = (sourceAssetBit (pub 84).val level.val : F) := by
  have found : exactCsrExpressions[316+level.val]? = some (.bit 88 level.val) := by
    fin_cases level <;> decide
  have current := actual_csr_node_field_equation pub found
  have asset := actual_public_coefficient pub ⟨84,by decide⟩
  change actualCsrCoefficients pub 88 = pub 84 at asset
  simpa only [expressionField,asset,sourceAssetBit] using current

theorem actual_stable_orientation_coefficients (pub : Nat → F) (level : Fin 4) :
    actualCsrCoefficients pub (348+3*level.val) = -(1-(sourceAssetBit (pub 84).val level.val : F)) ∧
    actualCsrCoefficients pub (349+3*level.val) = -(sourceAssetBit (pub 84).val level.val : F) := by
  have positiveNode : exactCsrExpressions[347+3*level.val]? = some (.sub 1 (316+level.val)) := by
    fin_cases level <;> decide
  have inverseNode : exactCsrExpressions[348+3*level.val]? = some (.sub 0 (347+3*level.val)) := by
    fin_cases level <;> decide
  have negativeNode : exactCsrExpressions[349+3*level.val]? = some (.sub 0 (316+level.val)) := by
    fin_cases level <;> decide
  have positive := actual_csr_node_field_equation pub positiveNode
  have inverse := actual_csr_node_field_equation pub inverseNode
  have negative := actual_csr_node_field_equation pub negativeNode
  simp only [expressionField,(actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,
    actual_stable_bit_coefficient pub level,zero_sub] at positive inverse negative
  rw [positive] at inverse
  exact ⟨inverse,negative⟩

theorem source_asset_low_four (asset : Nat) :
    sourceAssetBit asset 0 + 2*sourceAssetBit asset 1 + 4*sourceAssetBit asset 2 +
      8*sourceAssetBit asset 3 = asset % 16 := by
  simp only [sourceAssetBit,Nat.pow_zero,Nat.pow_one,Nat.reducePow,Nat.div_one]
  omega

theorem source_asset_bit_mask (asset : Nat) (level : Fin 4) :
    sourceAssetBit (asset%16) level.val = sourceAssetBit asset level.val := by
  fin_cases level <;> simp only [sourceAssetBit,Nat.pow_zero,Nat.pow_one,Nat.reducePow,Nat.div_one] <;> omega

theorem actual_stable_index_coefficient (pub : Nat → F) :
    actualCsrCoefficients pub 346 = ((pub 84).val % 16 : Nat) := by
  have c2 := actual_csr_node_field_equation pub (show exactCsrExpressions[2]? = some (.constant 2) by decide)
  have c4 := actual_csr_node_field_equation pub (show exactCsrExpressions[128]? = some (.constant 4) by decide)
  have c8 := actual_csr_node_field_equation pub (show exactCsrExpressions[207]? = some (.constant 8) by decide)
  have m1 := actual_csr_node_field_equation pub (show exactCsrExpressions[341]? = some (.mul 2 317) by decide)
  have a1 := actual_csr_node_field_equation pub (show exactCsrExpressions[342]? = some (.add 316 341) by decide)
  have m2 := actual_csr_node_field_equation pub (show exactCsrExpressions[343]? = some (.mul 128 318) by decide)
  have a2 := actual_csr_node_field_equation pub (show exactCsrExpressions[344]? = some (.add 342 343) by decide)
  have m3 := actual_csr_node_field_equation pub (show exactCsrExpressions[345]? = some (.mul 207 319) by decide)
  have a3 := actual_csr_node_field_equation pub (show exactCsrExpressions[346]? = some (.add 344 345) by decide)
  have b0 := actual_stable_bit_coefficient pub ⟨0,by decide⟩
  have b1 := actual_stable_bit_coefficient pub ⟨1,by decide⟩
  have b2 := actual_stable_bit_coefficient pub ⟨2,by decide⟩
  have b3 := actual_stable_bit_coefficient pub ⟨3,by decide⟩
  simp only [Nat.add_zero,Nat.reduceAdd] at b0 b1 b2 b3
  simp only [expressionField,Nat.cast_ofNat] at c2 c4 c8 m1 a1 m2 a2 m3 a3
  rw [a3,a2,a1,m1,m2,m3,c2,c4,c8,b0,b1,b2,b3]
  simpa only [Nat.cast_add,Nat.cast_mul,Nat.cast_ofNat] using
    congrArg (fun value : Nat => (value : F)) (source_asset_low_four (pub 84).val)

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableStateCoefficients

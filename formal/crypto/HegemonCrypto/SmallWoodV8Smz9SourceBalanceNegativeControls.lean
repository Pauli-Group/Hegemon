import HegemonCrypto.SmallWoodV8Smz9SourceFullBalanceRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceBalanceRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

theorem actual_zero_rows_balance_formula (pub : Nat → F) (slot : Fin 4) :
    fieldAt exactNonlinearExpressions pub (fun _ => 0) (balanceRootSourceAt slot.val).root =
      -fieldAt exactNonlinearExpressions pub (fun _ => 0) (balanceRootSourceAt slot.val).expected := by
  rw [actual_balance_root_formula _ (balance_root_source_at_valid slot.isLt).1]
  simp only [sourceDelta,sourceContribution,mul_zero,zero_add,sub_self,zero_sub]

/-- Positive fee with no input/output values violates the actual native balance root. -/
theorem actual_native_fee_without_value_negative_control :
    fieldAt exactNonlinearExpressions (fun index => if index = 44 then 1 else 0) (fun _ => 0) 1149 = -1 := by
  have root := actual_zero_rows_balance_formula (fun index => if index = 44 then 1 else 0)
    (⟨0,by decide⟩ : Fin 4)
  change fieldAt exactNonlinearExpressions (fun index => if index = 44 then 1 else 0) (fun _ => 0) 1149 =
    -fieldAt exactNonlinearExpressions (fun index => if index = 44 then 1 else 0) (fun _ => 0) 1049 at root
  rw [(actual_expected_common_terms _ _).1] at root
  norm_num [signedFieldValue] at root ⊢
  exact root

theorem actual_native_fee_without_value_nonzero :
    fieldAt exactNonlinearExpressions (fun index => if index = 44 then 1 else 0) (fun _ => 0) 1149 ≠ 0 := by
  rw [actual_native_fee_without_value_negative_control]
  decide

/-- Deliberately malformed public data: nonzero issuance with zero note values
gives a nonzero root in every nonnative balance slot. No typed admission is claimed. -/
theorem actual_nonnative_issuance_without_value_negative_control (slot : Fin 3) :
    fieldAt exactNonlinearExpressions (fun _ => 1) (fun _ => 0)
      (balanceRootSourceAt (slot.val + 1)).root = 1 := by
  have bound : slot.val + 1 < 4 := by omega
  have root := actual_zero_rows_balance_formula (fun _ => 1) (⟨slot.val + 1,bound⟩ : Fin 4)
  have source := (balance_root_source_at_valid bound).2.2
  rw [if_neg (by omega : ¬slot.val + 1 = 0)] at source
  have selected := actual_node_field_equation (fun _ => (1 : F)) (fun _ => 0) source
  have asset : fieldAt exactNonlinearExpressions (fun _ => (1 : F)) (fun _ => 0) (58 + (slot.val + 1)) = 1 := by
    have read := actual_source_public (fun _ => (1 : F)) (fun _ => 0) (index := 54 + (slot.val + 1)) (by omega)
    simpa only [show 4 + (54 + (slot.val + 1)) = 58 + (slot.val + 1) by omega] using read
  have stableAsset : fieldAt exactNonlinearExpressions (fun _ => (1 : F)) (fun _ => 0) 63 = 1 :=
    actual_source_public _ _ (index := 59) (by decide)
  have enabled := (actual_stable_direction_terms (fun _ => (1 : F)) (fun _ => 0)).2.1
  have common := (actual_expected_common_terms (fun _ => (1 : F)) (fun _ => 0)).2
  simp only [expressionField,asset,stableAsset,if_true] at selected
  rw [selected,common,enabled] at root
  norm_num [stableEnabledPolynomial,signedFieldValue,
    inv_mul_cancel₀ (by decide : (2 : F) ≠ 0)] at root ⊢
  exact root

theorem actual_nonnative_issuance_without_value_nonzero (slot : Fin 3) :
    fieldAt exactNonlinearExpressions (fun _ => 1) (fun _ => 0)
      (balanceRootSourceAt (slot.val + 1)).root ≠ 0 := by
  rw [actual_nonnative_issuance_without_value_negative_control]
  decide

/-- Distinctness is essential: duplicate real assets make the source inverse
denominator zero and destroy the indicator property. This public profile is not canonical. -/
theorem duplicate_assets_destroy_indicator_negative_control :
    sourceWeight (fun _ => (1 : F)) 0 1 = 0 ∧
      sourceWeight (fun _ => (1 : F)) 0 1 ≠ 1 := by
  have nonpadding : (1 : F) ≠ (balancePaddingAssetId : F) := by decide
  norm_num [sourceWeight,interpolationTriple,assetFactor,nonpadding]


end
end HegemonCrypto.SmallWood.V8Smz9SourceBalanceRoots

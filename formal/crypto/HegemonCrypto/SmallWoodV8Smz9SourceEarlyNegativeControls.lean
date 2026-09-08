import HegemonCrypto.SmallWoodV8Smz9SourceEarlyPrefixRootCoverage

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

/-- The corrected descriptors align with the unchanged executable root list.
The four stale descriptor records remain explicit rejected controls. -/
theorem exact_early_descriptor_root_alignment_examples :
    exactNonlinearIdentities[63]? = some ⟨1025,[63,0,0,0],"base.input_asset_membership_excluding_padding"⟩ ∧
    exactNonlinearRoots[63]? = some 916 ∧
    exactNonlinearIdentities[95]? = some ⟨1025,[95,63,0,0],"base.input_direction_boolean"⟩ ∧
    exactNonlinearRoots[95]? = some 980 ∧
    exactNonlinearIdentities[98]? = some ⟨1025,[98,0,0,0],"base.output_inactive_ciphertext"⟩ ∧
    exactNonlinearRoots[98]? = some 1006 ∧
    exactNonlinearIdentities[104]? = some ⟨1025,[104,1,0,0],"base.output_asset_membership_excluding_padding"⟩ ∧
    exactNonlinearRoots[104]? = some 1023 ∧
    exactNonlinearIdentities[63]? ≠ some ⟨1025,[63,32,0,0],"base.input_direction_boolean"⟩ ∧
    exactNonlinearIdentities[95]? ≠ some ⟨1025,[95,0,0,0],"base.input_asset_membership_excluding_padding"⟩ ∧
    exactNonlinearIdentities[98]? ≠ some ⟨1025,[98,1,0,0],"base.output_asset_membership_excluding_padding"⟩ ∧
    exactNonlinearIdentities[104]? ≠ some ⟨1025,[104,5,0,0],"base.output_inactive_ciphertext"⟩ := by decide

noncomputable section

theorem actual_public_boolean_negative_nonzero (rows : Nat → F) :
    fieldAt exactNonlinearExpressions (fun _ => 2) rows 811 ≠ 0 := by
  rw [public_boolean_two_negative_control]
  decide

theorem actual_path_boolean_negative_nonzero (pub : Nat → F) :
    fieldAt exactNonlinearExpressions pub (fun _ => 2) 841 ≠ 0 := by
  rw [path_boolean_two_negative_control]
  decide

theorem actual_reserved_negative_nonzero (rows : Nat → F) :
    fieldAt exactNonlinearExpressions (fun _ => 1) rows 67 ≠ 0 := by
  rw [reserved_one_negative_control]
  decide

theorem actual_inactive_ciphertext_negative_nonzero :
    fieldAt exactNonlinearExpressions (fun _ => 0) (fun _ => 1) 1006 ≠ 0 := by
  have formula := actual_ciphertext_root_formula (fun _ => 0) (fun _ => 1)
    (⟨0,by decide⟩ : Fin 2) (⟨0,by decide⟩ : Fin 6)
  change fieldAt exactNonlinearExpressions (fun _ => 0) (fun _ => 1) 1006 = 1 * (1 - 0) at formula
  rw [formula]
  norm_num

theorem actual_unlisted_note_asset_negative_nonzero :
    fieldAt exactNonlinearExpressions (fun _ => 1) (fun _ => 2) 916 ≠ 0 := by
  have formula := actual_asset_root_formula (assetRootAt 0) (asset_root_at_valid (by decide : 0 < 4)).1
    (fun _ => 1) (fun _ => 2)
  change fieldAt exactNonlinearExpressions (fun _ => 1) (fun _ => 2) 916 =
    1 * (((assetFactor 2 1 * assetFactor 2 1) * assetFactor 2 1) * assetFactor 2 1) at formula
  rw [formula]
  have nonpadding : (1 : F) ≠ (balancePaddingAssetId : F) := by decide
  norm_num [assetFactor,nonpadding]








end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

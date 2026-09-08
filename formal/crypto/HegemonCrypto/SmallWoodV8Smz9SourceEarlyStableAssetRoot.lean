import HegemonCrypto.SmallWoodV8Smz9SourceEarlyAssetRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem canonical_stable_asset_membership (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    statement.compatibility.enabled = 0 ∨
      statement.compatibility.assetId < fieldModulus ∧
      statement.compatibility.assetId ≠ balancePaddingAssetId ∧
      statement.balanceAssets.count statement.compatibility.assetId = 1 := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,compatibility,_⟩ := canonical
  have bound : 2 ^ 32 < fieldModulus := by decide
  cases mode : statement.stablecoin.direction <;>
    simp [CanonicalCompatibility,mode] at compatibility <;> omega

theorem counted_asset_has_slot (assets : List Nat) (asset : Nat)
    (length : assets.length = 4) (count : assets.count asset = 1) :
    ∃ slot, slot < 4 ∧ wordAt assets slot = asset := by
  have member : asset ∈ assets := List.count_pos_iff.mp (by omega)
  obtain ⟨slot,bound,equal⟩ := List.mem_iff_getElem.mp member
  exact ⟨slot,by omega,by simpa only [wordAt,List.getD_eq_getElem?_getD,
    List.getElem?_eq_getElem bound,Option.getD_some] using equal⟩

noncomputable section

theorem actual_stable_asset_root_formula (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 1042 = stableEnabledPolynomial pub *
      (((assetFactor (pub 59) (pub 54) * assetFactor (pub 59) (pub 55)) *
        assetFactor (pub 59) (pub 56)) * assetFactor (pub 59) (pub 57)) := by
  have one := (actual_source_constants pub rows).2.1
  have padding := actual_node_field_equation pub rows (node := 905)
    (expression := .constant balancePaddingAssetId) (by decide)
  have asset : fieldAt exactNonlinearExpressions pub rows 63 = pub 59 :=
    actual_source_public pub rows (index := 59) (by decide)
  have candidates : ∀ slot : Fin 4,
      fieldAt exactNonlinearExpressions pub rows (58 + slot.val) = pub (54 + slot.val) := by
    intro slot
    have read := actual_source_public pub rows (index := 54 + slot.val) (by omega)
    simpa only [show 4 + (54 + slot.val) = 58 + slot.val by omega] using read
  have c0 : fieldAt exactNonlinearExpressions pub rows 58 = pub 54 := candidates ⟨0,by decide⟩
  have c1 : fieldAt exactNonlinearExpressions pub rows 59 = pub 55 := candidates ⟨1,by decide⟩
  have c2 : fieldAt exactNonlinearExpressions pub rows 60 = pub 56 := candidates ⟨2,by decide⟩
  have c3 : fieldAt exactNonlinearExpressions pub rows 61 = pub 57 := candidates ⟨3,by decide⟩
  have n1031 := actual_node_field_equation pub rows (node := 1031) (expression := .sub 63 58) (by decide)
  have n1032 := actual_node_field_equation pub rows (node := 1032) (expression := .selectEqual 58 905 1 1031) (by decide)
  have n1033 := actual_node_field_equation pub rows (node := 1033) (expression := .sub 63 59) (by decide)
  have n1034 := actual_node_field_equation pub rows (node := 1034) (expression := .selectEqual 59 905 1 1033) (by decide)
  have n1035 := actual_node_field_equation pub rows (node := 1035) (expression := .mul 1032 1034) (by decide)
  have n1036 := actual_node_field_equation pub rows (node := 1036) (expression := .sub 63 60) (by decide)
  have n1037 := actual_node_field_equation pub rows (node := 1037) (expression := .selectEqual 60 905 1 1036) (by decide)
  have n1038 := actual_node_field_equation pub rows (node := 1038) (expression := .mul 1035 1037) (by decide)
  have n1039 := actual_node_field_equation pub rows (node := 1039) (expression := .sub 63 61) (by decide)
  have n1040 := actual_node_field_equation pub rows (node := 1040) (expression := .selectEqual 61 905 1 1039) (by decide)
  have n1041 := actual_node_field_equation pub rows (node := 1041) (expression := .mul 1038 1040) (by decide)
  have n1042 := actual_node_field_equation pub rows (node := 1042) (expression := .mul 832 1041) (by decide)
  simp only [expressionField] at padding n1031 n1032 n1033 n1034 n1035 n1036 n1037 n1038 n1039 n1040 n1041 n1042
  rw [asset,c0] at n1031
  rw [asset,c1] at n1033
  rw [asset,c2] at n1036
  rw [asset,c3] at n1039
  rw [c0,padding,one,n1031] at n1032
  rw [c1,padding,one,n1033] at n1034
  rw [c2,padding,one,n1036] at n1037
  rw [c3,padding,one,n1039] at n1040
  rw [(actual_stable_direction_terms pub rows).2.1,n1041,n1038,n1035,n1032,n1034,n1037,n1040] at n1042
  exact n1042

theorem canonical_stable_asset_root_zero (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) (rows : Nat → F) :
    fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 1042 = 0 := by
  rw [actual_stable_asset_root_formula,(canonical_stable_enabled_and_mint statement canonical).1]
  rcases canonical_stable_asset_membership statement canonical with disabled | enabled
  · rw [disabled,Nat.cast_zero,zero_mul]
  · have asset : encodedPublicField statement 59 = (statement.compatibility.assetId : F) := by
      have read := encoded_compatibility_scalar statement canonical (by decide : 1 < 5)
      change (encodePublicStatement statement).getD 59 0 = statement.compatibility.assetId at read
      exact congrArg (fun n : Nat => (n : F)) read
    have nonpadding : (statement.compatibility.assetId : F) ≠ (balancePaddingAssetId : F) := by
      intro equal
      exact enabled.2.1 (canonical_nat_cast_injective enabled.1 balance_padding_asset_id_is_canonical equal)
    have matched : ∃ slot, slot < 4 ∧ encodedPublicField statement (54 + slot) =
        (statement.compatibility.assetId : F) := by
      obtain ⟨slot,bound,equal⟩ := counted_asset_has_slot statement.balanceAssets
        statement.compatibility.assetId (admitted_public_lengths statement canonical).2.2.2.2.2.2 enabled.2.2
      exact ⟨slot,bound,by simp only [encodedPublicField,encoded_balance_asset statement canonical bound,equal]⟩
    have zero := matching_asset_factors_zero (statement.compatibility.assetId : F)
      (fun slot => encodedPublicField statement (54 + slot)) matched nonpadding
    rw [asset,zero,mul_zero]

theorem full_candidate_stable_asset_root_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[111]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [show exactNonlinearRoots[111]? = some 1042 by decide,Option.map_some,
    canonical_stable_asset_root_zero statement valid.1]







end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

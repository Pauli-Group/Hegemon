import HegemonCrypto.SmallWoodV8Smz9SourceBalanceContributions

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

theorem canonical_balance_public_words (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    (encodePublicStatement statement).getD 44 0 = statement.fee ∧
    (encodePublicStatement statement).getD 45 0 = 0 ∧
    (encodePublicStatement statement).getD 46 0 = 0 ∧
    (encodePublicStatement statement).getD 58 0 = statement.compatibility.enabled ∧
    (encodePublicStatement statement).getD 59 0 = statement.compatibility.assetId ∧
    (encodePublicStatement statement).getD 61 0 = statement.compatibility.issuanceSign ∧
    (encodePublicStatement statement).getD 62 0 = statement.compatibility.issuanceMagnitude := by
  have facts := canonical
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,signZero,magnitudeZero,_⟩ := facts
  exact ⟨encoded_balance_scalar statement canonical (index := 0) (by decide),
    (encoded_balance_scalar statement canonical (index := 1) (by decide)).trans signZero,
    (encoded_balance_scalar statement canonical (index := 2) (by decide)).trans magnitudeZero,
    encoded_compatibility_scalar statement canonical (index := 0) (by decide),
    encoded_compatibility_scalar statement canonical (index := 1) (by decide),
    encoded_compatibility_scalar statement canonical (index := 3) (by decide),
    encoded_compatibility_scalar statement canonical (index := 4) (by decide)⟩

theorem canonical_compatibility_asset_canonical (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    statement.compatibility.assetId < fieldModulus := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,compatibility,_⟩ := canonical
  have bound : 2 ^ 32 < fieldModulus := by decide
  cases mode : statement.stablecoin.direction <;>
    simp [CanonicalCompatibility,mode] at compatibility <;> omega

theorem canonical_native_slot_iff (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) (slot : Fin 4) :
    wordAt statement.balanceAssets slot.val = nativeAssetId ↔ slot.val = 0 := by
  have assets := canonical_assets statement canonical
  constructor
  · intro native
    by_contra nonzero
    have positive : 0 < slot.val := by omega
    have firstReal : wordAt statement.balanceAssets 0 ≠ balancePaddingAssetId := by
      rw [assets.2.1]
      decide
    have slotReal : wordAt statement.balanceAssets slot.val ≠ balancePaddingAssetId := by
      rw [native]
      decide
    have ordered := assets.2.2.2.1 0 slot.val positive slot.isLt firstReal slotReal
    rw [assets.2.1,native] at ordered
    exact Nat.lt_irrefl _ ordered
  · intro zero
    rw [zero]
    exact assets.2.1

noncomputable section

theorem canonical_source_expected_field (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) (slot : Fin 4) :
    sourceExpected (encodedPublicField statement) slot.val =
      typedExpectedField statement (wordAt statement.balanceAssets slot.val) := by
  have fields := canonical_balance_public_words statement canonical
  have asset := encoded_balance_asset statement canonical slot.isLt
  have nativeIff := canonical_native_slot_iff statement canonical slot
  have facts := canonical
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,compatibility,_⟩ := facts
  by_cases native : wordAt statement.balanceAssets slot.val = nativeAssetId
  · have slotZero := nativeIff.mp native
    rw [sourceExpected,if_pos slotZero,typedExpectedField,if_pos native]
    simp only [encodedPublicField,fields.1,fields.2.1,fields.2.2.1,Nat.cast_zero,signedFieldValue,
      zero_add,mul_zero,sub_self,sub_zero]
  · have slotNonzero : slot.val ≠ 0 := by
      intro zero
      exact native (nativeIff.mpr zero)
    have comparison : (wordAt statement.balanceAssets slot.val : F) = (statement.compatibility.assetId : F) ↔
        statement.compatibility.assetId = wordAt statement.balanceAssets slot.val := by
      constructor
      · intro equal
        exact (canonical_nat_cast_injective ((canonical_assets statement canonical).2.2.1 slot.val slot.isLt)
          (canonical_compatibility_asset_canonical statement canonical) equal).symm
      · intro equal
        rw [equal]
    simp only [sourceExpected,if_neg slotNonzero,encodedPublicField,asset,fields.2.2.2.1,
      fields.2.2.2.2.1,fields.2.2.2.2.2.1,fields.2.2.2.2.2.2,
      typedExpectedField,if_neg native,comparison]
    rcases compatibility.1 with disabled | enabled
    · simp [disabled]
    · rw [enabled]
      by_cases matching : statement.compatibility.assetId = wordAt statement.balanceAssets slot.val
      · simp only [matching,if_true,and_self,Nat.cast_one,one_mul]
        rcases compatibility.2.1 with signZero | signOne
        · simp [signedFieldValue,signZero]
        · simp only [signedFieldValue,signOne,if_true,Nat.cast_one]
          ring
      · simp [matching]

theorem canonical_actual_expected_field (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) (rows : Nat → F) (slot : Fin 4) :
    fieldAt exactNonlinearExpressions (encodedPublicField statement) rows (balanceRootSourceAt slot.val).expected =
      typedExpectedField statement (wordAt statement.balanceAssets slot.val) := by
  rw [← canonical_source_expected_field statement canonical slot]
  have source := balance_root_source_at_valid slot.isLt
  have common := actual_expected_common_terms (encodedPublicField statement) rows
  by_cases native : slot.val = 0
  · rw [if_pos native] at source
    rw [source.2.2,sourceExpected,if_pos native,common.1]
  · rw [if_neg native] at source
    have selected := actual_node_field_equation (encodedPublicField statement) rows source.2.2
    have asset : fieldAt exactNonlinearExpressions (encodedPublicField statement) rows (58 + slot.val) =
        encodedPublicField statement (54 + slot.val) := by
      have read := actual_source_public (encodedPublicField statement) rows (index := 54 + slot.val) (by omega)
      simpa only [show 4 + (54 + slot.val) = 58 + slot.val by omega] using read
    have stableAsset : fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 63 =
        encodedPublicField statement 59 := actual_source_public _ _ (index := 59) (by decide)
    have enabled : fieldAt exactNonlinearExpressions (encodedPublicField statement) rows 832 =
        encodedPublicField statement 58 := by
      rw [(actual_stable_direction_terms (encodedPublicField statement) rows).2.1,
        (canonical_stable_enabled_and_mint statement canonical).1]
      exact (congrArg (fun n : Nat => (n : F)) (canonical_balance_public_words statement canonical).2.2.2.1).symm
    simpa only [expressionField,sourceExpected,if_neg native,asset,stableAsset,common.2,enabled,
      (actual_source_constants (encodedPublicField statement) rows).1] using selected

theorem canonical_padding_expected_zero (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    typedExpectedField statement balancePaddingAssetId = 0 := by
  have nonnative : balancePaddingAssetId ≠ nativeAssetId := by decide
  rcases canonical_stable_asset_membership statement canonical with disabled | enabled
  · simp [typedExpectedField,nonnative,disabled]
  · simp [typedExpectedField,nonnative,enabled.2.1]

theorem typed_nonpadding_field_balance (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 4)
    (nonpadding : wordAt statement.balanceAssets slot.val ≠ balancePaddingAssetId) :
    (inputValueForAsset witness (wordAt statement.balanceAssets slot.val) : F) -
      (outputValueForAsset witness (wordAt statement.balanceAssets slot.val) : F) =
      typedExpectedField statement (wordAt statement.balanceAssets slot.val) := by
  have balance := (valid.2.2.2.1 slot.val slot.isLt).resolve_left nonpadding
  by_cases native : wordAt statement.balanceAssets slot.val = nativeAssetId
  · rw [if_pos native] at balance
    rw [typedExpectedField,if_pos native]
    have lifted := congrArg (fun n : Nat => (n : F)) balance
    simp only [Nat.cast_add] at lifted
    linear_combination lifted
  · rw [if_neg native] at balance
    rw [typedExpectedField,if_neg native]
    by_cases stable : statement.compatibility.enabled = 1 ∧
        statement.compatibility.assetId = wordAt statement.balanceAssets slot.val
    · rw [if_pos stable] at balance
      rw [if_pos stable]
      by_cases mint : statement.compatibility.issuanceSign = 1
      · rw [if_pos mint] at balance
        rw [if_pos mint]
        have lifted := congrArg (fun n : Nat => (n : F)) balance
        simp only [Nat.cast_add] at lifted
        linear_combination lifted
      · rw [if_neg mint] at balance
        rw [if_neg mint]
        have lifted := congrArg (fun n : Nat => (n : F)) balance
        simp only [Nat.cast_add] at lifted
        linear_combination lifted
    · rw [if_neg stable] at balance
      rw [if_neg stable,balance,sub_self]


end
end HegemonCrypto.SmallWood.V8Smz9SourceBalanceRoots

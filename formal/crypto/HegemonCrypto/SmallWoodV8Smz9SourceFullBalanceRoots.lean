import HegemonCrypto.SmallWoodV8Smz9SourceBalanceExpected
import HegemonCrypto.SmallWoodV8Smz9SourceEarlyPrefixRootCoverage

namespace HegemonCrypto.SmallWood.V8Smz9SourceBalanceRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem exact_balance_root_indices (slot : Fin 4) :
    exactNonlinearRoots[112 + slot.val]? = some (balanceRootSourceAt slot.val).root := by
  have finite : ∀ s : Fin 4,
      exactNonlinearRoots[112 + s.val]? = some (balanceRootSourceAt s.val).root := by decide
  exact finite slot

noncomputable section

theorem source_delta_padding_zero (pub rows : Nat → F) (slot : Nat)
    (padding : pub (54 + slot) = (balancePaddingAssetId : F)) :
    sourceDelta pub rows slot = 0 := by
  simp only [sourceDelta,sourceContribution,sourceWeight,padding,if_true,zero_mul,zero_add,sub_self]

theorem full_candidate_balance_expression_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (slot : Fin 4) :
    fieldAt exactNonlinearExpressions (encodedPublicField statement)
      (laneField (fullTypedSourceCandidate statement witness) lane.val) (balanceRootSourceAt slot.val).root = 0 := by
  rw [actual_balance_root_formula _ (balance_root_source_at_valid slot.isLt).1,
    (balance_root_source_at_valid slot.isLt).2.1,
    canonical_actual_expected_field statement valid.1]
  by_cases padding : wordAt statement.balanceAssets slot.val = balancePaddingAssetId
  · have fieldPadding : encodedPublicField statement (54 + slot.val) = (balancePaddingAssetId : F) := by
      simp only [encodedPublicField,encoded_balance_asset statement valid.1 slot.isLt,padding]
    rw [source_delta_padding_zero _ _ _ fieldPadding,padding,canonical_padding_expected_zero statement valid.1,sub_self]
  · rw [full_candidate_source_delta statement witness valid lane slot,
      typed_nonpadding_field_balance statement witness valid slot padding,sub_self]

theorem full_candidate_actual_balance_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (slot : Fin 4) :
    (exactNonlinearRoots[112 + slot.val]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [exact_balance_root_indices,Option.map_some,full_candidate_balance_expression_roots_zero statement witness valid]

theorem full_candidate_first116_nonlinear_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (root : Fin 116) :
    (exactNonlinearRoots[root.val]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  by_cases early : root.val < 112
  · exact full_candidate_first112_nonlinear_roots_zero statement witness valid lane ⟨root.val,early⟩
  · have zero := full_candidate_actual_balance_roots_zero statement witness valid lane ⟨root.val - 112,by omega⟩
    have address : 112 + (root.val - 112) = root.val := by omega
    exact address ▸ zero


end
end HegemonCrypto.SmallWood.V8Smz9SourceBalanceRoots

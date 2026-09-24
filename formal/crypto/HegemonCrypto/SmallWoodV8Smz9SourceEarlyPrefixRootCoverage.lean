import HegemonCrypto.SmallWoodV8Smz9SourceEarlyStableAssetRoot

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

/-- Exact contiguous coverage. The four balance roots 112 through 115 are not
claimed here. Root indices refer to the actual executable root list, not labels. -/
theorem full_candidate_first112_nonlinear_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (root : Fin 112) :
    (exactNonlinearRoots[root.val]?).map
      (fieldAt exactNonlinearExpressions (encodedPublicField statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  by_cases publicFlags : root.val < 7
  · exact full_candidate_public_boolean_roots_zero statement witness valid lane ⟨root.val,publicFlags⟩
  by_cases stablePublic : root.val < 13
  · have zero := full_candidate_stable_public_roots_zero statement witness valid lane
      ⟨root.val - 7,by omega⟩
    have address : 7 + (root.val - 7) = root.val := by omega
    exact address ▸ zero
  by_cases reserved : root.val < 31
  · have zero := full_candidate_reserved_roots_zero statement witness valid lane ⟨root.val - 13,by omega⟩
    have address : 13 + (root.val - 13) = root.val := by omega
    exact address ▸ zero
  by_cases firstPath : root.val < 63
  · have zero := full_candidate_all_path_roots_zero statement witness (encodedPublicField statement) lane
      ⟨0,by decide⟩ ⟨root.val - 31,by omega⟩
    have address : pathRootIndex 0 (root.val - 31) = root.val := by change 31 + (root.val - 31) = root.val; omega
    exact address ▸ zero
  by_cases firstAsset : root.val = 63
  · rw [firstAsset]
    exact full_candidate_note_asset_roots_zero statement witness valid lane ⟨0,by decide⟩
  by_cases secondPath : root.val < 96
  · have zero := full_candidate_all_path_roots_zero statement witness (encodedPublicField statement) lane
      ⟨1,by decide⟩ ⟨root.val - 64,by omega⟩
    have address : pathRootIndex 1 (root.val - 64) = root.val := by simp only [pathRootIndex,if_neg Nat.one_ne_zero]; omega
    exact address ▸ zero
  by_cases secondAsset : root.val = 96
  · rw [secondAsset]
    exact full_candidate_note_asset_roots_zero statement witness valid lane ⟨1,by decide⟩
  by_cases firstOutputAsset : root.val = 97
  · rw [firstOutputAsset]
    exact full_candidate_note_asset_roots_zero statement witness valid lane ⟨2,by decide⟩
  by_cases firstCiphertext : root.val < 104
  · have zero := full_candidate_inactive_ciphertext_roots_zero statement witness valid lane
      ⟨0,by decide⟩ ⟨root.val - 98,by omega⟩
    have address : ciphertextRootIndex 0 (root.val - 98) = root.val := by change 98 + (root.val - 98) = root.val; omega
    exact address ▸ zero
  by_cases secondOutputAsset : root.val = 104
  · rw [secondOutputAsset]
    exact full_candidate_note_asset_roots_zero statement witness valid lane ⟨3,by decide⟩
  by_cases secondCiphertext : root.val < 111
  · have zero := full_candidate_inactive_ciphertext_roots_zero statement witness valid lane
      ⟨1,by decide⟩ ⟨root.val - 105,by omega⟩
    have address : ciphertextRootIndex 1 (root.val - 105) = root.val := by simp only [ciphertextRootIndex,if_neg Nat.one_ne_zero]; omega
    exact address ▸ zero
  have last : root.val = 111 := by omega
  rw [last]
  exact full_candidate_stable_asset_root_zero statement witness valid lane



end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

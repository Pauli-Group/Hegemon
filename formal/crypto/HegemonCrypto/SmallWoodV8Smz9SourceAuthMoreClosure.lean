import HegemonCrypto.SmallWoodV8Smz9SourceAuthRemainingClosure
import HegemonCrypto.SmallWoodV8Smz9SourceAuthMoreDAG

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthMoreClosure
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMoreDAG
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem remaining_named_readback (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) (row : Nat) (family : AuthFamily) (index : Nat)
    (bound : index < family.width) (address : row = 92+family.base+index) :
    laneField (fullTypedSourceCandidate statement witness) lane.val row =
      (authFamilyWord statement witness (typedSourceFinals statement witness) family index : F) := by
  rw [address]
  exact full_candidate_auth_family statement witness family index bound lane

theorem candidate_root_298 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[298]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_298,remaining_auth_readback statement witness lane 155 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (155-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) false (⟨0,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_300 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[300]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_300,remaining_auth_readback statement witness lane 156 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (156-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) false (⟨1,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_302 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[302]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_302,remaining_auth_readback statement witness lane 157 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (157-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) false (⟨2,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_304 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[304]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_304,remaining_auth_readback statement witness lane 158 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (158-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) false (⟨3,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_306 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[306]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_306,remaining_auth_readback statement witness lane 159 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (159-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) false (⟨4,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_308 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[308]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_308,remaining_auth_readback statement witness lane 160 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (160-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) false (⟨5,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_311 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[311]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_311,remaining_auth_readback statement witness lane 162 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (162-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) true (⟨0,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_313 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[313]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_313,remaining_auth_readback statement witness lane 163 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (163-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) true (⟨1,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_315 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[315]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_315,remaining_auth_readback statement witness lane 164 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (164-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) true (⟨2,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_317 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[317]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_317,remaining_auth_readback statement witness lane 165 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (165-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) true (⟨3,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_319 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[319]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_319,remaining_auth_readback statement witness lane 166 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (166-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) true (⟨4,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_321 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[321]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_321,remaining_auth_readback statement witness lane 167 (by decide) (by decide),
    bit_polynomial _ (show BooleanWord (sourceAuthRow statement witness (typedSourceFinals statement witness) (167-92)) from
      source_bitmap_row_boolean statement witness valid (typedSourceFinals statement witness) true (⟨5,by decide⟩ : Fin 6)),mul_zero]

theorem candidate_root_346 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[346]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_346,
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 105 .legacy 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 196 .policyTag 0 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 0 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 0 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 0 []) 0 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 0 ⟨0,by decide⟩,mul_zero]

theorem candidate_root_347 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[347]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_347,
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 106 .legacy 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 197 .policyTag 1 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 0 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 1 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 0 []) 1 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 0 ⟨1,by decide⟩,mul_zero]

theorem candidate_root_348 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[348]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_348,
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 107 .legacy 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 198 .policyTag 2 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 0 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 2 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 0 []) 2 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 0 ⟨2,by decide⟩,mul_zero]

theorem candidate_root_349 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[349]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_349,
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 108 .legacy 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 199 .policyTag 3 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 0 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 3 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 0 []) 3 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 0 ⟨3,by decide⟩,mul_zero]

theorem candidate_root_350 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[350]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_350,
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 109 .legacy 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 200 .policyTag 4 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 0 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 4 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 0 []) 4 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 0 ⟨4,by decide⟩,mul_zero]

theorem candidate_root_352 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[352]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_352,
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 105 .legacy 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 201 .policyTag 5 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 1 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 0 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 1 []) 0 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 1 ⟨0,by decide⟩,mul_zero]

theorem candidate_root_353 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[353]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_353,
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 106 .legacy 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 202 .policyTag 6 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 1 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 1 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 1 []) 1 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 1 ⟨1,by decide⟩,mul_zero]

theorem candidate_root_354 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[354]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_354,
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 107 .legacy 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 203 .policyTag 7 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 1 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 2 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 1 []) 2 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 1 ⟨2,by decide⟩,mul_zero]

theorem candidate_root_355 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[355]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_355,
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 108 .legacy 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 204 .policyTag 8 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 1 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 3 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 1 []) 3 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 1 ⟨3,by decide⟩,mul_zero]

theorem candidate_root_356 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[356]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_356,
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 109 .legacy 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 205 .policyTag 9 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 1 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 4 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 1 []) 4 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 1 ⟨4,by decide⟩,mul_zero]

theorem candidate_root_358 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[358]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_358,
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 105 .legacy 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 206 .policyTag 10 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 2 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 0 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 2 []) 0 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 2 ⟨0,by decide⟩,mul_zero]

theorem candidate_root_359 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[359]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_359,
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 106 .legacy 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 207 .policyTag 11 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 2 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 1 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 2 []) 1 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 2 ⟨1,by decide⟩,mul_zero]

theorem candidate_root_360 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[360]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_360,
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 107 .legacy 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 208 .policyTag 12 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 2 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 2 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 2 []) 2 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 2 ⟨2,by decide⟩,mul_zero]

theorem candidate_root_361 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[361]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_361,
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 108 .legacy 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 209 .policyTag 13 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 2 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 3 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 2 []) 3 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 2 ⟨3,by decide⟩,mul_zero]

theorem candidate_root_362 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[362]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_362,
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 109 .legacy 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 210 .policyTag 14 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 2 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 4 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 2 []) 4 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 2 ⟨4,by decide⟩,mul_zero]

theorem candidate_root_364 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[364]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_364,
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 105 .legacy 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 211 .policyTag 15 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 3 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 0 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 3 []) 0 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 3 ⟨0,by decide⟩,mul_zero]

theorem candidate_root_365 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[365]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_365,
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 106 .legacy 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 212 .policyTag 16 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 3 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 1 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 3 []) 1 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 3 ⟨1,by decide⟩,mul_zero]

theorem candidate_root_366 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[366]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_366,
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 107 .legacy 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 213 .policyTag 17 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 3 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 2 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 3 []) 2 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 3 ⟨2,by decide⟩,mul_zero]

theorem candidate_root_367 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[367]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_367,
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 108 .legacy 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 214 .policyTag 18 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 3 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 3 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 3 []) 3 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 3 ⟨3,by decide⟩,mul_zero]

theorem candidate_root_368 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[368]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_368,
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 109 .legacy 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 215 .policyTag 19 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 3 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 4 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 3 []) 4 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 3 ⟨4,by decide⟩,mul_zero]

theorem candidate_root_370 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[370]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_370,
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 105 .legacy 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 216 .policyTag 20 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 4 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 0 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 4 []) 0 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 4 ⟨0,by decide⟩,mul_zero]

theorem candidate_root_371 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[371]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_371,
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 106 .legacy 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 217 .policyTag 21 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 4 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 1 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 4 []) 1 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 4 ⟨1,by decide⟩,mul_zero]

theorem candidate_root_372 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[372]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_372,
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 107 .legacy 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 218 .policyTag 22 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 4 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 2 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 4 []) 2 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 4 ⟨2,by decide⟩,mul_zero]

theorem candidate_root_373 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[373]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_373,
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 108 .legacy 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 219 .policyTag 23 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 4 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 3 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 4 []) 3 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 4 ⟨3,by decide⟩,mul_zero]

theorem candidate_root_374 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[374]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_374,
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 109 .legacy 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 220 .policyTag 24 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 4 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 4 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 4 []) 4 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 4 ⟨4,by decide⟩,mul_zero]

theorem candidate_root_376 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[376]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_376,
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 105 .legacy 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 221 .policyTag 25 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 5 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 0 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 5 []) 0 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 5 ⟨0,by decide⟩,mul_zero]

theorem candidate_root_377 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[377]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_377,
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 106 .legacy 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 222 .policyTag 26 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 5 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 1 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 5 []) 1 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 5 ⟨1,by decide⟩,mul_zero]

theorem candidate_root_378 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[378]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_378,
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 107 .legacy 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 223 .policyTag 27 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 5 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 2 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 5 []) 2 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 5 ⟨2,by decide⟩,mul_zero]

theorem candidate_root_379 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[379]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_379,
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 108 .legacy 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 224 .policyTag 28 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 5 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 3 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 5 []) 3 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 5 ⟨3,by decide⟩,mul_zero]

theorem candidate_root_380 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[380]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_380,
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 109 .legacy 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 225 .policyTag 29 (by decide) (by decide)]
  change some ((_ * (authMembership witness.authorization (typedSourceFinals statement witness) 5 : F)) *
    ((authHashWord (typedSourceFinals statement witness) 0 4 : F) -
      (wordAt (witness.authorization.policySignerTags.getD 5 []) 4 : F))) = some 0
  rw [mul_assoc,membership_tag_difference witness.authorization _ 5 ⟨4,by decide⟩,mul_zero]

def selectedMoreRoot (index : Fin 42) : Nat :=
  [298,300,302,304,306,308,311,313,315,317,319,321,346,347,348,349,350,352,353,354,355,356,358,359,360,361,362,364,365,366,367,368,370,371,372,373,374,376,377,378,379,380].getD index.val 0

theorem full_candidate_actual_42_more_auth_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (index : Fin 42) :
    (exactNonlinearRoots[selectedMoreRoot index]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  fin_cases index
  · exact candidate_root_298 statement witness valid lane
  · exact candidate_root_300 statement witness valid lane
  · exact candidate_root_302 statement witness valid lane
  · exact candidate_root_304 statement witness valid lane
  · exact candidate_root_306 statement witness valid lane
  · exact candidate_root_308 statement witness valid lane
  · exact candidate_root_311 statement witness valid lane
  · exact candidate_root_313 statement witness valid lane
  · exact candidate_root_315 statement witness valid lane
  · exact candidate_root_317 statement witness valid lane
  · exact candidate_root_319 statement witness valid lane
  · exact candidate_root_321 statement witness valid lane
  · exact candidate_root_346 statement witness valid lane
  · exact candidate_root_347 statement witness valid lane
  · exact candidate_root_348 statement witness valid lane
  · exact candidate_root_349 statement witness valid lane
  · exact candidate_root_350 statement witness valid lane
  · exact candidate_root_352 statement witness valid lane
  · exact candidate_root_353 statement witness valid lane
  · exact candidate_root_354 statement witness valid lane
  · exact candidate_root_355 statement witness valid lane
  · exact candidate_root_356 statement witness valid lane
  · exact candidate_root_358 statement witness valid lane
  · exact candidate_root_359 statement witness valid lane
  · exact candidate_root_360 statement witness valid lane
  · exact candidate_root_361 statement witness valid lane
  · exact candidate_root_362 statement witness valid lane
  · exact candidate_root_364 statement witness valid lane
  · exact candidate_root_365 statement witness valid lane
  · exact candidate_root_366 statement witness valid lane
  · exact candidate_root_367 statement witness valid lane
  · exact candidate_root_368 statement witness valid lane
  · exact candidate_root_370 statement witness valid lane
  · exact candidate_root_371 statement witness valid lane
  · exact candidate_root_372 statement witness valid lane
  · exact candidate_root_373 statement witness valid lane
  · exact candidate_root_374 statement witness valid lane
  · exact candidate_root_376 statement witness valid lane
  · exact candidate_root_377 statement witness valid lane
  · exact candidate_root_378 statement witness valid lane
  · exact candidate_root_379 statement witness valid lane
  · exact candidate_root_380 statement witness valid lane

theorem more_roots_disjoint :
    (List.ofFn selectedRemainingRoot ++ List.ofFn selectedMoreRoot).Nodup ∧
      (List.ofFn selectedRemainingRoot ++ List.ofFn selectedMoreRoot).length = 88 := by decide

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthMoreClosure

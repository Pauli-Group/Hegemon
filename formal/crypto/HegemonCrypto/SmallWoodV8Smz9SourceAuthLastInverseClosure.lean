import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastClosure
import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastInverse
import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastInverseDAG

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverseClosure
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMoreClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverse
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverseDAG
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem candidate_root_411 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[411]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_411,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 196 .policyTag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 201 .policyTag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 232 .distinctInverse 0 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))))) * (((authDistinctInverse witness.authorization 0 : F) * ((wordAt (witness.authorization.policySignerTags.getD 0 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 1 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_0,activity_cast_1]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨0,by decide⟩ : Fin 15)).1

theorem candidate_root_412 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[412]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_412,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 232 .distinctInverse 0 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 0 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))))))) = some 0
  rw [activity_cast_0,activity_cast_1]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨0,by decide⟩ : Fin 15)).2

theorem candidate_root_413 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[413]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_413,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 196 .policyTag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 206 .policyTag 10 (by decide) (by decide),
    remaining_named_readback statement witness lane 233 .distinctInverse 1 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))))) * (((authDistinctInverse witness.authorization 1 : F) * ((wordAt (witness.authorization.policySignerTags.getD 0 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 2 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_0,activity_cast_2]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨1,by decide⟩ : Fin 15)).1

theorem candidate_root_414 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[414]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_414,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 233 .distinctInverse 1 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 1 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))))))) = some 0
  rw [activity_cast_0,activity_cast_2]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨1,by decide⟩ : Fin 15)).2

theorem candidate_root_415 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[415]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_415,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 196 .policyTag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 211 .policyTag 15 (by decide) (by decide),
    remaining_named_readback statement witness lane 234 .distinctInverse 2 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))) * (((authDistinctInverse witness.authorization 2 : F) * ((wordAt (witness.authorization.policySignerTags.getD 0 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 3 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_0,activity_cast_3]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨2,by decide⟩ : Fin 15)).1

theorem candidate_root_416 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[416]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_416,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 234 .distinctInverse 2 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 2 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))))) = some 0
  rw [activity_cast_0,activity_cast_3]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨2,by decide⟩ : Fin 15)).2

theorem candidate_root_417 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[417]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_417,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 196 .policyTag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 216 .policyTag 20 (by decide) (by decide),
    remaining_named_readback statement witness lane 235 .distinctInverse 3 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))) * (((authDistinctInverse witness.authorization 3 : F) * ((wordAt (witness.authorization.policySignerTags.getD 0 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 4 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_0,activity_cast_4]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨3,by decide⟩ : Fin 15)).1

theorem candidate_root_418 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[418]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_418,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 235 .distinctInverse 3 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 3 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))))) = some 0
  rw [activity_cast_0,activity_cast_4]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨3,by decide⟩ : Fin 15)).2

theorem candidate_root_419 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[419]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_419,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 196 .policyTag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 221 .policyTag 25 (by decide) (by decide),
    remaining_named_readback statement witness lane 236 .distinctInverse 4 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))))) * (((authDistinctInverse witness.authorization 4 : F) * ((wordAt (witness.authorization.policySignerTags.getD 0 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 5 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_0,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨4,by decide⟩ : Fin 15)).1

theorem candidate_root_420 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[420]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_420,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 236 .distinctInverse 4 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 4 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))))))) = some 0
  rw [activity_cast_0,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨4,by decide⟩ : Fin 15)).2

theorem candidate_root_421 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[421]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_421,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 201 .policyTag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 206 .policyTag 10 (by decide) (by decide),
    remaining_named_readback statement witness lane 237 .distinctInverse 5 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))))) * (((authDistinctInverse witness.authorization 5 : F) * ((wordAt (witness.authorization.policySignerTags.getD 1 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 2 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_1,activity_cast_2]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨5,by decide⟩ : Fin 15)).1

theorem candidate_root_422 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[422]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_422,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 237 .distinctInverse 5 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 5 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))))))) = some 0
  rw [activity_cast_1,activity_cast_2]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨5,by decide⟩ : Fin 15)).2

theorem candidate_root_423 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[423]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_423,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 201 .policyTag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 211 .policyTag 15 (by decide) (by decide),
    remaining_named_readback statement witness lane 238 .distinctInverse 6 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))) * (((authDistinctInverse witness.authorization 6 : F) * ((wordAt (witness.authorization.policySignerTags.getD 1 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 3 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_1,activity_cast_3]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨6,by decide⟩ : Fin 15)).1

theorem candidate_root_424 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[424]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_424,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 238 .distinctInverse 6 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 6 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))))) = some 0
  rw [activity_cast_1,activity_cast_3]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨6,by decide⟩ : Fin 15)).2

theorem candidate_root_425 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[425]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_425,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 201 .policyTag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 216 .policyTag 20 (by decide) (by decide),
    remaining_named_readback statement witness lane 239 .distinctInverse 7 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))) * (((authDistinctInverse witness.authorization 7 : F) * ((wordAt (witness.authorization.policySignerTags.getD 1 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 4 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_1,activity_cast_4]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨7,by decide⟩ : Fin 15)).1

theorem candidate_root_426 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[426]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_426,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 239 .distinctInverse 7 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 7 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))))) = some 0
  rw [activity_cast_1,activity_cast_4]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨7,by decide⟩ : Fin 15)).2

theorem candidate_root_427 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[427]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_427,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 201 .policyTag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 221 .policyTag 25 (by decide) (by decide),
    remaining_named_readback statement witness lane 240 .distinctInverse 8 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))))) * (((authDistinctInverse witness.authorization 8 : F) * ((wordAt (witness.authorization.policySignerTags.getD 1 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 5 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_1,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨8,by decide⟩ : Fin 15)).1

theorem candidate_root_428 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[428]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_428,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 240 .distinctInverse 8 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 8 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))))))) = some 0
  rw [activity_cast_1,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨8,by decide⟩ : Fin 15)).2

theorem candidate_root_429 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[429]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_429,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 206 .policyTag 10 (by decide) (by decide),
    remaining_named_readback statement witness lane 211 .policyTag 15 (by decide) (by decide),
    remaining_named_readback statement witness lane 241 .distinctInverse 9 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))) * (((authDistinctInverse witness.authorization 9 : F) * ((wordAt (witness.authorization.policySignerTags.getD 2 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 3 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_2,activity_cast_3]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨9,by decide⟩ : Fin 15)).1

theorem candidate_root_430 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[430]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_430,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 241 .distinctInverse 9 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 9 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))))) = some 0
  rw [activity_cast_2,activity_cast_3]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨9,by decide⟩ : Fin 15)).2

theorem candidate_root_431 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[431]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_431,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 206 .policyTag 10 (by decide) (by decide),
    remaining_named_readback statement witness lane 216 .policyTag 20 (by decide) (by decide),
    remaining_named_readback statement witness lane 242 .distinctInverse 10 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))) * (((authDistinctInverse witness.authorization 10 : F) * ((wordAt (witness.authorization.policySignerTags.getD 2 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 4 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_2,activity_cast_4]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨10,by decide⟩ : Fin 15)).1

theorem candidate_root_432 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[432]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_432,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 242 .distinctInverse 10 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 10 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))))) = some 0
  rw [activity_cast_2,activity_cast_4]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨10,by decide⟩ : Fin 15)).2

theorem candidate_root_433 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[433]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_433,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 206 .policyTag 10 (by decide) (by decide),
    remaining_named_readback statement witness lane 221 .policyTag 25 (by decide) (by decide),
    remaining_named_readback statement witness lane 243 .distinctInverse 11 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))))) * (((authDistinctInverse witness.authorization 11 : F) * ((wordAt (witness.authorization.policySignerTags.getD 2 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 5 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_2,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨11,by decide⟩ : Fin 15)).1

theorem candidate_root_434 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[434]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_434,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 243 .distinctInverse 11 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 11 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))))))) = some 0
  rw [activity_cast_2,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨11,by decide⟩ : Fin 15)).2

theorem candidate_root_435 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[435]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_435,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 211 .policyTag 15 (by decide) (by decide),
    remaining_named_readback statement witness lane 216 .policyTag 20 (by decide) (by decide),
    remaining_named_readback statement witness lane 244 .distinctInverse 12 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))) * (((authDistinctInverse witness.authorization 12 : F) * ((wordAt (witness.authorization.policySignerTags.getD 3 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 4 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_3,activity_cast_4]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨12,by decide⟩ : Fin 15)).1

theorem candidate_root_436 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[436]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_436,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 244 .distinctInverse 12 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 12 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))))) = some 0
  rw [activity_cast_3,activity_cast_4]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨12,by decide⟩ : Fin 15)).2

theorem candidate_root_437 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[437]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_437,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 211 .policyTag 15 (by decide) (by decide),
    remaining_named_readback statement witness lane 221 .policyTag 25 (by decide) (by decide),
    remaining_named_readback statement witness lane 245 .distinctInverse 13 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))) * (((authDistinctInverse witness.authorization 13 : F) * ((wordAt (witness.authorization.policySignerTags.getD 3 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 5 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_3,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨13,by decide⟩ : Fin 15)).1

theorem candidate_root_438 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[438]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_438,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 245 .distinctInverse 13 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 13 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))))) = some 0
  rw [activity_cast_3,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨13,by decide⟩ : Fin 15)).2

theorem candidate_root_439 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[439]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_439,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 216 .policyTag 20 (by decide) (by decide),
    remaining_named_readback statement witness lane 221 .policyTag 25 (by decide) (by decide),
    remaining_named_readback statement witness lane 246 .distinctInverse 14 (by decide) (by decide)]
  change some ((((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))) * (((authDistinctInverse witness.authorization 14 : F) * ((wordAt (witness.authorization.policySignerTags.getD 4 []) 0 : F) - (wordAt (witness.authorization.policySignerTags.getD 5 []) 0 : F))) - 1)) = some 0
  rw [activity_cast_4,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨14,by decide⟩ : Fin 15)).1

theorem candidate_root_440 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[440]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_440,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 246 .distinctInverse 14 (by decide) (by decide)]
  change some ((authDistinctInverse witness.authorization 14 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))))) = some 0
  rw [activity_cast_4,activity_cast_5]
  congr 1
  simpa [auth_pairs_exact,mul_comm,mul_left_comm,mul_assoc] using
    (pair_polynomials statement witness valid (⟨14,by decide⟩ : Fin 15)).2

def inverseRootIndex (root : Fin 30) : Nat := 411+root.val
theorem full_candidate_actual_30_inverse_auth_roots_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (root : Fin 30) :
    (exactNonlinearRoots[inverseRootIndex root]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  fin_cases root <;> first
  | exact candidate_root_411 statement witness valid lane
  | exact candidate_root_412 statement witness valid lane
  | exact candidate_root_413 statement witness valid lane
  | exact candidate_root_414 statement witness valid lane
  | exact candidate_root_415 statement witness valid lane
  | exact candidate_root_416 statement witness valid lane
  | exact candidate_root_417 statement witness valid lane
  | exact candidate_root_418 statement witness valid lane
  | exact candidate_root_419 statement witness valid lane
  | exact candidate_root_420 statement witness valid lane
  | exact candidate_root_421 statement witness valid lane
  | exact candidate_root_422 statement witness valid lane
  | exact candidate_root_423 statement witness valid lane
  | exact candidate_root_424 statement witness valid lane
  | exact candidate_root_425 statement witness valid lane
  | exact candidate_root_426 statement witness valid lane
  | exact candidate_root_427 statement witness valid lane
  | exact candidate_root_428 statement witness valid lane
  | exact candidate_root_429 statement witness valid lane
  | exact candidate_root_430 statement witness valid lane
  | exact candidate_root_431 statement witness valid lane
  | exact candidate_root_432 statement witness valid lane
  | exact candidate_root_433 statement witness valid lane
  | exact candidate_root_434 statement witness valid lane
  | exact candidate_root_435 statement witness valid lane
  | exact candidate_root_436 statement witness valid lane
  | exact candidate_root_437 statement witness valid lane
  | exact candidate_root_438 statement witness valid lane
  | exact candidate_root_439 statement witness valid lane
  | exact candidate_root_440 statement witness valid lane
end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverseClosure


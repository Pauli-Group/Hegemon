import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastCore
import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastDAG

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthLastClosure
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
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastDAG
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem activity_cast_0 (witness : V8Witness) :
    ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) = (authSlotActive witness.authorization 0 : F) := by
  norm_num [authSlotActive,List.range_succ]
  ring

theorem activity_cast_1 (witness : V8Witness) :
    ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))) = (authSlotActive witness.authorization 1 : F) := by
  norm_num [authSlotActive,List.range_succ]
  ring

theorem activity_cast_2 (witness : V8Witness) :
    ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))) = (authSlotActive witness.authorization 2 : F) := by
  norm_num [authSlotActive,List.range_succ]
  ring

theorem activity_cast_3 (witness : V8Witness) :
    ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))) = (authSlotActive witness.authorization 3 : F) := by
  norm_num [authSlotActive,List.range_succ]
  ring

theorem activity_cast_4 (witness : V8Witness) :
    ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)) = (authSlotActive witness.authorization 4 : F) := by
  norm_num [authSlotActive,List.range_succ]

theorem activity_cast_5 (witness : V8Witness) :
    (authSignerFlag witness.authorization 5 : F) = (authSlotActive witness.authorization 5 : F) := by
  norm_num [authSlotActive,List.range_succ]

theorem candidate_root_299 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[299]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_299,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 155 .scalar 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some (((wordAt witness.authorization.current.approvedSlots 0 : F) * ((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F))) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))))) = some 0
  rw [activity_cast_0]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid false (⟨0,by decide⟩ : Fin 6)

theorem candidate_root_301 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[301]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_301,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 156 .scalar 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some (((wordAt witness.authorization.current.approvedSlots 1 : F) * ((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F))) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F))))))) = some 0
  rw [activity_cast_1]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid false (⟨1,by decide⟩ : Fin 6)

theorem candidate_root_303 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[303]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_303,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 157 .scalar 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some (((wordAt witness.authorization.current.approvedSlots 2 : F) * ((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F))) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F)))))) = some 0
  rw [activity_cast_2]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid false (⟨2,by decide⟩ : Fin 6)

theorem candidate_root_305 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[305]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_305,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 158 .scalar 6 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some (((wordAt witness.authorization.current.approvedSlots 3 : F) * ((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F))) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F))))) = some 0
  rw [activity_cast_3]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid false (⟨3,by decide⟩ : Fin 6)

theorem candidate_root_307 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[307]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_307,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 159 .scalar 7 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some (((wordAt witness.authorization.current.approvedSlots 4 : F) * ((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F))) * (1 - ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F)))) = some 0
  rw [activity_cast_4]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid false (⟨4,by decide⟩ : Fin 6)

theorem candidate_root_309 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[309]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_309,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 160 .scalar 8 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some (((wordAt witness.authorization.current.approvedSlots 5 : F) * ((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F))) * (1 - (authSignerFlag witness.authorization 5 : F))) = some 0
  rw [activity_cast_5]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid false (⟨5,by decide⟩ : Fin 6)

theorem candidate_root_312 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[312]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_312,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 162 .scalar 10 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F))))))) * ((authModeFlag witness.authorization.mode 1 : F) * (wordAt witness.authorization.next.approvedSlots 0 : F))) = some 0
  rw [activity_cast_0]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid true (⟨0,by decide⟩ : Fin 6)

theorem candidate_root_314 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[314]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_314,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 163 .scalar 11 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F)))))) * ((authModeFlag witness.authorization.mode 1 : F) * (wordAt witness.authorization.next.approvedSlots 1 : F))) = some 0
  rw [activity_cast_1]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid true (⟨1,by decide⟩ : Fin 6)

theorem candidate_root_316 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[316]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_316,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 164 .scalar 12 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F))))) * ((authModeFlag witness.authorization.mode 1 : F) * (wordAt witness.authorization.next.approvedSlots 2 : F))) = some 0
  rw [activity_cast_2]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid true (⟨2,by decide⟩ : Fin 6)

theorem candidate_root_318 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[318]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_318,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 165 .scalar 13 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F)))) * ((authModeFlag witness.authorization.mode 1 : F) * (wordAt witness.authorization.next.approvedSlots 3 : F))) = some 0
  rw [activity_cast_3]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid true (⟨3,by decide⟩ : Fin 6)

theorem candidate_root_320 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[320]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_320,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 166 .scalar 14 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F))) * ((authModeFlag witness.authorization.mode 1 : F) * (wordAt witness.authorization.next.approvedSlots 4 : F))) = some 0
  rw [activity_cast_4]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid true (⟨4,by decide⟩ : Fin 6)

theorem candidate_root_322 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[322]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_322,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 167 .scalar 15 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide)]
  change some ((1 - (authSignerFlag witness.authorization 5 : F)) * ((authModeFlag witness.authorization.mode 1 : F) * (wordAt witness.authorization.next.approvedSlots 5 : F))) = some 0
  rw [activity_cast_5]
  congr 1
  simpa [mul_comm,mul_left_comm,mul_assoc] using inactive_bitmap statement witness valid true (⟨5,by decide⟩ : Fin 6)

theorem candidate_root_345 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[345]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_345,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F))))))) * ((authModeFlag witness.authorization.mode 1 : F) * (authMembership witness.authorization (typedSourceFinals statement witness) 0 : F))) = some 0
  rw [activity_cast_0]
  congr 1
  have selected := selected_slot_active witness.authorization (typedSourceFinals statement witness) 0
  linear_combination (authModeFlag witness.authorization.mode 1 : F) * selected

theorem candidate_root_351 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[351]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_351,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F)))))) * ((authModeFlag witness.authorization.mode 1 : F) * (authMembership witness.authorization (typedSourceFinals statement witness) 1 : F))) = some 0
  rw [activity_cast_1]
  congr 1
  have selected := selected_slot_active witness.authorization (typedSourceFinals statement witness) 1
  linear_combination (authModeFlag witness.authorization.mode 1 : F) * selected

theorem candidate_root_357 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[357]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_357,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F))))) * ((authModeFlag witness.authorization.mode 1 : F) * (authMembership witness.authorization (typedSourceFinals statement witness) 2 : F))) = some 0
  rw [activity_cast_2]
  congr 1
  have selected := selected_slot_active witness.authorization (typedSourceFinals statement witness) 2
  linear_combination (authModeFlag witness.authorization.mode 1 : F) * selected

theorem candidate_root_363 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[363]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_363,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F)))) * ((authModeFlag witness.authorization.mode 1 : F) * (authMembership witness.authorization (typedSourceFinals statement witness) 3 : F))) = some 0
  rw [activity_cast_3]
  congr 1
  have selected := selected_slot_active witness.authorization (typedSourceFinals statement witness) 3
  linear_combination (authModeFlag witness.authorization.mode 1 : F) * selected

theorem candidate_root_369 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[369]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_369,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide)]
  change some ((1 - ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F))) * ((authModeFlag witness.authorization.mode 1 : F) * (authMembership witness.authorization (typedSourceFinals statement witness) 4 : F))) = some 0
  rw [activity_cast_4]
  congr 1
  have selected := selected_slot_active witness.authorization (typedSourceFinals statement witness) 4
  linear_combination (authModeFlag witness.authorization.mode 1 : F) * selected

theorem candidate_root_375 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[375]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_375,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide)]
  change some ((1 - (authSignerFlag witness.authorization 5 : F)) * ((authModeFlag witness.authorization.mode 1 : F) * (authMembership witness.authorization (typedSourceFinals statement witness) 5 : F))) = some 0
  rw [activity_cast_5]
  congr 1
  have selected := selected_slot_active witness.authorization (typedSourceFinals statement witness) 5
  linear_combination (authModeFlag witness.authorization.mode 1 : F) * selected

theorem candidate_root_381 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[381]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_381,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 196 .policyTag 0 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 0 []) 0 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F))))))))) = some 0
  rw [activity_cast_0]
  congr 1
  exact inactive_tag statement witness valid ⟨0,by decide⟩ ⟨0,by decide⟩

theorem candidate_root_382 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[382]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_382,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 197 .policyTag 1 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 0 []) 1 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F))))))))) = some 0
  rw [activity_cast_0]
  congr 1
  exact inactive_tag statement witness valid ⟨0,by decide⟩ ⟨1,by decide⟩

theorem candidate_root_383 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[383]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_383,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 198 .policyTag 2 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 0 []) 2 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F))))))))) = some 0
  rw [activity_cast_0]
  congr 1
  exact inactive_tag statement witness valid ⟨0,by decide⟩ ⟨2,by decide⟩

theorem candidate_root_384 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[384]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_384,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 199 .policyTag 3 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 0 []) 3 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F))))))))) = some 0
  rw [activity_cast_0]
  congr 1
  exact inactive_tag statement witness valid ⟨0,by decide⟩ ⟨3,by decide⟩

theorem candidate_root_385 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[385]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_385,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 176 .signerFlag 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 200 .policyTag 4 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 0 []) 4 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F))))))))) = some 0
  rw [activity_cast_0]
  congr 1
  exact inactive_tag statement witness valid ⟨0,by decide⟩ ⟨4,by decide⟩

theorem candidate_root_386 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[386]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_386,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 201 .policyTag 5 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 1 []) 0 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F)))))))) = some 0
  rw [activity_cast_1]
  congr 1
  exact inactive_tag statement witness valid ⟨1,by decide⟩ ⟨0,by decide⟩

theorem candidate_root_387 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[387]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_387,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 202 .policyTag 6 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 1 []) 1 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F)))))))) = some 0
  rw [activity_cast_1]
  congr 1
  exact inactive_tag statement witness valid ⟨1,by decide⟩ ⟨1,by decide⟩

theorem candidate_root_388 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[388]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_388,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 203 .policyTag 7 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 1 []) 2 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F)))))))) = some 0
  rw [activity_cast_1]
  congr 1
  exact inactive_tag statement witness valid ⟨1,by decide⟩ ⟨2,by decide⟩

theorem candidate_root_389 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[389]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_389,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 204 .policyTag 8 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 1 []) 3 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F)))))))) = some 0
  rw [activity_cast_1]
  congr 1
  exact inactive_tag statement witness valid ⟨1,by decide⟩ ⟨3,by decide⟩

theorem candidate_root_390 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[390]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_390,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 177 .signerFlag 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 205 .policyTag 9 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 1 []) 4 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 1 : F) + (authSignerFlag witness.authorization 2 : F)))))))) = some 0
  rw [activity_cast_1]
  congr 1
  exact inactive_tag statement witness valid ⟨1,by decide⟩ ⟨4,by decide⟩

theorem candidate_root_391 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[391]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_391,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 206 .policyTag 10 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 2 []) 0 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F))))))) = some 0
  rw [activity_cast_2]
  congr 1
  exact inactive_tag statement witness valid ⟨2,by decide⟩ ⟨0,by decide⟩

theorem candidate_root_392 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[392]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_392,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 207 .policyTag 11 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 2 []) 1 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F))))))) = some 0
  rw [activity_cast_2]
  congr 1
  exact inactive_tag statement witness valid ⟨2,by decide⟩ ⟨1,by decide⟩

theorem candidate_root_393 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[393]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_393,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 208 .policyTag 12 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 2 []) 2 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F))))))) = some 0
  rw [activity_cast_2]
  congr 1
  exact inactive_tag statement witness valid ⟨2,by decide⟩ ⟨2,by decide⟩

theorem candidate_root_394 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[394]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_394,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 209 .policyTag 13 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 2 []) 3 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F))))))) = some 0
  rw [activity_cast_2]
  congr 1
  exact inactive_tag statement witness valid ⟨2,by decide⟩ ⟨3,by decide⟩

theorem candidate_root_395 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[395]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_395,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 178 .signerFlag 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 210 .policyTag 14 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 2 []) 4 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 2 : F) + (authSignerFlag witness.authorization 3 : F))))))) = some 0
  rw [activity_cast_2]
  congr 1
  exact inactive_tag statement witness valid ⟨2,by decide⟩ ⟨4,by decide⟩

theorem candidate_root_396 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[396]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_396,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 211 .policyTag 15 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 3 []) 0 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F)))))) = some 0
  rw [activity_cast_3]
  congr 1
  exact inactive_tag statement witness valid ⟨3,by decide⟩ ⟨0,by decide⟩

theorem candidate_root_397 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[397]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_397,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 212 .policyTag 16 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 3 []) 1 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F)))))) = some 0
  rw [activity_cast_3]
  congr 1
  exact inactive_tag statement witness valid ⟨3,by decide⟩ ⟨1,by decide⟩

theorem candidate_root_398 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[398]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_398,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 213 .policyTag 17 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 3 []) 2 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F)))))) = some 0
  rw [activity_cast_3]
  congr 1
  exact inactive_tag statement witness valid ⟨3,by decide⟩ ⟨2,by decide⟩

theorem candidate_root_399 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[399]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_399,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 214 .policyTag 18 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 3 []) 3 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F)))))) = some 0
  rw [activity_cast_3]
  congr 1
  exact inactive_tag statement witness valid ⟨3,by decide⟩ ⟨3,by decide⟩

theorem candidate_root_400 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[400]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_400,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 179 .signerFlag 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 215 .policyTag 19 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 3 []) 4 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 3 : F) + (authSignerFlag witness.authorization 4 : F)))))) = some 0
  rw [activity_cast_3]
  congr 1
  exact inactive_tag statement witness valid ⟨3,by decide⟩ ⟨4,by decide⟩

theorem candidate_root_401 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[401]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_401,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 216 .policyTag 20 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 4 []) 0 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F))))) = some 0
  rw [activity_cast_4]
  congr 1
  exact inactive_tag statement witness valid ⟨4,by decide⟩ ⟨0,by decide⟩

theorem candidate_root_402 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[402]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_402,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 217 .policyTag 21 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 4 []) 1 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F))))) = some 0
  rw [activity_cast_4]
  congr 1
  exact inactive_tag statement witness valid ⟨4,by decide⟩ ⟨1,by decide⟩

theorem candidate_root_403 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[403]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_403,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 218 .policyTag 22 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 4 []) 2 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F))))) = some 0
  rw [activity_cast_4]
  congr 1
  exact inactive_tag statement witness valid ⟨4,by decide⟩ ⟨2,by decide⟩

theorem candidate_root_404 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[404]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_404,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 219 .policyTag 23 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 4 []) 3 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F))))) = some 0
  rw [activity_cast_4]
  congr 1
  exact inactive_tag statement witness valid ⟨4,by decide⟩ ⟨3,by decide⟩

theorem candidate_root_405 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[405]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_405,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 180 .signerFlag 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 220 .policyTag 24 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 4 []) 4 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - ((authSignerFlag witness.authorization 4 : F) + (authSignerFlag witness.authorization 5 : F))))) = some 0
  rw [activity_cast_4]
  congr 1
  exact inactive_tag statement witness valid ⟨4,by decide⟩ ⟨4,by decide⟩

theorem candidate_root_406 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[406]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_406,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 221 .policyTag 25 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 5 []) 0 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (authSignerFlag witness.authorization 5 : F)))) = some 0
  rw [activity_cast_5]
  congr 1
  exact inactive_tag statement witness valid ⟨5,by decide⟩ ⟨0,by decide⟩

theorem candidate_root_407 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[407]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_407,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 222 .policyTag 26 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 5 []) 1 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (authSignerFlag witness.authorization 5 : F)))) = some 0
  rw [activity_cast_5]
  congr 1
  exact inactive_tag statement witness valid ⟨5,by decide⟩ ⟨1,by decide⟩

theorem candidate_root_408 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[408]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_408,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 223 .policyTag 27 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 5 []) 2 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (authSignerFlag witness.authorization 5 : F)))) = some 0
  rw [activity_cast_5]
  congr 1
  exact inactive_tag statement witness valid ⟨5,by decide⟩ ⟨2,by decide⟩

theorem candidate_root_409 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[409]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_409,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 224 .policyTag 28 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 5 []) 3 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (authSignerFlag witness.authorization 5 : F)))) = some 0
  rw [activity_cast_5]
  congr 1
  exact inactive_tag statement witness valid ⟨5,by decide⟩ ⟨3,by decide⟩

theorem candidate_root_410 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[410]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_410,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 181 .signerFlag 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 225 .policyTag 29 (by decide) (by decide)]
  change some ((wordAt (witness.authorization.policySignerTags.getD 5 []) 4 : F) * (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (1 - (authSignerFlag witness.authorization 5 : F)))) = some 0
  rw [activity_cast_5]
  congr 1
  exact inactive_tag statement witness valid ⟨5,by decide⟩ ⟨4,by decide⟩

def lastRootIndex (root : Fin 48) : Nat := [299,301,303,305,307,309,312,314,316,318,320,322,345,351,357,363,369,375,381,382,383,384,385,386,387,388,389,390,391,392,393,394,395,396,397,398,399,400,401,402,403,404,405,406,407,408,409,410].getD root.val 0

theorem full_candidate_actual_48_last_auth_roots_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (root : Fin 48) :
    (exactNonlinearRoots[lastRootIndex root]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  fin_cases root <;> first
  | exact candidate_root_299 statement witness valid lane
  | exact candidate_root_301 statement witness valid lane
  | exact candidate_root_303 statement witness valid lane
  | exact candidate_root_305 statement witness valid lane
  | exact candidate_root_307 statement witness valid lane
  | exact candidate_root_309 statement witness valid lane
  | exact candidate_root_312 statement witness valid lane
  | exact candidate_root_314 statement witness valid lane
  | exact candidate_root_316 statement witness valid lane
  | exact candidate_root_318 statement witness valid lane
  | exact candidate_root_320 statement witness valid lane
  | exact candidate_root_322 statement witness valid lane
  | exact candidate_root_345 statement witness valid lane
  | exact candidate_root_351 statement witness valid lane
  | exact candidate_root_357 statement witness valid lane
  | exact candidate_root_363 statement witness valid lane
  | exact candidate_root_369 statement witness valid lane
  | exact candidate_root_375 statement witness valid lane
  | exact candidate_root_381 statement witness valid lane
  | exact candidate_root_382 statement witness valid lane
  | exact candidate_root_383 statement witness valid lane
  | exact candidate_root_384 statement witness valid lane
  | exact candidate_root_385 statement witness valid lane
  | exact candidate_root_386 statement witness valid lane
  | exact candidate_root_387 statement witness valid lane
  | exact candidate_root_388 statement witness valid lane
  | exact candidate_root_389 statement witness valid lane
  | exact candidate_root_390 statement witness valid lane
  | exact candidate_root_391 statement witness valid lane
  | exact candidate_root_392 statement witness valid lane
  | exact candidate_root_393 statement witness valid lane
  | exact candidate_root_394 statement witness valid lane
  | exact candidate_root_395 statement witness valid lane
  | exact candidate_root_396 statement witness valid lane
  | exact candidate_root_397 statement witness valid lane
  | exact candidate_root_398 statement witness valid lane
  | exact candidate_root_399 statement witness valid lane
  | exact candidate_root_400 statement witness valid lane
  | exact candidate_root_401 statement witness valid lane
  | exact candidate_root_402 statement witness valid lane
  | exact candidate_root_403 statement witness valid lane
  | exact candidate_root_404 statement witness valid lane
  | exact candidate_root_405 statement witness valid lane
  | exact candidate_root_406 statement witness valid lane
  | exact candidate_root_407 statement witness valid lane
  | exact candidate_root_408 statement witness valid lane
  | exact candidate_root_409 statement witness valid lane
  | exact candidate_root_410 statement witness valid lane

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthLastClosure

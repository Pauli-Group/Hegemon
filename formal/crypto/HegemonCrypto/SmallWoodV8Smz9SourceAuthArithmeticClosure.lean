import HegemonCrypto.SmallWoodV8Smz9SourceAuthRemainingClosure
import HegemonCrypto.SmallWoodV8Smz9SourceAuthArithmeticDAG

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthArithmeticClosure
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthArithmeticDAG
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem source_arithmetic_267 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    (((sourceAuthRow statement witness hashes (93-92) : F) + (sourceAuthRow statement witness hashes (94-92) : F)) * (((sourceAuthRow statement witness hashes (175-92) : F) + ((sourceAuthRow statement witness hashes (174-92) : F) + ((sourceAuthRow statement witness hashes (173-92) : F) + ((sourceAuthRow statement witness hashes (172-92) : F) + ((sourceAuthRow statement witness hashes (170-92) : F) + (sourceAuthRow statement witness hashes (171-92) : F)))))) - 1)) = 0 := by
  change (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authThresholdFlag witness.authorization 5 : F) + ((authThresholdFlag witness.authorization 4 : F) + ((authThresholdFlag witness.authorization 3 : F) + ((authThresholdFlag witness.authorization 2 : F) + ((authThresholdFlag witness.authorization 0 : F) + (authThresholdFlag witness.authorization 1 : F)))))) - 1)) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have thresholdBound : witness.authorization.current.threshold ≤ 6 := by omega
    have thresholdLower : 1 ≤ witness.authorization.current.threshold := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.threshold <;>
      simp
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have thresholdBound : witness.authorization.current.threshold ≤ 6 := by omega
    have thresholdLower : 1 ≤ witness.authorization.current.threshold := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.threshold <;>
      simp

theorem candidate_root_267 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[267]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_267,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 94 (by decide) (by decide),
    remaining_auth_readback statement witness lane 170 (by decide) (by decide),
    remaining_auth_readback statement witness lane 171 (by decide) (by decide),
    remaining_auth_readback statement witness lane 172 (by decide) (by decide),
    remaining_auth_readback statement witness lane 173 (by decide) (by decide),
    remaining_auth_readback statement witness lane 174 (by decide) (by decide),
    remaining_auth_readback statement witness lane 175 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_267 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_268 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    (((sourceAuthRow statement witness hashes (93-92) : F) + (sourceAuthRow statement witness hashes (94-92) : F)) * ((sourceAuthRow statement witness hashes (152-92) : F) - ((((((sourceAuthRow statement witness hashes (170-92) : F) + (2 * (sourceAuthRow statement witness hashes (171-92) : F))) + ((sourceAuthRow statement witness hashes (172-92) : F) * 3)) + ((sourceAuthRow statement witness hashes (173-92) : F) * 4)) + ((sourceAuthRow statement witness hashes (174-92) : F) * 5)) + ((sourceAuthRow statement witness hashes (175-92) : F) * 6)))) = 0 := by
  change (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((witness.authorization.current.threshold : F) - ((((((authThresholdFlag witness.authorization 0 : F) + (2 * (authThresholdFlag witness.authorization 1 : F))) + ((authThresholdFlag witness.authorization 2 : F) * 3)) + ((authThresholdFlag witness.authorization 3 : F) * 4)) + ((authThresholdFlag witness.authorization 4 : F) * 5)) + ((authThresholdFlag witness.authorization 5 : F) * 6)))) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have thresholdBound : witness.authorization.current.threshold ≤ 6 := by omega
    have thresholdLower : 1 ≤ witness.authorization.current.threshold := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.threshold <;>
      simp
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have thresholdBound : witness.authorization.current.threshold ≤ 6 := by omega
    have thresholdLower : 1 ≤ witness.authorization.current.threshold := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.threshold <;>
      simp

theorem candidate_root_268 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[268]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_268,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 94 (by decide) (by decide),
    remaining_auth_readback statement witness lane 152 (by decide) (by decide),
    remaining_auth_readback statement witness lane 170 (by decide) (by decide),
    remaining_auth_readback statement witness lane 171 (by decide) (by decide),
    remaining_auth_readback statement witness lane 172 (by decide) (by decide),
    remaining_auth_readback statement witness lane 173 (by decide) (by decide),
    remaining_auth_readback statement witness lane 174 (by decide) (by decide),
    remaining_auth_readback statement witness lane 175 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_268 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_275 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    (((sourceAuthRow statement witness hashes (93-92) : F) + (sourceAuthRow statement witness hashes (94-92) : F)) * (((sourceAuthRow statement witness hashes (181-92) : F) + ((sourceAuthRow statement witness hashes (180-92) : F) + ((sourceAuthRow statement witness hashes (179-92) : F) + ((sourceAuthRow statement witness hashes (178-92) : F) + ((sourceAuthRow statement witness hashes (176-92) : F) + (sourceAuthRow statement witness hashes (177-92) : F)))))) - 1)) = 0 := by
  change (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authSignerFlag witness.authorization 5 : F) + ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) - 1)) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have signerCountBound : witness.authorization.current.signerCount ≤ 6 := by omega
    have signerCountLower : 1 ≤ witness.authorization.current.signerCount := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.signerCount <;>
      simp
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have signerCountBound : witness.authorization.current.signerCount ≤ 6 := by omega
    have signerCountLower : 1 ≤ witness.authorization.current.signerCount := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.signerCount <;>
      simp

theorem candidate_root_275 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[275]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_275,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 94 (by decide) (by decide),
    remaining_auth_readback statement witness lane 176 (by decide) (by decide),
    remaining_auth_readback statement witness lane 177 (by decide) (by decide),
    remaining_auth_readback statement witness lane 178 (by decide) (by decide),
    remaining_auth_readback statement witness lane 179 (by decide) (by decide),
    remaining_auth_readback statement witness lane 180 (by decide) (by decide),
    remaining_auth_readback statement witness lane 181 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_275 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_276 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    (((sourceAuthRow statement witness hashes (93-92) : F) + (sourceAuthRow statement witness hashes (94-92) : F)) * ((sourceAuthRow statement witness hashes (153-92) : F) - ((((((sourceAuthRow statement witness hashes (176-92) : F) + (2 * (sourceAuthRow statement witness hashes (177-92) : F))) + ((sourceAuthRow statement witness hashes (178-92) : F) * 3)) + ((sourceAuthRow statement witness hashes (179-92) : F) * 4)) + ((sourceAuthRow statement witness hashes (180-92) : F) * 5)) + ((sourceAuthRow statement witness hashes (181-92) : F) * 6)))) = 0 := by
  change (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((witness.authorization.current.signerCount : F) - ((((((authSignerFlag witness.authorization 0 : F) + (2 * (authSignerFlag witness.authorization 1 : F))) + ((authSignerFlag witness.authorization 2 : F) * 3)) + ((authSignerFlag witness.authorization 3 : F) * 4)) + ((authSignerFlag witness.authorization 4 : F) * 5)) + ((authSignerFlag witness.authorization 5 : F) * 6)))) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have signerCountBound : witness.authorization.current.signerCount ≤ 6 := by omega
    have signerCountLower : 1 ≤ witness.authorization.current.signerCount := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.signerCount <;>
      simp
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have signerCountBound : witness.authorization.current.signerCount ≤ 6 := by omega
    have signerCountLower : 1 ≤ witness.authorization.current.signerCount := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.signerCount <;>
      simp

theorem candidate_root_276 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[276]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_276,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 94 (by decide) (by decide),
    remaining_auth_readback statement witness lane 153 (by decide) (by decide),
    remaining_auth_readback statement witness lane 176 (by decide) (by decide),
    remaining_auth_readback statement witness lane 177 (by decide) (by decide),
    remaining_auth_readback statement witness lane 178 (by decide) (by decide),
    remaining_auth_readback statement witness lane 179 (by decide) (by decide),
    remaining_auth_readback statement witness lane 180 (by decide) (by decide),
    remaining_auth_readback statement witness lane 181 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_276 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_277 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    (((sourceAuthRow statement witness hashes (93-92) : F) + (sourceAuthRow statement witness hashes (94-92) : F)) * ((((((sourceAuthRow statement witness hashes (171-92) : F) * (sourceAuthRow statement witness hashes (176-92) : F)) + ((sourceAuthRow statement witness hashes (172-92) : F) * ((sourceAuthRow statement witness hashes (176-92) : F) + (sourceAuthRow statement witness hashes (177-92) : F)))) + ((sourceAuthRow statement witness hashes (173-92) : F) * ((sourceAuthRow statement witness hashes (178-92) : F) + ((sourceAuthRow statement witness hashes (176-92) : F) + (sourceAuthRow statement witness hashes (177-92) : F))))) + ((sourceAuthRow statement witness hashes (174-92) : F) * ((sourceAuthRow statement witness hashes (179-92) : F) + ((sourceAuthRow statement witness hashes (178-92) : F) + ((sourceAuthRow statement witness hashes (176-92) : F) + (sourceAuthRow statement witness hashes (177-92) : F)))))) + ((sourceAuthRow statement witness hashes (175-92) : F) * ((sourceAuthRow statement witness hashes (180-92) : F) + ((sourceAuthRow statement witness hashes (179-92) : F) + ((sourceAuthRow statement witness hashes (178-92) : F) + ((sourceAuthRow statement witness hashes (176-92) : F) + (sourceAuthRow statement witness hashes (177-92) : F)))))))) = 0 := by
  change (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((((((authThresholdFlag witness.authorization 1 : F) * (authSignerFlag witness.authorization 0 : F)) + ((authThresholdFlag witness.authorization 2 : F) * ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))) + ((authThresholdFlag witness.authorization 3 : F) * ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F))))) + ((authThresholdFlag witness.authorization 4 : F) * ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))) + ((authThresholdFlag witness.authorization 5 : F) * ((authSignerFlag witness.authorization 4 : F) + ((authSignerFlag witness.authorization 3 : F) + ((authSignerFlag witness.authorization 2 : F) + ((authSignerFlag witness.authorization 0 : F) + (authSignerFlag witness.authorization 1 : F)))))))) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have thresholdBound : witness.authorization.current.threshold ≤ 6 := by omega
    have thresholdLower : 1 ≤ witness.authorization.current.threshold := by omega
    have signerCountBound : witness.authorization.current.signerCount ≤ 6 := by omega
    have signerCountLower : 1 ≤ witness.authorization.current.signerCount := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.threshold <;> interval_cases witness.authorization.current.signerCount <;>
      simp <;> omega
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have thresholdBound : witness.authorization.current.threshold ≤ 6 := by omega
    have thresholdLower : 1 ≤ witness.authorization.current.threshold := by omega
    have signerCountBound : witness.authorization.current.signerCount ≤ 6 := by omega
    have signerCountLower : 1 ≤ witness.authorization.current.signerCount := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.threshold <;> interval_cases witness.authorization.current.signerCount <;>
      simp <;> omega

theorem candidate_root_277 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[277]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_277,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 94 (by decide) (by decide),
    remaining_auth_readback statement witness lane 171 (by decide) (by decide),
    remaining_auth_readback statement witness lane 172 (by decide) (by decide),
    remaining_auth_readback statement witness lane 173 (by decide) (by decide),
    remaining_auth_readback statement witness lane 174 (by decide) (by decide),
    remaining_auth_readback statement witness lane 175 (by decide) (by decide),
    remaining_auth_readback statement witness lane 176 (by decide) (by decide),
    remaining_auth_readback statement witness lane 177 (by decide) (by decide),
    remaining_auth_readback statement witness lane 178 (by decide) (by decide),
    remaining_auth_readback statement witness lane 179 (by decide) (by decide),
    remaining_auth_readback statement witness lane 180 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_277 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_285 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    (((sourceAuthRow statement witness hashes (93-92) : F) + (sourceAuthRow statement witness hashes (94-92) : F)) * (((sourceAuthRow statement witness hashes (188-92) : F) + ((sourceAuthRow statement witness hashes (187-92) : F) + ((sourceAuthRow statement witness hashes (186-92) : F) + ((sourceAuthRow statement witness hashes (185-92) : F) + ((sourceAuthRow statement witness hashes (184-92) : F) + ((sourceAuthRow statement witness hashes (182-92) : F) + (sourceAuthRow statement witness hashes (183-92) : F))))))) - 1)) = 0 := by
  change (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * (((authCurrentCountFlag witness.authorization 6 : F) + ((authCurrentCountFlag witness.authorization 5 : F) + ((authCurrentCountFlag witness.authorization 4 : F) + ((authCurrentCountFlag witness.authorization 3 : F) + ((authCurrentCountFlag witness.authorization 2 : F) + ((authCurrentCountFlag witness.authorization 0 : F) + (authCurrentCountFlag witness.authorization 1 : F))))))) - 1)) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have approvalCountBound : witness.authorization.current.approvalCount ≤ 6 := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.approvalCount <;>
      simp
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have approvalCountBound : witness.authorization.current.approvalCount ≤ 6 := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.approvalCount <;>
      simp

theorem candidate_root_285 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[285]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_285,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 94 (by decide) (by decide),
    remaining_auth_readback statement witness lane 182 (by decide) (by decide),
    remaining_auth_readback statement witness lane 183 (by decide) (by decide),
    remaining_auth_readback statement witness lane 184 (by decide) (by decide),
    remaining_auth_readback statement witness lane 185 (by decide) (by decide),
    remaining_auth_readback statement witness lane 186 (by decide) (by decide),
    remaining_auth_readback statement witness lane 187 (by decide) (by decide),
    remaining_auth_readback statement witness lane 188 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_285 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_286 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    (((sourceAuthRow statement witness hashes (93-92) : F) + (sourceAuthRow statement witness hashes (94-92) : F)) * ((sourceAuthRow statement witness hashes (154-92) : F) - ((((((sourceAuthRow statement witness hashes (183-92) : F) + (2 * (sourceAuthRow statement witness hashes (184-92) : F))) + ((sourceAuthRow statement witness hashes (185-92) : F) * 3)) + ((sourceAuthRow statement witness hashes (186-92) : F) * 4)) + ((sourceAuthRow statement witness hashes (187-92) : F) * 5)) + ((sourceAuthRow statement witness hashes (188-92) : F) * 6)))) = 0 := by
  change (((authModeFlag witness.authorization.mode 1 : F) + (authModeFlag witness.authorization.mode 2 : F)) * ((witness.authorization.current.approvalCount : F) - ((((((authCurrentCountFlag witness.authorization 1 : F) + (2 * (authCurrentCountFlag witness.authorization 2 : F))) + ((authCurrentCountFlag witness.authorization 3 : F) * 3)) + ((authCurrentCountFlag witness.authorization 4 : F) * 4)) + ((authCurrentCountFlag witness.authorization 5 : F) * 5)) + ((authCurrentCountFlag witness.authorization 6 : F) * 6)))) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have approvalCountBound : witness.authorization.current.approvalCount ≤ 6 := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.approvalCount <;>
      simp
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have approvalCountBound : witness.authorization.current.approvalCount ≤ 6 := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.approvalCount <;>
      simp

theorem candidate_root_286 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[286]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_286,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 94 (by decide) (by decide),
    remaining_auth_readback statement witness lane 154 (by decide) (by decide),
    remaining_auth_readback statement witness lane 183 (by decide) (by decide),
    remaining_auth_readback statement witness lane 184 (by decide) (by decide),
    remaining_auth_readback statement witness lane 185 (by decide) (by decide),
    remaining_auth_readback statement witness lane 186 (by decide) (by decide),
    remaining_auth_readback statement witness lane 187 (by decide) (by decide),
    remaining_auth_readback statement witness lane 188 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_286 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_294 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    ((sourceAuthRow statement witness hashes (93-92) : F) * (((sourceAuthRow statement witness hashes (195-92) : F) + ((sourceAuthRow statement witness hashes (194-92) : F) + ((sourceAuthRow statement witness hashes (193-92) : F) + ((sourceAuthRow statement witness hashes (192-92) : F) + ((sourceAuthRow statement witness hashes (191-92) : F) + ((sourceAuthRow statement witness hashes (189-92) : F) + (sourceAuthRow statement witness hashes (190-92) : F))))))) - 1)) = 0 := by
  change ((authModeFlag witness.authorization.mode 1 : F) * (((authNextCountFlag witness.authorization 6 : F) + ((authNextCountFlag witness.authorization 5 : F) + ((authNextCountFlag witness.authorization 4 : F) + ((authNextCountFlag witness.authorization 3 : F) + ((authNextCountFlag witness.authorization 2 : F) + ((authNextCountFlag witness.authorization 0 : F) + (authNextCountFlag witness.authorization 1 : F))))))) - 1)) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have top := approval_next_count_bound statement witness valid mode
    have next_approvalCountBound : witness.authorization.next.approvalCount ≤ 6 := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.next.approvalCount <;>
      simp
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]

theorem candidate_root_294 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[294]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_294,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 189 (by decide) (by decide),
    remaining_auth_readback statement witness lane 190 (by decide) (by decide),
    remaining_auth_readback statement witness lane 191 (by decide) (by decide),
    remaining_auth_readback statement witness lane 192 (by decide) (by decide),
    remaining_auth_readback statement witness lane 193 (by decide) (by decide),
    remaining_auth_readback statement witness lane 194 (by decide) (by decide),
    remaining_auth_readback statement witness lane 195 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_294 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_295 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    ((sourceAuthRow statement witness hashes (93-92) : F) * ((sourceAuthRow statement witness hashes (161-92) : F) - ((((((sourceAuthRow statement witness hashes (190-92) : F) + (2 * (sourceAuthRow statement witness hashes (191-92) : F))) + ((sourceAuthRow statement witness hashes (192-92) : F) * 3)) + ((sourceAuthRow statement witness hashes (193-92) : F) * 4)) + ((sourceAuthRow statement witness hashes (194-92) : F) * 5)) + ((sourceAuthRow statement witness hashes (195-92) : F) * 6)))) = 0 := by
  change ((authModeFlag witness.authorization.mode 1 : F) * ((witness.authorization.next.approvalCount : F) - ((((((authNextCountFlag witness.authorization 1 : F) + (2 * (authNextCountFlag witness.authorization 2 : F))) + ((authNextCountFlag witness.authorization 3 : F) * 3)) + ((authNextCountFlag witness.authorization 4 : F) * 4)) + ((authNextCountFlag witness.authorization 5 : F) * 5)) + ((authNextCountFlag witness.authorization 6 : F) * 6)))) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have top := approval_next_count_bound statement witness valid mode
    have next_approvalCountBound : witness.authorization.next.approvalCount ≤ 6 := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.next.approvalCount <;>
      simp
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]

theorem candidate_root_295 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[295]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_295,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 161 (by decide) (by decide),
    remaining_auth_readback statement witness lane 190 (by decide) (by decide),
    remaining_auth_readback statement witness lane 191 (by decide) (by decide),
    remaining_auth_readback statement witness lane 192 (by decide) (by decide),
    remaining_auth_readback statement witness lane 193 (by decide) (by decide),
    remaining_auth_readback statement witness lane 194 (by decide) (by decide),
    remaining_auth_readback statement witness lane 195 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_295 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_296 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    ((sourceAuthRow statement witness hashes (93-92) : F) * (((sourceAuthRow statement witness hashes (161-92) : F) - (sourceAuthRow statement witness hashes (154-92) : F)) - 1)) = 0 := by
  change ((authModeFlag witness.authorization.mode 1 : F) * (((witness.authorization.next.approvalCount : F) - (witness.authorization.current.approvalCount : F)) - 1)) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have increment := approval_count_increment statement witness valid mode
    norm_num [sourceAuthRow,authModeFlag,authScalar,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode,increment,Nat.cast_add]
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]

theorem candidate_root_296 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[296]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_296,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 154 (by decide) (by decide),
    remaining_auth_readback statement witness lane 161 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_296 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_297 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    ((sourceAuthRow statement witness hashes (93-92) : F) * (sourceAuthRow statement witness hashes (188-92) : F)) = 0 := by
  change ((authModeFlag witness.authorization.mode 1 : F) * (authCurrentCountFlag witness.authorization 6 : F)) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have increment := approval_count_increment statement witness valid mode
    have nextBound := approval_next_count_bound statement witness valid mode
    have top : witness.authorization.current.approvalCount ≤ 5 := by omega
    have approvalCountBound : witness.authorization.current.approvalCount ≤ 5 := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.approvalCount <;>
      simp
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]

theorem candidate_root_297 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[297]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_297,
    remaining_auth_readback statement witness lane 93 (by decide) (by decide),
    remaining_auth_readback statement witness lane 188 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_297 statement witness valid (typedSourceFinals statement witness))

theorem source_arithmetic_441 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) :
    ((sourceAuthRow statement witness hashes (94-92) : F) * (((((((sourceAuthRow statement witness hashes (170-92) : F) * (sourceAuthRow statement witness hashes (182-92) : F)) + ((sourceAuthRow statement witness hashes (171-92) : F) * ((sourceAuthRow statement witness hashes (182-92) : F) + (sourceAuthRow statement witness hashes (183-92) : F)))) + ((sourceAuthRow statement witness hashes (172-92) : F) * ((sourceAuthRow statement witness hashes (184-92) : F) + ((sourceAuthRow statement witness hashes (182-92) : F) + (sourceAuthRow statement witness hashes (183-92) : F))))) + ((sourceAuthRow statement witness hashes (173-92) : F) * ((sourceAuthRow statement witness hashes (185-92) : F) + ((sourceAuthRow statement witness hashes (184-92) : F) + ((sourceAuthRow statement witness hashes (182-92) : F) + (sourceAuthRow statement witness hashes (183-92) : F)))))) + ((sourceAuthRow statement witness hashes (174-92) : F) * ((sourceAuthRow statement witness hashes (186-92) : F) + ((sourceAuthRow statement witness hashes (185-92) : F) + ((sourceAuthRow statement witness hashes (184-92) : F) + ((sourceAuthRow statement witness hashes (182-92) : F) + (sourceAuthRow statement witness hashes (183-92) : F))))))) + ((sourceAuthRow statement witness hashes (175-92) : F) * ((sourceAuthRow statement witness hashes (187-92) : F) + ((sourceAuthRow statement witness hashes (186-92) : F) + ((sourceAuthRow statement witness hashes (185-92) : F) + ((sourceAuthRow statement witness hashes (184-92) : F) + ((sourceAuthRow statement witness hashes (182-92) : F) + (sourceAuthRow statement witness hashes (183-92) : F))))))))) = 0 := by
  change ((authModeFlag witness.authorization.mode 2 : F) * (((((((authThresholdFlag witness.authorization 0 : F) * (authCurrentCountFlag witness.authorization 0 : F)) + ((authThresholdFlag witness.authorization 1 : F) * ((authCurrentCountFlag witness.authorization 0 : F) + (authCurrentCountFlag witness.authorization 1 : F)))) + ((authThresholdFlag witness.authorization 2 : F) * ((authCurrentCountFlag witness.authorization 2 : F) + ((authCurrentCountFlag witness.authorization 0 : F) + (authCurrentCountFlag witness.authorization 1 : F))))) + ((authThresholdFlag witness.authorization 3 : F) * ((authCurrentCountFlag witness.authorization 3 : F) + ((authCurrentCountFlag witness.authorization 2 : F) + ((authCurrentCountFlag witness.authorization 0 : F) + (authCurrentCountFlag witness.authorization 1 : F)))))) + ((authThresholdFlag witness.authorization 4 : F) * ((authCurrentCountFlag witness.authorization 4 : F) + ((authCurrentCountFlag witness.authorization 3 : F) + ((authCurrentCountFlag witness.authorization 2 : F) + ((authCurrentCountFlag witness.authorization 0 : F) + (authCurrentCountFlag witness.authorization 1 : F))))))) + ((authThresholdFlag witness.authorization 5 : F) * ((authCurrentCountFlag witness.authorization 5 : F) + ((authCurrentCountFlag witness.authorization 4 : F) + ((authCurrentCountFlag witness.authorization 3 : F) + ((authCurrentCountFlag witness.authorization 2 : F) + ((authCurrentCountFlag witness.authorization 0 : F) + (authCurrentCountFlag witness.authorization 1 : F))))))))) = 0
  cases mode : witness.authorization.mode
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
  · have bounds := current_scalar_bounds statement witness valid (by simp [mode])
    have thresholdBound := final_threshold_bound statement witness valid mode
    have thresholdBound : witness.authorization.current.threshold ≤ 6 := by omega
    have thresholdLower : 1 ≤ witness.authorization.current.threshold := by omega
    have approvalCountBound : witness.authorization.current.approvalCount ≤ 6 := by omega
    norm_num [authModeFlag,authThresholdFlag,authSignerFlag,authCurrentCountFlag,authNextCountFlag,authBit,mode]
    interval_cases witness.authorization.current.threshold <;> interval_cases witness.authorization.current.approvalCount <;>
      simp

theorem candidate_root_441 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[441]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_441,
    remaining_auth_readback statement witness lane 94 (by decide) (by decide),
    remaining_auth_readback statement witness lane 170 (by decide) (by decide),
    remaining_auth_readback statement witness lane 171 (by decide) (by decide),
    remaining_auth_readback statement witness lane 172 (by decide) (by decide),
    remaining_auth_readback statement witness lane 173 (by decide) (by decide),
    remaining_auth_readback statement witness lane 174 (by decide) (by decide),
    remaining_auth_readback statement witness lane 175 (by decide) (by decide),
    remaining_auth_readback statement witness lane 182 (by decide) (by decide),
    remaining_auth_readback statement witness lane 183 (by decide) (by decide),
    remaining_auth_readback statement witness lane 184 (by decide) (by decide),
    remaining_auth_readback statement witness lane 185 (by decide) (by decide),
    remaining_auth_readback statement witness lane 186 (by decide) (by decide),
    remaining_auth_readback statement witness lane 187 (by decide) (by decide)]
  exact congrArg some (source_arithmetic_441 statement witness valid (typedSourceFinals statement witness))

def selectedArithmeticRoot (index : Fin 12) : Nat :=
  [267,268,275,276,277,285,286,294,295,296,297,441].getD index.val 0

theorem full_candidate_actual_12_arithmetic_auth_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (index : Fin 12) :
    (exactNonlinearRoots[selectedArithmeticRoot index]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  fin_cases index
  · exact candidate_root_267 statement witness valid lane
  · exact candidate_root_268 statement witness valid lane
  · exact candidate_root_275 statement witness valid lane
  · exact candidate_root_276 statement witness valid lane
  · exact candidate_root_277 statement witness valid lane
  · exact candidate_root_285 statement witness valid lane
  · exact candidate_root_286 statement witness valid lane
  · exact candidate_root_294 statement witness valid lane
  · exact candidate_root_295 statement witness valid lane
  · exact candidate_root_296 statement witness valid lane
  · exact candidate_root_297 statement witness valid lane
  · exact candidate_root_441 statement witness valid lane

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthArithmeticClosure

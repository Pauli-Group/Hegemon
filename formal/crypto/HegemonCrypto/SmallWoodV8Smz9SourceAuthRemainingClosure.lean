import HegemonCrypto.SmallWoodV8Smz9SourceAuthRemainingCore
import HegemonCrypto.SmallWoodV8Smz9SourceAuthIntent
import HegemonCrypto.SmallWoodV8Smz9SourceAuthRemainingDAG

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingClosure
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (encoded_input_flag encoded_output_flag)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootClosure
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthIntent
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingDAG
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem remaining_auth_readback (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) (row : Nat) (lower : 92 ≤ row) (upper : row < 247) :
    laneField (fullTypedSourceCandidate statement witness) lane.val row =
      (sourceAuthRow statement witness (typedSourceFinals statement witness) (row-92) : F) := by
  simpa only [Nat.add_sub_of_le lower] using
    full_candidate_auth_row statement witness (⟨row-92,by omega⟩ : Fin 155) lane

theorem remaining_intent_readback (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) (row limb : Nat) (bound : limb < 7) (address : row = 145+limb) :
    laneField (fullTypedSourceCandidate statement witness) lane.val row =
      (wordAt witness.authorization.current.intentDigest limb : F) := by
  rw [address]
  exact full_candidate_auth_family statement witness .intent limb bound lane

theorem remaining_statement_digest_readback (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) (row limb : Nat) (bound : limb < 7) (address : row = 131+limb) :
    laneField (fullTypedSourceCandidate statement witness) lane.val row =
      (authHashWord (typedSourceFinals statement witness) 93 limb : F) := by
  rw [address]
  exact full_candidate_auth_family statement witness .statementDigest limb bound lane

theorem candidate_root_252 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[252]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_252,full_candidate_mode1_row statement witness lane,
    encoded_input_flag statement valid.1 (show 0 < 2 by decide)]
  exact congrArg some (source_input_activity statement witness valid ⟨0,by decide⟩ ⟨0,by decide⟩)

theorem candidate_root_253 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[253]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_253,full_candidate_mode1_row statement witness lane,
    encoded_input_flag statement valid.1 (show 1 < 2 by decide)]
  exact congrArg some (source_input_activity statement witness valid ⟨1,by decide⟩ ⟨0,by decide⟩)

theorem candidate_root_254 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[254]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_254,full_candidate_mode1_row statement witness lane,
    encoded_output_flag statement valid.1 (show 0 < 2 by decide)]
  exact congrArg some (source_output_activity statement witness valid)

theorem candidate_root_255 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[255]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_255,full_candidate_mode2_row statement witness lane,
    encoded_input_flag statement valid.1 (show 0 < 2 by decide)]
  exact congrArg some (source_input_activity statement witness valid ⟨0,by decide⟩ ⟨1,by decide⟩)

theorem candidate_root_256 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[256]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_256,full_candidate_mode2_row statement witness lane,
    encoded_input_flag statement valid.1 (show 1 < 2 by decide)]
  exact congrArg some (source_input_activity statement witness valid ⟨1,by decide⟩ ⟨1,by decide⟩)

theorem candidate_root_261 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[261]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_261, remaining_auth_readback statement witness lane 170 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 78 (by decide)),mul_zero]

theorem candidate_root_262 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[262]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_262, remaining_auth_readback statement witness lane 171 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 79 (by decide)),mul_zero]

theorem candidate_root_263 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[263]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_263, remaining_auth_readback statement witness lane 172 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 80 (by decide)),mul_zero]

theorem candidate_root_264 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[264]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_264, remaining_auth_readback statement witness lane 173 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 81 (by decide)),mul_zero]

theorem candidate_root_265 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[265]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_265, remaining_auth_readback statement witness lane 174 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 82 (by decide)),mul_zero]

theorem candidate_root_266 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[266]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_266, remaining_auth_readback statement witness lane 175 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 83 (by decide)),mul_zero]

theorem candidate_root_269 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[269]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_269, remaining_auth_readback statement witness lane 176 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 84 (by decide)),mul_zero]

theorem candidate_root_270 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[270]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_270, remaining_auth_readback statement witness lane 177 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 85 (by decide)),mul_zero]

theorem candidate_root_271 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[271]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_271, remaining_auth_readback statement witness lane 178 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 86 (by decide)),mul_zero]

theorem candidate_root_272 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[272]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_272, remaining_auth_readback statement witness lane 179 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 87 (by decide)),mul_zero]

theorem candidate_root_273 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[273]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_273, remaining_auth_readback statement witness lane 180 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 88 (by decide)),mul_zero]

theorem candidate_root_274 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[274]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_274, remaining_auth_readback statement witness lane 181 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 89 (by decide)),mul_zero]

theorem candidate_root_278 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[278]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_278, remaining_auth_readback statement witness lane 182 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 90 (by decide)),mul_zero]

theorem candidate_root_279 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[279]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_279, remaining_auth_readback statement witness lane 183 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 91 (by decide)),mul_zero]

theorem candidate_root_280 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[280]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_280, remaining_auth_readback statement witness lane 184 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 92 (by decide)),mul_zero]

theorem candidate_root_281 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[281]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_281, remaining_auth_readback statement witness lane 185 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 93 (by decide)),mul_zero]

theorem candidate_root_282 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[282]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_282, remaining_auth_readback statement witness lane 186 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 94 (by decide)),mul_zero]

theorem candidate_root_283 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[283]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_283, remaining_auth_readback statement witness lane 187 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 95 (by decide)),mul_zero]

theorem candidate_root_284 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[284]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_284, remaining_auth_readback statement witness lane 188 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 96 (by decide)),mul_zero]

theorem candidate_root_287 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[287]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_287, remaining_auth_readback statement witness lane 189 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 97 (by decide)),mul_zero]

theorem candidate_root_288 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[288]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_288, remaining_auth_readback statement witness lane 190 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 98 (by decide)),mul_zero]

theorem candidate_root_289 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[289]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_289, remaining_auth_readback statement witness lane 191 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 99 (by decide)),mul_zero]

theorem candidate_root_290 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[290]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_290, remaining_auth_readback statement witness lane 192 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 100 (by decide)),mul_zero]

theorem candidate_root_291 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[291]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_291, remaining_auth_readback statement witness lane 193 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 101 (by decide)),mul_zero]

theorem candidate_root_292 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[292]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_292, remaining_auth_readback statement witness lane 194 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 102 (by decide)),mul_zero]

theorem candidate_root_293 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[293]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_293, remaining_auth_readback statement witness lane 195 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 103 (by decide)),mul_zero]

theorem candidate_root_336 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[336]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_336,remaining_auth_readback statement witness lane 168 (by decide) (by decide),
    (show sourceAuthRow statement witness (typedSourceFinals statement witness) (168-92) = 0 from source_reserved_zero statement witness _ ⟨0,by decide⟩),Nat.cast_zero,mul_zero]

theorem candidate_root_337 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[337]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_337,remaining_auth_readback statement witness lane 169 (by decide) (by decide),
    (show sourceAuthRow statement witness (typedSourceFinals statement witness) (169-92) = 0 from source_reserved_zero statement witness _ ⟨1,by decide⟩),Nat.cast_zero,mul_zero]

theorem candidate_root_338 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[338]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_338, remaining_auth_readback statement witness lane 226 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 134 (by decide)),mul_zero]

theorem candidate_root_339 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[339]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_339, remaining_auth_readback statement witness lane 227 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 135 (by decide)),mul_zero]

theorem candidate_root_340 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[340]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_340, remaining_auth_readback statement witness lane 228 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 136 (by decide)),mul_zero]

theorem candidate_root_341 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[341]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_341, remaining_auth_readback statement witness lane 229 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 137 (by decide)),mul_zero]

theorem candidate_root_342 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[342]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_342, remaining_auth_readback statement witness lane 230 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 138 (by decide)),mul_zero]

theorem candidate_root_343 (statement : V8PublicStatement) (witness : V8Witness)
    (_valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[343]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_343, remaining_auth_readback statement witness lane 231 (by decide) (by decide),
    bit_polynomial _ (source_boolean_row statement witness _ 139 (by decide)),mul_zero]

theorem candidate_root_442 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[442]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_442,full_candidate_mode2_row statement witness lane,
    remaining_intent_readback statement witness lane 145 0 (by decide) (by decide),
    remaining_statement_digest_readback statement witness lane 131 0 (by decide) (by decide)]
  exact congrArg some (source_final_intent_product statement witness valid ⟨0,by decide⟩)

theorem candidate_root_443 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[443]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_443,full_candidate_mode2_row statement witness lane,
    remaining_intent_readback statement witness lane 146 1 (by decide) (by decide),
    remaining_statement_digest_readback statement witness lane 132 1 (by decide) (by decide)]
  exact congrArg some (source_final_intent_product statement witness valid ⟨1,by decide⟩)

theorem candidate_root_444 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[444]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_444,full_candidate_mode2_row statement witness lane,
    remaining_intent_readback statement witness lane 147 2 (by decide) (by decide),
    remaining_statement_digest_readback statement witness lane 133 2 (by decide) (by decide)]
  exact congrArg some (source_final_intent_product statement witness valid ⟨2,by decide⟩)

theorem candidate_root_445 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[445]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_445,full_candidate_mode2_row statement witness lane,
    remaining_intent_readback statement witness lane 148 3 (by decide) (by decide),
    remaining_statement_digest_readback statement witness lane 134 3 (by decide) (by decide)]
  exact congrArg some (source_final_intent_product statement witness valid ⟨3,by decide⟩)

theorem candidate_root_446 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[446]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_446,full_candidate_mode2_row statement witness lane,
    remaining_intent_readback statement witness lane 149 4 (by decide) (by decide),
    remaining_statement_digest_readback statement witness lane 135 4 (by decide) (by decide)]
  exact congrArg some (source_final_intent_product statement witness valid ⟨4,by decide⟩)

theorem candidate_root_447 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[447]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_447,full_candidate_mode2_row statement witness lane,
    remaining_intent_readback statement witness lane 150 5 (by decide) (by decide),
    remaining_statement_digest_readback statement witness lane 136 5 (by decide) (by decide)]
  exact congrArg some (source_final_intent_product statement witness valid ⟨5,by decide⟩)

theorem candidate_root_448 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[448]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_448,full_candidate_mode2_row statement witness lane,
    remaining_intent_readback statement witness lane 151 6 (by decide) (by decide),
    remaining_statement_digest_readback statement witness lane 137 6 (by decide) (by decide)]
  exact congrArg some (source_final_intent_product statement witness valid ⟨6,by decide⟩)

def selectedRemainingRoot (index : Fin 46) : Nat :=
  [252,253,254,255,256,261,262,263,264,265,266,269,270,271,272,273,274,278,279,280,281,282,283,284,287,288,289,290,291,292,293,336,337,338,339,340,341,342,343,442,443,444,445,446,447,448].getD index.val 0

theorem selected_remaining_roots_exact :
    List.ofFn selectedRemainingRoot =
      List.range' 252 5 ++ List.range' 261 6 ++ List.range' 269 6 ++
        List.range' 278 7 ++ List.range' 287 7 ++ List.range' 336 8 ++ List.range' 442 7 := by decide

theorem full_candidate_actual_46_remaining_auth_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64)
    (index : Fin 46) :
    (exactNonlinearRoots[selectedRemainingRoot index]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  fin_cases index
  · exact candidate_root_252 statement witness valid lane
  · exact candidate_root_253 statement witness valid lane
  · exact candidate_root_254 statement witness valid lane
  · exact candidate_root_255 statement witness valid lane
  · exact candidate_root_256 statement witness valid lane
  · exact candidate_root_261 statement witness valid lane
  · exact candidate_root_262 statement witness valid lane
  · exact candidate_root_263 statement witness valid lane
  · exact candidate_root_264 statement witness valid lane
  · exact candidate_root_265 statement witness valid lane
  · exact candidate_root_266 statement witness valid lane
  · exact candidate_root_269 statement witness valid lane
  · exact candidate_root_270 statement witness valid lane
  · exact candidate_root_271 statement witness valid lane
  · exact candidate_root_272 statement witness valid lane
  · exact candidate_root_273 statement witness valid lane
  · exact candidate_root_274 statement witness valid lane
  · exact candidate_root_278 statement witness valid lane
  · exact candidate_root_279 statement witness valid lane
  · exact candidate_root_280 statement witness valid lane
  · exact candidate_root_281 statement witness valid lane
  · exact candidate_root_282 statement witness valid lane
  · exact candidate_root_283 statement witness valid lane
  · exact candidate_root_284 statement witness valid lane
  · exact candidate_root_287 statement witness valid lane
  · exact candidate_root_288 statement witness valid lane
  · exact candidate_root_289 statement witness valid lane
  · exact candidate_root_290 statement witness valid lane
  · exact candidate_root_291 statement witness valid lane
  · exact candidate_root_292 statement witness valid lane
  · exact candidate_root_293 statement witness valid lane
  · exact candidate_root_336 statement witness valid lane
  · exact candidate_root_337 statement witness valid lane
  · exact candidate_root_338 statement witness valid lane
  · exact candidate_root_339 statement witness valid lane
  · exact candidate_root_340 statement witness valid lane
  · exact candidate_root_341 statement witness valid lane
  · exact candidate_root_342 statement witness valid lane
  · exact candidate_root_343 statement witness valid lane
  · exact candidate_root_442 statement witness valid lane
  · exact candidate_root_443 statement witness valid lane
  · exact candidate_root_444 statement witness valid lane
  · exact candidate_root_445 statement witness valid lane
  · exact candidate_root_446 statement witness valid lane
  · exact candidate_root_447 statement witness valid lane
  · exact candidate_root_448 statement witness valid lane

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingClosure

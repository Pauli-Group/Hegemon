import HegemonCrypto.SmallWoodV8Smz9SourceAuthFinalDAG
import HegemonCrypto.SmallWoodV8Smz9SourceAuthMembershipCore
namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalClosure
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMoreClosure
open HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
open HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalDAG
open HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMembershipCore
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section
theorem candidate_root_257 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[257]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_257,
    full_candidate_raw_field_readback statement witness ⟨76,by decide⟩ lane,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 117 .next 0 (by decide) (by decide)]
  exact congrArg some (output_next_key_product statement witness valid ⟨0,by decide⟩)

theorem candidate_root_258 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[258]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_258,
    full_candidate_raw_field_readback statement witness ⟨77,by decide⟩ lane,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 118 .next 1 (by decide) (by decide)]
  exact congrArg some (output_next_key_product statement witness valid ⟨1,by decide⟩)

theorem candidate_root_259 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[259]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_259,
    full_candidate_raw_field_readback statement witness ⟨78,by decide⟩ lane,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 119 .next 2 (by decide) (by decide)]
  exact congrArg some (output_next_key_product statement witness valid ⟨2,by decide⟩)

theorem candidate_root_260 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[260]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_260,
    full_candidate_raw_field_readback statement witness ⟨79,by decide⟩ lane,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 120 .next 3 (by decide) (by decide)]
  exact congrArg some (output_next_key_product statement witness valid ⟨3,by decide⟩)

theorem candidate_root_310 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[310]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_310,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 94 .mode 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 154 .scalar 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 155 .scalar 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 156 .scalar 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 157 .scalar 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 158 .scalar 6 (by decide) (by decide),
    remaining_named_readback statement witness lane 159 .scalar 7 (by decide) (by decide),
    remaining_named_readback statement witness lane 160 .scalar 8 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (current_bitmap_count_product statement witness valid)

theorem candidate_root_323 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[323]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_323,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 161 .scalar 9 (by decide) (by decide),
    remaining_named_readback statement witness lane 162 .scalar 10 (by decide) (by decide),
    remaining_named_readback statement witness lane 163 .scalar 11 (by decide) (by decide),
    remaining_named_readback statement witness lane 164 .scalar 12 (by decide) (by decide),
    remaining_named_readback statement witness lane 165 .scalar 13 (by decide) (by decide),
    remaining_named_readback statement witness lane 166 .scalar 14 (by decide) (by decide),
    remaining_named_readback statement witness lane 167 .scalar 15 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (next_bitmap_count_product statement witness valid)

theorem candidate_root_324 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[324]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_324,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 155 .scalar 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨0,by decide⟩).1

theorem candidate_root_325 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[325]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_325,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 155 .scalar 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 162 .scalar 10 (by decide) (by decide),
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨0,by decide⟩).2

theorem candidate_root_326 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[326]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_326,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 156 .scalar 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨1,by decide⟩).1

theorem candidate_root_327 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[327]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_327,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 156 .scalar 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 163 .scalar 11 (by decide) (by decide),
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨1,by decide⟩).2

theorem candidate_root_328 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[328]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_328,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 157 .scalar 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨2,by decide⟩).1

theorem candidate_root_329 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[329]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_329,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 157 .scalar 5 (by decide) (by decide),
    remaining_named_readback statement witness lane 164 .scalar 12 (by decide) (by decide),
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨2,by decide⟩).2

theorem candidate_root_330 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[330]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_330,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 158 .scalar 6 (by decide) (by decide),
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨3,by decide⟩).1

theorem candidate_root_331 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[331]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_331,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 158 .scalar 6 (by decide) (by decide),
    remaining_named_readback statement witness lane 165 .scalar 13 (by decide) (by decide),
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨3,by decide⟩).2

theorem candidate_root_332 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[332]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_332,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 159 .scalar 7 (by decide) (by decide),
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨4,by decide⟩).1

theorem candidate_root_333 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[333]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_333,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 159 .scalar 7 (by decide) (by decide),
    remaining_named_readback statement witness lane 166 .scalar 14 (by decide) (by decide),
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨4,by decide⟩).2

theorem candidate_root_334 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[334]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_334,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 160 .scalar 8 (by decide) (by decide),
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨5,by decide⟩).1

theorem candidate_root_335 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[335]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_335,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 160 .scalar 8 (by decide) (by decide),
    remaining_named_readback statement witness lane 167 .scalar 15 (by decide) (by decide),
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide)]
  simpa [authFamilyWord,authScalar] using congrArg some
    (membership_transition_products statement witness valid ⟨5,by decide⟩).2

theorem candidate_root_344 (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    (exactNonlinearRoots[344]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_root_344,
    remaining_named_readback statement witness lane 93 .mode 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 226 .membership 0 (by decide) (by decide),
    remaining_named_readback statement witness lane 227 .membership 1 (by decide) (by decide),
    remaining_named_readback statement witness lane 228 .membership 2 (by decide) (by decide),
    remaining_named_readback statement witness lane 229 .membership 3 (by decide) (by decide),
    remaining_named_readback statement witness lane 230 .membership 4 (by decide) (by decide),
    remaining_named_readback statement witness lane 231 .membership 5 (by decide) (by decide)]
  simpa [authFamilyWord,List.range_succ,add_comm,add_left_comm,add_assoc] using
    congrArg some (membership_sum_product statement witness valid)

def finalAuthIndex (index : Fin 19) : Nat := [257,258,259,260,310,323,324,325,326,327,328,329,330,331,332,333,334,335,344].getD index.val 0
theorem full_candidate_actual_19_final_auth_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (index : Fin 19) :
    (exactNonlinearRoots[finalAuthIndex index]?).map
      (fieldAt exactNonlinearExpressions (fun j => ((encodePublicStatement statement).getD j 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  fin_cases index
  · exact candidate_root_257 statement witness valid lane
  · exact candidate_root_258 statement witness valid lane
  · exact candidate_root_259 statement witness valid lane
  · exact candidate_root_260 statement witness valid lane
  · exact candidate_root_310 statement witness valid lane
  · exact candidate_root_323 statement witness valid lane
  · exact candidate_root_324 statement witness valid lane
  · exact candidate_root_325 statement witness valid lane
  · exact candidate_root_326 statement witness valid lane
  · exact candidate_root_327 statement witness valid lane
  · exact candidate_root_328 statement witness valid lane
  · exact candidate_root_329 statement witness valid lane
  · exact candidate_root_330 statement witness valid lane
  · exact candidate_root_331 statement witness valid lane
  · exact candidate_root_332 statement witness valid lane
  · exact candidate_root_333 statement witness valid lane
  · exact candidate_root_334 statement witness valid lane
  · exact candidate_root_335 statement witness valid lane
  · exact candidate_root_344 statement witness valid lane
end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalClosure

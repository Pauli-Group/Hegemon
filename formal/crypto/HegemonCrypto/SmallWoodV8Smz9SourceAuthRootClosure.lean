import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputSelection

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthRootClosure

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootTables
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInputSelection

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

theorem full_candidate_mode_row (statement : V8PublicStatement) (witness : V8Witness)
    (index : Fin 3) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (92 + index.val) =
      (authModeFlag witness.authorization.mode index.val : F) :=
  full_candidate_auth_family statement witness .mode index.val index.isLt lane

theorem full_candidate_mode0_row (statement : V8PublicStatement) (witness : V8Witness) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val 92 =
      (authModeFlag witness.authorization.mode 0 : F) :=
  full_candidate_mode_row statement witness ⟨0,by decide⟩ lane
theorem full_candidate_mode1_row (statement : V8PublicStatement) (witness : V8Witness) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val 93 =
      (authModeFlag witness.authorization.mode 1 : F) :=
  full_candidate_mode_row statement witness ⟨1,by decide⟩ lane
theorem full_candidate_mode2_row (statement : V8PublicStatement) (witness : V8Witness) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val 94 =
      (authModeFlag witness.authorization.mode 2 : F) :=
  full_candidate_mode_row statement witness ⟨2,by decide⟩ lane

theorem full_candidate_mode_root_zero (statement : V8PublicStatement) (witness : V8Witness)
    (pub : Nat → F) (index : Fin 4) (lane : Fin 64) :
    (exactNonlinearRoots[129 + index.val]?).map
      (fieldAt exactNonlinearExpressions pub
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  by_cases boolean : index.val < 3
  · rw [(actual_mode_table ⟨index.val,boolean⟩).1,Option.map_some,actual_mode_formula,
      full_candidate_mode_row statement witness ⟨index.val,boolean⟩ lane]
    exact congrArg some (mode_boolean witness.authorization.mode ⟨index.val,boolean⟩)
  · have last : index.val = 3 := by omega
    rw [last,show exactNonlinearRoots[129 + 3]? = some 1243 by decide,
      Option.map_some,actual_mode_sum_formula,
      full_candidate_mode0_row statement witness lane,
      full_candidate_mode1_row statement witness lane,
      full_candidate_mode2_row statement witness lane]
    exact congrArg some (mode_one_hot witness.authorization.mode)

theorem full_candidate_single_zero_root (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F)
    (index : Fin 109) (lane : Fin 64) :
    (exactNonlinearRoots[133 + index.val]?).map
      (fieldAt exactNonlinearExpressions pub
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  have table := actual_single_zero_table index
  rw [table.1,Option.map_some,actual_single_zero_formula,
    full_candidate_mode0_row statement witness lane,
    full_candidate_auth_row statement witness ⟨singleZeroOffset index.val,table.2.2.2.2⟩ lane]
  by_cases single : witness.authorization.mode = .singleKey
  · rw [single_protected_row_zero statement witness valid single _ _ table.2.2.2.1 table.2.2.2.2]
    simp only [Nat.cast_zero,mul_zero]
  · have gate : authModeFlag witness.authorization.mode 0 = 0 := by
      cases mode : witness.authorization.mode <;> simp_all [authModeFlag,authBit]
    rw [gate,Nat.cast_zero,zero_mul]

theorem final_source_zeroing (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (finalMode : witness.authorization.mode = .finalThresholdSpend) (hashes : AuthHashFinals)
    (index : Fin 22) :
    sourceAuthRow statement witness hashes (finalZeroOffset index.val) =
      if index.val = 9 then 1 else 0 := by
  obtain ⟨_,_,_,_,_,_,count,_,approved⟩ := final_zero_next statement witness valid finalMode
  have approvedWords := zero_words_readback _ approved
  fin_cases index <;> simp [finalZeroOffset,sourceAuthRow,authScalar,
    authNextCountFlag,authMembership,authBit,finalMode,count,approvedWords]

theorem full_candidate_final_zero_root (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F)
    (index : Fin 22) (lane : Fin 64) :
    (exactNonlinearRoots[449 + index.val]?).map
      (fieldAt exactNonlinearExpressions pub
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  have table := actual_final_zero_table index
  rw [table.1,Option.map_some,actual_final_zero_formula,
    full_candidate_mode2_row statement witness lane,
    full_candidate_auth_row statement witness ⟨finalZeroOffset index.val,table.2.2.2⟩ lane]
  by_cases finalMode : witness.authorization.mode = .finalThresholdSpend
  · rw [final_source_zeroing statement witness valid finalMode _ index]
    split_ifs <;> simp
  · have gate : authModeFlag witness.authorization.mode 2 = 0 := by
      cases mode : witness.authorization.mode <;> simp_all [authModeFlag,authBit]
    rw [gate,Nat.cast_zero,zero_mul]

/-- Exact145-root worklist: roots129..251, then449..470. -/
def selectedAuthRoot (index : Fin 145) : Nat :=
  if index.val < 123 then 129 + index.val else 326 + index.val

theorem selected_auth_root_intervals :
    (List.ofFn selectedAuthRoot) = List.range' 129 123 ++ List.range' 449 22 := by decide

/-- Fixed typed validity and actual encoded public values, with the original full source candidate. -/
theorem full_candidate_actual_145_auth_roots_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (index : Fin 145) :
    (exactNonlinearRoots[selectedAuthRoot index]?).map
      (fieldAt exactNonlinearExpressions
        (fun publicIndex => ((encodePublicStatement statement).getD publicIndex 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  by_cases early : index.val < 123
  · simp only [selectedAuthRoot,if_pos early]
    by_cases mode : index.val < 4
    · exact full_candidate_mode_root_zero statement witness _ ⟨index.val,mode⟩ lane
    by_cases single : index.val < 113
    · have address : 129 + index.val = 133 + (index.val - 4) := by omega
      rw [address]
      exact full_candidate_single_zero_root statement witness valid _ ⟨index.val - 4,by omega⟩ lane
    · let offset := index.val - 113
      have offsetBound : offset < 10 := by dsimp [offset]; omega
      have address : 129 + index.val = 242 + 5 * (offset / 5) + offset % 5 := by
        have parts := Nat.mod_add_div offset 5
        dsimp [offset] at *
        omega
      rw [address]
      exact full_candidate_input_auth_zero statement witness valid
        ⟨offset / 5,by omega⟩ ⟨offset % 5,Nat.mod_lt _ (by decide)⟩ lane
  · simp only [selectedAuthRoot,if_neg early]
    have address : 326 + index.val = 449 + (index.val - 123) := by omega
    rw [address]
    exact full_candidate_final_zero_root statement witness valid _ ⟨index.val - 123,by omega⟩ lane

end


end HegemonCrypto.SmallWood.V8Smz9SourceAuthRootClosure

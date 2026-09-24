import HegemonCrypto.SmallWoodV8Smz9SourceFullBalanceRoots
import HegemonCrypto.SmallWoodV8Smz9SourceInlineRoots
import HegemonCrypto.SmallWoodV8Smz9SourceAuthRemainingPacket
import HegemonCrypto.SmallWoodV8Smz9SourceRoleRoots
import HegemonCrypto.SmallWoodV8Smz9SourceFullStableBooleanRoots
import HegemonCrypto.SmallWoodV8Smz9SourceMultiplicationRoot
import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastClosure
import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastInverseClosure
import HegemonCrypto.SmallWoodV8Smz9SourceAuthFinalClosure

/-! Every actual nonlinear root on the same complete typed constructor.
This is field interpretation, not complete Option-interpreter execution,
complete CSR satisfaction, Rust refinement, or production-security authority. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceAllNonlinear
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceBalanceRoots
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRoots
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingPacket
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverseClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalClosure
open HegemonCrypto.SmallWood.V8Smz9SourceRoleRoots
open HegemonCrypto.SmallWood.V8Smz9SourceStableBooleanRoots
open HegemonCrypto.SmallWood.V8Smz9SourceMultiplicationRoot
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

abbrev actualSourcePub (statement : V8PublicStatement) : Nat → F :=
  fun i => ((encodePublicStatement statement).getD i 0 : F)

theorem actual_root_list_length : exactNonlinearRoots.length = 830 := by decide

theorem actual_dense_index_lookup (index : Fin 5) :
    exactNonlinearRoots[116 + index.val]? =
      some (if index.val < 4 then 1183 + 6 * index.val else 1203) := by
  fin_cases index <;> decide

theorem full_candidate_dense_indexed_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (index : Fin 5) :
    (exactNonlinearRoots[116 + index.val]?).map
      (fieldAt exactNonlinearExpressions (actualSourcePub statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [actual_dense_index_lookup,Option.map_some]
  by_cases lower : index.val < 4
  · rw [if_pos lower]
    exact congrArg some ((full_candidate_all_five_actual_dense_roots_zero statement witness valid lane).1
      ⟨index.val,lower⟩)
  · rw [if_neg lower]
    exact congrArg some (full_candidate_all_five_actual_dense_roots_zero statement witness valid lane).2

theorem middle_auth_complete_cover (index : Fin 197) :
    (∃ j : Fin 100, selectedPacketRoot j = 252 + index.val) ∨
    (∃ j : Fin 48, lastRootIndex j = 252 + index.val) ∨
    (∃ j : Fin 30, inverseRootIndex j = 252 + index.val) ∨
    (∃ j : Fin 19, finalAuthIndex j = 252 + index.val) := by
  have all : ∀ i : Fin 197,
      (∃ j : Fin 100, selectedPacketRoot j = 252 + i.val) ∨
      (∃ j : Fin 48, lastRootIndex j = 252 + i.val) ∨
      (∃ j : Fin 30, inverseRootIndex j = 252 + i.val) ∨
      (∃ j : Fin 19, finalAuthIndex j = 252 + i.val) := by decide
  exact all index

theorem full_candidate_middle_auth_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (index : Fin 197) :
    (exactNonlinearRoots[252 + index.val]?).map
      (fieldAt exactNonlinearExpressions (actualSourcePub statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rcases middle_auth_complete_cover index with ⟨j,equal⟩ | ⟨j,equal⟩ | ⟨j,equal⟩ | ⟨j,equal⟩
  · rw [← equal]
    exact full_candidate_actual_100_remaining_auth_roots_zero statement witness valid lane j
  · rw [← equal]
    exact full_candidate_actual_48_last_auth_roots_zero statement witness valid lane j
  · rw [← equal]
    exact full_candidate_actual_30_inverse_auth_roots_zero statement witness valid lane j
  · rw [← equal]
    exact full_candidate_actual_19_final_auth_roots_zero statement witness valid lane j

theorem actual_hash_index_present (index : Fin 332) :
    ∃ root, exactNonlinearRoots[471 + index.val]? = some root ∧
      root ∈ (exactNonlinearRoots.drop 471).take 332 := by
  have bound : 471 + index.val < exactNonlinearRoots.length := by rw [actual_root_list_length]; omega
  let root := exactNonlinearRoots[471 + index.val]'bound
  have found : exactNonlinearRoots[471 + index.val]? = some root := List.getElem?_eq_getElem bound
  refine ⟨root,found,?_⟩
  apply List.mem_of_getElem? (i := index.val)
  rw [List.getElem?_take_of_lt index.isLt,List.getElem?_drop]
  exact found

theorem full_candidate_hash_indexed_zero (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) (index : Fin 332) :
    (exactNonlinearRoots[471 + index.val]?).map
      (fieldAt exactNonlinearExpressions (actualSourcePub statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  obtain ⟨root,found,member⟩ := actual_hash_index_present index
  rw [found,Option.map_some]
  exact congrArg some (full_candidate_all_332_actual_hash_roots_zero statement witness
    (encodePublicStatement statement) lane root member)

theorem full_candidate_all_830_actual_nonlinear_roots_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (lane : Fin 64) (index : Fin 830) :
    (exactNonlinearRoots[index.val]?).map
      (fieldAt exactNonlinearExpressions (actualSourcePub statement)
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  by_cases early : index.val < 116
  · exact full_candidate_first116_nonlinear_roots_zero statement witness valid lane ⟨index.val,early⟩
  by_cases dense : index.val < 121
  · have result := full_candidate_dense_indexed_zero statement witness valid lane ⟨index.val-116,by omega⟩
    simpa only [show 116 + (index.val-116) = index.val by omega] using result
  by_cases inline : index.val < 129
  · have result := full_candidate_actual_eight_inline_roots_zero statement witness (actualSourcePub statement)
      lane ⟨index.val-121,by omega⟩
    simpa only [show 121 + (index.val-121) = index.val by omega] using result
  by_cases initialAuth : index.val < 252
  · have result := full_candidate_actual_145_auth_roots_zero statement witness valid lane ⟨index.val-129,by omega⟩
    simpa only [selectedAuthRoot,if_pos (show index.val-129 < 123 by omega),
      show 129 + (index.val-129) = index.val by omega] using result
  by_cases middleAuth : index.val < 449
  · have result := full_candidate_middle_auth_zero statement witness valid lane ⟨index.val-252,by omega⟩
    simpa only [show 252 + (index.val-252) = index.val by omega] using result
  by_cases finalAuth : index.val < 471
  · have result := full_candidate_actual_145_auth_roots_zero statement witness valid lane ⟨index.val-326,by omega⟩
    simpa only [selectedAuthRoot,if_neg (show ¬index.val-326 < 123 by omega),
      show 326 + (index.val-326) = index.val by omega] using result
  by_cases hash : index.val < 803
  · have result := full_candidate_hash_indexed_zero statement witness lane ⟨index.val-471,by omega⟩
    simpa only [show 471 + (index.val-471) = index.val by omega] using result
  by_cases role : index.val < 805
  · have result := full_candidate_actual_role_roots_zero statement witness valid (encodePublicStatement statement)
      lane ⟨index.val-803,by omega⟩
    simpa only [show 803 + (index.val-803) = index.val by omega] using result
  by_cases boolean : index.val = 805
  · rw [boolean]
    exact (full_candidate_actual_stable_boolean_and_radix_roots_zero statement witness valid lane).1
  by_cases multiplication : index.val = 806
  · rw [multiplication]
    exact full_candidate_actual_multiplication_root_zero statement witness valid (encodePublicStatement statement) lane
  · have result := (full_candidate_actual_stable_boolean_and_radix_roots_zero statement witness valid lane).2
      ⟨index.val-807,by omega⟩
    simpa only [show 807 + (index.val-807) = index.val by omega] using result

end
end HegemonCrypto.SmallWood.V8Smz9SourceAllNonlinear

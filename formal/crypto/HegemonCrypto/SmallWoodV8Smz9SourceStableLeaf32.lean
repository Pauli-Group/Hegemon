import HegemonCrypto.SmallWoodV8Smz9SourceStableLeafFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableLeaf32
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableStateCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableLeafFrames
open HegemonCrypto.SmallWood.V8Smz9StableStateHash
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_leaf_high_coefficient (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 16) (high : 11 ≤ lane.val) :
    actualCsrCoefficients (liveTypedPub statement)
      (if lane.val=11 then 346 else if lane.val<14 then 0 else if lane.val=14 then 558 else 544) =
      (leafHighWord statement lane.val : F) := by
  have index := actual_stable_index_coefficient (liveTypedPub statement)
  rw [live_typed_public_asset_val statement witness valid] at index
  have domain : actualCsrCoefficients (liveTypedPub statement) 558 = (stablecoinV8DomainStateLeaf : F) :=
    actual_csr_node_field_equation _ (show exactCsrExpressions[558]? = some (.constant stablecoinV8DomainStateLeaf) by decide)
  have marker : actualCsrCoefficients (liveTypedPub statement) 544 = (poseidon2V8SuiteMarker : F) :=
    actual_csr_node_field_equation _ (show exactCsrExpressions[544]? = some (.constant poseidon2V8SuiteMarker) by decide)
  fin_cases lane <;> simp_all [leafHighWord,(actual_csr_zero_one (liveTypedPub statement)).1]

theorem full_candidate_leaf_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (lane : Fin 16) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (leafAttempt which.val lane.val) = 0 := by
  by_cases low : lane.val<7
  · simp only [leafAttempt,if_pos low]
    rw [actual_copy_residual_formula,full_candidate_leaf_config statement witness valid which ⟨lane.val,low⟩,sub_self]
  · by_cases middle : lane.val<11
    · have counterBound : lane.val-7<4 := by omega
      have address : 7+(lane.val-7)=lane.val := by omega
      by_cases before : which.val=0
      · have whichZero : which=⟨0,by decide⟩ := Fin.ext before
        subst which
        have source := full_candidate_leaf_before statement witness valid ⟨lane.val-7,counterBound⟩
        simp only [address] at source
        simp only [leafAttempt,if_neg low,if_pos middle,
          and_true,if_true,Nat.add_zero]
        rw [actual_copy_residual_formula,source,sub_self]
      · have whichOne : which=⟨1,by decide⟩ := Fin.ext (by change which.val=1; omega)
        subst which
        have source := full_candidate_leaf_after statement witness valid ⟨lane.val-7,counterBound⟩
        simp only [address] at source
        have target := actual_public_coefficient (liveTypedPub statement) ⟨109+(lane.val-7),by omega⟩
        have targetAddress : 4+(109+(lane.val-7))=113+(lane.val-7) := by omega
        simp only [targetAddress] at target
        simp only [leafAttempt,if_neg low,if_pos middle,
          if_neg (show ¬(lane.val<11 ∧ (1:Nat)=0) by omega),if_neg (show ¬(1:Nat)=0 by decide),
          attempt,actualCsrResidual,actualCsrTerms,
          List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one (liveTypedPub statement)).2,one_mul,add_zero]
        rw [target,source]
        exact sub_self _
    · simp only [leafAttempt,if_neg low,if_neg middle,
        if_neg (show ¬(lane.val<11 ∧ which.val=0) from fun h => middle h.1),attempt,actualCsrResidual,actualCsrTerms,
        List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one (liveTypedPub statement)).2,one_mul,add_zero]
      rw [actual_leaf_high_coefficient statement witness valid lane (by omega),
        full_candidate_leaf_high statement witness valid which lane (by omega),sub_self]

theorem stable_leaf32_distinct_count : ((List.range 32).map (19972+·)).length = 32 ∧
    ((List.range 32).map (19972+·)).Nodup := by decide

theorem full_candidate_actual_leaf32_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 32) :
    (exactCsrAttempts[19972+index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  have found := exact_attempt_lookup _ (exact_leaf_attempts ⟨index.val/16,by omega⟩ ⟨index.val%16,by omega⟩)
  have address : 19972+16*(index.val/16)+index.val%16=19972+index.val := by omega
  change exactCsrAttempts[19972+16*(index.val/16)+index.val%16]? = _ at found
  rw [address] at found
  rw [found,Option.map_some,full_candidate_leaf_attempt_zero statement witness valid]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableLeaf32

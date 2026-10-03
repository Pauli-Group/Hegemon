import HegemonCrypto.SmallWoodV8Smz9SourceStablePathFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourceStablePath128
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableStateCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStablePathFrames
open HegemonCrypto.SmallWood.V8Smz9StableStateHash
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_path_capacity_coefficient (pub : Nat → F) (level : Fin 4) (lane : Fin 16) :
    actualCsrCoefficients pub (if lane.val=14 then 559+level.val else 544) =
      (((if lane.val=14 then stablecoinV8DomainStateNode0+level.val else poseidon2V8SuiteMarker) : Nat) : F) := by
  have found : exactCsrExpressions[if lane.val=14 then 559+level.val else 544]? =
      some (.constant (if lane.val=14 then stablecoinV8DomainStateNode0+level.val else poseidon2V8SuiteMarker)) := by
    fin_cases level <;> fin_cases lane <;> decide
  exact actual_csr_node_field_equation pub found

theorem full_candidate_path_rate_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (level : Fin 4) (which : Fin 2) (lane : Fin 14) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (pathAttempt level.val which.val lane.val) = 0 := by
  have coeff := actual_stable_orientation_coefficients (liveTypedPub statement) level
  rw [live_typed_public_asset_val statement witness valid] at coeff
  have bitBound : sourceAssetBit statement.stablecoin.assetId level.val < 2 := Nat.mod_lt _ (by decide)
  have initial := full_candidate_path_rate statement witness valid level which lane
  by_cases bit : sourceAssetBit statement.stablecoin.assetId level.val=0
  · simp only [bit,Nat.cast_zero,sub_zero,neg_zero] at coeff
    by_cases left : lane.val<7
    all_goals simp only [pathAttempt,left,lane.isLt,↓reduceIte,attempt,actualCsrResidual,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one (liveTypedPub statement)).1,
      (actual_csr_zero_one (liveTypedPub statement)).2,coeff.1,coeff.2,one_mul,neg_one_mul,zero_mul,add_zero,sub_zero]
    all_goals rw [initial]
    all_goals simp only [pathSourceWord,bit,left,↓reduceIte,add_neg_cancel]
  · have bitOne : sourceAssetBit statement.stablecoin.assetId level.val=1 := by omega
    simp only [bitOne,Nat.cast_one,sub_self,neg_zero] at coeff
    by_cases left : lane.val<7
    all_goals simp only [pathAttempt,left,lane.isLt,↓reduceIte,attempt,actualCsrResidual,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one (liveTypedPub statement)).1,
      (actual_csr_zero_one (liveTypedPub statement)).2,coeff.1,coeff.2,one_mul,neg_one_mul,zero_mul,add_zero,zero_add,sub_zero]
    all_goals rw [initial]
    all_goals simp only [pathSourceWord,bit,left,↓reduceIte,add_neg_cancel]

theorem full_candidate_path_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (level : Fin 4) (which : Fin 2) (lane : Fin 16) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (pathAttempt level.val which.val lane.val) = 0 := by
  by_cases rate : lane.val<14
  · exact full_candidate_path_rate_zero statement witness valid level which ⟨lane.val,rate⟩
  · simp only [pathAttempt,if_neg rate,if_neg (show ¬lane.val<7 by omega),attempt,actualCsrResidual,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one (liveTypedPub statement)).2,one_mul,add_zero]
    rw [actual_path_capacity_coefficient (liveTypedPub statement) level lane,
      full_candidate_path_capacity statement witness valid level which lane (by omega),sub_self]

theorem stable_path128_distinct_count : ((List.range 128).map (20004+·)).length = 128 ∧
    ((List.range 128).map (20004+·)).Nodup := by decide

theorem full_candidate_actual_path128_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 128) :
    (exactCsrAttempts[20004+index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  have found := exact_attempt_lookup _ (exact_path_attempts ⟨index.val/32,by omega⟩
    ⟨(index.val%32)/16,by omega⟩ ⟨index.val%16,by omega⟩)
  have address : 20004+32*(index.val/32)+16*((index.val%32)/16)+index.val%16=20004+index.val := by omega
  change exactCsrAttempts[20004+32*(index.val/32)+16*((index.val%32)/16)+index.val%16]? = _ at found
  rw [address] at found
  rw [found,Option.map_some,full_candidate_path_attempt_zero statement witness valid]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStablePath128

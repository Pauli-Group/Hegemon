import HegemonCrypto.SmallWoodV8Smz9SourceStableStateCoefficients
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleInitialFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourceStablePathFrames
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableStateCoefficients
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem actual_stable_path_frame (statement : V8PublicStatement) (witness : V8Witness)
    (level : Fin 4) (which : Fin 2) :
    actualSourceFrame statement witness ⟨115+2*level.val+which.val,by omega⟩ =
      let operands := orient (statement.stablecoin.assetId &&& 15) level.val
        (finalDigest (scheduledFinal statement witness) (113+2*level.val+which.val))
        (stableSibling witness level.val)
      compressFrameWords (stablecoinV8DomainStateNode0+level.val) operands.1 operands.2 := by
  fin_cases level <;> fin_cases which <;> rfl

theorem full_candidate_stable_sibling (statement : V8PublicStatement) (witness : V8Witness)
    (level : Fin 4) (limb : Fin 7) :
    (stableSibling witness level.val).getD limb.val 0 =
      (fullTypedSourceCandidate statement witness).getD (41463+7*level.val+limb.val) 0 := by
  have address : 41463+7*level.val+limb.val=41408+(55+(7*level.val+limb.val)) := by omega
  rw [address,full_candidate_source_word_readback statement witness ⟨55+(7*level.val+limb.val),by omega⟩,
    stable_source_sibling_readback statement witness (7*level.val+limb.val) (by omega)]
  simp only [stableSibling,stableWitnessSlice,List.getD_eq_getElem?_getD,List.getElem?_map,
    List.getElem?_range,limb.isLt,Option.map_some,Option.getD_some]
  congr 1
  omega

theorem full_candidate_digest_word (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (limb : Fin 7) :
    (finalDigest (scheduledFinal statement witness) call.val).getD limb.val 0 =
      (fullTypedSourceCandidate statement witness).getD (hashFinalIndex call.val limb.val) 0 := by
  rw [full_candidate_final_schedule_readback statement witness call ⟨limb.val,by omega⟩]
  simp only [finalDigest,List.getD_eq_getElem?_getD,List.getElem?_take,limb.isLt,if_true]

def pathSourceWord (statement : V8PublicStatement) (witness : V8Witness) (level which lane : Nat) : Nat :=
  let previous := (fullTypedSourceCandidate statement witness).getD (hashFinalIndex (113+2*level+which) (lane%7)) 0
  let sibling := (fullTypedSourceCandidate statement witness).getD (41463+7*level+lane%7) 0
  if sourceAssetBit statement.stablecoin.assetId level=0 then
    if lane<7 then previous else sibling
  else if lane<7 then sibling else previous

theorem full_candidate_path_rate (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (level : Fin 4) (which : Fin 2) (lane : Fin 14) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (115+2*level.val+which.val) lane.val) 0 =
      pathSourceWord statement witness level.val which.val lane.val := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨115+2*level.val+which.val,by omega⟩
    ⟨lane.val,by omega⟩,actual_stable_path_frame]
  have masked : ((statement.stablecoin.assetId &&& 15)/2^level.val)%2 =
      sourceAssetBit statement.stablecoin.assetId level.val := by
    rw [stable_asset_mask_exact]
    exact source_asset_bit_mask _ level
  rw [orient_is_source_bit,masked]
  by_cases bit : sourceAssetBit statement.stablecoin.assetId level.val=0
  · simp only [pathSourceWord,if_pos bit]
    rw [compress_frame_word _ _ _ ⟨lane.val,by omega⟩]
    by_cases left : lane.val<7
    · simp only [if_pos left,Nat.mod_eq_of_lt left]
      exact full_candidate_digest_word statement witness ⟨113+2*level.val+which.val,by omega⟩ ⟨lane.val,left⟩
    · simp only [if_neg left,if_pos lane.isLt,show lane.val%7=lane.val-7 by omega]
      exact full_candidate_stable_sibling statement witness level ⟨lane.val-7,by omega⟩
  · simp only [pathSourceWord,if_neg bit]
    rw [compress_frame_word _ _ _ ⟨lane.val,by omega⟩]
    by_cases left : lane.val<7
    · simp only [if_pos left,Nat.mod_eq_of_lt left]
      exact full_candidate_stable_sibling statement witness level ⟨lane.val,left⟩
    · simp only [if_neg left,if_pos lane.isLt,show lane.val%7=lane.val-7 by omega]
      exact full_candidate_digest_word statement witness ⟨113+2*level.val+which.val,by omega⟩ ⟨lane.val-7,by omega⟩

theorem full_candidate_path_capacity (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (level : Fin 4) (which : Fin 2) (lane : Fin 16)
    (capacity : 14 ≤ lane.val) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (115+2*level.val+which.val) lane.val) 0 =
      if lane.val=14 then stablecoinV8DomainStateNode0+level.val else poseidon2V8SuiteMarker := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨115+2*level.val+which.val,by omega⟩ lane,
    actual_stable_path_frame,compress_frame_word]
  simp only [if_neg (show ¬lane.val<7 by omega),if_neg (show ¬lane.val<14 by omega)]

end HegemonCrypto.SmallWood.V8Smz9SourceStablePathFrames

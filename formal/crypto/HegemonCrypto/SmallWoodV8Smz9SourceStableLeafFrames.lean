import HegemonCrypto.SmallWoodV8Smz9SourceStablePathFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableLeafFrames
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStablePathFrames
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem encoded_stable_after_counter (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (counter : Fin 4) :
    (encodePublicStatement statement).getD (109+counter.val) 0 =
      (sourceCounterWords statement.stablecoin.after).getD counter.val 0 := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,intent,before,after,_⟩ := valid.1
  have source := encoded_stable_public_word statement valid.1 (26+counter.val)
  fin_cases counter <;>
    simpa [encodeStablecoinPublic,sourceCounterWords,List.getD_eq_getElem?_getD,
      List.getElem?_append,List.length_append,intent.1,before.1,after.1,digestWords] using source

theorem actual_stable_leaf_frame (statement : V8PublicStatement) (witness : V8Witness) (which : Fin 2) :
    actualSourceFrame statement witness ⟨113+which.val,by omega⟩ =
      compressFrameWords stablecoinV8DomainStateLeaf (finalDigest (scheduledFinal statement witness) 112)
        (stableLeafRight statement witness (which.val=1)) := by
  fin_cases which <;> rfl

theorem full_candidate_leaf_config (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (lane : Fin 7) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (113+which.val) lane.val) 0 =
      (fullTypedSourceCandidate statement witness).getD (hashFinalIndex 112 lane.val) 0 := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨113+which.val,by omega⟩ ⟨lane.val,by omega⟩,
    actual_stable_leaf_frame,compress_frame_word _ _ _ ⟨lane.val,by omega⟩,if_pos lane.isLt]
  exact full_candidate_digest_word statement witness ⟨112,by decide⟩ lane

theorem full_candidate_leaf_before (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (counter : Fin 4) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex 113 (7+counter.val)) 0 =
      (fullTypedSourceCandidate statement witness).getD (41498+counter.val) 0 := by
  have address : 41498+counter.val=41408+(90+counter.val) := by omega
  have frame := actual_stable_leaf_frame statement witness ⟨0,by decide⟩
  change actualSourceFrame statement witness ⟨113,by decide⟩ = _ at frame
  rw [address,full_candidate_source_word_readback statement witness ⟨90+counter.val,by omega⟩,
    stable_source_before_readback statement witness counter.val counter.isLt,
    full_candidate_initial_source_readback statement witness valid ⟨113,by decide⟩ ⟨7+counter.val,by omega⟩,
    frame,
    compress_frame_word _ _ _ ⟨7+counter.val,by omega⟩]
  fin_cases counter <;> simp [stableLeafRight,stableBeforeWords,stableWitnessSlice,List.range_succ]

theorem full_candidate_leaf_after (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (counter : Fin 4) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex 114 (7+counter.val)) 0 =
      (encodePublicStatement statement).getD (109+counter.val) 0 := by
  have frame := actual_stable_leaf_frame statement witness ⟨1,by decide⟩
  change actualSourceFrame statement witness ⟨114,by decide⟩ = _ at frame
  rw [encoded_stable_after_counter statement witness valid counter,
    full_candidate_initial_source_readback statement witness valid ⟨114,by decide⟩ ⟨7+counter.val,by omega⟩,
    frame,
    compress_frame_word _ _ _ ⟨7+counter.val,by omega⟩]
  fin_cases counter <;> simp [stableLeafRight,sourceCounterWords]

def leafHighWord (statement : V8PublicStatement) (lane : Nat) : Nat :=
  if lane=11 then statement.stablecoin.assetId%16 else if lane=14 then stablecoinV8DomainStateLeaf
  else if lane=15 then poseidon2V8SuiteMarker else 0

theorem full_candidate_leaf_high (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (lane : Fin 16)
    (high : 11 ≤ lane.val) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (113+which.val) lane.val) 0 =
      leafHighWord statement lane.val := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨113+which.val,by omega⟩ lane,
    actual_stable_leaf_frame,compress_frame_word]
  fin_cases which <;> fin_cases lane <;>
    simp_all [leafHighWord,stableLeafRight,sourceCounterWords,stableBeforeWords,stableWitnessSlice,List.range_succ]

end HegemonCrypto.SmallWood.V8Smz9SourceStableLeafFrames

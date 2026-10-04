import HegemonCrypto.SmallWoodV8Smz9SourceStableNode48

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableChunk64
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9StableConfigHash
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_stable_chunk_frame (statement : V8PublicStatement) (witness : V8Witness) (chunk : Fin 4) :
    actualSourceFrame statement witness ⟨106+chunk.val,by omega⟩ =
      compressFrameWords (stablecoinV8ConfigChunkDomains.getD chunk.val 0)
        (fixedWords 7 ((stableConfigWords witness).drop (chunk.val*14)))
        (fixedWords 7 ((stableConfigWords witness).drop (chunk.val*14+7))) := by
  fin_cases chunk <;> rfl

theorem config_source_word (witness : V8Witness) (offset : Nat) :
    (stableConfigWords witness).getD offset 0 =
      if offset<55 then stableWitnessWord witness.stablecoin offset else 0 := by
  simp only [stableConfigWords,stableWitnessSlice,List.getD_eq_getElem?_getD,
    List.getElem?_map,Nat.zero_add]
  split <;> simp_all

theorem fixed_drop_word (values : List Nat) (offset : Nat) (limb : Fin 7) :
    (fixedWords 7 (values.drop offset)).getD limb.val 0 = values.getD (offset+limb.val) 0 := by
  simp only [fixedWords,List.getD_eq_getElem?_getD,List.getElem?_map,List.getElem?_range,
    limb.isLt,Option.map_some,Option.getD_some,List.getElem?_drop]

theorem actual_chunk_frame_rate (statement : V8PublicStatement) (witness : V8Witness)
    (chunk : Fin 4) (lane : Fin 14) :
    (actualSourceFrame statement witness ⟨106+chunk.val,by omega⟩).getD lane.val 0 =
      if chunk.val*14+lane.val<55 then stableWitnessWord witness.stablecoin (chunk.val*14+lane.val) else 0 := by
  rw [actual_stable_chunk_frame,compress_frame_word _ _ _ ⟨lane.val,by omega⟩]
  by_cases left : lane.val<7
  · rw [if_pos left,fixed_drop_word _ _ ⟨lane.val,left⟩,config_source_word]
  · rw [if_neg left,if_pos lane.isLt,fixed_drop_word _ _ ⟨lane.val-7,by omega⟩]
    have address : chunk.val*14+7+(lane.val-7)=chunk.val*14+lane.val := by omega
    rw [address,config_source_word]

theorem full_candidate_chunk_copy (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (word : Fin 55) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (106+word.val/14) (word.val%14)) 0 =
      (fullTypedSourceCandidate statement witness).getD (41408+word.val) 0 := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨106+word.val/14,by omega⟩
    ⟨word.val%14,by omega⟩,actual_chunk_frame_rate statement witness ⟨word.val/14,by omega⟩ ⟨word.val%14,by omega⟩]
  have address : word.val/14*14+word.val%14=word.val := by omega
  rw [address,if_pos word.isLt,full_candidate_source_word_readback statement witness ⟨word.val,by omega⟩,
    stable_source_config_readback statement witness word.val word.isLt]

theorem full_candidate_chunk_constant (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (chunk : Fin 4) (lane : Fin 16)
    (constant : 14 ≤ lane.val ∨ chunk.val*14+lane.val=55) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (106+chunk.val) lane.val) 0 =
      chunkConstant chunk.val lane.val := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨106+chunk.val,by omega⟩ lane]
  by_cases rate : lane.val<14
  · have last : chunk.val*14+lane.val=55 := by omega
    rw [actual_chunk_frame_rate statement witness chunk ⟨lane.val,rate⟩,last,if_neg (by decide)]
    simp only [chunkConstant,if_neg (show lane.val≠14 by omega),if_neg (show lane.val≠15 by omega)]
  · rw [actual_stable_chunk_frame,compress_frame_word]
    simp only [if_neg (show ¬lane.val<7 by omega),if_neg rate,chunkConstant]
    split <;> (try rfl)
    have last : lane.val=15 := by omega
    simp only [last,if_true]

theorem actual_chunk_constant_coefficient (pub : Nat → F) (chunk : Fin 4) (lane : Fin 16) :
    actualCsrCoefficients pub (if lane.val=14 then 551+chunk.val else if lane.val=15 then 544 else 0) =
      (chunkConstant chunk.val lane.val : F) := by
  have found : exactCsrExpressions[if lane.val=14 then 551+chunk.val else if lane.val=15 then 544 else 0]? =
      some (.constant (chunkConstant chunk.val lane.val)) := by
    fin_cases chunk <;> fin_cases lane <;> decide
  exact actual_csr_node_field_equation pub found

theorem full_candidate_chunk_constant_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (chunk : Fin 4) (lane : Fin 16)
    (constant : 14 ≤ lane.val ∨ chunk.val*14+lane.val=55) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (chunkConstantAttempt chunk.val lane.val) = 0 := by
  simp only [chunkConstantAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one pub).2,one_mul,add_zero]
  rw [actual_chunk_constant_coefficient pub chunk lane,
    full_candidate_chunk_constant statement witness valid chunk lane constant,sub_self]

theorem full_candidate_config_copy_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (word : Fin 55) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (stableCopyAttempt word.val) = 0 := by
  simp only [stableCopyAttempt,if_pos word.isLt,stableCopyDestination,stableCopySource,stableSourceIndex]
  rw [actual_copy_residual_formula,full_candidate_chunk_copy statement witness valid word,sub_self]

theorem stable_chunk64_distinct_count : ((List.range 64).map (19860+·)).length = 64 ∧
    ((List.range 64).map (19860+·)).Nodup := by decide

theorem full_candidate_actual_chunk64_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (index : Fin 64) :
    (exactCsrAttempts[19860+index.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  let chunk : Fin 4 := ⟨index.val/16,by omega⟩
  let lane : Fin 16 := ⟨index.val%16,by omega⟩
  by_cases rate : lane.val<14 ∧ chunk.val*14+lane.val<55
  · let word : Fin 55 := ⟨chunk.val*14+lane.val,rate.2⟩
    have found := exact_attempt_lookup _ (exact_stable_copy_attempts word.val (by omega))
    have division : word.val/14=chunk.val := by dsimp [word]; omega
    have modulo : word.val%14=lane.val := by dsimp [word]; omega
    have address : (stableCopyAttempt word.val).globalIndex=19860+index.val := by
      simp only [stableCopyAttempt,if_pos word.isLt,attempt,division,modulo]
      dsimp [chunk,lane]
      omega
    rw [address] at found
    rw [found,Option.map_some,full_candidate_config_copy_zero statement witness valid pub word]
  · have constant : 14 ≤ lane.val ∨ chunk.val*14+lane.val=55 := by
      dsimp [chunk,lane] at *
      omega
    have found := exact_attempt_lookup _ (exact_chunk_constant_attempts chunk lane constant)
    have address : (chunkConstantAttempt chunk.val lane.val).globalIndex=19860+index.val := by
      dsimp [chunkConstantAttempt,attempt,chunk,lane]
      omega
    rw [address] at found
    rw [found,Option.map_some,full_candidate_chunk_constant_zero statement witness valid pub chunk lane constant]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableChunk64

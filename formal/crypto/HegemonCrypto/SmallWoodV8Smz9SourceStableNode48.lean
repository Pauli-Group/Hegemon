import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleInitialFrames
import HegemonCrypto.SmallWoodV8Smz9StableConfigHash

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableNode48
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9StableConfigHash
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_stable_node_frame (statement : V8PublicStatement) (witness : V8Witness) (node : Fin 3) :
    actualSourceFrame statement witness ⟨110+node.val,by omega⟩ =
      compressFrameWords (nodeDomain node.val)
        (finalDigest (scheduledFinal statement witness) (nodeChild node.val 0))
        (finalDigest (scheduledFinal statement witness) (nodeChild node.val 1)) := by
  fin_cases node <;> rfl

theorem full_candidate_node_rate (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (node : Fin 3) (lane : Fin 14) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (110+node.val) lane.val) 0 =
      (fullTypedSourceCandidate statement witness).getD
        (hashFinalIndex (nodeChild node.val (lane.val/7)) (lane.val%7)) 0 := by
  have childBound : nodeChild node.val (lane.val/7) < 125 := by
    unfold nodeChild
    split <;> omega
  rw [full_candidate_initial_source_readback statement witness valid ⟨110+node.val,by omega⟩
      ⟨lane.val,by omega⟩, actual_stable_node_frame,
    compress_frame_word _ _ _ ⟨lane.val,by omega⟩,
    full_candidate_final_schedule_readback statement witness ⟨_,childBound⟩ ⟨lane.val%7,by omega⟩]
  by_cases left : lane.val < 7
  · simp only [show lane.val/7=0 by omega, Nat.mod_eq_of_lt left,
      finalDigest,List.getD_eq_getElem?_getD,List.getElem?_take,left,if_true]
  · simp only [if_neg left,if_pos lane.isLt,show lane.val/7=1 by omega,
      show lane.val%7=lane.val-7 by omega,finalDigest,List.getD_eq_getElem?_getD,
      List.getElem?_take,show lane.val-7<7 by omega,if_true]

theorem full_candidate_node_capacity (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (node : Fin 3) (lane : Fin 16)
    (capacity : 14 ≤ lane.val) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (110+node.val) lane.val) 0 =
      if lane.val=14 then nodeDomain node.val else poseidon2V8SuiteMarker := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨110+node.val,by omega⟩ lane,
    actual_stable_node_frame,compress_frame_word]
  simp only [if_neg (show ¬lane.val<7 by omega),if_neg (show ¬lane.val<14 by omega)]

theorem actual_node_capacity_coefficient (pub : Nat → F) (node : Fin 3) (lane : Fin 16) :
    actualCsrCoefficients pub (if lane.val=14 then 555+node.val else 544) =
      (((if lane.val=14 then nodeDomain node.val else poseidon2V8SuiteMarker) : Nat) : F) := by
  have exactNode : exactCsrExpressions[if lane.val=14 then 555+node.val else 544]? =
      some (.constant (if lane.val=14 then nodeDomain node.val else poseidon2V8SuiteMarker)) := by
    fin_cases node <;> fin_cases lane <;> decide
  exact actual_csr_node_field_equation pub exactNode

theorem full_candidate_node_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (node : Fin 3) (lane : Fin 16) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (nodeAttempt node.val lane.val) = 0 := by
  by_cases rate : lane.val<14
  · simp only [nodeAttempt,if_pos rate]
    rw [actual_copy_residual_formula,full_candidate_node_rate statement witness valid node ⟨lane.val,rate⟩,sub_self]
  · simp only [nodeAttempt,if_neg rate,attempt,actualCsrResidual,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one pub).2,one_mul,add_zero]
    rw [actual_node_capacity_coefficient pub node lane,
      full_candidate_node_capacity statement witness valid node lane (by omega),sub_self]

theorem stable_node48_distinct_count : ((List.range 48).map (19924+·)).length = 48 ∧
    ((List.range 48).map (19924+·)).Nodup := by decide

theorem full_candidate_actual_node48_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (index : Fin 48) :
    (exactCsrAttempts[19924+index.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  have found := exact_attempt_lookup _ (exact_node_attempts ⟨index.val/16,by omega⟩ ⟨index.val%16,by omega⟩)
  have address : 19924+16*(index.val/16)+index.val%16=19924+index.val := by omega
  change exactCsrAttempts[19924+16*(index.val/16)+index.val%16]? = _ at found
  rw [address] at found
  rw [found,Option.map_some,full_candidate_node_attempt_zero statement witness valid pub]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableNode48

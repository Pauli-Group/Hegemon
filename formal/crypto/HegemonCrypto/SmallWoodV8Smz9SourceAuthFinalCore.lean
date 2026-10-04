import HegemonCrypto.SmallWoodV8Smz9SourceAuthMoreClosure
import HegemonCrypto.SmallWoodV8Smz9SourceAuthorizationDigests
import HegemonCrypto.SmallWoodV8Smz9SourceEarlyPathRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalCore
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem approval_effective_next (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    effectiveNext witness.authorization = witness.authorization.next := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,approval] at auth
  obtain ⟨_,_,_,_,_,_,policy,intent,threshold,signers,_⟩ := auth
  unfold effectiveNext
  rw [← policy,← intent,← threshold,← signers]

theorem approval_output_next_binding (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    (witness.outputs.getD 0 default).note.authorizationKey =
      (exactV8AccumulatorDigest witness.authorization.next).take 4 := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,approval] at auth
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,key⟩ := auth
  exact key

theorem typed_next_hash_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) (limb : Fin 7) :
    authHashWord (typedSourceFinals statement witness) 103 limb.val =
      (exactV8AccumulatorDigest witness.authorization.next).getD limb.val 0 := by
  rw [auth_hash_word_readback _ ⟨103,by decide⟩ limb]
  change callFinalWord (typedLiveInitialStates statement witness) 103 limb.val = _
  rw [typed_call_final_word_is_scheduled statement witness ⟨103,by decide⟩]
  apply first_seven_readback
  rw [typed_effective_next_digest_exact statement witness valid,
    approval_effective_next statement witness valid approval]

theorem output_next_key_product (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 4) :
    (authModeFlag witness.authorization.mode 1 : F) *
      (((witness.outputs.getD 0 default).note.authorizationKey.getD limb.val 0 : F) -
        (authHashWord (typedSourceFinals statement witness) 103 limb.val : F)) = 0 := by
  by_cases approval : witness.authorization.mode = .approvalStep
  · rw [approval_output_next_binding statement witness valid approval,
      typed_next_hash_word statement witness valid approval ⟨limb.val,by omega⟩]
    simp only [List.getD_eq_getElem?_getD,List.getElem?_take,if_pos limb.isLt,
      sub_self,mul_zero]
  · have gate : authModeFlag witness.authorization.mode 1 = 0 := by
      cases mode : witness.authorization.mode <;> simp_all [authModeFlag,authBit]
    rw [gate,Nat.cast_zero,zero_mul]

theorem canonical_bitmap_count (opening : V8AccumulatorOpening)
    (canonical : CanonicalAccumulator opening) :
    (opening.approvalCount : F) =
      (wordAt opening.approvedSlots 5 : F) + ((wordAt opening.approvedSlots 4 : F) +
      ((wordAt opening.approvedSlots 3 : F) + ((wordAt opening.approvedSlots 2 : F) +
      ((wordAt opening.approvedSlots 0 : F) + (wordAt opening.approvedSlots 1 : F))))) := by
  obtain ⟨_,_,_,_,_,_,_,_,length,_,count,_⟩ := canonical
  have words : opening.approvedSlots = [wordAt opening.approvedSlots 0,
      wordAt opening.approvedSlots 1,wordAt opening.approvedSlots 2,
      wordAt opening.approvedSlots 3,wordAt opening.approvedSlots 4,
      wordAt opening.approvedSlots 5] := by
    simpa [wordAt,List.range_succ] using
      (range_getD opening.approvedSlots 6 length).symm
  have countSum := congrArg (fun n : Nat => (n : F))
    (count.trans (congrArg List.sum words))
  simp only [List.sum_cons,List.sum_nil,Nat.cast_add,add_zero] at countSum
  rw [countSum]
  ring

theorem current_bitmap_count_product (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ((authModeFlag witness.authorization.mode 1 : F) +
      (authModeFlag witness.authorization.mode 2 : F)) *
      ((witness.authorization.current.approvalCount : F) -
        ((wordAt witness.authorization.current.approvedSlots 5 : F) +
          ((wordAt witness.authorization.current.approvedSlots 4 : F) +
          ((wordAt witness.authorization.current.approvedSlots 3 : F) +
          ((wordAt witness.authorization.current.approvedSlots 2 : F) +
          ((wordAt witness.authorization.current.approvedSlots 0 : F) +
            (wordAt witness.authorization.current.approvedSlots 1 : F))))))) = 0 := by
  by_cases single : witness.authorization.mode = .singleKey
  · simp [single,authModeFlag,authBit]
  · rw [canonical_bitmap_count _ (non_single_current_canonical statement witness valid single),
      sub_self,mul_zero]

theorem next_bitmap_count_product (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (authModeFlag witness.authorization.mode 1 : F) *
      ((witness.authorization.next.approvalCount : F) -
        ((wordAt witness.authorization.next.approvedSlots 5 : F) +
          ((wordAt witness.authorization.next.approvedSlots 4 : F) +
          ((wordAt witness.authorization.next.approvedSlots 3 : F) +
          ((wordAt witness.authorization.next.approvedSlots 2 : F) +
          ((wordAt witness.authorization.next.approvedSlots 0 : F) +
            (wordAt witness.authorization.next.approvedSlots 1 : F))))))) = 0 := by
  by_cases approval : witness.authorization.mode = .approvalStep
  · rw [canonical_bitmap_count _ (approval_next_canonical statement witness valid approval),
      sub_self,mul_zero]
  · have gate : authModeFlag witness.authorization.mode 1 = 0 := by
      cases mode : witness.authorization.mode <;> simp_all [authModeFlag,authBit]
    rw [gate,Nat.cast_zero,zero_mul]

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthFinalCore

import HegemonCrypto.SmallWoodV8Smz9SourceAuthMembershipCore
import HegemonCrypto.SmallWoodV8Smz9SourceInactiveMerkleRightReadback
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputSelection

/-! Typed input-note keys agree with the actual authorization source rows.
The finite selection proof is abstract in the hash accessor; its endpoint
instantiates all three digest facts from the actual typed source schedule. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceNoteInputKeyBridge
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMembershipCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInputSelection
open HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem source_global_spend_key (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    globalSpendKey statement witness = selectedTransactionSpendKey statement witness := by
  unfold globalSpendKey selectedTransactionSpendKey inputAt flagAt
  split_ifs
  · exact fixed_words_exact 4 _ (valid_input_spend_words_exact statement witness valid 0 (by decide)).1
  · exact fixed_words_exact 4 _ (valid_input_spend_words_exact statement witness valid 1 (by decide)).1
  · rfl

theorem typed_legacy_hash_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    authHashWord (typedSourceFinals statement witness) 0 limb.val =
      (exactV8TransactionPrf (selectedTransactionSpendKey statement witness)).getD limb.val 0 := by
  rw [auth_hash_word_readback _ ⟨0,by decide⟩ limb]
  change callFinalWord (typedLiveInitialStates statement witness) 0 limb.val = _
  rw [typed_call_final_word_is_scheduled statement witness ⟨0,by decide⟩]
  apply first_seven_readback
  rw [source_transaction_prf_digest,source_global_spend_key statement witness valid]

theorem typed_current_hash_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    authHashWord (typedSourceFinals statement witness) 100 limb.val =
      (exactV8AccumulatorDigest witness.authorization.current).getD limb.val 0 := by
  rw [auth_hash_word_readback _ ⟨100,by decide⟩ limb]
  change callFinalWord (typedLiveInitialStates statement witness) 100 limb.val = _
  rw [typed_call_final_word_is_scheduled statement witness ⟨100,by decide⟩]
  exact first_seven_readback _ _ (typed_current_digest_exact statement witness valid) limb

theorem typed_value_lock_hash_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    authHashWord (typedSourceFinals statement witness) 105 limb.val =
      (exactV8ValueLockDigest witness.authorization.current).getD limb.val 0 := by
  rw [auth_hash_word_readback _ ⟨105,by decide⟩ limb]
  change callFinalWord (typedLiveInitialStates statement witness) 105 limb.val = _
  rw [typed_call_final_word_is_scheduled statement witness ⟨105,by decide⟩]
  exact first_seven_readback _ _ (typed_value_lock_digest_exact statement witness valid) limb

theorem first_four_word (words : List Nat) (limb : Fin 4) :
    (words.take 4).getD limb.val 0 = words.getD limb.val 0 := by
  simp only [List.getD_eq_getElem?_getD,List.getElem?_take,if_pos limb.isLt]

theorem legacy_key_word (words : List Nat) (limb : Fin 4) :
    ((words.drop 1).take 4).getD limb.val 0 = words.getD (1 + limb.val) 0 := by
  rw [first_four_word]
  simp only [List.getD_eq_getElem?_getD,List.getElem?_drop]

theorem auth_input_key_from_digest_bindings (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (legacy : ∀ limb : Fin 7, authHashWord hashes 0 limb.val =
      (exactV8TransactionPrf (selectedTransactionSpendKey statement witness)).getD limb.val 0)
    (current : ∀ limb : Fin 7, authHashWord hashes 100 limb.val =
      (exactV8AccumulatorDigest witness.authorization.current).getD limb.val 0)
    (valueLock : ∀ limb : Fin 7, authHashWord hashes 105 limb.val =
      (exactV8ValueLockDigest witness.authorization.current).getD limb.val 0)
    (input : Fin 2) (limb : Fin 4) :
    authInputKey statement witness.authorization hashes input.val limb.val =
      (witness.inputs.getD input.val default).note.authorizationKey.getD limb.val 0 := by
  by_cases inactive : flagAt statement.inputFlags input.val = 0
  · rw [authInputKey,if_pos inactive]
    have zero := (typed_inactive_input_zero statement witness valid input inactive).2.2.2.1
    exact (zero_words_getD _ zero.2.2.2.2.2.1 limb.val).symm
  have active : flagAt statement.inputFlags input.val = 1 :=
    (typed_input_flag_boolean statement witness valid input).resolve_left inactive
  have auth := valid.2.2.1.2.2
  cases mode : witness.authorization.mode with
  | singleKey =>
      simp only [V8AuthorizationValid,mode] at auth
      rw [authInputKey,if_neg inactive,mode,auth.2.2.2 input.val input.isLt active,legacy_key_word]
      exact legacy ⟨1 + limb.val,by omega⟩
  | approvalStep =>
      simp only [V8AuthorizationValid,mode] at auth
      obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,key0,key1,_⟩ := auth
      rw [authInputKey,if_neg inactive,mode]
      fin_cases input
      · rw [key0,first_four_word]
        exact current ⟨limb.val,by omega⟩
      · rw [key1,legacy_key_word]
        exact legacy ⟨1 + limb.val,by omega⟩
  | finalThresholdSpend =>
      simp only [V8AuthorizationValid,mode] at auth
      obtain ⟨_,_,_,_,_,_,_,key0,key1⟩ := auth
      rw [authInputKey,if_neg inactive,mode]
      fin_cases input
      · rw [key0,first_four_word]
        exact valueLock ⟨limb.val,by omega⟩
      · rw [key1,first_four_word]
        exact current ⟨limb.val,by omega⟩

theorem auth_input_key_note_readback (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Fin 4) :
    authInputKey statement witness.authorization (typedSourceFinals statement witness) input.val limb.val =
      (witness.inputs.getD input.val default).note.authorizationKey.getD limb.val 0 :=
  auth_input_key_from_digest_bindings statement witness valid _
    (typed_legacy_hash_word statement witness valid)
    (typed_current_hash_word statement witness valid)
    (typed_value_lock_hash_word statement witness valid) input limb

end
end HegemonCrypto.SmallWood.V8Smz9SourceNoteInputKeyBridge

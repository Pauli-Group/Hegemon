import HegemonCrypto.SmallWoodV8Smz9SourceNullifierWords
import HegemonCrypto.SmallWoodV8Smz9SourceNoteDigestForward
import HegemonCrypto.SmallWoodV8Smz9SourceNoteInputKeyBridge
import HegemonCrypto.SmallWoodV8Smz9SourceInputKeyCsr12

namespace HegemonCrypto.SmallWood.V8Smz9SourceNullifierDigestForward
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierFrames
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierWords
open HegemonCrypto.SmallWood.V8Smz9SourceNoteDigestForward
open HegemonCrypto.SmallWood.V8Smz9SourceNoteInputKeyBridge
open HegemonCrypto.SmallWood.V8Smz9SourceInputKeyCsr12
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9NullifierSource
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem typed_active_selected_spend_key (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2)
    (active : flagAt statement.inputFlags input.val = 1) :
    selectedTransactionSpendKey statement witness = (witness.inputs.getD input.val default).spendKey := by
  fin_cases input
  · exact selected_transaction_spend_key_first_active statement witness active
  · by_cases first : flagAt statement.inputFlags 0 = 1
    · rw [selected_transaction_spend_key_first_active statement witness first]
      exact typed_active_spend_keys_equal statement witness valid first active
    · rw [selectedTransactionSpendKey,if_neg first,if_pos active]

theorem auth_prf_semantic_from_bindings (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (input : Fin 2) (active : flagAt statement.inputFlags input.val = 1)
    (legacy : authHashWord hashes 0 0 =
      (exactV8TransactionPrf (witness.inputs.getD input.val default).spendKey).getD 0 0)
    (current : authHashWord hashes 100 4 = (exactV8AccumulatorDigest witness.authorization.current).getD 4 0)
    (valueLock : authHashWord hashes 105 4 = (exactV8ValueLockDigest witness.authorization.current).getD 4 0) :
    authInputPrf statement witness.authorization hashes input.val =
      effectiveInputAuthorizationPrf exactV8SemanticPrimitives witness input.val := by
  rw [authInputPrf,if_neg (by omega)]
  cases mode : witness.authorization.mode <;>
    simp only [effectiveInputAuthorizationPrf,mode,exactV8SemanticPrimitives,wordAt,legacy,current,valueLock]

theorem typed_active_auth_prf_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2)
    (active : flagAt statement.inputFlags input.val = 1) :
    authInputPrf statement witness.authorization (typedSourceFinals statement witness) input.val =
      effectiveInputAuthorizationPrf exactV8SemanticPrimitives witness input.val := by
  apply auth_prf_semantic_from_bindings statement witness _ input active
  · rw [typed_legacy_hash_word statement witness valid ⟨0,by decide⟩,
      typed_active_selected_spend_key statement witness valid input active]
  · exact typed_current_hash_word statement witness valid ⟨4,by decide⟩
  · exact typed_value_lock_hash_word statement witness valid ⟨4,by decide⟩

theorem typed_input_rho_length (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    (inputAt witness input.val).note.rho.length = 4 := by
  rcases typed_input_note_shape statement witness valid input with canonical | zero
  · exact canonical.2.2.2.2.2.1.1
  · exact zero.2.2.2.2.2.2.1.1

theorem active_nullifier_source_words_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2)
    (active : flagAt statement.inputFlags input.val = 1) :
    actualNullifierSourceWords statement witness input.val =
      [effectiveInputAuthorizationPrf exactV8SemanticPrimitives witness input.val,
       (inputAt witness input.val).position] ++ (inputAt witness input.val).note.rho := by
  have scalar := actual_nullifier_scalar_binding statement witness valid input
  change effectiveInputPrf statement witness (wordAtState (scheduledFinal statement witness 0) 0) input.val = _ at scalar
  have flag : statement.inputFlags.getD input.val 0 = 1 := active
  rw [actualNullifierSourceWords,sourceNullifierWords,if_pos flag,scalar,
    typed_active_auth_prf_exact statement witness valid input active,
    fixed_words_exact 4 _ (typed_input_rho_length statement witness valid input)]
  rw [if_pos flag]

theorem nullifier_segment_plan (statement : V8PublicStatement) (witness : V8Witness)
    (input : Fin 2) (block : Fin 1) :
    sourceCallPlan statement witness (nullifierCall input.val + block.val) (scheduledFinal statement witness) =
      .sponge (.inputNullifier input.val) 2 (actualNullifierSourceWords statement witness input.val) 1 block.val
        (previousSponge (nullifierCall input.val + block.val) block.val) := by
  fin_cases input <;> fin_cases block <;> rfl

theorem source_nullifier_scheduled_digest (statement : V8PublicStatement) (witness : V8Witness) (input : Fin 2) :
    (stateWords (scheduledFinal statement witness (nullifierCall input.val))).take 7 =
      poseidon2V8Sponge 2 (actualNullifierSourceWords statement witness input.val) := by
  have fit : nullifierCall input.val + 1 ≤ 125 := by fin_cases input <;> decide
  exact source_sponge_segment_digest statement witness (nullifierCall input.val) 1 2
    (actualNullifierSourceWords statement witness input.val) (fun _ => .inputNullifier input.val)
    fit (by decide) (fun block bound => nullifier_segment_plan statement witness input ⟨block,bound⟩)
    (by decide) (by rw [actualNullifierSourceWords,nullifier_words_length]; decide)
    (by rw [actualNullifierSourceWords,nullifier_words_length]; rfl)

theorem typed_active_nullifier_scheduled_digest_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2)
    (active : flagAt statement.inputFlags input.val = 1) :
    (stateWords (scheduledFinal statement witness (nullifierCall input.val))).take 7 =
      exactV8Nullifier input.val (effectiveInputAuthorizationPrf exactV8SemanticPrimitives witness input.val)
        (inputAt witness input.val).position (inputAt witness input.val).note.rho := by
  rw [source_nullifier_scheduled_digest,active_nullifier_source_words_exact statement witness valid input active]
  rfl

end
end HegemonCrypto.SmallWood.V8Smz9SourceNullifierDigestForward

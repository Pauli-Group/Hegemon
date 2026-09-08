import HegemonCrypto.SmallWoodV8Smz9SourceNullifierFrames
import HegemonCrypto.SmallWoodV8Smz9SourceNoteFrames
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitialWords
import HegemonCrypto.SmallWoodV8Smz9SourceInactiveMerkleRightReadback
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputSelection

namespace HegemonCrypto.SmallWood.V8Smz9SourceNullifierWords
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (rawIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceNullifierFrames
open HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInputSelection
open HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem typed_auth_hash_scheduled_word (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (limb : Fin 7) :
    authHashWord (typedSourceFinals statement witness) call.val limb.val =
      (stateWords (scheduledFinal statement witness call.val)).getD limb.val 0 := by
  rw [auth_hash_word_readback _ call limb]
  exact typed_call_final_word_is_scheduled statement witness call limb.val

theorem typed_auth_source_current_word (statement : V8PublicStatement) (witness : V8Witness) :
    authHashWord (typedSourceFinals statement witness) 100 4 =
      (sourceSpongeDigest 6 (sourceAccumulatorWords witness.authorization.current)).getD 4 0 := by
  rw [typed_auth_hash_scheduled_word statement witness ⟨100,by decide⟩ ⟨4,by decide⟩]
  exact first_seven_readback _ _ (source_current_segment_digest statement witness) ⟨4,by decide⟩

theorem typed_auth_source_value_lock_word (statement : V8PublicStatement) (witness : V8Witness) :
    authHashWord (typedSourceFinals statement witness) 105 4 =
      (sourceSpongeDigest 8 (sourceValueLockWords witness.authorization.current)).getD 4 0 := by
  rw [typed_auth_hash_scheduled_word statement witness ⟨105,by decide⟩ ⟨4,by decide⟩]
  exact first_seven_readback _ _ (source_value_lock_segment_digest statement witness) ⟨4,by decide⟩

theorem effective_prf_from_source_bindings (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (legacy : Nat)
    (legacyBinding : authHashWord hashes 0 0 = legacy)
    (currentBinding : authHashWord hashes 100 4 =
      (sourceSpongeDigest 6 (sourceAccumulatorWords witness.authorization.current)).getD 4 0)
    (valueBinding : authHashWord hashes 105 4 =
      (sourceSpongeDigest 8 (sourceValueLockWords witness.authorization.current)).getD 4 0)
    (input : Nat) (boolean : flagAt statement.inputFlags input = 0 ∨ flagAt statement.inputFlags input = 1) :
    effectiveInputPrf statement witness legacy input = authInputPrf statement witness.authorization hashes input := by
  rcases boolean with inactive | active
  · have zero : statement.inputFlags.getD input 0 = 0 := inactive
    have notActive : statement.inputFlags.getD input 0 ≠ 1 := by omega
    rw [effectiveInputPrf,if_pos notActive,authInputPrf,if_pos inactive]
  · have one : statement.inputFlags.getD input 0 = 1 := active
    simp only [effectiveInputPrf,authInputPrf,flagAt,one,ne_eq,not_true_eq_false,
      ite_false,Nat.one_ne_zero]
    cases witness.authorization.mode <;> simp only [legacyBinding,currentBinding,valueBinding]

theorem actual_nullifier_scalar_binding (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    (actualNullifierSourceWords statement witness input.val).getD 0 0 =
      authInputPrf statement witness.authorization (typedSourceFinals statement witness) input.val := by
  change effectiveInputPrf statement witness (wordAtState (scheduledFinal statement witness 0) 0) input.val = _
  apply effective_prf_from_source_bindings statement witness _ _
  · exact typed_auth_hash_scheduled_word statement witness ⟨0,by decide⟩ ⟨0,by decide⟩
  · exact typed_auth_source_current_word statement witness
  · exact typed_auth_source_value_lock_word statement witness
  · exact typed_input_flag_boolean statement witness valid input

theorem auth_source_scalar_row (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (input : Fin 2) :
    sourceAuthRow statement witness hashes (95 + input.val - 92) =
      authInputPrf statement witness.authorization hashes input.val := by
  fin_cases input <;> rfl

theorem full_candidate_nullifier_scalar_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    ((fullTypedSourceCandidate statement witness).getD (rawIndex (95 + input.val)) 0 : F) =
      ((actualNullifierSourceWords statement witness input.val).getD 0 0 : F) := by
  rw [full_candidate_all_raw_word statement witness ⟨_,by omega⟩,constructedRawWord,
    if_neg (show ¬95 + input.val < 92 by omega),auth_source_scalar_row,
    actual_nullifier_scalar_binding statement witness valid input]
  rfl

theorem actual_nullifier_position_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    (actualNullifierSourceWords statement witness input.val).getD 1 0 =
      (witness.inputs.getD input.val default).position := by
  change (if flagAt statement.inputFlags input.val = 1 then
    (witness.inputs.getD input.val default).position else 0) = _
  rcases typed_input_flag_boolean statement witness valid input
    with inactive | active
  · rw [if_neg (by omega)]
    exact (typed_inactive_input_zero statement witness valid input inactive).2.2.2.2.1.symm
  · rw [if_pos active]

theorem source_note_rho_word (note : V8NoteOpening) (limb : Fin 4) :
    (sourceNoteWords note).getD (6 + limb.val) 0 = note.rho.getD limb.val 0 := by
  fin_cases limb <;> rfl

theorem actual_nullifier_rho_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Fin 4) :
    (actualNullifierSourceWords statement witness input.val).getD (2 + limb.val) 0 =
      (sourceNoteWords (sourceNoteOpening witness input.val)).getD (6 + limb.val) 0 := by
  rw [source_note_rho_word,sourceNoteOpening,if_pos input.isLt]
  rcases typed_input_flag_boolean statement witness valid input
    with inactive | active
  · have zero := (typed_inactive_input_zero statement witness valid input inactive).2.2.2.1
    have rhoZero := zero_words_getD _ zero.2.2.2.2.2.2.2.1 limb.val
    rw [rhoZero]
    have notActive : ¬statement.inputFlags.getD input.val 0 = 1 := by change ¬flagAt statement.inputFlags input.val = 1; omega
    fin_cases limb <;> simp only [actualNullifierSourceWords,sourceNullifierWords,if_neg notActive] <;> rfl
  · have isActive : statement.inputFlags.getD input.val 0 = 1 := active
    fin_cases limb <;> simp only [actualNullifierSourceWords,sourceNullifierWords,if_pos isActive] <;> rfl

end
end HegemonCrypto.SmallWood.V8Smz9SourceNullifierWords

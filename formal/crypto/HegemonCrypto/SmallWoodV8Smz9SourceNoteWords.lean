import HegemonCrypto.SmallWoodV8Smz9SourceNoteFrames
import HegemonCrypto.SmallWoodV8Smz9SourceNoteInputKeyBridge
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitialWords
import HegemonCrypto.SmallWoodV8Smz9InputAuthorizationKeys

namespace HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (rawIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open HegemonCrypto.SmallWood.V8Smz9SourceNoteInputKeyBridge
open HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9InputAuthorizationKeys
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def noteValueAssetRow (note word : Nat) : Nat := [0,34,68,80].getD note 0 + word

theorem note_value_asset_row_bound (note : Fin 4) (word : Fin 2) :
    noteValueAssetRow note.val word.val < 92 := by fin_cases note <;> fin_cases word <;> decide

theorem note_value_asset_address (note : Fin 4) (word : Fin 2) :
    densePrivateAddress note.val + 64 * word.val = rawIndex (noteValueAssetRow note.val word.val) := by
  fin_cases note <;> fin_cases word <;> rfl

theorem source_note_value_asset_word (statement : V8PublicStatement) (witness : V8Witness)
    (note : Fin 4) (word : Fin 2) :
    sourceWord statement witness (noteValueAssetRow note.val word.val) =
      (sourceNoteWords (sourceNoteOpening witness note.val)).getD word.val 0 := by
  fin_cases note <;> fin_cases word <;>
    simp [noteValueAssetRow,sourceWord,inputWord,outputWord,sourceNoteOpening,sourceNoteWords]

theorem full_candidate_note_value_asset_word (statement : V8PublicStatement) (witness : V8Witness)
    (note : Fin 4) (word : Fin 2) :
    ((fullTypedSourceCandidate statement witness).getD (densePrivateAddress note.val + 64 * word.val) 0 : F) =
      ((sourceNoteWords (sourceNoteOpening witness note.val)).getD word.val 0 : F) := by
  have bound := note_value_asset_row_bound note word
  rw [note_value_asset_address,full_candidate_all_raw_word statement witness ⟨_,by omega⟩,
    constructedRawWord,if_pos bound,source_note_value_asset_word]

theorem source_note_authorization_word (note : V8NoteOpening) (limb : Fin 4) :
    (sourceNoteWords note).getD (14 + limb.val) 0 = note.authorizationKey.getD limb.val 0 := by
  fin_cases limb <;> rfl

theorem auth_source_input_key_word (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (input : Fin 2) (limb : Fin 4) :
    sourceAuthRow statement witness hashes (97 + 4 * input.val + limb.val - 92) =
      authInputKey statement witness.authorization hashes input.val limb.val := by
  fin_cases input <;> fin_cases limb <;> rfl

theorem full_candidate_input_note_key_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Fin 4) :
    ((fullTypedSourceCandidate statement witness).getD (rawIndex (97 + 4 * input.val + limb.val)) 0 : F) =
      ((witness.inputs.getD input.val default).note.authorizationKey.getD limb.val 0 : F) := by
  rw [full_candidate_all_raw_word statement witness ⟨_,by omega⟩,constructedRawWord,
    if_neg (show ¬ 97 + 4 * input.val + limb.val < 92 by omega),auth_source_input_key_word]
  exact congrArg (fun n : Nat => (n : F)) (auth_input_key_note_readback statement witness valid input limb)

theorem full_candidate_output_note_key_word (statement : V8PublicStatement) (witness : V8Witness)
    (output : Fin 2) (limb : Fin 4) :
    ((fullTypedSourceCandidate statement witness).getD (rawIndex (76 + 12 * output.val + limb.val)) 0 : F) =
      ((witness.outputs.getD output.val default).note.authorizationKey.getD limb.val 0 : F) := by
  rw [full_candidate_all_raw_word statement witness ⟨_,by omega⟩,constructedRawWord,
    if_pos (show 76 + 12 * output.val + limb.val < 92 by omega)]
  dsimp only [Fin.val]
  have row : 76 + 12 * output.val + limb.val = 68 + 12 * output.val + (8 + limb.val) := by omega
  rw [row,source_output_word statement witness output.val (8 + limb.val) output.isLt (by omega)]
  simp only [outputWord,if_neg (by omega : ¬8 + limb.val = 0),if_neg (by omega : ¬8 + limb.val = 1),
    if_neg (by omega : ¬8 + limb.val < 8),Nat.add_sub_cancel_left]

theorem full_candidate_note_authorization_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) (limb : Fin 4) :
    ((fullTypedSourceCandidate statement witness).getD (rawIndex (noteAuthRow note.val + limb.val)) 0 : F) =
      ((sourceNoteWords (sourceNoteOpening witness note.val)).getD (14 + limb.val) 0 : F) := by
  rw [source_note_authorization_word]
  fin_cases note
  · exact full_candidate_input_note_key_word statement witness valid ⟨0,by decide⟩ limb
  · exact full_candidate_input_note_key_word statement witness valid ⟨1,by decide⟩ limb
  · exact full_candidate_output_note_key_word statement witness ⟨0,by decide⟩ limb
  · exact full_candidate_output_note_key_word statement witness ⟨1,by decide⟩ limb

end
end HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames

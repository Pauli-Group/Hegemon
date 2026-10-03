import HegemonCrypto.SmallWoodV8Smz9SourceNoteWords
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitial128
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (rawIndex hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9InputAuthorizationKeys
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem full_candidate_note_value_asset_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (note : Fin 4) (word : Fin 2) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness)
      (noteBridgeExpectedAttempt note.val word.val) = 0 := by
  simp only [noteBridgeExpectedAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,actual_auth_initial_negative pub,
    one_mul,neg_one_mul,add_zero,sub_zero]
  have initial := full_candidate_note_initial_field statement witness valid note ⟨0,by decide⟩ ⟨word.val,by omega⟩
  have small : word.val < 8 := by omega
  have below : word.val < 18 := by omega
  norm_num [small,below] at initial
  simp only [← List.getD_eq_getElem?_getD] at initial
  rw [initial,full_candidate_note_value_asset_word]
  ring

theorem note_auth_exact_lookup (note : Fin 4) (limb : Fin 4) :
    exactCsrAttempts[noteBridgeAttemptIndex note.val + noteAuthLocal limb.val]? =
      some (noteAuthAttempt note.val limb.val) :=
  exact_attempt_lookup _ (exact_note_auth_attempt note limb)

theorem full_candidate_note_auth_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (note : Fin 4) (limb : Fin 4) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (noteAuthAttempt note.val limb.val) = 0 := by
  simp only [noteAuthAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_csr_zero_one pub).1,(actual_csr_zero_one pub).2,actual_auth_initial_negative pub,
    one_mul,neg_one_mul,add_zero,sub_zero]
  rw [full_candidate_note_initial_field statement witness valid note
      ⟨(14 + limb.val) / 8,by omega⟩ ⟨(14 + limb.val) % 8,by omega⟩]
  have first : (14 + limb.val) / 8 ≠ 0 := by omega
  have rate : (14 + limb.val) % 8 < 8 ∧ (14 + limb.val) / 8 * 8 + (14 + limb.val) % 8 < 18 := by omega
  have index : (14 + limb.val) / 8 * 8 + (14 + limb.val) % 8 = 14 + limb.val := by omega
  rw [if_neg first,if_pos rate,index,full_candidate_note_authorization_word statement witness valid note limb]
  ring

end
end HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames

import HegemonCrypto.SmallWoodV8Smz9SourceNoteFrameRoots
import HegemonCrypto.SmallWoodV8Smz9SourceNoteInactive72
import HegemonCrypto.SmallWoodV8Smz9SourceNoteBindings24

namespace HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9InputAuthorizationKeys
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def noteInitialFrameBlock (offset : Nat) : Nat := if offset < 10 then 0 else if offset < 20 then 1 else 2
def noteInitialFrameLane (offset : Nat) : Nat := if offset < 10 then 6 + offset else if offset < 20 then offset - 4 else offset - 20

theorem note_initial_frame_offset (offset : Fin 36) (notValue : ¬ offset.val < 2)
    (notKey : ¬ (offset.val = 10 ∨ offset.val = 11 ∨ offset.val = 20 ∨ offset.val = 21)) :
    NoteFrameCoordinate (noteInitialFrameBlock offset.val) (noteInitialFrameLane offset.val) ∧
      noteFrameLocal (noteInitialFrameBlock offset.val) (noteInitialFrameLane offset.val) = offset.val := by
  fin_cases offset <;> first
    | exact (notValue (by decide)).elim
    | exact (notKey (by decide)).elim
    | decide

theorem note_initial_key_offset (offset : Nat)
    (key : offset = 10 ∨ offset = 11 ∨ offset = 20 ∨ offset = 21) :
    ∃ limb : Fin 4, noteAuthLocal limb.val = offset := by
  rcases key with rfl | rfl | rfl | rfl
  · exact ⟨⟨0,by decide⟩,rfl⟩
  · exact ⟨⟨1,by decide⟩,rfl⟩
  · exact ⟨⟨2,by decide⟩,rfl⟩
  · exact ⟨⟨3,by decide⟩,rfl⟩

theorem full_candidate_note_initial36_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (note : Fin 4) (offset : Fin 36) :
    (exactCsrAttempts[noteBridgeAttemptIndex note.val + offset.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases value : offset.val < 2
  · rw [exact_note_bridge_attempts note.val note.isLt offset.val value,Option.map_some,
      full_candidate_note_value_asset_residual_zero statement witness valid pub note ⟨offset.val,value⟩]
  by_cases key : offset.val = 10 ∨ offset.val = 11 ∨ offset.val = 20 ∨ offset.val = 21
  · obtain ⟨limb,index⟩ := note_initial_key_offset offset.val key
    rw [← index,note_auth_exact_lookup note limb,Option.map_some,
      full_candidate_note_auth_residual_zero statement witness valid pub note limb]
  · have frame := note_initial_frame_offset offset value key
    rw [← frame.2,note_frame_exact_lookup note ⟨_,frame.1.1⟩ ⟨_,frame.1.2.1⟩ frame.1,
      Option.map_some,full_candidate_note_frame_residual_zero statement witness valid pub _ _ _ frame.1]

def note216Index (index : Nat) : Nat :=
  if index < 144 then noteBridgeAttemptIndex (index / 36) + index % 36 else inactiveNote72Index (index - 144)

theorem note216_distinct_count :
    ((List.range 216).map note216Index).length = 216 ∧
      ((List.range 216).map note216Index).Nodup := by decide

theorem full_candidate_actual_note216_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 216) :
    (exactCsrAttempts[note216Index index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases initial : index.val < 144
  · rw [note216Index,if_pos initial]
    exact full_candidate_note_initial36_zero statement witness valid _ ⟨index.val / 36,by omega⟩ ⟨index.val % 36,by omega⟩
  · rw [note216Index,if_neg initial]
    exact full_candidate_actual_inactive_note72_zero statement witness valid ⟨index.val - 144,by omega⟩

end
end HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames

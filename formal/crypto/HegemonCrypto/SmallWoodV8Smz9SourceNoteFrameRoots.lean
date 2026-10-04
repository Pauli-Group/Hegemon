import HegemonCrypto.SmallWoodV8Smz9SourceNoteFrames
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitial128
import HegemonCrypto.SmallWoodV8Smz9SourceBase7

namespace HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open Hegemon.Transaction
open Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open HegemonCrypto.SmallWood.V8Smz9SourceBase7
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_note_frame_constant_node (block lane : Nat) :
    exactCsrExpressions[noteFrameTarget block lane]? = some (.constant (noteFrameConstant block lane)) := by
  unfold noteFrameTarget noteFrameConstant
  split_ifs <;> decide

theorem actual_note_frame_coefficient (pub : Nat → F) (block lane : Nat) :
    actualCsrCoefficients pub (noteFrameTarget block lane) = (noteFrameConstant block lane : F) :=
  actual_csr_node_field_equation pub (actual_note_frame_constant_node block lane)

theorem actual_note_frame_residual (pub : Nat → F) (packed : List Nat) (note block lane : Nat) :
    actualCsrResidual pub packed (noteFrameAttempt note block lane) =
      (packed.getD (hashInitialIndex (noteBridgeCall note + block) lane) 0 : F) -
      (if block = 0 then 0 else (packed.getD (hashFinalIndex (noteBridgeCall note + block - 1) lane) 0 : F)) -
      (noteFrameConstant block lane : F) := by
  by_cases first : block = 0 <;>
    simp [noteFrameAttempt,actualCsrResidual,actualCsrTerms,attempt,
      first,(actual_csr_zero_one pub).2,actual_auth_initial_negative pub,
      actual_note_frame_coefficient,sub_eq_add_neg,add_assoc]

theorem full_candidate_note_frame_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F)
    (note : Fin 4) (block : Fin 3) (lane : Fin 16)
    (coordinate : NoteFrameCoordinate block.val lane.val) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness)
      (noteFrameAttempt note.val block.val lane.val) = 0 := by
  have padding : ¬ (lane.val < 8 ∧ block.val * 8 + lane.val < 18) := by
    unfold NoteFrameCoordinate at coordinate
    omega
  rw [actual_note_frame_residual,full_candidate_note_initial_field statement witness valid note block lane,
    if_neg padding]
  ring

theorem note_frame_exact_lookup (note : Fin 4) (block : Fin 3) (lane : Fin 16)
    (coordinate : NoteFrameCoordinate block.val lane.val) :
    exactCsrAttempts[noteBridgeAttemptIndex note.val + noteFrameLocal block.val lane.val]? =
      some (noteFrameAttempt note.val block.val lane.val) :=
  exact_attempt_lookup _ (exact_note_frame_sources note block lane coordinate)

def noteFrameBlock (offset : Nat) : Nat := if offset < 8 then 0 else if offset < 16 then 1 else 2
def noteFrameLane (offset : Nat) : Nat := if offset < 8 then 8 + offset else if offset < 16 then offset else offset - 14
def noteFrameIndex (index : Nat) : Nat :=
  noteBridgeAttemptIndex (index / 30) + noteFrameLocal (noteFrameBlock (index % 30)) (noteFrameLane (index % 30))

theorem note_frame120_distinct_count :
    ((List.range 120).map noteFrameIndex).length = 120 ∧
      ((List.range 120).map noteFrameIndex).Nodup := by decide

theorem note_frame_offset_valid (offset : Fin 30) :
    NoteFrameCoordinate (noteFrameBlock offset.val) (noteFrameLane offset.val) := by
  unfold NoteFrameCoordinate noteFrameBlock noteFrameLane
  split_ifs <;> omega

theorem full_candidate_actual_note_frame120_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (index : Fin 120) :
    (exactCsrAttempts[noteFrameIndex index.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  have coordinate := note_frame_offset_valid ⟨index.val % 30,by omega⟩
  rw [noteFrameIndex,note_frame_exact_lookup ⟨index.val / 30,by omega⟩
    ⟨_,coordinate.1⟩ ⟨_,coordinate.2.1⟩ coordinate,Option.map_some,
    full_candidate_note_frame_residual_zero statement witness valid pub _ _ _ coordinate]

end
end HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames

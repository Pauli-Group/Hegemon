import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitialFrames
import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNotes

/-! Exact 18-word source note preimages and the three-block initial frames. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def sourceNoteOpening (witness : V8Witness) (note : Nat) : V8NoteOpening :=
  if note < 2 then (witness.inputs.getD note default).note
  else (witness.outputs.getD (note - 2) default).note

theorem source_note_call_bound (note : Fin 4) : noteBridgeCall note.val < 80 := by
  fin_cases note <;> decide

theorem actual_note_preparation (statement : V8PublicStatement) (witness : V8Witness)
    (note : Fin 4) (block : Fin 3) :
    actualSourceFrame statement witness
      ⟨noteBridgeCall note.val + block.val,by have := source_note_call_bound note; omega⟩ =
      spongePreparedWords 1 (sourceNoteWords (sourceNoteOpening witness note.val)) 3
        (stateWords (authInitialPrior statement witness (noteBridgeCall note.val) block.val)) block.val := by
  fin_cases note <;> fin_cases block <;> rfl

theorem note_preparation_field (inputs : List Nat) (shape : inputs.length = 18)
    (block : Fin 3) (previous : State) (firstZero : block.val = 0 → previous = zeroState)
    (lane : Fin 16) :
    ((spongePreparedWords 1 inputs 3 (stateWords previous) block.val).getD lane.val 0 : F) =
      ((stateWords previous).getD lane.val 0 : F) +
        (if lane.val < 8 ∧ block.val * 8 + lane.val < 18 then
          (inputs.getD (block.val * 8 + lane.val) 0 : F)
         else (noteFrameConstant block.val lane.val : F)) := by
  fin_cases block
  · have zero := firstZero rfl
    subst previous
    fin_cases lane <;> simp [spongePreparedWords,poseidon2V8SeedFirstBlock,stateWords,zeroState,word,
      shape,Poseidon2Width16Kernel.rate,Poseidon2Width16Kernel.width,List.range_succ,noteFrameConstant]
  all_goals fin_cases lane <;> simp [spongePreparedWords,stateWords,
    shape,Poseidon2Width16Kernel.rate,List.range_succ,noteFrameConstant]

theorem full_candidate_note_initial_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) (block : Fin 3) (lane : Fin 16) :
    ((fullTypedSourceCandidate statement witness).getD
      (Poseidon2V8DecoderRefinement.hashInitialIndex (noteBridgeCall note.val + block.val) lane.val) 0 : F) =
      (if block.val = 0 then 0 else ((fullTypedSourceCandidate statement witness).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex (noteBridgeCall note.val + block.val - 1) lane.val) 0 : F)) +
      (if lane.val < 8 ∧ block.val * 8 + lane.val < 18 then
        ((sourceNoteWords (sourceNoteOpening witness note.val)).getD (block.val * 8 + lane.val) 0 : F)
       else (noteFrameConstant block.val lane.val : F)) := by
  have bound := source_note_call_bound note
  rw [full_candidate_initial_source_readback statement witness valid
      ⟨noteBridgeCall note.val + block.val,by omega⟩ lane,
    actual_note_preparation,
    note_preparation_field _ (note_words_length _) block _
      (fun first => by simp only [authInitialPrior,if_pos first]) lane,
    full_candidate_auth_prior_field statement witness _ _ (by omega) lane]

end
end HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames

import HegemonCrypto.SmallWoodV8Smz9SourceSpongeSegment
import HegemonCrypto.SmallWoodV8Smz9TypedScheduleSources
import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition
import HegemonCrypto.SmallWoodV8Smz9SourceNoteFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourceNoteDigestForward

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder

set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem input_zero_note_plan (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 3) :
    sourceCallPlan statement witness (1 + block.val) (scheduledFinal statement witness) =
      .sponge (.inputNote 0 block.val) 1
        (sourceNoteWords (sourceNoteOpening witness 0)) 3 block.val
        (previousSponge (1 + block.val) block.val) := by
  fin_cases block <;> rfl

theorem input_one_note_plan (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 3) :
    sourceCallPlan statement witness (37 + block.val) (scheduledFinal statement witness) =
      .sponge (.inputNote 1 block.val) 1
        (sourceNoteWords (sourceNoteOpening witness 1)) 3 block.val
        (previousSponge (37 + block.val) block.val) := by
  fin_cases block <;> rfl

theorem output_zero_note_plan (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 3) :
    sourceCallPlan statement witness (73 + block.val) (scheduledFinal statement witness) =
      .sponge (.outputNote 0 block.val) 1
        (sourceNoteWords (sourceNoteOpening witness 2)) 3 block.val
        (previousSponge (73 + block.val) block.val) := by
  fin_cases block <;> rfl

theorem output_one_note_plan (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 3) :
    sourceCallPlan statement witness (76 + block.val) (scheduledFinal statement witness) =
      .sponge (.outputNote 1 block.val) 1
        (sourceNoteWords (sourceNoteOpening witness 3)) 3 block.val
        (previousSponge (76 + block.val) block.val) := by
  fin_cases block <;> rfl

theorem input_zero_note_scheduled_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 3)).take 7 =
      poseidon2V8Sponge 1 (sourceNoteWords (sourceNoteOpening witness 0)) := by
  exact source_sponge_segment_digest statement witness 1 3 1
    (sourceNoteWords (sourceNoteOpening witness 0)) (.inputNote 0)
    (by decide) (by decide)
    (fun block bound => input_zero_note_plan statement witness ⟨block, bound⟩)
    (by decide) (by rw [note_words_length]; decide) (by rw [note_words_length]; decide)

theorem input_one_note_scheduled_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 39)).take 7 =
      poseidon2V8Sponge 1 (sourceNoteWords (sourceNoteOpening witness 1)) := by
  exact source_sponge_segment_digest statement witness 37 3 1
    (sourceNoteWords (sourceNoteOpening witness 1)) (.inputNote 1)
    (by decide) (by decide)
    (fun block bound => input_one_note_plan statement witness ⟨block, bound⟩)
    (by decide) (by rw [note_words_length]; decide) (by rw [note_words_length]; decide)

theorem output_zero_note_scheduled_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 75)).take 7 =
      poseidon2V8Sponge 1 (sourceNoteWords (sourceNoteOpening witness 2)) := by
  exact source_sponge_segment_digest statement witness 73 3 1
    (sourceNoteWords (sourceNoteOpening witness 2)) (.outputNote 0)
    (by decide) (by decide)
    (fun block bound => output_zero_note_plan statement witness ⟨block, bound⟩)
    (by decide) (by rw [note_words_length]; decide) (by rw [note_words_length]; decide)

theorem output_one_note_scheduled_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 78)).take 7 =
      poseidon2V8Sponge 1 (sourceNoteWords (sourceNoteOpening witness 3)) := by
  exact source_sponge_segment_digest statement witness 76 3 1
    (sourceNoteWords (sourceNoteOpening witness 3)) (.outputNote 1)
    (by decide) (by decide)
    (fun block bound => output_one_note_plan statement witness ⟨block, bound⟩)
    (by decide) (by rw [note_words_length]; decide) (by rw [note_words_length]; decide)

theorem source_note_words_eq_exact_of_shape (note : V8NoteOpening)
    (shape : CanonicalNoteOpening note ∨ ZeroNoteOpening note) :
    sourceNoteWords note = exactV8NoteWords note := by
  rcases shape with canonical | zero
  · rcases canonical with ⟨_, _, _, recipient, authorization, rho, randomness⟩
    simp only [sourceNoteWords, exactV8NoteWords,
      fixed_words_exact _ _ recipient.1, fixed_words_exact _ _ rho.1,
      fixed_words_exact _ _ randomness.1, fixed_words_exact _ _ authorization.1]
  · rcases zero with ⟨_, _, recipient, _, authorization, _, rho, _, randomness, _⟩
    simp only [sourceNoteWords, exactV8NoteWords,
      fixed_words_exact _ _ recipient.1, fixed_words_exact _ _ rho.1,
      fixed_words_exact _ _ randomness.1, fixed_words_exact _ _ authorization.1]

theorem source_note_digest_eq_exact_of_shape (note : V8NoteOpening)
    (shape : CanonicalNoteOpening note ∨ ZeroNoteOpening note) :
    poseidon2V8Sponge 1 (sourceNoteWords note) = exactV8NoteCommitment note := by
  rw [source_note_words_eq_exact_of_shape note shape]
  rfl

theorem typed_input_note_shape (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    CanonicalNoteOpening (inputAt witness input.val).note ∨ ZeroNoteOpening (inputAt witness input.val).note := by
  have facts := valid.2.1.2.2.1 input.val input.isLt
  change _ ∧ (if (inputAt witness input.val).active = 0 then ZeroInputWitness (inputAt witness input.val) else _) at facts
  split at facts
  · exact Or.inr facts.2.2.2.2.1
  · exact Or.inl facts.2.1

theorem typed_output_note_shape (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (output : Fin 2) :
    CanonicalNoteOpening (outputAt witness output.val).note ∨ ZeroNoteOpening (outputAt witness output.val).note := by
  have facts := valid.2.1.2.2.2.1 output.val output.isLt
  change _ ∧ (if (outputAt witness output.val).active = 0 then ZeroOutputWitness (outputAt witness output.val) else _) at facts
  split at facts
  · exact Or.inr facts.2.2.1
  · exact Or.inl facts.2.1

theorem source_note_scheduled_digest (statement : V8PublicStatement) (witness : V8Witness) (note : Fin 4) :
    (stateWords (scheduledFinal statement witness (noteBridgeCall note.val + 2))).take 7 =
      poseidon2V8Sponge 1 (sourceNoteWords (sourceNoteOpening witness note.val)) := by
  fin_cases note
  · exact input_zero_note_scheduled_digest statement witness
  · exact input_one_note_scheduled_digest statement witness
  · exact output_zero_note_scheduled_digest statement witness
  · exact output_one_note_scheduled_digest statement witness

theorem typed_note_shape (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) :
    CanonicalNoteOpening (sourceNoteOpening witness note.val) ∨ ZeroNoteOpening (sourceNoteOpening witness note.val) := by
  by_cases input : note.val < 2
  · simpa only [sourceNoteOpening,if_pos input,inputAt] using
      typed_input_note_shape statement witness valid ⟨note.val,input⟩
  · simpa only [sourceNoteOpening,if_neg input,outputAt] using
      typed_output_note_shape statement witness valid ⟨note.val - 2,by omega⟩

theorem typed_note_scheduled_digest_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (note : Fin 4) :
    (stateWords (scheduledFinal statement witness (noteBridgeCall note.val + 2))).take 7 =
      exactV8NoteCommitment (sourceNoteOpening witness note.val) := by
  rw [source_note_scheduled_digest,source_note_digest_eq_exact_of_shape _ (typed_note_shape statement witness valid note)]

end HegemonCrypto.SmallWood.V8Smz9SourceNoteDigestForward

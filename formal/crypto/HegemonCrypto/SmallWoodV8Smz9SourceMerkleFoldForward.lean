import HegemonCrypto.SmallWoodV8Smz9SourceMerkleDigestForward
import HegemonCrypto.SmallWoodV8Smz9SourceNoteDigestForward

namespace HegemonCrypto.SmallWood.V8Smz9SourceMerkleFoldForward
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (inputNoteCall inputMerkleCall)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows (previousCall)
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleDigestForward
open HegemonCrypto.SmallWood.V8Smz9SourceNoteDigestForward
open HegemonCrypto.SmallWood.V8Smz9SourceNoteFrames
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (noteBridgeCall)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def sourceMerkleStep (witness : V8Witness) (input : Nat) (current : List Nat) (level : Nat) : List Nat :=
  if (inputAt witness input).position / (2 ^ level) % 2 = 0 then
    poseidon2V8Compress14 4 current ((inputAt witness input).siblings.getD level [])
  else poseidon2V8Compress14 4 ((inputAt witness input).siblings.getD level []) current

theorem typed_input_note_scheduled_digest_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    (stateWords (scheduledFinal statement witness (inputNoteCall input.val + 2))).take 7 =
      exactV8NoteCommitment (inputAt witness input.val).note := by
  have digest := typed_note_scheduled_digest_exact statement witness valid ⟨input.val,by omega⟩
  have call : noteBridgeCall input.val = inputNoteCall input.val := by fin_cases input <;> rfl
  simpa only [call,sourceNoteOpening,if_pos input.isLt,inputAt] using digest

theorem merkle_prefix_call_indices (input : Fin 2) (level : Nat) :
    inputNoteCall input.val + 2 + (level + 1) = inputMerkleCall input.val level ∧
      previousCall input.val level = inputNoteCall input.val + 2 + level := by
  fin_cases input <;> by_cases first : level = 0 <;>
    simp [inputNoteCall,inputMerkleCall,previousCall,first]
  all_goals omega

theorem scheduled_merkle_prefix_fold (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (count : Nat)
    (bound : count ≤ 32) :
    (stateWords (scheduledFinal statement witness (inputNoteCall input.val + 2 + count))).take 7 =
      (List.range count).foldl (sourceMerkleStep witness input.val)
        (exactV8NoteCommitment (inputAt witness input.val).note) := by
  induction count with
  | zero =>
      simpa only [Nat.add_zero,List.range_zero,List.foldl_nil] using
        typed_input_note_scheduled_digest_exact statement witness valid input
  | succ count ih =>
      have levelBound : count < 32 := by omega
      have calls := merkle_prefix_call_indices input count
      rw [calls.1,scheduled_merkle_final_digest_step statement witness valid input.val count input.isLt levelBound,
        calls.2,ih (by omega),List.range_succ,List.foldl_append,List.foldl_cons,List.foldl_nil]
      rfl

theorem typed_merkle_scheduled_digest_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) :
    (stateWords (scheduledFinal statement witness (inputMerkleCall input.val 31))).take 7 =
      exactV8MerkleRoot (exactV8NoteCommitment (inputAt witness input.val).note)
        (inputAt witness input.val).position (inputAt witness input.val).siblings := by
  have folded := scheduled_merkle_prefix_fold statement witness valid input 32 (by decide)
  have finalCall : inputNoteCall input.val + 2 + 32 = inputMerkleCall input.val 31 := by
    fin_cases input <;> rfl
  rw [finalCall] at folded
  exact folded

end HegemonCrypto.SmallWood.V8Smz9SourceMerkleFoldForward

import HegemonCrypto.SmallWoodV8Smz9SourceMerkleInitialFrames
import HegemonCrypto.SmallWoodV8Smz9SourceInlineRows
import HegemonCrypto.SmallWoodV8Smz9TypedScheduleInventory
import HegemonCrypto.SmallWoodV8Smz9TypedScheduleKernel

namespace HegemonCrypto.SmallWood.V8Smz9SourceMerkleDigestForward

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies

set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem flat_merkle_step_call (input level : Nat) (levelBound : level < 32) :
    V8Smz9InputMerkleSources.merkleCall (input * 32 + level) =
      inputMerkleCall input level := by
  have parts : (input * 32 + level) / 32 = input ∧
      (input * 32 + level) % 32 = level := by omega
  simp only [V8Smz9InputMerkleSources.merkleCall, inputMerkleCall, parts.1, parts.2]

theorem source_merkle_plan_at_step (statement : V8PublicStatement) (witness : V8Witness)
    (input level : Nat) (inputBound : input < 2) (levelBound : level < 32) :
    sourceCallPlan statement witness (inputMerkleCall input level)
        (scheduledFinal statement witness) =
      let operands := orient (inputAt witness input).position level
        (finalDigest (scheduledFinal statement witness)
          (previousCall input level))
        (fixedWords 7 ((inputAt witness input).siblings.getD level []))
      Plan.compress (.inputMerkle input level) 4 operands.1 operands.2 := by
  have stepBound : input * 32 + level < 64 := by omega
  have plan := actual_merkle_plan statement witness (scheduledFinal statement witness)
    ⟨input * 32 + level, stepBound⟩
  rw [flat_merkle_step_call input level levelBound] at plan
  have parts : (input * 32 + level) / 32 = input ∧ (input * 32 + level) % 32 = level := by omega
  simpa only [parts.1,parts.2] using plan

theorem scheduled_merkle_final_digest_step (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness)
    (input level : Nat) (inputBound : input < 2) (levelBound : level < 32) :
    (stateWords (scheduledFinal statement witness (inputMerkleCall input level))).take 7 =
      if (witness.inputs.getD input default).position / (2 ^ level) % 2 = 0 then
        poseidon2V8Compress14 4
          ((stateWords (scheduledFinal statement witness (previousCall input level))).take 7)
          ((inputAt witness input).siblings.getD level [])
      else
        poseidon2V8Compress14 4
          ((inputAt witness input).siblings.getD level [])
          ((stateWords (scheduledFinal statement witness (previousCall input level))).take 7) := by
  rw [every_call_has_actual_kernel_final]
  have callBound : inputMerkleCall input level < 125 := by
    unfold inputMerkleCall
    split <;> omega
  have initial := typed_valid_initial_is_actual_source_frame statement witness valid
    ⟨inputMerkleCall input level, callBound⟩
  change stateWords (scheduledInitial statement witness (inputMerkleCall input level)) = _ at initial
  rw [initial, source_merkle_plan_at_step statement witness input level inputBound levelBound]
  simp only [rawPreparedPlan, compress_digest_is_exact_source]
  let sibling := (inputAt witness input).siblings.getD level []
  have siblingShape := typed_sibling_exact statement witness valid
    ⟨input, inputBound⟩ ⟨level, levelBound⟩
  have siblingExact : fixedWords 7 sibling = sibling :=
    fixed_words_exact 7 sibling siblingShape.1
  rw [siblingExact]
  rw [orient_is_source_bit]
  by_cases bit : (witness.inputs.getD input default).position / (2 ^ level) % 2 = 0
  all_goals simp only [inputAt,bit,↓reduceIte]
  all_goals rfl

end HegemonCrypto.SmallWood.V8Smz9SourceMerkleDigestForward

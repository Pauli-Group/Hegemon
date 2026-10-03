import HegemonCrypto.SmallWoodV8Smz9SourceFullRatePreparation
import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9ActionIntentSourceWords
import Mathlib.Tactic.FinCases

namespace HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial
open HegemonCrypto.SmallWood.V8Smz9FullRateSponge
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9ActionIntentSourceWords
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 3000000

def actionPriorState (statement : V8PublicStatement) (witness : V8Witness) (block : Nat) : State :=
  if block = 0 then zeroState else scheduledFinal statement witness (79 + block - 1)

theorem action_projection_length (statement : V8PublicStatement) :
    (exactV8ActionIntentProjection statement).length = 120 := by
  simp only [exactV8ActionIntentProjection, List.length_map, List.length_range, publicWordCount]

theorem action_projection_word (statement : V8PublicStatement) (wordIndex : Fin 120) :
    (exactV8ActionIntentProjection statement).getD wordIndex.val 0 =
      actionIntentProjectedWord (encodePublicStatement statement) wordIndex.val := by
  simp [exactV8ActionIntentProjection, actionIntentProjectedWord, ActionIntentExcluded,
    publicWordCount, List.getD_eq_getElem?_getD, wordIndex.isLt]

theorem actual_action_plan (statement : V8PublicStatement) (witness : V8Witness)
    (earlier : Nat → State) (block : Fin 15) :
    sourceCallPlan statement witness (79 + block.val) earlier =
      Plan.sponge (.actionIntent block.val) poseidon2V8ActionIntentDomain
        (exactV8ActionIntentProjection statement) 15 block.val
        (previousSponge (79 + block.val) block.val) := by
  fin_cases block <;> rfl

theorem actual_action_source_frame (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 15) :
    actualSourceFrame statement witness ⟨79 + block.val, by omega⟩ =
      fullRateFrame poseidon2V8ActionIntentDomain (exactV8ActionIntentProjection statement) 15
        (stateWords (actionPriorState statement witness block.val)) block.val := by
  rw [actualSourceFrame, actual_action_plan]
  dsimp only [rawPreparedPlan]
  by_cases first : block.val = 0
  · simp only [previousSponge, actionPriorState, if_pos first]
    exact source_full_rate_preparation _ _ _ 15 block.val
      (action_projection_length statement) block.isLt (state_words_length _)
  · simp only [previousSponge, actionPriorState, if_neg first]
    exact source_full_rate_preparation _ _ _ 15 block.val
      (action_projection_length statement) block.isLt (state_words_length _)

noncomputable section

theorem action_frame_field (inputs : List Nat) (inputShape : inputs.length = 120)
    (block : Fin 15) (previous : State) (firstZero : block.val = 0 → previous = zeroState)
    (lane : Fin 16) :
    ((fullRateFrame poseidon2V8ActionIntentDomain inputs 15 (stateWords previous) block.val).getD lane.val 0 : F) =
      ((stateWords previous).getD lane.val 0 : F) +
        (if lane.val < 8 then (inputs.getD (block.val * 8 + lane.val) 0 : F)
          else (fullRateFrameConstant 0 block.val lane.val : F)) := by
  rw [full_rate_frame_word]
  fin_cases block
  · have zero := firstZero rfl
    subst previous
    fin_cases lane <;>
      simp [stateWords, zeroState, word, inputShape, fullRateFrameConstant,
        fullRateSourceDomain, fullRateSourceBlocks, poseidon2V8ActionIntentDomain]
  all_goals fin_cases lane <;>
    simp [stateWords, inputShape, fullRateFrameConstant, fullRateSourceBlocks]

theorem actual_action_frame_field (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 15) (lane : Fin 16) :
    ((actualSourceFrame statement witness ⟨79 + block.val, by omega⟩).getD lane.val 0 : F) =
      ((stateWords (actionPriorState statement witness block.val)).getD lane.val 0 : F) +
        (if lane.val < 8 then ((exactV8ActionIntentProjection statement).getD (block.val * 8 + lane.val) 0 : F)
          else (fullRateFrameConstant 0 block.val lane.val : F)) := by
  rw [actual_action_source_frame]
  exact action_frame_field _ (action_projection_length statement) block
    (actionPriorState statement witness block.val)
    (fun first => by simp only [actionPriorState, if_pos first]) lane

end
end HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial

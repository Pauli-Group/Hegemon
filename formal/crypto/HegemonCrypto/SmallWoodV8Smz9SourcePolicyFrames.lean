import HegemonCrypto.SmallWoodV8Smz9SourceFullRatePreparation
import HegemonCrypto.SmallWoodV8Smz9SourcePolicyRawWords
import HegemonCrypto.SmallWoodV8Smz9FullRateSourceFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9FullRateSponge
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1200000

def policyPriorState (statement : V8PublicStatement) (witness : V8Witness) (block : Nat) : State :=
  if block=0 then zeroState else scheduledFinal statement witness (94+block-1)

theorem actual_policy_plan (statement : V8PublicStatement) (witness : V8Witness)
    (earlier : Nat → State) (block : Fin 4) :
    sourceCallPlan statement witness (94+block.val) earlier =
      Plan.sponge (.policy block.val) 7 (sourcePolicyWords witness.authorization)
        4 block.val (previousSponge (94+block.val) block.val) := by
  fin_cases block <;> rfl

theorem actual_policy_source_frame (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 4) :
    actualSourceFrame statement witness ⟨94+block.val, by omega⟩ =
      fullRateFrame 7 (sourcePolicyWords witness.authorization) 4
        (stateWords (policyPriorState statement witness block.val)) block.val := by
  rw [actualSourceFrame, actual_policy_plan]
  dsimp only [rawPreparedPlan]
  by_cases first : block.val=0
  · simp only [previousSponge, policyPriorState, if_pos first]
    exact source_full_rate_preparation 7 _ _ 4 block.val
      (policy_words_length witness.authorization) block.isLt (state_words_length _)
  · simp only [previousSponge, policyPriorState, if_neg first]
    exact source_full_rate_preparation 7 _ _ 4 block.val
      (policy_words_length witness.authorization) block.isLt (state_words_length _)

noncomputable section

theorem policy_frame_field (inputs : List Nat) (inputShape : inputs.length=32)
    (block : Fin 4) (previous : State) (firstZero : block.val=0 → previous=zeroState)
    (lane : Fin 16) :
    ((fullRateFrame 7 inputs 4 (stateWords previous) block.val).getD lane.val 0 : F) =
      ((stateWords previous).getD lane.val 0 : F) +
        (if lane.val<8 then (inputs.getD (block.val*8+lane.val) 0 : F)
          else (fullRateFrameConstant 1 block.val lane.val : F)) := by
  rw [full_rate_frame_word]
  fin_cases block
  · have zero := firstZero rfl
    subst previous
    fin_cases lane <;>
      simp [stateWords, zeroState, word, inputShape, fullRateFrameConstant,
        fullRateSourceDomain, fullRateSourceBlocks, poseidon2V8PolicyDomain]
  all_goals fin_cases lane <;>
    simp [stateWords, inputShape, fullRateFrameConstant, fullRateSourceBlocks]

/-- The actual frame word interpreted in the field. The source rate word and
the previous computed state remain explicit until constructor readback. -/
theorem actual_policy_frame_field (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 4) (lane : Fin 16) :
    ((actualSourceFrame statement witness ⟨94+block.val, by omega⟩).getD lane.val 0 : F) =
      ((stateWords (policyPriorState statement witness block.val)).getD lane.val 0 : F) +
        (if lane.val<8 then ((sourcePolicyWords witness.authorization).getD (block.val*8+lane.val) 0 : F)
          else (fullRateFrameConstant 1 block.val lane.val : F)) := by
  rw [actual_policy_source_frame]
  exact policy_frame_field _ (policy_words_length witness.authorization) block
    (policyPriorState statement witness block.val)
    (fun first => by simp only [policyPriorState, if_pos first]) lane

end



end HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial

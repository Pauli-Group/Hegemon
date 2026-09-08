import HegemonCrypto.SmallWoodV8Smz9ActionIntentSourceWords
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9ActionIntentSourceWords
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

def actionInitialTarget (block lane : Nat) : Nat :=
  if lane < 8 then actionIntentWordTarget (block * 8 + lane)
  else fullRateFrameTarget 0 block lane

def actionInitialAttempt (block lane : Nat) : CsrExecutableAttempt :=
  attempt (18468 + 16 * block + lane) 24 (16 * block + lane) 0
    ([(hashInitialIndex (79 + block) lane, 1)] ++
      if block = 0 then [] else [(hashFinalIndex (79 + block - 1) lane, 158)])
    (actionInitialTarget block lane)

theorem action_rate_descriptor (block : Fin 15) (lane : Fin 8) :
    actionInitialAttempt block.val lane.val = actionIntentWordAttempt (block.val * 8 + lane.val) := by
  have div : (block.val * 8 + lane.val) / 8 = block.val := by omega
  have mod : (block.val * 8 + lane.val) % 8 = lane.val := by omega
  simp only [actionInitialAttempt, actionInitialTarget, actionIntentWordAttempt,
    if_pos lane.isLt, div, mod]

theorem action_capacity_descriptor (block : Fin 15) (lane : Fin 8) :
    actionInitialAttempt block.val (8 + lane.val) = fullRateFrameAttempt 0 block.val (8 + lane.val) := by
  simp only [actionInitialAttempt, actionInitialTarget, fullRateFrameAttempt,
    fullRateSourceCall, fullRateSourceAttempt, show ¬8 + lane.val < 8 by omega,
    if_false, if_true, Nat.mul_zero]

theorem action_initial_descriptor_member (block : Fin 15) (lane : Fin 16) :
    actionInitialAttempt block.val lane.val ∈ exactCsrAttempts := by
  by_cases rate : lane.val < 8
  · rw [action_rate_descriptor block ⟨lane.val, rate⟩]
    exact action_intent_word_source ⟨block.val * 8 + lane.val, by omega⟩
  · have address : lane.val = 8 + (lane.val - 8) := by omega
    rw [address, action_capacity_descriptor block ⟨lane.val - 8, by omega⟩]
    exact full_rate_frame_source ⟨0, by decide⟩ block ⟨lane.val - 8, by omega⟩ block.isLt

theorem exact_action_initial_attempt (block : Fin 15) (lane : Fin 16) :
    exactCsrAttempts[18468 + 16 * block.val + lane.val]? =
      some (actionInitialAttempt block.val lane.val) :=
  exact_attempt_lookup _ (action_initial_descriptor_member block lane)

theorem exact_action_all_240_lookup (offset : Fin 240) :
    exactCsrAttempts[18468 + offset.val]? =
      some (actionInitialAttempt (offset.val / 16) (offset.val % 16)) := by
  have address : 18468 + offset.val = 18468 + 16 * (offset.val / 16) + offset.val % 16 := by omega
  rw [address]
  exact exact_action_initial_attempt ⟨offset.val / 16, by omega⟩ ⟨offset.val % 16, by omega⟩

end HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial

import HegemonCrypto.SmallWoodV8Smz9SourcePolicyRawWords
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies
import HegemonCrypto.SmallWoodV8Smz9FullRateSourceFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9PolicySourceWords
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

def policyInitialAttempt (block lane : Nat) : CsrExecutableAttempt :=
  attempt (18715+16*block+lane) 26 (16*block+lane) 0
    (([(hashInitialIndex (94+block) lane, 1)] ++
      if block=0 then [] else [(hashFinalIndex (94+block-1) lane, 158)]) ++
      if lane<8 then [(rawIndex (policyWordRow (block*8+lane)), 158)] else [])
    (if lane<8 then 0 else fullRateFrameTarget 1 block lane)

theorem policy_rate_descriptor (block : Fin 4) (lane : Fin 8) :
    policyInitialAttempt block.val lane.val = policyWordAttempt (block.val*8+lane.val) := by
  have div : (block.val*8+lane.val)/8 = block.val := by omega
  have mod : (block.val*8+lane.val)%8 = lane.val := by omega
  simp only [policyInitialAttempt, policyWordAttempt, if_pos lane.isLt, div, mod]

theorem policy_capacity_descriptor (block : Fin 4) (lane : Fin 8) :
    policyInitialAttempt block.val (8+lane.val) = fullRateFrameAttempt 1 block.val (8+lane.val) := by
  simp only [policyInitialAttempt, fullRateFrameAttempt, fullRateSourceCall,
    fullRateSourceAttempt, show ¬8+lane.val<8 by omega, if_false,
    Nat.one_ne_zero, List.append_nil]

theorem policy_initial_descriptor_member (block : Fin 4) (lane : Fin 16) :
    policyInitialAttempt block.val lane.val ∈ exactCsrAttempts := by
  by_cases rate : lane.val<8
  · rw [policy_rate_descriptor block ⟨lane.val, rate⟩]
    exact policy_word_source _ (by omega)
  · have address : lane.val = 8+(lane.val-8) := by omega
    rw [address, policy_capacity_descriptor block ⟨lane.val-8, by omega⟩]
    exact full_rate_frame_source ⟨1, by decide⟩ ⟨block.val, by omega⟩
      ⟨lane.val-8, by omega⟩ (by exact block.isLt)

/-- Checked source membership plus canonical global-index metadata identifies
the actual entry, including family, local index, emission, terms, and target. -/
theorem exact_policy_initial_attempt (block : Fin 4) (lane : Fin 16) :
    exactCsrAttempts[18715+16*block.val+lane.val]? = some (policyInitialAttempt block.val lane.val) :=
  exact_attempt_lookup _ (policy_initial_descriptor_member block lane)



end HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial

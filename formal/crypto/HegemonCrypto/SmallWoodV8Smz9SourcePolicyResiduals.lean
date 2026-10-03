import HegemonCrypto.SmallWoodV8Smz9SourcePolicyFrames
import HegemonCrypto.SmallWoodV8Smz9SourcePolicyAttempts

namespace HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9PolicySourceWords
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

noncomputable section

theorem actual_policy_capacity_coefficient (pub : Nat → F) (block : Fin 4) (lane : Fin 8) :
    actualCsrCoefficients pub (fullRateFrameTarget 1 block.val (8+lane.val)) =
      (fullRateFrameConstant 1 block.val (8+lane.val) : F) :=
  actual_csr_node_field_equation pub
    (full_rate_frame_target ⟨1, by decide⟩ ⟨block.val, by omega⟩ lane)

theorem actual_policy_residual_formula (pub : Nat → F) (words : List Nat) (block lane : Nat) :
    actualCsrResidual pub words (policyInitialAttempt block lane) =
      (words.getD (hashInitialIndex (94+block) lane) 0 : F) -
        (if block=0 then 0 else (words.getD (hashFinalIndex (94+block-1) lane) 0 : F)) -
        (if lane<8 then (words.getD (rawIndex (policyWordRow (block*8+lane))) 0 : F)
          else actualCsrCoefficients pub (fullRateFrameTarget 1 block lane)) := by
  have negative : actualCsrCoefficients pub 158 = -1 := by
    simpa using (actual_dense_negative_coefficients pub).1 0 (by decide)
  by_cases first : block=0 <;> by_cases rate : lane<8 <;>
    simp [policyInitialAttempt, actualCsrResidual, actualCsrTerms, attempt,
      first, rate, (actual_csr_zero_one pub).1, (actual_csr_zero_one pub).2,
      negative, sub_eq_add_neg, add_assoc]

theorem typed_policy_prior_field (statement : V8PublicStatement) (witness : V8Witness)
    (tail : List Nat) (block : Fin 4) (lane : Fin 16) :
    ((stateWords (policyPriorState statement witness block.val)).getD lane.val 0 : F) =
      if block.val=0 then 0 else
        ((typedAssignment statement witness tail).getD
          (hashFinalIndex (94+block.val-1) lane.val) 0 : F) := by
  by_cases first : block.val=0
  · fin_cases lane <;> simp [policyPriorState, first, stateWords, zeroState, word]
  · rw [policyPriorState, if_neg first, if_neg first,
      typed_final_is_scheduled_final statement witness tail
        ⟨94+block.val-1, by omega⟩ lane]

theorem typed_policy_initial_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (tail : List Nat)
    (block : Fin 4) (lane : Fin 16) :
    ((typedAssignment statement witness tail).getD
      (hashInitialIndex (94+block.val) lane.val) 0 : F) =
      (if block.val=0 then 0 else ((typedAssignment statement witness tail).getD
        (hashFinalIndex (94+block.val-1) lane.val) 0 : F)) +
      (if lane.val<8 then ((sourcePolicyWords witness.authorization).getD (block.val*8+lane.val) 0 : F)
        else (fullRateFrameConstant 1 block.val lane.val : F)) := by
  rw [typed_initial_readback statement witness valid tail ⟨94+block.val, by omega⟩ lane,
    actual_policy_frame_field, typed_policy_prior_field statement witness tail block lane]

/-- All subtraction terms and constants are tied to actual constructed cells
and interpreted source DAG nodes; none is an external equality assumption. -/
theorem typed_policy_initial_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (tail : List Nat)
    (pub : Nat → F) (block : Fin 4) (lane : Fin 16) :
    actualCsrResidual pub (typedAssignment statement witness tail)
      (policyInitialAttempt block.val lane.val) = 0 := by
  rw [actual_policy_residual_formula, typed_policy_initial_field statement witness valid tail block lane]
  by_cases rate : lane.val<8
  · rw [if_pos rate, if_pos rate,
      typed_policy_raw_word statement witness tail ⟨block.val*8+lane.val, by omega⟩]
    ring
  · rw [if_neg rate, if_neg rate]
    have address : lane.val = 8+(lane.val-8) := by omega
    have coefficient := actual_policy_capacity_coefficient pub block ⟨lane.val-8, by omega⟩
    rw [← address] at coefficient
    rw [coefficient]
    ring

theorem typed_all_64_actual_policy_initial_csr_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (tail : List Nat)
    (pub : Nat → F) (offset : Fin 64) :
    (exactCsrAttempts[18715+offset.val]?).map
      (actualCsrResidual pub (typedAssignment statement witness tail)) = some 0 := by
  have address : 18715+offset.val = 18715+16*(offset.val/16)+offset.val%16 := by omega
  rw [address, exact_policy_initial_attempt ⟨offset.val/16, by omega⟩ ⟨offset.val%16, by omega⟩,
    Option.map_some, typed_policy_initial_attempt_zero statement witness valid tail pub]

end




end HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial

import HegemonCrypto.SmallWoodV8Smz9SourceActionIntentFrames
import HegemonCrypto.SmallWoodV8Smz9SourceActionIntentAttempts

namespace HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ActionIntentSourceWords
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

noncomputable section

theorem actual_action_rate_coefficient (publicWords : List Nat) (wordIndex : Fin 120) :
    actualCsrCoefficients (fun index => (publicWords.getD index 0 : F))
      (actionIntentWordTarget wordIndex.val) =
        (actionIntentProjectedWord publicWords wordIndex.val : F) := by
  by_cases excluded : ActionIntentExcluded wordIndex.val
  · simp only [actionIntentWordTarget, actionIntentProjectedWord, if_pos excluded, Nat.cast_zero]
    exact (actual_csr_zero_one _).1
  · simp only [actionIntentWordTarget, actionIntentProjectedWord, if_neg excluded]
    exact actual_csr_node_field_equation _ (action_intent_public_node wordIndex)

theorem actual_action_capacity_coefficient (pub : Nat → F) (block : Fin 15) (lane : Fin 8) :
    actualCsrCoefficients pub (fullRateFrameTarget 0 block.val (8 + lane.val)) =
      (fullRateFrameConstant 0 block.val (8 + lane.val) : F) :=
  actual_csr_node_field_equation pub (full_rate_frame_target ⟨0, by decide⟩ block lane)

theorem actual_action_residual_formula (pub : Nat → F) (words : List Nat) (block lane : Nat) :
    actualCsrResidual pub words (actionInitialAttempt block lane) =
      (words.getD (hashInitialIndex (79 + block) lane) 0 : F) -
        (if block = 0 then 0 else (words.getD (hashFinalIndex (79 + block - 1) lane) 0 : F)) -
        actualCsrCoefficients pub (actionInitialTarget block lane) := by
  have negative : actualCsrCoefficients pub 158 = -1 := by
    simpa using (actual_dense_negative_coefficients pub).1 0 (by decide)
  by_cases first : block = 0 <;>
    simp [actionInitialAttempt, actualCsrResidual, actualCsrTerms, attempt,
      first, (actual_csr_zero_one pub).2, negative, sub_eq_add_neg, add_assoc]

theorem full_candidate_action_prior_field (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 15) (lane : Fin 16) :
    ((stateWords (actionPriorState statement witness block.val)).getD lane.val 0 : F) =
      if block.val = 0 then 0 else
        ((fullTypedSourceCandidate statement witness).getD
          (hashFinalIndex (79 + block.val - 1) lane.val) 0 : F) := by
  by_cases first : block.val = 0
  · fin_cases lane <;> simp [actionPriorState, first, stateWords, zeroState, word]
  · rw [actionPriorState, if_neg first, if_neg first,
      full_candidate_final_schedule_readback statement witness ⟨79 + block.val - 1, by omega⟩ lane]

theorem full_candidate_action_initial_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (block : Fin 15) (lane : Fin 16) :
    ((fullTypedSourceCandidate statement witness).getD
      (hashInitialIndex (79 + block.val) lane.val) 0 : F) =
      (if block.val = 0 then 0 else ((fullTypedSourceCandidate statement witness).getD
        (hashFinalIndex (79 + block.val - 1) lane.val) 0 : F)) +
      (if lane.val < 8 then ((exactV8ActionIntentProjection statement).getD (block.val * 8 + lane.val) 0 : F)
        else (fullRateFrameConstant 0 block.val lane.val : F)) := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨79 + block.val, by omega⟩ lane,
    actual_action_frame_field, full_candidate_action_prior_field statement witness block lane]

theorem full_candidate_action_initial_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (block : Fin 15) (lane : Fin 16) :
    actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
      (fullTypedSourceCandidate statement witness) (actionInitialAttempt block.val lane.val) = 0 := by
  rw [actual_action_residual_formula, full_candidate_action_initial_field statement witness valid block lane]
  by_cases rate : lane.val < 8
  · rw [if_pos rate, actionInitialTarget, if_pos rate,
      actual_action_rate_coefficient _ ⟨block.val * 8 + lane.val, by omega⟩,
      action_projection_word statement ⟨block.val * 8 + lane.val, by omega⟩]
    ring
  · rw [if_neg rate, actionInitialTarget, if_neg rate]
    have address : lane.val = 8 + (lane.val - 8) := by omega
    have coefficient := actual_action_capacity_coefficient
      (fun index => ((encodePublicStatement statement).getD index 0 : F)) block ⟨lane.val - 8, by omega⟩
    rw [← address] at coefficient
    rw [coefficient]
    ring

theorem full_candidate_actual_action_all_240_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 240) :
    ∃ entry, exactCsrAttempts[18468 + offset.val]? = some entry ∧ entry.family = 24 ∧
      entry.localIndex = offset.val ∧
      actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (fullTypedSourceCandidate statement witness) entry = 0 := by
  refine ⟨actionInitialAttempt (offset.val / 16) (offset.val % 16), exact_action_all_240_lookup offset,
    rfl, ?_, full_candidate_action_initial_attempt_zero statement witness valid
      ⟨offset.val / 16, by omega⟩ ⟨offset.val % 16, by omega⟩⟩
  change 16 * (offset.val / 16) + offset.val % 16 = offset.val
  omega

end
end HegemonCrypto.SmallWood.V8Smz9SourceActionIntentInitial

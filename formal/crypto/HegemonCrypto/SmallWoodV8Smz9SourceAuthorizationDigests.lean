import HegemonCrypto.SmallWoodV8Smz9SourceAuthorizationProjections
import HegemonCrypto.SmallWoodV8Smz9SourceInlineRows

namespace HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
set_option Elab.async false
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

theorem policy_segment_plan (statement : V8PublicStatement) (witness : V8Witness) (block : Fin 4) :
    sourceCallPlan statement witness (94+block.val) (scheduledFinal statement witness) =
      .sponge (.policy block.val) 7 (sourcePolicyWords witness.authorization) 4 block.val
        (previousSponge (94+block.val) block.val) := by
  fin_cases block <;> rfl

theorem current_segment_plan (statement : V8PublicStatement) (witness : V8Witness) (block : Fin 3) :
    sourceCallPlan statement witness (98+block.val) (scheduledFinal statement witness) =
      .sponge (.currentAccumulator block.val) 6 (sourceAccumulatorWords witness.authorization.current) 3 block.val
        (previousSponge (98+block.val) block.val) := by
  fin_cases block <;> rfl

theorem next_segment_plan (statement : V8PublicStatement) (witness : V8Witness) (block : Fin 3) :
    sourceCallPlan statement witness (101+block.val) (scheduledFinal statement witness) =
      .sponge (.nextAccumulator block.val) 6 (sourceAccumulatorWords (effectiveNext witness.authorization)) 3 block.val
        (previousSponge (101+block.val) block.val) := by
  fin_cases block <;> rfl

theorem value_lock_segment_plan (statement : V8PublicStatement) (witness : V8Witness) (block : Fin 2) :
    sourceCallPlan statement witness (104+block.val) (scheduledFinal statement witness) =
      .sponge (.valueLock block.val) 8 (sourceValueLockWords witness.authorization.current) 2 block.val
        (previousSponge (104+block.val) block.val) := by
  fin_cases block <;> rfl

theorem source_policy_segment_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 97)).take 7 =
      poseidon2V8Sponge 7 (sourcePolicyWords witness.authorization) := by
  exact source_sponge_segment_digest statement witness 94 4 7 (sourcePolicyWords witness.authorization) .policy
    (by decide) (by decide) (fun block bound => policy_segment_plan statement witness ⟨block, bound⟩)
    (by decide) (by rw [policy_words_length]; decide) (by rw [policy_words_length]; rfl)

theorem source_current_segment_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 100)).take 7 =
      poseidon2V8Sponge 6 (sourceAccumulatorWords witness.authorization.current) := by
  exact source_sponge_segment_digest statement witness 98 3 6 (sourceAccumulatorWords witness.authorization.current)
    .currentAccumulator (by decide) (by decide)
    (fun block bound => current_segment_plan statement witness ⟨block, bound⟩)
    (by decide) (by rw [accumulator_words_length]; decide) (by rw [accumulator_words_length]; rfl)

theorem source_next_segment_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 103)).take 7 =
      poseidon2V8Sponge 6 (sourceAccumulatorWords (effectiveNext witness.authorization)) := by
  exact source_sponge_segment_digest statement witness 101 3 6
    (sourceAccumulatorWords (effectiveNext witness.authorization)) .nextAccumulator (by decide) (by decide)
    (fun block bound => next_segment_plan statement witness ⟨block, bound⟩)
    (by decide) (by rw [accumulator_words_length]; decide) (by rw [accumulator_words_length]; rfl)

theorem source_value_lock_segment_digest (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 105)).take 7 =
      poseidon2V8Sponge 8 (sourceValueLockWords witness.authorization.current) := by
  exact source_sponge_segment_digest statement witness 104 2 8
    (sourceValueLockWords witness.authorization.current) .valueLock (by decide) (by decide)
    (fun block bound => value_lock_segment_plan statement witness ⟨block, bound⟩)
    (by decide) (by rw [value_lock_words_length]; decide) (by rw [value_lock_words_length]; rfl)

theorem typed_policy_digest_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (stateWords (scheduledFinal statement witness 97)).take 7 =
      exactV8PolicyRoot witness.authorization.policySignerTags
        witness.authorization.current.threshold witness.authorization.current.signerCount := by
  rw [source_policy_segment_digest,
    source_policy_words_exact _ (typed_valid_authorization_geometry statement witness valid).2.2]
  rfl

theorem typed_current_digest_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (stateWords (scheduledFinal statement witness 100)).take 7 =
      exactV8AccumulatorDigest witness.authorization.current := by
  rw [source_current_segment_digest,
    source_accumulator_words_exact _ (typed_valid_authorization_geometry statement witness valid).1]
  rfl

/-- In final-threshold mode the effective next record is deliberately not the
all-zero typed next record; the source retains the current fixed fields. -/
theorem typed_effective_next_digest_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (stateWords (scheduledFinal statement witness 103)).take 7 =
      exactV8AccumulatorDigest (effectiveNext witness.authorization) := by
  have shapes := typed_valid_authorization_geometry statement witness valid
  rw [source_next_segment_digest, source_accumulator_words_exact _
    (effective_next_geometry _ shapes.1 shapes.2.1)]
  rfl

theorem typed_value_lock_digest_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (stateWords (scheduledFinal statement witness 105)).take 7 =
      exactV8ValueLockDigest witness.authorization.current := by
  rw [source_value_lock_segment_digest,
    source_value_lock_words_exact _ (typed_valid_authorization_geometry statement witness valid).1]
  rfl

theorem typed_call_final_word_is_scheduled (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (limb : Nat) :
    callFinalWord (typedLiveInitialStates statement witness) call.val limb =
      (stateWords (scheduledFinal statement witness call.val)).getD limb 0 := by
  rw [call_final_word_is_permutation, every_call_has_actual_kernel_final]
  have initial : callInitial (typedLiveInitialStates statement witness) call.val =
      stateWords (scheduledInitial statement witness call.val) := by
    simp only [callInitial, dif_pos call.isLt, typedLiveInitialStates, stateWords]
  rw [initial]

theorem first_seven_readback (words digest : List Nat) (same : words.take 7 = digest)
    (limb : Fin 7) : words.getD limb.val 0 = digest.getD limb.val 0 := by
  rw [← same]
  simp only [List.getD_eq_getElem?_getD, List.getElem?_take, if_pos limb.isLt]

theorem typed_policy_call_final_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    callFinalWord (typedLiveInitialStates statement witness) 97 limb.val =
      (exactV8PolicyRoot witness.authorization.policySignerTags
        witness.authorization.current.threshold witness.authorization.current.signerCount).getD limb.val 0 := by
  rw [typed_call_final_word_is_scheduled statement witness ⟨97, by decide⟩]
  exact first_seven_readback _ _ (typed_policy_digest_exact statement witness valid) limb

theorem typed_non_single_policy_binding (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) :
    witness.authorization.current.policyRoot =
      exactV8PolicyRoot witness.authorization.policySignerTags
        witness.authorization.current.threshold witness.authorization.current.signerCount ∧
      NonzeroWords witness.authorization.current.policyRoot := by
  have auth := valid.2.2.1.2.2
  unfold V8AuthorizationValid at auth
  cases mode : witness.authorization.mode with
  | singleKey => exact False.elim (nonsingle mode)
  | approvalStep =>
      simp only [mode] at auth
      exact ⟨auth.2.2.2.2.2.1, auth.2.2.1.2.1⟩
  | finalThresholdSpend =>
      simp only [mode] at auth
      exact ⟨auth.2.2.2.2.1, auth.2.1.2.1⟩

theorem typed_non_single_policy_final_is_current (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) :
    (stateWords (scheduledFinal statement witness 97)).take 7 = witness.authorization.current.policyRoot :=
  (typed_policy_digest_exact statement witness valid).trans
    (typed_non_single_policy_binding statement witness valid nonsingle).1.symm

theorem typed_non_single_policy_call_is_current (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) (limb : Fin 7) :
    callFinalWord (typedLiveInitialStates statement witness) 97 limb.val =
      witness.authorization.current.policyRoot.getD limb.val 0 := by
  rw [typed_policy_call_final_word statement witness valid,
    ← (typed_non_single_policy_binding statement witness valid nonsingle).1]

theorem typed_non_single_policy_final_nonzero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) :
    NonzeroWords ((stateWords (scheduledFinal statement witness 97)).take 7) := by
  rw [typed_non_single_policy_final_is_current statement witness valid nonsingle]
  exact (typed_non_single_policy_binding statement witness valid nonsingle).2

end HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments

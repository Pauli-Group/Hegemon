import HegemonCrypto.SmallWoodV8Smz9SourceAuthInitialFrames
import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootInputs
import HegemonCrypto.SmallWoodV8Smz9SourceReplicateReadback

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (rawIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem typed_source_policy_word_is_current (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    authPolicyWord witness.authorization (computedAuthFinals (typedLiveInitialStates statement witness)) limb.val =
      witness.authorization.current.policyRoot.getD limb.val 0 := by
  by_cases single : witness.authorization.mode = .singleKey
  · rw [authPolicyWord,if_pos single]
    exact (zero_words_readback _ (single_zero_openings statement witness valid single).1.2.1 limb.val).symm
  · rw [authPolicyWord,if_neg single,auth_hash_word_readback _ ⟨97,by decide⟩ limb]
    exact typed_non_single_policy_call_is_current statement witness valid single limb

def accumulatorInitialRawRow (which word : Nat) : Nat :=
  if which = 0 then 138 + word else nextOpeningRawRow word

theorem accumulator_initial_raw_row_bound (which : Fin 2) (word : Fin 23) :
    accumulatorInitialRawRow which.val word.val < 247 := by
  unfold accumulatorInitialRawRow nextOpeningRawRow
  split_ifs <;> omega

theorem auth_accumulator_source_word (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals)
    (policyBinding : ∀ limb : Fin 7, authPolicyWord witness.authorization hashes limb.val =
      witness.authorization.current.policyRoot.getD limb.val 0) (which : Fin 2) (word : Fin 23) :
    sourceAuthRow statement witness hashes (accumulatorInitialRawRow which.val word.val - 92) =
      (sourceAccumulatorWords (sourceAccumulatorOpening witness which.val)).getD word.val 0 := by
  fin_cases which <;> fin_cases word
  · exact policyBinding ⟨0,by decide⟩
  · exact policyBinding ⟨1,by decide⟩
  · exact policyBinding ⟨2,by decide⟩
  · exact policyBinding ⟨3,by decide⟩
  · exact policyBinding ⟨4,by decide⟩
  · exact policyBinding ⟨5,by decide⟩
  · exact policyBinding ⟨6,by decide⟩
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · exact policyBinding ⟨0,by decide⟩
  · exact policyBinding ⟨1,by decide⟩
  · exact policyBinding ⟨2,by decide⟩
  · exact policyBinding ⟨3,by decide⟩
  · exact policyBinding ⟨4,by decide⟩
  · exact policyBinding ⟨5,by decide⟩
  · exact policyBinding ⟨6,by decide⟩
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl

theorem auth_value_lock_source_word (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals)
    (policyBinding : ∀ limb : Fin 7, authPolicyWord witness.authorization hashes limb.val =
      witness.authorization.current.policyRoot.getD limb.val 0) (word : Fin 14) :
    sourceAuthRow statement witness hashes (138 + word.val - 92) =
      (sourceValueLockWords witness.authorization.current).getD word.val 0 := by
  fin_cases word
  · exact policyBinding ⟨0,by decide⟩
  · exact policyBinding ⟨1,by decide⟩
  · exact policyBinding ⟨2,by decide⟩
  · exact policyBinding ⟨3,by decide⟩
  · exact policyBinding ⟨4,by decide⟩
  · exact policyBinding ⟨5,by decide⟩
  · exact policyBinding ⟨6,by decide⟩
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl

theorem constructed_accumulator_source_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (word : Fin 23) :
    constructedRawWord statement witness (typedLiveInitialStates statement witness)
      (accumulatorInitialRawRow which.val word.val) =
      (sourceAccumulatorWords (sourceAccumulatorOpening witness which.val)).getD word.val 0 := by
  have lower : ¬ accumulatorInitialRawRow which.val word.val < 92 := by
    unfold accumulatorInitialRawRow nextOpeningRawRow
    split_ifs <;> omega
  rw [constructedRawWord,if_neg lower]
  exact auth_accumulator_source_word statement witness _
    (typed_source_policy_word_is_current statement witness valid) which word

theorem constructed_value_lock_source_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (word : Fin 14) :
    constructedRawWord statement witness (typedLiveInitialStates statement witness) (138 + word.val) =
      (sourceValueLockWords witness.authorization.current).getD word.val 0 := by
  rw [constructedRawWord,if_neg (show ¬ 138 + word.val < 92 by omega)]
  exact auth_value_lock_source_word statement witness _
    (typed_source_policy_word_is_current statement witness valid) word

theorem full_candidate_all_raw_word (statement : V8PublicStatement) (witness : V8Witness) (row : Fin 247) :
    (fullTypedSourceCandidate statement witness).getD (rawIndex row.val) 0 =
      constructedRawWord statement witness (typedLiveInitialStates statement witness) row.val := by
  simp only [rawIndex,Poseidon2V8DecoderRefinement.rawRowStart,
    Poseidon2V8DecoderRefinement.packingFactor,Nat.zero_add]
  change (constructedAssignment statement witness (typedLiveInitialStates statement witness)
    (typedSourceTail statement witness)).getD (row.val * 64 + 0) 0 = _
  rw [constructed_all_raw_rows_readback statement witness _ _ row ⟨0,by decide⟩]

theorem full_candidate_accumulator_source_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (word : Fin 23) :
    ((fullTypedSourceCandidate statement witness).getD (rawIndex (accumulatorInitialRawRow which.val word.val)) 0 : F) =
      ((sourceAccumulatorWords (sourceAccumulatorOpening witness which.val)).getD word.val 0 : F) := by
  rw [full_candidate_all_raw_word statement witness ⟨_,accumulator_initial_raw_row_bound which word⟩,
    constructed_accumulator_source_word statement witness valid which word]

theorem full_candidate_value_lock_source_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (word : Fin 14) :
    ((fullTypedSourceCandidate statement witness).getD (rawIndex (138 + word.val)) 0 : F) =
      ((sourceValueLockWords witness.authorization.current).getD word.val 0 : F) := by
  rw [full_candidate_all_raw_word statement witness ⟨138 + word.val,by omega⟩,
    constructed_value_lock_source_word statement witness valid word]

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128

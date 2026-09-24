import HegemonCrypto.SmallWoodV8Smz9SourceAuthorizationDigests
import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9AccumulatorSource
import HegemonCrypto.SmallWoodV8Smz9ValueLockSource

/-! Source-preparation fields for authorization sponges with short final blocks.
The 23-word and 14-word lengths remain exact, including final padding. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9AccumulatorSource
open HegemonCrypto.SmallWood.V8Smz9ValueLockSource
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def sourceAccumulatorOpening (witness : V8Witness) (which : Nat) : V8AccumulatorOpening :=
  if which = 0 then witness.authorization.current else effectiveNext witness.authorization

def authInitialPrior (statement : V8PublicStatement) (witness : V8Witness) (start block : Nat) : State :=
  if block = 0 then zeroState else scheduledFinal statement witness (start + block - 1)

theorem actual_accumulator_preparation (statement : V8PublicStatement) (witness : V8Witness)
    (which : Fin 2) (block : Fin 3) :
    actualSourceFrame statement witness ⟨98 + 3 * which.val + block.val,by omega⟩ =
      spongePreparedWords 6 (sourceAccumulatorWords (sourceAccumulatorOpening witness which.val)) 3
        (stateWords (authInitialPrior statement witness (98 + 3 * which.val) block.val)) block.val := by
  fin_cases which <;> fin_cases block <;> rfl

theorem actual_value_lock_preparation (statement : V8PublicStatement) (witness : V8Witness)
    (block : Fin 2) :
    actualSourceFrame statement witness ⟨104 + block.val,by omega⟩ =
      spongePreparedWords 8 (sourceValueLockWords witness.authorization.current) 2
        (stateWords (authInitialPrior statement witness 104 block.val)) block.val := by
  fin_cases block <;> rfl

theorem accumulator_preparation_field (inputs : List Nat) (shape : inputs.length = 23)
    (block : Fin 3) (previous : State) (firstZero : block.val = 0 → previous = zeroState)
    (lane : Fin 16) :
    ((spongePreparedWords 6 inputs 3 (stateWords previous) block.val).getD lane.val 0 : F) =
      ((stateWords previous).getD lane.val 0 : F) +
        (if lane.val < 8 ∧ block.val * 8 + lane.val < 23 then
          (inputs.getD (block.val * 8 + lane.val) 0 : F)
         else (accumulatorFrameConstant block.val lane.val : F)) := by
  fin_cases block
  · have zero := firstZero rfl
    subst previous
    fin_cases lane <;> simp [spongePreparedWords,poseidon2V8SeedFirstBlock,stateWords,zeroState,word,
      shape,Poseidon2Width16Kernel.rate,Poseidon2Width16Kernel.width,List.range_succ,accumulatorFrameConstant]
  all_goals fin_cases lane <;> simp [spongePreparedWords,stateWords,
    shape,Poseidon2Width16Kernel.rate,List.range_succ,accumulatorFrameConstant]

theorem value_lock_preparation_field (inputs : List Nat) (shape : inputs.length = 14)
    (block : Fin 2) (previous : State) (firstZero : block.val = 0 → previous = zeroState)
    (lane : Fin 16) :
    ((spongePreparedWords 8 inputs 2 (stateWords previous) block.val).getD lane.val 0 : F) =
      ((stateWords previous).getD lane.val 0 : F) +
        (if lane.val < 8 ∧ block.val * 8 + lane.val < 14 then
          (inputs.getD (block.val * 8 + lane.val) 0 : F)
         else (valueLockFrameConstant block.val lane.val : F)) := by
  fin_cases block
  · have zero := firstZero rfl
    subst previous
    fin_cases lane <;> simp [spongePreparedWords,poseidon2V8SeedFirstBlock,stateWords,zeroState,word,
      shape,Poseidon2Width16Kernel.rate,Poseidon2Width16Kernel.width,List.range_succ,valueLockFrameConstant]
  all_goals fin_cases lane <;> simp [spongePreparedWords,stateWords,
    shape,Poseidon2Width16Kernel.rate,List.range_succ,valueLockFrameConstant]

theorem full_candidate_auth_prior_field (statement : V8PublicStatement) (witness : V8Witness)
    (start block : Nat) (bound : start + block - 1 < 125) (lane : Fin 16) :
    ((stateWords (authInitialPrior statement witness start block)).getD lane.val 0 : F) =
      if block = 0 then 0 else
        ((fullTypedSourceCandidate statement witness).getD
          (Poseidon2V8DecoderRefinement.hashFinalIndex (start + block - 1) lane.val) 0 : F) := by
  by_cases first : block = 0
  · fin_cases lane <;> simp [authInitialPrior,first,stateWords,zeroState,word]
  · rw [authInitialPrior,if_neg first,if_neg first,
      full_candidate_final_schedule_readback statement witness ⟨start + block - 1,bound⟩ lane]

theorem full_candidate_accumulator_initial_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (block : Fin 3) (lane : Fin 16) :
    ((fullTypedSourceCandidate statement witness).getD
      (Poseidon2V8DecoderRefinement.hashInitialIndex (98 + 3 * which.val + block.val) lane.val) 0 : F) =
      (if block.val = 0 then 0 else ((fullTypedSourceCandidate statement witness).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex (98 + 3 * which.val + block.val - 1) lane.val) 0 : F)) +
      (if lane.val < 8 ∧ block.val * 8 + lane.val < 23 then
        ((sourceAccumulatorWords (sourceAccumulatorOpening witness which.val)).getD (block.val * 8 + lane.val) 0 : F)
       else (accumulatorFrameConstant block.val lane.val : F)) := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨98 + 3 * which.val + block.val,by omega⟩ lane,
    actual_accumulator_preparation,
    accumulator_preparation_field _ (accumulator_words_length _) block _
      (fun first => by simp only [authInitialPrior,if_pos first]) lane,
    full_candidate_auth_prior_field statement witness _ _ (by omega) lane]

theorem full_candidate_value_lock_initial_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (block : Fin 2) (lane : Fin 16) :
    ((fullTypedSourceCandidate statement witness).getD
      (Poseidon2V8DecoderRefinement.hashInitialIndex (104 + block.val) lane.val) 0 : F) =
      (if block.val = 0 then 0 else ((fullTypedSourceCandidate statement witness).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex (104 + block.val - 1) lane.val) 0 : F)) +
      (if lane.val < 8 ∧ block.val * 8 + lane.val < 14 then
        ((sourceValueLockWords witness.authorization.current).getD (block.val * 8 + lane.val) 0 : F)
       else (valueLockFrameConstant block.val lane.val : F)) := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨104 + block.val,by omega⟩ lane,
    actual_value_lock_preparation,
    value_lock_preparation_field _ (value_lock_words_length _) block _
      (fun first => by simp only [authInitialPrior,if_pos first]) lane,
    full_candidate_auth_prior_field statement witness _ _ (by omega) lane]

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthInitial128

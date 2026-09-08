import HegemonCrypto.SmallWoodV8Smz9SourcePrfFrames
import HegemonCrypto.SmallWoodV8Smz9NullifierSource
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceNullifierFrames
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9NullifierSource
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def actualNullifierSourceWords (statement : V8PublicStatement) (witness : V8Witness) (input : Nat) : List Nat :=
  sourceNullifierWords statement witness (wordAtState (scheduledFinal statement witness 0) 0) input

theorem actual_nullifier_preparation (statement : V8PublicStatement) (witness : V8Witness) (input : Fin 2) :
    actualSourceFrame statement witness ⟨nullifierCall input.val,by unfold nullifierCall; omega⟩ =
      spongePreparedWords 2 (actualNullifierSourceWords statement witness input.val) 1 (stateWords zeroState) 0 := by
  fin_cases input <;> rfl

theorem nullifier_preparation_field (inputs : List Nat) (shape : inputs.length = 6) (lane : Fin 16) :
    ((spongePreparedWords 2 inputs 1 (stateWords zeroState) 0).getD lane.val 0 : F) =
      if lane.val < 6 then (inputs.getD lane.val 0 : F) else (nullifierFrameConstant lane.val : F) := by
  fin_cases lane <;> simp [spongePreparedWords,poseidon2V8SeedFirstBlock,stateWords,zeroState,word,
    shape,Poseidon2Width16Kernel.rate,Poseidon2Width16Kernel.width,List.range_succ,nullifierFrameConstant]

theorem full_candidate_nullifier_initial_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (lane : Fin 16) :
    ((fullTypedSourceCandidate statement witness).getD (hashInitialIndex (nullifierCall input.val) lane.val) 0 : F) =
      if lane.val < 6 then ((actualNullifierSourceWords statement witness input.val).getD lane.val 0 : F)
      else (nullifierFrameConstant lane.val : F) := by
  rw [full_candidate_initial_source_readback statement witness valid
    ⟨nullifierCall input.val,by unfold nullifierCall; omega⟩ lane,actual_nullifier_preparation]
  exact nullifier_preparation_field _ (nullifier_words_length _ _ _ _) lane

theorem actual_nullifier_frame_coefficient (pub : Nat → F) (lane : Fin 16) :
    actualCsrCoefficients pub (nullifierFrameTarget lane.val) = (nullifierFrameConstant lane.val : F) :=
  actual_csr_node_field_equation pub (exact_nullifier_frame_nodes lane)

theorem full_candidate_nullifier_frame_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F)
    (input : Fin 2) (lane : Fin 16) (padding : 6 ≤ lane.val) :
    actualCsrResidual pub (fullTypedSourceCandidate statement witness) (nullifierFrameAttempt input.val lane.val) = 0 := by
  simp only [nullifierFrameAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one pub).2,
    one_mul,add_zero,actual_nullifier_frame_coefficient]
  rw [full_candidate_nullifier_initial_field statement witness valid input lane,if_neg (by omega),sub_self]

theorem nullifier_frame_exact_lookup (input : Fin 2) (lane : Fin 16) (padding : 6 ≤ lane.val) :
    exactCsrAttempts[18300 + 16 * input.val + lane.val]? = some (nullifierFrameAttempt input.val lane.val) :=
  exact_attempt_lookup _ (exact_nullifier_frame_attempts input lane padding)

def nullifierFrame20Index (index : Nat) : Nat := 18306 + 16 * (index / 10) + index % 10

theorem nullifier_frame20_distinct_count :
    ((List.range 20).map nullifierFrame20Index).length = 20 ∧
      ((List.range 20).map nullifierFrame20Index).Nodup := by decide

theorem full_candidate_actual_nullifier_frame20_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (index : Fin 20) :
    (exactCsrAttempts[nullifierFrame20Index index.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  have address : nullifierFrame20Index index.val = 18300 + 16 * (index.val / 10) + (6 + index.val % 10) := by
    unfold nullifierFrame20Index
    omega
  have padding : 6 ≤ 6 + index.val % 10 := by omega
  rw [address,nullifier_frame_exact_lookup ⟨index.val / 10,by omega⟩ ⟨6 + index.val % 10,by omega⟩ padding,
    Option.map_some,full_candidate_nullifier_frame_zero statement witness valid pub _ _ padding]

end
end HegemonCrypto.SmallWood.V8Smz9SourceNullifierFrames

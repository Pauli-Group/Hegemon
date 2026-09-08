import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointPrf
import Mathlib.Tactic.FinCases

namespace HegemonCrypto.SmallWood.V8Smz9SourcePrfInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrf
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

theorem actual_prf_source_frame (statement : V8PublicStatement) (witness : V8Witness) :
    actualSourceFrame statement witness ⟨0, by decide⟩ =
      spongePreparedWords 2 (globalSpendKey statement witness) 1 (stateWords zeroState) 0 := rfl

noncomputable section

theorem prf_preparation_field (inputs : List Nat) (shape : inputs.length = 4) (lane : Fin 16) :
    ((spongePreparedWords 2 inputs 1 (stateWords zeroState) 0).getD lane.val 0 : F) =
      if lane.val < 4 then (inputs.getD lane.val 0 : F) else (prfFrameConstant lane.val : F) := by
  have words : inputs = [inputs.getD 0 0, inputs.getD 1 0, inputs.getD 2 0, inputs.getD 3 0] :=
    (range_getD inputs 4 shape).symm
  rw [words]
  fin_cases lane <;>
    simp [spongePreparedWords, poseidon2V8SeedFirstBlock, stateWords, zeroState, word,
      Poseidon2Width16Kernel.rate, Poseidon2Width16Kernel.width, List.range_succ, prfFrameConstant]

theorem full_candidate_prf_initial_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 16) :
    ((fullTypedSourceCandidate statement witness).getD
      (Poseidon2V8DecoderRefinement.hashInitialIndex 0 lane.val) 0 : F) =
      if lane.val < 4 then ((globalSpendKey statement witness).getD lane.val 0 : F)
      else (prfFrameConstant lane.val : F) := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨0, by decide⟩ lane,
    actual_prf_source_frame]
  exact prf_preparation_field _ (global_spend_key_length statement witness) lane

end
end HegemonCrypto.SmallWood.V8Smz9SourcePrfInitial

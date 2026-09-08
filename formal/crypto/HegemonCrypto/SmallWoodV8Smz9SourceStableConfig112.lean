import HegemonCrypto.SmallWoodV8Smz9SourceStableChunk64

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableConfig112
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableNode48
open HegemonCrypto.SmallWood.V8Smz9SourceStableChunk64
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem stable_config112_distinct_count : ((List.range 112).map (19860+·)).length = 112 ∧
    ((List.range 112).map (19860+·)).Nodup := by decide

theorem full_candidate_actual_config112_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pub : Nat → F) (index : Fin 112) :
    (exactCsrAttempts[19860+index.val]?).map
      (actualCsrResidual pub (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases chunk : index.val<64
  · exact full_candidate_actual_chunk64_zero statement witness valid pub ⟨index.val,chunk⟩
  · have address : 19860+index.val=19924+(index.val-64) := by omega
    rw [address]
    exact full_candidate_actual_node48_zero statement witness valid pub ⟨index.val-64,by omega⟩

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableConfig112

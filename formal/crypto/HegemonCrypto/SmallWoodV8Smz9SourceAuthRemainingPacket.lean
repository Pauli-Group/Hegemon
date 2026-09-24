import HegemonCrypto.SmallWoodV8Smz9SourceAuthMoreClosure
import HegemonCrypto.SmallWoodV8Smz9SourceAuthArithmeticClosure

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingPacket
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMoreClosure
open HegemonCrypto.SmallWood.V8Smz9SourceAuthArithmeticClosure
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def selectedPacketRoot (index : Fin 100) : Nat :=
  if early : index.val < 46 then selectedRemainingRoot ⟨index.val,early⟩
  else if middle : index.val < 88 then selectedMoreRoot ⟨index.val-46,by omega⟩
  else selectedArithmeticRoot ⟨index.val-88,by omega⟩

noncomputable section
theorem full_candidate_actual_100_remaining_auth_roots_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) (index : Fin 100) :
    (exactNonlinearRoots[selectedPacketRoot index]?).map
      (fieldAt exactNonlinearExpressions (fun i => ((encodePublicStatement statement).getD i 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  by_cases early : index.val < 46
  · simp only [selectedPacketRoot,dif_pos early]
    exact full_candidate_actual_46_remaining_auth_roots_zero statement witness valid lane ⟨index.val,early⟩
  · by_cases middle : index.val < 88
    · simp only [selectedPacketRoot,dif_neg early,dif_pos middle]
      exact full_candidate_actual_42_more_auth_roots_zero statement witness valid lane ⟨index.val-46,by omega⟩
    · simp only [selectedPacketRoot,dif_neg early,dif_neg middle]
      exact full_candidate_actual_12_arithmetic_auth_roots_zero statement witness valid lane ⟨index.val-88,by omega⟩
end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingPacket

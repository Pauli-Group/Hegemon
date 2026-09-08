import HegemonCrypto.SmallWoodV8Smz9SourcePublicMerkle14
import HegemonCrypto.SmallWoodV8Smz9SourcePublicNullifier14
import HegemonCrypto.SmallWoodV8Smz9SourceOutputCommitment14

namespace HegemonCrypto.SmallWood.V8Smz9SourcePublicDigest42
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourcePublicMerkle14
open HegemonCrypto.SmallWood.V8Smz9SourcePublicNullifier14
open HegemonCrypto.SmallWood.V8Smz9SourceOutputCommitment14
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def publicDigest42Index (index : Nat) : Nat :=
  if index < 14 then 18286 + index
  else if index < 28 then 18332 + (index - 14)
  else 18454 + (index - 28)

theorem public_digest42_distinct_count :
    ((List.range 42).map publicDigest42Index).length = 42 ∧
      ((List.range 42).map publicDigest42Index).Nodup := by decide

theorem full_candidate_actual_public_digest42_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 42) :
    (exactCsrAttempts[publicDigest42Index index.val]?).map
      (actualCsrResidual (fun slot => ((encodePublicStatement statement).getD slot 0 : F))
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases root : index.val < 14
  · rw [publicDigest42Index,if_pos root]
    exact full_candidate_actual_public_merkle14_zero statement witness valid ⟨index.val,root⟩
  by_cases nullifier : index.val < 28
  · rw [publicDigest42Index,if_neg root,if_pos nullifier]
    exact full_candidate_actual_public_nullifier14_zero statement witness valid ⟨index.val - 14,by omega⟩
  · rw [publicDigest42Index,if_neg root,if_neg nullifier]
    exact full_candidate_actual_output_commitment14_zero statement witness valid ⟨index.val - 28,by omega⟩

end
end HegemonCrypto.SmallWood.V8Smz9SourcePublicDigest42

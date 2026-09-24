import HegemonCrypto.SmallWoodV8Smz9RelationProgramComponentsGenerated

namespace HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 200000

/-- Source row-major loop: row0..246, lane1..63, one attempt per pair. -/
def expectedReplicateAttempt (index : Nat) : CsrExecutableAttempt :=
  attempt index 0 index 0
    [((index / 63) * 64 + (index % 63 + 1), 1), ((index / 63) * 64, 3)] 0

def replicateChunk (start count : Nat) : Prop :=
  (exactCsrAttempts.drop start).take count =
    (List.range count).map (fun localIndex => expectedReplicateAttempt (start+localIndex))

instance (start count : Nat) : Decidable (replicateChunk start count) := by
  unfold replicateChunk
  infer_instance

/-- The actual coefficient is the canonical p-1 constant, not a guessed DAG subtraction. -/
theorem exact_replicate_negative_one_node :
    exactCsrExpressions[3]? = some (.constant 18446744069414584320) := by decide

theorem replicate_geometry_count : 247 * 63 = 15561 := by decide

end HegemonCrypto.SmallWood.V8Smz9SourceReplicateCsr

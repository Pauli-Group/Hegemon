import Hegemon.Transaction.Poseidon2V8SemanticSpecification

namespace HegemonCrypto.SmallWood.V8Smz9NullifierSponge

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option maxHeartbeats 1000000
set_option maxRecDepth 100000

def nullifierFrame (inputs : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 6 then Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0)
    else if lane = 8 then 2
    else if lane = 9 then 6
    else if lane = 10 then poseidon2V8SpongeModeMarker
    else if lane = 11 then 1
    else if lane = 15 then poseidon2V8SuiteMarker
    else 0

/-- Exact six-word source sponge, including unused rate lanes6/7 and final marker11. -/
theorem nullifier_sponge_one_frame (inputs : List Nat) (length : inputs.length = 6) :
    poseidon2V8Sponge poseidon2V8NullifierDomain inputs =
      (Poseidon2Width16Kernel.permutation (nullifierFrame inputs)).take digestWords := by
  simp [poseidon2V8Sponge, poseidon2V8AbsorbBlock, poseidon2V8InitialState,
    poseidon2V8SeedFirstBlock, poseidon2V8NullifierDomain, Poseidon2Width16Kernel.width,
    Poseidon2Width16Kernel.rate, length, nullifierFrame, List.range_succ,
    List.replicate_succ, List.getD, Poseidon2Width16Kernel.fieldAdd,
    Poseidon2Width16Kernel.fieldModulus, NoteCommitmentInputs.fieldModulus]

end HegemonCrypto.SmallWood.V8Smz9NullifierSponge

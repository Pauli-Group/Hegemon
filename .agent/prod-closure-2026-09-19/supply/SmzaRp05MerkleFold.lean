import SmzaRp05MerkleFrameCertificate

/-!
# Generic current-call Merkle fold (source-only)

This single induction composes the 32 accepted call steps for either input.
Its local step interface is supplied later by checked frame/orientation data
and a current-call final-digest theorem.  The latter may come from the
existing `KernelCertificate` or a finite paired-DAG refinement; this fold
does not commit to either provider and does not assert accepted root equality
without those local lemmas.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05MerkleFold

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge

set_option autoImplicit false

def noteFinalCall (input : Fin 2) : Nat :=
  if input.val = 0 then 3 else 40

def merkleCall (input : Fin 2) (level : Nat) : Nat :=
  if input.val = 0 then 4 + level else 41 + level

def boundaryCall (input : Fin 2) (count : Nat) : Nat :=
  if count = 0 then noteFinalCall input else merkleCall input (count - 1)

def callDigest (packed : List Nat) (call : Nat) : Digest :=
  (packedFinalState packed call).take digestWords

def foldStep (position : Nat) (siblings : List Digest)
    (level : Nat) (current : Digest) : Digest :=
  let sibling := siblings.getD level []
  if (position / 2 ^ level) % 2 = 0 then
    poseidon2V8Compress14 poseidon2V8MerkleDomain current sibling
  else
    poseidon2V8Compress14 poseidon2V8MerkleDomain sibling current

/-- Local call equation at one step.  The downstream source theorem must
derive this from RP05 accepted rows, exact CSR frame copies, the nonlinear
orientation gate and a current-call kernel certificate. -/
def CallStepCorrect (packed : List Nat) (input : Fin 2)
    (position : Nat) (siblings : List Digest) : Prop :=
  ∀ level, level < 32 →
    callDigest packed (merkleCall input level) =
      foldStep position siblings level
        (callDigest packed (boundaryCall input level))

theorem accepted_call_prefix_fold
    (packed : List Nat) (input : Fin 2)
    (position : Nat) (siblings : List Digest)
    (stepCorrect : CallStepCorrect packed input position siblings)
    (count : Nat) (countBound : count ≤ 32) :
    (List.range count).foldl
        (fun current level => foldStep position siblings level current)
        (callDigest packed (noteFinalCall input)) =
      callDigest packed (boundaryCall input count) := by
  induction count with
  | zero => simp [boundaryCall]
  | succ count ih =>
      have lower : count < 32 := by omega
      rw [List.range_succ, List.foldl_append]
      simp only [List.foldl_cons, List.foldl_nil]
      rw [ih (by omega)]
      simpa [boundaryCall] using (stepCorrect count lower).symm

/-- Once the source note-call digest and all 32 local Merkle calls are
certified, the exact typed Merkle root is the final current call digest. -/
theorem note_and_steps_give_final_root
    (packed : List Nat) (input : Fin 2)
    (opening : V8NoteOpening) (position : Nat) (siblings : List Digest)
    (noteDigest : exactV8NoteCommitment opening =
      callDigest packed (noteFinalCall input))
    (stepCorrect : CallStepCorrect packed input position siblings) :
    exactV8MerkleRoot (exactV8NoteCommitment opening) position siblings =
      callDigest packed (merkleCall input 31) := by
  unfold exactV8MerkleRoot
  rw [noteDigest]
  change (List.range merkleDepth).foldl
      (fun current level => foldStep position siblings level current)
      (callDigest packed (noteFinalCall input)) = _
  have folded := accepted_call_prefix_fold packed input position siblings
    stepCorrect 32 (by decide)
  simpa [merkleDepth, boundaryCall] using folded

end HegemonCrypto.SmallWood.SmzaRp05MerkleFold

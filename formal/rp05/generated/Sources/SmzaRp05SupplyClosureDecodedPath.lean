import SmzaRp05SupplyClosureAcceptedMerkle
import SmzaRp05LedgerMerkleBinding

/-! Construct the root-first path consumed by the historical binding
comparator directly from the existing packed decoder's position and siblings.
The accepted-root equation is derived; no path/root readback premise remains. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDecodedPath

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05LedgerMerkleBinding
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureAcceptedMerkle
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open HegemonCrypto.SmallWood.SmzaRp05MerkleFold
open HegemonCrypto.SmallWood.MerkleExtraction
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder

set_option autoImplicit false

def decodedPath (position : Nat) (siblings : List Digest) :
    Nat → AuthenticationPath Digest
  | 0 => []
  | count + 1 =>
      { sibling := siblings.getD count []
        childSide := if (position / 2 ^ count) % 2 = 0 then .left else .right } ::
        decodedPath position siblings count

theorem decoded_path_length (position : Nat) (siblings : List Digest)
    (count : Nat) : (decodedPath position siblings count).length = count := by
  induction count with
  | zero => rfl
  | succ count ih => simp only [decodedPath, List.length_cons, ih]

theorem decoded_path_root_fold (opening : V8NoteOpening) (position : Nat)
    (siblings : List Digest) (count : Nat) :
    rootFromPath rp05PathHash (exactV8NoteWords opening)
      (decodedPath position siblings count) =
    (List.range count).foldl
      (fun current level => foldStep position siblings level current)
      (exactV8NoteCommitment opening) := by
  induction count with
  | zero => rfl
  | succ count ih =>
      simp only [decodedPath, rootFromPath, List.range_succ,
        List.foldl_append, List.foldl_cons, List.foldl_nil]
      rw [ih]
      unfold foldStep
      split_ifs <;> rfl

theorem decoded_path_root (opening : V8NoteOpening) (position : Nat)
    (siblings : List Digest) :
    rootFromPath rp05PathHash (exactV8NoteWords opening)
      (decodedPath position siblings merkleDepth) =
    exactV8MerkleRoot (exactV8NoteCommitment opening) position siblings :=
  decoded_path_root_fold opening position siblings merkleDepth

theorem current_active_input_opens_public_anchor
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2)
    (active : publicWords.getD input.val 0 = 1) :
    let path := decodedPath (projectPosition packed input.val)
      (SmzaRp05BalanceCore.projectInput statement packed input.val).siblings merkleDepth
    OpensAt rp05PathHash
      ((List.range 7).map fun limb => publicWords.getD (47 + limb) 0)
      (pathSides path)
      (exactV8NoteWords (projectNote packed (noteCall input))) path := by
  refine ⟨rfl, ?_⟩
  rw [decoded_path_root]
  exact current_active_input_merkle_root accepted statement input active

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDecodedPath

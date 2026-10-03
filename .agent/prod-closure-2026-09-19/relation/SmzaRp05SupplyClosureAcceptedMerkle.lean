import SmzaRp05SupplyClosureHashCalls
import SmzaRp05NoteSpongeBridge
import SmzaRp05NoteFrameInstance
import SmzaRp05MerkleFrameInstance
import SmzaRp05CurrentNullifierCertificates

/-! Connect the existing current note, orientation, Merkle-frame and public
root certificates through the current program's nonlinear hash recurrence.
This gives the exact accepted active-input root equation; historical native
anchor provenance and registry construction remain separate obligations. -/

namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureAcceptedMerkle

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHashCalls
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open HegemonCrypto.SmallWood.SmzaRp05NoteSpongeBridge
open HegemonCrypto.SmallWood.SmzaRp05MerkleFold
open HegemonCrypto.SmallWood.SmzaRp05MerkleCallStep
open HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem current_final_state_correct {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) :
    FinalStateCorrect packed := by
  intro call bound
  exact current_hash_call_state accepted bound

theorem current_final_call_correct {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) :
    FinalCallCorrect packed := by
  intro call bound
  exact congrArg (List.take digestWords) (current_hash_call_state accepted bound).symm

theorem current_note_digest {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (input : Fin 2) :
    exactV8NoteCommitment (projectNote packed (noteCall input)) =
      callDigest packed (noteFinalCall input) := by
  have note := accepted_note_digest_eq_exact_commitment
    SmzaRp05NoteFrameInstance.certificate accepted
    (current_final_state_correct accepted) input
  have callEq : noteCall input + 2 = noteFinalCall input := by
    fin_cases input <;> rfl
  rw [callEq] at note
  exact note.symm

theorem current_active_input_merkle_root {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2)
    (active : publicWords.getD input.val 0 = 1) :
    exactV8MerkleRoot
      (exactV8NoteCommitment (projectNote packed (noteCall input)))
      (projectPosition packed input.val)
      (SmzaRp05BalanceCore.projectInput statement packed input.val).siblings =
        (List.range 7).map (fun limb => publicWords.getD (47 + limb) 0) := by
  have steps := accepted_all_call_steps
    SmzaRp05MerkleFrameInstance.certificate
    SmzaRp05MerkleFrameInstance.orientationCertificate
    SmzaRp05CurrentNullifierCertificates.directionCertificate
    accepted (current_final_call_correct accepted) statement input
  have folded := note_and_steps_give_final_root packed input
    (projectNote packed (noteCall input)) (projectPosition packed input.val)
    (SmzaRp05BalanceCore.projectInput statement packed input.val).siblings
    (current_note_digest accepted input) steps
  rw [folded]
  apply List.ext_getElem
  · simp [callDigest, packedFinalState, digestWords]
  · intro limb leftBound rightBound
    have limbBound : limb < 7 := by simpa using rightBound
    have word := accepted_active_public_merkle_word
      SmzaRp05MerkleFrameInstance.publicRootCertificate
      accepted input ⟨limb, limbBound⟩ active
    have callEq : currentMerkleCall input ⟨31, by decide⟩ =
        merkleCall input 31 := rfl
    rw [callEq] at word
    simpa [callDigest, packedFinalState, packedWord, digestWords,
      List.getElem_map, List.getElem_range] using word

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureAcceptedMerkle

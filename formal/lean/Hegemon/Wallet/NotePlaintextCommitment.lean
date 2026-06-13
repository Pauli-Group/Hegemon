import Hegemon.Transaction.SpendAuthorization
import Hegemon.Wallet.NoteCiphertextDecrypt

namespace Hegemon
namespace Wallet
namespace NotePlaintextCommitment

open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SpendAuthorization
open Hegemon.Wallet.NoteCiphertextDecrypt

structure NotePlaintextSummary where
  value : Nat
  assetId : Nat
  rho : Nat
  noteRandomness : Nat
deriving DecidableEq, Repr

structure WalletRecipientMaterial where
  recipientKey : Digest
  authorizationPublicKey : Digest
deriving DecidableEq, Repr

structure ExportedNoteData where
  value : Nat
  assetId : Nat
  recipientKey : Digest
  authorizationPublicKey : Digest
  rho : Nat
  noteRandomness : Nat
deriving DecidableEq, Repr

def exportNoteData
    (plaintext : NotePlaintextSummary)
    (material : WalletRecipientMaterial) : ExportedNoteData :=
  {
    value := plaintext.value,
    assetId := plaintext.assetId,
    recipientKey := material.recipientKey,
    authorizationPublicKey := material.authorizationPublicKey,
    rho := plaintext.rho,
    noteRandomness := plaintext.noteRandomness
  }

def noteDataAsInputWitness (data : ExportedNoteData) : InputSpendWitness :=
  {
    value := data.value,
    assetId := data.assetId,
    recipientKey := data.recipientKey,
    authorizationPublicKey := data.authorizationPublicKey,
    spendSecret := 0,
    rho := data.rho,
    noteRandomness := data.noteRandomness,
    notePosition := 0,
    noteCommitment := 0,
    merkleDepth := 0,
    merkleSiblings := []
  }

def commitmentFromNoteData (data : ExportedNoteData) : Digest :=
  noteCommitmentFromWitness (noteDataAsInputWitness data)

def commitmentFromPlaintext
    (plaintext : NotePlaintextSummary)
    (material : WalletRecipientMaterial) : Digest :=
  commitmentFromNoteData (exportNoteData plaintext material)

def inputWitnessFromRecovered
    (data : ExportedNoteData)
    (spendSecret notePosition merkleDepth : Nat)
    (merkleSiblings : List Digest) : InputSpendWitness :=
  {
    value := data.value,
    assetId := data.assetId,
    recipientKey := data.recipientKey,
    authorizationPublicKey := data.authorizationPublicKey,
    spendSecret,
    rho := data.rho,
    noteRandomness := data.noteRandomness,
    notePosition,
    noteCommitment := commitmentFromNoteData data,
    merkleDepth,
    merkleSiblings
  }

theorem exported_note_data_replays_plaintext_and_material_fields
    (plaintext : NotePlaintextSummary)
    (material : WalletRecipientMaterial) :
    let data := exportNoteData plaintext material
    data.value = plaintext.value
      ∧ data.assetId = plaintext.assetId
      ∧ data.recipientKey = material.recipientKey
      ∧ data.authorizationPublicKey = material.authorizationPublicKey
      ∧ data.rho = plaintext.rho
      ∧ data.noteRandomness = plaintext.noteRandomness := by
  simp [exportNoteData]

theorem exported_note_data_commitment_uses_spend_authorization_relation
    (plaintext : NotePlaintextSummary)
    (material : WalletRecipientMaterial) :
    commitmentFromPlaintext plaintext material =
      noteCommitmentFromWitness
        (noteDataAsInputWitness (exportNoteData plaintext material)) := by
  rfl

theorem exported_note_data_commitment_expands_to_field_formula
    (plaintext : NotePlaintextSummary)
    (material : WalletRecipientMaterial) :
    commitmentFromPlaintext plaintext material =
      (plaintext.value * 1315423911
        + plaintext.assetId * 2654435761
        + material.recipientKey * 97531
        + material.authorizationPublicKey * 314159
        + plaintext.rho * 271828
        + plaintext.noteRandomness * 65537
        + 97) % authDigestMod := by
  simp [
    commitmentFromPlaintext,
    commitmentFromNoteData,
    exportNoteData,
    noteDataAsInputWitness,
    noteCommitmentFromWitness
  ]

theorem input_witness_from_recovered_reconstructs_note_commitment
    (data : ExportedNoteData)
    (spendSecret notePosition merkleDepth : Nat)
    (merkleSiblings : List Digest) :
    noteCommitmentFromWitness
      (inputWitnessFromRecovered data spendSecret notePosition merkleDepth merkleSiblings) =
      (inputWitnessFromRecovered
        data spendSecret notePosition merkleDepth merkleSiblings).noteCommitment := by
  simp [
    inputWitnessFromRecovered,
    commitmentFromNoteData,
    noteDataAsInputWitness,
    noteCommitmentFromWitness
  ]

theorem input_witness_from_exported_plaintext_reconstructs_commitment
    (plaintext : NotePlaintextSummary)
    (material : WalletRecipientMaterial)
    (spendSecret notePosition merkleDepth : Nat)
    (merkleSiblings : List Digest) :
    noteCommitmentFromWitness
      (inputWitnessFromRecovered
        (exportNoteData plaintext material)
        spendSecret
        notePosition
        merkleDepth
        merkleSiblings) =
      commitmentFromPlaintext plaintext material := by
  simp [
    inputWitnessFromRecovered,
    commitmentFromPlaintext,
    commitmentFromNoteData,
    exportNoteData,
    noteDataAsInputWitness,
    noteCommitmentFromWitness
  ]

theorem decrypt_success_plaintext_to_commitment_boundary
    {attempt : DecryptAttempt}
    {plaintext : NotePlaintextSummary}
    {material : WalletRecipientMaterial}
    {data : ExportedNoteData}
    {publicCommitment : Digest}
    (accepted : evaluateDecrypt attempt = none)
    (exported : data = exportNoteData plaintext material)
    (published : publicCommitment = commitmentFromNoteData data) :
    attempt.ciphertext.version = attempt.material.version
      ∧ attempt.ciphertext.cryptoSuite = attempt.material.cryptoSuite
      ∧ attempt.ciphertext.diversifierIndex = attempt.material.diversifierIndex
      ∧ attempt.cryptoAuthenticates = true
      ∧ publicCommitment = commitmentFromPlaintext plaintext material := by
  have metadata := decrypt_success_implies_metadata_matches accepted
  have commitment :
      publicCommitment = commitmentFromPlaintext plaintext material := by
    calc
      publicCommitment = commitmentFromNoteData data := published
      _ = commitmentFromNoteData (exportNoteData plaintext material) := by
        rw [exported]
      _ = commitmentFromPlaintext plaintext material := rfl
  exact
    ⟨metadata.left,
      metadata.right.left,
      metadata.right.right.left,
      metadata.right.right.right,
      commitment⟩

theorem active_output_slot_commitment_matches_exported_plaintext
    {flags : List Nat}
    {commitments ciphertextHashes : List Digest}
    {index ciphertextHash : Nat}
    {plaintext : NotePlaintextSummary}
    {material : WalletRecipientMaterial}
    {publicCommitment : Digest}
    (slot :
      OutputSlotAt
        flags
        commitments
        ciphertextHashes
        index
        1
        publicCommitment
        ciphertextHash)
    (commitmentMatches :
      publicCommitment = commitmentFromPlaintext plaintext material) :
    commitments[index]? = some (commitmentFromPlaintext plaintext material) := by
  have indices := output_slot_at_get_indices slot
  simpa [commitmentMatches] using indices.right.left

end NotePlaintextCommitment
end Wallet
end Hegemon

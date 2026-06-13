import Hegemon.Native.BlockArtifactBindingAdmission
import Hegemon.Transaction.AssetIsolation
import Hegemon.Transaction.CanonicalVerifierBoundary

namespace Hegemon
namespace Native
namespace TxLeafCanonicalSurface

open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Transaction.AcceptedProofArtifact
open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.AssetIsolation
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

def TxLeafActionBindingFacts
    (input : TxLeafActionBindingInput) : Prop :=
  input.nullifiersMatch = true
    ∧ input.commitmentsMatch = true
    ∧ input.ciphertextHashesMatch = true
    ∧ input.inputCountMatches = true
    ∧ input.outputCountMatches = true
    ∧ input.versionMatches = true
    ∧ input.feeMatches = true
    ∧ input.stablecoinPayloadMatches = true
    ∧ input.balanceTagMatches = true
    ∧ input.receiptStatementHashMatches = true
    ∧ input.publicInputsDigestMatches = true
    ∧ input.proofDigestMatches = true
    ∧ input.proofBackendMatches = true
    ∧ input.ciphertextPayloadHashesMatch = true

theorem tx_leaf_action_accepts_implies_preconditions
    {input : TxLeafActionBindingInput}
    (accepted : txLeafActionBindingAccepts input = true) :
    txLeafActionBindingPreconditions input = true := by
  rw [← tx_leaf_action_accepts_iff_preconditions input]
  exact accepted

theorem tx_leaf_action_accepts_implies_binding_facts
    {input : TxLeafActionBindingInput}
    (accepted : txLeafActionBindingAccepts input = true) :
    TxLeafActionBindingFacts input := by
  have preconditions :=
    tx_leaf_action_accepts_implies_preconditions accepted
  cases input with
  | mk nullifiersMatch commitmentsMatch ciphertextHashesMatch
      inputCountMatches outputCountMatches versionMatches feeMatches
      stablecoinPayloadMatches balanceTagMatches receiptStatementHashMatches
      publicInputsDigestMatches proofDigestMatches proofBackendMatches
      ciphertextPayloadHashesMatch =>
      simp [
        TxLeafActionBindingFacts,
        txLeafActionBindingPreconditions
      ] at preconditions ⊢
      rcases preconditions with ⟨h0123456789012, h13⟩
      rcases h0123456789012 with ⟨h012345678901, h12⟩
      rcases h012345678901 with ⟨h01234567890, h11⟩
      rcases h01234567890 with ⟨h0123456789, h10⟩
      rcases h0123456789 with ⟨h012345678, h9⟩
      rcases h012345678 with ⟨h01234567, h8⟩
      rcases h01234567 with ⟨h0123456, h7⟩
      rcases h0123456 with ⟨h012345, h6⟩
      rcases h012345 with ⟨h01234, h5⟩
      rcases h01234 with ⟨h0123, h4⟩
      rcases h0123 with ⟨h012, h3⟩
      rcases h012 with ⟨h01, h2⟩
      rcases h01 with ⟨h0, h1⟩
      exact
        ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10,
          h11, h12, h13⟩

theorem native_tx_leaf_binding_and_canonical_surface_implies_transaction_relation
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (sound :
      DeployedTxVerifierSoundnessAssumption
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots
      ∧ txLeafActionBindingPreconditions input = true
      ∧ TxLeafActionBindingFacts input := by
  exact
    ⟨accepted_wrapper_and_canonical_statement_implies_transaction_relation
        surface
        sound,
      tx_leaf_action_accepts_implies_preconditions bindingAccepted,
      tx_leaf_action_accepts_implies_binding_facts bindingAccepted⟩

theorem native_tx_leaf_binding_and_canonical_surface_authorizes_asset_delta
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId : Nat}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (sound :
      DeployedTxVerifierSoundnessAssumption
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    AuthorizedAssetDelta balanceWitness slots assetId
      ∧ TxLeafActionBindingFacts input := by
  have relationFacts :=
    native_tx_leaf_binding_and_canonical_surface_implies_transaction_relation
      bindingAccepted
      surface
      sound
  exact
    ⟨accepted_transaction_relation_authorized_asset_delta
        relationFacts.left,
      relationFacts.right.right⟩

theorem native_tx_leaf_binding_and_canonical_surface_authorized_asset_delta_value
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId : Nat}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (sound :
      DeployedTxVerifierSoundnessAssumption
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    Hegemon.Transaction.slotDelta assetId slots =
        authorizedAssetDeltaValue balanceWitness assetId
      ∧ TxLeafActionBindingFacts input := by
  have relationFacts :=
    native_tx_leaf_binding_and_canonical_surface_implies_transaction_relation
      bindingAccepted
      surface
      sound
  exact
    ⟨accepted_transaction_relation_authorized_asset_delta_value
        relationFacts.left,
      relationFacts.right.right⟩

end TxLeafCanonicalSurface
end Native
end Hegemon

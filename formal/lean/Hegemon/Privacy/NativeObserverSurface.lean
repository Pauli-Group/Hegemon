import Hegemon.Native.TxLeafCanonicalSurface
import Hegemon.Privacy.Observer

namespace Hegemon
namespace Privacy
namespace NativeObserverSurface

open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Privacy.Observer
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

theorem valid_observer_chain_surface_bound_to_shape
    {world : ShieldedTransactionWorld}
    {shape : PublicInputShape}
    (valid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape) :
    summariesHaveChainCiphertextFormat world.ciphertextSummaries
      ∧ world.ciphertextSummaries.length = activeOutputCount shape := by
  have format :=
    valid_observer_chain_surface_summaries_have_chain_format valid
  have count :=
    valid_observer_chain_surface_ciphertext_count valid
  rw [shapeEq] at count
  exact ⟨format, count⟩

theorem native_tx_leaf_output_slot_bound_to_observer_surface
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
    {index activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {world : ShieldedTransactionWorld}
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
    (slot :
      OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        activeFlag
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape) :
    OutputSlotFacts
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ OutputSlotAt
        bound.outputFlags
        statementFields.commitmentSeeds
        statementFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ OutputSlotAt
        bound.outputFlags
        bindingFields.commitmentSeeds
        bindingFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ TxLeafActionBindingFacts input
      ∧ summariesHaveChainCiphertextFormat world.ciphertextSummaries
      ∧ world.ciphertextSummaries.length = activeOutputCount shape := by
  have nativeFacts :=
    native_tx_leaf_binding_and_canonical_surface_output_slot_bound_to_statement
      bindingAccepted
      surface
      slot
  have observerFacts :=
    valid_observer_chain_surface_bound_to_shape
      observerValid
      shapeEq
  exact
    ⟨nativeFacts.left,
      nativeFacts.right.left,
      nativeFacts.right.right.left,
      nativeFacts.right.right.right,
      observerFacts.left,
      observerFacts.right⟩

theorem native_tx_leaf_output_slot_same_chain_wire_preserves_allowed_leakage
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
    {index activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {left right : ShieldedTransactionWorld}
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
    (slot :
      OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        activeFlag
        publicCommitment
        publicCiphertextHash)
    (leftValid : validObserverChainSurface left)
    (rightValid : validObserverChainSurface right)
    (leftShape : left.publicInputs = shape)
    (rightShape : right.publicInputs = shape)
    (ciphertextBytes : left.ciphertextBytes = right.ciphertextBytes)
    (placement : samePlacement left right) :
    sameAllowedLeakage left right
      ∧ OutputSlotFacts
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ OutputSlotAt
        bound.outputFlags
        statementFields.commitmentSeeds
        statementFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ OutputSlotAt
        bound.outputFlags
        bindingFields.commitmentSeeds
        bindingFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ TxLeafActionBindingFacts input
      ∧ left.ciphertextSummaries.length = activeOutputCount shape
      ∧ right.ciphertextSummaries.length = activeOutputCount shape := by
  have publicInputs : samePublicInputs left right := by
    unfold samePublicInputs
    rw [leftShape, rightShape]
  have leakage :=
    same_allowed_leakage_of_valid_observer_chain_surfaces
      leftValid
      rightValid
      publicInputs
      ciphertextBytes
      placement
  have nativeFacts :=
    native_tx_leaf_binding_and_canonical_surface_output_slot_bound_to_statement
      bindingAccepted
      surface
      slot
  have leftObserver :=
    valid_observer_chain_surface_bound_to_shape
      leftValid
      leftShape
  have rightObserver :=
    valid_observer_chain_surface_bound_to_shape
      rightValid
      rightShape
  exact
    ⟨leakage,
      nativeFacts.left,
      nativeFacts.right.left,
      nativeFacts.right.right.left,
      nativeFacts.right.right.right,
      leftObserver.right,
      rightObserver.right⟩

end NativeObserverSurface
end Privacy
end Hegemon

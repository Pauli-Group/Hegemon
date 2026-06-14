import Hegemon.Native.TxLeafCanonicalSurface
import Hegemon.Privacy.CiphertextPrivacy
import Hegemon.Privacy.Observer
import Hegemon.Wallet.NotePlaintextCommitment

namespace Hegemon
namespace Privacy
namespace NativeObserverSurface

open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Privacy.CiphertextPrivacy
open Hegemon.Privacy.Observer
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Wallet.NoteCiphertextDecrypt
open Hegemon.Wallet.NotePlaintextCommitment

def ActiveOutputPublicMetadataBoundary
    (input : TxLeafActionBindingInput)
    (shape : PublicInputShape)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (left right : ShieldedTransactionWorld)
    (index : Nat)
    (publicCommitment publicCiphertextHash : Digest) : Prop :=
  ∃ leftWire rightWire summary,
    left.ciphertextBytes[
        activeFlagCountBefore shape.outputFlags index]? = some leftWire
      ∧ right.ciphertextBytes[
        activeFlagCountBefore shape.outputFlags index]? = some rightWire
      ∧ left.ciphertextSummaries[
        activeFlagCountBefore shape.outputFlags index]? = some summary
      ∧ right.ciphertextSummaries[
        activeFlagCountBefore shape.outputFlags index]? = some summary
      ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
        leftWire = some summary
      ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
        rightWire = some summary
      ∧ summaryHasChainCiphertextFormat summary
      ∧ samePublicMetadataLeakage left right
      ∧ shape.outputFlags[index]? = some 1
      ∧ shape.commitments[index]? = some publicCommitment
      ∧ shape.ciphertextHashes[index]? = some publicCiphertextHash
      ∧ bound.outputFlags[index]? = some 1
      ∧ statementFields.commitmentSeeds[index]? = some publicCommitment
      ∧ statementFields.ciphertextHashSeeds[index]? =
        some publicCiphertextHash
      ∧ bindingFields.commitmentSeeds[index]? = some publicCommitment
      ∧ bindingFields.ciphertextHashSeeds[index]? =
        some publicCiphertextHash
      ∧ input.ciphertextHashesMatch = true
      ∧ input.ciphertextPayloadHashesMatch = true
      ∧ input.outputCountMatches = true
      ∧ OutputSlotFacts 1 publicCommitment publicCiphertextHash
      ∧ TxLeafActionBindingFacts input

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

theorem native_tx_leaf_active_output_slot_forces_nonempty_observer_ciphertexts
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape) :
    world.ciphertextBytes.length ≠ 0
      ∧ world.ciphertextSummaries.length ≠ 0
      ∧ summariesHaveChainCiphertextFormat world.ciphertextSummaries
      ∧ OutputSlotAt
        bound.outputFlags
        statementFields.commitmentSeeds
        statementFields.ciphertextHashSeeds
        index
        1
        publicCommitment
        publicCiphertextHash
      ∧ OutputSlotAt
        bound.outputFlags
        bindingFields.commitmentSeeds
        bindingFields.ciphertextHashSeeds
        index
        1
        publicCommitment
        publicCiphertextHash
      ∧ TxLeafActionBindingFacts input := by
  have activeCountNonzero :
      activeOutputCount shape ≠ 0 :=
    output_slot_active_flag_count_nonzero slot
  have observerFacts :=
    native_tx_leaf_output_slot_bound_to_observer_surface
      bindingAccepted
      surface
      slot
      observerValid
      shapeEq
  have ciphertextBytesCount :
      world.ciphertextBytes.length = activeOutputCount shape := by
    have count := observerValid.right.right
    rw [shapeEq] at count
    exact count
  have ciphertextBytesNonzero :
      world.ciphertextBytes.length ≠ 0 := by
    rw [ciphertextBytesCount]
    exact activeCountNonzero
  have ciphertextSummariesNonzero :
      world.ciphertextSummaries.length ≠ 0 := by
    rw [observerFacts.right.right.right.right.right]
    exact activeCountNonzero
  exact
    ⟨ciphertextBytesNonzero,
      ciphertextSummariesNonzero,
      observerFacts.right.right.right.right.left,
      observerFacts.right.left,
      observerFacts.right.right.left,
      observerFacts.right.right.right.left⟩

theorem native_tx_leaf_active_output_slot_has_observer_rank
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape) :
    activeFlagCountBefore shape.outputFlags index < world.ciphertextBytes.length
      ∧ activeFlagCountBefore shape.outputFlags index <
        world.ciphertextSummaries.length
      ∧ summariesHaveChainCiphertextFormat world.ciphertextSummaries
      ∧ OutputSlotAt
        bound.outputFlags
        statementFields.commitmentSeeds
        statementFields.ciphertextHashSeeds
        index
        1
        publicCommitment
        publicCiphertextHash
      ∧ OutputSlotAt
        bound.outputFlags
        bindingFields.commitmentSeeds
        bindingFields.ciphertextHashSeeds
        index
        1
        publicCommitment
        publicCiphertextHash
      ∧ TxLeafActionBindingFacts input := by
  have rankLtCount :
      activeFlagCountBefore shape.outputFlags index <
        activeOutputCount shape :=
    output_slot_active_rank_lt_count slot
  have observerFacts :=
    valid_observer_chain_surface_bound_to_shape
      observerValid
      shapeEq
  have nativeFacts :=
    native_tx_leaf_binding_and_canonical_surface_output_slot_bound_to_statement
      bindingAccepted
      surface
      slot
  have ciphertextBytesCount :
      world.ciphertextBytes.length = activeOutputCount shape := by
    have count := observerValid.right.right
    rw [shapeEq] at count
    exact count
  have bytesRank :
      activeFlagCountBefore shape.outputFlags index <
        world.ciphertextBytes.length := by
    rw [ciphertextBytesCount]
    exact rankLtCount
  have summariesRank :
      activeFlagCountBefore shape.outputFlags index <
        world.ciphertextSummaries.length := by
    rw [observerFacts.right]
    exact rankLtCount
  exact
    ⟨bytesRank,
      summariesRank,
      observerFacts.left,
      nativeFacts.right.left,
      nativeFacts.right.right.left,
      nativeFacts.right.right.right⟩

theorem native_tx_leaf_active_output_slot_has_parsed_observer_wire_at_rank
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape) :
    ∃ wire summary,
      world.ciphertextBytes[
          activeFlagCountBefore shape.outputFlags index]? = some wire
        ∧ world.ciphertextSummaries[
          activeFlagCountBefore shape.outputFlags index]? = some summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
          wire = some summary
        ∧ summaryHasChainCiphertextFormat summary
        ∧ OutputSlotFacts
          1
          publicCommitment
          publicCiphertextHash
        ∧ OutputSlotAt
          bound.outputFlags
          statementFields.commitmentSeeds
          statementFields.ciphertextHashSeeds
          index
          1
          publicCommitment
          publicCiphertextHash
        ∧ OutputSlotAt
          bound.outputFlags
          bindingFields.commitmentSeeds
      bindingFields.ciphertextHashSeeds
      index
      1
      publicCommitment
      publicCiphertextHash
    ∧ TxLeafActionBindingFacts input := by
  have rankFacts :=
    native_tx_leaf_active_output_slot_has_observer_rank
      bindingAccepted
      surface
      slot
      observerValid
      shapeEq
  rcases
      valid_observer_chain_surface_ciphertext_at_rank
        observerValid
        rankFacts.left with
    ⟨wire, summary, wireAt, summaryAt, parsedSummary, format⟩
  have nativeFacts :=
    native_tx_leaf_binding_and_canonical_surface_output_slot_bound_to_statement
      bindingAccepted
      surface
      slot
  exact
    ⟨wire,
      summary,
      wireAt,
      summaryAt,
      parsedSummary,
      format,
      nativeFacts.left,
      nativeFacts.right.left,
      nativeFacts.right.right.left,
      nativeFacts.right.right.right⟩

theorem native_tx_leaf_active_output_slot_has_indexed_statement_observer_wire
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape) :
    ∃ wire summary,
      world.ciphertextBytes[
          activeFlagCountBefore shape.outputFlags index]? = some wire
        ∧ world.ciphertextSummaries[
          activeFlagCountBefore shape.outputFlags index]? = some summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
          wire = some summary
        ∧ summaryHasChainCiphertextFormat summary
        ∧ shape.outputFlags[index]? = some 1
        ∧ shape.commitments[index]? = some publicCommitment
        ∧ shape.ciphertextHashes[index]? = some publicCiphertextHash
        ∧ bound.outputFlags[index]? = some 1
        ∧ statementFields.commitmentSeeds[index]? = some publicCommitment
        ∧ statementFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ bound.outputFlags[index]? = some 1
        ∧ bindingFields.commitmentSeeds[index]? = some publicCommitment
        ∧ bindingFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ OutputSlotFacts
          1
          publicCommitment
          publicCiphertextHash
        ∧ TxLeafActionBindingFacts input := by
  rcases
      native_tx_leaf_active_output_slot_has_parsed_observer_wire_at_rank
        bindingAccepted
        surface
        slot
        observerValid
        shapeEq with
    ⟨wire,
      summary,
      wireAt,
      summaryAt,
      parsedSummary,
      format,
      outputFacts,
      statementSlot,
      bindingSlot,
      bindingFacts⟩
  have shapeIndices :=
    output_slot_at_get_indices slot
  have statementIndices :=
    output_slot_at_get_indices statementSlot
  have bindingIndices :=
    output_slot_at_get_indices bindingSlot
  exact
    ⟨wire,
      summary,
      wireAt,
      summaryAt,
      parsedSummary,
      format,
      shapeIndices.left,
      shapeIndices.right.left,
      shapeIndices.right.right,
      statementIndices.left,
      statementIndices.right.left,
      statementIndices.right.right,
      bindingIndices.left,
      bindingIndices.right.left,
      bindingIndices.right.right,
      outputFacts,
      bindingFacts⟩

theorem native_tx_leaf_active_output_slot_has_indexed_statement_observer_wire_fixed_chain_shape
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape)
    (observerBytesBounded :
      ∀ wire,
        wire ∈ world.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    ∃ wire summary,
      world.ciphertextBytes[
          activeFlagCountBefore shape.outputFlags index]? = some wire
        ∧ world.ciphertextSummaries[
          activeFlagCountBefore shape.outputFlags index]? = some summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
          wire = some summary
        ∧ summaryHasChainCiphertextFormat summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire
        ∧ wire.length =
          Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
            + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
            + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
        ∧ shape.outputFlags[index]? = some 1
        ∧ shape.commitments[index]? = some publicCommitment
        ∧ shape.ciphertextHashes[index]? = some publicCiphertextHash
        ∧ bound.outputFlags[index]? = some 1
        ∧ statementFields.commitmentSeeds[index]? = some publicCommitment
        ∧ statementFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ bound.outputFlags[index]? = some 1
        ∧ bindingFields.commitmentSeeds[index]? = some publicCommitment
        ∧ bindingFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ OutputSlotFacts
          1
          publicCommitment
          publicCiphertextHash
        ∧ TxLeafActionBindingFacts input := by
  rcases
      native_tx_leaf_active_output_slot_has_indexed_statement_observer_wire
        bindingAccepted
        surface
        slot
        observerValid
        shapeEq with
    ⟨wire,
      summary,
      wireAt,
      summaryAt,
      parsedSummary,
      format,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      statementFlag,
      statementCommitment,
      statementCiphertext,
      bindingFlag,
      bindingCommitment,
      bindingCiphertext,
      outputFacts,
      bindingFacts⟩
  have wireBounded :
      Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire :=
    observerBytesBounded wire (List.mem_of_getElem? wireAt)
  have wireLength :
      wire.length =
        Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
          + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
          + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen :=
    Hegemon.Wallet.NoteCiphertextWire.parsed_chain_ciphertext_has_fixed_wire_length_of_bounded
      wireBounded
      parsedSummary
  exact
    ⟨wire,
      summary,
      wireAt,
      summaryAt,
      parsedSummary,
      format,
      wireBounded,
      wireLength,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      statementFlag,
      statementCommitment,
      statementCiphertext,
      bindingFlag,
      bindingCommitment,
      bindingCiphertext,
      outputFacts,
      bindingFacts⟩

theorem native_tx_leaf_active_output_ciphertext_boundary_facts
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape)
    (observerBytesBounded :
      ∀ wire,
        wire ∈ world.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    ∃ wire summary,
      world.ciphertextBytes[
          activeFlagCountBefore shape.outputFlags index]? = some wire
        ∧ world.ciphertextSummaries[
          activeFlagCountBefore shape.outputFlags index]? = some summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
          wire = some summary
        ∧ summaryHasChainCiphertextFormat summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire
        ∧ wire.length =
          Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
            + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
            + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
        ∧ shape.outputFlags[index]? = some 1
        ∧ shape.commitments[index]? = some publicCommitment
        ∧ shape.ciphertextHashes[index]? = some publicCiphertextHash
        ∧ bound.outputFlags[index]? = some 1
        ∧ statementFields.commitmentSeeds[index]? = some publicCommitment
        ∧ statementFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ bindingFields.commitmentSeeds[index]? = some publicCommitment
        ∧ bindingFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ input.ciphertextHashesMatch = true
        ∧ input.ciphertextPayloadHashesMatch = true
        ∧ input.outputCountMatches = true
        ∧ OutputSlotFacts
          1
          publicCommitment
          publicCiphertextHash
        ∧ TxLeafActionBindingFacts input := by
  rcases
      native_tx_leaf_active_output_slot_has_indexed_statement_observer_wire_fixed_chain_shape
        bindingAccepted
        surface
        slot
        observerValid
        shapeEq
        observerBytesBounded with
    ⟨wire,
      summary,
      wireAt,
      summaryAt,
      parsedSummary,
      format,
      wireBounded,
      wireLength,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      statementFlag,
      statementCommitment,
      statementCiphertext,
      bindingFlag,
      bindingCommitment,
      bindingCiphertext,
      outputFacts,
      bindingFacts⟩
  rcases bindingFacts with
    ⟨_hNullifiers,
      _hCommitments,
      hCiphertextHashes,
      _hInputCount,
      hOutputCount,
      _hVersion,
      _hFee,
      _hStablecoinPayload,
      _hBalanceTag,
      _hReceiptStatementHash,
      _hPublicInputsDigest,
      _hProofDigest,
      _hProofBackend,
      hCiphertextPayloadHashes⟩
  exact
    ⟨wire,
      summary,
      wireAt,
      summaryAt,
      parsedSummary,
      format,
      wireBounded,
      wireLength,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      statementFlag,
      statementCommitment,
      statementCiphertext,
      bindingCommitment,
      bindingCiphertext,
      hCiphertextHashes,
      hCiphertextPayloadHashes,
      hOutputCount,
      outputFacts,
      ⟨_hNullifiers,
        _hCommitments,
        hCiphertextHashes,
        _hInputCount,
        hOutputCount,
        _hVersion,
        _hFee,
        _hStablecoinPayload,
        _hBalanceTag,
        _hReceiptStatementHash,
        _hPublicInputsDigest,
        _hProofDigest,
        _hProofBackend,
        hCiphertextPayloadHashes⟩⟩

theorem native_tx_leaf_active_output_ciphertext_boundary_has_projected_da_bytes
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape)
    (observerBytesBounded :
      ∀ wire,
        wire ∈ world.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    ∃ wire summary daBytes,
      world.ciphertextBytes[
          activeFlagCountBefore shape.outputFlags index]? = some wire
        ∧ world.ciphertextSummaries[
          activeFlagCountBefore shape.outputFlags index]? = some summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
          wire = some summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
          wire = some daBytes
        ∧ daBytes.length =
          Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
            + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
        ∧ summaryHasChainCiphertextFormat summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire
        ∧ wire.length =
          Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
            + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
            + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
        ∧ shape.outputFlags[index]? = some 1
        ∧ shape.commitments[index]? = some publicCommitment
        ∧ shape.ciphertextHashes[index]? = some publicCiphertextHash
        ∧ statementFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ bindingFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ input.ciphertextHashesMatch = true
        ∧ input.ciphertextPayloadHashesMatch = true
        ∧ input.outputCountMatches = true
        ∧ OutputSlotFacts
          1
          publicCommitment
          publicCiphertextHash
        ∧ TxLeafActionBindingFacts input := by
  rcases
      native_tx_leaf_active_output_ciphertext_boundary_facts
        bindingAccepted
        surface
        slot
        observerValid
        shapeEq
        observerBytesBounded with
    ⟨wire,
      summary,
      wireAt,
      summaryAt,
      parsedSummary,
      format,
      wireBounded,
      wireLength,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      _statementFlag,
      _statementCommitment,
      statementCiphertext,
      _bindingCommitment,
      bindingCiphertext,
      ciphertextHashesMatch,
      ciphertextPayloadHashesMatch,
      outputCountMatches,
      outputFacts,
      bindingFacts⟩
  rcases
      Hegemon.Wallet.NoteCiphertextWire.parsed_chain_ciphertext_has_projected_da_bytes_of_bounded
        wireBounded
        parsedSummary with
    ⟨daBytes, daProjection, daLength⟩
  exact
    ⟨wire,
      summary,
      daBytes,
      wireAt,
      summaryAt,
      parsedSummary,
      daProjection,
      daLength,
      format,
      wireBounded,
      wireLength,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      statementCiphertext,
      bindingCiphertext,
      ciphertextHashesMatch,
      ciphertextPayloadHashesMatch,
      outputCountMatches,
      outputFacts,
      bindingFacts⟩

theorem native_tx_leaf_active_output_ciphertext_boundary_binds_projected_da_hash
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (observerValid : validObserverChainSurface world)
    (shapeEq : world.publicInputs = shape)
    (observerBytesBounded :
      ∀ wire,
        wire ∈ world.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire)
    (ciphertextHashMatches : List Byte → Digest → Prop)
    (ciphertextHashPreimage :
      ∀ {wire summary daBytes},
        world.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? = some wire ->
          Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            wire = some summary ->
          Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            wire = some daBytes ->
          ciphertextHashMatches daBytes publicCiphertextHash) :
    ∃ wire summary daBytes,
      world.ciphertextBytes[
          activeFlagCountBefore shape.outputFlags index]? = some wire
        ∧ world.ciphertextSummaries[
          activeFlagCountBefore shape.outputFlags index]? = some summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
          wire = some summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
          wire = some daBytes
        ∧ ciphertextHashMatches daBytes publicCiphertextHash
        ∧ daBytes.length =
          Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
            + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
        ∧ summaryHasChainCiphertextFormat summary
        ∧ Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire
        ∧ wire.length =
          Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
            + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
            + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
        ∧ shape.outputFlags[index]? = some 1
        ∧ shape.commitments[index]? = some publicCommitment
        ∧ shape.ciphertextHashes[index]? = some publicCiphertextHash
        ∧ statementFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ bindingFields.ciphertextHashSeeds[index]? =
          some publicCiphertextHash
        ∧ input.ciphertextHashesMatch = true
        ∧ input.ciphertextPayloadHashesMatch = true
        ∧ input.outputCountMatches = true
        ∧ OutputSlotFacts
          1
          publicCommitment
          publicCiphertextHash
        ∧ TxLeafActionBindingFacts input := by
  rcases
      native_tx_leaf_active_output_ciphertext_boundary_has_projected_da_bytes
        bindingAccepted
        surface
        slot
        observerValid
        shapeEq
        observerBytesBounded with
    ⟨wire,
      summary,
      daBytes,
      wireAt,
      summaryAt,
      parsedSummary,
      daProjection,
      daLength,
      format,
      wireBounded,
      wireLength,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      statementCiphertext,
      bindingCiphertext,
      ciphertextHashesMatch,
      ciphertextPayloadHashesMatch,
      outputCountMatches,
      outputFacts,
      bindingFacts⟩
  have projectedHash :
      ciphertextHashMatches daBytes publicCiphertextHash :=
    ciphertextHashPreimage wireAt parsedSummary daProjection
  exact
    ⟨wire,
      summary,
      daBytes,
      wireAt,
      summaryAt,
      parsedSummary,
      daProjection,
      projectedHash,
      daLength,
      format,
      wireBounded,
      wireLength,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      statementCiphertext,
      bindingCiphertext,
      ciphertextHashesMatch,
      ciphertextPayloadHashesMatch,
      outputCountMatches,
      outputFacts,
      bindingFacts⟩

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

theorem native_tx_leaf_active_output_public_metadata_boundary
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (leftValid : validObserverChainSurface left)
    (rightValid : validObserverChainSurface right)
    (leftShape : left.publicInputs = shape)
    (rightShape : right.publicInputs = shape)
    (metadata : samePublicMetadataLeakage left right) :
    ActiveOutputPublicMetadataBoundary
      input
      shape
      bound
      statementFields
      bindingFields
      left
      right
      index
      publicCommitment
      publicCiphertextHash := by
  rcases
      native_tx_leaf_active_output_slot_has_indexed_statement_observer_wire
        bindingAccepted
        surface
        slot
        leftValid
        leftShape with
    ⟨leftWire,
      leftSummary,
      leftWireAt,
      leftSummaryAt,
      leftParsed,
      leftFormat,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      leftStatementFlag,
      leftStatementCommitment,
      leftStatementCiphertext,
      _leftBindingFlag,
      leftBindingCommitment,
      leftBindingCiphertext,
      leftOutputFacts,
      leftBindingFacts⟩
  rcases
      native_tx_leaf_active_output_slot_has_indexed_statement_observer_wire
        bindingAccepted
        surface
        slot
        rightValid
        rightShape with
    ⟨rightWire,
      rightSummary,
      rightWireAt,
      rightSummaryAt,
      rightParsed,
      _rightFormat,
      _rightShapeFlag,
      _rightShapeCommitment,
      _rightShapeCiphertext,
      _rightStatementFlag,
      _rightStatementCommitment,
      _rightStatementCiphertext,
      _rightBindingFlag,
      _rightBindingCommitment,
      _rightBindingCiphertext,
      _rightOutputFacts,
      _rightBindingFacts⟩
  have summariesEq :
      left.ciphertextSummaries = right.ciphertextSummaries :=
    congrArg PublicMetadataView.ciphertextSummaries metadata
  have summaryEq : leftSummary = rightSummary := by
    have someEq : some leftSummary = some rightSummary := by
      calc
        some leftSummary =
            left.ciphertextSummaries[
              activeFlagCountBefore shape.outputFlags index]? :=
          leftSummaryAt.symm
        _ =
            right.ciphertextSummaries[
              activeFlagCountBefore shape.outputFlags index]? := by
          rw [summariesEq]
        _ = some rightSummary :=
          rightSummaryAt
    exact Option.some.inj someEq
  subst rightSummary
  rcases leftBindingFacts with
    ⟨_hNullifiers,
      _hCommitments,
      hCiphertextHashes,
      _hInputCount,
      hOutputCount,
      _hVersion,
      _hFee,
      _hStablecoinPayload,
      _hBalanceTag,
      _hReceiptStatementHash,
      _hPublicInputsDigest,
      _hProofDigest,
      _hProofBackend,
      hCiphertextPayloadHashes⟩
  unfold ActiveOutputPublicMetadataBoundary
  exact
    ⟨leftWire,
      rightWire,
      leftSummary,
      leftWireAt,
      rightWireAt,
      leftSummaryAt,
      rightSummaryAt,
      leftParsed,
      rightParsed,
      leftFormat,
      metadata,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      leftStatementFlag,
      leftStatementCommitment,
      leftStatementCiphertext,
      leftBindingCommitment,
      leftBindingCiphertext,
      hCiphertextHashes,
      hCiphertextPayloadHashes,
      hOutputCount,
      leftOutputFacts,
      ⟨_hNullifiers,
        _hCommitments,
        hCiphertextHashes,
        _hInputCount,
        hOutputCount,
        _hVersion,
        _hFee,
        _hStablecoinPayload,
        _hBalanceTag,
        _hReceiptStatementHash,
        _hPublicInputsDigest,
        _hProofDigest,
        _hProofBackend,
        hCiphertextPayloadHashes⟩⟩

theorem native_tx_leaf_active_output_ciphertext_privacy_game_public_metadata_boundary
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape)
    (rightShape : right.publicInputs = shape) :
    ActiveOutputPublicMetadataBoundary
      input
      shape
      bound
      statementFields
      bindingFields
      left
      right
      index
      publicCommitment
      publicCiphertextHash := by
  exact
    native_tx_leaf_active_output_public_metadata_boundary
      bindingAccepted
      surface
      slot
      game.leftValid
      game.rightValid
      leftShape
      rightShape
      (ciphertext_privacy_game_preserves_public_metadata_leakage game)

theorem native_tx_leaf_ciphertext_privacy_game_active_output_slot_selects_same_public_summary
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
    {index : Nat}
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
        1
        publicCommitment
        publicCiphertextHash)
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape) :
    samePublicMetadataLeakage left right
      ∧ sameBatchTimingLeakage left right
      ∧ game.wireIndistinguishable
      ∧ ActiveOutputPublicMetadataBoundary
        input
        shape
        bound
        statementFields
        bindingFields
        left
        right
        index
        publicCommitment
        publicCiphertextHash := by
  have rightShape : right.publicInputs = shape := by
    calc
      right.publicInputs = left.publicInputs := game.publicInputs.symm
      _ = shape := leftShape
  exact
    ⟨ciphertext_privacy_game_preserves_public_metadata_leakage game,
      ciphertext_privacy_game_preserves_batch_timing_leakage game,
      ciphertext_privacy_game_only_open_crypto_obligation game,
      native_tx_leaf_active_output_ciphertext_privacy_game_public_metadata_boundary
        bindingAccepted
        surface
        slot
        game
        leftShape
        rightShape⟩

theorem native_tx_leaf_ciphertext_privacy_game_selected_output_wire_da_commitment_boundary
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
    {index : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {left right : ShieldedTransactionWorld}
    (mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness : Prop)
    (mlKemAssumption : mlKemIndistinguishability)
    (aeadAssumption : aeadCiphertextConfidentiality)
    (kdfAssumption : kdfDomainSeparation)
    (rngAssumption : rngFreshness)
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
        1
        publicCommitment
        publicCiphertextHash)
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape)
    (leftObserverBytesBounded :
      ∀ wire,
        wire ∈ left.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire)
    (rightObserverBytesBounded :
      ∀ wire,
        wire ∈ right.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    mlKemIndistinguishability
      ∧ aeadCiphertextConfidentiality
      ∧ kdfDomainSeparation
      ∧ rngFreshness
      ∧ samePublicMetadataLeakage left right
      ∧ sameBatchTimingLeakage left right
      ∧ game.wireIndistinguishable
      ∧ ∃ leftWire rightWire summary leftDaBytes rightDaBytes,
        left.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? =
          some leftWire
          ∧ right.ciphertextBytes[
              activeFlagCountBefore shape.outputFlags index]? =
            some rightWire
          ∧ left.ciphertextSummaries[
              activeFlagCountBefore shape.outputFlags index]? =
            some summary
          ∧ right.ciphertextSummaries[
              activeFlagCountBefore shape.outputFlags index]? =
            some summary
          ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            leftWire = some summary
          ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            rightWire = some summary
          ∧ Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            leftWire = some leftDaBytes
          ∧ Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            rightWire = some rightDaBytes
          ∧ leftDaBytes.length =
            Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
              + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
          ∧ rightDaBytes.length =
            Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
              + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
          ∧ summaryHasChainCiphertextFormat summary
          ∧ Hegemon.Wallet.NoteCiphertextWire.bytesBounded leftWire
          ∧ Hegemon.Wallet.NoteCiphertextWire.bytesBounded rightWire
          ∧ leftWire.length =
            Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
              + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
              + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
          ∧ rightWire.length =
            Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
              + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
              + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
          ∧ shape.outputFlags[index]? = some 1
          ∧ shape.commitments[index]? = some publicCommitment
          ∧ shape.ciphertextHashes[index]? = some publicCiphertextHash
          ∧ statementFields.commitmentSeeds[index]? =
            some publicCommitment
          ∧ statementFields.ciphertextHashSeeds[index]? =
            some publicCiphertextHash
          ∧ bindingFields.commitmentSeeds[index]? =
            some publicCommitment
          ∧ bindingFields.ciphertextHashSeeds[index]? =
            some publicCiphertextHash
          ∧ input.ciphertextHashesMatch = true
          ∧ input.ciphertextPayloadHashesMatch = true
          ∧ input.outputCountMatches = true
          ∧ OutputSlotFacts
            1
            publicCommitment
            publicCiphertextHash
          ∧ TxLeafActionBindingFacts input
          ∧ ActiveOutputPublicMetadataBoundary
            input
            shape
            bound
            statementFields
            bindingFields
            left
            right
            index
            publicCommitment
            publicCiphertextHash := by
  have rightShape : right.publicInputs = shape := by
    calc
      right.publicInputs = left.publicInputs := game.publicInputs.symm
      _ = shape := leftShape
  have selectedBoundary :
      samePublicMetadataLeakage left right
        ∧ sameBatchTimingLeakage left right
        ∧ game.wireIndistinguishable
        ∧ ActiveOutputPublicMetadataBoundary
          input
          shape
          bound
          statementFields
          bindingFields
          left
          right
          index
          publicCommitment
          publicCiphertextHash :=
    native_tx_leaf_ciphertext_privacy_game_active_output_slot_selects_same_public_summary
      bindingAccepted
      surface
      slot
      game
      leftShape
  rcases selectedBoundary with
    ⟨metadata, timing, wireIndistinguishable, activeBoundary⟩
  have activeBoundaryCopy := activeBoundary
  rcases activeBoundary with
    ⟨activeLeftWire,
      activeRightWire,
      summary,
      activeLeftWireAt,
      activeRightWireAt,
      activeLeftSummaryAt,
      activeRightSummaryAt,
      activeLeftParsed,
      activeRightParsed,
      summaryFormat,
      _metadata,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      _boundFlag,
      statementCommitment,
      statementCiphertext,
      bindingCommitment,
      bindingCiphertext,
      ciphertextHashesMatch,
      ciphertextPayloadHashesMatch,
      outputCountMatches,
      outputFacts,
      bindingFacts⟩
  rcases
      native_tx_leaf_active_output_ciphertext_boundary_has_projected_da_bytes
        bindingAccepted
        surface
        slot
        game.leftValid
        leftShape
        leftObserverBytesBounded with
    ⟨leftWire,
      leftSummary,
      leftDaBytes,
      leftWireAt,
      _leftSummaryAt,
      _leftParsed,
      leftDaProjection,
      leftDaLength,
      _leftFormat,
      leftWireBounded,
      leftWireLength,
      _leftShapeFlag,
      _leftShapeCommitment,
      _leftShapeCiphertext,
      _leftStatementCiphertext,
      _leftBindingCiphertext,
      _leftCiphertextHashesMatch,
      _leftCiphertextPayloadHashesMatch,
      _leftOutputCountMatches,
      _leftOutputFacts,
      _leftBindingFacts⟩
  rcases
      native_tx_leaf_active_output_ciphertext_boundary_has_projected_da_bytes
        bindingAccepted
        surface
        slot
        game.rightValid
        rightShape
        rightObserverBytesBounded with
    ⟨rightWire,
      rightSummary,
      rightDaBytes,
      rightWireAt,
      _rightSummaryAt,
      _rightParsed,
      rightDaProjection,
      rightDaLength,
      _rightFormat,
      rightWireBounded,
      rightWireLength,
      _rightShapeFlag,
      _rightShapeCommitment,
      _rightShapeCiphertext,
      _rightStatementCiphertext,
      _rightBindingCiphertext,
      _rightCiphertextHashesMatch,
      _rightCiphertextPayloadHashesMatch,
      _rightOutputCountMatches,
      _rightOutputFacts,
      _rightBindingFacts⟩
  have leftWireEq : leftWire = activeLeftWire := by
    have someEq : some leftWire = some activeLeftWire := by
      calc
        some leftWire =
            left.ciphertextBytes[
              activeFlagCountBefore shape.outputFlags index]? :=
          leftWireAt.symm
        _ = some activeLeftWire :=
          activeLeftWireAt
    exact Option.some.inj someEq
  have rightWireEq : rightWire = activeRightWire := by
    have someEq : some rightWire = some activeRightWire := by
      calc
        some rightWire =
            right.ciphertextBytes[
              activeFlagCountBefore shape.outputFlags index]? :=
          rightWireAt.symm
        _ = some activeRightWire :=
          activeRightWireAt
    exact Option.some.inj someEq
  subst leftWire
  subst rightWire
  exact
    ⟨mlKemAssumption,
      aeadAssumption,
      kdfAssumption,
      rngAssumption,
      metadata,
      timing,
      wireIndistinguishable,
      activeLeftWire,
      activeRightWire,
      summary,
      leftDaBytes,
      rightDaBytes,
      activeLeftWireAt,
      activeRightWireAt,
      activeLeftSummaryAt,
      activeRightSummaryAt,
      activeLeftParsed,
      activeRightParsed,
      leftDaProjection,
      rightDaProjection,
      leftDaLength,
      rightDaLength,
      summaryFormat,
      leftWireBounded,
      rightWireBounded,
      leftWireLength,
      rightWireLength,
      shapeFlag,
      shapeCommitment,
      shapeCiphertext,
      statementCommitment,
      statementCiphertext,
      bindingCommitment,
      bindingCiphertext,
      ciphertextHashesMatch,
      ciphertextPayloadHashesMatch,
      outputCountMatches,
      outputFacts,
      bindingFacts,
      activeBoundaryCopy⟩

theorem native_tx_leaf_ciphertext_privacy_game_decrypts_selected_output_to_statement_commitment
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
    {index : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    {left right : ShieldedTransactionWorld}
    {attempt : DecryptAttempt}
    {plaintext : NotePlaintextSummary}
    {material : WalletRecipientMaterial}
    {data : ExportedNoteData}
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
        1
        publicCommitment
        publicCiphertextHash)
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape)
    (selectedAttempt :
      left.ciphertextSummaries[
        activeFlagCountBefore shape.outputFlags index]? =
          some attempt.ciphertext)
    (decryptAccepted : evaluateDecrypt attempt = none)
    (exported : data = exportNoteData plaintext material)
    (published : publicCommitment = commitmentFromNoteData data) :
    samePublicMetadataLeakage left right
      ∧ sameBatchTimingLeakage left right
      ∧ game.wireIndistinguishable
      ∧ attempt.ciphertext.version = attempt.material.version
      ∧ attempt.ciphertext.cryptoSuite = attempt.material.cryptoSuite
      ∧ attempt.ciphertext.diversifierIndex =
        attempt.material.diversifierIndex
      ∧ attempt.cryptoAuthenticates = true
      ∧ publicCommitment = commitmentFromPlaintext plaintext material
      ∧ shape.commitments[index]? =
        some (commitmentFromPlaintext plaintext material)
      ∧ statementFields.commitmentSeeds[index]? =
        some (commitmentFromPlaintext plaintext material)
      ∧ bindingFields.commitmentSeeds[index]? =
        some (commitmentFromPlaintext plaintext material)
      ∧ ∃ leftWire rightWire,
        left.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? =
          some leftWire
          ∧ right.ciphertextBytes[
              activeFlagCountBefore shape.outputFlags index]? =
            some rightWire
          ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            leftWire = some attempt.ciphertext
          ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            rightWire = some attempt.ciphertext
          ∧ summaryHasChainCiphertextFormat attempt.ciphertext
          ∧ ActiveOutputPublicMetadataBoundary
            input
            shape
            bound
            statementFields
            bindingFields
            left
            right
            index
            publicCommitment
            publicCiphertextHash := by
  have rightShape : right.publicInputs = shape := by
    calc
      right.publicInputs = left.publicInputs := game.publicInputs.symm
      _ = shape := leftShape
  have privacyBoundary :
      ActiveOutputPublicMetadataBoundary
        input
        shape
        bound
        statementFields
        bindingFields
        left
        right
        index
        publicCommitment
        publicCiphertextHash :=
    native_tx_leaf_active_output_ciphertext_privacy_game_public_metadata_boundary
      bindingAccepted
      surface
      slot
      game
      leftShape
      rightShape
  have privacyBoundaryCopy := privacyBoundary
  rcases privacyBoundary with
    ⟨leftWire,
      rightWire,
      summary,
      leftWireAt,
      rightWireAt,
      leftSummaryAt,
      _rightSummaryAt,
      leftParsed,
      rightParsed,
      summaryFormat,
      _metadata,
      _shapeFlag,
      shapeCommitment,
      _shapeCiphertext,
      _boundFlag,
      statementCommitment,
      _statementCiphertext,
      bindingCommitment,
      _bindingCiphertext,
      _ciphertextHashes,
      _ciphertextPayloadHashes,
      _outputCount,
      _outputFacts,
      _bindingFacts⟩
  have selectedSummary : summary = attempt.ciphertext := by
    have someEq : some summary = some attempt.ciphertext := by
      calc
        some summary =
            left.ciphertextSummaries[
              activeFlagCountBefore shape.outputFlags index]? :=
          leftSummaryAt.symm
        _ = some attempt.ciphertext := selectedAttempt
    exact Option.some.inj someEq
  subst summary
  have decryptBoundary :=
    decrypt_success_plaintext_to_commitment_boundary
      decryptAccepted
      exported
      published
  have commitmentAt :
      shape.commitments[index]? =
        some (commitmentFromPlaintext plaintext material) := by
    rw [← decryptBoundary.right.right.right.right]
    exact shapeCommitment
  have statementCommitmentAt :
      statementFields.commitmentSeeds[index]? =
        some (commitmentFromPlaintext plaintext material) := by
    rw [← decryptBoundary.right.right.right.right]
    exact statementCommitment
  have bindingCommitmentAt :
      bindingFields.commitmentSeeds[index]? =
        some (commitmentFromPlaintext plaintext material) := by
    rw [← decryptBoundary.right.right.right.right]
    exact bindingCommitment
  exact
    ⟨ciphertext_privacy_game_preserves_public_metadata_leakage game,
      ciphertext_privacy_game_preserves_batch_timing_leakage game,
      ciphertext_privacy_game_only_open_crypto_obligation game,
      decryptBoundary.left,
      decryptBoundary.right.left,
      decryptBoundary.right.right.left,
      decryptBoundary.right.right.right.left,
      decryptBoundary.right.right.right.right,
      commitmentAt,
      statementCommitmentAt,
      bindingCommitmentAt,
      ⟨leftWire,
        rightWire,
        leftWireAt,
        rightWireAt,
        leftParsed,
        rightParsed,
        summaryFormat,
        privacyBoundaryCopy⟩⟩

end NativeObserverSurface
end Privacy
end Hegemon

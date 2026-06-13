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

import Hegemon.Consensus.DaRoot
import Hegemon.Native.MaterializedSidecarDaBlobPublication

namespace Hegemon
namespace Native
namespace MaterializedConsensusDaBlobRefinement

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.MaterializedSidecarDaBlobPublication
open Hegemon.Native.RawIngressFullBytePublicationSurface
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

def u32Bound : Nat := 4294967296

structure MaterializedTransferActionRow where
  nullifiers : List Digest
  commitments : List Digest
  ciphertextHashes : List Digest
  ciphertextSizes : List Nat
  balanceTag : Digest
  circuitVersion : Nat
  cryptoVersion : Nat
deriving DecidableEq, Repr

structure MaterializedTransferPayloadRow where
  ciphertexts : List (List Byte)
deriving DecidableEq, Repr

structure MaterializedConsensusTransaction where
  nullifiers : List Digest
  commitments : List Digest
  ciphertextHashes : List Digest
  ciphertexts : List (List Byte)
  balanceTag : Digest
  circuitVersion : Nat
  cryptoVersion : Nat
deriving DecidableEq, Repr

structure MaterializedRowFeedsTransactionNew
    (action : MaterializedTransferActionRow)
    (payload : MaterializedTransferPayloadRow)
    (transaction : MaterializedConsensusTransaction) : Prop where
  nullifiersFromAction :
    transaction.nullifiers = action.nullifiers
  commitmentsFromAction :
    transaction.commitments = action.commitments
  ciphertextsFromPayload :
    transaction.ciphertexts = payload.ciphertexts
  ciphertextHashesFromAction :
    transaction.ciphertextHashes = action.ciphertextHashes
  ciphertextHashCountMatchesPayload :
    action.ciphertextHashes.length = payload.ciphertexts.length
  ciphertextSizeCountMatchesPayload :
    action.ciphertextSizes.length = payload.ciphertexts.length
  balanceTagFromTxLeaf :
    transaction.balanceTag = action.balanceTag
  circuitVersionFromAction :
    transaction.circuitVersion = action.circuitVersion
  cryptoVersionFromAction :
    transaction.cryptoVersion = action.cryptoVersion

structure MaterializedRowsFeedTransactionNew
    (actions : List MaterializedTransferActionRow)
    (payloads : List MaterializedTransferPayloadRow)
    (transactions : List MaterializedConsensusTransaction) : Prop where
  actionPayloadLengths :
    actions.length = payloads.length
  payloadTransactionLengths :
    payloads.length = transactions.length
  rowBinding :
    ∀ (index : Nat) action payload transaction,
      actions[index]? = some action →
      payloads[index]? = some payload →
      transactions[index]? = some transaction →
        MaterializedRowFeedsTransactionNew action payload transaction

def consensusDaPayload
    (transaction : MaterializedConsensusTransaction) :
    Consensus.DaRoot.TxDaPayload :=
  { ciphertexts := transaction.ciphertexts }

def consensusTransactionBytes
    (transaction : MaterializedConsensusTransaction) : List Byte :=
  u32le transaction.ciphertexts.length
    ++ transaction.ciphertexts.foldl
      (fun acc ciphertext =>
        acc ++ Consensus.DaRoot.ciphertextBytes ciphertext)
      []

structure TransactionNewFeedsConsensusDaPayload
    (transaction : MaterializedConsensusTransaction)
    (payload : Consensus.DaRoot.TxDaPayload) : Prop where
  ciphertextsFromTransaction :
    payload.ciphertexts = transaction.ciphertexts

structure TransactionNewFeedsConsensusDaBlob
    (transactions : List MaterializedConsensusTransaction)
    (payloads : List Consensus.DaRoot.TxDaPayload)
    (blobBytes : List Byte) : Prop where
  payloadCountMatchesTransactions :
    payloads.length = transactions.length
  payloadBinding :
    ∀ (index : Nat) transaction payload,
      transactions[index]? = some transaction →
      payloads[index]? = some payload →
        TransactionNewFeedsConsensusDaPayload transaction payload
  blobBytesEq :
    blobBytes = Consensus.DaRoot.daBlob payloads

def CiphertextRowsFitU32
    (ciphertexts : List (List Byte)) : Prop :=
  ciphertexts.length < u32Bound
    ∧ ∀ ciphertext, ciphertext ∈ ciphertexts →
        ciphertext.length < u32Bound

def TransactionsFitU32
    (transactions : List MaterializedConsensusTransaction) : Prop :=
  transactions.length < u32Bound
    ∧ ∀ transaction, transaction ∈ transactions →
        CiphertextRowsFitU32 transaction.ciphertexts

structure MaterializedConsensusDaBlobRefinementFacts
    (surface : RawIngressSidecarReplaySurface)
    (blockActionDecode : BlockActionDecodeInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput)
    (shape : PublicInputShape)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (actions : List MaterializedTransferActionRow)
    (payloads : List MaterializedTransferPayloadRow)
    (transactions : List MaterializedConsensusTransaction)
    (daPayloads : List Consensus.DaRoot.TxDaPayload)
    (blobBytes : List Byte) : Prop where
  materializedRowsFeedTransactionNew :
    MaterializedRowsFeedTransactionNew actions payloads transactions
  transactionNewFeedsConsensusDaBlob :
    TransactionNewFeedsConsensusDaBlob transactions daPayloads blobBytes
  blobBytesEq :
    blobBytes = Consensus.DaRoot.daBlob daPayloads
  transactionLengthBounds :
    TransactionsFitU32 transactions
  materializedSidecarRows :
    surface.transferState.sidecarCiphertextsAvailable = true
      ∧ surface.transferState.sidecarCiphertextSizesPresent = true
      ∧ surface.transferState.sidecarCiphertextSizesMatch = true
  wireReplayDaRowBinding :
    actionWireReplayProjectionPreconditions
      surface.daSidecarReplay.wireReplayProjection = true
      ∧ surface.daSidecarReplay.wireReplayProjection.actionCount =
        surface.daSidecarReplay.wireReplayProjection.plannedCount
      ∧ surface.daSidecarReplay.wireReplayProjection.actionCount =
        surface.daSidecarReplay.wireReplayProjection.actions.length
      ∧ wireOutput.projectedActionCount =
        blockActionDecode.actualActionPayloadCount
  candidateDaPublication :
    surface.daSidecarReplay.candidateBinding.daRootMatches = true
      ∧ surface.daSidecarReplay.candidateBinding.txStatementsCommitmentMatches =
        true
      ∧ surface.daSidecarReplay.candidateBinding.recursiveStateRootMatches =
        true
      ∧ surface.daSidecarReplay.candidateArtifact.txCount ≠ 0
      ∧ surface.daSidecarReplay.candidateArtifact.daChunkCount ≠ 0
  provenBatchDaPublication :
    surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
      ∧ surface.daSidecarReplay.provenBatchBinding.daChunkCount ≠ 0
  recursiveSemanticDaPublication :
    semanticFields.daRoot =
      surface.daSidecarReplay.recursiveSemanticSource.daRoot
  txLeafCiphertextPublication :
    txLeaf.ciphertextHashesMatch = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true
  statementCiphertextVectorPublication :
    shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds
  txLeafNativeStatementArtifactBinding :
    txLeaf.receiptStatementHashMatches = true
      ∧ txLeaf.publicInputsDigestMatches = true
      ∧ txLeaf.proofDigestMatches = true
      ∧ txLeaf.proofBackendMatches = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true
  acceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  commitmentRootPublication :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  replayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  finalReplaySetsUnique :
    final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup

theorem materialized_rows_feed_transaction_new_at
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
    {index : Nat}
    {action : MaterializedTransferActionRow}
    {payload : MaterializedTransferPayloadRow}
    {transaction : MaterializedConsensusTransaction}
    (rows :
      MaterializedRowsFeedTransactionNew actions payloads transactions)
    (actionAt : actions[index]? = some action)
    (payloadAt : payloads[index]? = some payload)
    (transactionAt : transactions[index]? = some transaction) :
    MaterializedRowFeedsTransactionNew action payload transaction :=
  rows.rowBinding index action payload transaction
    actionAt payloadAt transactionAt

theorem transaction_new_feeds_consensus_da_payload_at
    {transactions : List MaterializedConsensusTransaction}
    {payloads : List Consensus.DaRoot.TxDaPayload}
    {blobBytes : List Byte}
    {index : Nat}
    {transaction : MaterializedConsensusTransaction}
    {payload : Consensus.DaRoot.TxDaPayload}
    (binding :
      TransactionNewFeedsConsensusDaBlob
        transactions
        payloads
        blobBytes)
    (transactionAt : transactions[index]? = some transaction)
    (payloadAt : payloads[index]? = some payload) :
    TransactionNewFeedsConsensusDaPayload transaction payload :=
  binding.payloadBinding index transaction payload transactionAt payloadAt

theorem transaction_new_feeds_consensus_transaction_bytes
    {transaction : MaterializedConsensusTransaction}
    {payload : Consensus.DaRoot.TxDaPayload}
    (binding :
      TransactionNewFeedsConsensusDaPayload transaction payload) :
    Consensus.DaRoot.transactionBytes payload =
      consensusTransactionBytes transaction := by
  unfold Consensus.DaRoot.transactionBytes consensusTransactionBytes
  rw [binding.ciphertextsFromTransaction]

theorem transaction_new_feeds_consensus_da_blob_bytes
    {transactions : List MaterializedConsensusTransaction}
    {payloads : List Consensus.DaRoot.TxDaPayload}
    {blobBytes : List Byte}
    (binding :
      TransactionNewFeedsConsensusDaBlob
        transactions
        payloads
        blobBytes) :
    blobBytes = Consensus.DaRoot.daBlob payloads :=
  binding.blobBytesEq

theorem accepted_materialized_transfer_payloads_feed_transaction_new_da_blob
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
    {daPayloads : List Consensus.DaRoot.TxDaPayload}
    {blobBytes : List Byte}
    {daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    (publication :
      MaterializedSidecarDaBlobPublicationFacts
        surface
        pendingDecode
        blockActionDecode
        actionHash
        wireOutput
        semanticFields
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        blocks
        artifactBytes
        summary
        txLeaf
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
        (MaterializedRowsFeedTransactionNew
          actions
          payloads
          transactions)
        (TransactionNewFeedsConsensusDaBlob
          transactions
          daPayloads
          blobBytes)
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence)
    (u32Bounds : TransactionsFitU32 transactions) :
    MaterializedConsensusDaBlobRefinementFacts
      surface
      blockActionDecode
      wireOutput
      semanticFields
      initial
      final
      blocks
      txLeaf
      shape
      statementFields
      bindingFields
      actions
      payloads
      transactions
      daPayloads
      blobBytes := by
  exact
    { materializedRowsFeedTransactionNew :=
        publication.assumptions.materializedRowsFeedTransactionNewExplicit
      transactionNewFeedsConsensusDaBlob :=
        publication.assumptions.transactionNewFeedsConsensusDaBlobExplicit
      blobBytesEq :=
        publication.assumptions.transactionNewFeedsConsensusDaBlobExplicit.blobBytesEq
      transactionLengthBounds := u32Bounds
      materializedSidecarRows := publication.materializedSidecarRows
      wireReplayDaRowBinding := publication.wireReplayDaRowBinding
      candidateDaPublication := publication.candidateDaPublication
      provenBatchDaPublication := publication.provenBatchDaPublication
      recursiveSemanticDaPublication := publication.recursiveSemanticDaPublication
      txLeafCiphertextPublication := publication.txLeafCiphertextPublication
      statementCiphertextVectorPublication :=
        publication.statementCiphertextVectorPublication
      txLeafNativeStatementArtifactBinding :=
        publication.txLeafNativeStatementArtifactBinding
      acceptedLedgerTreeReplay := publication.acceptedLedgerTreeReplay
      commitmentRootPublication := publication.commitmentRootPublication
      replayedSupply := publication.replayedSupply
      finalReplaySetsUnique := publication.finalReplaySetsUnique }

end MaterializedConsensusDaBlobRefinement
end Native
end Hegemon

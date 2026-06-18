import Hegemon.Consensus.DaRoot
import Hegemon.Native.AcceptedBlockAdmissionSafety
import Hegemon.Native.CommitmentTreeContentRefinement
import Hegemon.Native.MaterializedSidecarDaBlobPublication
import Hegemon.Native.MaterializedTransferNoTheftPublication
import Hegemon.Privacy.NativeSidecarObserverSurface

namespace Hegemon
namespace Native
namespace MaterializedConsensusDaBlobRefinement

open Hegemon.Native.AcceptedChain
open Hegemon.Native.AcceptedBlockAdmissionSafety
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.CommitmentTreeContentRefinement
open Hegemon.Native.MaterializedSidecarDaBlobPublication
open Hegemon.Native.MaterializedTransferNoTheftPublication
open Hegemon.Native.RawIngressFullBytePublicationSurface
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StablecoinPolicyAuthorization
open Hegemon.Native.StablecoinPolicyLiveAuthorization
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TransferActionPayloadAdmission
open Hegemon.Native.TransferNoTheftBoundary
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Privacy.CiphertextPrivacy
open Hegemon.Privacy.NativeObserverSurface
open Hegemon.Privacy.NativeSidecarObserverSurface
open Hegemon.Privacy.Observer
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SmallWoodVerifierSoundnessEnvelope
open Hegemon.Wallet.NoteCiphertextDecrypt
open Hegemon.Wallet.NotePlaintextCommitment

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

theorem consensus_da_payload_transaction_bytes
    (transaction : MaterializedConsensusTransaction) :
    Consensus.DaRoot.transactionBytes (consensusDaPayload transaction) =
      consensusTransactionBytes transaction := by
  rfl

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

def MaterializedSidecarOpenAssumptionPrivacyBoundary
    (sidecarSurface : RawIngressSidecarReplaySurface)
    (blockActionDecode : BlockActionDecodeInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput)
    (shape : PublicInputShape)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (left right : ShieldedTransactionWorld)
    (assumptions : PrivacyBoundaryAssumptions)
    (mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness : Prop)
    (game : CiphertextPrivacyGame left right) : Prop :=
  (sidecarSurface.transferState.sidecarCiphertextsAvailable = true
    ∧ sidecarSurface.transferState.sidecarCiphertextSizesPresent = true
    ∧ sidecarSurface.transferState.sidecarCiphertextSizesMatch = true)
    ∧ (actionWireReplayProjectionPreconditions
        sidecarSurface.daSidecarReplay.wireReplayProjection = true
      ∧ sidecarSurface.daSidecarReplay.wireReplayProjection.actionCount =
        sidecarSurface.daSidecarReplay.wireReplayProjection.plannedCount
      ∧ sidecarSurface.daSidecarReplay.wireReplayProjection.actionCount =
        sidecarSurface.daSidecarReplay.wireReplayProjection.actions.length
      ∧ wireOutput.projectedActionCount =
        blockActionDecode.actualActionPayloadCount)
    ∧ (txLeaf.ciphertextHashesMatch = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true)
    ∧ (shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds)
    ∧ CiphertextPrivacyOpenAssumptionBoundaryFacts
      left
      right
      game.wireIndistinguishable
      assumptions
    ∧ ∀ index publicCommitment publicCiphertextHash
        attempt plaintext material data,
      OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        1
        publicCommitment
        publicCiphertextHash ->
      left.ciphertextSummaries[
        activeFlagCountBefore shape.outputFlags index]? =
          some attempt.ciphertext ->
      evaluateDecrypt attempt = none ->
      data = exportNoteData plaintext material ->
      publicCommitment = commitmentFromNoteData data ->
      (ciphertextHashMatches : List Byte → Digest → Prop) ->
      (∀ {wire summary daBytes},
        left.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? = some wire ->
          Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            wire = some summary ->
          Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            wire = some daBytes ->
          ciphertextHashMatches daBytes publicCiphertextHash) ->
      (∀ {wire summary daBytes},
        right.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? = some wire ->
          Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            wire = some summary ->
          Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            wire = some daBytes ->
          ciphertextHashMatches daBytes publicCiphertextHash) ->
      ActiveOutputDecryptDaCommitmentFacts
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        game.wireIndistinguishable
        txLeaf
        shape
        statementFields
        bindingFields
        left
        right
        index
        publicCommitment
        publicCiphertextHash
        attempt
        plaintext
        material
        ciphertextHashMatches

structure TransferFilteredMaterializedTransactionProjectionFacts
    (blockActionDecode : BlockActionDecodeInput)
    (validationSummary : BlockActionValidationSummary)
    (wireOutput : ActionWireReplayProjectionOutput)
    (actions : List MaterializedTransferActionRow)
    (payloads : List MaterializedTransferPayloadRow)
    (transactions : List MaterializedConsensusTransaction) : Prop where
  decodedNativeActionsMatchWireRows :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
  validatedActionsMatchWireRows :
    wireOutput.projectedActionCount =
      validationSummary.validatedActionCount
  materializedActionsMatchWireRows :
    wireOutput.projectedActionCount = actions.length
  materializedPayloadsMatchWireRows :
    wireOutput.projectedActionCount = payloads.length
  payloadRowsMatchTransactionRows :
    payloads.length = transactions.length
  rowBinding :
    ∀ (index : Nat) action payload transaction,
      actions[index]? = some action →
      payloads[index]? = some payload →
      transactions[index]? = some transaction →
        MaterializedRowFeedsTransactionNew action payload transaction

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

theorem transaction_new_feeds_concrete_consensus_da_blob
    (transactions : List MaterializedConsensusTransaction) :
    TransactionNewFeedsConsensusDaBlob
      transactions
      (transactions.map consensusDaPayload)
      (Consensus.DaRoot.daBlob (transactions.map consensusDaPayload)) := by
  refine
    { payloadCountMatchesTransactions := by simp
      payloadBinding := ?_
      blobBytesEq := rfl }
  intro index transaction payload transactionAt payloadAt
  have mappedAt :
      (transactions.map consensusDaPayload)[index]? =
        some (consensusDaPayload transaction) := by
    rw [List.getElem?_map, transactionAt]
    rfl
  rw [payloadAt] at mappedAt
  injection mappedAt with payloadEq
  subst payload
  exact { ciphertextsFromTransaction := rfl }

theorem raw_ingress_production_projection_lifts_transfer_filter_facts
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
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
    (productionProjection :
      RawIngressFullByteProductionProjectionFacts
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
        validation
        validationSummary
        actions.length
        payloads.length)
    (payloadRowsMatchTransactionRows :
      payloads.length = transactions.length)
    (rowBinding :
      ∀ (index : Nat) action payload transaction,
        actions[index]? = some action →
        payloads[index]? = some payload →
        transactions[index]? = some transaction →
          MaterializedRowFeedsTransactionNew action payload transaction) :
    TransferFilteredMaterializedTransactionProjectionFacts
      blockActionDecode
      validationSummary
      wireOutput
      actions
      payloads
      transactions :=
  {
    decodedNativeActionsMatchWireRows :=
      productionProjection.fullByteRowsMatchDecodedPayloads,
    validatedActionsMatchWireRows :=
      productionProjection.replayRowsMatchValidatedActions,
    materializedActionsMatchWireRows :=
      productionProjection.wireRowsMatchMaterializedActions,
    materializedPayloadsMatchWireRows :=
      productionProjection.wireRowsMatchMaterializedPayloads,
    payloadRowsMatchTransactionRows :=
      payloadRowsMatchTransactionRows,
    rowBinding := rowBinding
  }

theorem transfer_filtered_projection_rows_feed_transaction_new
    {blockActionDecode : BlockActionDecodeInput}
    {validationSummary : BlockActionValidationSummary}
    {wireOutput : ActionWireReplayProjectionOutput}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
    (projection :
      TransferFilteredMaterializedTransactionProjectionFacts
        blockActionDecode
        validationSummary
        wireOutput
        actions
        payloads
        transactions) :
    MaterializedRowsFeedTransactionNew
      actions
      payloads
      transactions := by
  refine
    { actionPayloadLengths := ?_
      payloadTransactionLengths :=
        projection.payloadRowsMatchTransactionRows
      rowBinding := projection.rowBinding }
  calc
    actions.length = wireOutput.projectedActionCount :=
      projection.materializedActionsMatchWireRows.symm
    _ = payloads.length :=
      projection.materializedPayloadsMatchWireRows

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

theorem accepted_materialized_transfer_payloads_feed_concrete_consensus_da_blob
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
        True
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
      (transactions.map consensusDaPayload)
      (Consensus.DaRoot.daBlob (transactions.map consensusDaPayload)) := by
  exact
    { materializedRowsFeedTransactionNew :=
        publication.assumptions.materializedRowsFeedTransactionNewExplicit
      transactionNewFeedsConsensusDaBlob :=
        transaction_new_feeds_concrete_consensus_da_blob transactions
      blobBytesEq := rfl
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

theorem accepted_materialized_transfer_projection_rows_feed_concrete_consensus_da_blob
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
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
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
        True
        True
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence)
    (productionProjection :
      RawIngressFullByteProductionProjectionFacts
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
        validation
        validationSummary
        actions.length
        payloads.length)
    (payloadRowsMatchTransactionRows :
      payloads.length = transactions.length)
    (rowBinding :
      ∀ (index : Nat) action payload transaction,
        actions[index]? = some action →
        payloads[index]? = some payload →
        transactions[index]? = some transaction →
          MaterializedRowFeedsTransactionNew action payload transaction)
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
      (transactions.map consensusDaPayload)
      (Consensus.DaRoot.daBlob (transactions.map consensusDaPayload)) := by
  have projection :
      TransferFilteredMaterializedTransactionProjectionFacts
        blockActionDecode
        validationSummary
        wireOutput
        actions
        payloads
        transactions :=
    raw_ingress_production_projection_lifts_transfer_filter_facts
      productionProjection
      payloadRowsMatchTransactionRows
      rowBinding
  exact
    { materializedRowsFeedTransactionNew :=
        transfer_filtered_projection_rows_feed_transaction_new projection
      transactionNewFeedsConsensusDaBlob :=
        transaction_new_feeds_concrete_consensus_da_blob transactions
      blobBytesEq := rfl
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

structure MaterializedTransferSmallWoodConsensusDaBlobPublicationFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (payload : TransferPayloadInput)
    (transferKey : Nat)
    (txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (balanceWitness : Hegemon.Transaction.BalanceWitness)
    (slots : List Hegemon.Transaction.BalanceSlot)
    (assetId index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (candidateWrapper :
      Hegemon.Transaction.SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput)
    (publicStatement :
      Hegemon.Transaction.SmallWoodPublicStatementBinding.PublicStatementSurface)
    (authSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveAuthLinkSurface)
    (inputSpendSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface)
    (outputSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveOutputBindingSurface)
    (smallwoodBalanceSurface :
      Hegemon.Transaction.SmallWoodBalanceBoundary.BalanceSurface)
    (airBalanceSurface :
      Hegemon.Transaction.AirBalanceBoundary.AirBalanceFinalRowSurface)
    (policyInput : StablecoinPolicyAuthorizationInput)
    (productionPayload : StablecoinMintExceptionPayload)
    (validation : BlockActionValidationInput)
    (validationSummary : BlockActionValidationSummary)
    (actions : List MaterializedTransferActionRow)
    (payloads : List MaterializedTransferPayloadRow)
    (transactions : List MaterializedConsensusTransaction)
    (daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop) : Prop where
  transferPublication :
    MaterializedTransferNoTheftPublicationFacts
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
      payload
      transferKey
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
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
      True
      True
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence
  consensusDaBlobRefinement :
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
      (transactions.map consensusDaPayload)
      (Consensus.DaRoot.daBlob (transactions.map consensusDaPayload))
  smallwoodVerifierExport :
    SmallWoodPublicStatementVerifierExportFacts
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
      slots
      candidateWrapper
      publicStatement
      authSurface
      inputSpendSurface
      outputSurface
      smallwoodBalanceSurface
      airBalanceSurface
  authorizedAssetDeltaValue :
    Hegemon.Transaction.slotDelta assetId slots =
      publicAuthorizedAssetDeltaValue publicFields assetId
  authorizedStablecoinExceptionSurface :
    AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      (Hegemon.Transaction.slotDelta assetId slots)
      (nativeStablecoinLivePolicyAuthorizes
        policyInput
        productionPayload)
  nativeStablecoinLiveAuthorization :
    NativeStablecoinLiveAuthorizationFacts
      policyInput
      productionPayload
  transactionLengthBounds :
    TransactionsFitU32 transactions

theorem accepted_materialized_transfer_smallwood_consensus_da_blob_certificate
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
    {payload : TransferPayloadInput}
    {transferKey : Nat}
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
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {candidateWrapper :
      Hegemon.Transaction.SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
    {publicStatement :
      Hegemon.Transaction.SmallWoodPublicStatementBinding.PublicStatementSurface}
    {authSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveAuthLinkSurface}
    {inputSpendSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface}
    {outputSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveOutputBindingSurface}
    {smallwoodBalanceSurface :
      Hegemon.Transaction.SmallWoodBalanceBoundary.BalanceSurface}
    {airBalanceSurface :
      Hegemon.Transaction.AirBalanceBoundary.AirBalanceFinalRowSurface}
    {policyInput : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
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
        True
        True
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence)
    (productionProjection :
      RawIngressFullByteProductionProjectionFacts
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
        validation
        validationSummary
        actions.length
        payloads.length)
    (payloadRowsMatchTransactionRows :
      payloads.length = transactions.length)
    (rowBinding :
      ∀ (index : Nat) action payload transaction,
        actions[index]? = some action →
        payloads[index]? = some payload →
        transactions[index]? = some transaction →
          MaterializedRowFeedsTransactionNew action payload transaction)
    (u32Bounds : TransactionsFitU32 transactions)
    (payloadAccepted :
      transferPayloadAccepts payload = true)
    (txLeafAccepted :
      BlockArtifactBindingAdmission.txLeafActionBindingAccepts txLeaf = true)
    (smallwoodExport :
      SmallWoodPublicStatementVerifierExportFacts
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
        slots
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1)
    (nonNative : assetId ≠ Hegemon.Transaction.nativeAsset)
    (nonzero : Hegemon.Transaction.slotDelta assetId slots ≠ 0)
    (present : policyInput.stablecoinPresent = true)
    (policyAccepted :
      stablecoinPolicyAuthorizationAccepts policyInput = true)
    (exactPayload :
      productionPayload =
        stablecoinMintExceptionPayload
          publicFields
          assetId
          (Hegemon.Transaction.slotDelta assetId slots)) :
    MaterializedTransferSmallWoodConsensusDaBlobPublicationFacts
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
      payload
      transferKey
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
      spendWitnesses
      balanceWitness
      slots
      assetId
      index
      activeFlag
      publicNullifier
      witness
      candidateWrapper
      publicStatement
      authSurface
      inputSpendSurface
      outputSurface
      smallwoodBalanceSurface
      airBalanceSurface
      policyInput
      productionPayload
      validation
      validationSummary
      actions
      payloads
      transactions
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence := by
  have transferCertificate :=
    accepted_materialized_transfer_publication_from_smallwood_native_policy_certificate
      (transferKey := transferKey)
      (materializedFacts := publication)
      (payloadAccepted := payloadAccepted)
      (txLeafAccepted := txLeafAccepted)
      (smallwoodExport := smallwoodExport)
      (slot := slot)
      (active := active)
      (nonNative := nonNative)
      (nonzero := nonzero)
      (present := present)
      (policyAccepted := policyAccepted)
      (exactPayload := exactPayload)
  rcases transferCertificate with
    ⟨transferPublication,
      smallwoodVerifierExport,
      authorizedAssetDeltaValue,
      authorizedStablecoinExceptionSurface,
      nativeStablecoinLiveAuthorization⟩
  have consensusCertificate :=
    accepted_materialized_transfer_projection_rows_feed_concrete_consensus_da_blob
      (publication := publication)
      (productionProjection := productionProjection)
      (payloadRowsMatchTransactionRows := payloadRowsMatchTransactionRows)
      (rowBinding := rowBinding)
      (u32Bounds := u32Bounds)
  exact
    { transferPublication := transferPublication
      consensusDaBlobRefinement := consensusCertificate
      smallwoodVerifierExport := smallwoodVerifierExport
      authorizedAssetDeltaValue := authorizedAssetDeltaValue
      authorizedStablecoinExceptionSurface :=
        authorizedStablecoinExceptionSurface
      nativeStablecoinLiveAuthorization :=
        nativeStablecoinLiveAuthorization
      transactionLengthBounds :=
        consensusCertificate.transactionLengthBounds }

theorem materialized_transfer_smallwood_consensus_da_blob_certificate_implies_admission_safety
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
    {payload : TransferPayloadInput}
    {transferKey : Nat}
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
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {candidateWrapper :
      Hegemon.Transaction.SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
    {publicStatement :
      Hegemon.Transaction.SmallWoodPublicStatementBinding.PublicStatementSurface}
    {authSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveAuthLinkSurface}
    {inputSpendSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface}
    {outputSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveOutputBindingSurface}
    {smallwoodBalanceSurface :
      Hegemon.Transaction.SmallWoodBalanceBoundary.BalanceSurface}
    {airBalanceSurface :
      Hegemon.Transaction.AirBalanceBoundary.AirBalanceFinalRowSurface}
    {policyInput : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
    {daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    (certificate :
      MaterializedTransferSmallWoodConsensusDaBlobPublicationFacts
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
        payload
        transferKey
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
        spendWitnesses
        balanceWitness
        slots
        assetId
        index
        activeFlag
        publicNullifier
        witness
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface
        policyInput
        productionPayload
        validation
        validationSummary
        actions
        payloads
        transactions
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence) :
    AcceptedBlockAdmissionSafetyFacts
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
      merkleRoot :=
  raw_ingress_full_byte_publication_facts_imply_accepted_block_admission_safety
    certificate.transferPublication.materializedDaPublicationFacts.fullBytePublication

structure AcceptedMaterializedTransferEndToEndSecurityBoundaryFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (payload : TransferPayloadInput)
    (transferKey : Nat)
    (txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (balanceWitness : Hegemon.Transaction.BalanceWitness)
    (slots : List Hegemon.Transaction.BalanceSlot)
    (assetId index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (candidateWrapper :
      Hegemon.Transaction.SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput)
    (publicStatement :
      Hegemon.Transaction.SmallWoodPublicStatementBinding.PublicStatementSurface)
    (authSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveAuthLinkSurface)
    (inputSpendSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface)
    (outputSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveOutputBindingSurface)
    (smallwoodBalanceSurface :
      Hegemon.Transaction.SmallWoodBalanceBoundary.BalanceSurface)
    (airBalanceSurface :
      Hegemon.Transaction.AirBalanceBoundary.AirBalanceFinalRowSurface)
    (policyInput : StablecoinPolicyAuthorizationInput)
    (productionPayload : StablecoinMintExceptionPayload)
    (validation : BlockActionValidationInput)
    (validationSummary : BlockActionValidationSummary)
    (actions : List MaterializedTransferActionRow)
    (payloads : List MaterializedTransferPayloadRow)
    (transactions : List MaterializedConsensusTransaction)
    (daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop)
    (left right : ShieldedTransactionWorld)
    (assumptions : PrivacyBoundaryAssumptions)
    (mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness : Prop)
    (game : CiphertextPrivacyGame left right) : Prop where
  certificate :
    MaterializedTransferSmallWoodConsensusDaBlobPublicationFacts
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
      payload
      transferKey
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
      spendWitnesses
      balanceWitness
      slots
      assetId
      index
      activeFlag
      publicNullifier
      witness
      candidateWrapper
      publicStatement
      authSurface
      inputSpendSurface
      outputSurface
      smallwoodBalanceSurface
      airBalanceSurface
      policyInput
      productionPayload
      validation
      validationSummary
      actions
      payloads
      transactions
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence
  admissionSafety :
    AcceptedBlockAdmissionSafetyFacts
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
  privacyBoundary :
    MaterializedSidecarOpenAssumptionPrivacyBoundary
      surface
      blockActionDecode
      wireOutput
      txLeaf
      shape
      statementFields
      bindingFields
      left
      right
      assumptions
      mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness
      game
  replayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
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
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup
  activeInputNoTheftFullBinding :
    ActiveInputNoTheftFullBinding
      payload
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
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
  inputSlotAuthorizationFullBinding :
    InputSlotAuthorizationFullBinding
      payload
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
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
  smallwoodVerifierExport :
    SmallWoodPublicStatementVerifierExportFacts
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
      slots
      candidateWrapper
      publicStatement
      authSurface
      inputSpendSurface
      outputSurface
      smallwoodBalanceSurface
      airBalanceSurface
  authorizedAssetDeltaValue :
    Hegemon.Transaction.slotDelta assetId slots =
      publicAuthorizedAssetDeltaValue publicFields assetId
  authorizedStablecoinExceptionSurface :
    AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      (Hegemon.Transaction.slotDelta assetId slots)
      (nativeStablecoinLivePolicyAuthorizes
        policyInput
        productionPayload)
  nativeStablecoinLiveAuthorization :
    NativeStablecoinLiveAuthorizationFacts
      policyInput
      productionPayload
  consensusDaBlobRefinement :
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
      (transactions.map consensusDaPayload)
      (Consensus.DaRoot.daBlob (transactions.map consensusDaPayload))
  txLeafStatementArtifactFacts :
    NativeTxLeafFullStatementArtifactFacts
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
  txLeafNativeStatementArtifactBinding :
    txLeaf.receiptStatementHashMatches = true
      ∧ txLeaf.publicInputsDigestMatches = true
      ∧ txLeaf.proofDigestMatches = true
      ∧ txLeaf.proofBackendMatches = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true
  txLeafCiphertextPublication :
    txLeaf.ciphertextHashesMatch = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true
  statementCiphertextVectorPublication :
    shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds
  materializedSidecarRows :
    surface.transferState.sidecarCiphertextsAvailable = true
      ∧ surface.transferState.sidecarCiphertextSizesPresent = true
      ∧ surface.transferState.sidecarCiphertextSizesMatch = true
  transactionLengthBounds :
    TransactionsFitU32 transactions

theorem materialized_transfer_smallwood_consensus_da_blob_certificate_implies_end_to_end_security_boundary
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
    {payload : TransferPayloadInput}
    {transferKey : Nat}
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
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {candidateWrapper :
      Hegemon.Transaction.SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
    {publicStatement :
      Hegemon.Transaction.SmallWoodPublicStatementBinding.PublicStatementSurface}
    {authSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveAuthLinkSurface}
    {inputSpendSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface}
    {outputSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveOutputBindingSurface}
    {smallwoodBalanceSurface :
      Hegemon.Transaction.SmallWoodBalanceBoundary.BalanceSurface}
    {airBalanceSurface :
      Hegemon.Transaction.AirBalanceBoundary.AirBalanceFinalRowSurface}
    {policyInput : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
    {daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    {left right : ShieldedTransactionWorld}
    {assumptions : PrivacyBoundaryAssumptions}
    {mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness : Prop}
    {game : CiphertextPrivacyGame left right}
    (certificate :
      MaterializedTransferSmallWoodConsensusDaBlobPublicationFacts
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
        payload
        transferKey
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
        spendWitnesses
        balanceWitness
        slots
        assetId
        index
        activeFlag
        publicNullifier
        witness
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface
        policyInput
        productionPayload
        validation
        validationSummary
        actions
        payloads
        transactions
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence)
    (privacyBoundary :
      MaterializedSidecarOpenAssumptionPrivacyBoundary
        surface
        blockActionDecode
        wireOutput
        txLeaf
        shape
        statementFields
        bindingFields
        left
        right
        assumptions
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        game) :
    AcceptedMaterializedTransferEndToEndSecurityBoundaryFacts
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
      payload
      transferKey
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
      spendWitnesses
      balanceWitness
      slots
      assetId
      index
      activeFlag
      publicNullifier
      witness
      candidateWrapper
      publicStatement
      authSurface
      inputSpendSurface
      outputSurface
      smallwoodBalanceSurface
      airBalanceSurface
      policyInput
      productionPayload
      validation
      validationSummary
      actions
      payloads
      transactions
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence
      left
      right
      assumptions
      mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness
      game := by
  exact
    {
      certificate := certificate,
      admissionSafety :=
        materialized_transfer_smallwood_consensus_da_blob_certificate_implies_admission_safety
          certificate,
      privacyBoundary := privacyBoundary,
      replayedSupply :=
        certificate.transferPublication.replayedSupply,
      acceptedLedgerTreeReplay :=
        certificate.transferPublication.acceptedLedgerTreeReplay,
      commitmentRootPublication :=
        certificate.transferPublication.commitmentRootPublication,
      finalSpentNullifiersUnique :=
        certificate.transferPublication.finalReplaySetsUnique.left,
      finalBridgeReplaysUnique :=
        certificate.transferPublication.finalReplaySetsUnique.right,
      activeInputNoTheftFullBinding :=
        certificate.transferPublication.activeInputNoTheftFullBinding,
      inputSlotAuthorizationFullBinding :=
        certificate.transferPublication.inputSlotAuthorizationFullBinding,
      smallwoodVerifierExport :=
        certificate.smallwoodVerifierExport,
      authorizedAssetDeltaValue :=
        certificate.authorizedAssetDeltaValue,
      authorizedStablecoinExceptionSurface :=
        certificate.authorizedStablecoinExceptionSurface,
      nativeStablecoinLiveAuthorization :=
        certificate.nativeStablecoinLiveAuthorization,
      consensusDaBlobRefinement :=
        certificate.consensusDaBlobRefinement,
      txLeafStatementArtifactFacts :=
        certificate.transferPublication.txLeafStatementArtifactFacts,
      txLeafNativeStatementArtifactBinding :=
        certificate.consensusDaBlobRefinement.txLeafNativeStatementArtifactBinding,
      txLeafCiphertextPublication :=
        certificate.transferPublication.txLeafCiphertextPublication,
      statementCiphertextVectorPublication :=
        certificate.transferPublication.statementCiphertextVectorPublication,
      materializedSidecarRows :=
        certificate.consensusDaBlobRefinement.materializedSidecarRows,
      transactionLengthBounds :=
        certificate.transactionLengthBounds
    }

structure MaterializedTransferHighestStandardCoreReviewFacts
    (noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety : Prop) : Prop where
  noCounterfeiting : noCounterfeiting
  acceptedLedgerReplay : acceptedLedgerReplay
  commitmentRootPublication : commitmentRootPublication
  noDoubleSpend : noDoubleSpend
  bridgeReplayUnique : bridgeReplayUnique
  activeInputNoTheft : activeInputNoTheft
  totalInputAuthorization : totalInputAuthorization
  smallwoodVerifierExport : smallwoodVerifierExport
  authorizedPerAssetDelta : authorizedPerAssetDelta
  authorizedStablecoinException : authorizedStablecoinException
  nativeStablecoinPolicyLive : nativeStablecoinPolicyLive
  consensusDaBlobRefinement : consensusDaBlobRefinement
  txLeafStatementArtifact : txLeafStatementArtifact
  txLeafNativeStatementArtifact : txLeafNativeStatementArtifact
  txLeafCiphertextPublication : txLeafCiphertextPublication
  statementCiphertextVectorPublication : statementCiphertextVectorPublication
  sidecarMaterialization : sidecarMaterialization
  privacyBoundary : privacyBoundary
  admissionSafety : admissionSafety

theorem accepted_materialized_transfer_end_to_end_boundary_exposes_highest_standard_core_review
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
    {payload : TransferPayloadInput}
    {transferKey : Nat}
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
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {candidateWrapper :
      Hegemon.Transaction.SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
    {publicStatement :
      Hegemon.Transaction.SmallWoodPublicStatementBinding.PublicStatementSurface}
    {authSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveAuthLinkSurface}
    {inputSpendSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface}
    {outputSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveOutputBindingSurface}
    {smallwoodBalanceSurface :
      Hegemon.Transaction.SmallWoodBalanceBoundary.BalanceSurface}
    {airBalanceSurface :
      Hegemon.Transaction.AirBalanceBoundary.AirBalanceFinalRowSurface}
    {policyInput : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
    {daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    {left right : ShieldedTransactionWorld}
    {assumptions : PrivacyBoundaryAssumptions}
    {mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness : Prop}
    {game : CiphertextPrivacyGame left right}
    (boundary :
      AcceptedMaterializedTransferEndToEndSecurityBoundaryFacts
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
        payload
        transferKey
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
        spendWitnesses
        balanceWitness
        slots
        assetId
        index
        activeFlag
        publicNullifier
        witness
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface
        policyInput
        productionPayload
        validation
        validationSummary
        actions
        payloads
        transactions
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence
        left
        right
        assumptions
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        game) :
    MaterializedTransferHighestStandardCoreReviewFacts
      (expectedNativeSupplyAfter
        initial.ledger.supply
        (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
        some final.ledger.supply)
      (validateNativeLedgerTreeReplayChain
        initial
        (rawTreeReplayInputs blocks) =
        some final)
      (expectedCommitmentRootAfter
        initial.commitmentRoot
        (rawTreeReplayInputs blocks) =
        some final.commitmentRoot)
      final.ledger.spentNullifiers.Nodup
      final.ledger.consumedBridgeReplays.Nodup
      (ActiveInputNoTheftFullBinding
        payload
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
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
      (InputSlotAuthorizationFullBinding
        payload
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
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
      (SmallWoodPublicStatementVerifierExportFacts
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
        slots
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface)
      (Hegemon.Transaction.slotDelta assetId slots =
        publicAuthorizedAssetDeltaValue publicFields assetId)
      (AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        (Hegemon.Transaction.slotDelta assetId slots)
        (nativeStablecoinLivePolicyAuthorizes
          policyInput
          productionPayload))
      (NativeStablecoinLiveAuthorizationFacts
        policyInput
        productionPayload)
      (MaterializedConsensusDaBlobRefinementFacts
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
        (transactions.map consensusDaPayload)
        (Consensus.DaRoot.daBlob (transactions.map consensusDaPayload)))
      (NativeTxLeafFullStatementArtifactFacts
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
        merkleRoot)
      (txLeaf.receiptStatementHashMatches = true
        ∧ txLeaf.publicInputsDigestMatches = true
        ∧ txLeaf.proofDigestMatches = true
        ∧ txLeaf.proofBackendMatches = true
        ∧ txLeaf.ciphertextPayloadHashesMatch = true)
      (txLeaf.ciphertextHashesMatch = true
        ∧ txLeaf.ciphertextPayloadHashesMatch = true)
      (shape.ciphertextHashes = statementFields.ciphertextHashSeeds
        ∧ bindingFields.ciphertextHashSeeds =
          statementFields.ciphertextHashSeeds)
      (surface.transferState.sidecarCiphertextsAvailable = true
        ∧ surface.transferState.sidecarCiphertextSizesPresent = true
        ∧ surface.transferState.sidecarCiphertextSizesMatch = true)
      (MaterializedSidecarOpenAssumptionPrivacyBoundary
        surface
        blockActionDecode
        wireOutput
        txLeaf
        shape
        statementFields
        bindingFields
        left
        right
        assumptions
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        game)
      (AcceptedBlockAdmissionSafetyFacts
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
        merkleRoot) := by
  exact
    {
      noCounterfeiting := boundary.replayedSupply
      acceptedLedgerReplay := boundary.acceptedLedgerTreeReplay
      commitmentRootPublication := boundary.commitmentRootPublication
      noDoubleSpend := boundary.finalSpentNullifiersUnique
      bridgeReplayUnique := boundary.finalBridgeReplaysUnique
      activeInputNoTheft := boundary.activeInputNoTheftFullBinding
      totalInputAuthorization := boundary.inputSlotAuthorizationFullBinding
      smallwoodVerifierExport := boundary.smallwoodVerifierExport
      authorizedPerAssetDelta := boundary.authorizedAssetDeltaValue
      authorizedStablecoinException :=
        boundary.authorizedStablecoinExceptionSurface
      nativeStablecoinPolicyLive :=
        boundary.nativeStablecoinLiveAuthorization
      consensusDaBlobRefinement := boundary.consensusDaBlobRefinement
      txLeafStatementArtifact := boundary.txLeafStatementArtifactFacts
      txLeafNativeStatementArtifact :=
        boundary.txLeafNativeStatementArtifactBinding
      txLeafCiphertextPublication := boundary.txLeafCiphertextPublication
      statementCiphertextVectorPublication :=
        boundary.statementCiphertextVectorPublication
      sidecarMaterialization := boundary.materializedSidecarRows
      privacyBoundary := boundary.privacyBoundary
      admissionSafety := boundary.admissionSafety
    }

variable {surface : RawIngressSidecarReplaySurface}
variable {pendingDecode : ExactDecodeInput}
variable {blockActionDecode : BlockActionDecodeInput}
variable {actionHash : AdmissionInput}
variable {wireOutput : ActionWireReplayProjectionOutput}
variable {semanticFields :
  Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
variable {blockIndex : BlockIndexReloadInput}
variable {canonicalState : CanonicalStateReloadInput}
variable {reorgChain : CanonicalReorgChainInput}
variable {commitManifest : AtomicCommitManifestInput}
variable {durability : StorageDurabilityInput}
variable {initial final : NativeLedgerTreeReplayState}
variable {blocks : List RawDecodedNativeTreeReplayBlock}
variable {artifactBytes : List Byte}
variable {summary : TxLeafSummary}
variable {payload : TransferPayloadInput}
variable {transferKey : Nat}
variable {txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput}
variable {wrapper : ProofWrapperInput}
variable {shape : PublicInputShape}
variable {publicFields :
  Hegemon.Transaction.PublicInputBinding.PublicFields}
variable {serializedFields :
  Hegemon.Transaction.PublicInputBinding.SerializedFields}
variable {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
variable {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
variable {statementBytes : List Byte}
variable {bindingFields :
  Hegemon.Transaction.ProofStatementBinding.BindingFields}
variable {bindingBytes : List Byte}
variable {merkleRoot : Digest}
variable {spendWitnesses :
  List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
variable {balanceWitness : Hegemon.Transaction.BalanceWitness}
variable {slots : List Hegemon.Transaction.BalanceSlot}
variable {assetId index activeFlag : Nat}
variable {publicNullifier : Digest}
variable {witness :
  Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
variable {candidateWrapper :
  Hegemon.Transaction.SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
variable {publicStatement :
  Hegemon.Transaction.SmallWoodPublicStatementBinding.PublicStatementSurface}
variable {authSurface :
  Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveAuthLinkSurface}
variable {inputSpendSurface :
  Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface}
variable {outputSurface :
  Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveOutputBindingSurface}
variable {smallwoodBalanceSurface :
  Hegemon.Transaction.SmallWoodBalanceBoundary.BalanceSurface}
variable {airBalanceSurface :
  Hegemon.Transaction.AirBalanceBoundary.AirBalanceFinalRowSurface}
variable {policyInput : StablecoinPolicyAuthorizationInput}
variable {productionPayload : StablecoinMintExceptionPayload}
variable {validation : BlockActionValidationInput}
variable {validationSummary : BlockActionValidationSummary}
variable {actions : List MaterializedTransferActionRow}
variable {payloads : List MaterializedTransferPayloadRow}
variable {transactions : List MaterializedConsensusTransaction}
variable {daRootHashSecurityEquivalence
  daAvailability
  proofSystemSoundness
  completeNativeNodeEquivalence : Prop}
variable {left right : ShieldedTransactionWorld}
variable {assumptions : PrivacyBoundaryAssumptions}
variable {mlKemIndistinguishability
  aeadCiphertextConfidentiality
  kdfDomainSeparation
  rngFreshness : Prop}
variable {game : CiphertextPrivacyGame left right}
variable {materializedActionCount materializedPayloadCount : Nat}
variable {decodedRows validationRows materializedRows plannedRows wireRows :
  List PendingActionByteReplayRowCountBinding.PendingActionFieldProjectionRow}
variable {canonicalRows :
  PendingActionByteReplayRowCountBinding.PendingActionCanonicalFieldRows}
variable {depth historyLimit : Nat}

structure MaterializedTransferLedgerIntegrityEndToEndReviewFacts
    (boundary :
      AcceptedMaterializedTransferEndToEndSecurityBoundaryFacts
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
        payload
        transferKey
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
        spendWitnesses
        balanceWitness
        slots
        assetId
        index
        activeFlag
        publicNullifier
        witness
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface
        policyInput
        productionPayload
        validation
        validationSummary
        actions
        payloads
        transactions
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence
        left
        right
        assumptions
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        game)
    (integrity :
      RawIngressCommitmentTreeNullifierIntegrityCertificate
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
        validation
        validationSummary
        materializedActionCount
        materializedPayloadCount
        decodedRows
        validationRows
        materializedRows
        plannedRows
        wireRows
        canonicalRows
        depth
        historyLimit) : Prop where
  endToEndBoundary :
    AcceptedMaterializedTransferEndToEndSecurityBoundaryFacts
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
      payload
      transferKey
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
      spendWitnesses
      balanceWitness
      slots
      assetId
      index
      activeFlag
      publicNullifier
      witness
      candidateWrapper
      publicStatement
      authSurface
      inputSpendSurface
      outputSurface
      smallwoodBalanceSurface
      airBalanceSurface
      policyInput
      productionPayload
      validation
      validationSummary
      actions
      payloads
      transactions
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence
      left
      right
      assumptions
      mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness
      game
  coreReview :
    MaterializedTransferHighestStandardCoreReviewFacts
      (expectedNativeSupplyAfter
        initial.ledger.supply
        (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
        some final.ledger.supply)
      (validateNativeLedgerTreeReplayChain
        initial
        (rawTreeReplayInputs blocks) =
        some final)
      (expectedCommitmentRootAfter
        initial.commitmentRoot
        (rawTreeReplayInputs blocks) =
        some final.commitmentRoot)
      final.ledger.spentNullifiers.Nodup
      final.ledger.consumedBridgeReplays.Nodup
      (ActiveInputNoTheftFullBinding
        payload
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
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
      (InputSlotAuthorizationFullBinding
        payload
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
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
      (SmallWoodPublicStatementVerifierExportFacts
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
        slots
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface)
      (Hegemon.Transaction.slotDelta assetId slots =
        publicAuthorizedAssetDeltaValue publicFields assetId)
      (AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        (Hegemon.Transaction.slotDelta assetId slots)
        (nativeStablecoinLivePolicyAuthorizes
          policyInput
          productionPayload))
      (NativeStablecoinLiveAuthorizationFacts
        policyInput
        productionPayload)
      (MaterializedConsensusDaBlobRefinementFacts
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
        (transactions.map consensusDaPayload)
        (Consensus.DaRoot.daBlob (transactions.map consensusDaPayload)))
      (NativeTxLeafFullStatementArtifactFacts
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
        merkleRoot)
      (txLeaf.receiptStatementHashMatches = true
        ∧ txLeaf.publicInputsDigestMatches = true
        ∧ txLeaf.proofDigestMatches = true
        ∧ txLeaf.proofBackendMatches = true
        ∧ txLeaf.ciphertextPayloadHashesMatch = true)
      (txLeaf.ciphertextHashesMatch = true
        ∧ txLeaf.ciphertextPayloadHashesMatch = true)
      (shape.ciphertextHashes = statementFields.ciphertextHashSeeds
        ∧ bindingFields.ciphertextHashSeeds =
          statementFields.ciphertextHashSeeds)
      (surface.transferState.sidecarCiphertextsAvailable = true
        ∧ surface.transferState.sidecarCiphertextSizesPresent = true
        ∧ surface.transferState.sidecarCiphertextSizesMatch = true)
      (MaterializedSidecarOpenAssumptionPrivacyBoundary
        surface
        blockActionDecode
        wireOutput
        txLeaf
        shape
        statementFields
        bindingFields
        left
        right
        assumptions
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        game)
      (AcceptedBlockAdmissionSafetyFacts
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
        merkleRoot)
  commitmentNullifierIntegrity :
    RawIngressCommitmentTreeNullifierIntegrityCertificate
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
      validation
      validationSummary
      materializedActionCount
      materializedPayloadCount
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows
      depth
      historyLimit
  replayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  commitmentRootPublished :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  leafCursorPublished :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount
  exactCanonicalCommitmentRows :
    canonicalRows.commitmentRows =
      PendingActionByteReplayRowCountBinding.projectedCommitmentRows
        decodedRows
  exactCanonicalNullifierRows :
    canonicalRows.nullifierRows =
      PendingActionByteReplayRowCountBinding.projectedNullifierRows
        decodedRows
  exactCanonicalBridgeReplayRows :
    canonicalRows.bridgeReplayRows =
      PendingActionByteReplayRowCountBinding.projectedBridgeReplayRows
        plannedRows
  appendMutationRowsMatchCanonicalRows :
    (CommitmentTreeContentRefinement.rawIngressAppendSummaries
      depth
      historyLimit
      initial
      decodedRows).length =
      canonicalRows.commitmentRows.length
  finalNullifierUniqueness :
    final.ledger.spentNullifiers.Nodup
  finalReplayUniqueness :
    final.ledger.consumedBridgeReplays.Nodup
  privacyBoundary :
    MaterializedSidecarOpenAssumptionPrivacyBoundary
      surface
      blockActionDecode
      wireOutput
      txLeaf
      shape
      statementFields
      bindingFields
      left
      right
      assumptions
      mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness
      game
  admissionSafety :
    AcceptedBlockAdmissionSafetyFacts
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

theorem materialized_transfer_end_to_end_boundary_with_commitment_tree_nullifier_integrity_review
    (boundary :
      AcceptedMaterializedTransferEndToEndSecurityBoundaryFacts
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
        payload
        transferKey
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
        spendWitnesses
        balanceWitness
        slots
        assetId
        index
        activeFlag
        publicNullifier
        witness
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface
        policyInput
        productionPayload
        validation
        validationSummary
        actions
        payloads
        transactions
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence
        left
        right
        assumptions
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        game)
    (integrity :
      RawIngressCommitmentTreeNullifierIntegrityCertificate
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
        validation
        validationSummary
        materializedActionCount
        materializedPayloadCount
        decodedRows
        validationRows
        materializedRows
        plannedRows
        wireRows
        canonicalRows
        depth
        historyLimit) :
    MaterializedTransferLedgerIntegrityEndToEndReviewFacts
      boundary
      integrity := by
  exact
    {
      endToEndBoundary := boundary,
      coreReview :=
        accepted_materialized_transfer_end_to_end_boundary_exposes_highest_standard_core_review
          boundary,
      commitmentNullifierIntegrity := integrity,
      replayedSupply := integrity.replayedSupply,
      commitmentRootPublished := integrity.commitmentRootPublished,
      leafCursorPublished := integrity.leafCursorPublished,
      exactCanonicalCommitmentRows :=
        integrity.exactCanonicalCommitmentRows,
      exactCanonicalNullifierRows :=
        integrity.exactCanonicalNullifierRows,
      exactCanonicalBridgeReplayRows :=
        integrity.exactCanonicalBridgeReplayRows,
      appendMutationRowsMatchCanonicalRows :=
        integrity.appendMutationCountMatchesCanonicalRows,
      finalNullifierUniqueness :=
        integrity.finalNullifierUniqueness,
      finalReplayUniqueness :=
        integrity.finalReplayUniqueness,
      privacyBoundary := boundary.privacyBoundary,
      admissionSafety := boundary.admissionSafety
    }

structure MaterializedTransferCoreResidualAssumptions where
  arbitraryParserEquivalence : Prop
  hashSecurityEquivalence : Prop
  proofSystemSoundness : Prop
  storageDurabilityBelowSled : Prop
  daAvailabilityRetention : Prop
  completeNativeNodeEquivalence : Prop

structure MaterializedTransferHighestStandardResidualReviewFacts
    (noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety : Prop)
    (residuals : MaterializedTransferCoreResidualAssumptions) : Prop where
  coreReview :
    MaterializedTransferHighestStandardCoreReviewFacts
      noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
  arbitraryParserEquivalence :
    residuals.arbitraryParserEquivalence
  hashSecurityEquivalence :
    residuals.hashSecurityEquivalence
  proofSystemSoundness :
    residuals.proofSystemSoundness
  storageDurabilityBelowSled :
    residuals.storageDurabilityBelowSled
  daAvailabilityRetention :
    residuals.daAvailabilityRetention
  completeNativeNodeEquivalence :
    residuals.completeNativeNodeEquivalence
  noCounterfeiting :
    noCounterfeiting
  acceptedLedgerReplay :
    acceptedLedgerReplay
  commitmentRootPublication :
    commitmentRootPublication
  noDoubleSpend :
    noDoubleSpend
  bridgeReplayUnique :
    bridgeReplayUnique

theorem materialized_transfer_highest_standard_core_review_with_explicit_residuals
    {noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety : Prop}
    {residuals : MaterializedTransferCoreResidualAssumptions}
    (core :
      MaterializedTransferHighestStandardCoreReviewFacts
        noCounterfeiting
        acceptedLedgerReplay
        commitmentRootPublication
        noDoubleSpend
        bridgeReplayUnique
        activeInputNoTheft
        totalInputAuthorization
        smallwoodVerifierExport
        authorizedPerAssetDelta
        authorizedStablecoinException
        nativeStablecoinPolicyLive
        consensusDaBlobRefinement
        txLeafStatementArtifact
        txLeafNativeStatementArtifact
        txLeafCiphertextPublication
        statementCiphertextVectorPublication
        sidecarMaterialization
        privacyBoundary
        admissionSafety)
    (arbitraryParserEquivalence :
      residuals.arbitraryParserEquivalence)
    (hashSecurityEquivalence :
      residuals.hashSecurityEquivalence)
    (proofSystemSoundness :
      residuals.proofSystemSoundness)
    (storageDurabilityBelowSled :
      residuals.storageDurabilityBelowSled)
    (daAvailabilityRetention :
      residuals.daAvailabilityRetention)
    (completeNativeNodeEquivalence :
      residuals.completeNativeNodeEquivalence) :
    MaterializedTransferHighestStandardResidualReviewFacts
      noCounterfeiting
      acceptedLedgerReplay
      commitmentRootPublication
      noDoubleSpend
      bridgeReplayUnique
      activeInputNoTheft
      totalInputAuthorization
      smallwoodVerifierExport
      authorizedPerAssetDelta
      authorizedStablecoinException
      nativeStablecoinPolicyLive
      consensusDaBlobRefinement
      txLeafStatementArtifact
      txLeafNativeStatementArtifact
      txLeafCiphertextPublication
      statementCiphertextVectorPublication
      sidecarMaterialization
      privacyBoundary
      admissionSafety
      residuals := by
  exact {
    coreReview := core,
    arbitraryParserEquivalence := arbitraryParserEquivalence,
    hashSecurityEquivalence := hashSecurityEquivalence,
    proofSystemSoundness := proofSystemSoundness,
    storageDurabilityBelowSled := storageDurabilityBelowSled,
    daAvailabilityRetention := daAvailabilityRetention,
    completeNativeNodeEquivalence := completeNativeNodeEquivalence,
    noCounterfeiting := core.noCounterfeiting,
    acceptedLedgerReplay := core.acceptedLedgerReplay,
    commitmentRootPublication := core.commitmentRootPublication,
    noDoubleSpend := core.noDoubleSpend,
    bridgeReplayUnique := core.bridgeReplayUnique
  }
theorem accepted_materialized_transfer_smallwood_consensus_da_blob_privacy_certificate
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
    {payload : TransferPayloadInput}
    {transferKey : Nat}
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
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {candidateWrapper :
      Hegemon.Transaction.SmallWoodCandidateWrapperAdmission.WrapperAdmissionInput}
    {publicStatement :
      Hegemon.Transaction.SmallWoodPublicStatementBinding.PublicStatementSurface}
    {authSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveAuthLinkSurface}
    {inputSpendSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveInputSpendBoundarySurface}
    {outputSurface :
      Hegemon.Transaction.SmallWoodSpendAuthorization.ActiveOutputBindingSurface}
    {smallwoodBalanceSurface :
      Hegemon.Transaction.SmallWoodBalanceBoundary.BalanceSurface}
    {airBalanceSurface :
      Hegemon.Transaction.AirBalanceBoundary.AirBalanceFinalRowSurface}
    {policyInput : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {actions : List MaterializedTransferActionRow}
    {payloads : List MaterializedTransferPayloadRow}
    {transactions : List MaterializedConsensusTransaction}
    {daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    {left right : ShieldedTransactionWorld}
    {assumptions : PrivacyBoundaryAssumptions}
    (assumptionProofs : PrivacyBoundaryAssumptionProofs assumptions)
    (mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness : Prop)
    (mlKemAssumption : mlKemIndistinguishability)
    (aeadAssumption : aeadCiphertextConfidentiality)
    (kdfAssumption : kdfDomainSeparation)
    (rngAssumption : rngFreshness)
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
        True
        True
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence)
    (productionProjection :
      RawIngressFullByteProductionProjectionFacts
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
        validation
        validationSummary
        actions.length
        payloads.length)
    (payloadRowsMatchTransactionRows :
      payloads.length = transactions.length)
    (rowBinding :
      ∀ (index : Nat) action payload transaction,
        actions[index]? = some action →
        payloads[index]? = some payload →
        transactions[index]? = some transaction →
          MaterializedRowFeedsTransactionNew action payload transaction)
    (u32Bounds : TransactionsFitU32 transactions)
    (payloadAccepted :
      transferPayloadAccepts payload = true)
    (txLeafAccepted :
      BlockArtifactBindingAdmission.txLeafActionBindingAccepts txLeaf = true)
    (canonicalSurface :
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
    (smallwoodExport :
      SmallWoodPublicStatementVerifierExportFacts
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
        slots
        candidateWrapper
        publicStatement
        authSurface
        inputSpendSurface
        outputSurface
        smallwoodBalanceSurface
        airBalanceSurface)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1)
    (nonNative : assetId ≠ Hegemon.Transaction.nativeAsset)
    (nonzero : Hegemon.Transaction.slotDelta assetId slots ≠ 0)
    (present : policyInput.stablecoinPresent = true)
    (policyAccepted :
      stablecoinPolicyAuthorizationAccepts policyInput = true)
    (exactPayload :
      productionPayload =
        stablecoinMintExceptionPayload
          publicFields
          assetId
          (Hegemon.Transaction.slotDelta assetId slots))
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
    MaterializedTransferSmallWoodConsensusDaBlobPublicationFacts
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
      payload
      transferKey
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
      spendWitnesses
      balanceWitness
      slots
      assetId
      index
      activeFlag
      publicNullifier
      witness
      candidateWrapper
      publicStatement
      authSurface
      inputSpendSurface
      outputSurface
      smallwoodBalanceSurface
      airBalanceSurface
      policyInput
      productionPayload
      validation
      validationSummary
      actions
      payloads
      transactions
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence
    ∧ MaterializedSidecarOpenAssumptionPrivacyBoundary
      surface
      blockActionDecode
      wireOutput
      txLeaf
      shape
      statementFields
      bindingFields
      left
      right
      assumptions
      mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness
      game := by
  have integrityCertificate :=
    accepted_materialized_transfer_smallwood_consensus_da_blob_certificate
      (transferKey := transferKey)
      (publication := publication)
      (productionProjection := productionProjection)
      (payloadRowsMatchTransactionRows := payloadRowsMatchTransactionRows)
      (rowBinding := rowBinding)
      (u32Bounds := u32Bounds)
      (payloadAccepted := payloadAccepted)
      (txLeafAccepted := txLeafAccepted)
      (smallwoodExport := smallwoodExport)
      (slot := slot)
      (active := active)
      (nonNative := nonNative)
      (nonzero := nonzero)
      (present := present)
      (policyAccepted := policyAccepted)
      (exactPayload := exactPayload)
  have privacyBoundary :
      MaterializedSidecarOpenAssumptionPrivacyBoundary
        surface
        blockActionDecode
        wireOutput
        txLeaf
        shape
        statementFields
        bindingFields
        left
        right
        assumptions
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        game :=
    materialized_sidecar_ciphertext_privacy_game_all_active_outputs_open_assumption_decrypt_da_boundary
      (assumptionProofs := assumptionProofs)
      mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness
      mlKemAssumption
      aeadAssumption
      kdfAssumption
      rngAssumption
      (facts := publication)
      (canonicalSurface := canonicalSurface)
      (game := game)
      (leftShape := leftShape)
      (leftObserverBytesBounded := leftObserverBytesBounded)
      (rightObserverBytesBounded := rightObserverBytesBounded)
  exact ⟨integrityCertificate, privacyBoundary⟩

end MaterializedConsensusDaBlobRefinement
end Native
end Hegemon

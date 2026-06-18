import Hegemon.Consensus.DaRoot
import Hegemon.Native.MaterializedSidecarDaBlobPublication
import Hegemon.Native.MaterializedTransferNoTheftPublication
import Hegemon.Privacy.NativeSidecarObserverSurface

namespace Hegemon
namespace Native
namespace MaterializedConsensusDaBlobRefinement

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.MaterializedSidecarDaBlobPublication
open Hegemon.Native.MaterializedTransferNoTheftPublication
open Hegemon.Native.RawIngressFullBytePublicationSurface
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StablecoinPolicyAuthorization
open Hegemon.Native.StablecoinPolicyLiveAuthorization
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TransferActionPayloadAdmission
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

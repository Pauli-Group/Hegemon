import Hegemon.Native.RawIngressFullBytePublicationSurface

namespace Hegemon
namespace Native
namespace MaterializedSidecarDaBlobPublication

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.PendingActionByteParserRefinement
open Hegemon.Native.RawIngressFullBytePublicationSurface
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafArtifactProjectionRefinement
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

structure MaterializedSidecarDaBlobExternalAssumptions
    (materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop) : Prop where
  materializedRowsFeedTransactionNewExplicit :
    materializedRowsFeedTransactionNew
  transactionNewFeedsConsensusDaBlobExplicit :
    transactionNewFeedsConsensusDaBlob
  daRootHashSecurityEquivalenceExplicit :
    daRootHashSecurityEquivalence
  daAvailabilityExplicit : daAvailability
  proofSystemSoundnessExplicit : proofSystemSoundness
  completeNativeNodeEquivalenceExplicit : completeNativeNodeEquivalence

structure MaterializedSidecarDaBlobPublicationFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput)
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
    (materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop) : Prop where
  assumptions :
    MaterializedSidecarDaBlobExternalAssumptions
      materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence
  fullBytePublication :
    RawIngressFullBytePublicationFacts
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

theorem accepted_materialized_sidecar_da_blob_publication
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
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
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    (assumptions :
      MaterializedSidecarDaBlobExternalAssumptions
        materializedRowsFeedTransactionNew
        transactionNewFeedsConsensusDaBlob
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence)
    (fullFacts :
      RawIngressFullBytePublicationFacts
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
        merkleRoot) :
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
      materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence := by
  rcases fullFacts.txLeafFullStatementArtifactFacts.txLeafActionBindingFacts with
    ⟨_nullifiers,
      _commitments,
      ciphertextHashes,
      _inputCount,
      _outputCount,
      _version,
      _fee,
      _stablecoinPayload,
      _balanceTag,
      _receiptStatement,
      _publicInputsDigest,
      _proofDigest,
      _proofBackend,
      ciphertextPayloadHashes⟩
  rcases fullFacts.txLeafFullStatementArtifactFacts.outputVectorBinding with
    ⟨_outputFlags,
      _commitmentsShape,
      ciphertextShape,
      _bindingCommitments,
      bindingCiphertextHashes⟩
  exact
    { assumptions := assumptions
      fullBytePublication := fullFacts
      materializedSidecarRows :=
        ⟨fullFacts.sidecarCiphertextsAvailable,
          fullFacts.sidecarCiphertextSizesPresent,
          fullFacts.sidecarCiphertextSizesMatch⟩
      wireReplayDaRowBinding :=
        ⟨fullFacts.wireProjectionPreconditions,
          fullFacts.rawIngressPublicationFacts.wireReplayPlannedCount,
          fullFacts.rawIngressPublicationFacts.wireReplayActionCount,
          fullFacts.projectedActionRowsMatchDecodedPayloads⟩
      candidateDaPublication :=
        ⟨fullFacts.candidateDaRootMatches,
          fullFacts.candidateTxStatementsCommitmentMatches,
          fullFacts.candidateRecursiveStateRootMatches,
          fullFacts.rawIngressPublicationFacts.candidateTxCountNonzero,
          fullFacts.rawIngressPublicationFacts.candidateDaChunkCountNonzero⟩
      provenBatchDaPublication :=
        ⟨fullFacts.provenBatchDaRootMatches,
          fullFacts.provenBatchHasChunks⟩
      recursiveSemanticDaPublication := fullFacts.semanticDaRootBound
      txLeafCiphertextPublication :=
        ⟨ciphertextHashes, ciphertextPayloadHashes⟩
      statementCiphertextVectorPublication :=
        ⟨ciphertextShape, bindingCiphertextHashes⟩
      txLeafNativeStatementArtifactBinding :=
        fullFacts.txLeafFullStatementArtifactFacts.nativeStatementArtifactBinding
      acceptedLedgerTreeReplay := fullFacts.acceptedLedgerTreeReplay
      commitmentRootPublication := fullFacts.commitmentRootPublication
      replayedSupply := fullFacts.replayedSupply
      finalReplaySetsUnique :=
        ⟨fullFacts.finalSpentNullifiersUnique,
          fullFacts.finalBridgeReplaysUnique⟩ }

end MaterializedSidecarDaBlobPublication
end Native
end Hegemon

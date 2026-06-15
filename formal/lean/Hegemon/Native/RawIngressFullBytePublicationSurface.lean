import Hegemon.Native.TxLeafArtifactProjectionRefinement

namespace Hegemon
namespace Native
namespace RawIngressFullBytePublicationSurface

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalPublicationRefinement
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.PendingActionByteParserRefinement
open Hegemon.Native.PendingActionBytePublicationRefinement
open Hegemon.Native.PendingActionReload
open Hegemon.Native.RawIngressPendingActionPublicationRefinement
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafArtifactProjectionRefinement
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

structure RawIngressFullBytePublicationFacts
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
    (txLeaf : TxLeafActionBindingInput)
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
    (merkleRoot : Digest) : Prop where
  parsedRawIngressPublication :
    ParsedRawIngressPendingActionTxLeafPublicationFacts
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
  pendingDecodePreconditions :
    exactDecodePreconditions pendingDecode = true
  pendingDecodeExact :
    pendingDecode.parserAccepts = true
      ∧ pendingDecode.consumedAllBytes = true
      ∧ pendingDecode.canonicalReencodeMatches = true
  blockActionDecodePreconditions :
    blockActionDecodePreconditions blockActionDecode = true
  blockActionDecodeExact :
    actionCountMatches blockActionDecode = true
      ∧ blockActionDecode.everyActionDecodesExactly = true
  pendingReloadPreconditions :
    pendingActionReloadPreconditions surface.pendingReload = true
  actionHashPreconditions :
    admissionPreconditions actionHash = true
  wireProjectionPreconditions :
    actionWireReplayProjectionPreconditions
      surface.daSidecarReplay.wireReplayProjection = true
  acceptedWireProjection :
    ActionWireReplayProjectionAdmission.evaluateActionWireReplayProjection
      surface.daSidecarReplay.wireReplayProjection =
        Except.ok wireOutput
  parserWireReplayFacts :
    PendingActionByteParserWireReplayFacts
      pendingDecode
      blockActionDecode
      surface.pendingReload
      surface.daSidecarReplay.wireReplayProjection
      wireOutput
  projectedActionRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
  rawIngressPublicationFacts :
    RawIngressLedgerTreePublicationFacts
      surface
      semanticFields
      initial
      final
      blocks
  canonicalPublicationFacts :
    CanonicalPublicationReplayFacts
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      (rawTreeReplayInputs blocks)
  sidecarCiphertextsAvailable :
    surface.transferState.sidecarCiphertextsAvailable = true
  sidecarCiphertextSizesPresent :
    surface.transferState.sidecarCiphertextSizesPresent = true
  sidecarCiphertextSizesMatch :
    surface.transferState.sidecarCiphertextSizesMatch = true
  candidateDaRootMatches :
    surface.daSidecarReplay.candidateBinding.daRootMatches = true
  candidateTxStatementsCommitmentMatches :
    surface.daSidecarReplay.candidateBinding.txStatementsCommitmentMatches =
      true
  candidateRecursiveStateRootMatches :
    surface.daSidecarReplay.candidateBinding.recursiveStateRootMatches =
      true
  provenBatchDaRootMatches :
    surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
  provenBatchHasChunks :
    surface.daSidecarReplay.provenBatchBinding.daChunkCount ≠ 0
  semanticDaRootBound :
    semanticFields.daRoot =
      surface.daSidecarReplay.recursiveSemanticSource.daRoot
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
  replayedLeafCursor :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount
  rawTreeCarriedStatePreconditions :
    rawProjectedTreeCarriedStatePreconditions initial blocks = true
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup
  artifactByteShapeFacts :
    AcceptedNativeTxLeafArtifactByteShapeFacts
      artifactBytes
      summary
  txLeafProjectionAssumptions :
    NativeTxLeafArtifactCanonicalProjectionAssumptions
      summary
      txLeaf
      shape
      serializedFields
      bound
      statementFields
      bindingFields
  txLeafAccepted :
    txLeafActionBindingAccepts txLeaf = true
  txLeafFullStatementArtifactFacts :
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

theorem accepted_raw_ingress_full_byte_publication_surface
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
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
    (rawIngressFacts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireActionCountMatchesDeclared :
      surface.daSidecarReplay.wireReplayProjection.actionCount =
        blockActionDecode.declaredTxCount)
    (blockIndexAccepted : blockIndexReloadAccepts blockIndex = true)
    (canonicalStateAccepted :
      canonicalStateReloadAccepts canonicalState = true)
    (canonicalReorgAccepted :
      canonicalReorgChainAccepts reorgChain = true)
    (atomicCommitAccepted :
      atomicCommitManifestAccepts commitManifest = true)
    (durabilityAccepted :
      storageDurabilityAccepts durability = true)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final)
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (projection :
      NativeTxLeafArtifactCanonicalProjectionAssumptions
        summary
        txLeaf
        shape
        serializedFields
        bound
        statementFields
        bindingFields)
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
        merkleRoot) :
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
      merkleRoot := by
  have parsedFacts :=
    accepted_raw_ingress_pending_action_bytes_bind_parsed_tx_leaf_publication
      rawIngressFacts
      sidecarRoute
      pendingDecodeAccepted
      blockActionDecodeAccepted
      actionHashAccepted
      wireActionCountMatchesDeclared
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
      parsed
      projection
      canonicalSurface
  let rawTxLeafFacts :=
    parsedFacts.rawIngressTxLeafPublicationFacts
  let rawPendingFacts :=
    rawTxLeafFacts.rawIngressPendingActionPublicationFacts
  let byteFacts :=
    rawPendingFacts.pendingActionBytePublicationFacts
  let publicationFacts :=
    rawPendingFacts.rawIngressPublicationFacts
  let parsedCanonicalFacts :=
    parsedFacts.parsedCanonicalFacts
  exact
    { parsedRawIngressPublication := parsedFacts
      pendingDecodePreconditions :=
        byteFacts.pendingDecodePreconditions
      pendingDecodeExact :=
        byteFacts.pendingDecodeExact
      blockActionDecodePreconditions :=
        byteFacts.blockActionDecodePreconditions
      blockActionDecodeExact :=
        byteFacts.blockActionDecodeExact
      pendingReloadPreconditions :=
        byteFacts.pendingReloadPreconditions
      actionHashPreconditions :=
        byteFacts.actionHashPreconditions
      wireProjectionPreconditions :=
        byteFacts.wireProjectionPreconditions
      acceptedWireProjection :=
        byteFacts.acceptedWireProjection
      parserWireReplayFacts :=
        byteFacts.parserWireReplayFacts
      projectedActionRowsMatchDecodedPayloads :=
        byteFacts.projectedActionRowsMatchDecodedPayloads
      rawIngressPublicationFacts :=
        publicationFacts
      canonicalPublicationFacts :=
        byteFacts.canonicalPublicationFacts
      sidecarCiphertextsAvailable :=
        publicationFacts.sidecarCiphertextsAvailable
      sidecarCiphertextSizesPresent :=
        publicationFacts.sidecarCiphertextSizesPresent
      sidecarCiphertextSizesMatch :=
        publicationFacts.sidecarCiphertextSizesMatch
      candidateDaRootMatches :=
        publicationFacts.candidateDaRootMatches
      candidateTxStatementsCommitmentMatches :=
        publicationFacts.candidateTxStatementsCommitmentMatches
      candidateRecursiveStateRootMatches :=
        publicationFacts.candidateRecursiveStateRootMatches
      provenBatchDaRootMatches :=
        publicationFacts.provenBatchDaRootMatches
      provenBatchHasChunks :=
        publicationFacts.provenBatchHasChunks
      semanticDaRootBound :=
        publicationFacts.semanticDaRootBound
      acceptedLedgerTreeReplay :=
        publicationFacts.acceptedLedgerTreeReplay
      commitmentRootPublication :=
        publicationFacts.commitmentRootPublication
      replayedSupply :=
        publicationFacts.replayedSupply
      replayedLeafCursor :=
        publicationFacts.replayedLeafCursor
      rawTreeCarriedStatePreconditions :=
        byteFacts.rawTreeCarriedStatePreconditions
      finalSpentNullifiersUnique :=
        publicationFacts.finalSpentNullifiersUnique
      finalBridgeReplaysUnique :=
        publicationFacts.finalBridgeReplaysUnique
      artifactByteShapeFacts :=
        parsedCanonicalFacts.artifactByteShapeFacts
      txLeafProjectionAssumptions :=
        parsedCanonicalFacts.projectionAssumptions
      txLeafAccepted :=
        parsedCanonicalFacts.txLeafAccepted
      txLeafFullStatementArtifactFacts :=
        parsedCanonicalFacts.txLeafFullStatementArtifactFacts }

end RawIngressFullBytePublicationSurface
end Native
end Hegemon

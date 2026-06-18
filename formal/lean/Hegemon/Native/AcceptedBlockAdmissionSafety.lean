import Hegemon.Native.RawIngressFullBytePublicationSurface

namespace Hegemon
namespace Native
namespace AcceptedBlockAdmissionSafety

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalPublicationRefinement
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.RawIngressFullBytePublicationSurface
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafArtifactProjectionRefinement
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

structure AcceptedBlockAdmissionSafetyFacts
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
  actionHashPreconditions :
    admissionPreconditions actionHash = true
  acceptedWireProjection :
    ActionWireReplayProjectionAdmission.evaluateActionWireReplayProjection
      surface.daSidecarReplay.wireReplayProjection =
        Except.ok wireOutput
  projectedActionRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
  sidecarCiphertextsAvailable :
    surface.transferState.sidecarCiphertextsAvailable = true
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

structure AcceptedBlockCanonicalAdmissionSafetyCertificate
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
  admissionSafetyFacts :
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
  ledgerProjectionMatchesRawReplay :
    ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks) =
      rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)
  blockIndexReloadPreconditionsHold :
    blockIndexReloadPreconditions blockIndex = true
  canonicalStateReloadPreconditionsHold :
    canonicalStateReloadPreconditions canonicalState = true
  canonicalReorgChainPreconditionsHold :
    canonicalReorgChainPreconditions reorgChain = true
  atomicCommitManifestPreconditionsHold :
    atomicCommitManifestPreconditions commitManifest = true
  storageDurabilityPreconditionsHold :
    storageDurabilityPreconditions durability = true
  canonicalAcceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  rawAcceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  canonicalAcceptedLedgerReplay :
    validateNativeLedgerReplayChain
      initial.ledger
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger
  rawAcceptedLedgerReplay :
    validateNativeLedgerReplayChain
      initial.ledger
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger
  canonicalReplayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger.supply
  rawReplayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  canonicalReplayedLeafCursor :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger.leafCount
  rawReplayedLeafCursor :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount
  canonicalCommitmentPlan :
    nativeLedgerReplayCommitmentPlanPreconditions
      initial.ledger
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) = true
  rawCommitmentPlan :
    nativeLedgerReplayCommitmentPlanPreconditions
      initial.ledger
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) = true
  canonicalCommitmentRootPublication :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  rawCommitmentRootPublication :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  rawTreeCarriedStatePreconditions :
    rawProjectedTreeCarriedStatePreconditions initial blocks = true
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup

theorem raw_ingress_full_byte_publication_facts_imply_accepted_block_admission_safety
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
    (facts :
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
      merkleRoot := by
  exact
    {
      pendingDecodePreconditions := facts.pendingDecodePreconditions
      pendingDecodeExact := facts.pendingDecodeExact
      blockActionDecodePreconditions := facts.blockActionDecodePreconditions
      blockActionDecodeExact := facts.blockActionDecodeExact
      actionHashPreconditions := facts.actionHashPreconditions
      acceptedWireProjection := facts.acceptedWireProjection
      projectedActionRowsMatchDecodedPayloads :=
        facts.projectedActionRowsMatchDecodedPayloads
      sidecarCiphertextsAvailable := facts.sidecarCiphertextsAvailable
      sidecarCiphertextSizesMatch := facts.sidecarCiphertextSizesMatch
      candidateDaRootMatches := facts.candidateDaRootMatches
      candidateTxStatementsCommitmentMatches :=
        facts.candidateTxStatementsCommitmentMatches
      candidateRecursiveStateRootMatches :=
        facts.candidateRecursiveStateRootMatches
      provenBatchDaRootMatches := facts.provenBatchDaRootMatches
      semanticDaRootBound := facts.semanticDaRootBound
      acceptedLedgerTreeReplay := facts.acceptedLedgerTreeReplay
      commitmentRootPublication := facts.commitmentRootPublication
      replayedSupply := facts.replayedSupply
      replayedLeafCursor := facts.replayedLeafCursor
      rawTreeCarriedStatePreconditions :=
        facts.rawTreeCarriedStatePreconditions
      finalSpentNullifiersUnique := facts.finalSpentNullifiersUnique
      finalBridgeReplaysUnique := facts.finalBridgeReplaysUnique
      artifactByteShapeFacts := facts.artifactByteShapeFacts
      txLeafProjectionAssumptions := facts.txLeafProjectionAssumptions
      txLeafAccepted := facts.txLeafAccepted
      txLeafFullStatementArtifactFacts :=
        facts.txLeafFullStatementArtifactFacts
    }

theorem raw_ingress_full_byte_publication_facts_imply_canonical_admission_safety_certificate
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
    (facts :
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
    AcceptedBlockCanonicalAdmissionSafetyCertificate
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
  have admissionSafetyFacts :=
    raw_ingress_full_byte_publication_facts_imply_accepted_block_admission_safety
      facts
  have ledgerProjectionMatchesRawReplay :
      ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks) =
        rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks) :=
    ledgerBlocksFromRawTreeReplayInputs blocks
  have rawAcceptedLedgerReplay :
      validateNativeLedgerReplayChain
        initial.ledger
        (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
        some final.ledger := by
    simpa [ledgerProjectionMatchesRawReplay] using
      facts.canonicalPublicationFacts.acceptedLedgerReplay
  have rawCommitmentPlan :
      nativeLedgerReplayCommitmentPlanPreconditions
        initial.ledger
        (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) = true := by
    simpa [ledgerProjectionMatchesRawReplay] using
      facts.canonicalPublicationFacts.canonicalCommitmentPlan
  exact
    {
      admissionSafetyFacts := admissionSafetyFacts
      canonicalPublicationFacts := facts.canonicalPublicationFacts
      ledgerProjectionMatchesRawReplay := ledgerProjectionMatchesRawReplay
      blockIndexReloadPreconditionsHold :=
        facts.canonicalPublicationFacts.blockIndexPreconditions
      canonicalStateReloadPreconditionsHold :=
        facts.canonicalPublicationFacts.canonicalStatePreconditions
      canonicalReorgChainPreconditionsHold :=
        facts.canonicalPublicationFacts.canonicalReorgPreconditions
      atomicCommitManifestPreconditionsHold :=
        facts.canonicalPublicationFacts.atomicCommitPreconditions
      storageDurabilityPreconditionsHold :=
        facts.canonicalPublicationFacts.storageDurabilityPreconditions
      canonicalAcceptedLedgerTreeReplay :=
        facts.canonicalPublicationFacts.acceptedLedgerTreeReplay
      rawAcceptedLedgerTreeReplay :=
        facts.acceptedLedgerTreeReplay
      canonicalAcceptedLedgerReplay :=
        facts.canonicalPublicationFacts.acceptedLedgerReplay
      rawAcceptedLedgerReplay := rawAcceptedLedgerReplay
      canonicalReplayedSupply :=
        facts.canonicalPublicationFacts.replayedSupply
      rawReplayedSupply := facts.replayedSupply
      canonicalReplayedLeafCursor :=
        facts.canonicalPublicationFacts.replayedLeafCursor
      rawReplayedLeafCursor := facts.replayedLeafCursor
      canonicalCommitmentPlan :=
        facts.canonicalPublicationFacts.canonicalCommitmentPlan
      rawCommitmentPlan := rawCommitmentPlan
      canonicalCommitmentRootPublication :=
        facts.canonicalPublicationFacts.commitmentRootPublication
      rawCommitmentRootPublication :=
        facts.commitmentRootPublication
      rawTreeCarriedStatePreconditions :=
        facts.rawTreeCarriedStatePreconditions
      finalSpentNullifiersUnique :=
        facts.finalSpentNullifiersUnique
      finalBridgeReplaysUnique :=
        facts.finalBridgeReplaysUnique
    }

theorem accepted_raw_ingress_full_byte_publication_yields_accepted_block_admission_safety
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
      merkleRoot := by
  exact
    raw_ingress_full_byte_publication_facts_imply_accepted_block_admission_safety
      (accepted_raw_ingress_full_byte_publication_surface
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
        canonicalSurface)

theorem accepted_raw_ingress_full_byte_publication_yields_canonical_admission_safety_certificate
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
    AcceptedBlockCanonicalAdmissionSafetyCertificate
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
  exact
    raw_ingress_full_byte_publication_facts_imply_canonical_admission_safety_certificate
      (accepted_raw_ingress_full_byte_publication_surface
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
        canonicalSurface)

end AcceptedBlockAdmissionSafety
end Native
end Hegemon

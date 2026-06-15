import Hegemon.Native.RawIngressPendingActionPublicationRefinement

namespace Hegemon
namespace Native
namespace RawIngressActionHashTxLeafPublication

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
open Hegemon.Native.PendingActionBytePublicationRefinement
open Hegemon.Native.RawIngressPendingActionPublicationRefinement
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

structure RawIngressActionHashTxLeafPublicationAssumptions
    (pendingActionExactDecodeParserSoundness : Prop)
    (blockActionExactDecodeParserSoundness : Prop)
    (actionHashBindingSoundness : Prop)
    (canonicalStatementHashBindingSoundness : Prop)
    (nativeTxLeafProofSystemSoundness : Prop) : Prop where
  pendingActionExactDecodeParserSound :
    pendingActionExactDecodeParserSoundness
  blockActionExactDecodeParserSound :
    blockActionExactDecodeParserSoundness
  actionHashBindingSound :
    actionHashBindingSoundness
  canonicalStatementHashBindingSound :
    canonicalStatementHashBindingSoundness
  nativeTxLeafProofSystemSound :
    nativeTxLeafProofSystemSoundness

structure RawIngressActionHashTxLeafPublicationFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput : ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields :
      Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (pendingActionExactDecodeParserSoundness : Prop)
    (blockActionExactDecodeParserSoundness : Prop)
    (actionHashBindingSoundness : Prop)
    (canonicalStatementHashBindingSoundness : Prop)
    (nativeTxLeafProofSystemSoundness : Prop) : Prop where
  assumptions :
    RawIngressActionHashTxLeafPublicationAssumptions
      pendingActionExactDecodeParserSoundness
      blockActionExactDecodeParserSoundness
      actionHashBindingSoundness
      canonicalStatementHashBindingSoundness
      nativeTxLeafProofSystemSoundness
  rawIngressTxLeafPublicationFacts :
    RawIngressPendingActionTxLeafPublicationFacts
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
  rawIngressPublicationFacts :
    RawIngressLedgerTreePublicationFacts
      surface
      semanticFields
      initial
      final
      blocks
  pendingActionBytePublicationFacts :
    PendingActionBytePublicationFacts
      pendingDecode
      blockActionDecode
      surface.pendingReload
      actionHash
      surface.daSidecarReplay.wireReplayProjection
      wireOutput
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
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
  actionHashCountMatches :
    actionHash.actionCountMatches = true
  actionHashesMatch :
    actionHash.actionHashesMatch = true
  actionHashesUnique :
    actionHash.actionHashesUnique = true
  pendingActionRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
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
  rawTreeCarriedStatePreconditions :
    rawProjectedTreeCarriedStatePreconditions initial blocks = true
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
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup
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
  statementPreimage :
    Hegemon.Transaction.StatementHash.statementPreimage
      statementFields = some statementBytes
  statementLength :
    statementBytes.length =
      Hegemon.Transaction.StatementHash.expectedPreimageLength
  bindingMessage :
    Hegemon.Transaction.ProofStatementBinding.bindingMessage
      bindingFields = some bindingBytes
  publicBindingValid :
    Hegemon.Transaction.PublicInputBinding.validBinding
      publicFields
      serializedFields = true
  wrapperPreconditions : proofWrapperPreconditions wrapper = true
  wrapperSurface : acceptedProofWrapperSurface wrapper
  publicShapeValid : validPublicInputShape shape = true
  coreStatementBinding :
    CanonicalStatementCoreBinding
      shape
      bound
      statementFields
      bindingFields
      merkleRoot
  vectorBinding :
    shape.nullifiers = statementFields.nullifierSeeds
      ∧ shape.commitments = statementFields.commitmentSeeds
      ∧ shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.nullifierSeeds = statementFields.nullifierSeeds
      ∧ bindingFields.commitmentSeeds = statementFields.commitmentSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds
  inputVectorBinding :
    shape.inputFlags = bound.inputFlags
      ∧ shape.nullifiers = statementFields.nullifierSeeds
      ∧ bindingFields.nullifierSeeds = statementFields.nullifierSeeds
  outputVectorBinding :
    shape.outputFlags = bound.outputFlags
      ∧ shape.commitments = statementFields.commitmentSeeds
      ∧ shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.commitmentSeeds = statementFields.commitmentSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds
  valueBalanceBinding :
    statementFields.valueBalanceSign = bound.valueBalanceSign
      ∧ statementFields.valueBalanceMagnitude = bound.valueBalanceMagnitude
      ∧ Hegemon.Transaction.PublicInputBinding.signedMagnitudeMatches
        bindingFields.valueBalance
        bound.valueBalanceSign
        bound.valueBalanceMagnitude = true
  stablecoinPayloadBinding :
    statementFields.stablecoinPolicyHashSeed = bound.stablecoinPolicyHash
      ∧ statementFields.stablecoinOracleCommitmentSeed =
        bound.stablecoinOracleCommitment
      ∧ statementFields.stablecoinAttestationCommitmentSeed =
        bound.stablecoinAttestationCommitment
      ∧ bindingFields.stablecoinPolicyHashSeed = bound.stablecoinPolicyHash
      ∧ bindingFields.stablecoinOracleCommitmentSeed =
        bound.stablecoinOracleCommitment
      ∧ bindingFields.stablecoinAttestationCommitmentSeed =
        bound.stablecoinAttestationCommitment
      ∧ Hegemon.Transaction.PublicInputBinding.signedMagnitudeMatches
        bindingFields.stablecoinIssuanceDelta
        bound.stablecoinIssuanceSign
        bound.stablecoinIssuanceMagnitude = true
  txLeafActionPreconditions :
    txLeafActionBindingPreconditions txLeaf = true
  txLeafActionBindingFacts : TxLeafActionBindingFacts txLeaf
  nativeStatementArtifactBinding :
    txLeaf.receiptStatementHashMatches = true
      ∧ txLeaf.publicInputsDigestMatches = true
      ∧ txLeaf.proofDigestMatches = true
      ∧ txLeaf.proofBackendMatches = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true

theorem action_hash_admission_preconditions_components
    {input : AdmissionInput}
    (preconditions : admissionPreconditions input = true) :
    input.actionCountMatches = true
      ∧ input.actionHashesMatch = true
      ∧ input.actionHashesUnique = true := by
  cases input with
  | mk actionCountMatches actionHashesMatch actionHashesUnique =>
      cases actionCountMatches <;>
        cases actionHashesMatch <;>
        cases actionHashesUnique <;>
        simp [admissionPreconditions] at preconditions ⊢

theorem raw_ingress_pending_action_tx_leaf_publication_facts_expose_action_hash_and_statement_binding
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields :
      Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {pendingActionExactDecodeParserSoundness : Prop}
    {blockActionExactDecodeParserSoundness : Prop}
    {actionHashBindingSoundness : Prop}
    {canonicalStatementHashBindingSoundness : Prop}
    {nativeTxLeafProofSystemSoundness : Prop}
    (assumptions :
      RawIngressActionHashTxLeafPublicationAssumptions
        pendingActionExactDecodeParserSoundness
        blockActionExactDecodeParserSoundness
        actionHashBindingSoundness
        canonicalStatementHashBindingSoundness
        nativeTxLeafProofSystemSoundness)
    (facts :
      RawIngressPendingActionTxLeafPublicationFacts
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
    RawIngressActionHashTxLeafPublicationFacts
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
      pendingActionExactDecodeParserSoundness
      blockActionExactDecodeParserSoundness
      actionHashBindingSoundness
      canonicalStatementHashBindingSoundness
      nativeTxLeafProofSystemSoundness := by
  let rawPendingFacts := facts.rawIngressPendingActionPublicationFacts
  let byteFacts := rawPendingFacts.pendingActionBytePublicationFacts
  let txLeafFacts := facts.txLeafStatementArtifactFacts
  have actionHashComponents :=
    action_hash_admission_preconditions_components
      byteFacts.actionHashPreconditions
  exact
    {
      assumptions := assumptions,
      rawIngressTxLeafPublicationFacts := facts,
      rawIngressPublicationFacts :=
        rawPendingFacts.rawIngressPublicationFacts,
      pendingActionBytePublicationFacts := byteFacts,
      pendingDecodePreconditions := byteFacts.pendingDecodePreconditions,
      pendingDecodeExact := byteFacts.pendingDecodeExact,
      blockActionDecodePreconditions :=
        byteFacts.blockActionDecodePreconditions,
      blockActionDecodeExact := byteFacts.blockActionDecodeExact,
      actionHashPreconditions := byteFacts.actionHashPreconditions,
      actionHashCountMatches := actionHashComponents.left,
      actionHashesMatch := actionHashComponents.right.left,
      actionHashesUnique := actionHashComponents.right.right,
      pendingActionRowsMatchDecodedPayloads :=
        rawPendingFacts.pendingActionRowsMatchDecodedPayloads,
      canonicalPublicationFacts := byteFacts.canonicalPublicationFacts,
      rawTreeCarriedStatePreconditions :=
        byteFacts.rawTreeCarriedStatePreconditions,
      acceptedLedgerTreeReplay := rawPendingFacts.acceptedLedgerTreeReplay,
      commitmentRootPublication :=
        rawPendingFacts.commitmentRootPublication,
      replayedSupply := rawPendingFacts.replayedSupply,
      replayedLeafCursor := rawPendingFacts.replayedLeafCursor,
      finalSpentNullifiersUnique :=
        rawPendingFacts.finalSpentNullifiersUnique,
      finalBridgeReplaysUnique :=
        rawPendingFacts.finalBridgeReplaysUnique,
      txLeafStatementArtifactFacts := txLeafFacts,
      statementPreimage := txLeafFacts.statementPreimage,
      statementLength := txLeafFacts.statementLength,
      bindingMessage := txLeafFacts.bindingMessage,
      publicBindingValid := txLeafFacts.publicBindingValid,
      wrapperPreconditions := txLeafFacts.wrapperPreconditions,
      wrapperSurface := txLeafFacts.wrapperSurface,
      publicShapeValid := txLeafFacts.publicShapeValid,
      coreStatementBinding := txLeafFacts.coreStatementBinding,
      vectorBinding := txLeafFacts.vectorBinding,
      inputVectorBinding := txLeafFacts.inputVectorBinding,
      outputVectorBinding := txLeafFacts.outputVectorBinding,
      valueBalanceBinding := txLeafFacts.valueBalanceBinding,
      stablecoinPayloadBinding := txLeafFacts.stablecoinPayloadBinding,
      txLeafActionPreconditions := txLeafFacts.txLeafActionPreconditions,
      txLeafActionBindingFacts := txLeafFacts.txLeafActionBindingFacts,
      nativeStatementArtifactBinding :=
        txLeafFacts.nativeStatementArtifactBinding
    }

theorem accepted_raw_ingress_action_hash_tx_leaf_publication
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput : ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
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
    {txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields :
      Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {pendingActionExactDecodeParserSoundness : Prop}
    {blockActionExactDecodeParserSoundness : Prop}
    {actionHashBindingSoundness : Prop}
    {canonicalStatementHashBindingSoundness : Prop}
    {nativeTxLeafProofSystemSoundness : Prop}
    (assumptions :
      RawIngressActionHashTxLeafPublicationAssumptions
        pendingActionExactDecodeParserSoundness
        blockActionExactDecodeParserSoundness
        actionHashBindingSoundness
        canonicalStatementHashBindingSoundness
        nativeTxLeafProofSystemSoundness)
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
        merkleRoot) :
    RawIngressActionHashTxLeafPublicationFacts
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
      pendingActionExactDecodeParserSoundness
      blockActionExactDecodeParserSoundness
      actionHashBindingSoundness
      canonicalStatementHashBindingSoundness
      nativeTxLeafProofSystemSoundness := by
  have rawIngressTxLeafFacts :=
    accepted_raw_ingress_pending_action_bytes_bind_tx_leaf_publication
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
      txLeafAccepted
      canonicalSurface
  exact
    raw_ingress_pending_action_tx_leaf_publication_facts_expose_action_hash_and_statement_binding
      assumptions
      rawIngressTxLeafFacts

end RawIngressActionHashTxLeafPublication
end Native
end Hegemon

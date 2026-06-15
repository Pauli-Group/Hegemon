import Hegemon.Native.MaterializedSidecarDaBlobPublication
import Hegemon.Native.TransferNoTheftBoundary

namespace Hegemon
namespace Native
namespace MaterializedTransferNoTheftPublication

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
open Hegemon.Native.PendingActionByteParserRefinement
open Hegemon.Native.RawIngressFullBytePublicationSurface
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TransferActionPayloadAdmission
open Hegemon.Native.TransferNoTheftBoundary
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

structure MaterializedTransferNoTheftPublicationFacts
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
    (statementFields :
      Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop) : Prop where
  materializedDaPublicationFacts :
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
      completeNativeNodeEquivalence
  noTheftBoundaryFacts :
    ValidatedTransferPayloadNoTheftBoundaryFacts
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
  inputSlotAuthorizationBoundaryFacts :
    ValidatedTransferPayloadInputSlotAuthorizationBoundaryFacts
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
  finalReplaySetsUnique :
    final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup
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
  txLeafCiphertextPublication :
    txLeaf.ciphertextHashesMatch = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true
  statementCiphertextVectorPublication :
    shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds
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

theorem accepted_materialized_transfer_no_theft_publication
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
    {statementFields :
      Hegemon.Transaction.StatementHash.StatementFields}
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
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    (materializedFacts :
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
        completeNativeNodeEquivalence)
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
    (sound :
      DeployedTxVerifierSoundnessAssumption
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
        slots)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
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
      materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence := by
  have noTheftFacts :=
    validated_transfer_payload_active_input_no_theft_full_binding
      (payload := payload)
      (transferKey := transferKey)
      (input := txLeaf)
      (wrapper := wrapper)
      (shape := shape)
      (publicFields := publicFields)
      (serializedFields := serializedFields)
      (bound := bound)
      (statementFields := statementFields)
      (statementBytes := statementBytes)
      (bindingFields := bindingFields)
      (bindingBytes := bindingBytes)
      (merkleRoot := merkleRoot)
      (spendWitnesses := spendWitnesses)
      (balanceWitness := balanceWitness)
      (slots := slots)
      (assetId := assetId)
      (index := index)
      (activeFlag := activeFlag)
      (publicNullifier := publicNullifier)
      (witness := witness)
      payloadAccepted
      txLeafAccepted
      canonicalSurface
      sound
      slot
      active
  have authorizationFacts :=
    validated_transfer_payload_input_slot_authorization_full_binding
      (payload := payload)
      (transferKey := transferKey)
      (input := txLeaf)
      (wrapper := wrapper)
      (shape := shape)
      (publicFields := publicFields)
      (serializedFields := serializedFields)
      (bound := bound)
      (statementFields := statementFields)
      (statementBytes := statementBytes)
      (bindingFields := bindingFields)
      (bindingBytes := bindingBytes)
      (merkleRoot := merkleRoot)
      (spendWitnesses := spendWitnesses)
      (balanceWitness := balanceWitness)
      (slots := slots)
      (assetId := assetId)
      (index := index)
      (activeFlag := activeFlag)
      (publicNullifier := publicNullifier)
      (witness := witness)
      payloadAccepted
      txLeafAccepted
      canonicalSurface
      sound
      slot
  exact
    { materializedDaPublicationFacts := materializedFacts
      noTheftBoundaryFacts := noTheftFacts
      inputSlotAuthorizationBoundaryFacts := authorizationFacts
      replayedSupply := materializedFacts.replayedSupply
      acceptedLedgerTreeReplay := materializedFacts.acceptedLedgerTreeReplay
      commitmentRootPublication := materializedFacts.commitmentRootPublication
      finalReplaySetsUnique := materializedFacts.finalReplaySetsUnique
      txLeafStatementArtifactFacts :=
        materializedFacts.fullBytePublication.txLeafFullStatementArtifactFacts
      txLeafCiphertextPublication :=
        materializedFacts.txLeafCiphertextPublication
      statementCiphertextVectorPublication :=
        materializedFacts.statementCiphertextVectorPublication
      candidateDaPublication := materializedFacts.candidateDaPublication
      provenBatchDaPublication := materializedFacts.provenBatchDaPublication
      recursiveSemanticDaPublication :=
        materializedFacts.recursiveSemanticDaPublication
      activeInputNoTheftFullBinding :=
        noTheftFacts.noTheftFullBinding
      inputSlotAuthorizationFullBinding :=
        authorizationFacts.inputSlotFullBinding }

theorem accepted_materialized_transfer_no_theft_publication_from_spend_soundness
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
    {statementFields :
      Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    (materializedFacts :
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
        completeNativeNodeEquivalence)
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
    (spendSound :
      DeployedTxVerifierSpendSoundnessAssumption
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
        spendWitnesses)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
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
      materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence := by
  have noTheftFacts :=
    validated_transfer_payload_active_input_no_theft_full_binding_from_spend_soundness
      (payload := payload)
      (transferKey := transferKey)
      (input := txLeaf)
      (wrapper := wrapper)
      (shape := shape)
      (publicFields := publicFields)
      (serializedFields := serializedFields)
      (bound := bound)
      (statementFields := statementFields)
      (statementBytes := statementBytes)
      (bindingFields := bindingFields)
      (bindingBytes := bindingBytes)
      (merkleRoot := merkleRoot)
      (spendWitnesses := spendWitnesses)
      (index := index)
      (activeFlag := activeFlag)
      (publicNullifier := publicNullifier)
      (witness := witness)
      payloadAccepted
      txLeafAccepted
      canonicalSurface
      spendSound
      slot
      active
  have authorizationFacts :=
    validated_transfer_payload_input_slot_authorization_full_binding_from_spend_soundness
      (payload := payload)
      (transferKey := transferKey)
      (input := txLeaf)
      (wrapper := wrapper)
      (shape := shape)
      (publicFields := publicFields)
      (serializedFields := serializedFields)
      (bound := bound)
      (statementFields := statementFields)
      (statementBytes := statementBytes)
      (bindingFields := bindingFields)
      (bindingBytes := bindingBytes)
      (merkleRoot := merkleRoot)
      (spendWitnesses := spendWitnesses)
      (index := index)
      (activeFlag := activeFlag)
      (publicNullifier := publicNullifier)
      (witness := witness)
      payloadAccepted
      txLeafAccepted
      canonicalSurface
      spendSound
      slot
  exact
    { materializedDaPublicationFacts := materializedFacts
      noTheftBoundaryFacts := noTheftFacts
      inputSlotAuthorizationBoundaryFacts := authorizationFacts
      replayedSupply := materializedFacts.replayedSupply
      acceptedLedgerTreeReplay := materializedFacts.acceptedLedgerTreeReplay
      commitmentRootPublication := materializedFacts.commitmentRootPublication
      finalReplaySetsUnique := materializedFacts.finalReplaySetsUnique
      txLeafStatementArtifactFacts :=
        materializedFacts.fullBytePublication.txLeafFullStatementArtifactFacts
      txLeafCiphertextPublication :=
        materializedFacts.txLeafCiphertextPublication
      statementCiphertextVectorPublication :=
        materializedFacts.statementCiphertextVectorPublication
      candidateDaPublication := materializedFacts.candidateDaPublication
      provenBatchDaPublication := materializedFacts.provenBatchDaPublication
      recursiveSemanticDaPublication :=
        materializedFacts.recursiveSemanticDaPublication
      activeInputNoTheftFullBinding :=
        noTheftFacts.noTheftFullBinding
      inputSlotAuthorizationFullBinding :=
        authorizationFacts.inputSlotFullBinding }

theorem accepted_materialized_transfer_no_theft_publication_authorized_asset_delta_value
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
    {statementFields :
      Hegemon.Transaction.StatementHash.StatementFields}
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
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    (materializedFacts :
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
        completeNativeNodeEquivalence)
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
    (sound :
      DeployedTxVerifierSoundnessAssumption
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
        slots)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
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
      materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence
    ∧ Hegemon.Transaction.slotDelta assetId slots =
      Hegemon.Transaction.AssetIsolation.authorizedAssetDeltaValue
        balanceWitness
        assetId := by
  exact
    ⟨accepted_materialized_transfer_no_theft_publication
        (materializedFacts := materializedFacts)
        (payloadAccepted := payloadAccepted)
        (txLeafAccepted := txLeafAccepted)
        (canonicalSurface := canonicalSurface)
        (sound := sound)
        (assetId := assetId)
        (slot := slot)
        (active := active),
      (native_tx_leaf_binding_and_canonical_surface_authorized_asset_delta_value
        (input := txLeaf)
        (wrapper := wrapper)
        (shape := shape)
        (publicFields := publicFields)
        (serializedFields := serializedFields)
        (bound := bound)
        (statementFields := statementFields)
        (statementBytes := statementBytes)
        (bindingFields := bindingFields)
        (bindingBytes := bindingBytes)
        (merkleRoot := merkleRoot)
        (spendWitnesses := spendWitnesses)
        (balanceWitness := balanceWitness)
        (slots := slots)
        (assetId := assetId)
        txLeafAccepted
        canonicalSurface
        sound).left⟩

theorem accepted_materialized_transfer_no_theft_publication_public_non_native_nonzero_requires_stablecoin_exception
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
    {statementFields :
      Hegemon.Transaction.StatementHash.StatementFields}
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
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    (materializedFacts :
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
        completeNativeNodeEquivalence)
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
    (spendSound :
      DeployedTxVerifierSpendSoundnessAssumption
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
        spendWitnesses)
    (balanceSound :
      DeployedTxVerifierBalancePublicFieldSoundnessAssumption
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
        balanceWitness
        slots)
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
    (nonzero : Hegemon.Transaction.slotDelta assetId slots ≠ 0) :
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
      materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence
    ∧ publicFields.stablecoinEnabled = 1
    ∧ assetId = publicFields.stablecoinAsset := by
  have publicationFacts :=
    accepted_materialized_transfer_no_theft_publication_from_spend_soundness
      (transferKey := transferKey)
      (materializedFacts := materializedFacts)
      (payloadAccepted := payloadAccepted)
      (txLeafAccepted := txLeafAccepted)
      (canonicalSurface := canonicalSurface)
      (spendSound := spendSound)
      (slot := slot)
      (active := active)
  have exceptionFacts :
      publicFields.stablecoinEnabled = 1
        ∧ assetId = publicFields.stablecoinAsset :=
    canonical_statement_balance_soundness_non_native_nonzero_public_stablecoin_exception
      canonicalSurface
      balanceSound
      nonNative
      nonzero
  exact ⟨publicationFacts, exceptionFacts⟩

theorem materialized_transfer_no_theft_publication_output_slot_statement_artifact_facts
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
    {statementFields :
      Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness :
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    (facts :
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
        materializedRowsFeedTransactionNew
        transactionNewFeedsConsensusDaBlob
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence)
    {outputIndex outputActiveFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (slot :
      Hegemon.Transaction.PublicInputs.OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        outputIndex
        outputActiveFlag
        publicCommitment
        publicCiphertextHash) :
    NativeTxLeafFullStatementArtifactOutputSlotFacts
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
      outputIndex
      outputActiveFlag
      publicCommitment
      publicCiphertextHash := by
  exact
    native_tx_leaf_full_statement_artifact_output_slot_full_binding
      facts.txLeafStatementArtifactFacts
      slot

end MaterializedTransferNoTheftPublication
end Native
end Hegemon

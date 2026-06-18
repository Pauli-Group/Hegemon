import Hegemon.Native.MaterializedSidecarDaBlobPublication
import Hegemon.Native.StablecoinPolicyLiveAuthorization
import Hegemon.Native.TransferNoTheftBoundary
import Hegemon.Transaction.SmallWoodVerifierSoundnessEnvelope

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
open Hegemon.Native.StablecoinPolicyAuthorization
open Hegemon.Native.StablecoinPolicyLiveAuthorization
open Hegemon.Native.TransferActionPayloadAdmission
open Hegemon.Native.TransferNoTheftBoundary
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofSystemBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SmallWoodVerifierSoundnessEnvelope

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

theorem accepted_materialized_transfer_no_theft_publication_from_spend_boundary_facts
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
    (spendFacts :
      CanonicalDeployedVerifierSpendBoundaryFacts
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
    validated_transfer_payload_active_input_no_theft_full_binding_from_spend_boundary_facts
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
      spendFacts
      slot
      active
  have authorizationFacts :=
    validated_transfer_payload_input_slot_authorization_full_binding_from_spend_boundary_facts
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
      spendFacts
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

theorem accepted_materialized_transfer_no_theft_publication_stablecoin_mint_exception_surface
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
    ∧ StablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      (Hegemon.Transaction.slotDelta assetId slots) := by
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
  have exceptionSurface :
      StablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        (Hegemon.Transaction.slotDelta assetId slots) :=
    canonical_statement_balance_soundness_non_native_nonzero_stablecoin_mint_exception_surface
      canonicalSurface
      balanceSound
      nonNative
      nonzero
  exact ⟨publicationFacts, exceptionSurface⟩

theorem accepted_materialized_transfer_no_theft_publication_authorized_stablecoin_mint_exception_surface
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
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
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
    (nonzero : Hegemon.Transaction.slotDelta assetId slots ≠ 0)
    (authorized :
      livePolicyAuthorizes
        (stablecoinMintExceptionPayload
          publicFields
          assetId
          (Hegemon.Transaction.slotDelta assetId slots))) :
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
    ∧ AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      (Hegemon.Transaction.slotDelta assetId slots)
      livePolicyAuthorizes := by
  have exceptionResult :=
    accepted_materialized_transfer_no_theft_publication_stablecoin_mint_exception_surface
      (transferKey := transferKey)
      (materializedFacts := materializedFacts)
      (payloadAccepted := payloadAccepted)
      (txLeafAccepted := txLeafAccepted)
      (canonicalSurface := canonicalSurface)
      (spendSound := spendSound)
      (balanceSound := balanceSound)
      (slot := slot)
      (active := active)
      (nonNative := nonNative)
      (nonzero := nonzero)
  rcases exceptionResult with ⟨publicationFacts, exceptionSurface⟩
  exact
    ⟨publicationFacts,
      stablecoin_mint_exception_authorized_payload_bound_to_statement
        exceptionSurface
        authorized⟩

theorem accepted_materialized_transfer_no_theft_publication_native_policy_authorized_stablecoin_mint_exception_surface
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
    {policyInput : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
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
    ∧ AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      (Hegemon.Transaction.slotDelta assetId slots)
      (nativeStablecoinLivePolicyAuthorizes
        policyInput
        productionPayload)
    ∧ NativeStablecoinLiveAuthorizationFacts
      policyInput
      productionPayload := by
  have publicationAndSurface :=
    accepted_materialized_transfer_no_theft_publication_stablecoin_mint_exception_surface
      (transferKey := transferKey)
      (materializedFacts := materializedFacts)
      (payloadAccepted := payloadAccepted)
      (txLeafAccepted := txLeafAccepted)
      (canonicalSurface := canonicalSurface)
      (spendSound := spendSound)
      (balanceSound := balanceSound)
      (slot := slot)
      (active := active)
      (nonNative := nonNative)
      (nonzero := nonzero)
  have authorizedPublication :=
    publication_stablecoin_exception_surface_authorized_by_native_policy
      publicationAndSurface
      present
      policyAccepted
      exactPayload
  exact
    ⟨authorizedPublication.1,
      authorizedPublication.2,
      native_policy_authorization_accepts_live_authorization_facts
        present
        policyAccepted⟩

theorem accepted_materialized_transfer_publication_from_smallwood_native_policy_certificate
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
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    {policyInput : StablecoinPolicyAuthorizationInput}
    {productionPayload : StablecoinMintExceptionPayload}
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
    ∧ SmallWoodPublicStatementVerifierExportFacts
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
    ∧ Hegemon.Transaction.slotDelta assetId slots =
      publicAuthorizedAssetDeltaValue publicFields assetId
    ∧ AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      (Hegemon.Transaction.slotDelta assetId slots)
      (nativeStablecoinLivePolicyAuthorizes
        policyInput
        productionPayload)
    ∧ NativeStablecoinLiveAuthorizationFacts
      policyInput
      productionPayload := by
  have publicationFacts :=
    accepted_materialized_transfer_no_theft_publication_from_spend_boundary_facts
      (transferKey := transferKey)
      (materializedFacts := materializedFacts)
      (payloadAccepted := payloadAccepted)
      (txLeafAccepted := txLeafAccepted)
      (spendFacts := smallwoodExport.verifierEnvelopeFacts.spendBoundaryFacts)
      (slot := slot)
      (active := active)
  have exceptionSurface :
      StablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        (Hegemon.Transaction.slotDelta assetId slots) :=
    smallwoodExport.nonNativeNonzeroStablecoinException
      nonNative
      nonzero
  have authorizedPublication :=
    publication_stablecoin_exception_surface_authorized_by_native_policy
      ⟨publicationFacts, exceptionSurface⟩
      present
      policyAccepted
      exactPayload
  have publicDelta :
      Hegemon.Transaction.slotDelta assetId slots =
        publicAuthorizedAssetDeltaValue publicFields assetId :=
    smallwoodExport.noTheftAndPublicConservation.right.left
  exact
    ⟨authorizedPublication.1,
      smallwoodExport,
      publicDelta,
      authorizedPublication.2,
      native_policy_authorization_accepts_live_authorization_facts
        present
        policyAccepted⟩

theorem smallwood_public_statement_export_yields_native_live_public_asset_isolation_certificate
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
        airBalanceSurface) :
    PublicAssetIsolationCertificate
      publicFields
      bound
      statementFields
      bindingFields
      slots
      (nativeStablecoinLivePolicyAuthorizes policyInput productionPayload) := by
  exact
    smallwood_public_statement_export_yields_public_asset_isolation_certificate
      smallwoodExport

structure MaterializedTransferNoTheftImplementationResidualAssumptions where
  parserAndCodecProjectionEquivalence : Prop
  materializedRowsFeedTransactionNew : Prop
  transactionNewFeedsConsensusDaBlob : Prop
  daRootHashSecurityEquivalence : Prop
  daAvailabilityRetention : Prop
  proofSystemSoundnessBoundary : Prop
  storageDurabilityBelowSled : Prop
  completeNativeNodeEquivalence : Prop

structure MaterializedTransferNoTheftImplementationEquivalenceCertificate
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
    (balanceWitness : Hegemon.Transaction.BalanceWitness)
    (slots : List Hegemon.Transaction.BalanceSlot)
    (index activeFlag : Nat)
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
    (materializedResiduals :
      MaterializedTransferNoTheftImplementationResidualAssumptions)
    (smallwoodResiduals : SmallWoodProofSystemResidualAssumptions) :
    Prop where
  materializedPublication :
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
      materializedResiduals.materializedRowsFeedTransactionNew
      materializedResiduals.transactionNewFeedsConsensusDaBlob
      materializedResiduals.daRootHashSecurityEquivalence
      materializedResiduals.daAvailabilityRetention
      materializedResiduals.proofSystemSoundnessBoundary
      materializedResiduals.completeNativeNodeEquivalence
  smallwoodResidualCertificate :
    SmallWoodResidualVerifierExportCanonicalSoundnessCertificate
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
      smallwoodResiduals
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
  proofSystemNoTheftBoundaryFacts :
    CanonicalProofSystemNoTheftBoundaryFacts
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
  activeInputNoTheftBinding :
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
  totalInputSlotAuthorization :
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
  replayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  finalReplaySetsUnique :
    final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup
  parserAndCodecProjectionEquivalence :
    materializedResiduals.parserAndCodecProjectionEquivalence
  materializedRowsFeedTransactionNew :
    materializedResiduals.materializedRowsFeedTransactionNew
  transactionNewFeedsConsensusDaBlob :
    materializedResiduals.transactionNewFeedsConsensusDaBlob
  daRootHashSecurityEquivalence :
    materializedResiduals.daRootHashSecurityEquivalence
  daAvailabilityRetention :
    materializedResiduals.daAvailabilityRetention
  proofSystemSoundnessBoundary :
    materializedResiduals.proofSystemSoundnessBoundary
  storageDurabilityBelowSled :
    materializedResiduals.storageDurabilityBelowSled
  completeNativeNodeEquivalence :
    materializedResiduals.completeNativeNodeEquivalence
  starkAirConstraintSoundness :
    smallwoodResiduals.starkAirConstraintSoundness
  pcsOpeningBinding :
    smallwoodResiduals.pcsOpeningBinding
  transcriptHashRandomOracle :
    smallwoodResiduals.transcriptHashRandomOracle
  merkleAndCommitmentHashSecurity :
    smallwoodResiduals.merkleAndCommitmentHashSecurity
  witnessExtractionCompleteness :
    smallwoodResiduals.witnessExtractionCompleteness
  verifierImplementationEquivalence :
    smallwoodResiduals.verifierImplementationEquivalence

theorem accepted_materialized_transfer_no_theft_from_smallwood_residuals_yields_implementation_equivalence_certificate
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
    {index activeFlag : Nat}
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
    {materializedResiduals :
      MaterializedTransferNoTheftImplementationResidualAssumptions}
    {smallwoodResiduals : SmallWoodProofSystemResidualAssumptions}
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
        materializedResiduals.materializedRowsFeedTransactionNew
        materializedResiduals.transactionNewFeedsConsensusDaBlob
        materializedResiduals.daRootHashSecurityEquivalence
        materializedResiduals.daAvailabilityRetention
        materializedResiduals.proofSystemSoundnessBoundary
        materializedResiduals.completeNativeNodeEquivalence)
    (payloadAccepted :
      transferPayloadAccepts payload = true)
    (txLeafAccepted :
      BlockArtifactBindingAdmission.txLeafActionBindingAccepts txLeaf = true)
    (smallwoodResidualCertificate :
      SmallWoodResidualVerifierExportCanonicalSoundnessCertificate
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
        smallwoodResiduals)
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
    (parserAndCodecProjectionEquivalence :
      materializedResiduals.parserAndCodecProjectionEquivalence)
    (materializedRowsFeedTransactionNew :
      materializedResiduals.materializedRowsFeedTransactionNew)
    (transactionNewFeedsConsensusDaBlob :
      materializedResiduals.transactionNewFeedsConsensusDaBlob)
    (daRootHashSecurityEquivalence :
      materializedResiduals.daRootHashSecurityEquivalence)
    (daAvailabilityRetention :
      materializedResiduals.daAvailabilityRetention)
    (proofSystemSoundnessBoundary :
      materializedResiduals.proofSystemSoundnessBoundary)
    (storageDurabilityBelowSled :
      materializedResiduals.storageDurabilityBelowSled)
    (completeNativeNodeEquivalence :
      materializedResiduals.completeNativeNodeEquivalence) :
    MaterializedTransferNoTheftImplementationEquivalenceCertificate
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
      materializedResiduals
      smallwoodResiduals := by
  have publicationFacts :=
    accepted_materialized_transfer_no_theft_publication_from_spend_boundary_facts
      (transferKey := transferKey)
      (materializedFacts := materializedFacts)
      (payloadAccepted := payloadAccepted)
      (txLeafAccepted := txLeafAccepted)
      (spendFacts :=
        smallwoodResidualCertificate.verifierExport.verifierEnvelopeFacts.spendBoundaryFacts)
      (slot := slot)
      (active := active)
  exact
    { materializedPublication := publicationFacts
      smallwoodResidualCertificate := smallwoodResidualCertificate
      smallwoodVerifierExport := smallwoodResidualCertificate.verifierExport
      proofSystemNoTheftBoundaryFacts :=
        smallwoodResidualCertificate.proofSystemNoTheftBoundaryFacts
      activeInputNoTheftBinding :=
        publicationFacts.activeInputNoTheftFullBinding
      totalInputSlotAuthorization :=
        publicationFacts.inputSlotAuthorizationFullBinding
      txLeafStatementArtifactFacts :=
        publicationFacts.txLeafStatementArtifactFacts
      replayedSupply := publicationFacts.replayedSupply
      finalReplaySetsUnique := publicationFacts.finalReplaySetsUnique
      parserAndCodecProjectionEquivalence :=
        parserAndCodecProjectionEquivalence
      materializedRowsFeedTransactionNew :=
        materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob :=
        transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence :=
        daRootHashSecurityEquivalence
      daAvailabilityRetention := daAvailabilityRetention
      proofSystemSoundnessBoundary := proofSystemSoundnessBoundary
      storageDurabilityBelowSled := storageDurabilityBelowSled
      completeNativeNodeEquivalence := completeNativeNodeEquivalence
      starkAirConstraintSoundness :=
        smallwoodResidualCertificate.starkAirConstraintSoundness
      pcsOpeningBinding :=
        smallwoodResidualCertificate.pcsOpeningBinding
      transcriptHashRandomOracle :=
        smallwoodResidualCertificate.transcriptHashRandomOracle
      merkleAndCommitmentHashSecurity :=
        smallwoodResidualCertificate.merkleAndCommitmentHashSecurity
      witnessExtractionCompleteness :=
        smallwoodResidualCertificate.witnessExtractionCompleteness
      verifierImplementationEquivalence :=
        smallwoodResidualCertificate.verifierImplementationEquivalence }

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

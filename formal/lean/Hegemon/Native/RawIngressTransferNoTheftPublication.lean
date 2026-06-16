import Hegemon.Native.RawIngressPendingActionPublicationRefinement
import Hegemon.Native.TransferNoTheftBoundary

namespace Hegemon
namespace Native
namespace RawIngressTransferNoTheftPublication

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.PendingActionReload
open Hegemon.Native.RawIngressPendingActionPublicationRefinement
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TransferActionPayloadAdmission
open Hegemon.Native.TransferNoTheftBoundary
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

structure RawIngressTransferNoTheftAuthorizationPublicationFacts
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
      Hegemon.Transaction.SpendAuthorization.InputSpendWitness) : Prop where
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
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
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

theorem accepted_raw_ingress_transfer_payload_no_theft_authorization_publication
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
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
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
    RawIngressTransferNoTheftAuthorizationPublicationFacts
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
      witness := by
  have rawTxLeafFacts :=
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
    {
      rawIngressTxLeafPublicationFacts := rawTxLeafFacts,
      noTheftBoundaryFacts := noTheftFacts,
      inputSlotAuthorizationBoundaryFacts := authorizationFacts,
      replayedSupply :=
        rawTxLeafFacts.rawIngressPendingActionPublicationFacts.replayedSupply,
      finalSpentNullifiersUnique :=
        rawTxLeafFacts.rawIngressPendingActionPublicationFacts.finalSpentNullifiersUnique,
      txLeafStatementArtifactFacts :=
        rawTxLeafFacts.txLeafStatementArtifactFacts,
      activeInputNoTheftFullBinding :=
        noTheftFacts.noTheftFullBinding,
      inputSlotAuthorizationFullBinding :=
        authorizationFacts.inputSlotFullBinding
    }

theorem accepted_raw_ingress_transfer_payload_no_theft_authorization_publication_from_spend_soundness
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
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
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
    RawIngressTransferNoTheftAuthorizationPublicationFacts
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
      witness := by
  have rawTxLeafFacts :=
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
    {
      rawIngressTxLeafPublicationFacts := rawTxLeafFacts,
      noTheftBoundaryFacts := noTheftFacts,
      inputSlotAuthorizationBoundaryFacts := authorizationFacts,
      replayedSupply :=
        rawTxLeafFacts.rawIngressPendingActionPublicationFacts.replayedSupply,
      finalSpentNullifiersUnique :=
        rawTxLeafFacts.rawIngressPendingActionPublicationFacts.finalSpentNullifiersUnique,
      txLeafStatementArtifactFacts :=
        rawTxLeafFacts.txLeafStatementArtifactFacts,
      activeInputNoTheftFullBinding :=
        noTheftFacts.noTheftFullBinding,
      inputSlotAuthorizationFullBinding :=
        authorizationFacts.inputSlotFullBinding
    }

theorem accepted_raw_ingress_transfer_payload_authorized_asset_delta_value
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
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
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
    RawIngressTransferNoTheftAuthorizationPublicationFacts
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
    ∧ Hegemon.Transaction.slotDelta assetId slots =
      Hegemon.Transaction.AssetIsolation.authorizedAssetDeltaValue
        balanceWitness
        assetId := by
  exact
    ⟨accepted_raw_ingress_transfer_payload_no_theft_authorization_publication
        (rawIngressFacts := rawIngressFacts)
        (sidecarRoute := sidecarRoute)
        (pendingDecodeAccepted := pendingDecodeAccepted)
        (blockActionDecodeAccepted := blockActionDecodeAccepted)
        (actionHashAccepted := actionHashAccepted)
        (wireActionCountMatchesDeclared := wireActionCountMatchesDeclared)
        (blockIndexAccepted := blockIndexAccepted)
        (canonicalStateAccepted := canonicalStateAccepted)
        (canonicalReorgAccepted := canonicalReorgAccepted)
        (atomicCommitAccepted := atomicCommitAccepted)
        (durabilityAccepted := durabilityAccepted)
        (initialNullifiersNodup := initialNullifiersNodup)
        (initialBridgeReplaysNodup := initialBridgeReplaysNodup)
        (acceptedRaw := acceptedRaw)
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

theorem accepted_raw_ingress_transfer_payload_public_non_native_nonzero_requires_stablecoin_exception
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
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
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
    RawIngressTransferNoTheftAuthorizationPublicationFacts
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
    ∧ publicFields.stablecoinEnabled = 1
    ∧ assetId = publicFields.stablecoinAsset := by
  have publicationFacts :=
    accepted_raw_ingress_transfer_payload_no_theft_authorization_publication_from_spend_soundness
      (transferKey := transferKey)
      (rawIngressFacts := rawIngressFacts)
      (sidecarRoute := sidecarRoute)
      (pendingDecodeAccepted := pendingDecodeAccepted)
      (blockActionDecodeAccepted := blockActionDecodeAccepted)
      (actionHashAccepted := actionHashAccepted)
      (wireActionCountMatchesDeclared := wireActionCountMatchesDeclared)
      (blockIndexAccepted := blockIndexAccepted)
      (canonicalStateAccepted := canonicalStateAccepted)
      (canonicalReorgAccepted := canonicalReorgAccepted)
      (atomicCommitAccepted := atomicCommitAccepted)
      (durabilityAccepted := durabilityAccepted)
      (initialNullifiersNodup := initialNullifiersNodup)
      (initialBridgeReplaysNodup := initialBridgeReplaysNodup)
      (acceptedRaw := acceptedRaw)
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

end RawIngressTransferNoTheftPublication
end Native
end Hegemon

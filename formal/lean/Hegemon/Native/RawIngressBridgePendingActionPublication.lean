import Hegemon.Bridge.MintReplayPolicy
import Hegemon.Native.BridgeMintSafety
import Hegemon.Native.CanonicalPublicationRefinement
import Hegemon.Native.InboundBridgeReceiptAdmission
import Hegemon.Native.NativeBackendReviewPolicy
import Hegemon.Native.RawIngressPendingActionPublicationRefinement

namespace Hegemon
namespace Native
namespace RawIngressBridgePendingActionPublication

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.BridgeActionPayloadAdmission
open Hegemon.Native.BridgeMintSafety
open Hegemon.Native.CanonicalPublicationRefinement
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.InboundBridgeReceiptAdmission
open Hegemon.Native.NativeBackendReviewPolicy
open Hegemon.Native.PendingActionReload
open Hegemon.Native.RawIngressPendingActionPublicationRefinement
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission

structure RawIngressBridgePendingActionPublicationFacts
    (input : BridgePayloadInput)
    (mintSurface : InboundBridgeMintAmountSurface)
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
    (consumed next : List Nat)
    (replay imported : Nat)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) : Prop where
  rawIngressPendingActionPublicationFacts :
    RawIngressPendingActionPublicationFacts
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
  rawIngressLedgerTreePublicationFacts :
    RawIngressLedgerTreePublicationFacts
      surface
      semanticFields
      initial
      final
      blocks
  inboundPayloadAuthorizationFacts :
    InboundBridgePayloadAuthorizationFacts input
  mintPayloadHashMatches :
    mintSurface.payloadHashMatches = true
  mintAmountBound :
    mintSurface.decodedPayloadAmount =
      mintSurface.authorizedExternalAmount
  noDirectNativeMint :
    inboundBridgeDirectMintDelta input = 0
  replayConsumed :
    replay ∈ next
  importedOnce :
    imported = 1
  nextReplaySetUnique :
    next.Nodup
  duplicateReplayRejects :
    importBridgeReplay next (some replay) =
      Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate
  pendingActionRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
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
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup

structure RawIngressBridgeCanonicalPublicationReplayFacts
    (input : BridgePayloadInput)
    (mintSurface : InboundBridgeMintAmountSurface)
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
    (receipt : InboundBridgeReceiptInput)
    (backendReview : NativeBackendReviewInput)
    (consumed next : List Nat)
    (replay imported : Nat)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (externalReceiptPqVerifierSoundness : Prop) : Prop where
  externalReceiptPqVerifierSound :
    externalReceiptPqVerifierSoundness
  receiptAccepted :
    inboundBridgeReceiptAccepts receipt = true
  receiptPreconditions :
    inboundBridgeReceiptPreconditions receipt = true
  backendReviewAccepted :
    nativeBackendReviewAccepts backendReview = true
  backendReviewPreconditions :
    nativeBackendReviewPreconditions backendReview = true
  bridgePendingActionPublicationFacts :
    RawIngressBridgePendingActionPublicationFacts
      input
      mintSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks
  rawBytePublication :
    RawIngressPendingActionPublicationFacts
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
  inboundPayloadAuthorizationFacts :
    InboundBridgePayloadAuthorizationFacts input
  mintPayloadHashMatches :
    mintSurface.payloadHashMatches = true
  mintAmountBound :
    mintSurface.decodedPayloadAmount =
      mintSurface.authorizedExternalAmount
  noDirectNativeMint :
    inboundBridgeDirectMintDelta input = 0
  replayConsumed :
    replay ∈ next
  importedOnce :
    imported = 1
  nextReplaySetUnique :
    next.Nodup
  duplicateReplayRejects :
    importBridgeReplay next (some replay) =
      Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate
  rawByteReplayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  canonicalReplayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger.supply
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup

structure RawIngressBridgeCanonicalPublicationFacts
    (input : BridgePayloadInput)
    (mintSurface : InboundBridgeMintAmountSurface)
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
    (consumed next : List Nat)
    (replay imported : Nat)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) : Prop where
  bridgePendingActionPublicationFacts :
    RawIngressBridgePendingActionPublicationFacts
      input
      mintSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks
  rawBytePublication :
    RawIngressPendingActionPublicationFacts
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
  rawIngressLedgerTreePublicationFacts :
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
  rawTreeCarriedStatePreconditions :
    rawProjectedTreeCarriedStatePreconditions initial blocks = true
  inboundPayloadAuthorizationFacts :
    InboundBridgePayloadAuthorizationFacts input
  mintPayloadHashMatches :
    mintSurface.payloadHashMatches = true
  mintAmountBound :
    mintSurface.decodedPayloadAmount =
      mintSurface.authorizedExternalAmount
  noDirectNativeMint :
    inboundBridgeDirectMintDelta input = 0
  replayConsumed :
    replay ∈ next
  importedOnce :
    imported = 1
  nextReplaySetUnique :
    next.Nodup
  duplicateReplayRejects :
    importBridgeReplay next (some replay) =
      Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate
  rawByteReplayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  canonicalReplayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger.supply
  rawCommitmentRootPublication :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  canonicalCommitmentRootPublication :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  canonicalCommitmentPlan :
    nativeLedgerReplayCommitmentPlanPreconditions
      initial.ledger
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      true
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup

theorem accepted_inbound_bridge_raw_ingress_pending_action_publication_safe
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
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
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
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
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressBridgePendingActionPublicationFacts
      input
      mintSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks := by
  have rawPendingFacts :=
    accepted_raw_ingress_pending_action_bytes_bind_publication
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
  have bridgeFacts :=
    accepted_inbound_payload_authorized_amount_raw_ingress_tree_replay_safe
      inbound
      acceptedPayload
      authorized
      rawIngressFacts
      sidecarRoute
      consumedNodup
      fresh
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  rcases bridgeFacts with
    ⟨rawPublicationFacts,
      payloadFacts,
      payloadHash,
      decodedAmount,
      noDirectMint,
      replayMem,
      importedOne,
      nextNodup,
      duplicateRejects,
      finalNullifiers,
      finalReplays⟩
  exact
    {
      rawIngressPendingActionPublicationFacts := rawPendingFacts,
      rawIngressLedgerTreePublicationFacts := rawPublicationFacts,
      inboundPayloadAuthorizationFacts := payloadFacts,
      mintPayloadHashMatches := payloadHash,
      mintAmountBound := decodedAmount,
      noDirectNativeMint := noDirectMint,
      replayConsumed := replayMem,
      importedOnce := importedOne,
      nextReplaySetUnique := nextNodup,
      duplicateReplayRejects := duplicateRejects,
      pendingActionRowsMatchDecodedPayloads :=
        rawPendingFacts.pendingActionRowsMatchDecodedPayloads,
      commitmentRootPublication :=
        rawPendingFacts.commitmentRootPublication,
      replayedSupply :=
        rawPendingFacts.replayedSupply,
      finalSpentNullifiersUnique :=
        finalNullifiers,
      finalBridgeReplaysUnique :=
        finalReplays
    }

theorem accepted_inbound_bridge_raw_ingress_canonical_publication_safe
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
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
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
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
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressBridgeCanonicalPublicationFacts
      input
      mintSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks := by
  have bridgePendingFacts :=
    accepted_inbound_bridge_raw_ingress_pending_action_publication_safe
      (input := input)
      (mintSurface := mintSurface)
      (surface := surface)
      (streamOutput := streamOutput)
      (wireOutput := wireOutput)
      (semanticFields := semanticFields)
      (pendingDecode := pendingDecode)
      (blockActionDecode := blockActionDecode)
      (actionHash := actionHash)
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (consumed := consumed)
      (next := next)
      (replay := replay)
      (imported := imported)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      inbound
      acceptedPayload
      authorized
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
      consumedNodup
      fresh
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  rcases
    accepted_raw_canonical_publication_refines_ledger_tree_replay
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw with
    ⟨canonicalFacts, rawTreeCarriedStatePreconditions⟩
  exact
    {
      bridgePendingActionPublicationFacts := bridgePendingFacts,
      rawBytePublication :=
        bridgePendingFacts.rawIngressPendingActionPublicationFacts,
      rawIngressLedgerTreePublicationFacts :=
        bridgePendingFacts.rawIngressLedgerTreePublicationFacts,
      canonicalPublicationFacts := canonicalFacts,
      rawTreeCarriedStatePreconditions :=
        rawTreeCarriedStatePreconditions,
      inboundPayloadAuthorizationFacts :=
        bridgePendingFacts.inboundPayloadAuthorizationFacts,
      mintPayloadHashMatches :=
        bridgePendingFacts.mintPayloadHashMatches,
      mintAmountBound :=
        bridgePendingFacts.mintAmountBound,
      noDirectNativeMint :=
        bridgePendingFacts.noDirectNativeMint,
      replayConsumed :=
        bridgePendingFacts.replayConsumed,
      importedOnce :=
        bridgePendingFacts.importedOnce,
      nextReplaySetUnique :=
        bridgePendingFacts.nextReplaySetUnique,
      duplicateReplayRejects :=
        bridgePendingFacts.duplicateReplayRejects,
      rawByteReplayedSupply :=
        bridgePendingFacts.replayedSupply,
      canonicalReplayedSupply :=
        canonicalFacts.replayedSupply,
      rawCommitmentRootPublication :=
        bridgePendingFacts.commitmentRootPublication,
      canonicalCommitmentRootPublication :=
        canonicalFacts.commitmentRootPublication,
      canonicalCommitmentPlan :=
        canonicalFacts.canonicalCommitmentPlan,
      finalSpentNullifiersUnique :=
        bridgePendingFacts.finalSpentNullifiersUnique,
      finalBridgeReplaysUnique :=
        bridgePendingFacts.finalBridgeReplaysUnique
    }

theorem accepted_inbound_bridge_raw_ingress_canonical_publication_authorized_bridge_asset_delta
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
    {assetSurface : InboundBridgeMintAssetSurface}
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
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
    (assetAuthorized :
      bridgeMintAssetAuthorized assetSurface = true)
    (assetDecodedAmountMatches :
      assetSurface.decodedPayloadAmount =
        mintSurface.decodedPayloadAmount)
    (assetAuthorizedAmountMatches :
      assetSurface.authorizedExternalAmount =
        mintSurface.authorizedExternalAmount)
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
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressBridgeCanonicalPublicationFacts
      input
      mintSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks
      ∧ inboundBridgeAuthorizedAssetDeltaValue
          assetSurface
          assetSurface.decodedPayloadAsset =
        mintSurface.decodedPayloadAmount
      ∧ assetSurface.authorizedExternalAmount =
        mintSurface.authorizedExternalAmount
      ∧ assetSurface.decodedPayloadAsset =
        assetSurface.authorizedExternalAsset
      ∧ assetSurface.decodedPayloadAsset ≠ assetSurface.nativeAssetId
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ expectedNativeSupplyAfter
          initial.ledger.supply
          (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
        some final.ledger.supply := by
  have publicationFacts :=
    accepted_inbound_bridge_raw_ingress_canonical_publication_safe
      (input := input)
      (mintSurface := mintSurface)
      (surface := surface)
      (streamOutput := streamOutput)
      (wireOutput := wireOutput)
      (semanticFields := semanticFields)
      (pendingDecode := pendingDecode)
      (blockActionDecode := blockActionDecode)
      (actionHash := actionHash)
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (consumed := consumed)
      (next := next)
      (replay := replay)
      (imported := imported)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      inbound
      acceptedPayload
      authorized
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
      consumedNodup
      fresh
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  have assetFacts :=
    bridge_mint_asset_authorized_facts assetAuthorized
  have assetDelta :=
    bridge_mint_asset_authorized_delta_value assetAuthorized
  have bridgeDelta :
      inboundBridgeAuthorizedAssetDeltaValue
          assetSurface
          assetSurface.decodedPayloadAsset =
        mintSurface.decodedPayloadAmount := by
    calc
      inboundBridgeAuthorizedAssetDeltaValue
          assetSurface
          assetSurface.decodedPayloadAsset =
          assetSurface.decodedPayloadAmount := assetDelta
      _ = mintSurface.decodedPayloadAmount := assetDecodedAmountMatches
  exact
    ⟨publicationFacts,
      bridgeDelta,
      assetAuthorizedAmountMatches,
      assetFacts.right.right.left,
      assetFacts.right.right.right,
      publicationFacts.noDirectNativeMint,
      publicationFacts.canonicalReplayedSupply⟩

theorem accepted_inbound_bridge_raw_ingress_canonical_publication_final_replay_safe
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
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
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
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
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialConsumedBridgeReplays :
      initial.ledger.consumedBridgeReplays = next)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressBridgeCanonicalPublicationFacts
      input
      mintSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks
      ∧ replay ∈ final.ledger.consumedBridgeReplays
      ∧ importBridgeReplay final.ledger.consumedBridgeReplays (some replay) =
        Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate := by
  have publicationFacts :=
    accepted_inbound_bridge_raw_ingress_canonical_publication_safe
      (input := input)
      (mintSurface := mintSurface)
      (surface := surface)
      (streamOutput := streamOutput)
      (wireOutput := wireOutput)
      (semanticFields := semanticFields)
      (pendingDecode := pendingDecode)
      (blockActionDecode := blockActionDecode)
      (actionHash := actionHash)
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (consumed := consumed)
      (next := next)
      (replay := replay)
      (imported := imported)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      inbound
      acceptedPayload
      authorized
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
      consumedNodup
      fresh
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  have rawFacts :=
    accepted_raw_projected_ledger_tree_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  have replayPresentInitial :
      replay ∈ initial.ledger.consumedBridgeReplays := by
    simpa [initialConsumedBridgeReplays] using publicationFacts.replayConsumed
  have replayPresentFinal :
      replay ∈ final.ledger.consumedBridgeReplays :=
    accepted_native_ledger_bridge_replay_preserves_prior_membership
      replayPresentInitial
      rawFacts.right.right.left
  have duplicateFinal :
      importBridgeReplay final.ledger.consumedBridgeReplays (some replay) =
        Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate := by
    have present :
        containsNat replay final.ledger.consumedBridgeReplays = true :=
      containsNat_true_iff.mpr replayPresentFinal
    simp [importBridgeReplay, present]
  exact ⟨publicationFacts, replayPresentFinal, duplicateFinal⟩

theorem accepted_inbound_bridge_raw_ingress_canonical_publication_authorized_asset_final_replay_safe
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
    {assetSurface : InboundBridgeMintAssetSurface}
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
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
    (assetAuthorized :
      bridgeMintAssetAuthorized assetSurface = true)
    (assetDecodedAmountMatches :
      assetSurface.decodedPayloadAmount =
        mintSurface.decodedPayloadAmount)
    (assetAuthorizedAmountMatches :
      assetSurface.authorizedExternalAmount =
        mintSurface.authorizedExternalAmount)
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
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialConsumedBridgeReplays :
      initial.ledger.consumedBridgeReplays = next)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressBridgeCanonicalPublicationFacts
      input
      mintSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks
      ∧ inboundBridgeAuthorizedAssetDeltaValue
          assetSurface
          assetSurface.decodedPayloadAsset =
        mintSurface.decodedPayloadAmount
      ∧ assetSurface.authorizedExternalAmount =
        mintSurface.authorizedExternalAmount
      ∧ assetSurface.decodedPayloadAsset =
        assetSurface.authorizedExternalAsset
      ∧ assetSurface.decodedPayloadAsset ≠ assetSurface.nativeAssetId
      ∧ inboundBridgeDirectMintDelta input = 0
      ∧ replay ∈ final.ledger.consumedBridgeReplays
      ∧ importBridgeReplay final.ledger.consumedBridgeReplays (some replay) =
        Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate
      ∧ expectedNativeSupplyAfter
          initial.ledger.supply
          (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
        some final.ledger.supply := by
  rcases
    accepted_inbound_bridge_raw_ingress_canonical_publication_authorized_bridge_asset_delta
      (input := input)
      (mintSurface := mintSurface)
      (assetSurface := assetSurface)
      (surface := surface)
      (streamOutput := streamOutput)
      (wireOutput := wireOutput)
      (semanticFields := semanticFields)
      (pendingDecode := pendingDecode)
      (blockActionDecode := blockActionDecode)
      (actionHash := actionHash)
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (consumed := consumed)
      (next := next)
      (replay := replay)
      (imported := imported)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      inbound
      acceptedPayload
      authorized
      assetAuthorized
      assetDecodedAmountMatches
      assetAuthorizedAmountMatches
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
      consumedNodup
      fresh
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw with
    ⟨publicationFacts,
      authorizedDelta,
      authorizedAmount,
      authorizedAsset,
      nonNativeAsset,
      noDirectMint,
      canonicalSupply⟩
  rcases
    accepted_inbound_bridge_raw_ingress_canonical_publication_final_replay_safe
      (input := input)
      (mintSurface := mintSurface)
      (surface := surface)
      (streamOutput := streamOutput)
      (wireOutput := wireOutput)
      (semanticFields := semanticFields)
      (pendingDecode := pendingDecode)
      (blockActionDecode := blockActionDecode)
      (actionHash := actionHash)
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (consumed := consumed)
      (next := next)
      (replay := replay)
      (imported := imported)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      inbound
      acceptedPayload
      authorized
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
      consumedNodup
      fresh
      initialConsumedBridgeReplays
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw with
    ⟨_publicationFacts,
      finalReplayPresent,
      finalReplayRejects⟩
  exact
    ⟨publicationFacts,
      authorizedDelta,
      authorizedAmount,
      authorizedAsset,
      nonNativeAsset,
      noDirectMint,
      finalReplayPresent,
      finalReplayRejects,
      canonicalSupply⟩

structure RawIngressBridgeMintReplayPolicyPublicationFacts
    (input : BridgePayloadInput)
    (mintSurface : InboundBridgeMintAmountSurface)
    (assetSurface : InboundBridgeMintAssetSurface)
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
    (consumed next : List Nat)
    (replay imported : Nat)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput)
    (policyResult :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayAccepted)
    (policyNativeReplayKeyMatches : Prop) : Prop where
  policyAccepted :
    Hegemon.Bridge.MintReplayPolicy.evaluateReceiptMintReplay
      policyInput =
        Except.ok policyResult
  policyFacts :
    Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayFacts
      policyInput
      policyResult
  policyImportsReplayKey :
    policyInput.replayKey ∈ policyResult.nextReplayState.consumed
  policyRejectsReplayAgain :
    policyResult.nextReplayState.importOne policyInput.replayKey = none
  policyNativeReplayKeyMatch :
    policyNativeReplayKeyMatches
  bridgeCanonicalPublicationFacts :
    RawIngressBridgeCanonicalPublicationFacts
      input
      mintSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks
  authorizedBridgeAssetDelta :
    inboundBridgeAuthorizedAssetDeltaValue
        assetSurface
        assetSurface.decodedPayloadAsset =
      mintSurface.decodedPayloadAmount
  authorizedExternalAmountMatches :
    assetSurface.authorizedExternalAmount =
      mintSurface.authorizedExternalAmount
  authorizedExternalAssetMatches :
    assetSurface.decodedPayloadAsset =
      assetSurface.authorizedExternalAsset
  authorizedAssetNonNative :
    assetSurface.decodedPayloadAsset ≠ assetSurface.nativeAssetId
  noDirectNativeMint :
    inboundBridgeDirectMintDelta input = 0
  finalReplayPresent :
    replay ∈ final.ledger.consumedBridgeReplays
  finalReplayRejectsDuplicate :
    importBridgeReplay final.ledger.consumedBridgeReplays (some replay) =
      Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate
  canonicalSupplyIntegrity :
    expectedNativeSupplyAfter
        initial.ledger.supply
        (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger.supply

theorem accepted_inbound_bridge_raw_ingress_canonical_publication_from_mint_replay_policy
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
    {assetSurface : InboundBridgeMintAssetSurface}
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
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput}
    {policyResult :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayAccepted}
    {policyNativeReplayKeyMatches : Prop}
    (policyAccepted :
      Hegemon.Bridge.MintReplayPolicy.evaluateReceiptMintReplay
        policyInput =
          Except.ok policyResult)
    (policyNativeReplayKeyMatch :
      policyNativeReplayKeyMatches)
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
    (assetAuthorized :
      bridgeMintAssetAuthorized assetSurface = true)
    (assetDecodedAmountMatches :
      assetSurface.decodedPayloadAmount =
        mintSurface.decodedPayloadAmount)
    (assetAuthorizedAmountMatches :
      assetSurface.authorizedExternalAmount =
        mintSurface.authorizedExternalAmount)
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
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialConsumedBridgeReplays :
      initial.ledger.consumedBridgeReplays = next)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressBridgeMintReplayPolicyPublicationFacts
      input
      mintSurface
      assetSurface
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
      consumed
      next
      replay
      imported
      initial
      final
      blocks
      policyInput
      policyResult
      policyNativeReplayKeyMatches := by
  rcases
    accepted_inbound_bridge_raw_ingress_canonical_publication_authorized_asset_final_replay_safe
      (input := input)
      (mintSurface := mintSurface)
      (assetSurface := assetSurface)
      (surface := surface)
      (streamOutput := streamOutput)
      (wireOutput := wireOutput)
      (semanticFields := semanticFields)
      (pendingDecode := pendingDecode)
      (blockActionDecode := blockActionDecode)
      (actionHash := actionHash)
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (consumed := consumed)
      (next := next)
      (replay := replay)
      (imported := imported)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      inbound
      acceptedPayload
      authorized
      assetAuthorized
      assetDecodedAmountMatches
      assetAuthorizedAmountMatches
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
      consumedNodup
      fresh
      initialConsumedBridgeReplays
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw with
    ⟨publicationFacts,
      authorizedDelta,
      authorizedAmount,
      authorizedAsset,
      nonNativeAsset,
      noDirectMint,
      finalReplayPresent,
      finalReplayRejects,
      canonicalSupply⟩
  exact
    {
      policyAccepted := policyAccepted,
      policyFacts :=
        Hegemon.Bridge.MintReplayPolicy.accepted_implies_receipt_mint_replay_facts
          policyAccepted,
      policyImportsReplayKey :=
        Hegemon.Bridge.MintReplayPolicy.accepted_imports_replay_key
          policyAccepted,
      policyRejectsReplayAgain :=
        Hegemon.Bridge.MintReplayPolicy.accepted_prevents_replay_again
          policyAccepted,
      policyNativeReplayKeyMatch := policyNativeReplayKeyMatch,
      bridgeCanonicalPublicationFacts := publicationFacts,
      authorizedBridgeAssetDelta := authorizedDelta,
      authorizedExternalAmountMatches := authorizedAmount,
      authorizedExternalAssetMatches := authorizedAsset,
      authorizedAssetNonNative := nonNativeAsset,
      noDirectNativeMint := noDirectMint,
      finalReplayPresent := finalReplayPresent,
      finalReplayRejectsDuplicate := finalReplayRejects,
      canonicalSupplyIntegrity := canonicalSupply
    }

theorem accepted_inbound_bridge_raw_ingress_canonical_publication_replay_safe
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
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
    {receipt : InboundBridgeReceiptInput}
    {backendReview : NativeBackendReviewInput}
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {externalReceiptPqVerifierSoundness : Prop}
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (acceptedPayload : bridgePayloadAccepts input = true)
    (authorized : bridgeMintAmountAuthorized mintSurface = true)
    (receiptAccepted :
      inboundBridgeReceiptAccepts receipt = true)
    (backendReviewAccepted :
      nativeBackendReviewAccepts backendReview = true)
    (externalReceiptPqVerifierSound :
      externalReceiptPqVerifierSoundness)
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
    (consumedNodup : consumed.Nodup)
    (fresh :
      importBridgeReplay consumed (some replay) =
        Except.ok (next, imported))
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressBridgeCanonicalPublicationReplayFacts
      input
      mintSurface
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
      receipt
      backendReview
      consumed
      next
      replay
      imported
      initial
      final
      blocks
      externalReceiptPqVerifierSoundness := by
  have receiptPreconditions :
      inboundBridgeReceiptPreconditions receipt = true :=
    (accepts_iff_inbound_bridge_receipt_preconditions
      (input := receipt)).mp receiptAccepted
  have backendReviewPreconditions :
      nativeBackendReviewPreconditions backendReview = true := by
    rw [← accepts_iff_native_backend_review_preconditions backendReview]
    exact backendReviewAccepted
  have bridgePendingFacts :=
    accepted_inbound_bridge_raw_ingress_pending_action_publication_safe
      (input := input)
      (mintSurface := mintSurface)
      (surface := surface)
      (streamOutput := streamOutput)
      (wireOutput := wireOutput)
      (semanticFields := semanticFields)
      (pendingDecode := pendingDecode)
      (blockActionDecode := blockActionDecode)
      (actionHash := actionHash)
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (consumed := consumed)
      (next := next)
      (replay := replay)
      (imported := imported)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      inbound
      acceptedPayload
      authorized
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
      consumedNodup
      fresh
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  rcases
    accepted_raw_canonical_publication_refines_ledger_tree_replay
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw with
    ⟨canonicalFacts, rawTreeCarriedStatePreconditions⟩
  exact
    {
      externalReceiptPqVerifierSound :=
        externalReceiptPqVerifierSound,
      receiptAccepted := receiptAccepted,
      receiptPreconditions := receiptPreconditions,
      backendReviewAccepted := backendReviewAccepted,
      backendReviewPreconditions := backendReviewPreconditions,
      bridgePendingActionPublicationFacts := bridgePendingFacts,
      rawBytePublication :=
        bridgePendingFacts.rawIngressPendingActionPublicationFacts,
      canonicalPublicationFacts := canonicalFacts,
      rawTreeCarriedStatePreconditions :=
        rawTreeCarriedStatePreconditions,
      inboundPayloadAuthorizationFacts :=
        bridgePendingFacts.inboundPayloadAuthorizationFacts,
      mintPayloadHashMatches :=
        bridgePendingFacts.mintPayloadHashMatches,
      mintAmountBound :=
        bridgePendingFacts.mintAmountBound,
      noDirectNativeMint :=
        bridgePendingFacts.noDirectNativeMint,
      replayConsumed :=
        bridgePendingFacts.replayConsumed,
      importedOnce :=
        bridgePendingFacts.importedOnce,
      nextReplaySetUnique :=
        bridgePendingFacts.nextReplaySetUnique,
      duplicateReplayRejects :=
        bridgePendingFacts.duplicateReplayRejects,
      rawByteReplayedSupply :=
        bridgePendingFacts.replayedSupply,
      canonicalReplayedSupply :=
        canonicalFacts.replayedSupply,
      finalSpentNullifiersUnique :=
        bridgePendingFacts.finalSpentNullifiersUnique,
      finalBridgeReplaysUnique :=
        bridgePendingFacts.finalBridgeReplaysUnique
    }

end RawIngressBridgePendingActionPublication
end Native
end Hegemon

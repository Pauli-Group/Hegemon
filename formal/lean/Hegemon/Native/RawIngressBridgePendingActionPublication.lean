import Hegemon.Bridge.MintReplayPolicy
import Hegemon.Native.BridgeMintSafety
import Hegemon.Native.CanonicalPublicationRefinement
import Hegemon.Native.InboundBridgeReceiptAdmission
import Hegemon.Native.NativeBackendReviewPolicy
import Hegemon.Native.RawIngressPendingActionPublicationRefinement
import Hegemon.Native.Risc0ReleaseVerifier

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
open Hegemon.Native.Risc0ReleaseVerifier
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

structure RawIngressBridgeCanonicalFinalReplayPublicationFacts
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
  canonicalPublicationFacts :
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
  importedReplayStateFeedsCanonicalInitial :
    initial.ledger.consumedBridgeReplays = next
  finalReplayPresent :
    replay ∈ final.ledger.consumedBridgeReplays
  finalReplayRejectsDuplicate :
    importBridgeReplay final.ledger.consumedBridgeReplays (some replay) =
      Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate

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

theorem accepted_inbound_bridge_raw_ingress_canonical_publication_binds_final_replay_state
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
    RawIngressBridgeCanonicalFinalReplayPublicationFacts
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
    ⟨publicationFacts,
      finalReplayPresent,
      finalReplayRejects⟩
  exact
    {
      canonicalPublicationFacts := publicationFacts,
      importedReplayStateFeedsCanonicalInitial :=
        initialConsumedBridgeReplays,
      finalReplayPresent := finalReplayPresent,
      finalReplayRejectsDuplicate := finalReplayRejects
    }

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
  bridgeCanonicalFinalReplayPublicationFacts :
    RawIngressBridgeCanonicalFinalReplayPublicationFacts
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
  have finalReplayPublicationFacts :
      RawIngressBridgeCanonicalFinalReplayPublicationFacts
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
        blocks :=
    {
      canonicalPublicationFacts := publicationFacts,
      importedReplayStateFeedsCanonicalInitial :=
        initialConsumedBridgeReplays,
      finalReplayPresent := finalReplayPresent,
      finalReplayRejectsDuplicate := finalReplayRejects
    }
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
      bridgeCanonicalFinalReplayPublicationFacts :=
        finalReplayPublicationFacts,
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

theorem release_disabled_blocks_receipt_mint_replay_policy_before_replay
    {releaseInput : Risc0ReleaseInput}
    {policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput}
    (disabled : releaseInput.verifierEnabled = false)
    (receiptVerifiedReflectsRelease :
      policyInput.receiptVerified =
        risc0ReleaseVerifierAccepts releaseInput)
    (inbound : policyInput.inboundBridgeMint = true)
    (noDelta : policyInput.stateDeltasAbsent = true)
    (present : policyInput.receiptEnvelopePresent = true) :
    Hegemon.Bridge.MintReplayPolicy.evaluateReceiptMintReplay
      policyInput =
        Except.error
          Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayReject.receiptNotVerified := by
  have releaseRejects :
      risc0ReleaseVerifierAccepts releaseInput = false :=
    release_build_never_accepts disabled
  have notVerified :
      policyInput.receiptVerified = false := by
    rw [receiptVerifiedReflectsRelease, releaseRejects]
  exact
    Hegemon.Bridge.MintReplayPolicy.receipt_not_verified_rejects_before_replay_or_mint
      inbound
      noDelta
      present
      notVerified

theorem release_disabled_precludes_accepted_inbound_bridge_mint_policy
    {releaseInput : Risc0ReleaseInput}
    {policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput}
    {policyResult :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayAccepted}
    (disabled : releaseInput.verifierEnabled = false)
    (receiptVerifiedReflectsRelease :
      policyInput.receiptVerified =
        risc0ReleaseVerifierAccepts releaseInput)
    (policyAccepted :
      Hegemon.Bridge.MintReplayPolicy.evaluateReceiptMintReplay
        policyInput =
          Except.ok policyResult) :
    False := by
  have releaseRejects :
      risc0ReleaseVerifierAccepts releaseInput = false :=
    release_build_never_accepts disabled
  have notVerified :
      policyInput.receiptVerified = false := by
    rw [receiptVerifiedReflectsRelease, releaseRejects]
  have policyFacts :=
    Hegemon.Bridge.MintReplayPolicy.accepted_implies_receipt_mint_replay_facts
      policyAccepted
  have verified :
      policyInput.receiptVerified = true :=
    policyFacts.right.right.right.left
  rw [notVerified] at verified
  contradiction

theorem release_disabled_precludes_raw_ingress_bridge_mint_replay_policy_publication
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
    {assetSurface : InboundBridgeMintAssetSurface}
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
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput}
    {policyResult :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayAccepted}
    {policyNativeReplayKeyMatches : Prop}
    {releaseInput : Risc0ReleaseInput}
    (disabled : releaseInput.verifierEnabled = false)
    (receiptVerifiedReflectsRelease :
      policyInput.receiptVerified =
        risc0ReleaseVerifierAccepts releaseInput)
    (facts :
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
        policyNativeReplayKeyMatches) :
    False :=
  release_disabled_precludes_accepted_inbound_bridge_mint_policy
    disabled
    receiptVerifiedReflectsRelease
    facts.policyAccepted

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

structure RawIngressBridgeMintReplayProductionReviewCertificate
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
    (receipt : InboundBridgeReceiptInput)
    (backendReview : NativeBackendReviewInput)
    (consumed next : List Nat)
    (replay imported : Nat)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput)
    (policyResult :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayAccepted)
    (policyNativeReplayKeyMatches : Prop)
    (externalReceiptPqVerifierSoundness : Prop) : Prop where
  policyPublicationFacts :
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
      policyNativeReplayKeyMatches
  receiptCanonicalReplayFacts :
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
      externalReceiptPqVerifierSoundness
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
  bridgeCanonicalFinalReplayPublicationFacts :
    RawIngressBridgeCanonicalFinalReplayPublicationFacts
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

theorem accepted_inbound_bridge_mint_replay_production_review_certificate
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
    {receipt : InboundBridgeReceiptInput}
    {backendReview : NativeBackendReviewInput}
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput}
    {policyResult :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayAccepted}
    {policyNativeReplayKeyMatches : Prop}
    {externalReceiptPqVerifierSoundness : Prop}
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
    (initialConsumedBridgeReplays :
      initial.ledger.consumedBridgeReplays = next)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressBridgeMintReplayProductionReviewCertificate
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
      receipt
      backendReview
      consumed
      next
      replay
      imported
      initial
      final
      blocks
      policyInput
      policyResult
      policyNativeReplayKeyMatches
      externalReceiptPqVerifierSoundness := by
  have policyPublicationFacts :=
    accepted_inbound_bridge_raw_ingress_canonical_publication_from_mint_replay_policy
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
      (policyInput := policyInput)
      (policyResult := policyResult)
      (policyNativeReplayKeyMatches := policyNativeReplayKeyMatches)
      policyAccepted
      policyNativeReplayKeyMatch
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
      acceptedRaw
  have receiptCanonicalReplayFacts :=
    accepted_inbound_bridge_raw_ingress_canonical_publication_replay_safe
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
      (receipt := receipt)
      (backendReview := backendReview)
      (consumed := consumed)
      (next := next)
      (replay := replay)
      (imported := imported)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      (externalReceiptPqVerifierSoundness :=
        externalReceiptPqVerifierSoundness)
      inbound
      acceptedPayload
      authorized
      receiptAccepted
      backendReviewAccepted
      externalReceiptPqVerifierSound
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
  exact
    {
      policyPublicationFacts := policyPublicationFacts,
      receiptCanonicalReplayFacts := receiptCanonicalReplayFacts,
      externalReceiptPqVerifierSound :=
        receiptCanonicalReplayFacts.externalReceiptPqVerifierSound,
      receiptAccepted :=
        receiptCanonicalReplayFacts.receiptAccepted,
      receiptPreconditions :=
        receiptCanonicalReplayFacts.receiptPreconditions,
      backendReviewAccepted :=
        receiptCanonicalReplayFacts.backendReviewAccepted,
      backendReviewPreconditions :=
        receiptCanonicalReplayFacts.backendReviewPreconditions,
      policyAccepted := policyPublicationFacts.policyAccepted,
      policyFacts := policyPublicationFacts.policyFacts,
      policyImportsReplayKey :=
        policyPublicationFacts.policyImportsReplayKey,
      policyRejectsReplayAgain :=
        policyPublicationFacts.policyRejectsReplayAgain,
      policyNativeReplayKeyMatch :=
        policyPublicationFacts.policyNativeReplayKeyMatch,
      bridgeCanonicalFinalReplayPublicationFacts :=
        policyPublicationFacts.bridgeCanonicalFinalReplayPublicationFacts,
      bridgeCanonicalPublicationFacts :=
        policyPublicationFacts.bridgeCanonicalPublicationFacts,
      authorizedBridgeAssetDelta :=
        policyPublicationFacts.authorizedBridgeAssetDelta,
      authorizedExternalAmountMatches :=
        policyPublicationFacts.authorizedExternalAmountMatches,
      authorizedExternalAssetMatches :=
        policyPublicationFacts.authorizedExternalAssetMatches,
      authorizedAssetNonNative :=
        policyPublicationFacts.authorizedAssetNonNative,
      noDirectNativeMint := policyPublicationFacts.noDirectNativeMint,
      finalReplayPresent := policyPublicationFacts.finalReplayPresent,
      finalReplayRejectsDuplicate :=
        policyPublicationFacts.finalReplayRejectsDuplicate,
      canonicalSupplyIntegrity :=
        policyPublicationFacts.canonicalSupplyIntegrity
    }

structure BridgeMintReplayProductionResidualAssumptions where
  externalReceiptPqVerifierSoundness : Prop
  pqCleanMintDecoderAuthorizationBinding : Prop
  parserImplementationEquivalence : Prop
  hashSecurityEquivalence : Prop
  daAvailabilityRetention : Prop
  storageDurabilityBelowSled : Prop
  completeNativeNodeEquivalence : Prop

structure RawIngressBridgeMintReplayReleaseHardenedCertificate
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
    (receipt : InboundBridgeReceiptInput)
    (backendReview : NativeBackendReviewInput)
    (consumed next : List Nat)
    (replay imported : Nat)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput)
    (policyResult :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayAccepted)
    (policyNativeReplayKeyMatches : Prop)
    (residuals : BridgeMintReplayProductionResidualAssumptions) : Prop where
  productionReviewCertificate :
    RawIngressBridgeMintReplayProductionReviewCertificate
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
      receipt
      backendReview
      consumed
      next
      replay
      imported
      initial
      final
      blocks
      policyInput
      policyResult
      policyNativeReplayKeyMatches
      residuals.externalReceiptPqVerifierSoundness
  rawIngressPolicyPublicationFacts :
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
      policyNativeReplayKeyMatches
  acceptedBridgePayloadAuthorizationFacts :
    InboundBridgePayloadAuthorizationFacts input
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
  finalReplayStateHandoff :
    RawIngressBridgeCanonicalFinalReplayPublicationFacts
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
  finalReplayPresent :
    replay ∈ final.ledger.consumedBridgeReplays
  finalReplayRejectsDuplicate :
    importBridgeReplay final.ledger.consumedBridgeReplays (some replay) =
      Except.error ActionStreamEffect.ActionStreamReject.bridgeReplayDuplicate
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
  canonicalSupplyIntegrity :
    expectedNativeSupplyAfter
        initial.ledger.supply
        (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger.supply
  releaseDisabledRejectsPolicyBeforeReplay :
    ∀ {releaseInput : Risc0ReleaseInput},
      releaseInput.verifierEnabled = false ->
      policyInput.receiptVerified =
        risc0ReleaseVerifierAccepts releaseInput ->
      Hegemon.Bridge.MintReplayPolicy.evaluateReceiptMintReplay
        policyInput =
          Except.error
            Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayReject.receiptNotVerified
  releaseDisabledPrecludesPolicyPublication :
    ∀ {releaseInput : Risc0ReleaseInput},
      releaseInput.verifierEnabled = false ->
      policyInput.receiptVerified =
        risc0ReleaseVerifierAccepts releaseInput ->
      False
  residualExternalReceiptPqVerifierSound :
    residuals.externalReceiptPqVerifierSoundness
  residualPqCleanMintDecoderAuthorizationBinding :
    residuals.pqCleanMintDecoderAuthorizationBinding
  residualParserImplementationEquivalence :
    residuals.parserImplementationEquivalence
  residualHashSecurityEquivalence :
    residuals.hashSecurityEquivalence
  residualDaAvailabilityRetention :
    residuals.daAvailabilityRetention
  residualStorageDurabilityBelowSled :
    residuals.storageDurabilityBelowSled
  residualCompleteNativeNodeEquivalence :
    residuals.completeNativeNodeEquivalence

theorem raw_ingress_bridge_mint_replay_production_certificate_hardened_by_release_disabled
    {input : BridgePayloadInput}
    {mintSurface : InboundBridgeMintAmountSurface}
    {assetSurface : InboundBridgeMintAssetSurface}
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
    {receipt : InboundBridgeReceiptInput}
    {backendReview : NativeBackendReviewInput}
    {consumed next : List Nat}
    {replay imported : Nat}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {policyInput :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayInput}
    {policyResult :
      Hegemon.Bridge.MintReplayPolicy.ReceiptMintReplayAccepted}
    {policyNativeReplayKeyMatches : Prop}
    {residuals : BridgeMintReplayProductionResidualAssumptions}
    (certificate :
      RawIngressBridgeMintReplayProductionReviewCertificate
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
        receipt
        backendReview
        consumed
        next
        replay
        imported
        initial
        final
        blocks
        policyInput
        policyResult
        policyNativeReplayKeyMatches
        residuals.externalReceiptPqVerifierSoundness)
    (pqCleanMintDecoderAuthorizationBinding :
      residuals.pqCleanMintDecoderAuthorizationBinding)
    (parserImplementationEquivalence :
      residuals.parserImplementationEquivalence)
    (hashSecurityEquivalence :
      residuals.hashSecurityEquivalence)
    (daAvailabilityRetention :
      residuals.daAvailabilityRetention)
    (storageDurabilityBelowSled :
      residuals.storageDurabilityBelowSled)
    (completeNativeNodeEquivalence :
      residuals.completeNativeNodeEquivalence) :
    RawIngressBridgeMintReplayReleaseHardenedCertificate
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
      receipt
      backendReview
      consumed
      next
      replay
      imported
      initial
      final
      blocks
      policyInput
      policyResult
      policyNativeReplayKeyMatches
      residuals := by
  exact
    {
      productionReviewCertificate := certificate,
      rawIngressPolicyPublicationFacts :=
        certificate.policyPublicationFacts,
      acceptedBridgePayloadAuthorizationFacts :=
        certificate.policyPublicationFacts.bridgeCanonicalPublicationFacts.inboundPayloadAuthorizationFacts,
      policyAccepted := certificate.policyAccepted,
      policyFacts := certificate.policyFacts,
      policyImportsReplayKey := certificate.policyImportsReplayKey,
      policyRejectsReplayAgain := certificate.policyRejectsReplayAgain,
      policyNativeReplayKeyMatch := certificate.policyNativeReplayKeyMatch,
      bridgeCanonicalPublicationFacts :=
        certificate.bridgeCanonicalPublicationFacts,
      finalReplayStateHandoff :=
        certificate.bridgeCanonicalFinalReplayPublicationFacts,
      finalReplayPresent := certificate.finalReplayPresent,
      finalReplayRejectsDuplicate :=
        certificate.finalReplayRejectsDuplicate,
      authorizedBridgeAssetDelta :=
        certificate.authorizedBridgeAssetDelta,
      authorizedExternalAmountMatches :=
        certificate.authorizedExternalAmountMatches,
      authorizedExternalAssetMatches :=
        certificate.authorizedExternalAssetMatches,
      authorizedAssetNonNative := certificate.authorizedAssetNonNative,
      noDirectNativeMint := certificate.noDirectNativeMint,
      canonicalSupplyIntegrity := certificate.canonicalSupplyIntegrity,
      releaseDisabledRejectsPolicyBeforeReplay := by
        intro releaseInput disabled receiptVerifiedReflectsRelease
        exact
          release_disabled_blocks_receipt_mint_replay_policy_before_replay
            (releaseInput := releaseInput)
            (policyInput := policyInput)
            disabled
            receiptVerifiedReflectsRelease
            certificate.policyFacts.left
            certificate.policyFacts.right.left
            certificate.policyFacts.right.right.left,
      releaseDisabledPrecludesPolicyPublication := by
        intro releaseInput disabled receiptVerifiedReflectsRelease
        exact
          release_disabled_precludes_raw_ingress_bridge_mint_replay_policy_publication
            (input := input)
            (mintSurface := mintSurface)
            (assetSurface := assetSurface)
            (surface := surface)
            (pendingDecode := pendingDecode)
            (blockActionDecode := blockActionDecode)
            (actionHash := actionHash)
            (wireOutput := wireOutput)
            (semanticFields := semanticFields)
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
            (policyInput := policyInput)
            (policyResult := policyResult)
            (policyNativeReplayKeyMatches :=
              policyNativeReplayKeyMatches)
            (releaseInput := releaseInput)
            disabled
            receiptVerifiedReflectsRelease
            certificate.policyPublicationFacts,
      residualExternalReceiptPqVerifierSound :=
        certificate.externalReceiptPqVerifierSound,
      residualPqCleanMintDecoderAuthorizationBinding :=
        pqCleanMintDecoderAuthorizationBinding,
      residualParserImplementationEquivalence :=
        parserImplementationEquivalence,
      residualHashSecurityEquivalence :=
        hashSecurityEquivalence,
      residualDaAvailabilityRetention := daAvailabilityRetention,
      residualStorageDurabilityBelowSled :=
        storageDurabilityBelowSled,
      residualCompleteNativeNodeEquivalence :=
        completeNativeNodeEquivalence
    }

end RawIngressBridgePendingActionPublication
end Native
end Hegemon

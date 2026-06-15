import Hegemon.Native.BridgeMintSafety
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
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
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

end RawIngressBridgePendingActionPublication
end Native
end Hegemon

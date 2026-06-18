import Hegemon.Native.PendingActionBytePublicationRefinement

namespace Hegemon
namespace Native
namespace CodecCanonicalPublicationBoundary

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalPublicationRefinement
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.PendingActionByteParserRefinement
open Hegemon.Native.PendingActionBytePublicationRefinement
open Hegemon.Native.PendingActionReload
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission

structure CodecCanonicalPublicationBoundaryFacts
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (pendingReload : PendingActionReloadInput)
    (actionHash : AdmissionInput)
    (wireProjection : ActionWireReplayProjectionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) : Prop where
  bytePublicationFacts :
    PendingActionBytePublicationFacts
      pendingDecode
      blockActionDecode
      pendingReload
      actionHash
      wireProjection
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
  pendingDecodeCanonicalNonMalleable :
    pendingDecode.parserAccepts = true
      ∧ pendingDecode.consumedAllBytes = true
      ∧ pendingDecode.canonicalReencodeMatches = true
  blockActionDecodePreconditions :
    blockActionDecodePreconditions blockActionDecode = true
  blockActionDecodeCanonicalNonMalleable :
    actionCountMatches blockActionDecode = true
      ∧ blockActionDecode.everyActionDecodesExactly = true
  declaredActionCountMatchesDecodedPayloads :
    blockActionDecode.declaredTxCount =
      blockActionDecode.actualActionPayloadCount
  wireRowsMatchDeclaredActionCount :
    wireOutput.projectedActionCount = blockActionDecode.declaredTxCount
  wireRowsMatchDecodedPayloads :
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

structure CodecCanonicalPublicationNonMalleabilityFacts
    (syncDecode : SyncDecodeInput)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (pendingReload : PendingActionReloadInput)
    (actionHash : AdmissionInput)
    (wireProjection : ActionWireReplayProjectionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) : Prop where
  canonicalPublicationBoundary :
    CodecCanonicalPublicationBoundaryFacts
      pendingDecode
      blockActionDecode
      pendingReload
      actionHash
      wireProjection
      wireOutput
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
  canonicalDecodeNonMalleability :
    CanonicalDecodeNonMalleabilityFacts
      syncDecode
      pendingDecode
      blockActionDecode
  pendingExactDecodeNonMalleable :
    exactDecodeAccepts pendingDecode = true ->
      pendingDecode.parserAccepts = true
        ∧ pendingDecode.consumedAllBytes = true
        ∧ pendingDecode.canonicalReencodeMatches = true
  blockActionDecodeNonMalleable :
    blockActionDecodeAccepts blockActionDecode = true ->
      actionCountMatches blockActionDecode = true
        ∧ blockActionDecode.everyActionDecodesExactly = true
  syncDecodeNonMalleable :
    syncDecodeAccepts syncDecode = true ->
      syncDecode.boundedWireDecodeAccepts = true
        ∧ syncDecode.consumedAllBytes = true
  pendingParserFailureRejectsBeforePublication :
    pendingDecode.parserAccepts = false ->
      evaluateExactDecodeRejection pendingDecode =
        some ExactDecodeReject.parserRejected
  pendingTrailingBytesRejectBeforePublication :
    pendingDecode.parserAccepts = true ->
      pendingDecode.consumedAllBytes = false ->
      evaluateExactDecodeRejection pendingDecode =
        some ExactDecodeReject.trailingBytes
  pendingNoncanonicalReencodeRejectsBeforePublication :
    pendingDecode.parserAccepts = true ->
      pendingDecode.consumedAllBytes = true ->
      pendingDecode.canonicalReencodeMatches = false ->
      evaluateExactDecodeRejection pendingDecode =
        some ExactDecodeReject.nonCanonicalEncoding
  blockActionCountMismatchRejectsBeforePublication :
    actionCountMatches blockActionDecode = false ->
      evaluateBlockActionDecodeRejection blockActionDecode =
        some BlockActionDecodeReject.actionCountMismatch
  blockActionNonexactPayloadRejectsBeforePublication :
    actionCountMatches blockActionDecode = true ->
      blockActionDecode.everyActionDecodesExactly = false ->
      evaluateBlockActionDecodeRejection blockActionDecode =
        some BlockActionDecodeReject.actionDecodeNotExact

theorem pending_action_byte_publication_facts_imply_codec_canonical_publication_boundary
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReloadInput}
    {actionHash : AdmissionInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (facts :
      PendingActionBytePublicationFacts
        pendingDecode
        blockActionDecode
        pendingReload
        actionHash
        wireProjection
        wireOutput
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        blocks) :
    CodecCanonicalPublicationBoundaryFacts
      pendingDecode
      blockActionDecode
      pendingReload
      actionHash
      wireProjection
      wireOutput
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks := by
  have declaredMatchesDecoded :
      blockActionDecode.declaredTxCount =
        blockActionDecode.actualActionPayloadCount :=
    facts.parserWireReplayFacts.blockActionDeclaredCount
  have wireRowsMatchDeclared :
      wireOutput.projectedActionCount =
        blockActionDecode.declaredTxCount := by
    calc
      wireOutput.projectedActionCount = wireProjection.actionCount :=
        facts.parserWireReplayFacts.wireProjectedActionCount
      _ = blockActionDecode.declaredTxCount :=
        facts.parserWireReplayFacts.wireActionCountMatchesDeclared
  exact
    {
      bytePublicationFacts := facts,
      pendingDecodePreconditions := facts.pendingDecodePreconditions,
      pendingDecodeCanonicalNonMalleable := facts.pendingDecodeExact,
      blockActionDecodePreconditions := facts.blockActionDecodePreconditions,
      blockActionDecodeCanonicalNonMalleable :=
        facts.blockActionDecodeExact,
      declaredActionCountMatchesDecodedPayloads := declaredMatchesDecoded,
      wireRowsMatchDeclaredActionCount := wireRowsMatchDeclared,
      wireRowsMatchDecodedPayloads :=
        facts.projectedActionRowsMatchDecodedPayloads,
      canonicalPublicationFacts := facts.canonicalPublicationFacts,
      rawTreeCarriedStatePreconditions :=
        facts.rawTreeCarriedStatePreconditions
    }

theorem accepted_pending_action_codec_canonical_publication_boundary
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReloadInput}
    {actionHash : AdmissionInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (pendingReloadAccepted :
      pendingActionReloadAccepts pendingReload = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireProjectionAccepted :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (wireActionCountMatchesDeclared :
      wireProjection.actionCount =
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
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    CodecCanonicalPublicationBoundaryFacts
      pendingDecode
      blockActionDecode
      pendingReload
      actionHash
      wireProjection
      wireOutput
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks := by
  have publicationFacts :=
    accepted_pending_action_bytes_bind_raw_canonical_publication
      pendingDecodeAccepted
      blockActionDecodeAccepted
      pendingReloadAccepted
      actionHashAccepted
      wireProjectionAccepted
      wireActionCountMatchesDeclared
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  exact
    pending_action_byte_publication_facts_imply_codec_canonical_publication_boundary
      publicationFacts

theorem accepted_pending_action_codec_canonical_publication_non_malleability_facts
    {syncDecode : SyncDecodeInput}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReloadInput}
    {actionHash : AdmissionInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (pendingReloadAccepted :
      pendingActionReloadAccepts pendingReload = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireProjectionAccepted :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (wireActionCountMatchesDeclared :
      wireProjection.actionCount =
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
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    CodecCanonicalPublicationNonMalleabilityFacts
      syncDecode
      pendingDecode
      blockActionDecode
      pendingReload
      actionHash
      wireProjection
      wireOutput
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks := by
  have canonicalPublicationBoundary :
      CodecCanonicalPublicationBoundaryFacts
        pendingDecode
        blockActionDecode
        pendingReload
        actionHash
        wireProjection
        wireOutput
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        blocks :=
    accepted_pending_action_codec_canonical_publication_boundary
      pendingDecodeAccepted
      blockActionDecodeAccepted
      pendingReloadAccepted
      actionHashAccepted
      wireProjectionAccepted
      wireActionCountMatchesDeclared
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  have nonMalleability :
      CanonicalDecodeNonMalleabilityFacts
        syncDecode
        pendingDecode
        blockActionDecode :=
    canonical_decode_non_malleability_facts
  exact
    {
      canonicalPublicationBoundary := canonicalPublicationBoundary
      canonicalDecodeNonMalleability := nonMalleability
      pendingExactDecodeNonMalleable :=
        nonMalleability.exactAcceptanceExcludesMalleability
      blockActionDecodeNonMalleable :=
        nonMalleability.actionAcceptanceExcludesMalleability
      syncDecodeNonMalleable :=
        nonMalleability.syncAcceptanceExcludesMalleability
      pendingParserFailureRejectsBeforePublication :=
        nonMalleability.exactParserRejects
      pendingTrailingBytesRejectBeforePublication :=
        nonMalleability.exactTrailingRejects
      pendingNoncanonicalReencodeRejectsBeforePublication :=
        nonMalleability.exactNoncanonicalRejects
      blockActionCountMismatchRejectsBeforePublication :=
        nonMalleability.actionCountMismatchRejects
      blockActionNonexactPayloadRejectsBeforePublication :=
        nonMalleability.actionNonExactRejects
    }

end CodecCanonicalPublicationBoundary
end Native
end Hegemon

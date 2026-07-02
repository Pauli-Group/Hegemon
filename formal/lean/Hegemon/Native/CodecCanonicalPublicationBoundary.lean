import Hegemon.Native.BridgeVerifierRegistrationScaleWire
import Hegemon.Native.CoinbaseActionPayloadScaleWire
import Hegemon.Native.InboundBridgeActionPayloadScaleWire
import Hegemon.Native.OutboundBridgeActionPayloadScaleWire
import Hegemon.Native.PendingActionBytePublicationRefinement
import Hegemon.Native.PendingActionScaleWire
import Hegemon.Native.ShieldedTransferInlineScaleWire
import Hegemon.Native.ShieldedTransferSidecarScaleWire

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
open Hegemon.Native.BridgeVerifierRegistrationScaleWire
open Hegemon.Native.CoinbaseActionPayloadScaleWire
open Hegemon.Native.InboundBridgeActionPayloadScaleWire
open Hegemon.Native.OutboundBridgeActionPayloadScaleWire
open Hegemon.Native.PendingActionByteParserRefinement
open Hegemon.Native.PendingActionBytePublicationRefinement
open Hegemon.Native.PendingActionReload
open Hegemon.Native.PendingActionScaleWire
open Hegemon.Native.ShieldedTransferInlineScaleWire
open Hegemon.Native.ShieldedTransferSidecarScaleWire
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

structure CodecCanonicalPublicationMetadataNonMalleabilityFacts
    (syncDecode : SyncDecodeInput)
    (metadataDecode : NativeMetadataDecodeInput)
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
  codecCanonicalNonMalleability :
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
      blocks
  metadataDecodeFacts :
    NativeMetadataDecodeFacts metadataDecode
  metadataAcceptsIff :
    nativeMetadataDecodeAccepts metadataDecode =
      nativeMetadataDecodePreconditions metadataDecode
  currentMetadataExactDecodePrecedesLegacy :
    exactDecodeAccepts metadataDecode.currentExact = true ->
      evaluateNativeMetadataDecode metadataDecode =
        Except.ok NativeMetadataDecodeSource.current
  legacyMetadataRequiresCurrentRejection :
    exactDecodeAccepts metadataDecode.currentExact = false ->
      exactDecodeAccepts metadataDecode.legacyExact = true ->
        evaluateNativeMetadataDecode metadataDecode =
          Except.ok NativeMetadataDecodeSource.legacy
  metadataBothExactDecodersRejectedFailClosed :
    exactDecodeAccepts metadataDecode.currentExact = false ->
      exactDecodeAccepts metadataDecode.legacyExact = false ->
        evaluateNativeMetadataDecode metadataDecode =
          Except.error NativeMetadataDecodeReject.currentAndLegacyRejected
  pendingExactDecodeBeforePublication :
    pendingDecode.parserAccepts = true
      ∧ pendingDecode.consumedAllBytes = true
      ∧ pendingDecode.canonicalReencodeMatches = true
  blockActionExactDecodeBeforePublication :
    actionCountMatches blockActionDecode = true
      ∧ blockActionDecode.everyActionDecodesExactly = true

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

theorem accepted_pending_action_codec_canonical_publication_with_metadata_non_malleability_facts
    {syncDecode : SyncDecodeInput}
    {metadataDecode : NativeMetadataDecodeInput}
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
    CodecCanonicalPublicationMetadataNonMalleabilityFacts
      syncDecode
      metadataDecode
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
  have codecFacts :
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
        blocks :=
    accepted_pending_action_codec_canonical_publication_non_malleability_facts
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
  have metadataFacts :
      NativeMetadataDecodeFacts metadataDecode :=
    native_metadata_decode_facts
  exact {
    codecCanonicalNonMalleability := codecFacts,
    metadataDecodeFacts := metadataFacts,
    metadataAcceptsIff := metadataFacts.acceptsIff,
    currentMetadataExactDecodePrecedesLegacy :=
      metadataFacts.currentExactPrecedesLegacy,
    legacyMetadataRequiresCurrentRejection :=
      metadataFacts.legacyRequiresCurrentRejected,
    metadataBothExactDecodersRejectedFailClosed :=
      metadataFacts.bothRejectedFailClosed,
    pendingExactDecodeBeforePublication :=
      (codecFacts.canonicalPublicationBoundary).pendingDecodeCanonicalNonMalleable,
    blockActionExactDecodeBeforePublication :=
      (codecFacts.canonicalPublicationBoundary).blockActionDecodeCanonicalNonMalleable
  }

structure BoundedCanonicalCodecGateCertificate
    (syncDecode : SyncDecodeInput)
    (metadataDecode : NativeMetadataDecodeInput)
    (pendingWire : PendingActionScaleWireInput)
    (coinbaseWire : CoinbaseActionPayloadScaleWireInput)
    (inlineTransferWire : ShieldedTransferInlineScaleWireInput)
    (sidecarTransferWire : ShieldedTransferSidecarScaleWireInput)
    (outboundBridgeWire : OutboundBridgeActionPayloadScaleWireInput)
    (inboundBridgeWire : InboundBridgeActionPayloadScaleWireInput)
    (bridgeVerifierRegistrationWire :
      BridgeVerifierRegistrationScaleWireInput)
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
  metadataPublication :
    CodecCanonicalPublicationMetadataNonMalleabilityFacts
      syncDecode
      metadataDecode
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
  pendingWireFacts :
    AcceptedPendingActionScaleWireFacts pendingWire
  pendingDecodeIsConcreteWire :
    pendingDecode = exactDecodeInputOfScaleWire pendingWire
  pendingConcreteWireExactDecode :
    exactDecodeAccepts (exactDecodeInputOfScaleWire pendingWire) = true
  coinbaseWireFacts :
    AcceptedCoinbaseActionPayloadScaleWireFacts coinbaseWire
  coinbaseConcreteWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfCoinbaseActionPayloadScaleWire coinbaseWire) = true
  inlineTransferWireFacts :
    AcceptedShieldedTransferInlineScaleWireFacts inlineTransferWire
  inlineTransferConcreteWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfShieldedTransferInlineScaleWire
        inlineTransferWire) = true
  sidecarTransferWireFacts :
    AcceptedShieldedTransferSidecarScaleWireFacts sidecarTransferWire
  sidecarTransferConcreteWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfShieldedTransferSidecarScaleWire
        sidecarTransferWire) = true
  outboundBridgeWireFacts :
    AcceptedOutboundBridgeActionPayloadScaleWireFacts outboundBridgeWire
  outboundBridgeConcreteWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfOutboundBridgeActionPayloadScaleWire
        outboundBridgeWire) = true
  inboundBridgeWireFacts :
    AcceptedInboundBridgeActionPayloadScaleWireFacts inboundBridgeWire
  inboundBridgeConcreteWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfInboundBridgeActionPayloadScaleWire
        inboundBridgeWire) = true
  bridgeVerifierRegistrationWireFacts :
    AcceptedBridgeVerifierRegistrationScaleWireFacts
      bridgeVerifierRegistrationWire
  bridgeVerifierRegistrationConcreteWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfBridgeVerifierRegistrationScaleWire
        bridgeVerifierRegistrationWire) = true
  metadataOrdering :
    NativeMetadataDecodeFacts metadataDecode
  metadataCurrentFirst :
    exactDecodeAccepts metadataDecode.currentExact = true ->
      evaluateNativeMetadataDecode metadataDecode =
        Except.ok NativeMetadataDecodeSource.current
  metadataLegacyFallbackOnlyAfterCurrentRejected :
    exactDecodeAccepts metadataDecode.currentExact = false ->
      exactDecodeAccepts metadataDecode.legacyExact = true ->
        evaluateNativeMetadataDecode metadataDecode =
          Except.ok NativeMetadataDecodeSource.legacy
  metadataBothDecodersRejectFailClosed :
    exactDecodeAccepts metadataDecode.currentExact = false ->
      exactDecodeAccepts metadataDecode.legacyExact = false ->
        evaluateNativeMetadataDecode metadataDecode =
          Except.error NativeMetadataDecodeReject.currentAndLegacyRejected
  pendingPublicationUsesConcreteWireDecode :
    exactDecodeAccepts pendingDecode = true
  pendingPublicationFullConsumption :
    pendingDecode.consumedAllBytes = true
  pendingPublicationCanonicalReencode :
    pendingDecode.canonicalReencodeMatches = true

theorem accepted_bounded_canonical_codec_gate_certificate
    {syncDecode : SyncDecodeInput}
    {metadataDecode : NativeMetadataDecodeInput}
    {pendingWire : PendingActionScaleWireInput}
    {coinbaseWire : CoinbaseActionPayloadScaleWireInput}
    {inlineTransferWire : ShieldedTransferInlineScaleWireInput}
    {sidecarTransferWire : ShieldedTransferSidecarScaleWireInput}
    {outboundBridgeWire : OutboundBridgeActionPayloadScaleWireInput}
    {inboundBridgeWire : InboundBridgeActionPayloadScaleWireInput}
    {bridgeVerifierRegistrationWire :
      BridgeVerifierRegistrationScaleWireInput}
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
    (metadataPublication :
      CodecCanonicalPublicationMetadataNonMalleabilityFacts
        syncDecode
        metadataDecode
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
        blocks)
    (pendingWireAccepted :
      pendingActionScaleWireAccepts pendingWire = true)
    (coinbaseWireAccepted :
      coinbaseActionPayloadScaleWireAccepts coinbaseWire = true)
    (inlineTransferWireAccepted :
      shieldedTransferInlineScaleWireAccepts inlineTransferWire = true)
    (sidecarTransferWireAccepted :
      shieldedTransferSidecarScaleWireAccepts sidecarTransferWire = true)
    (outboundBridgeWireAccepted :
      outboundBridgeActionPayloadScaleWireAccepts outboundBridgeWire = true)
    (inboundBridgeWireAccepted :
      inboundBridgeActionPayloadScaleWireAccepts inboundBridgeWire = true)
    (bridgeVerifierRegistrationWireAccepted :
      bridgeVerifierRegistrationScaleWireAccepts
        bridgeVerifierRegistrationWire = true)
    (pendingDecodeIsConcreteWire :
      pendingDecode = exactDecodeInputOfScaleWire pendingWire) :
    BoundedCanonicalCodecGateCertificate
      syncDecode
      metadataDecode
      pendingWire
      coinbaseWire
      inlineTransferWire
      sidecarTransferWire
      outboundBridgeWire
      inboundBridgeWire
      bridgeVerifierRegistrationWire
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
  have pendingWireFacts :
      AcceptedPendingActionScaleWireFacts pendingWire :=
    pending_action_scale_wire_acceptance_exposes_facts pendingWireAccepted
  have pendingConcreteExact :
      exactDecodeAccepts (exactDecodeInputOfScaleWire pendingWire) = true :=
    accepted_pending_action_scale_wire_exact_decode pendingWireAccepted
  have coinbaseWireFacts :
      AcceptedCoinbaseActionPayloadScaleWireFacts coinbaseWire :=
    coinbase_action_payload_scale_wire_acceptance_exposes_facts
      coinbaseWireAccepted
  have coinbaseConcreteExact :
      exactDecodeAccepts
        (exactDecodeInputOfCoinbaseActionPayloadScaleWire coinbaseWire) = true :=
    accepted_coinbase_action_payload_scale_wire_exact_decode
      coinbaseWireAccepted
  have inlineTransferWireFacts :
      AcceptedShieldedTransferInlineScaleWireFacts inlineTransferWire :=
    shielded_transfer_inline_scale_wire_acceptance_exposes_facts
      inlineTransferWireAccepted
  have inlineTransferConcreteExact :
      exactDecodeAccepts
        (exactDecodeInputOfShieldedTransferInlineScaleWire
          inlineTransferWire) = true :=
    accepted_shielded_transfer_inline_scale_wire_exact_decode
      inlineTransferWireAccepted
  have sidecarTransferWireFacts :
      AcceptedShieldedTransferSidecarScaleWireFacts sidecarTransferWire :=
    shielded_transfer_sidecar_scale_wire_acceptance_exposes_facts
      sidecarTransferWireAccepted
  have sidecarTransferConcreteExact :
      exactDecodeAccepts
        (exactDecodeInputOfShieldedTransferSidecarScaleWire
          sidecarTransferWire) = true :=
    accepted_shielded_transfer_sidecar_scale_wire_exact_decode
      sidecarTransferWireAccepted
  have outboundBridgeWireFacts :
      AcceptedOutboundBridgeActionPayloadScaleWireFacts outboundBridgeWire :=
    outbound_bridge_action_payload_scale_wire_acceptance_exposes_facts
      outboundBridgeWireAccepted
  have outboundBridgeConcreteExact :
      exactDecodeAccepts
        (exactDecodeInputOfOutboundBridgeActionPayloadScaleWire
          outboundBridgeWire) = true :=
    accepted_outbound_bridge_action_payload_scale_wire_exact_decode
      outboundBridgeWireAccepted
  have inboundBridgeWireFacts :
      AcceptedInboundBridgeActionPayloadScaleWireFacts inboundBridgeWire :=
    inbound_bridge_action_payload_scale_wire_acceptance_exposes_facts
      inboundBridgeWireAccepted
  have inboundBridgeConcreteExact :
      exactDecodeAccepts
        (exactDecodeInputOfInboundBridgeActionPayloadScaleWire
          inboundBridgeWire) = true :=
    accepted_inbound_bridge_action_payload_scale_wire_exact_decode
      inboundBridgeWireAccepted
  have bridgeVerifierRegistrationWireFacts :
      AcceptedBridgeVerifierRegistrationScaleWireFacts
        bridgeVerifierRegistrationWire :=
    bridge_verifier_registration_scale_wire_acceptance_exposes_facts
      bridgeVerifierRegistrationWireAccepted
  have bridgeVerifierRegistrationConcreteExact :
      exactDecodeAccepts
        (exactDecodeInputOfBridgeVerifierRegistrationScaleWire
          bridgeVerifierRegistrationWire) = true :=
    accepted_bridge_verifier_registration_scale_wire_exact_decode
      bridgeVerifierRegistrationWireAccepted
  refine
    { metadataPublication := metadataPublication
      pendingWireFacts := pendingWireFacts
      pendingDecodeIsConcreteWire := pendingDecodeIsConcreteWire
      pendingConcreteWireExactDecode := pendingConcreteExact
      coinbaseWireFacts := coinbaseWireFacts
      coinbaseConcreteWireExactDecode := coinbaseConcreteExact
      inlineTransferWireFacts := inlineTransferWireFacts
      inlineTransferConcreteWireExactDecode := inlineTransferConcreteExact
      sidecarTransferWireFacts := sidecarTransferWireFacts
      sidecarTransferConcreteWireExactDecode := sidecarTransferConcreteExact
      outboundBridgeWireFacts := outboundBridgeWireFacts
      outboundBridgeConcreteWireExactDecode := outboundBridgeConcreteExact
      inboundBridgeWireFacts := inboundBridgeWireFacts
      inboundBridgeConcreteWireExactDecode := inboundBridgeConcreteExact
      bridgeVerifierRegistrationWireFacts :=
        bridgeVerifierRegistrationWireFacts
      bridgeVerifierRegistrationConcreteWireExactDecode :=
        bridgeVerifierRegistrationConcreteExact
      metadataOrdering := metadataPublication.metadataDecodeFacts
      metadataCurrentFirst :=
        metadataPublication.currentMetadataExactDecodePrecedesLegacy
      metadataLegacyFallbackOnlyAfterCurrentRejected :=
        metadataPublication.legacyMetadataRequiresCurrentRejection
      metadataBothDecodersRejectFailClosed :=
        metadataPublication.metadataBothExactDecodersRejectedFailClosed
      pendingPublicationUsesConcreteWireDecode := ?_
      pendingPublicationFullConsumption := ?_
      pendingPublicationCanonicalReencode := ?_ }
  · rw [pendingDecodeIsConcreteWire]
    exact pendingConcreteExact
  · exact metadataPublication.pendingExactDecodeBeforePublication.2.1
  · exact metadataPublication.pendingExactDecodeBeforePublication.2.2

structure BoundedCanonicalCodecProductionBindingFacts
    (syncDecode : SyncDecodeInput)
    (metadataDecode : NativeMetadataDecodeInput)
    (pendingWire : PendingActionScaleWireInput)
    (coinbaseWire : CoinbaseActionPayloadScaleWireInput)
    (inlineTransferWire : ShieldedTransferInlineScaleWireInput)
    (sidecarTransferWire : ShieldedTransferSidecarScaleWireInput)
    (outboundBridgeWire : OutboundBridgeActionPayloadScaleWireInput)
    (inboundBridgeWire : InboundBridgeActionPayloadScaleWireInput)
    (bridgeVerifierRegistrationWire :
      BridgeVerifierRegistrationScaleWireInput)
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
  boundedCodecGate :
    BoundedCanonicalCodecGateCertificate
      syncDecode
      metadataDecode
      pendingWire
      coinbaseWire
      inlineTransferWire
      sidecarTransferWire
      outboundBridgeWire
      inboundBridgeWire
      bridgeVerifierRegistrationWire
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
  pendingDecodeIsConcreteWire :
    pendingDecode = exactDecodeInputOfScaleWire pendingWire
  pendingPublicationExactDecode :
    exactDecodeAccepts pendingDecode = true
  pendingPublicationFullConsumption :
    pendingDecode.consumedAllBytes = true
  pendingPublicationCanonicalReencode :
    pendingDecode.canonicalReencodeMatches = true
  blockActionCountMatchesBeforePublication :
    actionCountMatches blockActionDecode = true
  blockActionPayloadsExactBeforePublication :
    blockActionDecode.everyActionDecodesExactly = true
  blockActionDeclaredEqualsDecodedPayloads :
    blockActionDecode.declaredTxCount =
      blockActionDecode.actualActionPayloadCount
  decodedPayloadRowsEqualPublishedWireRows :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
  declaredRowsEqualPublishedWireRows :
    wireOutput.projectedActionCount =
      blockActionDecode.declaredTxCount
  pendingWireExactDecode :
    exactDecodeAccepts (exactDecodeInputOfScaleWire pendingWire) = true
  pendingWireFullConsumption :
    pendingWire.consumedAllBytes = true
  pendingWireCanonicalReencode :
    pendingWire.canonicalReencodeMatches = true
  coinbaseWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfCoinbaseActionPayloadScaleWire coinbaseWire) = true
  coinbaseWireFullConsumption :
    coinbaseWire.consumedAllBytes = true
  coinbaseWireCanonicalReencode :
    coinbaseWire.canonicalReencodeMatches = true
  inlineTransferWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfShieldedTransferInlineScaleWire
        inlineTransferWire) = true
  inlineTransferWireFullConsumption :
    inlineTransferWire.consumedAllBytes = true
  inlineTransferWireCanonicalReencode :
    inlineTransferWire.canonicalReencodeMatches = true
  sidecarTransferWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfShieldedTransferSidecarScaleWire
        sidecarTransferWire) = true
  sidecarTransferWireFullConsumption :
    sidecarTransferWire.consumedAllBytes = true
  sidecarTransferWireCanonicalReencode :
    sidecarTransferWire.canonicalReencodeMatches = true
  outboundBridgeWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfOutboundBridgeActionPayloadScaleWire
        outboundBridgeWire) = true
  outboundBridgeWireFullConsumption :
    outboundBridgeWire.consumedAllBytes = true
  outboundBridgeWireCanonicalReencode :
    outboundBridgeWire.canonicalReencodeMatches = true
  inboundBridgeWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfInboundBridgeActionPayloadScaleWire
        inboundBridgeWire) = true
  inboundBridgeWireFullConsumption :
    inboundBridgeWire.consumedAllBytes = true
  inboundBridgeWireCanonicalReencode :
    inboundBridgeWire.canonicalReencodeMatches = true
  bridgeVerifierRegistrationWireExactDecode :
    exactDecodeAccepts
      (exactDecodeInputOfBridgeVerifierRegistrationScaleWire
        bridgeVerifierRegistrationWire) = true
  bridgeVerifierRegistrationWireFullConsumption :
    bridgeVerifierRegistrationWire.consumedAllBytes = true
  bridgeVerifierRegistrationWireCanonicalReencode :
    bridgeVerifierRegistrationWire.canonicalReencodeMatches = true
  metadataCurrentBeforeLegacy :
    exactDecodeAccepts metadataDecode.currentExact = true ->
      evaluateNativeMetadataDecode metadataDecode =
        Except.ok NativeMetadataDecodeSource.current
  metadataLegacyFallbackOnlyAfterCurrentRejected :
    exactDecodeAccepts metadataDecode.currentExact = false ->
      exactDecodeAccepts metadataDecode.legacyExact = true ->
        evaluateNativeMetadataDecode metadataDecode =
          Except.ok NativeMetadataDecodeSource.legacy
  metadataBothDecodersRejectFailClosed :
    exactDecodeAccepts metadataDecode.currentExact = false ->
      exactDecodeAccepts metadataDecode.legacyExact = false ->
        evaluateNativeMetadataDecode metadataDecode =
          Except.error NativeMetadataDecodeReject.currentAndLegacyRejected

theorem bounded_canonical_codec_gate_certificate_exposes_production_binding
    {syncDecode : SyncDecodeInput}
    {metadataDecode : NativeMetadataDecodeInput}
    {pendingWire : PendingActionScaleWireInput}
    {coinbaseWire : CoinbaseActionPayloadScaleWireInput}
    {inlineTransferWire : ShieldedTransferInlineScaleWireInput}
    {sidecarTransferWire : ShieldedTransferSidecarScaleWireInput}
    {outboundBridgeWire : OutboundBridgeActionPayloadScaleWireInput}
    {inboundBridgeWire : InboundBridgeActionPayloadScaleWireInput}
    {bridgeVerifierRegistrationWire :
      BridgeVerifierRegistrationScaleWireInput}
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
    (certificate :
      BoundedCanonicalCodecGateCertificate
        syncDecode
        metadataDecode
        pendingWire
        coinbaseWire
        inlineTransferWire
        sidecarTransferWire
        outboundBridgeWire
        inboundBridgeWire
        bridgeVerifierRegistrationWire
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
    BoundedCanonicalCodecProductionBindingFacts
      syncDecode
      metadataDecode
      pendingWire
      coinbaseWire
      inlineTransferWire
      sidecarTransferWire
      outboundBridgeWire
      inboundBridgeWire
      bridgeVerifierRegistrationWire
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
  {
    boundedCodecGate := certificate,
    pendingDecodeIsConcreteWire := certificate.pendingDecodeIsConcreteWire,
    pendingPublicationExactDecode :=
      certificate.pendingPublicationUsesConcreteWireDecode,
    pendingPublicationFullConsumption :=
      certificate.pendingPublicationFullConsumption,
    pendingPublicationCanonicalReencode :=
      certificate.pendingPublicationCanonicalReencode,
    blockActionCountMatchesBeforePublication :=
      certificate.metadataPublication.blockActionExactDecodeBeforePublication.1,
    blockActionPayloadsExactBeforePublication :=
      certificate.metadataPublication.blockActionExactDecodeBeforePublication.2,
    blockActionDeclaredEqualsDecodedPayloads :=
      (certificate.metadataPublication.codecCanonicalNonMalleability.canonicalPublicationBoundary).declaredActionCountMatchesDecodedPayloads,
    decodedPayloadRowsEqualPublishedWireRows :=
      (certificate.metadataPublication.codecCanonicalNonMalleability.canonicalPublicationBoundary).wireRowsMatchDecodedPayloads,
    declaredRowsEqualPublishedWireRows :=
      (certificate.metadataPublication.codecCanonicalNonMalleability.canonicalPublicationBoundary).wireRowsMatchDeclaredActionCount,
    pendingWireExactDecode := certificate.pendingConcreteWireExactDecode,
    pendingWireFullConsumption :=
      certificate.pendingWireFacts.consumedAllBytes,
    pendingWireCanonicalReencode :=
      certificate.pendingWireFacts.canonicalReencodeMatches,
    coinbaseWireExactDecode := certificate.coinbaseConcreteWireExactDecode,
    coinbaseWireFullConsumption :=
      certificate.coinbaseWireFacts.consumedAllBytes,
    coinbaseWireCanonicalReencode :=
      certificate.coinbaseWireFacts.canonicalReencodeMatches,
    inlineTransferWireExactDecode :=
      certificate.inlineTransferConcreteWireExactDecode,
    inlineTransferWireFullConsumption :=
      certificate.inlineTransferWireFacts.consumedAllBytes,
    inlineTransferWireCanonicalReencode :=
      certificate.inlineTransferWireFacts.canonicalReencodeMatches,
    sidecarTransferWireExactDecode :=
      certificate.sidecarTransferConcreteWireExactDecode,
    sidecarTransferWireFullConsumption :=
      certificate.sidecarTransferWireFacts.consumedAllBytes,
    sidecarTransferWireCanonicalReencode :=
      certificate.sidecarTransferWireFacts.canonicalReencodeMatches,
    outboundBridgeWireExactDecode :=
      certificate.outboundBridgeConcreteWireExactDecode,
    outboundBridgeWireFullConsumption :=
      certificate.outboundBridgeWireFacts.consumedAllBytes,
    outboundBridgeWireCanonicalReencode :=
      certificate.outboundBridgeWireFacts.canonicalReencodeMatches,
    inboundBridgeWireExactDecode :=
      certificate.inboundBridgeConcreteWireExactDecode,
    inboundBridgeWireFullConsumption :=
      certificate.inboundBridgeWireFacts.consumedAllBytes,
    inboundBridgeWireCanonicalReencode :=
      certificate.inboundBridgeWireFacts.canonicalReencodeMatches,
    bridgeVerifierRegistrationWireExactDecode :=
      certificate.bridgeVerifierRegistrationConcreteWireExactDecode,
    bridgeVerifierRegistrationWireFullConsumption :=
      certificate.bridgeVerifierRegistrationWireFacts.consumedAllBytes,
    bridgeVerifierRegistrationWireCanonicalReencode :=
      (certificate.bridgeVerifierRegistrationWireFacts).canonicalReencodeMatches,
    metadataCurrentBeforeLegacy := certificate.metadataCurrentFirst,
    metadataLegacyFallbackOnlyAfterCurrentRejected :=
      certificate.metadataLegacyFallbackOnlyAfterCurrentRejected,
    metadataBothDecodersRejectFailClosed :=
      certificate.metadataBothDecodersRejectFailClosed
  }

theorem accepted_bounded_canonical_codec_gate_binds_production_wires
    {syncDecode : SyncDecodeInput}
    {metadataDecode : NativeMetadataDecodeInput}
    {pendingWire : PendingActionScaleWireInput}
    {coinbaseWire : CoinbaseActionPayloadScaleWireInput}
    {inlineTransferWire : ShieldedTransferInlineScaleWireInput}
    {sidecarTransferWire : ShieldedTransferSidecarScaleWireInput}
    {outboundBridgeWire : OutboundBridgeActionPayloadScaleWireInput}
    {inboundBridgeWire : InboundBridgeActionPayloadScaleWireInput}
    {bridgeVerifierRegistrationWire :
      BridgeVerifierRegistrationScaleWireInput}
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
    (metadataPublication :
      CodecCanonicalPublicationMetadataNonMalleabilityFacts
        syncDecode
        metadataDecode
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
        blocks)
    (pendingWireAccepted :
      pendingActionScaleWireAccepts pendingWire = true)
    (coinbaseWireAccepted :
      coinbaseActionPayloadScaleWireAccepts coinbaseWire = true)
    (inlineTransferWireAccepted :
      shieldedTransferInlineScaleWireAccepts inlineTransferWire = true)
    (sidecarTransferWireAccepted :
      shieldedTransferSidecarScaleWireAccepts sidecarTransferWire = true)
    (outboundBridgeWireAccepted :
      outboundBridgeActionPayloadScaleWireAccepts outboundBridgeWire = true)
    (inboundBridgeWireAccepted :
      inboundBridgeActionPayloadScaleWireAccepts inboundBridgeWire = true)
    (bridgeVerifierRegistrationWireAccepted :
      bridgeVerifierRegistrationScaleWireAccepts
        bridgeVerifierRegistrationWire = true)
    (pendingDecodeIsConcreteWire :
      pendingDecode = exactDecodeInputOfScaleWire pendingWire) :
    BoundedCanonicalCodecProductionBindingFacts
      syncDecode
      metadataDecode
      pendingWire
      coinbaseWire
      inlineTransferWire
      sidecarTransferWire
      outboundBridgeWire
      inboundBridgeWire
      bridgeVerifierRegistrationWire
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
  bounded_canonical_codec_gate_certificate_exposes_production_binding
    (accepted_bounded_canonical_codec_gate_certificate
      metadataPublication
      pendingWireAccepted
      coinbaseWireAccepted
      inlineTransferWireAccepted
      sidecarTransferWireAccepted
      outboundBridgeWireAccepted
      inboundBridgeWireAccepted
      bridgeVerifierRegistrationWireAccepted
      pendingDecodeIsConcreteWire)

end CodecCanonicalPublicationBoundary
end Native
end Hegemon

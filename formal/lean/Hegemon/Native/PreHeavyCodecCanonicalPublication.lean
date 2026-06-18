import Hegemon.Native.CodecCanonicalPublicationBoundary
import Hegemon.Native.PreHeavyWorkResourceBoundSurface

namespace Hegemon
namespace Native
namespace PreHeavyCodecCanonicalPublication

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.CodecCanonicalPublicationBoundary
open Hegemon.Native.CoinbaseActionPayloadScaleWire
open Hegemon.Native.PendingActionScaleWire
open Hegemon.Native.PendingActionReload
open Hegemon.Native.PreHeavyWorkResourceBoundSurface
open Hegemon.Native.StorageDurabilityAdmission

structure PreHeavyCodecCanonicalPublicationCertificate
    (surface : PreHeavyWorkVerificationPathSurface)
    (parserCorrectness benchmarkCaps : Prop)
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
  preHeavyDoSBounds :
    AcceptedPreHeavyWorkDoSBoundCertificate
      surface
      parserCorrectness
      benchmarkCaps
  codecCanonicalNonMalleability :
    CodecCanonicalPublicationNonMalleabilityFacts
      surface.syncPath.syncDecode
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
  syncExactDecodeBeforeImport :
    surface.syncPath.syncDecode.boundedWireDecodeAccepts = true
      ∧ surface.syncPath.syncDecode.consumedAllBytes = true
  pendingExactDecodeBeforePublication :
    pendingDecode.parserAccepts = true
      ∧ pendingDecode.consumedAllBytes = true
      ∧ pendingDecode.canonicalReencodeMatches = true
  blockActionExactDecodeBeforePublication :
    actionCountMatches blockActionDecode = true
      ∧ blockActionDecode.everyActionDecodesExactly = true
  decodedPayloadRowsEqualPublishedWireRows :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
  declaredRowsEqualPublishedWireRows :
    wireOutput.projectedActionCount =
      blockActionDecode.declaredTxCount
  canonicalPublicationFacts :
    CanonicalPublicationRefinement.CanonicalPublicationReplayFacts
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      (rawTreeReplayInputs blocks)
  parserCorrectnessAssumption :
    parserCorrectness
  benchmarkCapsAssumption :
    benchmarkCaps

theorem accepted_preheavy_codec_canonical_publication_certificate
    {surface : PreHeavyWorkVerificationPathSurface}
    {parserCorrectness benchmarkCaps : Prop}
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
    (preHeavyAccepted :
      AcceptedPreHeavyWorkVerificationPathInputs
        surface
        parserCorrectness
        benchmarkCaps)
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
    PreHeavyCodecCanonicalPublicationCertificate
      surface
      parserCorrectness
      benchmarkCaps
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
  have preHeavyCertificate :
      AcceptedPreHeavyWorkDoSBoundCertificate
        surface
        parserCorrectness
        benchmarkCaps :=
    accepted_preheavy_work_dos_bound_certificate preHeavyAccepted
  have codecFacts :
      CodecCanonicalPublicationNonMalleabilityFacts
        surface.syncPath.syncDecode
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
  exact {
    preHeavyDoSBounds := preHeavyCertificate,
    codecCanonicalNonMalleability := codecFacts,
    syncExactDecodeBeforeImport :=
      preHeavyCertificate.syncBounds.syncDecodeExact,
    pendingExactDecodeBeforePublication :=
      (codecFacts.canonicalPublicationBoundary).pendingDecodeCanonicalNonMalleable,
    blockActionExactDecodeBeforePublication :=
      (codecFacts.canonicalPublicationBoundary).blockActionDecodeCanonicalNonMalleable,
    decodedPayloadRowsEqualPublishedWireRows :=
      codecFacts.canonicalPublicationBoundary.wireRowsMatchDecodedPayloads,
    declaredRowsEqualPublishedWireRows :=
      codecFacts.canonicalPublicationBoundary.wireRowsMatchDeclaredActionCount,
    canonicalPublicationFacts :=
      codecFacts.canonicalPublicationBoundary.canonicalPublicationFacts,
    parserCorrectnessAssumption :=
      preHeavyCertificate.parserCorrectnessAssumption,
    benchmarkCapsAssumption :=
      preHeavyCertificate.benchmarkCapsAssumption
  }

structure PreHeavyBoundedCodecCanonicalPublicationCertificate
    (surface : PreHeavyWorkVerificationPathSurface)
    (parserCorrectness benchmarkCaps : Prop)
    (metadataDecode : NativeMetadataDecodeInput)
    (pendingWire : PendingActionScaleWireInput)
    (coinbaseWire : CoinbaseActionPayloadScaleWireInput)
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
  preHeavyCodecPublication :
    PreHeavyCodecCanonicalPublicationCertificate
      surface
      parserCorrectness
      benchmarkCaps
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
  boundedCodecGate :
    BoundedCanonicalCodecGateCertificate
      surface.syncPath.syncDecode
      metadataDecode
      pendingWire
      coinbaseWire
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
  syncExactDecodeBeforeImport :
    surface.syncPath.syncDecode.boundedWireDecodeAccepts = true
      ∧ surface.syncPath.syncDecode.consumedAllBytes = true
  pendingWireFacts :
    AcceptedPendingActionScaleWireFacts pendingWire
  coinbaseWireFacts :
    AcceptedCoinbaseActionPayloadScaleWireFacts coinbaseWire
  pendingPublicationUsesConcreteWireDecode :
    exactDecodeAccepts pendingDecode = true
  pendingPublicationFullConsumption :
    pendingDecode.consumedAllBytes = true
  pendingPublicationCanonicalReencode :
    pendingDecode.canonicalReencodeMatches = true
  metadataOrdering :
    NativeMetadataDecodeFacts metadataDecode
  parserCorrectnessAssumption :
    parserCorrectness
  benchmarkCapsAssumption :
    benchmarkCaps

theorem accepted_preheavy_bounded_codec_canonical_publication_certificate
    {surface : PreHeavyWorkVerificationPathSurface}
    {parserCorrectness benchmarkCaps : Prop}
    {metadataDecode : NativeMetadataDecodeInput}
    {pendingWire : PendingActionScaleWireInput}
    {coinbaseWire : CoinbaseActionPayloadScaleWireInput}
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
    (preHeavyAccepted :
      AcceptedPreHeavyWorkVerificationPathInputs
        surface
        parserCorrectness
        benchmarkCaps)
    (pendingWireAccepted :
      pendingActionScaleWireAccepts pendingWire = true)
    (coinbaseWireAccepted :
      coinbaseActionPayloadScaleWireAccepts coinbaseWire = true)
    (pendingDecodeIsConcreteWire :
      pendingDecode = exactDecodeInputOfScaleWire pendingWire)
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
    PreHeavyBoundedCodecCanonicalPublicationCertificate
      surface
      parserCorrectness
      benchmarkCaps
      metadataDecode
      pendingWire
      coinbaseWire
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
  have pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true := by
    rw [pendingDecodeIsConcreteWire]
    exact accepted_pending_action_scale_wire_exact_decode pendingWireAccepted
  have preHeavyCodec :
      PreHeavyCodecCanonicalPublicationCertificate
        surface
        parserCorrectness
        benchmarkCaps
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
    accepted_preheavy_codec_canonical_publication_certificate
      preHeavyAccepted
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
  have metadataPublication :
      CodecCanonicalPublicationMetadataNonMalleabilityFacts
        surface.syncPath.syncDecode
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
        blocks :=
    accepted_pending_action_codec_canonical_publication_with_metadata_non_malleability_facts
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
  have boundedCodec :
      BoundedCanonicalCodecGateCertificate
        surface.syncPath.syncDecode
        metadataDecode
        pendingWire
        coinbaseWire
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
    accepted_bounded_canonical_codec_gate_certificate
      metadataPublication
      pendingWireAccepted
      coinbaseWireAccepted
      pendingDecodeIsConcreteWire
  exact {
    preHeavyCodecPublication := preHeavyCodec,
    boundedCodecGate := boundedCodec,
    syncExactDecodeBeforeImport :=
      preHeavyCodec.syncExactDecodeBeforeImport,
    pendingWireFacts := boundedCodec.pendingWireFacts,
    coinbaseWireFacts := boundedCodec.coinbaseWireFacts,
    pendingPublicationUsesConcreteWireDecode :=
      boundedCodec.pendingPublicationUsesConcreteWireDecode,
    pendingPublicationFullConsumption :=
      boundedCodec.pendingPublicationFullConsumption,
    pendingPublicationCanonicalReencode :=
      boundedCodec.pendingPublicationCanonicalReencode,
    metadataOrdering := boundedCodec.metadataOrdering,
    parserCorrectnessAssumption :=
      preHeavyCodec.parserCorrectnessAssumption,
    benchmarkCapsAssumption :=
      preHeavyCodec.benchmarkCapsAssumption
  }

end PreHeavyCodecCanonicalPublication
end Native
end Hegemon

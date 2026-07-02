import Hegemon.Network.PqNoiseHandshakeChannel
import Hegemon.Privacy.NativeObserverSurface
import Hegemon.Privacy.NativeSidecarObserverSurface

namespace Hegemon
namespace Privacy
namespace PqTransportPrivacyBoundary

open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.MaterializedSidecarDaBlobPublication
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Network.PqNoiseHandshakeChannel
open Hegemon.Privacy.CiphertextPrivacy
open Hegemon.Privacy.NativeObserverSurface
open Hegemon.Privacy.NativeSidecarObserverSurface
open Hegemon.Privacy.Observer
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Wallet.NoteCiphertextDecrypt
open Hegemon.Wallet.NotePlaintextCommitment

structure PqTransportPrivacyBoundaryCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (localState peerState : Hegemon.Network.PqNoise.ChannelState)
    (localBytesSent localBytesReceived peerBytesSent peerBytesReceived : Nat)
    (firstFramePayloadBytes firstFrameTagBytes firstFrameWireBytes : Nat)
    (left right : ShieldedTransactionWorld)
    (wireIndistinguishable : Prop)
    (privacyAssumptions : PrivacyBoundaryAssumptions)
    (mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      hkdfDomainSeparation
      rngFreshness : Prop)
    (input : TxLeafActionBindingInput)
    (shape : PublicInputShape)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields) :
    Prop where
  acceptedHandshake :
    AcceptedAuthenticatedPqHandshake surface crypto
  establishedPqChannel :
    EstablishedPqChannelFacts surface crypto localState
  transportCompletion :
    PqTransportCompletionFacts surface crypto localState peerState
  wrapperCompletion :
    PqWrapperCompletionFacts
      surface
      crypto
      localState
      peerState
      localBytesSent
      localBytesReceived
      peerBytesSent
      peerBytesReceived
      firstFramePayloadBytes
      firstFrameTagBytes
      firstFrameWireBytes
  nativeCiphertextPrivacy :
    CiphertextPrivacyOpenAssumptionBoundaryFacts
      left
      right
      wireIndistinguishable
      privacyAssumptions
  allActiveOutputDecryptDaFacts :
    ∀ index publicCommitment publicCiphertextHash
        attempt plaintext material data,
      OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        1
        publicCommitment
        publicCiphertextHash ->
      left.ciphertextSummaries[
        activeFlagCountBefore shape.outputFlags index]? =
          some attempt.ciphertext ->
      evaluateDecrypt attempt = none ->
      data = exportNoteData plaintext material ->
      publicCommitment = commitmentFromNoteData data ->
      (ciphertextHashMatches : List Byte → Digest → Prop) ->
      (∀ {wire summary daBytes},
        left.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? = some wire ->
          Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            wire = some summary ->
          Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            wire = some daBytes ->
          ciphertextHashMatches daBytes publicCiphertextHash) ->
      (∀ {wire summary daBytes},
        right.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? = some wire ->
          Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            wire = some summary ->
          Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            wire = some daBytes ->
          ciphertextHashMatches daBytes publicCiphertextHash) ->
      ActiveOutputDecryptDaCommitmentFacts
        mlKemCiphertextIndistinguishability
        aeadCiphertextConfidentiality
        hkdfDomainSeparation
        rngFreshness
        wireIndistinguishable
        input
        shape
        statementFields
        bindingFields
        left
        right
        index
        publicCommitment
        publicCiphertextHash
        attempt
        plaintext
        material
        ciphertextHashMatches
  handshakeTranscriptBindsMessages :
    crypto.transcriptBindsHandshakeMessages
  handshakeMlKemSharedSecretsAgree :
    crypto.mlkemSharedSecretsAgree
  handshakeInitSignatureAuthentic :
    crypto.initSignatureAuthentic
  handshakeRespSignatureAuthentic :
    crypto.respSignatureAuthentic
  handshakeFinishSignatureAuthentic :
    crypto.finishSignatureAuthentic
  handshakeHkdfExtractExpandSound :
    crypto.hkdfExtractExpandSound
  handshakeAeadProtectOpenSound :
    crypto.aeadProtectOpenSound
  ciphertextMlKemIndistinguishability :
    mlKemCiphertextIndistinguishability
  ciphertextAeadConfidentiality :
    aeadCiphertextConfidentiality
  ciphertextHkdfDomainSeparation :
    hkdfDomainSeparation
  ciphertextRngFreshness :
    rngFreshness
  rawWireIndistinguishable :
    wireIndistinguishable
  proofSystemZeroKnowledge :
    privacyAssumptions.proofSystemZeroKnowledge
  walletMetadataHygiene :
    privacyAssumptions.walletMetadataHygiene
  timingAndBatchingPolicy :
    privacyAssumptions.timingAndBatchingPolicy
  networkMetadataPolicy :
    privacyAssumptions.networkMetadataPolicy

theorem accepted_pq_handshake_native_ciphertext_privacy_boundary_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {left right : ShieldedTransactionWorld}
    {privacyAssumptions : PrivacyBoundaryAssumptions}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    (privacyProofs : PrivacyBoundaryAssumptionProofs privacyAssumptions)
    (mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      hkdfDomainSeparation
      rngFreshness : Prop)
    (mlKemAssumption : mlKemCiphertextIndistinguishability)
    (aeadAssumption : aeadCiphertextConfidentiality)
    (hkdfAssumption : hkdfDomainSeparation)
    (rngAssumption : rngFreshness)
    (firstFramePayloadBytes : Nat)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape)
    (leftObserverBytesBounded :
      ∀ wire,
        wire ∈ left.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire)
    (rightObserverBytesBounded :
      ∀ wire,
        wire ∈ right.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    PqTransportPrivacyBoundaryCertificate
      surface
      crypto
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      0
      0
      0
      0
      firstFramePayloadBytes
      pqAeadTagBytes
      (firstFramePayloadBytes + pqAeadTagBytes)
      left
      right
      game.wireIndistinguishable
      privacyAssumptions
      mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      hkdfDomainSeparation
      rngFreshness
      input
      shape
      statementFields
      bindingFields := by
  rcases
      native_tx_leaf_ciphertext_privacy_game_all_active_outputs_open_assumption_decrypt_da_boundary
        privacyProofs
        mlKemCiphertextIndistinguishability
        aeadCiphertextConfidentiality
        hkdfDomainSeparation
        rngFreshness
        mlKemAssumption
        aeadAssumption
        hkdfAssumption
        rngAssumption
        bindingAccepted
        canonicalSurface
        game
        leftShape
        leftObserverBytesBounded
        rightObserverBytesBounded with
    ⟨nativePrivacy, allDecryptDaFacts⟩
  exact
    { acceptedHandshake := handshake
      establishedPqChannel :=
        accepted_authenticated_pq_handshake_establishes_pq_channel_facts
          handshake
      transportCompletion :=
        accepted_authenticated_pq_handshake_transport_completion_facts
          handshake
      wrapperCompletion :=
        accepted_authenticated_pq_handshake_wrapper_completion_facts
          handshake
          firstFramePayloadBytes
      nativeCiphertextPrivacy := nativePrivacy
      allActiveOutputDecryptDaFacts := allDecryptDaFacts
      handshakeTranscriptBindsMessages := handshake.transcriptBound
      handshakeMlKemSharedSecretsAgree := handshake.kemAgreed
      handshakeInitSignatureAuthentic := handshake.initSignatureVerified
      handshakeRespSignatureAuthentic := handshake.respSignatureVerified
      handshakeFinishSignatureAuthentic := handshake.finishSignatureVerified
      handshakeHkdfExtractExpandSound := handshake.hkdfSound
      handshakeAeadProtectOpenSound := handshake.aeadSound
      ciphertextMlKemIndistinguishability := mlKemAssumption
      ciphertextAeadConfidentiality := aeadAssumption
      ciphertextHkdfDomainSeparation := hkdfAssumption
      ciphertextRngFreshness := rngAssumption
      rawWireIndistinguishable := nativePrivacy.rawWireIndistinguishable
      proofSystemZeroKnowledge := nativePrivacy.proofSystemZeroKnowledge
      walletMetadataHygiene := nativePrivacy.walletMetadataHygiene
      timingAndBatchingPolicy := nativePrivacy.timingAndBatchingPolicy
      networkMetadataPolicy := nativePrivacy.networkMetadataPolicy }

theorem accepted_pq_handshake_native_ciphertext_privacy_boundary_exposes_raw_wire
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {localState peerState : Hegemon.Network.PqNoise.ChannelState}
    {localBytesSent localBytesReceived peerBytesSent peerBytesReceived : Nat}
    {firstFramePayloadBytes firstFrameTagBytes firstFrameWireBytes : Nat}
    {left right : ShieldedTransactionWorld}
    {wireIndistinguishable : Prop}
    {privacyAssumptions : PrivacyBoundaryAssumptions}
    {mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      hkdfDomainSeparation
      rngFreshness : Prop}
    {input : TxLeafActionBindingInput}
    {shape : PublicInputShape}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    (certificate :
      PqTransportPrivacyBoundaryCertificate
        surface
        crypto
        localState
        peerState
        localBytesSent
        localBytesReceived
        peerBytesSent
        peerBytesReceived
        firstFramePayloadBytes
        firstFrameTagBytes
        firstFrameWireBytes
        left
        right
        wireIndistinguishable
        privacyAssumptions
        mlKemCiphertextIndistinguishability
        aeadCiphertextConfidentiality
        hkdfDomainSeparation
        rngFreshness
        input
        shape
        statementFields
        bindingFields) :
    wireIndistinguishable :=
  certificate.rawWireIndistinguishable

structure PqTransportCiphertextResidualAssumptions where
  mlKemCiphertextIndistinguishability : Prop
  aeadCiphertextConfidentiality : Prop
  kdfDomainSeparation : Prop
  osRngFreshness : Prop
  parserWireExactness : Prop

structure PqTransportNativeCiphertextResidualCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (localState peerState : Hegemon.Network.PqNoise.ChannelState)
    (localBytesSent localBytesReceived peerBytesSent peerBytesReceived : Nat)
    (firstFramePayloadBytes firstFrameTagBytes firstFrameWireBytes : Nat)
    (left right : ShieldedTransactionWorld)
    (wireIndistinguishable : Prop)
    (privacyAssumptions : PrivacyBoundaryAssumptions)
    (residuals : PqTransportCiphertextResidualAssumptions)
    (input : TxLeafActionBindingInput)
    (shape : PublicInputShape)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields) :
    Prop where
  boundaryCertificate :
    PqTransportPrivacyBoundaryCertificate
      surface
      crypto
      localState
      peerState
      localBytesSent
      localBytesReceived
      peerBytesSent
      peerBytesReceived
      firstFramePayloadBytes
      firstFrameTagBytes
      firstFrameWireBytes
      left
      right
      wireIndistinguishable
      privacyAssumptions
      residuals.mlKemCiphertextIndistinguishability
      residuals.aeadCiphertextConfidentiality
      residuals.kdfDomainSeparation
      residuals.osRngFreshness
      input
      shape
      statementFields
      bindingFields
  mlKemCiphertextIndistinguishability :
    residuals.mlKemCiphertextIndistinguishability
  aeadCiphertextConfidentiality :
    residuals.aeadCiphertextConfidentiality
  kdfDomainSeparation :
    residuals.kdfDomainSeparation
  osRngFreshness :
    residuals.osRngFreshness
  parserWireExactness :
    residuals.parserWireExactness
  rawWireIndistinguishable :
    wireIndistinguishable
  proofSystemZeroKnowledge :
    privacyAssumptions.proofSystemZeroKnowledge
  walletMetadataHygiene :
    privacyAssumptions.walletMetadataHygiene
  timingAndBatchingPolicy :
    privacyAssumptions.timingAndBatchingPolicy
  networkMetadataPolicy :
    privacyAssumptions.networkMetadataPolicy

theorem accepted_pq_handshake_native_ciphertext_privacy_boundary_residual_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {left right : ShieldedTransactionWorld}
    {privacyAssumptions : PrivacyBoundaryAssumptions}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    (privacyProofs : PrivacyBoundaryAssumptionProofs privacyAssumptions)
    (mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      osRngFreshness
      parserWireExactness : Prop)
    (mlKemAssumption : mlKemCiphertextIndistinguishability)
    (aeadAssumption : aeadCiphertextConfidentiality)
    (kdfAssumption : kdfDomainSeparation)
    (rngAssumption : osRngFreshness)
    (parserWireAssumption : parserWireExactness)
    (firstFramePayloadBytes : Nat)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape)
    (leftObserverBytesBounded :
      ∀ wire,
        wire ∈ left.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire)
    (rightObserverBytesBounded :
      ∀ wire,
        wire ∈ right.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    PqTransportNativeCiphertextResidualCertificate
      surface
      crypto
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      0
      0
      0
      0
      firstFramePayloadBytes
      pqAeadTagBytes
      (firstFramePayloadBytes + pqAeadTagBytes)
      left
      right
      game.wireIndistinguishable
      privacyAssumptions
      { mlKemCiphertextIndistinguishability :=
          mlKemCiphertextIndistinguishability
        aeadCiphertextConfidentiality :=
          aeadCiphertextConfidentiality
        kdfDomainSeparation :=
          kdfDomainSeparation
        osRngFreshness :=
          osRngFreshness
        parserWireExactness :=
          parserWireExactness }
      input
      shape
      statementFields
      bindingFields := by
  let boundaryCertificate :=
    accepted_pq_handshake_native_ciphertext_privacy_boundary_certificate
      handshake
      privacyProofs
      mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      osRngFreshness
      mlKemAssumption
      aeadAssumption
      kdfAssumption
      rngAssumption
      firstFramePayloadBytes
      bindingAccepted
      canonicalSurface
      game
      leftShape
      leftObserverBytesBounded
      rightObserverBytesBounded
  exact
    { boundaryCertificate := boundaryCertificate
      mlKemCiphertextIndistinguishability :=
        boundaryCertificate.ciphertextMlKemIndistinguishability
      aeadCiphertextConfidentiality :=
        boundaryCertificate.ciphertextAeadConfidentiality
      kdfDomainSeparation :=
        boundaryCertificate.ciphertextHkdfDomainSeparation
      osRngFreshness :=
        boundaryCertificate.ciphertextRngFreshness
      parserWireExactness := parserWireAssumption
      rawWireIndistinguishable :=
        boundaryCertificate.rawWireIndistinguishable
      proofSystemZeroKnowledge :=
        boundaryCertificate.proofSystemZeroKnowledge
      walletMetadataHygiene :=
        boundaryCertificate.walletMetadataHygiene
      timingAndBatchingPolicy :=
        boundaryCertificate.timingAndBatchingPolicy
      networkMetadataPolicy :=
        boundaryCertificate.networkMetadataPolicy }

structure PqKemSeedTranscriptKdfImplementationBoundaryFacts
    (surface : HandshakeChannelSurface)
    (responderSeed initiatorSeed :
      Hegemon.Network.PqNoise.MlKemEncapsulationSeedFacts) : Prop where
  responderSeedUse :
    responderSeed.use =
      Hegemon.Network.PqNoise.KemEncapsulationUse.responderEncapsulatesToInitiator
  initiatorSeedUse :
    initiatorSeed.use =
      Hegemon.Network.PqNoise.KemEncapsulationUse.initiatorEncapsulatesToResponder
  responderSeedSourceOsRng :
    responderSeed.source = Hegemon.Network.PqNoise.KemSeedSource.osRng32
  initiatorSeedSourceOsRng :
    initiatorSeed.source = Hegemon.Network.PqNoise.KemSeedSource.osRng32
  responderSeedByteLength :
    responderSeed.seedByteLength = 32
  initiatorSeedByteLength :
    initiatorSeed.seedByteLength = 32
  responderSeedConsumedByMlKem :
    responderSeed.consumedByMlKemEncapsulate
  initiatorSeedConsumedByMlKem :
    initiatorSeed.consumedByMlKemEncapsulate
  transcriptOnlyEntersSessionScheduleAsSalt :
    Hegemon.Network.PqNoise.hkdfSalt surface.pqSession =
      surface.pqSession.transcriptHash
  kemSecretsEnterIkmInHandshakeOrder :
    Hegemon.Network.PqNoise.hkdfIkm surface.pqSession =
      surface.pqSession.shared1 ++ surface.pqSession.shared2
  respAndFinishBindTranscriptHash :
    surface.respHello.transcriptHash = surface.pqSession.transcriptHash
      ∧ surface.finish.transcriptHash = surface.pqSession.transcriptHash

theorem accepted_pq_kem_transcript_kdf_certificate_excludes_implementation_seed_misuse
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed :
      Hegemon.Network.PqNoise.MlKemEncapsulationSeedFacts}
    (certificate :
      AcceptedPqKemTranscriptKdfCertificate
        surface
        crypto
        responderSeed
        initiatorSeed) :
    PqKemSeedTranscriptKdfImplementationBoundaryFacts
      surface
      responderSeed
      initiatorSeed := by
  exact
    { responderSeedUse := certificate.responderSeedUse
      initiatorSeedUse := certificate.initiatorSeedUse
      responderSeedSourceOsRng := certificate.responderSeedSource
      initiatorSeedSourceOsRng := certificate.initiatorSeedSource
      responderSeedByteLength := certificate.responderSeedByteLength
      initiatorSeedByteLength := certificate.initiatorSeedByteLength
      responderSeedConsumedByMlKem :=
        certificate.responderEncapsulationUsesResponderSeed
      initiatorSeedConsumedByMlKem :=
        certificate.initiatorEncapsulationUsesInitiatorSeed
      transcriptOnlyEntersSessionScheduleAsSalt :=
        certificate.transcriptOnlyEntersSessionScheduleAsSalt
      kemSecretsEnterIkmInHandshakeOrder :=
        certificate.kemSecretsEnterIkmInHandshakeOrder
      respAndFinishBindTranscriptHash :=
        certificate.respAndFinishBindTranscriptHash }

structure PqTransportCiphertextPrimitiveResidualAssumptions where
  mlKemCiphertextIndistinguishability : Prop
  aeadCiphertextConfidentiality : Prop
  hkdfExtractExpandPrimitiveSecurity : Prop
  osRngQuality : Prop
  parserWireExactness : Prop

structure PqTransportNativeCiphertextSeedHardenedResidualCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (localState peerState : Hegemon.Network.PqNoise.ChannelState)
    (localBytesSent localBytesReceived peerBytesSent peerBytesReceived : Nat)
    (firstFramePayloadBytes firstFrameTagBytes firstFrameWireBytes : Nat)
    (left right : ShieldedTransactionWorld)
    (wireIndistinguishable : Prop)
    (privacyAssumptions : PrivacyBoundaryAssumptions)
    (residuals : PqTransportCiphertextPrimitiveResidualAssumptions)
    (responderSeed initiatorSeed :
      Hegemon.Network.PqNoise.MlKemEncapsulationSeedFacts)
    (input : TxLeafActionBindingInput)
    (shape : PublicInputShape)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields) :
    Prop where
  residualCertificate :
    PqTransportNativeCiphertextResidualCertificate
      surface
      crypto
      localState
      peerState
      localBytesSent
      localBytesReceived
      peerBytesSent
      peerBytesReceived
      firstFramePayloadBytes
      firstFrameTagBytes
      firstFrameWireBytes
      left
      right
      wireIndistinguishable
      privacyAssumptions
      { mlKemCiphertextIndistinguishability :=
          residuals.mlKemCiphertextIndistinguishability
        aeadCiphertextConfidentiality :=
          residuals.aeadCiphertextConfidentiality
        kdfDomainSeparation :=
          residuals.hkdfExtractExpandPrimitiveSecurity
        osRngFreshness :=
          residuals.osRngQuality
        parserWireExactness :=
          residuals.parserWireExactness }
      input
      shape
      statementFields
      bindingFields
  kemTranscriptKdfCertificate :
    AcceptedPqKemTranscriptKdfCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
  implementationSeedBoundary :
    PqKemSeedTranscriptKdfImplementationBoundaryFacts
      surface
      responderSeed
      initiatorSeed
  mlKemCiphertextIndistinguishability :
    residuals.mlKemCiphertextIndistinguishability
  aeadCiphertextConfidentiality :
    residuals.aeadCiphertextConfidentiality
  hkdfExtractExpandPrimitiveSecurity :
    residuals.hkdfExtractExpandPrimitiveSecurity
  osRngQuality :
    residuals.osRngQuality
  parserWireExactness :
    residuals.parserWireExactness
  rawWireIndistinguishable :
    wireIndistinguishable
  proofSystemZeroKnowledge :
    privacyAssumptions.proofSystemZeroKnowledge
  walletMetadataHygiene :
    privacyAssumptions.walletMetadataHygiene
  timingAndBatchingPolicy :
    privacyAssumptions.timingAndBatchingPolicy
  networkMetadataPolicy :
    privacyAssumptions.networkMetadataPolicy

theorem accepted_pq_kem_certificate_native_ciphertext_privacy_boundary_seed_hardened_residual_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed :
      Hegemon.Network.PqNoise.MlKemEncapsulationSeedFacts}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {left right : ShieldedTransactionWorld}
    {privacyAssumptions : PrivacyBoundaryAssumptions}
    (kemTranscriptKdfCertificate :
      AcceptedPqKemTranscriptKdfCertificate
        surface
        crypto
        responderSeed
        initiatorSeed)
    (privacyProofs : PrivacyBoundaryAssumptionProofs privacyAssumptions)
    (mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      hkdfExtractExpandPrimitiveSecurity
      osRngQuality
      parserWireExactness : Prop)
    (mlKemAssumption : mlKemCiphertextIndistinguishability)
    (aeadAssumption : aeadCiphertextConfidentiality)
    (hkdfAssumption : hkdfExtractExpandPrimitiveSecurity)
    (osRngAssumption : osRngQuality)
    (parserWireAssumption : parserWireExactness)
    (firstFramePayloadBytes : Nat)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape)
    (leftObserverBytesBounded :
      ∀ wire,
        wire ∈ left.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire)
    (rightObserverBytesBounded :
      ∀ wire,
        wire ∈ right.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    PqTransportNativeCiphertextSeedHardenedResidualCertificate
      surface
      crypto
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      0
      0
      0
      0
      firstFramePayloadBytes
      pqAeadTagBytes
      (firstFramePayloadBytes + pqAeadTagBytes)
      left
      right
      game.wireIndistinguishable
      privacyAssumptions
      { mlKemCiphertextIndistinguishability :=
          mlKemCiphertextIndistinguishability
        aeadCiphertextConfidentiality :=
          aeadCiphertextConfidentiality
        hkdfExtractExpandPrimitiveSecurity :=
          hkdfExtractExpandPrimitiveSecurity
        osRngQuality :=
          osRngQuality
        parserWireExactness :=
          parserWireExactness }
      responderSeed
      initiatorSeed
      input
      shape
      statementFields
      bindingFields := by
  let residualCertificate :=
    accepted_pq_handshake_native_ciphertext_privacy_boundary_residual_certificate
      kemTranscriptKdfCertificate.handshakeAccepted
      privacyProofs
      mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      hkdfExtractExpandPrimitiveSecurity
      osRngQuality
      parserWireExactness
      mlKemAssumption
      aeadAssumption
      hkdfAssumption
      osRngAssumption
      parserWireAssumption
      firstFramePayloadBytes
      bindingAccepted
      canonicalSurface
      game
      leftShape
      leftObserverBytesBounded
      rightObserverBytesBounded
  exact
    { residualCertificate := residualCertificate
      kemTranscriptKdfCertificate := kemTranscriptKdfCertificate
      implementationSeedBoundary :=
        accepted_pq_kem_transcript_kdf_certificate_excludes_implementation_seed_misuse
          kemTranscriptKdfCertificate
      mlKemCiphertextIndistinguishability :=
        residualCertificate.mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality :=
        residualCertificate.aeadCiphertextConfidentiality
      hkdfExtractExpandPrimitiveSecurity :=
        residualCertificate.kdfDomainSeparation
      osRngQuality :=
        residualCertificate.osRngFreshness
      parserWireExactness :=
        residualCertificate.parserWireExactness
      rawWireIndistinguishable :=
        residualCertificate.rawWireIndistinguishable
      proofSystemZeroKnowledge :=
        residualCertificate.proofSystemZeroKnowledge
      walletMetadataHygiene :=
        residualCertificate.walletMetadataHygiene
      timingAndBatchingPolicy :=
        residualCertificate.timingAndBatchingPolicy
      networkMetadataPolicy :=
        residualCertificate.networkMetadataPolicy }

structure PqTransportMaterializedSidecarCiphertextPrivacyCertificate
    (pqSurface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions pqSurface)
    (localState peerState : Hegemon.Network.PqNoise.ChannelState)
    (localBytesSent localBytesReceived peerBytesSent peerBytesReceived : Nat)
    (firstFramePayloadBytes firstFrameTagBytes firstFrameWireBytes : Nat)
    (sidecarSurface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : Hegemon.Native.AcceptedChain.NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (txLeaf : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop)
    (left right : ShieldedTransactionWorld)
    (wireIndistinguishable : Prop)
    (privacyAssumptions : PrivacyBoundaryAssumptions)
    (residuals : PqTransportCiphertextPrimitiveResidualAssumptions)
    (responderSeed initiatorSeed :
      Hegemon.Network.PqNoise.MlKemEncapsulationSeedFacts) :
    Prop where
  sidecarPublicationFacts :
    MaterializedSidecarDaBlobPublicationFacts
      sidecarSurface
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
  seedHardenedResidualCertificate :
    PqTransportNativeCiphertextSeedHardenedResidualCertificate
      pqSurface
      crypto
      localState
      peerState
      localBytesSent
      localBytesReceived
      peerBytesSent
      peerBytesReceived
      firstFramePayloadBytes
      firstFrameTagBytes
      firstFrameWireBytes
      left
      right
      wireIndistinguishable
      privacyAssumptions
      residuals
      responderSeed
      initiatorSeed
      txLeaf
      shape
      statementFields
      bindingFields
  materializedSidecarRows :
    sidecarSurface.transferState.sidecarCiphertextsAvailable = true
      ∧ sidecarSurface.transferState.sidecarCiphertextSizesPresent = true
      ∧ sidecarSurface.transferState.sidecarCiphertextSizesMatch = true
  wireReplayDaRowBinding :
    actionWireReplayProjectionPreconditions
        sidecarSurface.daSidecarReplay.wireReplayProjection = true
      ∧ sidecarSurface.daSidecarReplay.wireReplayProjection.actionCount =
        sidecarSurface.daSidecarReplay.wireReplayProjection.plannedCount
      ∧ sidecarSurface.daSidecarReplay.wireReplayProjection.actionCount =
        sidecarSurface.daSidecarReplay.wireReplayProjection.actions.length
      ∧ wireOutput.projectedActionCount =
        blockActionDecode.actualActionPayloadCount
  txLeafCiphertextPublication :
    txLeaf.ciphertextHashesMatch = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true
  statementCiphertextVectorPublication :
    shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds
  nativeOpenAssumptionBoundary :
    CiphertextPrivacyOpenAssumptionBoundaryFacts
      left
      right
      wireIndistinguishable
      privacyAssumptions
  allActiveOutputDecryptDaFacts :
    ∀ index publicCommitment publicCiphertextHash
        attempt plaintext material data,
      OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        1
        publicCommitment
        publicCiphertextHash ->
      left.ciphertextSummaries[
        activeFlagCountBefore shape.outputFlags index]? =
          some attempt.ciphertext ->
      evaluateDecrypt attempt = none ->
      data = exportNoteData plaintext material ->
      publicCommitment = commitmentFromNoteData data ->
      (ciphertextHashMatches : List Byte → Digest → Prop) ->
      (∀ {wire summary daBytes},
        left.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? = some wire ->
          Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            wire = some summary ->
          Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            wire = some daBytes ->
          ciphertextHashMatches daBytes publicCiphertextHash) ->
      (∀ {wire summary daBytes},
        right.ciphertextBytes[
            activeFlagCountBefore shape.outputFlags index]? = some wire ->
          Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
            wire = some summary ->
          Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
            wire = some daBytes ->
          ciphertextHashMatches daBytes publicCiphertextHash) ->
      ActiveOutputDecryptDaCommitmentFacts
        residuals.mlKemCiphertextIndistinguishability
        residuals.aeadCiphertextConfidentiality
        residuals.hkdfExtractExpandPrimitiveSecurity
        residuals.osRngQuality
        wireIndistinguishable
        txLeaf
        shape
        statementFields
        bindingFields
        left
        right
        index
        publicCommitment
        publicCiphertextHash
        attempt
        plaintext
        material
        ciphertextHashMatches
  implementationSeedBoundary :
    PqKemSeedTranscriptKdfImplementationBoundaryFacts
      pqSurface
      responderSeed
      initiatorSeed
  mlKemCiphertextIndistinguishability :
    residuals.mlKemCiphertextIndistinguishability
  aeadCiphertextConfidentiality :
    residuals.aeadCiphertextConfidentiality
  hkdfExtractExpandPrimitiveSecurity :
    residuals.hkdfExtractExpandPrimitiveSecurity
  osRngQuality :
    residuals.osRngQuality
  parserWireExactness :
    residuals.parserWireExactness
  rawWireIndistinguishable :
    wireIndistinguishable
  proofSystemZeroKnowledge :
    privacyAssumptions.proofSystemZeroKnowledge
  walletMetadataHygiene :
    privacyAssumptions.walletMetadataHygiene
  timingAndBatchingPolicy :
    privacyAssumptions.timingAndBatchingPolicy
  networkMetadataPolicy :
    privacyAssumptions.networkMetadataPolicy

theorem accepted_pq_kem_materialized_sidecar_ciphertext_privacy_boundary_seed_hardened_residual_certificate
    {pqSurface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions pqSurface}
    {responderSeed initiatorSeed :
      Hegemon.Network.PqNoise.MlKemEncapsulationSeedFacts}
    {sidecarSurface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : Hegemon.Native.AcceptedChain.NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    {left right : ShieldedTransactionWorld}
    {privacyAssumptions : PrivacyBoundaryAssumptions}
    (kemTranscriptKdfCertificate :
      AcceptedPqKemTranscriptKdfCertificate
        pqSurface
        crypto
        responderSeed
        initiatorSeed)
    (privacyProofs : PrivacyBoundaryAssumptionProofs privacyAssumptions)
    (mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      hkdfExtractExpandPrimitiveSecurity
      osRngQuality
      parserWireExactness : Prop)
    (mlKemAssumption : mlKemCiphertextIndistinguishability)
    (aeadAssumption : aeadCiphertextConfidentiality)
    (hkdfAssumption : hkdfExtractExpandPrimitiveSecurity)
    (osRngAssumption : osRngQuality)
    (parserWireAssumption : parserWireExactness)
    (firstFramePayloadBytes : Nat)
    (facts :
      MaterializedSidecarDaBlobPublicationFacts
        sidecarSurface
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
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape)
    (leftObserverBytesBounded :
      ∀ wire,
        wire ∈ left.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire)
    (rightObserverBytesBounded :
      ∀ wire,
        wire ∈ right.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    PqTransportMaterializedSidecarCiphertextPrivacyCertificate
      pqSurface
      crypto
      (pqChannelStateFromHandshake pqSurface)
      (peerPqChannelStateFromHandshake pqSurface)
      0
      0
      0
      0
      firstFramePayloadBytes
      pqAeadTagBytes
      (firstFramePayloadBytes + pqAeadTagBytes)
      sidecarSurface
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
      left
      right
      game.wireIndistinguishable
      privacyAssumptions
      { mlKemCiphertextIndistinguishability :=
          mlKemCiphertextIndistinguishability
        aeadCiphertextConfidentiality :=
          aeadCiphertextConfidentiality
        hkdfExtractExpandPrimitiveSecurity :=
          hkdfExtractExpandPrimitiveSecurity
        osRngQuality :=
          osRngQuality
        parserWireExactness :=
          parserWireExactness }
      responderSeed
      initiatorSeed := by
  let seedCertificate :=
    accepted_pq_kem_certificate_native_ciphertext_privacy_boundary_seed_hardened_residual_certificate
      kemTranscriptKdfCertificate
      privacyProofs
      mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality
      hkdfExtractExpandPrimitiveSecurity
      osRngQuality
      parserWireExactness
      mlKemAssumption
      aeadAssumption
      hkdfAssumption
      osRngAssumption
      parserWireAssumption
      firstFramePayloadBytes
      facts.fullBytePublication.txLeafAccepted
      canonicalSurface
      game
      leftShape
      leftObserverBytesBounded
      rightObserverBytesBounded
  rcases
      materialized_sidecar_ciphertext_privacy_game_all_active_outputs_open_assumption_decrypt_da_boundary
        privacyProofs
        mlKemCiphertextIndistinguishability
        aeadCiphertextConfidentiality
        hkdfExtractExpandPrimitiveSecurity
        osRngQuality
        mlKemAssumption
        aeadAssumption
        hkdfAssumption
        osRngAssumption
        facts
        canonicalSurface
        game
        leftShape
        leftObserverBytesBounded
        rightObserverBytesBounded with
    ⟨materializedRows,
      wireReplayDaRowBinding,
      txLeafCiphertextPublication,
      statementCiphertextVectorPublication,
      nativeOpenAssumptionBoundary,
      allActiveOutputDecryptDaFacts⟩
  exact
    { sidecarPublicationFacts := facts
      seedHardenedResidualCertificate := seedCertificate
      materializedSidecarRows := materializedRows
      wireReplayDaRowBinding := wireReplayDaRowBinding
      txLeafCiphertextPublication := txLeafCiphertextPublication
      statementCiphertextVectorPublication :=
        statementCiphertextVectorPublication
      nativeOpenAssumptionBoundary := nativeOpenAssumptionBoundary
      allActiveOutputDecryptDaFacts := allActiveOutputDecryptDaFacts
      implementationSeedBoundary :=
        seedCertificate.implementationSeedBoundary
      mlKemCiphertextIndistinguishability :=
        seedCertificate.mlKemCiphertextIndistinguishability
      aeadCiphertextConfidentiality :=
        seedCertificate.aeadCiphertextConfidentiality
      hkdfExtractExpandPrimitiveSecurity :=
        seedCertificate.hkdfExtractExpandPrimitiveSecurity
      osRngQuality := seedCertificate.osRngQuality
      parserWireExactness := seedCertificate.parserWireExactness
      rawWireIndistinguishable :=
        seedCertificate.rawWireIndistinguishable
      proofSystemZeroKnowledge :=
        seedCertificate.proofSystemZeroKnowledge
      walletMetadataHygiene :=
        seedCertificate.walletMetadataHygiene
      timingAndBatchingPolicy :=
        seedCertificate.timingAndBatchingPolicy
      networkMetadataPolicy :=
        seedCertificate.networkMetadataPolicy }

end PqTransportPrivacyBoundary
end Privacy
end Hegemon

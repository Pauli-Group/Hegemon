import Hegemon.Network.PqNoiseHandshakeChannel
import Hegemon.Privacy.NativeObserverSurface

namespace Hegemon
namespace Privacy
namespace PqTransportPrivacyBoundary

open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Network.PqNoiseHandshakeChannel
open Hegemon.Privacy.CiphertextPrivacy
open Hegemon.Privacy.NativeObserverSurface
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

end PqTransportPrivacyBoundary
end Privacy
end Hegemon

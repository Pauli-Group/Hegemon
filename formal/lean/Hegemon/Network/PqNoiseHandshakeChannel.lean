import Hegemon.Network.PqNoise
import Hegemon.Network.FrameResourceAdmission
import Hegemon.Network.SecureChannel

namespace Hegemon
namespace Network
namespace PqNoiseHandshakeChannel

def secureRole : PqNoise.Role -> SecureChannel.Role
  | PqNoise.Role.initiator => SecureChannel.Role.initiator
  | PqNoise.Role.responder => SecureChannel.Role.responder

def secureSlot : PqNoise.KeySlot -> SecureChannel.KeySlot
  | PqNoise.KeySlot.initiatorToResponder =>
      SecureChannel.KeySlot.initiatorToResponder
  | PqNoise.KeySlot.responderToInitiator =>
      SecureChannel.KeySlot.responderToInitiator

def secureLabel : SecureChannel.KeySlot -> List Byte
  | SecureChannel.KeySlot.initiatorToResponder =>
      SecureChannel.initiatorToResponderLabel
  | SecureChannel.KeySlot.responderToInitiator =>
      SecureChannel.responderToInitiatorLabel

structure HandshakeChannelSurface where
  role : PqNoise.Role
  initHello : PqNoise.InitHelloSigningInput
  respHello : PqNoise.RespHelloSigningInput
  finish : PqNoise.FinishSigningInput
  pqSession : PqNoise.SessionKeyInput
  channelSchedule : SecureChannel.KeyScheduleInput
deriving DecidableEq, Repr

structure CryptoAssumptions (surface : HandshakeChannelSurface) where
  transcriptBindsHandshakeMessages : Prop
  mlkemSharedSecretsAgree : Prop
  initSignatureAuthentic : Prop
  respSignatureAuthentic : Prop
  finishSignatureAuthentic : Prop
  hkdfExtractExpandSound : Prop
  aeadProtectOpenSound : Prop

structure AcceptedAuthenticatedPqHandshake
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface) : Prop where
  transcriptBound : crypto.transcriptBindsHandshakeMessages
  kemAgreed : crypto.mlkemSharedSecretsAgree
  initSignatureVerified : crypto.initSignatureAuthentic
  respSignatureVerified : crypto.respSignatureAuthentic
  finishSignatureVerified : crypto.finishSignatureAuthentic
  hkdfSound : crypto.hkdfExtractExpandSound
  aeadSound : crypto.aeadProtectOpenSound

structure AcceptedPqKemTranscriptKdfCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts) : Prop where
  handshakeAccepted :
    AcceptedAuthenticatedPqHandshake surface crypto
  transcriptBound :
    crypto.transcriptBindsHandshakeMessages
  kemSharedSecretsAgree :
    crypto.mlkemSharedSecretsAgree
  responderSeedUse :
    responderSeed.use =
      PqNoise.KemEncapsulationUse.responderEncapsulatesToInitiator
  initiatorSeedUse :
    initiatorSeed.use =
      PqNoise.KemEncapsulationUse.initiatorEncapsulatesToResponder
  responderSeedSource :
    responderSeed.source = PqNoise.KemSeedSource.osRng32
  initiatorSeedSource :
    initiatorSeed.source = PqNoise.KemSeedSource.osRng32
  responderSeedByteLength :
    responderSeed.seedByteLength = 32
  initiatorSeedByteLength :
    initiatorSeed.seedByteLength = 32
  responderEncapsulationUsesResponderSeed :
    responderSeed.consumedByMlKemEncapsulate
  initiatorEncapsulationUsesInitiatorSeed :
    initiatorSeed.consumedByMlKemEncapsulate
  transcriptOnlyEntersSessionScheduleAsSalt :
    PqNoise.hkdfSalt surface.pqSession = surface.pqSession.transcriptHash
  kemSecretsEnterIkmInHandshakeOrder :
    PqNoise.hkdfIkm surface.pqSession =
      surface.pqSession.shared1 ++ surface.pqSession.shared2
  i2rR2iAndAadLabelsSeparated :
    PqNoise.initiatorToResponderInfo ≠ PqNoise.responderToInitiatorInfo
      ∧ PqNoise.sessionAadInfo ≠ PqNoise.initiatorToResponderInfo
      ∧ PqNoise.sessionAadInfo ≠ PqNoise.responderToInitiatorInfo
  initSigningPreimageFields :
    PqNoise.initHelloSigningPreimage surface.initHello =
      asciiBytes "init-hello"
        ++ [byte surface.initHello.version]
        ++ surface.initHello.mlkemPublicKey
        ++ surface.initHello.identityKey
        ++ PqNoise.u64be surface.initHello.nonce
  respSigningPreimageFields :
    PqNoise.respHelloSigningPreimage surface.respHello =
      asciiBytes "resp-hello"
        ++ [byte surface.respHello.version]
        ++ surface.respHello.mlkemPublicKey
        ++ surface.respHello.mlkemCiphertext
        ++ surface.respHello.identityKey
        ++ PqNoise.u64be surface.respHello.nonce
        ++ surface.respHello.transcriptHash
  finishSigningPreimageFields :
    PqNoise.finishSigningPreimage surface.finish =
      asciiBytes "finish"
        ++ surface.finish.mlkemCiphertext
        ++ PqNoise.u64be surface.finish.nonce
        ++ surface.finish.transcriptHash
  respAndFinishBindTranscriptHash :
    surface.respHello.transcriptHash = surface.pqSession.transcriptHash
      ∧ surface.finish.transcriptHash = surface.pqSession.transcriptHash

def channelStateFromHandshake
    (surface : HandshakeChannelSurface) :
    SecureChannel.ChannelState :=
  SecureChannel.initialState (secureRole surface.role)

def pqChannelStateFromHandshake
    (surface : HandshakeChannelSurface) :
    PqNoise.ChannelState :=
  PqNoise.initialState surface.role

def peerRole : PqNoise.Role -> PqNoise.Role
  | PqNoise.Role.initiator => PqNoise.Role.responder
  | PqNoise.Role.responder => PqNoise.Role.initiator

def roleIsInitiator : PqNoise.Role -> Bool
  | PqNoise.Role.initiator => true
  | PqNoise.Role.responder => false

def pqAeadTagBytes : Nat := 16

def peerPqChannelStateFromHandshake
    (surface : HandshakeChannelSurface) :
    PqNoise.ChannelState :=
  PqNoise.initialState (peerRole surface.role)

def localPqSendStateAt
    (surface : HandshakeChannelSurface)
    (frameIndex localRecvCounter : Nat) :
    PqNoise.ChannelState :=
  { role := surface.role
    sendCounter := frameIndex
    recvCounter := localRecvCounter }

def peerPqReceiveStateAt
    (surface : HandshakeChannelSurface)
    (frameIndex peerSendCounter : Nat) :
    PqNoise.ChannelState :=
  { role := peerRole surface.role
    sendCounter := peerSendCounter
    recvCounter := frameIndex }

theorem pq_send_slot_maps_to_secure_send
    {role : PqNoise.Role} :
    secureSlot (PqNoise.sendSlot role) =
      SecureChannel.sendSlot (secureRole role) := by
  cases role <;> rfl

theorem pq_recv_slot_maps_to_secure_recv
    {role : PqNoise.Role} :
    secureSlot (PqNoise.recvSlot role) =
      SecureChannel.recvSlot (secureRole role) := by
  cases role <;> rfl

theorem pq_send_recv_infos_distinct
    {role : PqNoise.Role} :
    PqNoise.expandInfo (PqNoise.sendSlot role) ≠
      PqNoise.expandInfo (PqNoise.recvSlot role) := by
  cases role
  · exact PqNoise.hkdf_infos_distinct
  · exact Ne.symm PqNoise.hkdf_infos_distinct

theorem pq_send_slot_matches_peer_recv
    {role : PqNoise.Role} :
    PqNoise.sendSlot role = PqNoise.recvSlot (peerRole role) := by
  cases role <;> rfl

theorem pq_recv_slot_matches_peer_send
    {role : PqNoise.Role} :
    PqNoise.recvSlot role = PqNoise.sendSlot (peerRole role) := by
  cases role <;> rfl

theorem peerRole_ne
    {role : PqNoise.Role} :
    peerRole role ≠ role := by
  cases role <;> decide

theorem roleIsInitiator_peer
    {role : PqNoise.Role} :
    roleIsInitiator (peerRole role) = !roleIsInitiator role := by
  cases role <;> rfl

theorem secure_send_recv_labels_distinct
    {role : SecureChannel.Role} :
    secureLabel (SecureChannel.sendSlot role) ≠
      secureLabel (SecureChannel.recvSlot role) := by
  cases role
  · exact SecureChannel.directional_labels_distinct
  · exact Ne.symm SecureChannel.directional_labels_distinct

structure EstablishedChannelFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (state : SecureChannel.ChannelState) : Prop where
  handshakeAccepted :
    AcceptedAuthenticatedPqHandshake surface crypto
  roleBound :
    state.role = secureRole surface.role
  sendCounterZero :
    state.sendCounter = 0
  recvCounterZero :
    state.recvCounter = 0
  pqSendSlotMapsToSecureSend :
    secureSlot (PqNoise.sendSlot surface.role) =
      SecureChannel.sendSlot state.role
  pqRecvSlotMapsToSecureRecv :
    secureSlot (PqNoise.recvSlot surface.role) =
      SecureChannel.recvSlot state.role
  pqDirectionalInfosDistinct :
    PqNoise.expandInfo (PqNoise.sendSlot surface.role) ≠
      PqNoise.expandInfo (PqNoise.recvSlot surface.role)
  channelDirectionalLabelsDistinct :
    secureLabel (SecureChannel.sendSlot state.role) ≠
      secureLabel (SecureChannel.recvSlot state.role)
  channelSlotsDistinct :
    SecureChannel.sendSlot state.role ≠ SecureChannel.recvSlot state.role
  pqSaltBoundToTranscript :
    PqNoise.hkdfSalt surface.pqSession = surface.pqSession.transcriptHash
  pqIkmOrdersKemSecrets :
    PqNoise.hkdfIkm surface.pqSession =
      surface.pqSession.shared1 ++ surface.pqSession.shared2
  initHelloPreimageHasDomain :
    ∃ rest,
      PqNoise.initHelloSigningPreimage surface.initHello =
        asciiBytes "init-hello" ++ rest
  respHelloPreimageHasDomain :
    ∃ rest,
      PqNoise.respHelloSigningPreimage surface.respHello =
        asciiBytes "resp-hello" ++ rest
  finishPreimageHasDomain :
    ∃ rest,
      PqNoise.finishSigningPreimage surface.finish =
        asciiBytes "finish" ++ rest
  secureI2RPreimageHasDomain :
    ∃ rest,
      SecureChannel.initiatorToResponderPreimage surface.channelSchedule =
        SecureChannel.networkKdfDomain ++ rest
  secureR2IPreimageHasDomain :
    ∃ rest,
      SecureChannel.responderToInitiatorPreimage surface.channelSchedule =
        SecureChannel.networkKdfDomain ++ rest

structure EstablishedPqChannelFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (state : PqNoise.ChannelState) : Prop where
  handshakeAccepted :
    AcceptedAuthenticatedPqHandshake surface crypto
  roleBound :
    state.role = surface.role
  sendCounterZero :
    state.sendCounter = 0
  recvCounterZero :
    state.recvCounter = 0
  sendRecvSlotsDistinct :
    PqNoise.sendSlot state.role ≠ PqNoise.recvSlot state.role
  sendRecvInfosDistinct :
    PqNoise.expandInfo (PqNoise.sendSlot state.role) ≠
      PqNoise.expandInfo (PqNoise.recvSlot state.role)
  aadDistinctFromSend :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.sendSlot state.role)
  aadDistinctFromRecv :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.recvSlot state.role)
  pqSaltBoundToTranscript :
    PqNoise.hkdfSalt surface.pqSession = surface.pqSession.transcriptHash
  pqIkmOrdersKemSecrets :
    PqNoise.hkdfIkm surface.pqSession =
      surface.pqSession.shared1 ++ surface.pqSession.shared2
  initHelloPreimageHasDomain :
    ∃ rest,
      PqNoise.initHelloSigningPreimage surface.initHello =
        asciiBytes "init-hello" ++ rest
  respHelloPreimageHasDomain :
    ∃ rest,
      PqNoise.respHelloSigningPreimage surface.respHello =
        asciiBytes "resp-hello" ++ rest
  finishPreimageHasDomain :
    ∃ rest,
      PqNoise.finishSigningPreimage surface.finish =
        asciiBytes "finish" ++ rest

theorem accepted_authenticated_pq_handshake_establishes_pq_channel_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto) :
    EstablishedPqChannelFacts
      surface
      crypto
      (pqChannelStateFromHandshake surface) := by
  refine
    { handshakeAccepted := handshake
      roleBound := ?_
      sendCounterZero := ?_
      recvCounterZero := ?_
      sendRecvSlotsDistinct := ?_
      sendRecvInfosDistinct := ?_
      aadDistinctFromSend := ?_
      aadDistinctFromRecv := ?_
      pqSaltBoundToTranscript := ?_
      pqIkmOrdersKemSecrets := ?_
      initHelloPreimageHasDomain := ?_
      respHelloPreimageHasDomain := ?_
      finishPreimageHasDomain := ?_ }
  · simp [pqChannelStateFromHandshake, PqNoise.initialState]
  · simp [pqChannelStateFromHandshake, PqNoise.initialState]
  · simp [pqChannelStateFromHandshake, PqNoise.initialState]
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      (PqNoise.send_recv_slots_distinct :
        PqNoise.sendSlot surface.role ≠ PqNoise.recvSlot surface.role)
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      (pq_send_recv_infos_distinct :
        PqNoise.expandInfo (PqNoise.sendSlot surface.role) ≠
          PqNoise.expandInfo (PqNoise.recvSlot surface.role))
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      (PqNoise.aad_info_distinct_from_send :
        PqNoise.sessionAadInfo ≠
          PqNoise.expandInfo (PqNoise.sendSlot surface.role))
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      (PqNoise.aad_info_distinct_from_recv :
        PqNoise.sessionAadInfo ≠
          PqNoise.expandInfo (PqNoise.recvSlot surface.role))
  · rfl
  · rfl
  · exact PqNoise.init_hello_preimage_starts_with_domain
  · exact PqNoise.resp_hello_preimage_starts_with_domain
  · exact PqNoise.finish_preimage_starts_with_domain

theorem accepted_authenticated_pq_handshake_secret_rng_transcript_kdf_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    (responderSeedUse :
      responderSeed.use =
        PqNoise.KemEncapsulationUse.responderEncapsulatesToInitiator)
    (initiatorSeedUse :
      initiatorSeed.use =
        PqNoise.KemEncapsulationUse.initiatorEncapsulatesToResponder)
    (responderSeedSource :
      responderSeed.source = PqNoise.KemSeedSource.osRng32)
    (initiatorSeedSource :
      initiatorSeed.source = PqNoise.KemSeedSource.osRng32)
    (responderSeedByteLength :
      responderSeed.seedByteLength = 32)
    (initiatorSeedByteLength :
      initiatorSeed.seedByteLength = 32)
    (responderSeedConsumed :
      responderSeed.consumedByMlKemEncapsulate)
    (initiatorSeedConsumed :
      initiatorSeed.consumedByMlKemEncapsulate)
    (respTranscriptBound :
      surface.respHello.transcriptHash = surface.pqSession.transcriptHash)
    (finishTranscriptBound :
      surface.finish.transcriptHash = surface.pqSession.transcriptHash) :
    AcceptedPqKemTranscriptKdfCertificate
      surface crypto responderSeed initiatorSeed := by
  refine
    { handshakeAccepted := handshake
      transcriptBound := handshake.transcriptBound
      kemSharedSecretsAgree := handshake.kemAgreed
      responderSeedUse := responderSeedUse
      initiatorSeedUse := initiatorSeedUse
      responderSeedSource := responderSeedSource
      initiatorSeedSource := initiatorSeedSource
      responderSeedByteLength := responderSeedByteLength
      initiatorSeedByteLength := initiatorSeedByteLength
      responderEncapsulationUsesResponderSeed :=
        responderSeedConsumed
      initiatorEncapsulationUsesInitiatorSeed :=
        initiatorSeedConsumed
      transcriptOnlyEntersSessionScheduleAsSalt := rfl
      kemSecretsEnterIkmInHandshakeOrder := rfl
      i2rR2iAndAadLabelsSeparated := ?_
      initSigningPreimageFields := rfl
      respSigningPreimageFields := rfl
      finishSigningPreimageFields := rfl
      respAndFinishBindTranscriptHash :=
        ⟨respTranscriptBound, finishTranscriptBound⟩ }
  exact
    ⟨PqNoise.hkdf_infos_distinct,
      PqNoise.aad_info_distinct_from_i2r,
      PqNoise.aad_info_distinct_from_r2i⟩

structure PqTransportCompletionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (localState peerState : PqNoise.ChannelState) : Prop where
  localEstablished :
    EstablishedPqChannelFacts surface crypto localState
  peerRoleBound :
    peerState.role = peerRole surface.role
  peerSendCounterZero :
    peerState.sendCounter = 0
  peerRecvCounterZero :
    peerState.recvCounter = 0
  localSendSlotMatchesPeerRecv :
    PqNoise.sendSlot localState.role = PqNoise.recvSlot peerState.role
  localRecvSlotMatchesPeerSend :
    PqNoise.recvSlot localState.role = PqNoise.sendSlot peerState.role
  localSendInfoMatchesPeerRecvInfo :
    PqNoise.expandInfo (PqNoise.sendSlot localState.role) =
      PqNoise.expandInfo (PqNoise.recvSlot peerState.role)
  localRecvInfoMatchesPeerSendInfo :
    PqNoise.expandInfo (PqNoise.recvSlot localState.role) =
      PqNoise.expandInfo (PqNoise.sendSlot peerState.role)
  localSessionAadDistinctFromSend :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.sendSlot localState.role)
  localSessionAadDistinctFromRecv :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.recvSlot localState.role)
  peerSessionAadDistinctFromSend :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.sendSlot peerState.role)
  peerSessionAadDistinctFromRecv :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.recvSlot peerState.role)

theorem accepted_authenticated_pq_handshake_transport_completion_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto) :
    PqTransportCompletionFacts
      surface
      crypto
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface) := by
  refine
    { localEstablished :=
        accepted_authenticated_pq_handshake_establishes_pq_channel_facts handshake
      peerRoleBound := ?_
      peerSendCounterZero := ?_
      peerRecvCounterZero := ?_
      localSendSlotMatchesPeerRecv := ?_
      localRecvSlotMatchesPeerSend := ?_
      localSendInfoMatchesPeerRecvInfo := ?_
      localRecvInfoMatchesPeerSendInfo := ?_
      localSessionAadDistinctFromSend := ?_
      localSessionAadDistinctFromRecv := ?_
      peerSessionAadDistinctFromSend := ?_
      peerSessionAadDistinctFromRecv := ?_ }
  · simp [peerPqChannelStateFromHandshake, PqNoise.initialState]
  · simp [peerPqChannelStateFromHandshake, PqNoise.initialState]
  · simp [peerPqChannelStateFromHandshake, PqNoise.initialState]
  · simpa [pqChannelStateFromHandshake, peerPqChannelStateFromHandshake,
      PqNoise.initialState] using
      (pq_send_slot_matches_peer_recv (role := surface.role))
  · simpa [pqChannelStateFromHandshake, peerPqChannelStateFromHandshake,
      PqNoise.initialState] using
      (pq_recv_slot_matches_peer_send (role := surface.role))
  · simpa [pqChannelStateFromHandshake, peerPqChannelStateFromHandshake,
      PqNoise.initialState] using
      congrArg PqNoise.expandInfo
        (pq_send_slot_matches_peer_recv (role := surface.role))
  · simpa [pqChannelStateFromHandshake, peerPqChannelStateFromHandshake,
      PqNoise.initialState] using
      congrArg PqNoise.expandInfo
        (pq_recv_slot_matches_peer_send (role := surface.role))
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      (PqNoise.aad_info_distinct_from_send (role := surface.role))
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      (PqNoise.aad_info_distinct_from_recv (role := surface.role))
  · simpa [peerPqChannelStateFromHandshake, PqNoise.initialState] using
      (PqNoise.aad_info_distinct_from_send (role := peerRole surface.role))
  · simpa [peerPqChannelStateFromHandshake, PqNoise.initialState] using
      (PqNoise.aad_info_distinct_from_recv (role := peerRole surface.role))

structure PqWrapperCompletionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (localState peerState : PqNoise.ChannelState)
    (localBytesSent localBytesReceived peerBytesSent peerBytesReceived : Nat)
    (firstFramePayloadBytes firstFrameTagBytes firstFrameWireBytes : Nat) : Prop where
  transportCompletion :
    PqTransportCompletionFacts surface crypto localState peerState
  localRoleIsSurfaceRole :
    localState.role = surface.role
  peerRoleIsOpposite :
    peerState.role = peerRole surface.role
  localIsInitiatorBound :
    roleIsInitiator localState.role = roleIsInitiator surface.role
  peerIsInitiatorBound :
    roleIsInitiator peerState.role = roleIsInitiator (peerRole surface.role)
  peerInitiatorOpposite :
    roleIsInitiator peerState.role = !roleIsInitiator localState.role
  rolesDistinct :
    localState.role ≠ peerState.role
  localBytesSentZero :
    localBytesSent = 0
  localBytesReceivedZero :
    localBytesReceived = 0
  peerBytesSentZero :
    peerBytesSent = 0
  peerBytesReceivedZero :
    peerBytesReceived = 0
  firstFrameTagBytesBound :
    firstFrameTagBytes = pqAeadTagBytes
  firstFrameWireBytesBound :
    firstFrameWireBytes = firstFramePayloadBytes + firstFrameTagBytes

theorem accepted_authenticated_pq_handshake_wrapper_completion_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    (firstFramePayloadBytes : Nat) :
    PqWrapperCompletionFacts
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
      (firstFramePayloadBytes + pqAeadTagBytes) := by
  refine
    { transportCompletion :=
        accepted_authenticated_pq_handshake_transport_completion_facts handshake
      localRoleIsSurfaceRole := ?_
      peerRoleIsOpposite := ?_
      localIsInitiatorBound := ?_
      peerIsInitiatorBound := ?_
      peerInitiatorOpposite := ?_
      rolesDistinct := ?_
      localBytesSentZero := ?_
      localBytesReceivedZero := ?_
      peerBytesSentZero := ?_
      peerBytesReceivedZero := ?_
      firstFrameTagBytesBound := ?_
      firstFrameWireBytesBound := ?_ }
  · simp [pqChannelStateFromHandshake, PqNoise.initialState]
  · simp [peerPqChannelStateFromHandshake, PqNoise.initialState]
  · simp [pqChannelStateFromHandshake, PqNoise.initialState]
  · simp [peerPqChannelStateFromHandshake, PqNoise.initialState]
  · simpa [pqChannelStateFromHandshake, peerPqChannelStateFromHandshake,
      PqNoise.initialState] using
      (roleIsInitiator_peer (role := surface.role))
  · simpa [pqChannelStateFromHandshake, peerPqChannelStateFromHandshake,
      PqNoise.initialState] using
      (Ne.symm (peerRole_ne (role := surface.role)))
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl
  · rfl

theorem accepted_authenticated_pq_handshake_establishes_channel_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto) :
    EstablishedChannelFacts
      surface
      crypto
      (channelStateFromHandshake surface) := by
  refine
    { handshakeAccepted := handshake
      roleBound := ?_
      sendCounterZero := ?_
      recvCounterZero := ?_
      pqSendSlotMapsToSecureSend := ?_
      pqRecvSlotMapsToSecureRecv := ?_
      pqDirectionalInfosDistinct := pq_send_recv_infos_distinct
      channelDirectionalLabelsDistinct := ?_
      channelSlotsDistinct := ?_
      pqSaltBoundToTranscript := ?_
      pqIkmOrdersKemSecrets := ?_
      initHelloPreimageHasDomain := ?_
      respHelloPreimageHasDomain := ?_
      finishPreimageHasDomain := ?_
      secureI2RPreimageHasDomain := ?_
      secureR2IPreimageHasDomain := ?_ }
  · simp [channelStateFromHandshake, SecureChannel.initialState]
  · simp [channelStateFromHandshake, SecureChannel.initialState]
  · simp [channelStateFromHandshake, SecureChannel.initialState]
  · simp [channelStateFromHandshake, SecureChannel.initialState,
      pq_send_slot_maps_to_secure_send]
  · simp [channelStateFromHandshake, SecureChannel.initialState,
      pq_recv_slot_maps_to_secure_recv]
  · simpa [channelStateFromHandshake, SecureChannel.initialState] using
      (secure_send_recv_labels_distinct :
        secureLabel (SecureChannel.sendSlot (secureRole surface.role)) ≠
          secureLabel (SecureChannel.recvSlot (secureRole surface.role)))
  · simpa [channelStateFromHandshake, SecureChannel.initialState] using
      (SecureChannel.send_recv_slots_distinct :
        SecureChannel.sendSlot (secureRole surface.role) ≠
          SecureChannel.recvSlot (secureRole surface.role))
  · rfl
  · rfl
  · exact PqNoise.init_hello_preimage_starts_with_domain
  · exact PqNoise.resp_hello_preimage_starts_with_domain
  · exact PqNoise.finish_preimage_starts_with_domain
  · exact SecureChannel.key_preimage_starts_with_domain
  · exact SecureChannel.key_preimage_starts_with_domain

structure InitialProtectOpenTransitionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (protectedSlot : SecureChannel.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : SecureChannel.ChannelState)
    (openedSlot : SecureChannel.KeySlot)
    (openedNonce : List Byte)
    (openedNext : SecureChannel.ChannelState) : Prop where
  established :
    EstablishedChannelFacts surface crypto (channelStateFromHandshake surface)
  protectSlotIsSend :
    protectedSlot = SecureChannel.sendSlot (secureRole surface.role)
  protectSlotNotRecv :
    protectedSlot ≠ SecureChannel.recvSlot (secureRole surface.role)
  protectNonceZero :
    protectedNonce = SecureChannel.nonceFromCounter 0
  protectNextRole :
    protectedNext.role = secureRole surface.role
  protectNextSendCounter :
    protectedNext.sendCounter = 1
  protectNextRecvCounter :
    protectedNext.recvCounter = 0
  openSlotIsRecv :
    openedSlot = SecureChannel.recvSlot (secureRole surface.role)
  openSlotNotSend :
    openedSlot ≠ SecureChannel.sendSlot (secureRole surface.role)
  openNonceZero :
    openedNonce = SecureChannel.nonceFromCounter 0
  openNextRole :
    openedNext.role = secureRole surface.role
  openNextSendCounter :
    openedNext.sendCounter = 0
  openNextRecvCounter :
    openedNext.recvCounter = 1
  protectOpenSlotsDistinct :
    protectedSlot ≠ openedSlot

structure InitialPqProtectOpenTransitionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (openedSlot : PqNoise.KeySlot)
    (openedNonce : List Byte)
    (openedNext : PqNoise.ChannelState) : Prop where
  established :
    EstablishedPqChannelFacts surface crypto (pqChannelStateFromHandshake surface)
  protectSlotIsSend :
    protectedSlot = PqNoise.sendSlot surface.role
  protectSlotNotRecv :
    protectedSlot ≠ PqNoise.recvSlot surface.role
  protectAadDistinct :
    PqNoise.sessionAadInfo ≠ PqNoise.expandInfo protectedSlot
  protectNonceZero :
    protectedNonce = PqNoise.nonceFromCounter 0
  protectNextRole :
    protectedNext.role = surface.role
  protectNextSendCounter :
    protectedNext.sendCounter = 1
  protectNextRecvCounter :
    protectedNext.recvCounter = 0
  openSlotIsRecv :
    openedSlot = PqNoise.recvSlot surface.role
  openSlotNotSend :
    openedSlot ≠ PqNoise.sendSlot surface.role
  openAadDistinct :
    PqNoise.sessionAadInfo ≠ PqNoise.expandInfo openedSlot
  openNonceZero :
    openedNonce = PqNoise.nonceFromCounter 0
  openNextRole :
    openedNext.role = surface.role
  openNextSendCounter :
    openedNext.sendCounter = 0
  openNextRecvCounter :
    openedNext.recvCounter = 1
  protectOpenSlotsDistinct :
    protectedSlot ≠ openedSlot

structure InitialPqPeerFrameAdmissionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (peerOpenedSlot : PqNoise.KeySlot)
    (peerOpenedNonce : List Byte)
    (peerOpenedNext : PqNoise.ChannelState) : Prop where
  established :
    EstablishedPqChannelFacts surface crypto (pqChannelStateFromHandshake surface)
  localProtectSlotIsSend :
    protectedSlot = PqNoise.sendSlot surface.role
  localProtectSlotNotRecv :
    protectedSlot ≠ PqNoise.recvSlot surface.role
  peerOpenSlotIsRecv :
    peerOpenedSlot = PqNoise.recvSlot (peerRole surface.role)
  peerOpenSlotNotSend :
    peerOpenedSlot ≠ PqNoise.sendSlot (peerRole surface.role)
  protectedSlotAdmittedByPeer :
    protectedSlot = peerOpenedSlot
  protectedNonceAdmittedByPeer :
    protectedNonce = peerOpenedNonce
  frameAadDistinctFromDirectionalKeyInfo :
    PqNoise.sessionAadInfo ≠ PqNoise.expandInfo protectedSlot
  protectedNonceZero :
    protectedNonce = PqNoise.nonceFromCounter 0
  peerOpenedNonceZero :
    peerOpenedNonce = PqNoise.nonceFromCounter 0
  protectedNextRole :
    protectedNext.role = surface.role
  protectedNextSendCounter :
    protectedNext.sendCounter = 1
  protectedNextRecvCounter :
    protectedNext.recvCounter = 0
  peerOpenedNextRole :
    peerOpenedNext.role = peerRole surface.role
  peerOpenedNextSendCounter :
    peerOpenedNext.sendCounter = 0
  peerOpenedNextRecvCounter :
    peerOpenedNext.recvCounter = 1

structure IndexedPqPeerFrameAdmissionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (frameIndex localRecvCounter peerSendCounter : Nat)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (peerOpenedSlot : PqNoise.KeySlot)
    (peerOpenedNonce : List Byte)
    (peerOpenedNext : PqNoise.ChannelState) : Prop where
  established :
    EstablishedPqChannelFacts surface crypto (pqChannelStateFromHandshake surface)
  frameIndexBelowMax :
    frameIndex < PqNoise.u64Max
  localProtectAccepted :
    PqNoise.protectFrame
      (localPqSendStateAt surface frameIndex localRecvCounter) =
        some (protectedSlot, protectedNonce, protectedNext)
  peerOpenAccepted :
    PqNoise.openFrame
      (peerPqReceiveStateAt surface frameIndex peerSendCounter) =
        some (peerOpenedSlot, peerOpenedNonce, peerOpenedNext)
  localProtectSlotIsSend :
    protectedSlot = PqNoise.sendSlot surface.role
  localProtectSlotNotRecv :
    protectedSlot ≠ PqNoise.recvSlot surface.role
  peerOpenSlotIsRecv :
    peerOpenedSlot = PqNoise.recvSlot (peerRole surface.role)
  peerOpenSlotNotSend :
    peerOpenedSlot ≠ PqNoise.sendSlot (peerRole surface.role)
  protectedSlotAdmittedByPeer :
    protectedSlot = peerOpenedSlot
  protectedInfoAdmittedByPeer :
    PqNoise.expandInfo protectedSlot = PqNoise.expandInfo peerOpenedSlot
  protectedNonceAtFrameIndex :
    protectedNonce = PqNoise.nonceFromCounter frameIndex
  peerOpenedNonceAtFrameIndex :
    peerOpenedNonce = PqNoise.nonceFromCounter frameIndex
  protectedNonceAdmittedByPeer :
    protectedNonce = peerOpenedNonce
  frameAadDistinctFromDirectionalKeyInfo :
    PqNoise.sessionAadInfo ≠ PqNoise.expandInfo protectedSlot
  protectedNextRole :
    protectedNext.role = surface.role
  protectedNextSendCounter :
    protectedNext.sendCounter = frameIndex + 1
  protectedNextRecvCounterCarried :
    protectedNext.recvCounter = localRecvCounter
  peerOpenedNextRole :
    peerOpenedNext.role = peerRole surface.role
  peerOpenedNextSendCounterCarried :
    peerOpenedNext.sendCounter = peerSendCounter
  peerOpenedNextRecvCounter :
    peerOpenedNext.recvCounter = frameIndex + 1

theorem accepted_authenticated_pq_handshake_initial_pq_protect_open_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    {protectedSlot : PqNoise.KeySlot}
    {protectedNonce : List Byte}
    {protectedNext : PqNoise.ChannelState}
    {openedSlot : PqNoise.KeySlot}
    {openedNonce : List Byte}
    {openedNext : PqNoise.ChannelState}
    (protectAccepted :
      PqNoise.protectFrame (pqChannelStateFromHandshake surface) =
        some (protectedSlot, protectedNonce, protectedNext))
    (openAccepted :
      PqNoise.openFrame (pqChannelStateFromHandshake surface) =
        some (openedSlot, openedNonce, openedNext)) :
    InitialPqProtectOpenTransitionFacts
      surface
      crypto
      protectedSlot
      protectedNonce
      protectedNext
      openedSlot
      openedNonce
      openedNext := by
  rcases PqNoise.protectFrame_direction_and_counter protectAccepted with
    ⟨hProtectSlot,
      hProtectNotRecv,
      hProtectNonce,
      hProtectRole,
      hProtectSend,
      hProtectRecv⟩
  rcases PqNoise.openFrame_direction_and_counter openAccepted with
    ⟨hOpenSlot,
      hOpenNotSend,
      hOpenNonce,
      hOpenRole,
      hOpenSend,
      hOpenRecv⟩
  refine
    { established :=
        accepted_authenticated_pq_handshake_establishes_pq_channel_facts handshake
      protectSlotIsSend := ?_
      protectSlotNotRecv := ?_
      protectAadDistinct := ?_
      protectNonceZero := ?_
      protectNextRole := ?_
      protectNextSendCounter := ?_
      protectNextRecvCounter := ?_
      openSlotIsRecv := ?_
      openSlotNotSend := ?_
      openAadDistinct := ?_
      openNonceZero := ?_
      openNextRole := ?_
      openNextSendCounter := ?_
      openNextRecvCounter := ?_
      protectOpenSlotsDistinct := ?_ }
  · simpa [pqChannelStateFromHandshake] using hProtectSlot
  · simpa [pqChannelStateFromHandshake] using hProtectNotRecv
  · rw [hProtectSlot]
    exact PqNoise.aad_info_distinct_from_send
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hProtectNonce
  · simpa [pqChannelStateFromHandshake] using hProtectRole
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hProtectSend
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hProtectRecv
  · simpa [pqChannelStateFromHandshake] using hOpenSlot
  · simpa [pqChannelStateFromHandshake] using hOpenNotSend
  · rw [hOpenSlot]
    exact PqNoise.aad_info_distinct_from_recv
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hOpenNonce
  · simpa [pqChannelStateFromHandshake] using hOpenRole
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hOpenSend
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hOpenRecv
  · intro sameSlot
    have protectedIsRecv :
        protectedSlot = PqNoise.recvSlot surface.role := by
      rw [sameSlot]
      simpa [pqChannelStateFromHandshake] using hOpenSlot
    have protectedNotRecv :
        protectedSlot ≠ PqNoise.recvSlot surface.role := by
      simpa [pqChannelStateFromHandshake] using hProtectNotRecv
    exact protectedNotRecv protectedIsRecv

theorem accepted_authenticated_pq_handshake_initial_pq_peer_frame_admission_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    {protectedSlot : PqNoise.KeySlot}
    {protectedNonce : List Byte}
    {protectedNext : PqNoise.ChannelState}
    {peerOpenedSlot : PqNoise.KeySlot}
    {peerOpenedNonce : List Byte}
    {peerOpenedNext : PqNoise.ChannelState}
    (protectAccepted :
      PqNoise.protectFrame (pqChannelStateFromHandshake surface) =
        some (protectedSlot, protectedNonce, protectedNext))
    (peerOpenAccepted :
      PqNoise.openFrame (peerPqChannelStateFromHandshake surface) =
        some (peerOpenedSlot, peerOpenedNonce, peerOpenedNext)) :
    InitialPqPeerFrameAdmissionFacts
      surface
      crypto
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext := by
  rcases PqNoise.protectFrame_direction_and_counter protectAccepted with
    ⟨hProtectSlot,
      hProtectNotRecv,
      hProtectNonce,
      hProtectRole,
      hProtectSend,
      hProtectRecv⟩
  rcases PqNoise.openFrame_direction_and_counter peerOpenAccepted with
    ⟨hPeerOpenSlot,
      hPeerOpenNotSend,
      hPeerOpenNonce,
      hPeerOpenRole,
      hPeerOpenSend,
      hPeerOpenRecv⟩
  have hProtectedSlotSend :
      protectedSlot = PqNoise.sendSlot surface.role := by
    simpa [pqChannelStateFromHandshake] using hProtectSlot
  have hPeerOpenedSlotRecv :
      peerOpenedSlot = PqNoise.recvSlot (peerRole surface.role) := by
    simpa [peerPqChannelStateFromHandshake] using hPeerOpenSlot
  have hProtectedNonceZero :
      protectedNonce = PqNoise.nonceFromCounter 0 := by
    simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hProtectNonce
  have hPeerOpenedNonceZero :
      peerOpenedNonce = PqNoise.nonceFromCounter 0 := by
    simpa [peerPqChannelStateFromHandshake, PqNoise.initialState] using
      hPeerOpenNonce
  refine
    { established :=
        accepted_authenticated_pq_handshake_establishes_pq_channel_facts handshake
      localProtectSlotIsSend := hProtectedSlotSend
      localProtectSlotNotRecv := ?_
      peerOpenSlotIsRecv := hPeerOpenedSlotRecv
      peerOpenSlotNotSend := ?_
      protectedSlotAdmittedByPeer := ?_
      protectedNonceAdmittedByPeer := ?_
      frameAadDistinctFromDirectionalKeyInfo := ?_
      protectedNonceZero := hProtectedNonceZero
      peerOpenedNonceZero := hPeerOpenedNonceZero
      protectedNextRole := ?_
      protectedNextSendCounter := ?_
      protectedNextRecvCounter := ?_
      peerOpenedNextRole := ?_
      peerOpenedNextSendCounter := ?_
      peerOpenedNextRecvCounter := ?_ }
  · simpa [pqChannelStateFromHandshake] using hProtectNotRecv
  · simpa [peerPqChannelStateFromHandshake] using hPeerOpenNotSend
  · calc
      protectedSlot = PqNoise.sendSlot surface.role := hProtectedSlotSend
      _ = PqNoise.recvSlot (peerRole surface.role) :=
        pq_send_slot_matches_peer_recv
      _ = peerOpenedSlot := hPeerOpenedSlotRecv.symm
  · exact hProtectedNonceZero.trans hPeerOpenedNonceZero.symm
  · rw [hProtectedSlotSend]
    exact PqNoise.aad_info_distinct_from_send
  · simpa [pqChannelStateFromHandshake] using hProtectRole
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hProtectSend
  · simpa [pqChannelStateFromHandshake, PqNoise.initialState] using
      hProtectRecv
  · simpa [peerPqChannelStateFromHandshake] using hPeerOpenRole
  · simpa [peerPqChannelStateFromHandshake, PqNoise.initialState] using
      hPeerOpenSend
  · simpa [peerPqChannelStateFromHandshake, PqNoise.initialState] using
      hPeerOpenRecv

theorem accepted_authenticated_pq_handshake_indexed_pq_peer_frame_admission_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    {frameIndex localRecvCounter peerSendCounter : Nat}
    (frameIndexBelowMax : frameIndex < PqNoise.u64Max)
    {protectedSlot : PqNoise.KeySlot}
    {protectedNonce : List Byte}
    {protectedNext : PqNoise.ChannelState}
    {peerOpenedSlot : PqNoise.KeySlot}
    {peerOpenedNonce : List Byte}
    {peerOpenedNext : PqNoise.ChannelState}
    (protectAccepted :
      PqNoise.protectFrame
        (localPqSendStateAt surface frameIndex localRecvCounter) =
          some (protectedSlot, protectedNonce, protectedNext))
    (peerOpenAccepted :
      PqNoise.openFrame
        (peerPqReceiveStateAt surface frameIndex peerSendCounter) =
          some (peerOpenedSlot, peerOpenedNonce, peerOpenedNext)) :
    IndexedPqPeerFrameAdmissionFacts
      surface
      crypto
      frameIndex
      localRecvCounter
      peerSendCounter
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext := by
  rcases PqNoise.protectFrame_direction_and_counter protectAccepted with
    ⟨hProtectSlot,
      hProtectNotRecv,
      hProtectNonce,
      hProtectRole,
      hProtectSend,
      hProtectRecv⟩
  rcases PqNoise.openFrame_direction_and_counter peerOpenAccepted with
    ⟨hPeerOpenSlot,
      hPeerOpenNotSend,
      hPeerOpenNonce,
      hPeerOpenRole,
      hPeerOpenSend,
      hPeerOpenRecv⟩
  have hProtectedSlotSend :
      protectedSlot = PqNoise.sendSlot surface.role := by
    simpa [localPqSendStateAt] using hProtectSlot
  have hPeerOpenedSlotRecv :
      peerOpenedSlot = PqNoise.recvSlot (peerRole surface.role) := by
    simpa [peerPqReceiveStateAt] using hPeerOpenSlot
  have hProtectedNonceAtFrameIndex :
      protectedNonce = PqNoise.nonceFromCounter frameIndex := by
    simpa [localPqSendStateAt] using hProtectNonce
  have hPeerOpenedNonceAtFrameIndex :
      peerOpenedNonce = PqNoise.nonceFromCounter frameIndex := by
    simpa [peerPqReceiveStateAt] using hPeerOpenNonce
  have hProtectedSlotAdmittedByPeer :
      protectedSlot = peerOpenedSlot := by
    calc
      protectedSlot = PqNoise.sendSlot surface.role := hProtectedSlotSend
      _ = PqNoise.recvSlot (peerRole surface.role) :=
        pq_send_slot_matches_peer_recv
      _ = peerOpenedSlot := hPeerOpenedSlotRecv.symm
  refine
    { established :=
        accepted_authenticated_pq_handshake_establishes_pq_channel_facts handshake
      frameIndexBelowMax := frameIndexBelowMax
      localProtectAccepted := protectAccepted
      peerOpenAccepted := peerOpenAccepted
      localProtectSlotIsSend := hProtectedSlotSend
      localProtectSlotNotRecv := ?_
      peerOpenSlotIsRecv := hPeerOpenedSlotRecv
      peerOpenSlotNotSend := ?_
      protectedSlotAdmittedByPeer := hProtectedSlotAdmittedByPeer
      protectedInfoAdmittedByPeer := ?_
      protectedNonceAtFrameIndex := hProtectedNonceAtFrameIndex
      peerOpenedNonceAtFrameIndex := hPeerOpenedNonceAtFrameIndex
      protectedNonceAdmittedByPeer :=
        hProtectedNonceAtFrameIndex.trans hPeerOpenedNonceAtFrameIndex.symm
      frameAadDistinctFromDirectionalKeyInfo := ?_
      protectedNextRole := ?_
      protectedNextSendCounter := ?_
      protectedNextRecvCounterCarried := ?_
      peerOpenedNextRole := ?_
      peerOpenedNextSendCounterCarried := ?_
      peerOpenedNextRecvCounter := ?_ }
  · simpa [localPqSendStateAt] using hProtectNotRecv
  · simpa [peerPqReceiveStateAt] using hPeerOpenNotSend
  · rw [hProtectedSlotAdmittedByPeer]
  · rw [hProtectedSlotSend]
    exact PqNoise.aad_info_distinct_from_send
  · simpa [localPqSendStateAt] using hProtectRole
  · simpa [localPqSendStateAt] using hProtectSend
  · simpa [localPqSendStateAt] using hProtectRecv
  · simpa [peerPqReceiveStateAt] using hPeerOpenRole
  · simpa [peerPqReceiveStateAt] using hPeerOpenSend
  · simpa [peerPqReceiveStateAt] using hPeerOpenRecv

theorem accepted_authenticated_pq_handshake_bounded_pq_peer_frame_sequence_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    {sequenceLength frameIndex localRecvCounter peerSendCounter : Nat}
    (frameInSequence : frameIndex < sequenceLength)
    (sequenceBound : sequenceLength ≤ PqNoise.u64Max) :
    IndexedPqPeerFrameAdmissionFacts
      surface
      crypto
      frameIndex
      localRecvCounter
      peerSendCounter
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)
      ({ localPqSendStateAt surface frameIndex localRecvCounter with
          sendCounter := frameIndex + 1 })
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter frameIndex)
      ({ peerPqReceiveStateAt surface frameIndex peerSendCounter with
          recvCounter := frameIndex + 1 }) := by
  have frameIndexBelowMax : frameIndex < PqNoise.u64Max :=
    Nat.lt_of_lt_of_le frameInSequence sequenceBound
  have localSendCounterBelowMax :
      (localPqSendStateAt surface frameIndex localRecvCounter).sendCounter <
        PqNoise.u64Max := by
    simpa [localPqSendStateAt] using frameIndexBelowMax
  have peerRecvCounterBelowMax :
      (peerPqReceiveStateAt surface frameIndex peerSendCounter).recvCounter <
        PqNoise.u64Max := by
    simpa [peerPqReceiveStateAt] using frameIndexBelowMax
  apply
    accepted_authenticated_pq_handshake_indexed_pq_peer_frame_admission_facts
      handshake
      frameIndexBelowMax
  · simpa [localPqSendStateAt] using
      (PqNoise.protectFrame_accepts_below_max
        (state := localPqSendStateAt surface frameIndex localRecvCounter)
        localSendCounterBelowMax)
  · simpa [peerPqReceiveStateAt] using
      (PqNoise.openFrame_accepts_below_max
        (state := peerPqReceiveStateAt surface frameIndex peerSendCounter)
        peerRecvCounterBelowMax)

structure PqProductionChannelSafetyCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts)
    (localState peerState : PqNoise.ChannelState)
    (sequenceLength frameIndex localRecvCounter peerSendCounter : Nat)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (peerOpenedSlot : PqNoise.KeySlot)
    (peerOpenedNonce : List Byte)
    (peerOpenedNext : PqNoise.ChannelState) : Prop where
  kemTranscriptKdf :
    AcceptedPqKemTranscriptKdfCertificate
      surface crypto responderSeed initiatorSeed
  transportCompletion :
    PqTransportCompletionFacts surface crypto localState peerState
  indexedFrameAdmission :
    IndexedPqPeerFrameAdmissionFacts
      surface
      crypto
      frameIndex
      localRecvCounter
      peerSendCounter
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext
  sequenceAdmitsFrame :
    frameIndex < sequenceLength
  sequenceWithinCounterDomain :
    sequenceLength ≤ PqNoise.u64Max
  transcriptBindsHandshake :
    crypto.transcriptBindsHandshakeMessages
  kemSharedSecretsAgree :
    crypto.mlkemSharedSecretsAgree
  hkdfExtractExpandSound :
    crypto.hkdfExtractExpandSound
  aeadProtectOpenSound :
    crypto.aeadProtectOpenSound
  responderSeedOsRng :
    responderSeed.source = PqNoise.KemSeedSource.osRng32
  initiatorSeedOsRng :
    initiatorSeed.source = PqNoise.KemSeedSource.osRng32
  responderSeedNotPublicTranscriptDerived :
    responderSeed.source ≠ PqNoise.KemSeedSource.publicTranscriptDerived
  initiatorSeedNotPublicTranscriptDerived :
    initiatorSeed.source ≠ PqNoise.KemSeedSource.publicTranscriptDerived
  responderSeedNotFixedDeterministic :
    responderSeed.source ≠ PqNoise.KemSeedSource.fixedDeterministic
  initiatorSeedNotFixedDeterministic :
    initiatorSeed.source ≠ PqNoise.KemSeedSource.fixedDeterministic
  responderSeedNotCallerProvidedTest :
    responderSeed.source ≠ PqNoise.KemSeedSource.callerProvidedTest
  initiatorSeedNotCallerProvidedTest :
    initiatorSeed.source ≠ PqNoise.KemSeedSource.callerProvidedTest
  responderEncapsulationConsumesOsRngSeed :
    responderSeed.consumedByMlKemEncapsulate
  initiatorEncapsulationConsumesOsRngSeed :
    initiatorSeed.consumedByMlKemEncapsulate
  publicTranscriptOnlyEntersSessionScheduleAsSalt :
    PqNoise.hkdfSalt surface.pqSession = surface.pqSession.transcriptHash
  kemSharedSecretsOnlyEnterHkdfIkmInHandshakeOrder :
    PqNoise.hkdfIkm surface.pqSession =
      surface.pqSession.shared1 ++ surface.pqSession.shared2
  responseAndFinishSignaturesBindTranscript :
    surface.respHello.transcriptHash = surface.pqSession.transcriptHash
      ∧ surface.finish.transcriptHash = surface.pqSession.transcriptHash
  i2rR2iAndAadInfosSeparated :
    PqNoise.initiatorToResponderInfo ≠ PqNoise.responderToInitiatorInfo
      ∧ PqNoise.sessionAadInfo ≠ PqNoise.initiatorToResponderInfo
      ∧ PqNoise.sessionAadInfo ≠ PqNoise.responderToInitiatorInfo
  localSendRecvSlotsDistinct :
    PqNoise.sendSlot localState.role ≠ PqNoise.recvSlot localState.role
  localSendRecvInfosDistinct :
    PqNoise.expandInfo (PqNoise.sendSlot localState.role) ≠
      PqNoise.expandInfo (PqNoise.recvSlot localState.role)
  localSessionAadDistinctFromSend :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.sendSlot localState.role)
  localSessionAadDistinctFromRecv :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.recvSlot localState.role)
  peerSessionAadDistinctFromSend :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.sendSlot peerState.role)
  peerSessionAadDistinctFromRecv :
    PqNoise.sessionAadInfo ≠
      PqNoise.expandInfo (PqNoise.recvSlot peerState.role)
  localSendSlotAdmittedByPeerRecv :
    protectedSlot = peerOpenedSlot
  localSendInfoAdmittedByPeerRecv :
    PqNoise.expandInfo protectedSlot = PqNoise.expandInfo peerOpenedSlot
  frameAadDistinctFromDirectionalKeyInfo :
    PqNoise.sessionAadInfo ≠ PqNoise.expandInfo protectedSlot
  protectedNonceAtFrameIndex :
    protectedNonce = PqNoise.nonceFromCounter frameIndex
  peerOpenedNonceAtFrameIndex :
    peerOpenedNonce = PqNoise.nonceFromCounter frameIndex
  protectedNonceAdmittedByPeer :
    protectedNonce = peerOpenedNonce
  protectedNextSendCounter :
    protectedNext.sendCounter = frameIndex + 1
  protectedNextRecvCounterCarried :
    protectedNext.recvCounter = localRecvCounter
  peerOpenedNextSendCounterCarried :
    peerOpenedNext.sendCounter = peerSendCounter
  peerOpenedNextRecvCounter :
    peerOpenedNext.recvCounter = frameIndex + 1

structure PqFailedOpenReplayAdmissionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (sendCounter : Nat) : Prop where
  handshakeAccepted :
    AcceptedAuthenticatedPqHandshake surface crypto
  duplicateFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 1 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 0)).accepted = false
  duplicateRejectPreservesState :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 1 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 0)).next =
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 1 }
  nextFrameAfterDuplicateAccepted :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 1 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).accepted = true
  nextFrameAfterDuplicateAdvancesRecvCounter :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 1 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).next.recvCounter = 2
  futureFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 0 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).accepted = false
  futureRejectPreservesState :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 0 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).next =
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 0 }
  currentFrameAfterFutureRejectedAccepted :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 0 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 0)).accepted = true
  currentFrameAfterFutureRejectedAdvancesRecvCounter :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 0 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 0)).next.recvCounter = 1

theorem accepted_authenticated_pq_handshake_failed_open_replay_admission_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    (sendCounter : Nat) :
    PqFailedOpenReplayAdmissionFacts surface crypto sendCounter := by
  refine
    { handshakeAccepted := handshake
      duplicateFrameRejected := ?_
      duplicateRejectPreservesState := ?_
      nextFrameAfterDuplicateAccepted := ?_
      nextFrameAfterDuplicateAdvancesRecvCounter := ?_
      futureFrameRejected := ?_
      futureRejectPreservesState := ?_
      currentFrameAfterFutureRejectedAccepted := ?_
      currentFrameAfterFutureRejectedAdvancesRecvCounter := ?_ }
  · rw [PqNoise.openFrameWithObservedWire_rejects_stale_duplicate_after_first]
    rfl
  · rw [PqNoise.openFrameWithObservedWire_rejects_stale_duplicate_after_first]
    rfl
  · rw [PqNoise.openFrameWithObservedWire_next_frame_after_duplicate_rejects_accepts]
  · rw [PqNoise.openFrameWithObservedWire_next_frame_after_duplicate_rejects_accepts]
  · rw [PqNoise.openFrameWithObservedWire_rejects_future_gap_before_first]
    rfl
  · rw [PqNoise.openFrameWithObservedWire_rejects_future_gap_before_first]
    rfl
  · rw [PqNoise.openFrameWithObservedWire_current_frame_after_future_rejects_accepts]
  · rw [PqNoise.openFrameWithObservedWire_current_frame_after_future_rejects_accepts]

structure PqSameRoleMisbindAdmissionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (sendCounter recvCounter : Nat) : Prop where
  handshakeAccepted :
    AcceptedAuthenticatedPqHandshake surface crypto
  sameRoleSendSlotMismatchesRecv :
    PqNoise.sendSlot surface.role ≠ PqNoise.recvSlot surface.role
  peerRoleRequiredForSlotAdmission :
    PqNoise.sendSlot surface.role = PqNoise.recvSlot (peerRole surface.role)
  sameRoleFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := surface.role, sendCounter := sendCounter, recvCounter := recvCounter }
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter recvCounter)).accepted = false
  sameRoleRejectPreservesState :
    (PqNoise.openFrameWithObservedWire
      { role := surface.role, sendCounter := sendCounter, recvCounter := recvCounter }
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter recvCounter)).next =
      { role := surface.role, sendCounter := sendCounter, recvCounter := recvCounter }

theorem accepted_authenticated_pq_handshake_same_role_misbind_admission_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    (sendCounter recvCounter : Nat) :
    PqSameRoleMisbindAdmissionFacts surface crypto sendCounter recvCounter := by
  refine
    { handshakeAccepted := handshake
      sameRoleSendSlotMismatchesRecv := PqNoise.send_recv_slots_distinct
      peerRoleRequiredForSlotAdmission :=
        pq_send_slot_matches_peer_recv (role := surface.role)
      sameRoleFrameRejected := ?_
      sameRoleRejectPreservesState := ?_ }
  · rw [PqNoise.openFrameWithObservedWire_rejects_same_role_send_slot]
    rfl
  · rw [PqNoise.openFrameWithObservedWire_rejects_same_role_send_slot]
    rfl

structure PqIndexedStaleReplayAdmissionFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (sendCounter : Nat) : Prop where
  handshakeAccepted :
    AcceptedAuthenticatedPqHandshake surface crypto
  staleFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 3 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).accepted = false
  staleRejectPreservesState :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 3 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).next =
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 3 }
  currentFrameAfterStaleRejectedAccepted :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 3 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 3)).accepted = true
  currentFrameAfterStaleRejectedAdvancesRecvCounter :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role, sendCounter := sendCounter, recvCounter := 3 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 3)).next.recvCounter = 4

theorem accepted_authenticated_pq_handshake_indexed_stale_replay_admission_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    (sendCounter : Nat) :
    PqIndexedStaleReplayAdmissionFacts surface crypto sendCounter := by
  refine
    { handshakeAccepted := handshake
      staleFrameRejected := ?_
      staleRejectPreservesState := ?_
      currentFrameAfterStaleRejectedAccepted := ?_
      currentFrameAfterStaleRejectedAdvancesRecvCounter := ?_ }
  · rw [PqNoise.openFrameWithObservedWire_rejects_stale_nonce_one_at_three]
    rfl
  · rw [PqNoise.openFrameWithObservedWire_rejects_stale_nonce_one_at_three]
    rfl
  · rw [PqNoise.openFrameWithObservedWire_current_frame_after_stale_three_rejects_accepts]
  · rw [PqNoise.openFrameWithObservedWire_current_frame_after_stale_three_rejects_accepts]

theorem accepted_pq_v4_os_rng_transcript_kdf_directional_channel_safety_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts}
    (kemTranscriptKdf :
      AcceptedPqKemTranscriptKdfCertificate
        surface crypto responderSeed initiatorSeed)
    {sequenceLength frameIndex localRecvCounter peerSendCounter : Nat}
    (frameInSequence : frameIndex < sequenceLength)
    (sequenceBound : sequenceLength ≤ PqNoise.u64Max) :
    PqProductionChannelSafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)
      ({ localPqSendStateAt surface frameIndex localRecvCounter with
          sendCounter := frameIndex + 1 })
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter frameIndex)
      ({ peerPqReceiveStateAt surface frameIndex peerSendCounter with
          recvCounter := frameIndex + 1 }) := by
  let transportCompletion :=
    accepted_authenticated_pq_handshake_transport_completion_facts
      kemTranscriptKdf.handshakeAccepted
  let frameAdmission :=
    accepted_authenticated_pq_handshake_bounded_pq_peer_frame_sequence_facts
      kemTranscriptKdf.handshakeAccepted
      frameInSequence
      sequenceBound
      (localRecvCounter := localRecvCounter)
      (peerSendCounter := peerSendCounter)
  refine
    { kemTranscriptKdf := kemTranscriptKdf
      transportCompletion := transportCompletion
      indexedFrameAdmission := frameAdmission
      sequenceAdmitsFrame := frameInSequence
      sequenceWithinCounterDomain := sequenceBound
      transcriptBindsHandshake := kemTranscriptKdf.transcriptBound
      kemSharedSecretsAgree := kemTranscriptKdf.kemSharedSecretsAgree
      hkdfExtractExpandSound := kemTranscriptKdf.handshakeAccepted.hkdfSound
      aeadProtectOpenSound := kemTranscriptKdf.handshakeAccepted.aeadSound
      responderSeedOsRng := kemTranscriptKdf.responderSeedSource
      initiatorSeedOsRng := kemTranscriptKdf.initiatorSeedSource
      responderSeedNotPublicTranscriptDerived :=
        PqNoise.mlkem_os_rng_seed_not_public_transcript_derived
          kemTranscriptKdf.responderSeedSource
      initiatorSeedNotPublicTranscriptDerived :=
        PqNoise.mlkem_os_rng_seed_not_public_transcript_derived
          kemTranscriptKdf.initiatorSeedSource
      responderSeedNotFixedDeterministic :=
        PqNoise.mlkem_os_rng_seed_not_fixed_deterministic
          kemTranscriptKdf.responderSeedSource
      initiatorSeedNotFixedDeterministic :=
        PqNoise.mlkem_os_rng_seed_not_fixed_deterministic
          kemTranscriptKdf.initiatorSeedSource
      responderSeedNotCallerProvidedTest :=
        PqNoise.mlkem_os_rng_seed_not_caller_provided_test
          kemTranscriptKdf.responderSeedSource
      initiatorSeedNotCallerProvidedTest :=
        PqNoise.mlkem_os_rng_seed_not_caller_provided_test
          kemTranscriptKdf.initiatorSeedSource
      responderEncapsulationConsumesOsRngSeed :=
        kemTranscriptKdf.responderEncapsulationUsesResponderSeed
      initiatorEncapsulationConsumesOsRngSeed :=
        kemTranscriptKdf.initiatorEncapsulationUsesInitiatorSeed
      publicTranscriptOnlyEntersSessionScheduleAsSalt :=
        kemTranscriptKdf.transcriptOnlyEntersSessionScheduleAsSalt
      kemSharedSecretsOnlyEnterHkdfIkmInHandshakeOrder :=
        kemTranscriptKdf.kemSecretsEnterIkmInHandshakeOrder
      responseAndFinishSignaturesBindTranscript :=
        kemTranscriptKdf.respAndFinishBindTranscriptHash
      i2rR2iAndAadInfosSeparated :=
        kemTranscriptKdf.i2rR2iAndAadLabelsSeparated
      localSendRecvSlotsDistinct :=
        transportCompletion.localEstablished.sendRecvSlotsDistinct
      localSendRecvInfosDistinct :=
        transportCompletion.localEstablished.sendRecvInfosDistinct
      localSessionAadDistinctFromSend :=
        transportCompletion.localSessionAadDistinctFromSend
      localSessionAadDistinctFromRecv :=
        transportCompletion.localSessionAadDistinctFromRecv
      peerSessionAadDistinctFromSend :=
        transportCompletion.peerSessionAadDistinctFromSend
      peerSessionAadDistinctFromRecv :=
        transportCompletion.peerSessionAadDistinctFromRecv
      localSendSlotAdmittedByPeerRecv :=
        frameAdmission.protectedSlotAdmittedByPeer
      localSendInfoAdmittedByPeerRecv :=
        frameAdmission.protectedInfoAdmittedByPeer
      frameAadDistinctFromDirectionalKeyInfo :=
        frameAdmission.frameAadDistinctFromDirectionalKeyInfo
      protectedNonceAtFrameIndex :=
        frameAdmission.protectedNonceAtFrameIndex
      peerOpenedNonceAtFrameIndex :=
        frameAdmission.peerOpenedNonceAtFrameIndex
      protectedNonceAdmittedByPeer :=
        frameAdmission.protectedNonceAdmittedByPeer
      protectedNextSendCounter :=
        frameAdmission.protectedNextSendCounter
      protectedNextRecvCounterCarried :=
        frameAdmission.protectedNextRecvCounterCarried
      peerOpenedNextSendCounterCarried :=
        frameAdmission.peerOpenedNextSendCounterCarried
      peerOpenedNextRecvCounter :=
        frameAdmission.peerOpenedNextRecvCounter }

structure PqProductionChannelReplaySafetyCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts)
    (localState peerState : PqNoise.ChannelState)
    (sequenceLength frameIndex localRecvCounter peerSendCounter : Nat)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (peerOpenedSlot : PqNoise.KeySlot)
    (peerOpenedNonce : List Byte)
    (peerOpenedNext : PqNoise.ChannelState) : Prop where
  directionalChannelSafety :
    PqProductionChannelSafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      localState
      peerState
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext
  failedOpenReplayAdmission :
    PqFailedOpenReplayAdmissionFacts surface crypto peerSendCounter

theorem accepted_pq_v5_os_rng_transcript_kdf_directional_replay_channel_safety_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts}
    (kemTranscriptKdf :
      AcceptedPqKemTranscriptKdfCertificate
        surface crypto responderSeed initiatorSeed)
    {sequenceLength frameIndex localRecvCounter peerSendCounter : Nat}
    (frameInSequence : frameIndex < sequenceLength)
    (sequenceBound : sequenceLength ≤ PqNoise.u64Max) :
    PqProductionChannelReplaySafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)
      ({ localPqSendStateAt surface frameIndex localRecvCounter with
          sendCounter := frameIndex + 1 })
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter frameIndex)
      ({ peerPqReceiveStateAt surface frameIndex peerSendCounter with
          recvCounter := frameIndex + 1 }) := by
  exact
    { directionalChannelSafety :=
        accepted_pq_v4_os_rng_transcript_kdf_directional_channel_safety_certificate
          kemTranscriptKdf
          frameInSequence
          sequenceBound
      failedOpenReplayAdmission :=
        accepted_authenticated_pq_handshake_failed_open_replay_admission_facts
          kemTranscriptKdf.handshakeAccepted
          peerSendCounter }

structure PqProductionChannelRoleBindingReplaySafetyCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts)
    (localState peerState : PqNoise.ChannelState)
    (sequenceLength frameIndex localRecvCounter peerSendCounter : Nat)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (peerOpenedSlot : PqNoise.KeySlot)
    (peerOpenedNonce : List Byte)
    (peerOpenedNext : PqNoise.ChannelState) : Prop where
  replayChannelSafety :
    PqProductionChannelReplaySafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      localState
      peerState
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext
  sameRoleMisbindAdmission :
    PqSameRoleMisbindAdmissionFacts surface crypto peerSendCounter frameIndex

theorem accepted_pq_v6_os_rng_transcript_kdf_directional_replay_role_binding_channel_safety_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts}
    (kemTranscriptKdf :
      AcceptedPqKemTranscriptKdfCertificate
        surface crypto responderSeed initiatorSeed)
    {sequenceLength frameIndex localRecvCounter peerSendCounter : Nat}
    (frameInSequence : frameIndex < sequenceLength)
    (sequenceBound : sequenceLength ≤ PqNoise.u64Max) :
    PqProductionChannelRoleBindingReplaySafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)
      ({ localPqSendStateAt surface frameIndex localRecvCounter with
          sendCounter := frameIndex + 1 })
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter frameIndex)
      ({ peerPqReceiveStateAt surface frameIndex peerSendCounter with
          recvCounter := frameIndex + 1 }) := by
  exact
    { replayChannelSafety :=
        accepted_pq_v5_os_rng_transcript_kdf_directional_replay_channel_safety_certificate
          kemTranscriptKdf
          frameInSequence
          sequenceBound
      sameRoleMisbindAdmission :=
        accepted_authenticated_pq_handshake_same_role_misbind_admission_facts
          kemTranscriptKdf.handshakeAccepted
          peerSendCounter
          frameIndex }

structure PqProductionChannelIndexedReplaySafetyCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts)
    (localState peerState : PqNoise.ChannelState)
    (sequenceLength frameIndex localRecvCounter peerSendCounter : Nat)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (peerOpenedSlot : PqNoise.KeySlot)
    (peerOpenedNonce : List Byte)
    (peerOpenedNext : PqNoise.ChannelState) : Prop where
  roleBindingReplaySafety :
    PqProductionChannelRoleBindingReplaySafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      localState
      peerState
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext
  indexedStaleReplayAdmission :
    PqIndexedStaleReplayAdmissionFacts surface crypto peerSendCounter

theorem accepted_pq_v7_os_rng_transcript_kdf_directional_replay_role_binding_indexed_stale_channel_safety_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts}
    (kemTranscriptKdf :
      AcceptedPqKemTranscriptKdfCertificate
        surface crypto responderSeed initiatorSeed)
    {sequenceLength frameIndex localRecvCounter peerSendCounter : Nat}
    (frameInSequence : frameIndex < sequenceLength)
    (sequenceBound : sequenceLength ≤ PqNoise.u64Max) :
    PqProductionChannelIndexedReplaySafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)
      ({ localPqSendStateAt surface frameIndex localRecvCounter with
          sendCounter := frameIndex + 1 })
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter frameIndex)
      ({ peerPqReceiveStateAt surface frameIndex peerSendCounter with
          recvCounter := frameIndex + 1 }) := by
  exact
    { roleBindingReplaySafety :=
        accepted_pq_v6_os_rng_transcript_kdf_directional_replay_role_binding_channel_safety_certificate
          kemTranscriptKdf
          frameInSequence
          sequenceBound
      indexedStaleReplayAdmission :=
        accepted_authenticated_pq_handshake_indexed_stale_replay_admission_facts
          kemTranscriptKdf.handshakeAccepted
          peerSendCounter }

structure PqProductionWireParserAdmissionFacts
    (handshakeFrame sessionPlaintextFrame :
      FrameResourceAdmission.FrameDecodeInput) : Prop where
  handshakeFrameKind :
    handshakeFrame.kind = FrameResourceAdmission.FrameKind.pqHandshake
  sessionPlaintextFrameKind :
    sessionPlaintextFrame.kind =
      FrameResourceAdmission.FrameKind.pqSessionPlaintext
  handshakeFrameAccepted :
    FrameResourceAdmission.AcceptedFrameDecodeFacts handshakeFrame
  sessionPlaintextFrameAccepted :
    FrameResourceAdmission.AcceptedFrameDecodeFacts sessionPlaintextFrame
  handshakeFrameWithinBound :
    handshakeFrame.encodedBytes <=
      FrameResourceAdmission.frameKindMaxLen handshakeFrame.kind
  sessionPlaintextFrameWithinBound :
    sessionPlaintextFrame.encodedBytes <=
      FrameResourceAdmission.frameKindMaxLen sessionPlaintextFrame.kind
  handshakeMarkerBound :
    FrameResourceAdmission.frameKindMagic handshakeFrame.kind =
      FrameResourceAdmission.pqHandshakeMagic
  sessionPlaintextMarkerBound :
    FrameResourceAdmission.frameKindMagic sessionPlaintextFrame.kind =
      FrameResourceAdmission.pqSessionMagic
  handshakeMarkerAccepted :
    handshakeFrame.markerMatches = true
  sessionPlaintextMarkerAccepted :
    sessionPlaintextFrame.markerMatches = true
  handshakePostcardDecoded :
    handshakeFrame.postcardDecodes = true
  sessionPlaintextPostcardDecoded :
    sessionPlaintextFrame.postcardDecodes = true
  handshakeNoTrailingBytes :
    handshakeFrame.postcardConsumesAll = true
  sessionPlaintextNoTrailingBytes :
    sessionPlaintextFrame.postcardConsumesAll = true

theorem accepted_pq_wire_parser_admission_facts
    {handshakeFrame sessionPlaintextFrame :
      FrameResourceAdmission.FrameDecodeInput}
    (handshakeFrameKind :
      handshakeFrame.kind = FrameResourceAdmission.FrameKind.pqHandshake)
    (sessionPlaintextFrameKind :
      sessionPlaintextFrame.kind =
        FrameResourceAdmission.FrameKind.pqSessionPlaintext)
    (handshakeAccepted :
      FrameResourceAdmission.evaluateFrameDecode handshakeFrame = none)
    (sessionPlaintextAccepted :
      FrameResourceAdmission.evaluateFrameDecode sessionPlaintextFrame = none) :
    PqProductionWireParserAdmissionFacts
      handshakeFrame
      sessionPlaintextFrame := by
  let handshakeFacts :=
    FrameResourceAdmission.accepted_frame_decode_exposes_facts
      handshakeAccepted
  let sessionFacts :=
    FrameResourceAdmission.accepted_frame_decode_exposes_facts
      sessionPlaintextAccepted
  have handshakePostcard :
      FrameResourceAdmission.frameKindIsPostcardEncoded handshakeFrame.kind =
        true := by
    cases handshakeFrame.kind <;> rfl
  have sessionPostcard :
      FrameResourceAdmission.frameKindIsPostcardEncoded
          sessionPlaintextFrame.kind =
        true := by
    cases sessionPlaintextFrame.kind <;> rfl
  refine
    { handshakeFrameKind := handshakeFrameKind
      sessionPlaintextFrameKind := sessionPlaintextFrameKind
      handshakeFrameAccepted := handshakeFacts
      sessionPlaintextFrameAccepted := sessionFacts
      handshakeFrameWithinBound := handshakeFacts.withinBound
      sessionPlaintextFrameWithinBound := sessionFacts.withinBound
      handshakeMarkerBound := ?_
      sessionPlaintextMarkerBound := ?_
      handshakeMarkerAccepted := handshakeFacts.markerAccepted
      sessionPlaintextMarkerAccepted := sessionFacts.markerAccepted
      handshakePostcardDecoded :=
        handshakeFacts.postcardDecodeAccepted handshakePostcard
      sessionPlaintextPostcardDecoded :=
        sessionFacts.postcardDecodeAccepted sessionPostcard
      handshakeNoTrailingBytes :=
        handshakeFacts.noTrailingBytes handshakePostcard
      sessionPlaintextNoTrailingBytes :=
        sessionFacts.noTrailingBytes sessionPostcard }
  · simp [handshakeFrameKind, FrameResourceAdmission.frameKindMagic]
  · simp [sessionPlaintextFrameKind, FrameResourceAdmission.frameKindMagic]

structure PqProductionWireParserReplayChannelSafetyCertificate
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts)
    (localState peerState : PqNoise.ChannelState)
    (sequenceLength frameIndex localRecvCounter peerSendCounter : Nat)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (peerOpenedSlot : PqNoise.KeySlot)
    (peerOpenedNonce : List Byte)
    (peerOpenedNext : PqNoise.ChannelState)
    (firstFramePayloadBytes : Nat)
    (handshakeFrame sessionPlaintextFrame :
      FrameResourceAdmission.FrameDecodeInput) : Prop where
  indexedReplaySafety :
    PqProductionChannelIndexedReplaySafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      localState
      peerState
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext
  wrapperCompletion :
    PqWrapperCompletionFacts
      surface
      crypto
      localState
      peerState
      0
      0
      0
      0
      firstFramePayloadBytes
      pqAeadTagBytes
      (firstFramePayloadBytes + pqAeadTagBytes)
  wireParserAdmission :
    PqProductionWireParserAdmissionFacts
      handshakeFrame
      sessionPlaintextFrame
  exactHandshakeWireConsumesAll :
    handshakeFrame.postcardConsumesAll = true
  exactSessionPlaintextWireConsumesAll :
    sessionPlaintextFrame.postcardConsumesAll = true
  handshakeWireBounded :
    handshakeFrame.encodedBytes <=
      FrameResourceAdmission.pqHandshakeMaxFrameLen
  sessionPlaintextWireBounded :
    sessionPlaintextFrame.encodedBytes <=
      FrameResourceAdmission.pqSessionPlaintextMaxLen
  duplicateFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 1 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 0)).accepted = false
  futureFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 0 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).accepted = false
  indexedStaleFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 3 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).accepted = false
  sameRoleFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := surface.role
        sendCounter := peerSendCounter
        recvCounter := frameIndex }
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)).accepted = false
  osRngSeedsStillNotPublicTranscriptDerived :
    responderSeed.source ≠ PqNoise.KemSeedSource.publicTranscriptDerived
      ∧ initiatorSeed.source ≠ PqNoise.KemSeedSource.publicTranscriptDerived

theorem accepted_pq_v8_os_rng_transcript_kdf_wire_parser_replay_channel_safety_certificate
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts}
    (kemTranscriptKdf :
      AcceptedPqKemTranscriptKdfCertificate
        surface crypto responderSeed initiatorSeed)
    {sequenceLength frameIndex localRecvCounter peerSendCounter firstFramePayloadBytes : Nat}
    (frameInSequence : frameIndex < sequenceLength)
    (sequenceBound : sequenceLength ≤ PqNoise.u64Max)
    {handshakeFrame sessionPlaintextFrame :
      FrameResourceAdmission.FrameDecodeInput}
    (handshakeFrameKind :
      handshakeFrame.kind = FrameResourceAdmission.FrameKind.pqHandshake)
    (sessionPlaintextFrameKind :
      sessionPlaintextFrame.kind =
        FrameResourceAdmission.FrameKind.pqSessionPlaintext)
    (handshakeAccepted :
      FrameResourceAdmission.evaluateFrameDecode handshakeFrame = none)
    (sessionPlaintextAccepted :
      FrameResourceAdmission.evaluateFrameDecode sessionPlaintextFrame = none) :
    PqProductionWireParserReplayChannelSafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)
      ({ localPqSendStateAt surface frameIndex localRecvCounter with
          sendCounter := frameIndex + 1 })
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter frameIndex)
      ({ peerPqReceiveStateAt surface frameIndex peerSendCounter with
          recvCounter := frameIndex + 1 })
      firstFramePayloadBytes
      handshakeFrame
      sessionPlaintextFrame := by
  let indexedReplaySafety :=
    accepted_pq_v7_os_rng_transcript_kdf_directional_replay_role_binding_indexed_stale_channel_safety_certificate
      kemTranscriptKdf
      (localRecvCounter := localRecvCounter)
      (peerSendCounter := peerSendCounter)
      frameInSequence
      sequenceBound
  let wrapperCompletion :=
    accepted_authenticated_pq_handshake_wrapper_completion_facts
      kemTranscriptKdf.handshakeAccepted
      firstFramePayloadBytes
  let wireParserAdmission :=
    accepted_pq_wire_parser_admission_facts
      handshakeFrameKind
      sessionPlaintextFrameKind
      handshakeAccepted
      sessionPlaintextAccepted
  let roleBindingReplaySafety :=
    indexedReplaySafety.roleBindingReplaySafety
  let replayChannelSafety :=
    roleBindingReplaySafety.replayChannelSafety
  let directionalChannelSafety :=
    replayChannelSafety.directionalChannelSafety
  refine
    { indexedReplaySafety := indexedReplaySafety
      wrapperCompletion := wrapperCompletion
      wireParserAdmission := wireParserAdmission
      exactHandshakeWireConsumesAll :=
        wireParserAdmission.handshakeNoTrailingBytes
      exactSessionPlaintextWireConsumesAll :=
        wireParserAdmission.sessionPlaintextNoTrailingBytes
      handshakeWireBounded := ?_
      sessionPlaintextWireBounded := ?_
      duplicateFrameRejected :=
        replayChannelSafety.failedOpenReplayAdmission.duplicateFrameRejected
      futureFrameRejected :=
        replayChannelSafety.failedOpenReplayAdmission.futureFrameRejected
      indexedStaleFrameRejected :=
        indexedReplaySafety.indexedStaleReplayAdmission.staleFrameRejected
      sameRoleFrameRejected :=
        roleBindingReplaySafety.sameRoleMisbindAdmission.sameRoleFrameRejected
      osRngSeedsStillNotPublicTranscriptDerived :=
        ⟨directionalChannelSafety.responderSeedNotPublicTranscriptDerived,
          directionalChannelSafety.initiatorSeedNotPublicTranscriptDerived⟩ }
  · simpa [handshakeFrameKind, FrameResourceAdmission.frameKindMaxLen] using
      wireParserAdmission.handshakeFrameWithinBound
  · simpa [sessionPlaintextFrameKind, FrameResourceAdmission.frameKindMaxLen] using
      wireParserAdmission.sessionPlaintextFrameWithinBound

structure PqProductionChannelImplementationEquivalenceFacts
    (surface : HandshakeChannelSurface)
    (crypto : CryptoAssumptions surface)
    (responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts)
    (localState peerState : PqNoise.ChannelState)
    (sequenceLength frameIndex localRecvCounter peerSendCounter : Nat)
    (protectedSlot : PqNoise.KeySlot)
    (protectedNonce : List Byte)
    (protectedNext : PqNoise.ChannelState)
    (peerOpenedSlot : PqNoise.KeySlot)
    (peerOpenedNonce : List Byte)
    (peerOpenedNext : PqNoise.ChannelState)
    (firstFramePayloadBytes : Nat)
    (handshakeFrame sessionPlaintextFrame :
      FrameResourceAdmission.FrameDecodeInput) : Prop where
  wireParserReplayChannelSafety :
    PqProductionWireParserReplayChannelSafetyCertificate
      surface
      crypto
      responderSeed
      initiatorSeed
      localState
      peerState
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext
      firstFramePayloadBytes
      handshakeFrame
      sessionPlaintextFrame
  wrapperCompletion :
    PqWrapperCompletionFacts
      surface
      crypto
      localState
      peerState
      0
      0
      0
      0
      firstFramePayloadBytes
      pqAeadTagBytes
      (firstFramePayloadBytes + pqAeadTagBytes)
  wireParserAdmission :
    PqProductionWireParserAdmissionFacts
      handshakeFrame
      sessionPlaintextFrame
  acceptedHandshake :
    AcceptedAuthenticatedPqHandshake surface crypto
  responderSeedOsRng :
    responderSeed.source = PqNoise.KemSeedSource.osRng32
  initiatorSeedOsRng :
    initiatorSeed.source = PqNoise.KemSeedSource.osRng32
  responderSeedConsumedByMlKem :
    responderSeed.consumedByMlKemEncapsulate
  initiatorSeedConsumedByMlKem :
    initiatorSeed.consumedByMlKemEncapsulate
  responderSeedNotPublicTranscriptDerived :
    responderSeed.source ≠ PqNoise.KemSeedSource.publicTranscriptDerived
  initiatorSeedNotPublicTranscriptDerived :
    initiatorSeed.source ≠ PqNoise.KemSeedSource.publicTranscriptDerived
  responderSeedNotFixedDeterministic :
    responderSeed.source ≠ PqNoise.KemSeedSource.fixedDeterministic
  initiatorSeedNotFixedDeterministic :
    initiatorSeed.source ≠ PqNoise.KemSeedSource.fixedDeterministic
  responderSeedNotCallerProvidedTest :
    responderSeed.source ≠ PqNoise.KemSeedSource.callerProvidedTest
  initiatorSeedNotCallerProvidedTest :
    initiatorSeed.source ≠ PqNoise.KemSeedSource.callerProvidedTest
  publicTranscriptOnlyEntersHkdfSalt :
    PqNoise.hkdfSalt surface.pqSession = surface.pqSession.transcriptHash
  kemSharedSecretsOnlyEnterHkdfIkmInHandshakeOrder :
    PqNoise.hkdfIkm surface.pqSession =
      surface.pqSession.shared1 ++ surface.pqSession.shared2
  responseAndFinishSignaturesBindTranscript :
    surface.respHello.transcriptHash = surface.pqSession.transcriptHash
      ∧ surface.finish.transcriptHash = surface.pqSession.transcriptHash
  directionalKeyAndAadLabelsSeparated :
    PqNoise.initiatorToResponderInfo ≠ PqNoise.responderToInitiatorInfo
      ∧ PqNoise.sessionAadInfo ≠ PqNoise.initiatorToResponderInfo
      ∧ PqNoise.sessionAadInfo ≠ PqNoise.responderToInitiatorInfo
  localSendSlotMatchesPeerRecv :
    PqNoise.sendSlot localState.role = PqNoise.recvSlot peerState.role
  localRecvSlotMatchesPeerSend :
    PqNoise.recvSlot localState.role = PqNoise.sendSlot peerState.role
  localSendInfoMatchesPeerRecvInfo :
    PqNoise.expandInfo (PqNoise.sendSlot localState.role) =
      PqNoise.expandInfo (PqNoise.recvSlot peerState.role)
  localRecvInfoMatchesPeerSendInfo :
    PqNoise.expandInfo (PqNoise.recvSlot localState.role) =
      PqNoise.expandInfo (PqNoise.sendSlot peerState.role)
  localSendSlotAdmittedByPeerRecv :
    protectedSlot = peerOpenedSlot
  frameAadDistinctFromDirectionalKeyInfo :
    PqNoise.sessionAadInfo ≠ PqNoise.expandInfo protectedSlot
  protectedNonceAtFrameIndex :
    protectedNonce = PqNoise.nonceFromCounter frameIndex
  peerOpenedNonceAtFrameIndex :
    peerOpenedNonce = PqNoise.nonceFromCounter frameIndex
  protectedNonceAdmittedByPeer :
    protectedNonce = peerOpenedNonce
  protectedNextSendCounter :
    protectedNext.sendCounter = frameIndex + 1
  peerOpenedNextRecvCounter :
    peerOpenedNext.recvCounter = frameIndex + 1
  duplicateFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 1 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 0)).accepted = false
  duplicateRejectPreservesState :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 1 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 0)).next =
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 1 }
  futureFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 0 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).accepted = false
  futureRejectPreservesState :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 0 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).next =
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 0 }
  indexedStaleFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 3 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).accepted = false
  indexedStaleRejectPreservesState :
    (PqNoise.openFrameWithObservedWire
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 3 }
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter 1)).next =
      { role := peerRole surface.role
        sendCounter := peerSendCounter
        recvCounter := 3 }
  sameRoleFrameRejected :
    (PqNoise.openFrameWithObservedWire
      { role := surface.role
        sendCounter := peerSendCounter
        recvCounter := frameIndex }
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)).accepted = false
  sameRoleRejectPreservesState :
    (PqNoise.openFrameWithObservedWire
      { role := surface.role
        sendCounter := peerSendCounter
        recvCounter := frameIndex }
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)).next =
      { role := surface.role
        sendCounter := peerSendCounter
        recvCounter := frameIndex }
  exactHandshakeWireConsumesAll :
    handshakeFrame.postcardConsumesAll = true
  exactSessionPlaintextWireConsumesAll :
    sessionPlaintextFrame.postcardConsumesAll = true
  handshakeWireBounded :
    handshakeFrame.encodedBytes <=
      FrameResourceAdmission.pqHandshakeMaxFrameLen
  sessionPlaintextWireBounded :
    sessionPlaintextFrame.encodedBytes <=
      FrameResourceAdmission.pqSessionPlaintextMaxLen
  wrapperRolesDistinct :
    localState.role ≠ peerState.role

theorem accepted_pq_wire_parser_replay_channel_safety_exposes_implementation_equivalence_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts}
    {localState peerState : PqNoise.ChannelState}
    {sequenceLength frameIndex localRecvCounter peerSendCounter : Nat}
    {protectedSlot : PqNoise.KeySlot}
    {protectedNonce : List Byte}
    {protectedNext : PqNoise.ChannelState}
    {peerOpenedSlot : PqNoise.KeySlot}
    {peerOpenedNonce : List Byte}
    {peerOpenedNext : PqNoise.ChannelState}
    {firstFramePayloadBytes : Nat}
    {handshakeFrame sessionPlaintextFrame :
      FrameResourceAdmission.FrameDecodeInput}
    (certificate :
      PqProductionWireParserReplayChannelSafetyCertificate
        surface
        crypto
        responderSeed
        initiatorSeed
        localState
        peerState
        sequenceLength
        frameIndex
        localRecvCounter
        peerSendCounter
        protectedSlot
        protectedNonce
        protectedNext
        peerOpenedSlot
        peerOpenedNonce
        peerOpenedNext
        firstFramePayloadBytes
        handshakeFrame
        sessionPlaintextFrame) :
    PqProductionChannelImplementationEquivalenceFacts
      surface
      crypto
      responderSeed
      initiatorSeed
      localState
      peerState
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      protectedSlot
      protectedNonce
      protectedNext
      peerOpenedSlot
      peerOpenedNonce
      peerOpenedNext
      firstFramePayloadBytes
      handshakeFrame
      sessionPlaintextFrame := by
  let roleBindingReplaySafety :=
    certificate.indexedReplaySafety.roleBindingReplaySafety
  let replayChannelSafety :=
    roleBindingReplaySafety.replayChannelSafety
  let directionalSafety :=
    replayChannelSafety.directionalChannelSafety
  let failedReplay :=
    replayChannelSafety.failedOpenReplayAdmission
  let sameRole :=
    roleBindingReplaySafety.sameRoleMisbindAdmission
  let indexedStale :=
    certificate.indexedReplaySafety.indexedStaleReplayAdmission
  exact
    { wireParserReplayChannelSafety := certificate
      wrapperCompletion :=
        certificate.wrapperCompletion
      wireParserAdmission :=
        certificate.wireParserAdmission
      acceptedHandshake :=
        directionalSafety.kemTranscriptKdf.handshakeAccepted
      responderSeedOsRng :=
        directionalSafety.responderSeedOsRng
      initiatorSeedOsRng :=
        directionalSafety.initiatorSeedOsRng
      responderSeedConsumedByMlKem :=
        directionalSafety.responderEncapsulationConsumesOsRngSeed
      initiatorSeedConsumedByMlKem :=
        directionalSafety.initiatorEncapsulationConsumesOsRngSeed
      responderSeedNotPublicTranscriptDerived :=
        directionalSafety.responderSeedNotPublicTranscriptDerived
      initiatorSeedNotPublicTranscriptDerived :=
        directionalSafety.initiatorSeedNotPublicTranscriptDerived
      responderSeedNotFixedDeterministic :=
        directionalSafety.responderSeedNotFixedDeterministic
      initiatorSeedNotFixedDeterministic :=
        directionalSafety.initiatorSeedNotFixedDeterministic
      responderSeedNotCallerProvidedTest :=
        directionalSafety.responderSeedNotCallerProvidedTest
      initiatorSeedNotCallerProvidedTest :=
        directionalSafety.initiatorSeedNotCallerProvidedTest
      publicTranscriptOnlyEntersHkdfSalt :=
        directionalSafety.publicTranscriptOnlyEntersSessionScheduleAsSalt
      kemSharedSecretsOnlyEnterHkdfIkmInHandshakeOrder :=
        directionalSafety.kemSharedSecretsOnlyEnterHkdfIkmInHandshakeOrder
      responseAndFinishSignaturesBindTranscript :=
        directionalSafety.responseAndFinishSignaturesBindTranscript
      directionalKeyAndAadLabelsSeparated :=
        directionalSafety.i2rR2iAndAadInfosSeparated
      localSendSlotMatchesPeerRecv :=
        directionalSafety.transportCompletion.localSendSlotMatchesPeerRecv
      localRecvSlotMatchesPeerSend :=
        directionalSafety.transportCompletion.localRecvSlotMatchesPeerSend
      localSendInfoMatchesPeerRecvInfo :=
        directionalSafety.transportCompletion.localSendInfoMatchesPeerRecvInfo
      localRecvInfoMatchesPeerSendInfo :=
        directionalSafety.transportCompletion.localRecvInfoMatchesPeerSendInfo
      localSendSlotAdmittedByPeerRecv :=
        directionalSafety.localSendSlotAdmittedByPeerRecv
      frameAadDistinctFromDirectionalKeyInfo :=
        directionalSafety.frameAadDistinctFromDirectionalKeyInfo
      protectedNonceAtFrameIndex :=
        directionalSafety.protectedNonceAtFrameIndex
      peerOpenedNonceAtFrameIndex :=
        directionalSafety.peerOpenedNonceAtFrameIndex
      protectedNonceAdmittedByPeer :=
        directionalSafety.protectedNonceAdmittedByPeer
      protectedNextSendCounter :=
        directionalSafety.protectedNextSendCounter
      peerOpenedNextRecvCounter :=
        directionalSafety.peerOpenedNextRecvCounter
      duplicateFrameRejected :=
        failedReplay.duplicateFrameRejected
      duplicateRejectPreservesState :=
        failedReplay.duplicateRejectPreservesState
      futureFrameRejected :=
        failedReplay.futureFrameRejected
      futureRejectPreservesState :=
        failedReplay.futureRejectPreservesState
      indexedStaleFrameRejected :=
        indexedStale.staleFrameRejected
      indexedStaleRejectPreservesState :=
        indexedStale.staleRejectPreservesState
      sameRoleFrameRejected :=
        sameRole.sameRoleFrameRejected
      sameRoleRejectPreservesState :=
        sameRole.sameRoleRejectPreservesState
      exactHandshakeWireConsumesAll :=
        certificate.exactHandshakeWireConsumesAll
      exactSessionPlaintextWireConsumesAll :=
        certificate.exactSessionPlaintextWireConsumesAll
      handshakeWireBounded :=
        certificate.handshakeWireBounded
      sessionPlaintextWireBounded :=
        certificate.sessionPlaintextWireBounded
      wrapperRolesDistinct :=
        certificate.wrapperCompletion.rolesDistinct }

theorem accepted_pq_v9_os_rng_transcript_kdf_wire_parser_replay_channel_implementation_equivalence_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    {responderSeed initiatorSeed : PqNoise.MlKemEncapsulationSeedFacts}
    (kemTranscriptKdf :
      AcceptedPqKemTranscriptKdfCertificate
        surface crypto responderSeed initiatorSeed)
    {sequenceLength frameIndex localRecvCounter peerSendCounter firstFramePayloadBytes : Nat}
    (frameInSequence : frameIndex < sequenceLength)
    (sequenceBound : sequenceLength ≤ PqNoise.u64Max)
    {handshakeFrame sessionPlaintextFrame :
      FrameResourceAdmission.FrameDecodeInput}
    (handshakeFrameKind :
      handshakeFrame.kind = FrameResourceAdmission.FrameKind.pqHandshake)
    (sessionPlaintextFrameKind :
      sessionPlaintextFrame.kind =
        FrameResourceAdmission.FrameKind.pqSessionPlaintext)
    (handshakeAccepted :
      FrameResourceAdmission.evaluateFrameDecode handshakeFrame = none)
    (sessionPlaintextAccepted :
      FrameResourceAdmission.evaluateFrameDecode sessionPlaintextFrame = none) :
    PqProductionChannelImplementationEquivalenceFacts
      surface
      crypto
      responderSeed
      initiatorSeed
      (pqChannelStateFromHandshake surface)
      (peerPqChannelStateFromHandshake surface)
      sequenceLength
      frameIndex
      localRecvCounter
      peerSendCounter
      (PqNoise.sendSlot surface.role)
      (PqNoise.nonceFromCounter frameIndex)
      ({ localPqSendStateAt surface frameIndex localRecvCounter with
          sendCounter := frameIndex + 1 })
      (PqNoise.recvSlot (peerRole surface.role))
      (PqNoise.nonceFromCounter frameIndex)
      ({ peerPqReceiveStateAt surface frameIndex peerSendCounter with
          recvCounter := frameIndex + 1 })
      firstFramePayloadBytes
      handshakeFrame
      sessionPlaintextFrame := by
  exact
    accepted_pq_wire_parser_replay_channel_safety_exposes_implementation_equivalence_facts
      (accepted_pq_v8_os_rng_transcript_kdf_wire_parser_replay_channel_safety_certificate
        kemTranscriptKdf
        frameInSequence
        sequenceBound
        handshakeFrameKind
        sessionPlaintextFrameKind
        handshakeAccepted
        sessionPlaintextAccepted)

theorem accepted_authenticated_pq_handshake_initial_protect_open_facts
    {surface : HandshakeChannelSurface}
    {crypto : CryptoAssumptions surface}
    (handshake : AcceptedAuthenticatedPqHandshake surface crypto)
    {protectedSlot : SecureChannel.KeySlot}
    {protectedNonce : List Byte}
    {protectedNext : SecureChannel.ChannelState}
    {openedSlot : SecureChannel.KeySlot}
    {openedNonce : List Byte}
    {openedNext : SecureChannel.ChannelState}
    (protectAccepted :
      SecureChannel.protectFrame (channelStateFromHandshake surface) =
        some (protectedSlot, protectedNonce, protectedNext))
    (openAccepted :
      SecureChannel.openFrame (channelStateFromHandshake surface) =
        some (openedSlot, openedNonce, openedNext)) :
    InitialProtectOpenTransitionFacts
      surface
      crypto
      protectedSlot
      protectedNonce
      protectedNext
      openedSlot
      openedNonce
      openedNext := by
  rcases SecureChannel.protectFrame_direction_and_counter protectAccepted with
    ⟨hProtectSlot,
      hProtectNotRecv,
      hProtectNonce,
      hProtectRole,
      hProtectSend,
      hProtectRecv⟩
  rcases SecureChannel.openFrame_direction_and_counter openAccepted with
    ⟨hOpenSlot,
      hOpenNotSend,
      hOpenNonce,
      hOpenRole,
      hOpenSend,
      hOpenRecv⟩
  refine
    { established :=
        accepted_authenticated_pq_handshake_establishes_channel_facts handshake
      protectSlotIsSend := ?_
      protectSlotNotRecv := ?_
      protectNonceZero := ?_
      protectNextRole := ?_
      protectNextSendCounter := ?_
      protectNextRecvCounter := ?_
      openSlotIsRecv := ?_
      openSlotNotSend := ?_
      openNonceZero := ?_
      openNextRole := ?_
      openNextSendCounter := ?_
      openNextRecvCounter := ?_
      protectOpenSlotsDistinct := ?_ }
  · simpa [channelStateFromHandshake] using hProtectSlot
  · simpa [channelStateFromHandshake] using hProtectNotRecv
  · simpa [channelStateFromHandshake, SecureChannel.initialState] using
      hProtectNonce
  · simpa [channelStateFromHandshake] using hProtectRole
  · simpa [channelStateFromHandshake, SecureChannel.initialState] using
      hProtectSend
  · simpa [channelStateFromHandshake, SecureChannel.initialState] using
      hProtectRecv
  · simpa [channelStateFromHandshake] using hOpenSlot
  · simpa [channelStateFromHandshake] using hOpenNotSend
  · simpa [channelStateFromHandshake, SecureChannel.initialState] using
      hOpenNonce
  · simpa [channelStateFromHandshake] using hOpenRole
  · simpa [channelStateFromHandshake, SecureChannel.initialState] using
      hOpenSend
  · simpa [channelStateFromHandshake, SecureChannel.initialState] using
      hOpenRecv
  · intro sameSlot
    have protectedIsRecv :
        protectedSlot = SecureChannel.recvSlot (secureRole surface.role) := by
      rw [sameSlot]
      simpa [channelStateFromHandshake] using hOpenSlot
    have protectedNotRecv :
        protectedSlot ≠ SecureChannel.recvSlot (secureRole surface.role) := by
      simpa [channelStateFromHandshake] using hProtectNotRecv
    exact protectedNotRecv protectedIsRecv

end PqNoiseHandshakeChannel
end Network
end Hegemon

import Hegemon.Network.PqNoise
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

def channelStateFromHandshake
    (surface : HandshakeChannelSurface) :
    SecureChannel.ChannelState :=
  SecureChannel.initialState (secureRole surface.role)

def pqChannelStateFromHandshake
    (surface : HandshakeChannelSurface) :
    PqNoise.ChannelState :=
  PqNoise.initialState surface.role

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

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

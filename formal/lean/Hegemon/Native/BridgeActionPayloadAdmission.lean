namespace Hegemon
namespace Native
namespace BridgeActionPayloadAdmission

inductive BridgeActionKind where
  | outbound
  | inbound
  | register
  | unsupported
deriving DecidableEq, Repr

inductive BridgePayloadReject where
  | notBridgeAction
  | stateDeltasPresent
  | unsupportedBridgeAction
  | outboundPayloadEmpty
  | inboundProofReceiptEmpty
  | inboundReplayKeyMismatch
  | inboundDestinationMismatch
  | inboundPayloadHashMismatch
deriving DecidableEq, Repr

structure BridgePayloadInput where
  bridgeRoute : Bool
  stateDeltasAbsent : Bool
  actionKind : BridgeActionKind
  outboundPayloadNonempty : Bool
  inboundProofReceiptNonempty : Bool
  inboundReplayKeyMatches : Bool
  inboundDestinationMatches : Bool
  inboundPayloadHashMatches : Bool
deriving DecidableEq, Repr

def evaluateBridgePayload
    (input : BridgePayloadInput) : Except BridgePayloadReject Unit :=
  if input.bridgeRoute = false then
    Except.error BridgePayloadReject.notBridgeAction
  else if input.stateDeltasAbsent = false then
    Except.error BridgePayloadReject.stateDeltasPresent
  else
    match input.actionKind with
    | BridgeActionKind.outbound =>
        if input.outboundPayloadNonempty = false then
          Except.error BridgePayloadReject.outboundPayloadEmpty
        else
          Except.ok ()
    | BridgeActionKind.inbound =>
        if input.inboundProofReceiptNonempty = false then
          Except.error BridgePayloadReject.inboundProofReceiptEmpty
        else if input.inboundReplayKeyMatches = false then
          Except.error BridgePayloadReject.inboundReplayKeyMismatch
        else if input.inboundDestinationMatches = false then
          Except.error BridgePayloadReject.inboundDestinationMismatch
        else if input.inboundPayloadHashMatches = false then
          Except.error BridgePayloadReject.inboundPayloadHashMismatch
        else
          Except.ok ()
    | BridgeActionKind.register =>
        Except.ok ()
    | BridgeActionKind.unsupported =>
        Except.error BridgePayloadReject.unsupportedBridgeAction

def bridgePayloadAccepts (input : BridgePayloadInput) : Bool :=
  match evaluateBridgePayload input with
  | Except.ok _ => true
  | Except.error _ => false

def bridgePayloadRejection
    (input : BridgePayloadInput) : Option BridgePayloadReject :=
  match evaluateBridgePayload input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def bridgePayloadPreconditions (input : BridgePayloadInput) : Bool :=
  if input.bridgeRoute = false then
    false
  else if input.stateDeltasAbsent = false then
    false
  else
    match input.actionKind with
    | BridgeActionKind.outbound =>
        input.outboundPayloadNonempty
    | BridgeActionKind.inbound =>
        input.inboundProofReceiptNonempty
          && input.inboundReplayKeyMatches
          && input.inboundDestinationMatches
          && input.inboundPayloadHashMatches
    | BridgeActionKind.register =>
        true
    | BridgeActionKind.unsupported =>
        false

theorem accepts_iff_payload_preconditions (input : BridgePayloadInput) :
    bridgePayloadAccepts input = bridgePayloadPreconditions input := by
  cases input with
  | mk bridgeRoute stateDeltasAbsent actionKind outboundPayloadNonempty
      inboundProofReceiptNonempty inboundReplayKeyMatches
      inboundDestinationMatches inboundPayloadHashMatches =>
      unfold bridgePayloadAccepts bridgePayloadPreconditions evaluateBridgePayload
      cases bridgeRoute <;>
        cases stateDeltasAbsent <;>
        cases actionKind <;>
        cases outboundPayloadNonempty <;>
        cases inboundProofReceiptNonempty <;>
        cases inboundReplayKeyMatches <;>
        cases inboundDestinationMatches <;>
        cases inboundPayloadHashMatches <;>
        rfl

def validOutboundBridgePayload : BridgePayloadInput :=
  {
    bridgeRoute := true,
    stateDeltasAbsent := true,
    actionKind := BridgeActionKind.outbound,
    outboundPayloadNonempty := true,
    inboundProofReceiptNonempty := true,
    inboundReplayKeyMatches := true,
    inboundDestinationMatches := true,
    inboundPayloadHashMatches := true
  }

def validInboundBridgePayload : BridgePayloadInput :=
  {
    bridgeRoute := true,
    stateDeltasAbsent := true,
    actionKind := BridgeActionKind.inbound,
    outboundPayloadNonempty := true,
    inboundProofReceiptNonempty := true,
    inboundReplayKeyMatches := true,
    inboundDestinationMatches := true,
    inboundPayloadHashMatches := true
  }

def validRegisterBridgePayload : BridgePayloadInput :=
  {
    bridgeRoute := true,
    stateDeltasAbsent := true,
    actionKind := BridgeActionKind.register,
    outboundPayloadNonempty := true,
    inboundProofReceiptNonempty := true,
    inboundReplayKeyMatches := true,
    inboundDestinationMatches := true,
    inboundPayloadHashMatches := true
  }

theorem valid_outbound_accepts :
    evaluateBridgePayload validOutboundBridgePayload = Except.ok () := by
  rfl

theorem valid_inbound_accepts :
    evaluateBridgePayload validInboundBridgePayload = Except.ok () := by
  rfl

theorem valid_register_accepts :
    evaluateBridgePayload validRegisterBridgePayload = Except.ok () := by
  rfl

theorem not_bridge_action_rejects
    {input : BridgePayloadInput}
    (notBridge : input.bridgeRoute = false) :
    evaluateBridgePayload input =
      Except.error BridgePayloadReject.notBridgeAction := by
  unfold evaluateBridgePayload
  simp [notBridge]

theorem state_deltas_present_rejects
    {input : BridgePayloadInput}
    (bridge : input.bridgeRoute = true)
    (deltas : input.stateDeltasAbsent = false) :
    evaluateBridgePayload input =
      Except.error BridgePayloadReject.stateDeltasPresent := by
  unfold evaluateBridgePayload
  simp [bridge, deltas]

theorem unsupported_bridge_action_rejects
    {input : BridgePayloadInput}
    (bridge : input.bridgeRoute = true)
    (deltas : input.stateDeltasAbsent = true)
    (unsupported : input.actionKind = BridgeActionKind.unsupported) :
    evaluateBridgePayload input =
      Except.error BridgePayloadReject.unsupportedBridgeAction := by
  unfold evaluateBridgePayload
  simp [bridge, deltas, unsupported]

theorem outbound_payload_empty_rejects
    {input : BridgePayloadInput}
    (bridge : input.bridgeRoute = true)
    (deltas : input.stateDeltasAbsent = true)
    (outbound : input.actionKind = BridgeActionKind.outbound)
    (emptyPayload : input.outboundPayloadNonempty = false) :
    evaluateBridgePayload input =
      Except.error BridgePayloadReject.outboundPayloadEmpty := by
  unfold evaluateBridgePayload
  simp [bridge, deltas, outbound, emptyPayload]

theorem inbound_proof_receipt_empty_rejects
    {input : BridgePayloadInput}
    (bridge : input.bridgeRoute = true)
    (deltas : input.stateDeltasAbsent = true)
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (emptyProof : input.inboundProofReceiptNonempty = false) :
    evaluateBridgePayload input =
      Except.error BridgePayloadReject.inboundProofReceiptEmpty := by
  unfold evaluateBridgePayload
  simp [bridge, deltas, inbound, emptyProof]

theorem inbound_replay_key_mismatch_rejects
    {input : BridgePayloadInput}
    (bridge : input.bridgeRoute = true)
    (deltas : input.stateDeltasAbsent = true)
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (proof : input.inboundProofReceiptNonempty = true)
    (mismatch : input.inboundReplayKeyMatches = false) :
    evaluateBridgePayload input =
      Except.error BridgePayloadReject.inboundReplayKeyMismatch := by
  unfold evaluateBridgePayload
  simp [bridge, deltas, inbound, proof, mismatch]

theorem inbound_destination_mismatch_rejects
    {input : BridgePayloadInput}
    (bridge : input.bridgeRoute = true)
    (deltas : input.stateDeltasAbsent = true)
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (proof : input.inboundProofReceiptNonempty = true)
    (replay : input.inboundReplayKeyMatches = true)
    (mismatch : input.inboundDestinationMatches = false) :
    evaluateBridgePayload input =
      Except.error BridgePayloadReject.inboundDestinationMismatch := by
  unfold evaluateBridgePayload
  simp [bridge, deltas, inbound, proof, replay, mismatch]

theorem inbound_payload_hash_mismatch_rejects
    {input : BridgePayloadInput}
    (bridge : input.bridgeRoute = true)
    (deltas : input.stateDeltasAbsent = true)
    (inbound : input.actionKind = BridgeActionKind.inbound)
    (proof : input.inboundProofReceiptNonempty = true)
    (replay : input.inboundReplayKeyMatches = true)
    (destination : input.inboundDestinationMatches = true)
    (mismatch : input.inboundPayloadHashMatches = false) :
    evaluateBridgePayload input =
      Except.error BridgePayloadReject.inboundPayloadHashMismatch := by
  unfold evaluateBridgePayload
  simp [bridge, deltas, inbound, proof, replay, destination, mismatch]

end BridgeActionPayloadAdmission
end Native
end Hegemon

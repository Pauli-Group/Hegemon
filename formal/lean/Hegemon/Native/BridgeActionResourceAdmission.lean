import Hegemon.Native.BridgeActionPayloadAdmission
import Hegemon.Resource.BoundedRequestAdmission

namespace Hegemon
namespace Native
namespace BridgeActionResourceAdmission

open Hegemon.Native.BridgeActionPayloadAdmission
open Hegemon.Resource.BoundedRequestAdmission

structure BridgeActionResourceInput where
  actionKind : BridgeActionKind
  publicArgsBytes : Nat
  outboundPayloadBytes : Nat
  inboundProofReceiptBytes : Nat
  inboundMessagePayloadBytes : Nat
deriving DecidableEq, Repr

def bridgeActionResourceItemCount
    (input : BridgeActionResourceInput) : Nat :=
  match input.actionKind with
  | BridgeActionKind.outbound => 1
  | BridgeActionKind.inbound => 2
  | BridgeActionKind.register => 0
  | BridgeActionKind.unsupported => 0

def bridgeActionResourceMaxItemBytes
    (input : BridgeActionResourceInput) : Nat :=
  max input.outboundPayloadBytes
    (max input.inboundProofReceiptBytes input.inboundMessagePayloadBytes)

def bridgeActionResourceAggregateBytes
    (input : BridgeActionResourceInput) : Nat :=
  input.outboundPayloadBytes
    + input.inboundProofReceiptBytes
    + input.inboundMessagePayloadBytes

def bridgeActionResourcePayloadWorkUnits
    (input : BridgeActionResourceInput) : Nat :=
  max input.outboundPayloadBytes input.inboundMessagePayloadBytes

def bridgeActionResourceRequest
    (input : BridgeActionResourceInput) : ResourceRequest :=
  {
    rawBytes := input.publicArgsBytes,
    decodedBytes := input.publicArgsBytes,
    itemCount := bridgeActionResourceItemCount input,
    maxItemBytes := bridgeActionResourceMaxItemBytes input,
    aggregateBytes := bridgeActionResourceAggregateBytes input,
    workUnits := bridgeActionResourcePayloadWorkUnits input
  }

inductive BridgeActionResourceFirstReject where
  | payload : BridgePayloadReject -> BridgeActionResourceFirstReject
  | resource : ResourceReject -> BridgeActionResourceFirstReject
deriving DecidableEq, Repr

def evaluateBridgePayloadWithResource
    (policy : ResourcePolicy)
    (resourceInput : BridgeActionResourceInput)
    (payloadInput : BridgePayloadInput) :
    Except BridgeActionResourceFirstReject Unit :=
  match evaluateBoundedRequest policy
      (bridgeActionResourceRequest resourceInput) with
  | some reject =>
      Except.error (BridgeActionResourceFirstReject.resource reject)
  | none =>
      match evaluateBridgePayload payloadInput with
      | Except.error reject =>
          Except.error (BridgeActionResourceFirstReject.payload reject)
      | Except.ok _ =>
          Except.ok ()

structure AcceptedBridgeActionResourceFacts
    (policy : ResourcePolicy)
    (input : BridgeActionResourceInput) : Prop where
  boundedFacts :
    AcceptedBoundedRequestFacts policy
      (bridgeActionResourceRequest input)
  publicArgsWithinRawCap :
    ¬ policy.rawByteCap < input.publicArgsBytes
  publicArgsWithinDecodedCap :
    ¬ policy.decodedByteCap < input.publicArgsBytes
  dynamicItemCountWithinCap :
    ¬ policy.itemCountCap < bridgeActionResourceItemCount input
  outboundPayloadWithinItemByteCap :
    ¬ policy.itemByteCap < input.outboundPayloadBytes
  inboundProofReceiptWithinItemByteCap :
    ¬ policy.itemByteCap < input.inboundProofReceiptBytes
  inboundMessagePayloadWithinItemByteCap :
    ¬ policy.itemByteCap < input.inboundMessagePayloadBytes
  dynamicAggregateWithinCap :
    ¬ policy.aggregateByteCap < bridgeActionResourceAggregateBytes input
  payloadWorkWithinCap :
    ¬ policy.workUnitCap < bridgeActionResourcePayloadWorkUnits input

theorem accepted_bridge_action_resource_exposes_bounds
    {policy : ResourcePolicy}
    {input : BridgeActionResourceInput}
    (accepted :
      evaluateBoundedRequest policy
        (bridgeActionResourceRequest input) = none) :
    AcceptedBridgeActionResourceFacts policy input := by
  let facts :=
    accepted_bounded_request_exposes_all_caps
      (policy := policy)
      (request := bridgeActionResourceRequest input)
      accepted
  have maxWithin :
      ¬ policy.itemByteCap < bridgeActionResourceMaxItemBytes input := by
    simpa [bridgeActionResourceRequest] using facts.itemBytesWithinCap
  have outboundWithin :
      ¬ policy.itemByteCap < input.outboundPayloadBytes := by
    intro outboundOver
    exact maxWithin
      (Nat.lt_of_lt_of_le outboundOver
        (Nat.le_max_left input.outboundPayloadBytes
          (max input.inboundProofReceiptBytes input.inboundMessagePayloadBytes)))
  have receiptWithin :
      ¬ policy.itemByteCap < input.inboundProofReceiptBytes := by
    intro receiptOver
    exact maxWithin
      (Nat.lt_of_lt_of_le receiptOver
        (Nat.le_trans
          (Nat.le_max_left input.inboundProofReceiptBytes
            input.inboundMessagePayloadBytes)
          (Nat.le_max_right input.outboundPayloadBytes
            (max input.inboundProofReceiptBytes input.inboundMessagePayloadBytes))))
  have messageWithin :
      ¬ policy.itemByteCap < input.inboundMessagePayloadBytes := by
    intro messageOver
    exact maxWithin
      (Nat.lt_of_lt_of_le messageOver
        (Nat.le_trans
          (Nat.le_max_right input.inboundProofReceiptBytes
            input.inboundMessagePayloadBytes)
          (Nat.le_max_right input.outboundPayloadBytes
            (max input.inboundProofReceiptBytes input.inboundMessagePayloadBytes))))
  exact {
    boundedFacts := facts,
    publicArgsWithinRawCap := by
      simpa [bridgeActionResourceRequest] using facts.rawBytesWithinCap,
    publicArgsWithinDecodedCap := by
      simpa [bridgeActionResourceRequest] using facts.decodedBytesWithinCap,
    dynamicItemCountWithinCap := by
      simpa [bridgeActionResourceRequest] using facts.itemCountWithinCap,
    outboundPayloadWithinItemByteCap := outboundWithin,
    inboundProofReceiptWithinItemByteCap := receiptWithin,
    inboundMessagePayloadWithinItemByteCap := messageWithin,
    dynamicAggregateWithinCap := by
      simpa [bridgeActionResourceRequest] using
        facts.aggregateBytesWithinCap,
    payloadWorkWithinCap := by
      simpa [bridgeActionResourceRequest] using facts.workUnitsWithinCap
  }

theorem accepted_bridge_payload_with_resource_exposes_payload_acceptance
    {policy : ResourcePolicy}
    {resourceInput : BridgeActionResourceInput}
    {payloadInput : BridgePayloadInput}
    (accepted :
      evaluateBridgePayloadWithResource
        policy resourceInput payloadInput = Except.ok ()) :
    evaluateBridgePayload payloadInput = Except.ok () := by
  unfold evaluateBridgePayloadWithResource at accepted
  cases hr :
      evaluateBoundedRequest policy
        (bridgeActionResourceRequest resourceInput) with
  | some reject =>
      simp [hr] at accepted
  | none =>
      cases hp : evaluateBridgePayload payloadInput with
      | ok value =>
          cases value
          rfl
      | error reject =>
          simp [hr, hp] at accepted

theorem accepted_bridge_payload_with_resource_exposes_resource_bounds
    {policy : ResourcePolicy}
    {resourceInput : BridgeActionResourceInput}
    {payloadInput : BridgePayloadInput}
    (accepted :
      evaluateBridgePayloadWithResource
        policy resourceInput payloadInput = Except.ok ()) :
    AcceptedBridgeActionResourceFacts policy resourceInput := by
  unfold evaluateBridgePayloadWithResource at accepted
  cases hr :
      evaluateBoundedRequest policy
        (bridgeActionResourceRequest resourceInput) with
  | none =>
      exact accepted_bridge_action_resource_exposes_bounds hr
  | some reject =>
      simp [hr] at accepted

structure AcceptedInboundBridgeResourceBeforeVerifyFacts
    (policy : ResourcePolicy)
    (input : BridgeActionResourceInput) : Prop where
  actionKindInbound :
    input.actionKind = BridgeActionKind.inbound
  resourceFacts :
    AcceptedBridgeActionResourceFacts policy input
  proofReceiptWithinCap :
    ¬ policy.itemByteCap < input.inboundProofReceiptBytes
  messagePayloadWithinWorkCap :
    ¬ policy.workUnitCap < input.inboundMessagePayloadBytes
  publicArgsWithinCap :
    ¬ policy.rawByteCap < input.publicArgsBytes

theorem accepted_inbound_bridge_payload_resource_bounds_receipt_before_verify
    {policy : ResourcePolicy}
    {resourceInput : BridgeActionResourceInput}
    {payloadInput : BridgePayloadInput}
    (inboundResource :
      resourceInput.actionKind = BridgeActionKind.inbound)
    (_inboundPayload :
      payloadInput.actionKind = BridgeActionKind.inbound)
    (accepted :
      evaluateBridgePayloadWithResource
        policy resourceInput payloadInput = Except.ok ()) :
    AcceptedInboundBridgeResourceBeforeVerifyFacts policy resourceInput := by
  let facts :=
    accepted_bridge_payload_with_resource_exposes_resource_bounds accepted
  have payloadWorkMaxWithin :
      ¬ policy.workUnitCap <
        bridgeActionResourcePayloadWorkUnits resourceInput :=
    facts.payloadWorkWithinCap
  have messageWorkWithin :
      ¬ policy.workUnitCap < resourceInput.inboundMessagePayloadBytes := by
    intro messageOver
    exact payloadWorkMaxWithin
      (Nat.lt_of_lt_of_le messageOver
        (Nat.le_max_right resourceInput.outboundPayloadBytes
          resourceInput.inboundMessagePayloadBytes))
  exact {
    actionKindInbound := inboundResource,
    resourceFacts := facts,
    proofReceiptWithinCap :=
      facts.inboundProofReceiptWithinItemByteCap,
    messagePayloadWithinWorkCap := messageWorkWithin,
    publicArgsWithinCap := facts.publicArgsWithinRawCap
  }

def exampleBridgeActionResourcePolicy : ResourcePolicy :=
  {
    rawByteCap := 2097152,
    decodedByteCap := 2097152,
    itemCountCap := 2,
    itemByteCap := 524288,
    aggregateByteCap := 589824,
    workUnitCap := 65536
  }

def validInboundBridgeResource : BridgeActionResourceInput :=
  {
    actionKind := BridgeActionKind.inbound,
    publicArgsBytes := 256,
    outboundPayloadBytes := 0,
    inboundProofReceiptBytes := 4096,
    inboundMessagePayloadBytes := 128
  }

def validOutboundBridgeResource : BridgeActionResourceInput :=
  {
    actionKind := BridgeActionKind.outbound,
    publicArgsBytes := 160,
    outboundPayloadBytes := 128,
    inboundProofReceiptBytes := 0,
    inboundMessagePayloadBytes := 0
  }

theorem valid_inbound_bridge_resource_accepts :
    evaluateBoundedRequest exampleBridgeActionResourcePolicy
      (bridgeActionResourceRequest validInboundBridgeResource) = none := by
  decide

theorem valid_outbound_bridge_resource_accepts :
    evaluateBoundedRequest exampleBridgeActionResourcePolicy
      (bridgeActionResourceRequest validOutboundBridgeResource) = none := by
  decide

end BridgeActionResourceAdmission
end Native
end Hegemon

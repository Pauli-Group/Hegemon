import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace OutboundBridgeActionPayloadScaleWire

open Hegemon.Native.CodecAdmission

inductive OutboundBridgeActionPayloadScaleWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure OutboundBridgeActionPayloadScaleWireInput where
  destinationChainIdBytes : Nat
  appFamilyIdBytes : Nat
  payloadCompactPrefixBytes : Nat
  payloadBytes : Nat
  payloadCompactPrefixCanonical : Bool
  totalBytes : Nat
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def outboundBridgeActionPayloadEncodedLen
    (payloadCompactPrefixBytes payloadBytes : Nat) : Nat :=
  32 + 2 + payloadCompactPrefixBytes + payloadBytes

def fixedFieldWidthsOk
    (input : OutboundBridgeActionPayloadScaleWireInput) : Bool :=
  input.destinationChainIdBytes == 32
    && input.appFamilyIdBytes == 2

def expectedLengthMatches
    (input : OutboundBridgeActionPayloadScaleWireInput) : Bool :=
  input.totalBytes ==
    outboundBridgeActionPayloadEncodedLen
      input.payloadCompactPrefixBytes
      input.payloadBytes

def evaluateOutboundBridgeActionPayloadScaleWireRejection
    (input : OutboundBridgeActionPayloadScaleWireInput) :
    Option OutboundBridgeActionPayloadScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some OutboundBridgeActionPayloadScaleWireReject.parserRejected
  else if input.payloadCompactPrefixCanonical = false then
    some OutboundBridgeActionPayloadScaleWireReject.parserRejected
  else if expectedLengthMatches input = false then
    some OutboundBridgeActionPayloadScaleWireReject.parserRejected
  else if input.consumedAllBytes = false then
    some OutboundBridgeActionPayloadScaleWireReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some OutboundBridgeActionPayloadScaleWireReject.nonCanonicalEncoding
  else
    none

def outboundBridgeActionPayloadScaleWireAccepts
    (input : OutboundBridgeActionPayloadScaleWireInput) : Bool :=
  evaluateOutboundBridgeActionPayloadScaleWireRejection input = none

structure AcceptedOutboundBridgeActionPayloadScaleWireFacts
    (input : OutboundBridgeActionPayloadScaleWireInput) : Prop where
  fixedFieldWidths :
    fixedFieldWidthsOk input = true
  payloadCompactPrefixCanonical :
    input.payloadCompactPrefixCanonical = true
  totalLengthMatches :
    input.totalBytes =
      outboundBridgeActionPayloadEncodedLen
        input.payloadCompactPrefixBytes
        input.payloadBytes
  consumedAllBytes :
    input.consumedAllBytes = true
  canonicalReencodeMatches :
    input.canonicalReencodeMatches = true

theorem outbound_bridge_action_payload_scale_wire_acceptance_exposes_facts
    {input : OutboundBridgeActionPayloadScaleWireInput}
    (accepted : outboundBridgeActionPayloadScaleWireAccepts input = true) :
    AcceptedOutboundBridgeActionPayloadScaleWireFacts input := by
  unfold outboundBridgeActionPayloadScaleWireAccepts at accepted
  unfold evaluateOutboundBridgeActionPayloadScaleWireRejection at accepted
  by_cases hFixedFalse : fixedFieldWidthsOk input = false
  · simp [hFixedFalse] at accepted
  · have hFixed : fixedFieldWidthsOk input = true := by
      cases h : fixedFieldWidthsOk input <;> simp [h] at hFixedFalse ⊢
    simp [hFixed] at accepted
    by_cases hCompactFalse :
        input.payloadCompactPrefixCanonical = false
    · simp [hCompactFalse] at accepted
    · have hCompact :
          input.payloadCompactPrefixCanonical = true := by
        cases h : input.payloadCompactPrefixCanonical <;>
          simp [h] at hCompactFalse ⊢
      simp [hCompact] at accepted
      by_cases hLengthFalse : expectedLengthMatches input = false
      · simp [hLengthFalse] at accepted
      · have hLengthBool : expectedLengthMatches input = true := by
          cases h : expectedLengthMatches input <;>
            simp [h] at hLengthFalse ⊢
        have hLength :
            input.totalBytes =
              outboundBridgeActionPayloadEncodedLen
                input.payloadCompactPrefixBytes
                input.payloadBytes := by
          simpa [expectedLengthMatches] using hLengthBool
        simp [hLengthBool] at accepted
        by_cases hConsumedFalse : input.consumedAllBytes = false
        · simp [hConsumedFalse] at accepted
        · have hConsumed : input.consumedAllBytes = true := by
            cases h : input.consumedAllBytes <;>
              simp [h] at hConsumedFalse ⊢
          simp [hConsumed] at accepted
          by_cases hCanonicalFalse :
              input.canonicalReencodeMatches = false
          · simp [hCanonicalFalse] at accepted
          · have hCanonical : input.canonicalReencodeMatches = true := by
              cases h : input.canonicalReencodeMatches <;>
                simp [h] at hCanonicalFalse ⊢
            exact
              {
                fixedFieldWidths := hFixed,
                payloadCompactPrefixCanonical := hCompact,
                totalLengthMatches := hLength,
                consumedAllBytes := hConsumed,
                canonicalReencodeMatches := hCanonical
              }

theorem accepted_outbound_bridge_action_payload_scale_wire_total_length
    {input : OutboundBridgeActionPayloadScaleWireInput}
    (accepted : outboundBridgeActionPayloadScaleWireAccepts input = true) :
    input.totalBytes =
      outboundBridgeActionPayloadEncodedLen
        input.payloadCompactPrefixBytes
        input.payloadBytes :=
  (outbound_bridge_action_payload_scale_wire_acceptance_exposes_facts
    accepted).totalLengthMatches

def exactDecodeInputOfOutboundBridgeActionPayloadScaleWire
    (input : OutboundBridgeActionPayloadScaleWireInput) : ExactDecodeInput :=
  {
    parserAccepts := outboundBridgeActionPayloadScaleWireAccepts input,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

theorem accepted_outbound_bridge_action_payload_scale_wire_exact_decode
    {input : OutboundBridgeActionPayloadScaleWireInput}
    (accepted : outboundBridgeActionPayloadScaleWireAccepts input = true) :
    exactDecodeAccepts
      (exactDecodeInputOfOutboundBridgeActionPayloadScaleWire input) = true := by
  have facts :=
    outbound_bridge_action_payload_scale_wire_acceptance_exposes_facts accepted
  exact
    (exact_accepts_iff_preconditions
      (input := exactDecodeInputOfOutboundBridgeActionPayloadScaleWire input)).mpr
      (by
        simp [
          exactDecodeInputOfOutboundBridgeActionPayloadScaleWire,
          exactDecodePreconditions,
          accepted,
          facts.consumedAllBytes,
          facts.canonicalReencodeMatches
        ])

def validShortPayload : OutboundBridgeActionPayloadScaleWireInput :=
  {
    destinationChainIdBytes := 32,
    appFamilyIdBytes := 2,
    payloadCompactPrefixBytes := 1,
    payloadBytes := 3,
    payloadCompactPrefixCanonical := true,
    totalBytes := outboundBridgeActionPayloadEncodedLen 1 3,
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

def validEmptyPayload : OutboundBridgeActionPayloadScaleWireInput :=
  {
    validShortPayload with
    payloadBytes := 0,
    totalBytes := outboundBridgeActionPayloadEncodedLen 1 0
  }

theorem valid_short_payload_accepts :
    outboundBridgeActionPayloadScaleWireAccepts validShortPayload = true := by
  rfl

theorem valid_empty_payload_accepts :
    outboundBridgeActionPayloadScaleWireAccepts validEmptyPayload = true := by
  rfl

def payloadLengthOverrun : OutboundBridgeActionPayloadScaleWireInput :=
  {
    validShortPayload with
    payloadBytes := 4,
    totalBytes := outboundBridgeActionPayloadEncodedLen 1 3,
    canonicalReencodeMatches := false
  }

theorem payload_length_overrun_rejects :
    evaluateOutboundBridgeActionPayloadScaleWireRejection
      payloadLengthOverrun =
      some OutboundBridgeActionPayloadScaleWireReject.parserRejected := by
  rfl

def trailingByteCase : OutboundBridgeActionPayloadScaleWireInput :=
  { validShortPayload with consumedAllBytes := false }

theorem trailing_byte_case_rejects :
    evaluateOutboundBridgeActionPayloadScaleWireRejection trailingByteCase =
      some OutboundBridgeActionPayloadScaleWireReject.trailingBytes := by
  rfl

def noncanonicalPayloadCompactPrefix : OutboundBridgeActionPayloadScaleWireInput :=
  {
    validEmptyPayload with
    payloadCompactPrefixBytes := 2,
    payloadCompactPrefixCanonical := false,
    totalBytes := outboundBridgeActionPayloadEncodedLen 2 0,
    canonicalReencodeMatches := false
  }

theorem noncanonical_payload_compact_prefix_rejects :
    evaluateOutboundBridgeActionPayloadScaleWireRejection
      noncanonicalPayloadCompactPrefix =
      some OutboundBridgeActionPayloadScaleWireReject.parserRejected := by
  rfl

end OutboundBridgeActionPayloadScaleWire
end Native
end Hegemon

import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace InboundBridgeActionPayloadScaleWire

open Hegemon.Native.CodecAdmission

inductive InboundBridgeActionPayloadScaleWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure InboundBridgeActionPayloadScaleWireInput where
  sourceChainIdBytes : Nat
  sourceMessageNonceBytes : Nat
  verifierProgramHashBytes : Nat
  proofReceiptCompactPrefixBytes : Nat
  proofReceiptBytes : Nat
  proofReceiptCompactPrefixCanonical : Bool
  messageSourceChainIdBytes : Nat
  messageDestinationChainIdBytes : Nat
  messageAppFamilyIdBytes : Nat
  messageNonceBytes : Nat
  messageSourceHeightBytes : Nat
  messagePayloadHashBytes : Nat
  messagePayloadCompactPrefixBytes : Nat
  messagePayloadBytes : Nat
  messagePayloadCompactPrefixCanonical : Bool
  totalBytes : Nat
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def inboundBridgeMessageEncodedLen
    (messagePayloadCompactPrefixBytes messagePayloadBytes : Nat) : Nat :=
  32 + 32 + 2 + 16 + 8 + 48
    + messagePayloadCompactPrefixBytes
    + messagePayloadBytes

def inboundBridgeActionPayloadEncodedLen
    (proofReceiptCompactPrefixBytes proofReceiptBytes
      messagePayloadCompactPrefixBytes messagePayloadBytes : Nat) : Nat :=
  32 + 16 + 32
    + proofReceiptCompactPrefixBytes
    + proofReceiptBytes
    + inboundBridgeMessageEncodedLen
      messagePayloadCompactPrefixBytes
      messagePayloadBytes

def fixedFieldWidthsOk
    (input : InboundBridgeActionPayloadScaleWireInput) : Bool :=
  input.sourceChainIdBytes == 32
    && input.sourceMessageNonceBytes == 16
    && input.verifierProgramHashBytes == 32
    && input.messageSourceChainIdBytes == 32
    && input.messageDestinationChainIdBytes == 32
    && input.messageAppFamilyIdBytes == 2
    && input.messageNonceBytes == 16
    && input.messageSourceHeightBytes == 8
    && input.messagePayloadHashBytes == 48

def expectedLengthMatches
    (input : InboundBridgeActionPayloadScaleWireInput) : Bool :=
  input.totalBytes ==
    inboundBridgeActionPayloadEncodedLen
      input.proofReceiptCompactPrefixBytes
      input.proofReceiptBytes
      input.messagePayloadCompactPrefixBytes
      input.messagePayloadBytes

def evaluateInboundBridgeActionPayloadScaleWireRejection
    (input : InboundBridgeActionPayloadScaleWireInput) :
    Option InboundBridgeActionPayloadScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some InboundBridgeActionPayloadScaleWireReject.parserRejected
  else if input.proofReceiptCompactPrefixCanonical = false then
    some InboundBridgeActionPayloadScaleWireReject.parserRejected
  else if input.messagePayloadCompactPrefixCanonical = false then
    some InboundBridgeActionPayloadScaleWireReject.parserRejected
  else if expectedLengthMatches input = false then
    some InboundBridgeActionPayloadScaleWireReject.parserRejected
  else if input.consumedAllBytes = false then
    some InboundBridgeActionPayloadScaleWireReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some InboundBridgeActionPayloadScaleWireReject.nonCanonicalEncoding
  else
    none

def inboundBridgeActionPayloadScaleWireAccepts
    (input : InboundBridgeActionPayloadScaleWireInput) : Bool :=
  evaluateInboundBridgeActionPayloadScaleWireRejection input = none

structure AcceptedInboundBridgeActionPayloadScaleWireFacts
    (input : InboundBridgeActionPayloadScaleWireInput) : Prop where
  fixedFieldWidths :
    fixedFieldWidthsOk input = true
  proofReceiptCompactPrefixCanonical :
    input.proofReceiptCompactPrefixCanonical = true
  messagePayloadCompactPrefixCanonical :
    input.messagePayloadCompactPrefixCanonical = true
  totalLengthMatches :
    input.totalBytes =
      inboundBridgeActionPayloadEncodedLen
        input.proofReceiptCompactPrefixBytes
        input.proofReceiptBytes
        input.messagePayloadCompactPrefixBytes
        input.messagePayloadBytes
  consumedAllBytes :
    input.consumedAllBytes = true
  canonicalReencodeMatches :
    input.canonicalReencodeMatches = true

theorem inbound_bridge_action_payload_scale_wire_acceptance_exposes_facts
    {input : InboundBridgeActionPayloadScaleWireInput}
    (accepted : inboundBridgeActionPayloadScaleWireAccepts input = true) :
    AcceptedInboundBridgeActionPayloadScaleWireFacts input := by
  unfold inboundBridgeActionPayloadScaleWireAccepts at accepted
  unfold evaluateInboundBridgeActionPayloadScaleWireRejection at accepted
  by_cases hFixedFalse : fixedFieldWidthsOk input = false
  · simp [hFixedFalse] at accepted
  · have hFixed : fixedFieldWidthsOk input = true := by
      cases h : fixedFieldWidthsOk input <;> simp [h] at hFixedFalse ⊢
    simp [hFixed] at accepted
    by_cases hProofCompactFalse :
        input.proofReceiptCompactPrefixCanonical = false
    · simp [hProofCompactFalse] at accepted
    · have hProofCompact :
          input.proofReceiptCompactPrefixCanonical = true := by
        cases h : input.proofReceiptCompactPrefixCanonical <;>
          simp [h] at hProofCompactFalse ⊢
      simp [hProofCompact] at accepted
      by_cases hPayloadCompactFalse :
          input.messagePayloadCompactPrefixCanonical = false
      · simp [hPayloadCompactFalse] at accepted
      · have hPayloadCompact :
            input.messagePayloadCompactPrefixCanonical = true := by
          cases h : input.messagePayloadCompactPrefixCanonical <;>
            simp [h] at hPayloadCompactFalse ⊢
        simp [hPayloadCompact] at accepted
        by_cases hLengthFalse : expectedLengthMatches input = false
        · simp [hLengthFalse] at accepted
        · have hLengthBool : expectedLengthMatches input = true := by
            cases h : expectedLengthMatches input <;>
              simp [h] at hLengthFalse ⊢
          have hLength :
              input.totalBytes =
                inboundBridgeActionPayloadEncodedLen
                  input.proofReceiptCompactPrefixBytes
                  input.proofReceiptBytes
                  input.messagePayloadCompactPrefixBytes
                  input.messagePayloadBytes := by
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
            · have hCanonical :
                  input.canonicalReencodeMatches = true := by
                cases h : input.canonicalReencodeMatches <;>
                  simp [h] at hCanonicalFalse ⊢
              exact
                {
                  fixedFieldWidths := hFixed,
                  proofReceiptCompactPrefixCanonical := hProofCompact,
                  messagePayloadCompactPrefixCanonical := hPayloadCompact,
                  totalLengthMatches := hLength,
                  consumedAllBytes := hConsumed,
                  canonicalReencodeMatches := hCanonical
                }

theorem accepted_inbound_bridge_action_payload_scale_wire_total_length
    {input : InboundBridgeActionPayloadScaleWireInput}
    (accepted : inboundBridgeActionPayloadScaleWireAccepts input = true) :
    input.totalBytes =
      inboundBridgeActionPayloadEncodedLen
        input.proofReceiptCompactPrefixBytes
        input.proofReceiptBytes
        input.messagePayloadCompactPrefixBytes
        input.messagePayloadBytes :=
  (inbound_bridge_action_payload_scale_wire_acceptance_exposes_facts
    accepted).totalLengthMatches

def exactDecodeInputOfInboundBridgeActionPayloadScaleWire
    (input : InboundBridgeActionPayloadScaleWireInput) : ExactDecodeInput :=
  {
    parserAccepts := inboundBridgeActionPayloadScaleWireAccepts input,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

theorem accepted_inbound_bridge_action_payload_scale_wire_exact_decode
    {input : InboundBridgeActionPayloadScaleWireInput}
    (accepted : inboundBridgeActionPayloadScaleWireAccepts input = true) :
    exactDecodeAccepts
      (exactDecodeInputOfInboundBridgeActionPayloadScaleWire input) = true := by
  have facts :=
    inbound_bridge_action_payload_scale_wire_acceptance_exposes_facts accepted
  exact
    (exact_accepts_iff_preconditions
      (input := exactDecodeInputOfInboundBridgeActionPayloadScaleWire input)).mpr
      (by
        simp [
          exactDecodeInputOfInboundBridgeActionPayloadScaleWire,
          exactDecodePreconditions,
          accepted,
          facts.consumedAllBytes,
          facts.canonicalReencodeMatches
        ])

def validShortReceiptPayload : InboundBridgeActionPayloadScaleWireInput :=
  {
    sourceChainIdBytes := 32,
    sourceMessageNonceBytes := 16,
    verifierProgramHashBytes := 32,
    proofReceiptCompactPrefixBytes := 1,
    proofReceiptBytes := 2,
    proofReceiptCompactPrefixCanonical := true,
    messageSourceChainIdBytes := 32,
    messageDestinationChainIdBytes := 32,
    messageAppFamilyIdBytes := 2,
    messageNonceBytes := 16,
    messageSourceHeightBytes := 8,
    messagePayloadHashBytes := 48,
    messagePayloadCompactPrefixBytes := 1,
    messagePayloadBytes := 3,
    messagePayloadCompactPrefixCanonical := true,
    totalBytes := inboundBridgeActionPayloadEncodedLen 1 2 1 3,
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

def validEmptyReceiptPayload : InboundBridgeActionPayloadScaleWireInput :=
  {
    validShortReceiptPayload with
    proofReceiptBytes := 0,
    messagePayloadBytes := 0,
    totalBytes := inboundBridgeActionPayloadEncodedLen 1 0 1 0
  }

theorem valid_short_receipt_payload_accepts :
    inboundBridgeActionPayloadScaleWireAccepts validShortReceiptPayload =
      true := by
  rfl

theorem valid_empty_receipt_payload_accepts :
    inboundBridgeActionPayloadScaleWireAccepts validEmptyReceiptPayload =
      true := by
  rfl

def proofReceiptLengthOverrun : InboundBridgeActionPayloadScaleWireInput :=
  {
    validShortReceiptPayload with
    proofReceiptBytes := 3,
    totalBytes := 32 + 16 + 32 + 1 + 2,
    canonicalReencodeMatches := false
  }

theorem proof_receipt_length_overrun_rejects :
    evaluateInboundBridgeActionPayloadScaleWireRejection
      proofReceiptLengthOverrun =
      some InboundBridgeActionPayloadScaleWireReject.parserRejected := by
  rfl

def messagePayloadLengthOverrun : InboundBridgeActionPayloadScaleWireInput :=
  {
    validShortReceiptPayload with
    messagePayloadBytes := 4,
    totalBytes := inboundBridgeActionPayloadEncodedLen 1 2 1 3,
    canonicalReencodeMatches := false
  }

theorem message_payload_length_overrun_rejects :
    evaluateInboundBridgeActionPayloadScaleWireRejection
      messagePayloadLengthOverrun =
      some InboundBridgeActionPayloadScaleWireReject.parserRejected := by
  rfl

def trailingByteCase : InboundBridgeActionPayloadScaleWireInput :=
  { validShortReceiptPayload with consumedAllBytes := false }

theorem trailing_byte_case_rejects :
    evaluateInboundBridgeActionPayloadScaleWireRejection trailingByteCase =
      some InboundBridgeActionPayloadScaleWireReject.trailingBytes := by
  rfl

def noncanonicalProofReceiptCompactPrefix :
    InboundBridgeActionPayloadScaleWireInput :=
  {
    validEmptyReceiptPayload with
    proofReceiptCompactPrefixBytes := 2,
    proofReceiptCompactPrefixCanonical := false,
    totalBytes := inboundBridgeActionPayloadEncodedLen 2 0 1 0,
    canonicalReencodeMatches := false
  }

theorem noncanonical_proof_receipt_compact_prefix_rejects :
    evaluateInboundBridgeActionPayloadScaleWireRejection
      noncanonicalProofReceiptCompactPrefix =
      some InboundBridgeActionPayloadScaleWireReject.parserRejected := by
  rfl

def noncanonicalMessagePayloadCompactPrefix :
    InboundBridgeActionPayloadScaleWireInput :=
  {
    validEmptyReceiptPayload with
    messagePayloadCompactPrefixBytes := 2,
    messagePayloadCompactPrefixCanonical := false,
    totalBytes := inboundBridgeActionPayloadEncodedLen 1 0 2 0,
    canonicalReencodeMatches := false
  }

theorem noncanonical_message_payload_compact_prefix_rejects :
    evaluateInboundBridgeActionPayloadScaleWireRejection
      noncanonicalMessagePayloadCompactPrefix =
      some InboundBridgeActionPayloadScaleWireReject.parserRejected := by
  rfl

end InboundBridgeActionPayloadScaleWire
end Native
end Hegemon

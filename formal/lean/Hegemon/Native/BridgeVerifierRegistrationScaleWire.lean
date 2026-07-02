import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace BridgeVerifierRegistrationScaleWire

open Hegemon.Native.CodecAdmission

inductive BridgeVerifierRegistrationScaleWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure BridgeVerifierRegistrationScaleWireInput where
  sourceChainIdBytes : Nat
  verifierProgramHashBytes : Nat
  rulesHashBytes : Nat
  enabledAtHeightBytes : Nat
  totalBytes : Nat
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def bridgeVerifierRegistrationEncodedLen : Nat :=
  32 + 32 + 32 + 8

def fixedFieldWidthsOk
    (input : BridgeVerifierRegistrationScaleWireInput) : Bool :=
  input.sourceChainIdBytes == 32
    && input.verifierProgramHashBytes == 32
    && input.rulesHashBytes == 32
    && input.enabledAtHeightBytes == 8

def expectedLengthMatches
    (input : BridgeVerifierRegistrationScaleWireInput) : Bool :=
  input.totalBytes == bridgeVerifierRegistrationEncodedLen

def evaluateBridgeVerifierRegistrationScaleWireRejection
    (input : BridgeVerifierRegistrationScaleWireInput) :
    Option BridgeVerifierRegistrationScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some BridgeVerifierRegistrationScaleWireReject.parserRejected
  else if expectedLengthMatches input = false then
    some BridgeVerifierRegistrationScaleWireReject.parserRejected
  else if input.consumedAllBytes = false then
    some BridgeVerifierRegistrationScaleWireReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some BridgeVerifierRegistrationScaleWireReject.nonCanonicalEncoding
  else
    none

def bridgeVerifierRegistrationScaleWireAccepts
    (input : BridgeVerifierRegistrationScaleWireInput) : Bool :=
  evaluateBridgeVerifierRegistrationScaleWireRejection input = none

structure AcceptedBridgeVerifierRegistrationScaleWireFacts
    (input : BridgeVerifierRegistrationScaleWireInput) : Prop where
  fixedFieldWidths :
    fixedFieldWidthsOk input = true
  totalLengthMatches :
    input.totalBytes = bridgeVerifierRegistrationEncodedLen
  consumedAllBytes :
    input.consumedAllBytes = true
  canonicalReencodeMatches :
    input.canonicalReencodeMatches = true

theorem bridge_verifier_registration_scale_wire_acceptance_exposes_facts
    {input : BridgeVerifierRegistrationScaleWireInput}
    (accepted : bridgeVerifierRegistrationScaleWireAccepts input = true) :
    AcceptedBridgeVerifierRegistrationScaleWireFacts input := by
  unfold bridgeVerifierRegistrationScaleWireAccepts at accepted
  unfold evaluateBridgeVerifierRegistrationScaleWireRejection at accepted
  by_cases hFixedFalse : fixedFieldWidthsOk input = false
  · simp [hFixedFalse] at accepted
  · have hFixed : fixedFieldWidthsOk input = true := by
      cases h : fixedFieldWidthsOk input <;> simp [h] at hFixedFalse ⊢
    simp [hFixed] at accepted
    by_cases hLengthFalse : expectedLengthMatches input = false
    · simp [hLengthFalse] at accepted
    · have hLengthBool : expectedLengthMatches input = true := by
        cases h : expectedLengthMatches input <;>
          simp [h] at hLengthFalse ⊢
      have hLength :
          input.totalBytes = bridgeVerifierRegistrationEncodedLen := by
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
              totalLengthMatches := hLength,
              consumedAllBytes := hConsumed,
              canonicalReencodeMatches := hCanonical
            }

theorem accepted_bridge_verifier_registration_scale_wire_total_length
    {input : BridgeVerifierRegistrationScaleWireInput}
    (accepted : bridgeVerifierRegistrationScaleWireAccepts input = true) :
    input.totalBytes = bridgeVerifierRegistrationEncodedLen :=
  (bridge_verifier_registration_scale_wire_acceptance_exposes_facts
    accepted).totalLengthMatches

def exactDecodeInputOfBridgeVerifierRegistrationScaleWire
    (input : BridgeVerifierRegistrationScaleWireInput) : ExactDecodeInput :=
  {
    parserAccepts := bridgeVerifierRegistrationScaleWireAccepts input,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

theorem accepted_bridge_verifier_registration_scale_wire_exact_decode
    {input : BridgeVerifierRegistrationScaleWireInput}
    (accepted : bridgeVerifierRegistrationScaleWireAccepts input = true) :
    exactDecodeAccepts
      (exactDecodeInputOfBridgeVerifierRegistrationScaleWire input) = true := by
  have facts :=
    bridge_verifier_registration_scale_wire_acceptance_exposes_facts accepted
  exact
    (exact_accepts_iff_preconditions
      (input := exactDecodeInputOfBridgeVerifierRegistrationScaleWire input)).mpr
      (by
        simp [
          exactDecodeInputOfBridgeVerifierRegistrationScaleWire,
          exactDecodePreconditions,
          accepted,
          facts.consumedAllBytes,
          facts.canonicalReencodeMatches
        ])

def validRegistration : BridgeVerifierRegistrationScaleWireInput :=
  {
    sourceChainIdBytes := 32,
    verifierProgramHashBytes := 32,
    rulesHashBytes := 32,
    enabledAtHeightBytes := 8,
    totalBytes := bridgeVerifierRegistrationEncodedLen,
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

theorem valid_registration_accepts :
    bridgeVerifierRegistrationScaleWireAccepts validRegistration = true := by
  rfl

def shortRegistration : BridgeVerifierRegistrationScaleWireInput :=
  {
    validRegistration with
    totalBytes := bridgeVerifierRegistrationEncodedLen - 1,
    canonicalReencodeMatches := false
  }

theorem short_registration_rejects :
    evaluateBridgeVerifierRegistrationScaleWireRejection
      shortRegistration =
      some BridgeVerifierRegistrationScaleWireReject.parserRejected := by
  rfl

def trailingByteCase : BridgeVerifierRegistrationScaleWireInput :=
  { validRegistration with consumedAllBytes := false }

theorem trailing_byte_case_rejects :
    evaluateBridgeVerifierRegistrationScaleWireRejection trailingByteCase =
      some BridgeVerifierRegistrationScaleWireReject.trailingBytes := by
  rfl

def noncanonicalReencodeCase : BridgeVerifierRegistrationScaleWireInput :=
  { validRegistration with canonicalReencodeMatches := false }

theorem noncanonical_reencode_case_rejects :
    evaluateBridgeVerifierRegistrationScaleWireRejection
      noncanonicalReencodeCase =
      some BridgeVerifierRegistrationScaleWireReject.nonCanonicalEncoding := by
  rfl

end BridgeVerifierRegistrationScaleWire
end Native
end Hegemon

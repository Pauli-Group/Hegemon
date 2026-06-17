import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace CoinbaseActionPayloadScaleWire

open Hegemon.Native.CodecAdmission

inductive CoinbaseActionPayloadScaleWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure CoinbaseActionPayloadScaleWireInput where
  commitmentBytes : Nat
  noteCiphertextBytes : Nat
  kemCiphertextCompactPrefixBytes : Nat
  kemCiphertextBytes : Nat
  kemCiphertextCompactPrefixCanonical : Bool
  recipientAddressBytes : Nat
  amountBytes : Nat
  publicSeedBytes : Nat
  totalBytes : Nat
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def coinbaseActionPayloadEncodedLen
    (kemCiphertextCompactPrefixBytes kemCiphertextBytes : Nat) : Nat :=
  48 + 579 + kemCiphertextCompactPrefixBytes + kemCiphertextBytes + 69 + 8 + 32

def fixedFieldWidthsOk
    (input : CoinbaseActionPayloadScaleWireInput) : Bool :=
  input.commitmentBytes == 48
    && input.noteCiphertextBytes == 579
    && input.recipientAddressBytes == 69
    && input.amountBytes == 8
    && input.publicSeedBytes == 32

def expectedLengthMatches
    (input : CoinbaseActionPayloadScaleWireInput) : Bool :=
  input.totalBytes ==
    coinbaseActionPayloadEncodedLen
      input.kemCiphertextCompactPrefixBytes
      input.kemCiphertextBytes

def evaluateCoinbaseActionPayloadScaleWireRejection
    (input : CoinbaseActionPayloadScaleWireInput) :
    Option CoinbaseActionPayloadScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some CoinbaseActionPayloadScaleWireReject.parserRejected
  else if input.kemCiphertextCompactPrefixCanonical = false then
    some CoinbaseActionPayloadScaleWireReject.parserRejected
  else if expectedLengthMatches input = false then
    some CoinbaseActionPayloadScaleWireReject.parserRejected
  else if input.consumedAllBytes = false then
    some CoinbaseActionPayloadScaleWireReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some CoinbaseActionPayloadScaleWireReject.nonCanonicalEncoding
  else
    none

def coinbaseActionPayloadScaleWireAccepts
    (input : CoinbaseActionPayloadScaleWireInput) : Bool :=
  evaluateCoinbaseActionPayloadScaleWireRejection input = none

structure AcceptedCoinbaseActionPayloadScaleWireFacts
    (input : CoinbaseActionPayloadScaleWireInput) : Prop where
  fixedFieldWidths :
    fixedFieldWidthsOk input = true
  kemCiphertextCompactPrefixCanonical :
    input.kemCiphertextCompactPrefixCanonical = true
  totalLengthMatches :
    input.totalBytes =
      coinbaseActionPayloadEncodedLen
        input.kemCiphertextCompactPrefixBytes
        input.kemCiphertextBytes
  consumedAllBytes :
    input.consumedAllBytes = true
  canonicalReencodeMatches :
    input.canonicalReencodeMatches = true

theorem coinbase_action_payload_scale_wire_acceptance_exposes_facts
    {input : CoinbaseActionPayloadScaleWireInput}
    (accepted : coinbaseActionPayloadScaleWireAccepts input = true) :
    AcceptedCoinbaseActionPayloadScaleWireFacts input := by
  unfold coinbaseActionPayloadScaleWireAccepts at accepted
  unfold evaluateCoinbaseActionPayloadScaleWireRejection at accepted
  by_cases hFixedFalse : fixedFieldWidthsOk input = false
  · simp [hFixedFalse] at accepted
  · have hFixed : fixedFieldWidthsOk input = true := by
      cases h : fixedFieldWidthsOk input <;> simp [h] at hFixedFalse ⊢
    simp [hFixed] at accepted
    by_cases hCompactFalse :
        input.kemCiphertextCompactPrefixCanonical = false
    · simp [hCompactFalse] at accepted
    · have hCompact :
          input.kemCiphertextCompactPrefixCanonical = true := by
        cases h : input.kemCiphertextCompactPrefixCanonical <;>
          simp [h] at hCompactFalse ⊢
      simp [hCompact] at accepted
      by_cases hLengthFalse : expectedLengthMatches input = false
      · simp [hLengthFalse] at accepted
      · have hLengthBool : expectedLengthMatches input = true := by
          cases h : expectedLengthMatches input <;>
            simp [h] at hLengthFalse ⊢
        have hLength :
            input.totalBytes =
              coinbaseActionPayloadEncodedLen
                input.kemCiphertextCompactPrefixBytes
                input.kemCiphertextBytes := by
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
                kemCiphertextCompactPrefixCanonical := hCompact,
                totalLengthMatches := hLength,
                consumedAllBytes := hConsumed,
                canonicalReencodeMatches := hCanonical
              }

theorem accepted_coinbase_action_payload_scale_wire_total_length
    {input : CoinbaseActionPayloadScaleWireInput}
    (accepted : coinbaseActionPayloadScaleWireAccepts input = true) :
    input.totalBytes =
      coinbaseActionPayloadEncodedLen
        input.kemCiphertextCompactPrefixBytes
        input.kemCiphertextBytes :=
  (coinbase_action_payload_scale_wire_acceptance_exposes_facts accepted).totalLengthMatches

def exactDecodeInputOfCoinbaseActionPayloadScaleWire
    (input : CoinbaseActionPayloadScaleWireInput) : ExactDecodeInput :=
  {
    parserAccepts := coinbaseActionPayloadScaleWireAccepts input,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

theorem accepted_coinbase_action_payload_scale_wire_exact_decode
    {input : CoinbaseActionPayloadScaleWireInput}
    (accepted : coinbaseActionPayloadScaleWireAccepts input = true) :
    exactDecodeAccepts
      (exactDecodeInputOfCoinbaseActionPayloadScaleWire input) = true := by
  have facts :=
    coinbase_action_payload_scale_wire_acceptance_exposes_facts accepted
  exact
    (exact_accepts_iff_preconditions
      (input := exactDecodeInputOfCoinbaseActionPayloadScaleWire input)).mpr
      (by
        simp [
          exactDecodeInputOfCoinbaseActionPayloadScaleWire,
          exactDecodePreconditions,
          accepted,
          facts.consumedAllBytes,
          facts.canonicalReencodeMatches
        ])

def validShortKemPayload : CoinbaseActionPayloadScaleWireInput :=
  {
    commitmentBytes := 48,
    noteCiphertextBytes := 579,
    kemCiphertextCompactPrefixBytes := 1,
    kemCiphertextBytes := 3,
    kemCiphertextCompactPrefixCanonical := true,
    recipientAddressBytes := 69,
    amountBytes := 8,
    publicSeedBytes := 32,
    totalBytes := coinbaseActionPayloadEncodedLen 1 3,
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

def validZeroKemPayload : CoinbaseActionPayloadScaleWireInput :=
  {
    validShortKemPayload with
    kemCiphertextBytes := 0,
    totalBytes := coinbaseActionPayloadEncodedLen 1 0
  }

theorem valid_short_kem_payload_accepts :
    coinbaseActionPayloadScaleWireAccepts validShortKemPayload = true := by
  rfl

theorem valid_zero_kem_payload_accepts :
    coinbaseActionPayloadScaleWireAccepts validZeroKemPayload = true := by
  rfl

def kemCiphertextLengthOverrun : CoinbaseActionPayloadScaleWireInput :=
  {
    validShortKemPayload with
    kemCiphertextBytes := 4,
    totalBytes := coinbaseActionPayloadEncodedLen 1 3,
    canonicalReencodeMatches := false
  }

theorem kem_ciphertext_length_overrun_rejects :
    evaluateCoinbaseActionPayloadScaleWireRejection
      kemCiphertextLengthOverrun =
      some CoinbaseActionPayloadScaleWireReject.parserRejected := by
  rfl

def trailingByteCase : CoinbaseActionPayloadScaleWireInput :=
  { validShortKemPayload with consumedAllBytes := false }

theorem trailing_byte_case_rejects :
    evaluateCoinbaseActionPayloadScaleWireRejection trailingByteCase =
      some CoinbaseActionPayloadScaleWireReject.trailingBytes := by
  rfl

def noncanonicalKemCompactPrefix : CoinbaseActionPayloadScaleWireInput :=
  {
    validZeroKemPayload with
    kemCiphertextCompactPrefixBytes := 2,
    kemCiphertextCompactPrefixCanonical := false,
    totalBytes := coinbaseActionPayloadEncodedLen 2 0,
    canonicalReencodeMatches := false
  }

theorem noncanonical_kem_compact_prefix_rejects :
    evaluateCoinbaseActionPayloadScaleWireRejection
      noncanonicalKemCompactPrefix =
      some CoinbaseActionPayloadScaleWireReject.parserRejected := by
  rfl

end CoinbaseActionPayloadScaleWire
end Native
end Hegemon

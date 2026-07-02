import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace ShieldedTransferSidecarScaleWire

open Hegemon.Native.CodecAdmission

inductive ShieldedTransferSidecarScaleWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure ShieldedTransferSidecarScaleWireInput where
  proofCompactPrefixBytes : Nat
  proofBytes : Nat
  proofCompactPrefixCanonical : Bool
  commitmentCompactPrefixBytes : Nat
  commitmentCount : Nat
  commitmentElementBytes : Nat
  commitmentCompactPrefixCanonical : Bool
  ciphertextHashCompactPrefixBytes : Nat
  ciphertextHashCount : Nat
  ciphertextHashElementBytes : Nat
  ciphertextHashCompactPrefixCanonical : Bool
  ciphertextSizeCompactPrefixBytes : Nat
  ciphertextSizeCount : Nat
  ciphertextSizeElementBytes : Nat
  ciphertextSizeCompactPrefixCanonical : Bool
  anchorBytes : Nat
  balanceSlotCount : Nat
  balanceSlotBytes : Nat
  bindingHashBytes : Nat
  stablecoinOptionTagBytes : Nat
  stablecoinSomePayloadBytes : Nat
  feeBytes : Nat
  totalBytes : Nat
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def shieldedTransferSidecarEncodedLen
    (input : ShieldedTransferSidecarScaleWireInput) : Nat :=
  input.proofCompactPrefixBytes
    + input.proofBytes
    + input.commitmentCompactPrefixBytes
    + input.commitmentCount * input.commitmentElementBytes
    + input.ciphertextHashCompactPrefixBytes
    + input.ciphertextHashCount * input.ciphertextHashElementBytes
    + input.ciphertextSizeCompactPrefixBytes
    + input.ciphertextSizeCount * input.ciphertextSizeElementBytes
    + input.anchorBytes
    + input.balanceSlotBytes
    + input.bindingHashBytes
    + input.stablecoinOptionTagBytes
    + input.stablecoinSomePayloadBytes
    + input.feeBytes

def fixedFieldWidthsOk
    (input : ShieldedTransferSidecarScaleWireInput) : Bool :=
  input.commitmentElementBytes == 48
    && input.ciphertextHashElementBytes == 48
    && input.ciphertextSizeElementBytes == 4
    && input.anchorBytes == 48
    && input.balanceSlotCount == 4
    && input.balanceSlotBytes == 32
    && input.bindingHashBytes == 64
    && input.stablecoinOptionTagBytes == 1
    && input.feeBytes == 8

def compactPrefixesCanonical
    (input : ShieldedTransferSidecarScaleWireInput) : Bool :=
  input.proofCompactPrefixCanonical
    && input.commitmentCompactPrefixCanonical
    && input.ciphertextHashCompactPrefixCanonical
    && input.ciphertextSizeCompactPrefixCanonical

def expectedLengthMatches
    (input : ShieldedTransferSidecarScaleWireInput) : Bool :=
  input.totalBytes == shieldedTransferSidecarEncodedLen input

def evaluateShieldedTransferSidecarScaleWireRejection
    (input : ShieldedTransferSidecarScaleWireInput) :
    Option ShieldedTransferSidecarScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some ShieldedTransferSidecarScaleWireReject.parserRejected
  else if compactPrefixesCanonical input = false then
    some ShieldedTransferSidecarScaleWireReject.parserRejected
  else if expectedLengthMatches input = false then
    some ShieldedTransferSidecarScaleWireReject.parserRejected
  else if input.consumedAllBytes = false then
    some ShieldedTransferSidecarScaleWireReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some ShieldedTransferSidecarScaleWireReject.nonCanonicalEncoding
  else
    none

def shieldedTransferSidecarScaleWireAccepts
    (input : ShieldedTransferSidecarScaleWireInput) : Bool :=
  evaluateShieldedTransferSidecarScaleWireRejection input = none

structure AcceptedShieldedTransferSidecarScaleWireFacts
    (input : ShieldedTransferSidecarScaleWireInput) : Prop where
  fixedFieldWidths :
    fixedFieldWidthsOk input = true
  compactPrefixes :
    compactPrefixesCanonical input = true
  totalLengthMatches :
    input.totalBytes = shieldedTransferSidecarEncodedLen input
  consumedAllBytes :
    input.consumedAllBytes = true
  canonicalReencodeMatches :
    input.canonicalReencodeMatches = true

theorem shielded_transfer_sidecar_scale_wire_acceptance_exposes_facts
    {input : ShieldedTransferSidecarScaleWireInput}
    (accepted : shieldedTransferSidecarScaleWireAccepts input = true) :
    AcceptedShieldedTransferSidecarScaleWireFacts input := by
  unfold shieldedTransferSidecarScaleWireAccepts at accepted
  unfold evaluateShieldedTransferSidecarScaleWireRejection at accepted
  by_cases hFixedFalse : fixedFieldWidthsOk input = false
  · simp [hFixedFalse] at accepted
  · have hFixed : fixedFieldWidthsOk input = true := by
      cases h : fixedFieldWidthsOk input <;> simp [h] at hFixedFalse ⊢
    simp [hFixed] at accepted
    by_cases hCompactFalse : compactPrefixesCanonical input = false
    · simp [hCompactFalse] at accepted
    · have hCompact : compactPrefixesCanonical input = true := by
        cases h : compactPrefixesCanonical input <;>
          simp [h] at hCompactFalse ⊢
      simp [hCompact] at accepted
      by_cases hLengthFalse : expectedLengthMatches input = false
      · simp [hLengthFalse] at accepted
      · have hLengthBool : expectedLengthMatches input = true := by
          cases h : expectedLengthMatches input <;>
            simp [h] at hLengthFalse ⊢
        have hLength :
            input.totalBytes = shieldedTransferSidecarEncodedLen input := by
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
                compactPrefixes := hCompact,
                totalLengthMatches := hLength,
                consumedAllBytes := hConsumed,
                canonicalReencodeMatches := hCanonical
              }

theorem accepted_shielded_transfer_sidecar_scale_wire_total_length
    {input : ShieldedTransferSidecarScaleWireInput}
    (accepted : shieldedTransferSidecarScaleWireAccepts input = true) :
    input.totalBytes = shieldedTransferSidecarEncodedLen input :=
  (shielded_transfer_sidecar_scale_wire_acceptance_exposes_facts
    accepted).totalLengthMatches

def exactDecodeInputOfShieldedTransferSidecarScaleWire
    (input : ShieldedTransferSidecarScaleWireInput) : ExactDecodeInput :=
  {
    parserAccepts := shieldedTransferSidecarScaleWireAccepts input,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

theorem accepted_shielded_transfer_sidecar_scale_wire_exact_decode
    {input : ShieldedTransferSidecarScaleWireInput}
    (accepted : shieldedTransferSidecarScaleWireAccepts input = true) :
    exactDecodeAccepts
      (exactDecodeInputOfShieldedTransferSidecarScaleWire input) = true := by
  have facts :=
    shielded_transfer_sidecar_scale_wire_acceptance_exposes_facts accepted
  exact
    (exact_accepts_iff_preconditions
      (input := exactDecodeInputOfShieldedTransferSidecarScaleWire input)).mpr
      (by
        simp [
          exactDecodeInputOfShieldedTransferSidecarScaleWire,
          exactDecodePreconditions,
          accepted,
          facts.consumedAllBytes,
          facts.canonicalReencodeMatches
        ])

def validOneOutputSidecar : ShieldedTransferSidecarScaleWireInput :=
  {
    proofCompactPrefixBytes := 1,
    proofBytes := 3,
    proofCompactPrefixCanonical := true,
    commitmentCompactPrefixBytes := 1,
    commitmentCount := 1,
    commitmentElementBytes := 48,
    commitmentCompactPrefixCanonical := true,
    ciphertextHashCompactPrefixBytes := 1,
    ciphertextHashCount := 1,
    ciphertextHashElementBytes := 48,
    ciphertextHashCompactPrefixCanonical := true,
    ciphertextSizeCompactPrefixBytes := 1,
    ciphertextSizeCount := 1,
    ciphertextSizeElementBytes := 4,
    ciphertextSizeCompactPrefixCanonical := true,
    anchorBytes := 48,
    balanceSlotCount := 4,
    balanceSlotBytes := 32,
    bindingHashBytes := 64,
    stablecoinOptionTagBytes := 1,
    stablecoinSomePayloadBytes := 0,
    feeBytes := 8,
    totalBytes := 260,
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

def validEmptySidecar : ShieldedTransferSidecarScaleWireInput :=
  {
    validOneOutputSidecar with
    proofBytes := 0,
    commitmentCount := 0,
    ciphertextHashCount := 0,
    ciphertextSizeCount := 0,
    totalBytes := shieldedTransferSidecarEncodedLen {
      validOneOutputSidecar with
      proofBytes := 0,
      commitmentCount := 0,
      ciphertextHashCount := 0,
      ciphertextSizeCount := 0
    }
  }

def validStablecoinSidecar : ShieldedTransferSidecarScaleWireInput :=
  {
    validOneOutputSidecar with
    stablecoinSomePayloadBytes := 172,
    totalBytes := shieldedTransferSidecarEncodedLen {
      validOneOutputSidecar with
      stablecoinSomePayloadBytes := 172
    }
  }

theorem valid_one_output_sidecar_accepts :
    shieldedTransferSidecarScaleWireAccepts validOneOutputSidecar = true := by
  rfl

theorem valid_empty_sidecar_accepts :
    shieldedTransferSidecarScaleWireAccepts validEmptySidecar = true := by
  rfl

theorem valid_stablecoin_sidecar_accepts :
    shieldedTransferSidecarScaleWireAccepts validStablecoinSidecar = true := by
  rfl

def proofLengthOverrun : ShieldedTransferSidecarScaleWireInput :=
  {
    validOneOutputSidecar with
    proofBytes := 4,
    totalBytes := 1 + 3,
    canonicalReencodeMatches := false
  }

theorem proof_length_overrun_rejects :
    evaluateShieldedTransferSidecarScaleWireRejection
      proofLengthOverrun =
      some ShieldedTransferSidecarScaleWireReject.parserRejected := by
  rfl

def ciphertextHashCountOverrun : ShieldedTransferSidecarScaleWireInput :=
  {
    validOneOutputSidecar with
    proofBytes := 0,
    commitmentCount := 0,
    ciphertextHashCount := 2,
    ciphertextSizeCount := 0,
    totalBytes := 1 + 1 + 1 + 48,
    canonicalReencodeMatches := false
  }

theorem ciphertext_hash_count_overrun_rejects :
    evaluateShieldedTransferSidecarScaleWireRejection
      ciphertextHashCountOverrun =
      some ShieldedTransferSidecarScaleWireReject.parserRejected := by
  rfl

def ciphertextHashLengthOverrun : ShieldedTransferSidecarScaleWireInput :=
  {
    validOneOutputSidecar with
    proofBytes := 0,
    commitmentCount := 0,
    ciphertextHashCount := 1,
    ciphertextSizeCount := 0,
    totalBytes := 1 + 1 + 1 + 47,
    canonicalReencodeMatches := false
  }

theorem ciphertext_hash_length_overrun_rejects :
    evaluateShieldedTransferSidecarScaleWireRejection
      ciphertextHashLengthOverrun =
      some ShieldedTransferSidecarScaleWireReject.parserRejected := by
  rfl

def ciphertextSizeCountOverrun : ShieldedTransferSidecarScaleWireInput :=
  {
    validOneOutputSidecar with
    proofBytes := 0,
    commitmentCount := 0,
    ciphertextHashCount := 0,
    ciphertextSizeCount := 2,
    totalBytes := 1 + 1 + 1 + 1 + 4,
    canonicalReencodeMatches := false
  }

theorem ciphertext_size_count_overrun_rejects :
    evaluateShieldedTransferSidecarScaleWireRejection
      ciphertextSizeCountOverrun =
      some ShieldedTransferSidecarScaleWireReject.parserRejected := by
  rfl

def ciphertextSizeLengthOverrun : ShieldedTransferSidecarScaleWireInput :=
  {
    validOneOutputSidecar with
    proofBytes := 0,
    commitmentCount := 0,
    ciphertextHashCount := 0,
    ciphertextSizeCount := 1,
    totalBytes := 1 + 1 + 1 + 1 + 3,
    canonicalReencodeMatches := false
  }

theorem ciphertext_size_length_overrun_rejects :
    evaluateShieldedTransferSidecarScaleWireRejection
      ciphertextSizeLengthOverrun =
      some ShieldedTransferSidecarScaleWireReject.parserRejected := by
  rfl

def trailingByteCase : ShieldedTransferSidecarScaleWireInput :=
  { validOneOutputSidecar with consumedAllBytes := false }

theorem trailing_byte_case_rejects :
    evaluateShieldedTransferSidecarScaleWireRejection trailingByteCase =
      some ShieldedTransferSidecarScaleWireReject.trailingBytes := by
  rfl

def noncanonicalProofCompactPrefix : ShieldedTransferSidecarScaleWireInput :=
  {
    validEmptySidecar with
    proofCompactPrefixBytes := 2,
    proofCompactPrefixCanonical := false,
    totalBytes := shieldedTransferSidecarEncodedLen {
      validEmptySidecar with
      proofCompactPrefixBytes := 2
    },
    canonicalReencodeMatches := false
  }

theorem noncanonical_proof_compact_prefix_rejects :
    evaluateShieldedTransferSidecarScaleWireRejection
      noncanonicalProofCompactPrefix =
      some ShieldedTransferSidecarScaleWireReject.parserRejected := by
  rfl

end ShieldedTransferSidecarScaleWire
end Native
end Hegemon

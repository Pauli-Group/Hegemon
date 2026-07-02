import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace ShieldedTransferInlineScaleWire

open Hegemon.Native.CodecAdmission

inductive ShieldedTransferInlineScaleWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure ShieldedTransferInlineScaleWireInput where
  proofCompactPrefixBytes : Nat
  proofBytes : Nat
  proofCompactPrefixCanonical : Bool
  commitmentCompactPrefixBytes : Nat
  commitmentCount : Nat
  commitmentElementBytes : Nat
  commitmentCompactPrefixCanonical : Bool
  ciphertextCompactPrefixBytes : Nat
  ciphertextCount : Nat
  encryptedNoteCiphertextBytes : Nat
  kemCiphertextCompactPrefixBytes : Nat
  kemCiphertextBytes : Nat
  ciphertextCompactPrefixCanonical : Bool
  kemCiphertextCompactPrefixCanonical : Bool
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

def shieldedTransferInlineEncodedLen
    (input : ShieldedTransferInlineScaleWireInput) : Nat :=
  input.proofCompactPrefixBytes
    + input.proofBytes
    + input.commitmentCompactPrefixBytes
    + input.commitmentCount * input.commitmentElementBytes
    + input.ciphertextCompactPrefixBytes
    + input.ciphertextCount *
      (input.encryptedNoteCiphertextBytes
        + input.kemCiphertextCompactPrefixBytes
        + input.kemCiphertextBytes)
    + input.anchorBytes
    + input.balanceSlotBytes
    + input.bindingHashBytes
    + input.stablecoinOptionTagBytes
    + input.stablecoinSomePayloadBytes
    + input.feeBytes

def fixedFieldWidthsOk
    (input : ShieldedTransferInlineScaleWireInput) : Bool :=
  input.commitmentElementBytes == 48
    && input.encryptedNoteCiphertextBytes == 579
    && input.anchorBytes == 48
    && input.balanceSlotCount == 4
    && input.balanceSlotBytes == 32
    && input.bindingHashBytes == 64
    && input.stablecoinOptionTagBytes == 1
    && input.feeBytes == 8

def compactPrefixesCanonical
    (input : ShieldedTransferInlineScaleWireInput) : Bool :=
  input.proofCompactPrefixCanonical
    && input.commitmentCompactPrefixCanonical
    && input.ciphertextCompactPrefixCanonical
    && input.kemCiphertextCompactPrefixCanonical

def expectedLengthMatches
    (input : ShieldedTransferInlineScaleWireInput) : Bool :=
  input.totalBytes == shieldedTransferInlineEncodedLen input

def evaluateShieldedTransferInlineScaleWireRejection
    (input : ShieldedTransferInlineScaleWireInput) :
    Option ShieldedTransferInlineScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some ShieldedTransferInlineScaleWireReject.parserRejected
  else if compactPrefixesCanonical input = false then
    some ShieldedTransferInlineScaleWireReject.parserRejected
  else if expectedLengthMatches input = false then
    some ShieldedTransferInlineScaleWireReject.parserRejected
  else if input.consumedAllBytes = false then
    some ShieldedTransferInlineScaleWireReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some ShieldedTransferInlineScaleWireReject.nonCanonicalEncoding
  else
    none

def shieldedTransferInlineScaleWireAccepts
    (input : ShieldedTransferInlineScaleWireInput) : Bool :=
  evaluateShieldedTransferInlineScaleWireRejection input = none

structure AcceptedShieldedTransferInlineScaleWireFacts
    (input : ShieldedTransferInlineScaleWireInput) : Prop where
  fixedFieldWidths :
    fixedFieldWidthsOk input = true
  compactPrefixes :
    compactPrefixesCanonical input = true
  totalLengthMatches :
    input.totalBytes = shieldedTransferInlineEncodedLen input
  consumedAllBytes :
    input.consumedAllBytes = true
  canonicalReencodeMatches :
    input.canonicalReencodeMatches = true

theorem shielded_transfer_inline_scale_wire_acceptance_exposes_facts
    {input : ShieldedTransferInlineScaleWireInput}
    (accepted : shieldedTransferInlineScaleWireAccepts input = true) :
    AcceptedShieldedTransferInlineScaleWireFacts input := by
  unfold shieldedTransferInlineScaleWireAccepts at accepted
  unfold evaluateShieldedTransferInlineScaleWireRejection at accepted
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
            input.totalBytes = shieldedTransferInlineEncodedLen input := by
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

theorem accepted_shielded_transfer_inline_scale_wire_total_length
    {input : ShieldedTransferInlineScaleWireInput}
    (accepted : shieldedTransferInlineScaleWireAccepts input = true) :
    input.totalBytes = shieldedTransferInlineEncodedLen input :=
  (shielded_transfer_inline_scale_wire_acceptance_exposes_facts
    accepted).totalLengthMatches

def exactDecodeInputOfShieldedTransferInlineScaleWire
    (input : ShieldedTransferInlineScaleWireInput) : ExactDecodeInput :=
  {
    parserAccepts := shieldedTransferInlineScaleWireAccepts input,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

theorem accepted_shielded_transfer_inline_scale_wire_exact_decode
    {input : ShieldedTransferInlineScaleWireInput}
    (accepted : shieldedTransferInlineScaleWireAccepts input = true) :
    exactDecodeAccepts
      (exactDecodeInputOfShieldedTransferInlineScaleWire input) = true := by
  have facts :=
    shielded_transfer_inline_scale_wire_acceptance_exposes_facts accepted
  exact
    (exact_accepts_iff_preconditions
      (input := exactDecodeInputOfShieldedTransferInlineScaleWire input)).mpr
      (by
        simp [
          exactDecodeInputOfShieldedTransferInlineScaleWire,
          exactDecodePreconditions,
          accepted,
          facts.consumedAllBytes,
          facts.canonicalReencodeMatches
        ])

def validOneOutputInline : ShieldedTransferInlineScaleWireInput :=
  {
    proofCompactPrefixBytes := 1,
    proofBytes := 3,
    proofCompactPrefixCanonical := true,
    commitmentCompactPrefixBytes := 1,
    commitmentCount := 1,
    commitmentElementBytes := 48,
    commitmentCompactPrefixCanonical := true,
    ciphertextCompactPrefixBytes := 1,
    ciphertextCount := 1,
    encryptedNoteCiphertextBytes := 579,
    kemCiphertextCompactPrefixBytes := 1,
    kemCiphertextBytes := 32,
    ciphertextCompactPrefixCanonical := true,
    kemCiphertextCompactPrefixCanonical := true,
    anchorBytes := 48,
    balanceSlotCount := 4,
    balanceSlotBytes := 32,
    bindingHashBytes := 64,
    stablecoinOptionTagBytes := 1,
    stablecoinSomePayloadBytes := 0,
    feeBytes := 8,
    totalBytes := 819,
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

def validEmptyInline : ShieldedTransferInlineScaleWireInput :=
  {
    validOneOutputInline with
    proofBytes := 0,
    commitmentCount := 0,
    ciphertextCount := 0,
    kemCiphertextBytes := 0,
    totalBytes := shieldedTransferInlineEncodedLen {
      validOneOutputInline with
      proofBytes := 0,
      commitmentCount := 0,
      ciphertextCount := 0,
      kemCiphertextBytes := 0
    }
  }

def validStablecoinInline : ShieldedTransferInlineScaleWireInput :=
  {
    validOneOutputInline with
    stablecoinSomePayloadBytes := 172,
    totalBytes := shieldedTransferInlineEncodedLen {
      validOneOutputInline with
      stablecoinSomePayloadBytes := 172
    }
  }

theorem valid_one_output_inline_accepts :
    shieldedTransferInlineScaleWireAccepts validOneOutputInline = true := by
  rfl

theorem valid_empty_inline_accepts :
    shieldedTransferInlineScaleWireAccepts validEmptyInline = true := by
  rfl

theorem valid_stablecoin_inline_accepts :
    shieldedTransferInlineScaleWireAccepts validStablecoinInline = true := by
  rfl

def proofLengthOverrun : ShieldedTransferInlineScaleWireInput :=
  {
    validOneOutputInline with
    proofBytes := 4,
    totalBytes := 1 + 3,
    canonicalReencodeMatches := false
  }

theorem proof_length_overrun_rejects :
    evaluateShieldedTransferInlineScaleWireRejection
      proofLengthOverrun =
      some ShieldedTransferInlineScaleWireReject.parserRejected := by
  rfl

def kemLengthOverrun : ShieldedTransferInlineScaleWireInput :=
  {
    validOneOutputInline with
    kemCiphertextBytes := 33,
    totalBytes := 1 + 1 + 1 + 579 + 1 + 32,
    canonicalReencodeMatches := false
  }

theorem kem_length_overrun_rejects :
    evaluateShieldedTransferInlineScaleWireRejection
      kemLengthOverrun =
      some ShieldedTransferInlineScaleWireReject.parserRejected := by
  rfl

def trailingByteCase : ShieldedTransferInlineScaleWireInput :=
  { validOneOutputInline with consumedAllBytes := false }

theorem trailing_byte_case_rejects :
    evaluateShieldedTransferInlineScaleWireRejection trailingByteCase =
      some ShieldedTransferInlineScaleWireReject.trailingBytes := by
  rfl

def noncanonicalProofCompactPrefix : ShieldedTransferInlineScaleWireInput :=
  {
    validEmptyInline with
    proofCompactPrefixBytes := 2,
    proofCompactPrefixCanonical := false,
    totalBytes := shieldedTransferInlineEncodedLen {
      validEmptyInline with
      proofCompactPrefixBytes := 2
    },
    canonicalReencodeMatches := false
  }

theorem noncanonical_proof_compact_prefix_rejects :
    evaluateShieldedTransferInlineScaleWireRejection
      noncanonicalProofCompactPrefix =
      some ShieldedTransferInlineScaleWireReject.parserRejected := by
  rfl

end ShieldedTransferInlineScaleWire
end Native
end Hegemon

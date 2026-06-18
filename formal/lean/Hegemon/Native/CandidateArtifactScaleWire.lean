import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace CandidateArtifactScaleWire

open Hegemon.Native.CodecAdmission

inductive CandidateArtifactScaleWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure CandidateArtifactScaleWireInput where
  versionBytes : Nat
  txCountBytes : Nat
  txStatementsCommitmentBytes : Nat
  daRootBytes : Nat
  daChunkCountBytes : Nat
  commitmentProofCompactPrefixBytes : Nat
  commitmentProofBytes : Nat
  proofModeBytes : Nat
  proofModeTagValid : Bool
  proofKindBytes : Nat
  proofKindTagValid : Bool
  verifierProfileBytes : Nat
  receiptRootOptionTagBytes : Nat
  receiptRootOptionTagValid : Bool
  receiptRootNone : Bool
  receiptRootProofCompactPrefixBytes : Nat
  receiptRootProofBytes : Nat
  receiptRootRelationIdBytes : Nat
  receiptRootShapeDigestBytes : Nat
  receiptRootLeafCountBytes : Nat
  receiptRootFoldCountBytes : Nat
  receiptRootReceiptCompactPrefixBytes : Nat
  receiptRootReceiptCount : Nat
  receiptRootReceiptElementBytes : Nat
  recursiveBlockOptionTagBytes : Nat
  recursiveBlockOptionTagValid : Bool
  recursiveBlockPresent : Bool
  recursiveProofCompactPrefixBytes : Nat
  recursiveProofBytes : Nat
  compactPrefixesCanonical : Bool
  totalBytes : Nat
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def txValidityReceiptEncodedLen : Nat :=
  48 + 48 + 48 + 48

def starkProofEncodedLen (compactPrefixBytes proofBytes : Nat) : Nat :=
  compactPrefixBytes + proofBytes

def receiptRootProofPayloadEncodedLen
    (rootProofCompactPrefixBytes rootProofBytes
      receiptCompactPrefixBytes receiptCount receiptElementBytes : Nat) :
    Nat :=
  starkProofEncodedLen rootProofCompactPrefixBytes rootProofBytes
    + 32 + 32 + 4 + 4
    + receiptCompactPrefixBytes
    + receiptCount * receiptElementBytes

def recursiveBlockProofPayloadEncodedLen
    (recursiveProofCompactPrefixBytes recursiveProofBytes : Nat) : Nat :=
  starkProofEncodedLen recursiveProofCompactPrefixBytes recursiveProofBytes

def receiptRootPayloadBytesExpected
    (input : CandidateArtifactScaleWireInput) : Nat :=
  if input.receiptRootNone then
    0
  else
    receiptRootProofPayloadEncodedLen
      input.receiptRootProofCompactPrefixBytes
      input.receiptRootProofBytes
      input.receiptRootReceiptCompactPrefixBytes
      input.receiptRootReceiptCount
      input.receiptRootReceiptElementBytes

def recursiveBlockPayloadBytesExpected
    (input : CandidateArtifactScaleWireInput) : Nat :=
  if input.recursiveBlockPresent then
    recursiveBlockProofPayloadEncodedLen
      input.recursiveProofCompactPrefixBytes
      input.recursiveProofBytes
  else
    0

def candidateArtifactEncodedLen
    (commitmentProofCompactPrefixBytes commitmentProofBytes proofKindBytes
      receiptRootOptionTagBytes receiptRootPayloadBytes
      recursiveBlockOptionTagBytes recursiveBlockPayloadBytes : Nat) :
    Nat :=
  1 + 4 + 48 + 48 + 4
    + starkProofEncodedLen commitmentProofCompactPrefixBytes commitmentProofBytes
    + 1 + proofKindBytes + 48
    + receiptRootOptionTagBytes + receiptRootPayloadBytes
    + recursiveBlockOptionTagBytes + recursiveBlockPayloadBytes

def candidateArtifactBytesExpected
    (input : CandidateArtifactScaleWireInput) : Nat :=
  candidateArtifactEncodedLen
    input.commitmentProofCompactPrefixBytes
    input.commitmentProofBytes
    input.proofKindBytes
    input.receiptRootOptionTagBytes
    (receiptRootPayloadBytesExpected input)
    input.recursiveBlockOptionTagBytes
    (recursiveBlockPayloadBytesExpected input)

def fixedFieldWidthsOk (input : CandidateArtifactScaleWireInput) : Bool :=
  input.versionBytes == 1
    && input.txCountBytes == 4
    && input.txStatementsCommitmentBytes == 48
    && input.daRootBytes == 48
    && input.daChunkCountBytes == 4
    && input.proofModeBytes == 1
    && input.proofModeTagValid
    && ((input.proofKindBytes == 1) || (input.proofKindBytes == 17))
    && input.proofKindTagValid
    && input.verifierProfileBytes == 48
    && input.receiptRootOptionTagBytes == 1
    && input.receiptRootOptionTagValid
    && input.recursiveBlockOptionTagBytes == 1
    && input.recursiveBlockOptionTagValid

def receiptRootPayloadOk (input : CandidateArtifactScaleWireInput) : Bool :=
  input.receiptRootNone
    || (input.receiptRootProofCompactPrefixBytes >= 1
      && input.receiptRootRelationIdBytes == 32
      && input.receiptRootShapeDigestBytes == 32
      && input.receiptRootLeafCountBytes == 4
      && input.receiptRootFoldCountBytes == 4
      && input.receiptRootReceiptCompactPrefixBytes >= 1
      && input.receiptRootReceiptElementBytes == txValidityReceiptEncodedLen)

def recursiveBlockPayloadOk (input : CandidateArtifactScaleWireInput) : Bool :=
  (input.recursiveBlockPresent = false)
    || input.recursiveProofCompactPrefixBytes >= 1

def expectedLengthMatches (input : CandidateArtifactScaleWireInput) : Bool :=
  input.totalBytes == candidateArtifactBytesExpected input

def evaluateCandidateArtifactScaleWireRejection
    (input : CandidateArtifactScaleWireInput) :
    Option CandidateArtifactScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some CandidateArtifactScaleWireReject.parserRejected
  else if receiptRootPayloadOk input = false then
    some CandidateArtifactScaleWireReject.parserRejected
  else if recursiveBlockPayloadOk input = false then
    some CandidateArtifactScaleWireReject.parserRejected
  else if input.compactPrefixesCanonical = false then
    some CandidateArtifactScaleWireReject.parserRejected
  else if expectedLengthMatches input = false then
    some CandidateArtifactScaleWireReject.parserRejected
  else if input.consumedAllBytes = false then
    some CandidateArtifactScaleWireReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some CandidateArtifactScaleWireReject.nonCanonicalEncoding
  else
    none

def candidateArtifactScaleWireAccepts
    (input : CandidateArtifactScaleWireInput) : Bool :=
  evaluateCandidateArtifactScaleWireRejection input = none

structure AcceptedCandidateArtifactScaleWireFacts
    (input : CandidateArtifactScaleWireInput) : Prop where
  fixedFieldWidths : fixedFieldWidthsOk input = true
  receiptRootPayload : receiptRootPayloadOk input = true
  recursiveBlockPayload : recursiveBlockPayloadOk input = true
  compactPrefixesCanonical : input.compactPrefixesCanonical = true
  totalLengthMatches :
    input.totalBytes = candidateArtifactBytesExpected input
  consumedAllBytes : input.consumedAllBytes = true
  canonicalReencodeMatches : input.canonicalReencodeMatches = true

theorem candidate_artifact_scale_wire_acceptance_exposes_facts
    {input : CandidateArtifactScaleWireInput}
    (accepted : candidateArtifactScaleWireAccepts input = true) :
    AcceptedCandidateArtifactScaleWireFacts input := by
  unfold candidateArtifactScaleWireAccepts at accepted
  unfold evaluateCandidateArtifactScaleWireRejection at accepted
  by_cases hFixedFalse : fixedFieldWidthsOk input = false
  · simp [hFixedFalse] at accepted
  · have hFixed : fixedFieldWidthsOk input = true := by
      cases h : fixedFieldWidthsOk input <;> simp [h] at hFixedFalse ⊢
    simp [hFixed] at accepted
    by_cases hReceiptFalse : receiptRootPayloadOk input = false
    · simp [hReceiptFalse] at accepted
    · have hReceipt : receiptRootPayloadOk input = true := by
        cases h : receiptRootPayloadOk input <;> simp [h] at hReceiptFalse ⊢
      simp [hReceipt] at accepted
      by_cases hRecursiveFalse : recursiveBlockPayloadOk input = false
      · simp [hRecursiveFalse] at accepted
      · have hRecursive : recursiveBlockPayloadOk input = true := by
          cases h : recursiveBlockPayloadOk input <;>
            simp [h] at hRecursiveFalse ⊢
        simp [hRecursive] at accepted
        by_cases hCompactFalse : input.compactPrefixesCanonical = false
        · simp [hCompactFalse] at accepted
        · have hCompact : input.compactPrefixesCanonical = true := by
            cases h : input.compactPrefixesCanonical <;>
              simp [h] at hCompactFalse ⊢
          simp [hCompact] at accepted
          by_cases hLengthFalse : expectedLengthMatches input = false
          · simp [hLengthFalse] at accepted
          · have hLengthBool : expectedLengthMatches input = true := by
              cases h : expectedLengthMatches input <;>
                simp [h] at hLengthFalse ⊢
            have hLength :
                input.totalBytes = candidateArtifactBytesExpected input := by
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
                    receiptRootPayload := hReceipt,
                    recursiveBlockPayload := hRecursive,
                    compactPrefixesCanonical := hCompact,
                    totalLengthMatches := hLength,
                    consumedAllBytes := hConsumed,
                    canonicalReencodeMatches := hCanonical
                  }

def exactDecodeInputOfCandidateArtifactScaleWire
    (input : CandidateArtifactScaleWireInput) : ExactDecodeInput :=
  {
    parserAccepts := candidateArtifactScaleWireAccepts input,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

theorem accepted_candidate_artifact_scale_wire_exact_decode
    {input : CandidateArtifactScaleWireInput}
    (accepted : candidateArtifactScaleWireAccepts input = true) :
    exactDecodeAccepts
      (exactDecodeInputOfCandidateArtifactScaleWire input) = true := by
  have facts := candidate_artifact_scale_wire_acceptance_exposes_facts accepted
  exact
    (exact_accepts_iff_preconditions
      (input := exactDecodeInputOfCandidateArtifactScaleWire input)).mpr
      (by
        simp [
          exactDecodeInputOfCandidateArtifactScaleWire,
          exactDecodePreconditions,
          accepted,
          facts.consumedAllBytes,
          facts.canonicalReencodeMatches
        ])

def validRecursiveBlockV2 : CandidateArtifactScaleWireInput :=
  {
    versionBytes := 1,
    txCountBytes := 4,
    txStatementsCommitmentBytes := 48,
    daRootBytes := 48,
    daChunkCountBytes := 4,
    commitmentProofCompactPrefixBytes := 1,
    commitmentProofBytes := 0,
    proofModeBytes := 1,
    proofModeTagValid := true,
    proofKindBytes := 1,
    proofKindTagValid := true,
    verifierProfileBytes := 48,
    receiptRootOptionTagBytes := 1,
    receiptRootOptionTagValid := true,
    receiptRootNone := true,
    receiptRootProofCompactPrefixBytes := 0,
    receiptRootProofBytes := 0,
    receiptRootRelationIdBytes := 0,
    receiptRootShapeDigestBytes := 0,
    receiptRootLeafCountBytes := 0,
    receiptRootFoldCountBytes := 0,
    receiptRootReceiptCompactPrefixBytes := 0,
    receiptRootReceiptCount := 0,
    receiptRootReceiptElementBytes := 0,
    recursiveBlockOptionTagBytes := 1,
    recursiveBlockOptionTagValid := true,
    recursiveBlockPresent := true,
    recursiveProofCompactPrefixBytes := 1,
    recursiveProofBytes := 32,
    compactPrefixesCanonical := true,
    totalBytes :=
      candidateArtifactEncodedLen 1 0 1 1 0 1
        (recursiveBlockProofPayloadEncodedLen 1 32),
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

def validReceiptRoot : CandidateArtifactScaleWireInput :=
  {
    validRecursiveBlockV2 with
    receiptRootNone := false,
    receiptRootProofCompactPrefixBytes := 1,
    receiptRootProofBytes := 3,
    receiptRootRelationIdBytes := 32,
    receiptRootShapeDigestBytes := 32,
    receiptRootLeafCountBytes := 4,
    receiptRootFoldCountBytes := 4,
    receiptRootReceiptCompactPrefixBytes := 1,
    receiptRootReceiptCount := 1,
    receiptRootReceiptElementBytes := txValidityReceiptEncodedLen,
    recursiveBlockPresent := false,
    recursiveProofCompactPrefixBytes := 0,
    recursiveProofBytes := 0,
    totalBytes :=
      candidateArtifactEncodedLen 1 0 1 1
        (receiptRootProofPayloadEncodedLen 1 3 1 1
          txValidityReceiptEncodedLen)
        1 0
  }

def validCustomProofKind : CandidateArtifactScaleWireInput :=
  {
    validRecursiveBlockV2 with
    proofKindBytes := 17,
    totalBytes :=
      candidateArtifactEncodedLen 1 0 17 1 0 1
        (recursiveBlockProofPayloadEncodedLen 1 32)
  }

def trailingRecursiveBlockV2 : CandidateArtifactScaleWireInput :=
  { validRecursiveBlockV2 with consumedAllBytes := false }

def truncatedRecursiveBlockV2 : CandidateArtifactScaleWireInput :=
  {
    validRecursiveBlockV2 with
    totalBytes := 10,
    canonicalReencodeMatches := false
  }

def invalidProofMode : CandidateArtifactScaleWireInput :=
  {
    validRecursiveBlockV2 with
    proofModeTagValid := false,
    canonicalReencodeMatches := false
  }

def invalidProofKind : CandidateArtifactScaleWireInput :=
  {
    validRecursiveBlockV2 with
    proofKindTagValid := false,
    canonicalReencodeMatches := false
  }

def noncanonicalCommitmentProofPrefix : CandidateArtifactScaleWireInput :=
  {
    validRecursiveBlockV2 with
    compactPrefixesCanonical := false,
    totalBytes := validRecursiveBlockV2.totalBytes + 1
  }

def recursiveProofOverrun : CandidateArtifactScaleWireInput :=
  {
    validRecursiveBlockV2 with
    recursiveProofBytes := 33,
    canonicalReencodeMatches := false
  }

def receiptCountOverrun : CandidateArtifactScaleWireInput :=
  {
    validReceiptRoot with
    receiptRootReceiptCount := 2,
    canonicalReencodeMatches := false
  }

theorem valid_recursive_block_v2_wire_accepts :
    candidateArtifactScaleWireAccepts validRecursiveBlockV2 = true := by
  rfl

theorem valid_receipt_root_wire_accepts :
    candidateArtifactScaleWireAccepts validReceiptRoot = true := by
  rfl

theorem valid_custom_proof_kind_wire_accepts :
    candidateArtifactScaleWireAccepts validCustomProofKind = true := by
  rfl

theorem trailing_recursive_block_v2_rejects :
    evaluateCandidateArtifactScaleWireRejection trailingRecursiveBlockV2 =
      some CandidateArtifactScaleWireReject.trailingBytes := by
  rfl

theorem truncated_recursive_block_v2_rejects :
    evaluateCandidateArtifactScaleWireRejection truncatedRecursiveBlockV2 =
      some CandidateArtifactScaleWireReject.parserRejected := by
  rfl

theorem invalid_proof_mode_rejects :
    evaluateCandidateArtifactScaleWireRejection invalidProofMode =
      some CandidateArtifactScaleWireReject.parserRejected := by
  rfl

theorem invalid_proof_kind_rejects :
    evaluateCandidateArtifactScaleWireRejection invalidProofKind =
      some CandidateArtifactScaleWireReject.parserRejected := by
  rfl

theorem noncanonical_commitment_proof_prefix_rejects :
    evaluateCandidateArtifactScaleWireRejection noncanonicalCommitmentProofPrefix =
      some CandidateArtifactScaleWireReject.parserRejected := by
  rfl

theorem recursive_proof_overrun_rejects :
    evaluateCandidateArtifactScaleWireRejection recursiveProofOverrun =
      some CandidateArtifactScaleWireReject.parserRejected := by
  rfl

theorem receipt_count_overrun_rejects :
    evaluateCandidateArtifactScaleWireRejection receiptCountOverrun =
      some CandidateArtifactScaleWireReject.parserRejected := by
  rfl

end CandidateArtifactScaleWire
end Native
end Hegemon

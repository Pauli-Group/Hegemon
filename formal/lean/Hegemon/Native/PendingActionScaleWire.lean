import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace PendingActionScaleWire

open Hegemon.Native.CodecAdmission

inductive PendingActionScaleWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure PendingActionScaleWireInput where
  txHashBytes : Nat
  bindingBytes : Nat
  familyIdBytes : Nat
  actionIdBytes : Nat
  anchorBytes : Nat
  nullifierCount : Nat
  nullifierElementBytes : Nat
  commitmentCount : Nat
  commitmentElementBytes : Nat
  ciphertextHashCount : Nat
  ciphertextHashElementBytes : Nat
  ciphertextSizeCount : Nat
  ciphertextSizeElementBytes : Nat
  publicArgsBytes : Nat
  compactPrefixesCanonical : Bool
  feeBytes : Nat
  candidateOptionTagBytes : Nat
  candidateArtifactNone : Bool
  candidateArtifactPayloadBytes : Nat
  candidateArtifactVersionBytes : Nat
  candidateArtifactTxCountBytes : Nat
  candidateArtifactTxStatementsCommitmentBytes : Nat
  candidateArtifactDaRootBytes : Nat
  candidateArtifactDaChunkCountBytes : Nat
  candidateArtifactCommitmentProofBytes : Nat
  candidateArtifactProofModeBytes : Nat
  candidateArtifactProofKindBytes : Nat
  candidateArtifactVerifierProfileBytes : Nat
  candidateArtifactReceiptRootOptionTagBytes : Nat
  candidateArtifactReceiptRootNone : Bool
  candidateArtifactRecursiveBlockOptionTagBytes : Nat
  candidateArtifactRecursiveBlockPresent : Bool
  candidateArtifactRecursiveProofBytes : Nat
  receivedMsBytes : Nat
  totalBytes : Nat
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def recursiveBlockCandidateArtifactEncodedLen
    (commitmentProofBytes recursiveProofBytes : Nat) : Nat :=
  1 + 4 + 48 + 48 + 4
    + (1 + commitmentProofBytes)
    + 1 + 1 + 48
    + 1
    + 1 + (1 + recursiveProofBytes)

def candidateArtifactSomePayloadBytesExpected
    (input : PendingActionScaleWireInput) : Nat :=
  recursiveBlockCandidateArtifactEncodedLen
    input.candidateArtifactCommitmentProofBytes
    input.candidateArtifactRecursiveProofBytes

def candidateArtifactPayloadBytesExpected
    (input : PendingActionScaleWireInput) : Nat :=
  if input.candidateArtifactNone then
    0
  else
    candidateArtifactSomePayloadBytesExpected input

def pendingActionEncodedLen
    (nullifierCount commitmentCount ciphertextHashCount ciphertextSizeCount
      publicArgsBytes candidateArtifactPayloadBytes : Nat) : Nat :=
  32 + 4 + 2 + 2 + 48
    + (1 + 48 * nullifierCount)
    + (1 + 48 * commitmentCount)
    + (1 + 48 * ciphertextHashCount)
    + (1 + 4 * ciphertextSizeCount)
    + (1 + publicArgsBytes)
    + 8 + 1 + candidateArtifactPayloadBytes + 8

def pendingActionNoCandidateEncodedLen
    (nullifierCount commitmentCount ciphertextHashCount ciphertextSizeCount
      publicArgsBytes : Nat) : Nat :=
  pendingActionEncodedLen
    nullifierCount
    commitmentCount
    ciphertextHashCount
    ciphertextSizeCount
    publicArgsBytes
    0

def fixedFieldWidthsOk (input : PendingActionScaleWireInput) : Bool :=
  input.txHashBytes == 32
    && input.bindingBytes == 4
    && input.familyIdBytes == 2
    && input.actionIdBytes == 2
    && input.anchorBytes == 48
    && input.feeBytes == 8
    && input.candidateOptionTagBytes == 1
    && input.receivedMsBytes == 8

def vectorElementWidthsOk (input : PendingActionScaleWireInput) : Bool :=
  input.nullifierElementBytes == 48
    && input.commitmentElementBytes == 48
    && input.ciphertextHashElementBytes == 48
    && input.ciphertextSizeElementBytes == 4

def candidateArtifactSomeFixedWidthsOk
    (input : PendingActionScaleWireInput) : Bool :=
  input.candidateArtifactVersionBytes == 1
    && input.candidateArtifactTxCountBytes == 4
    && input.candidateArtifactTxStatementsCommitmentBytes == 48
    && input.candidateArtifactDaRootBytes == 48
    && input.candidateArtifactDaChunkCountBytes == 4
    && input.candidateArtifactProofModeBytes == 1
    && input.candidateArtifactProofKindBytes == 1
    && input.candidateArtifactVerifierProfileBytes == 48
    && input.candidateArtifactReceiptRootOptionTagBytes == 1
    && input.candidateArtifactRecursiveBlockOptionTagBytes == 1

def candidateArtifactPayloadOk (input : PendingActionScaleWireInput) : Bool :=
  input.candidateArtifactPayloadBytes == candidateArtifactPayloadBytesExpected input
    && (input.candidateArtifactNone
      || (candidateArtifactSomeFixedWidthsOk input
        && input.candidateArtifactReceiptRootNone
        && input.candidateArtifactRecursiveBlockPresent))

def expectedLengthMatches (input : PendingActionScaleWireInput) : Bool :=
  input.totalBytes ==
    pendingActionEncodedLen
      input.nullifierCount
      input.commitmentCount
      input.ciphertextHashCount
      input.ciphertextSizeCount
      input.publicArgsBytes
      input.candidateArtifactPayloadBytes

def evaluatePendingActionScaleWireRejection
    (input : PendingActionScaleWireInput) :
    Option PendingActionScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some PendingActionScaleWireReject.parserRejected
  else if vectorElementWidthsOk input = false then
    some PendingActionScaleWireReject.parserRejected
  else if (input.candidateOptionTagBytes == 1) = false then
    some PendingActionScaleWireReject.parserRejected
  else if candidateArtifactPayloadOk input = false then
    some PendingActionScaleWireReject.parserRejected
  else if input.compactPrefixesCanonical = false then
    some PendingActionScaleWireReject.parserRejected
  else if expectedLengthMatches input = false then
    some PendingActionScaleWireReject.parserRejected
  else if input.consumedAllBytes = false then
    some PendingActionScaleWireReject.trailingBytes
  else if input.canonicalReencodeMatches = false then
    some PendingActionScaleWireReject.nonCanonicalEncoding
  else
    none

def pendingActionScaleWireAccepts
    (input : PendingActionScaleWireInput) : Bool :=
  evaluatePendingActionScaleWireRejection input = none

structure AcceptedPendingActionScaleWireFacts
    (input : PendingActionScaleWireInput) : Prop where
  fixedFieldWidths :
    fixedFieldWidthsOk input = true
  vectorElementWidths :
    vectorElementWidthsOk input = true
  compactPrefixesCanonical :
    input.compactPrefixesCanonical = true
  candidateOptionTagWidth :
    input.candidateOptionTagBytes = 1
  candidateArtifactPayload :
    candidateArtifactPayloadOk input = true
  totalLengthMatches :
    input.totalBytes =
      pendingActionEncodedLen
        input.nullifierCount
        input.commitmentCount
        input.ciphertextHashCount
        input.ciphertextSizeCount
        input.publicArgsBytes
        input.candidateArtifactPayloadBytes
  consumedAllBytes :
    input.consumedAllBytes = true
  canonicalReencodeMatches :
    input.canonicalReencodeMatches = true

theorem pending_action_scale_wire_acceptance_exposes_facts
    {input : PendingActionScaleWireInput}
    (accepted : pendingActionScaleWireAccepts input = true) :
    AcceptedPendingActionScaleWireFacts input := by
  unfold pendingActionScaleWireAccepts at accepted
  unfold evaluatePendingActionScaleWireRejection at accepted
  by_cases hFixedFalse : fixedFieldWidthsOk input = false
  · simp [hFixedFalse] at accepted
  · have hFixed : fixedFieldWidthsOk input = true := by
      cases h : fixedFieldWidthsOk input <;> simp [h] at hFixedFalse ⊢
    simp [hFixed] at accepted
    by_cases hVectorFalse : vectorElementWidthsOk input = false
    · simp [hVectorFalse] at accepted
    · have hVector : vectorElementWidthsOk input = true := by
        cases h : vectorElementWidthsOk input <;> simp [h] at hVectorFalse ⊢
      simp [hVector] at accepted
      by_cases hTag : input.candidateOptionTagBytes = 1
      · rw [if_pos hTag] at accepted
        by_cases hCandidateFalse : candidateArtifactPayloadOk input = false
        · simp [hCandidateFalse] at accepted
        · have hCandidate : candidateArtifactPayloadOk input = true := by
            cases h : candidateArtifactPayloadOk input <;>
              simp [h] at hCandidateFalse ⊢
          simp [hCandidate] at accepted
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
                  input.totalBytes =
                    pendingActionEncodedLen
                      input.nullifierCount
                      input.commitmentCount
                      input.ciphertextHashCount
                      input.ciphertextSizeCount
                      input.publicArgsBytes
                      input.candidateArtifactPayloadBytes := by
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
                      vectorElementWidths := hVector,
                      compactPrefixesCanonical := hCompact,
                      candidateOptionTagWidth := hTag,
                      candidateArtifactPayload := hCandidate,
                      totalLengthMatches := hLength,
                      consumedAllBytes := hConsumed,
                      canonicalReencodeMatches := hCanonical
                    }
      · rw [if_neg hTag] at accepted
        cases accepted

theorem accepted_pending_action_scale_wire_total_length
    {input : PendingActionScaleWireInput}
    (accepted : pendingActionScaleWireAccepts input = true) :
    input.totalBytes =
      pendingActionEncodedLen
        input.nullifierCount
        input.commitmentCount
        input.ciphertextHashCount
        input.ciphertextSizeCount
        input.publicArgsBytes
        input.candidateArtifactPayloadBytes :=
  (pending_action_scale_wire_acceptance_exposes_facts accepted).totalLengthMatches

def exactDecodeInputOfScaleWire
    (input : PendingActionScaleWireInput) : ExactDecodeInput :=
  {
    parserAccepts := pendingActionScaleWireAccepts input,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

theorem accepted_pending_action_scale_wire_exact_decode
    {input : PendingActionScaleWireInput}
    (accepted : pendingActionScaleWireAccepts input = true) :
    exactDecodeAccepts (exactDecodeInputOfScaleWire input) = true := by
  have facts := pending_action_scale_wire_acceptance_exposes_facts accepted
  exact
    (exact_accepts_iff_preconditions
      (input := exactDecodeInputOfScaleWire input)).mpr
      (by
        simp [
          exactDecodeInputOfScaleWire,
          exactDecodePreconditions,
          accepted,
          facts.consumedAllBytes,
          facts.canonicalReencodeMatches
        ])

def validEmptyNoCandidate : PendingActionScaleWireInput :=
  {
    txHashBytes := 32,
    bindingBytes := 4,
    familyIdBytes := 2,
    actionIdBytes := 2,
    anchorBytes := 48,
    nullifierCount := 0,
    nullifierElementBytes := 48,
    commitmentCount := 0,
    commitmentElementBytes := 48,
    ciphertextHashCount := 0,
    ciphertextHashElementBytes := 48,
    ciphertextSizeCount := 0,
    ciphertextSizeElementBytes := 4,
    publicArgsBytes := 0,
    compactPrefixesCanonical := true,
    feeBytes := 8,
    candidateOptionTagBytes := 1,
    candidateArtifactNone := true,
    candidateArtifactPayloadBytes := 0,
    candidateArtifactVersionBytes := 0,
    candidateArtifactTxCountBytes := 0,
    candidateArtifactTxStatementsCommitmentBytes := 0,
    candidateArtifactDaRootBytes := 0,
    candidateArtifactDaChunkCountBytes := 0,
    candidateArtifactCommitmentProofBytes := 0,
    candidateArtifactProofModeBytes := 0,
    candidateArtifactProofKindBytes := 0,
    candidateArtifactVerifierProfileBytes := 0,
    candidateArtifactReceiptRootOptionTagBytes := 0,
    candidateArtifactReceiptRootNone := false,
    candidateArtifactRecursiveBlockOptionTagBytes := 0,
    candidateArtifactRecursiveBlockPresent := false,
    candidateArtifactRecursiveProofBytes := 0,
    receivedMsBytes := 8,
    totalBytes := pendingActionNoCandidateEncodedLen 0 0 0 0 0,
    consumedAllBytes := true,
    canonicalReencodeMatches := true
  }

def validOneEachNoCandidate : PendingActionScaleWireInput :=
  {
    validEmptyNoCandidate with
    nullifierCount := 1,
    commitmentCount := 1,
    ciphertextHashCount := 1,
    ciphertextSizeCount := 1,
    publicArgsBytes := 3,
    totalBytes := pendingActionNoCandidateEncodedLen 1 1 1 1 3
  }

def validCandidateArtifactSome : PendingActionScaleWireInput :=
  let payloadBytes := recursiveBlockCandidateArtifactEncodedLen 0 32
  {
    validEmptyNoCandidate with
    familyIdBytes := 2,
    actionIdBytes := 2,
    candidateArtifactNone := false,
    candidateArtifactPayloadBytes := payloadBytes,
    candidateArtifactVersionBytes := 1,
    candidateArtifactTxCountBytes := 4,
    candidateArtifactTxStatementsCommitmentBytes := 48,
    candidateArtifactDaRootBytes := 48,
    candidateArtifactDaChunkCountBytes := 4,
    candidateArtifactCommitmentProofBytes := 0,
    candidateArtifactProofModeBytes := 1,
    candidateArtifactProofKindBytes := 1,
    candidateArtifactVerifierProfileBytes := 48,
    candidateArtifactReceiptRootOptionTagBytes := 1,
    candidateArtifactReceiptRootNone := true,
    candidateArtifactRecursiveBlockOptionTagBytes := 1,
    candidateArtifactRecursiveBlockPresent := true,
    candidateArtifactRecursiveProofBytes := 32,
    totalBytes := pendingActionEncodedLen 0 0 0 0 0 payloadBytes
  }

theorem valid_empty_no_candidate_accepts :
    pendingActionScaleWireAccepts validEmptyNoCandidate = true := by
  rfl

theorem valid_one_each_no_candidate_accepts :
    pendingActionScaleWireAccepts validOneEachNoCandidate = true := by
  rfl

theorem valid_candidate_artifact_some_accepts :
    pendingActionScaleWireAccepts validCandidateArtifactSome = true := by
  rfl

def malformedNullifierCountOverrun : PendingActionScaleWireInput :=
  { validOneEachNoCandidate with
    nullifierCount := 2,
    totalBytes := pendingActionNoCandidateEncodedLen 1 1 1 1 3 }

theorem malformed_nullifier_count_overrun_rejects :
    evaluatePendingActionScaleWireRejection malformedNullifierCountOverrun =
      some PendingActionScaleWireReject.parserRejected := by
  rfl

def noncanonicalCompactPrefix : PendingActionScaleWireInput :=
  { validOneEachNoCandidate with compactPrefixesCanonical := false }

theorem noncanonical_compact_prefix_rejects :
    evaluatePendingActionScaleWireRejection noncanonicalCompactPrefix =
      some PendingActionScaleWireReject.parserRejected := by
  rfl

def trailingByteCase : PendingActionScaleWireInput :=
  { validEmptyNoCandidate with
    consumedAllBytes := false }

theorem trailing_byte_case_rejects :
    evaluatePendingActionScaleWireRejection trailingByteCase =
      some PendingActionScaleWireReject.trailingBytes := by
  rfl

def candidateSomeMissingPayload : PendingActionScaleWireInput :=
  { validEmptyNoCandidate with candidateArtifactNone := false }

theorem candidate_some_missing_payload_rejects :
    evaluatePendingActionScaleWireRejection candidateSomeMissingPayload =
      some PendingActionScaleWireReject.parserRejected := by
  rfl

end PendingActionScaleWire
end Native
end Hegemon

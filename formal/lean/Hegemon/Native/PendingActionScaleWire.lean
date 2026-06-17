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
  receivedMsBytes : Nat
  totalBytes : Nat
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def pendingActionNoCandidateEncodedLen
    (nullifierCount commitmentCount ciphertextHashCount ciphertextSizeCount
      publicArgsBytes : Nat) : Nat :=
  32 + 4 + 2 + 2 + 48
    + (1 + 48 * nullifierCount)
    + (1 + 48 * commitmentCount)
    + (1 + 48 * ciphertextHashCount)
    + (1 + 4 * ciphertextSizeCount)
    + (1 + publicArgsBytes)
    + 8 + 1 + 8

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

def expectedLengthMatches (input : PendingActionScaleWireInput) : Bool :=
  input.totalBytes ==
    pendingActionNoCandidateEncodedLen
      input.nullifierCount
      input.commitmentCount
      input.ciphertextHashCount
      input.ciphertextSizeCount
      input.publicArgsBytes

def evaluatePendingActionScaleWireRejection
    (input : PendingActionScaleWireInput) :
    Option PendingActionScaleWireReject :=
  if fixedFieldWidthsOk input = false then
    some PendingActionScaleWireReject.parserRejected
  else if vectorElementWidthsOk input = false then
    some PendingActionScaleWireReject.parserRejected
  else if (input.candidateOptionTagBytes == 1) = false then
    some PendingActionScaleWireReject.parserRejected
  else if input.candidateArtifactNone = false then
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
  candidateArtifactNone :
    input.candidateArtifactNone = true
  totalLengthMatches :
    input.totalBytes =
      pendingActionNoCandidateEncodedLen
        input.nullifierCount
        input.commitmentCount
        input.ciphertextHashCount
        input.ciphertextSizeCount
        input.publicArgsBytes
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
        by_cases hCandidateFalse : input.candidateArtifactNone = false
        · simp [hCandidateFalse] at accepted
        · have hCandidate : input.candidateArtifactNone = true := by
            cases h : input.candidateArtifactNone <;>
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
                    pendingActionNoCandidateEncodedLen
                      input.nullifierCount
                      input.commitmentCount
                      input.ciphertextHashCount
                      input.ciphertextSizeCount
                      input.publicArgsBytes := by
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
                      candidateArtifactNone := hCandidate,
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
      pendingActionNoCandidateEncodedLen
        input.nullifierCount
        input.commitmentCount
        input.ciphertextHashCount
        input.ciphertextSizeCount
        input.publicArgsBytes :=
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

theorem valid_empty_no_candidate_accepts :
    pendingActionScaleWireAccepts validEmptyNoCandidate = true := by
  rfl

theorem valid_one_each_no_candidate_accepts :
    pendingActionScaleWireAccepts validOneEachNoCandidate = true := by
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

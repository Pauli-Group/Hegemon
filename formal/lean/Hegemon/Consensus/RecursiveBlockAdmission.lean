import Hegemon.Resource.BoundedRequestAdmission

namespace Hegemon
namespace Consensus
namespace RecursiveBlockAdmission

open Hegemon.Resource.BoundedRequestAdmission

inductive ArtifactKind where
  | inlineTx
  | txLeaf
  | receiptRoot
  | recursiveBlockV1
  | recursiveBlockV2
deriving DecidableEq, Repr

inductive ArtifactReject where
  | artifactKindMismatch
  | verifierProfileMismatch
  | artifactTooLarge
  | artifactDecodeFailed
  | headerVersionMismatch
  | txCountMismatch
  | statementCommitmentMismatch
  | publicReplayMismatch
deriving DecidableEq, Repr

inductive DirectVerifierReject where
  | requiresSemanticReplay
deriving DecidableEq, Repr

structure ArtifactAdmissionInput where
  expectedKind : ArtifactKind
  envelopeKind : ArtifactKind
  verifierProfileMatches : Bool
  artifactBytesLen : Nat
  maxArtifactBytes : Nat
  artifactDecoded : Bool
  headerVersionMatches : Bool
  txCountMatches : Bool
  statementCommitmentMatches : Bool
  publicReplayMatches : Bool
deriving DecidableEq, Repr

def evaluateArtifactRejection (input : ArtifactAdmissionInput) : Option ArtifactReject :=
  if input.envelopeKind != input.expectedKind then
    some ArtifactReject.artifactKindMismatch
  else if input.verifierProfileMatches = false then
    some ArtifactReject.verifierProfileMismatch
  else if input.artifactBytesLen > input.maxArtifactBytes then
    some ArtifactReject.artifactTooLarge
  else if input.artifactDecoded = false then
    some ArtifactReject.artifactDecodeFailed
  else if input.headerVersionMatches = false then
    some ArtifactReject.headerVersionMismatch
  else if input.txCountMatches = false then
    some ArtifactReject.txCountMismatch
  else if input.statementCommitmentMatches = false then
    some ArtifactReject.statementCommitmentMismatch
  else if input.publicReplayMatches = false then
    some ArtifactReject.publicReplayMismatch
  else
    none

def artifactPreconditions (input : ArtifactAdmissionInput) : Bool :=
  if input.envelopeKind != input.expectedKind then
    false
  else if input.verifierProfileMatches = false then
    false
  else if input.artifactBytesLen > input.maxArtifactBytes then
    false
  else if input.artifactDecoded = false then
    false
  else if input.headerVersionMatches = false then
    false
  else if input.txCountMatches = false then
    false
  else if input.statementCommitmentMatches = false then
    false
  else if input.publicReplayMatches = false then
    false
  else
    true

def artifactAccepts (input : ArtifactAdmissionInput) : Bool :=
  evaluateArtifactRejection input = none

def evaluateDirectVerifierRejection (_kind : ArtifactKind) : Option DirectVerifierReject :=
  some DirectVerifierReject.requiresSemanticReplay

def recursiveBlockV1ArtifactBytes : Nat := 699452

def recursiveBlockV2ArtifactBytes : Nat := 523736

theorem artifact_accepts_iff_preconditions (input : ArtifactAdmissionInput) :
    artifactAccepts input = artifactPreconditions input := by
  unfold artifactAccepts artifactPreconditions evaluateArtifactRejection
  by_cases hKind : input.envelopeKind != input.expectedKind
  · simp [hKind]
  · simp [hKind]
    by_cases hProfile : input.verifierProfileMatches = false
    · simp [hProfile]
    · simp [hProfile]
      by_cases hOver : input.artifactBytesLen > input.maxArtifactBytes
      · simp [hOver]
      · simp [hOver]
        by_cases hDecoded : input.artifactDecoded = false
        · simp [hDecoded]
        · simp [hDecoded]
          by_cases hHeader : input.headerVersionMatches = false
          · simp [hHeader]
          · simp [hHeader]
            by_cases hTxCount : input.txCountMatches = false
            · simp [hTxCount]
            · simp [hTxCount]
              by_cases hStatement :
                  input.statementCommitmentMatches = false
              · simp [hStatement]
              · simp [hStatement]

def validV2Artifact : ArtifactAdmissionInput :=
  {
    expectedKind := ArtifactKind.recursiveBlockV2,
    envelopeKind := ArtifactKind.recursiveBlockV2,
    verifierProfileMatches := true,
    artifactBytesLen := recursiveBlockV2ArtifactBytes,
    maxArtifactBytes := recursiveBlockV2ArtifactBytes,
    artifactDecoded := true,
    headerVersionMatches := true,
    txCountMatches := true,
    statementCommitmentMatches := true,
    publicReplayMatches := true
  }

def validV1Artifact : ArtifactAdmissionInput :=
  { validV2Artifact with
    expectedKind := ArtifactKind.recursiveBlockV1,
    envelopeKind := ArtifactKind.recursiveBlockV1,
    artifactBytesLen := recursiveBlockV1ArtifactBytes,
    maxArtifactBytes := recursiveBlockV1ArtifactBytes
  }

theorem valid_v2_artifact_accepts :
    evaluateArtifactRejection validV2Artifact = none := by
  decide

theorem valid_v1_artifact_accepts :
    evaluateArtifactRejection validV1Artifact = none := by
  decide

theorem wrong_kind_rejects :
    evaluateArtifactRejection { validV2Artifact with envelopeKind := ArtifactKind.receiptRoot } =
      some ArtifactReject.artifactKindMismatch := by
  decide

theorem profile_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with verifierProfileMatches := false } =
      some ArtifactReject.verifierProfileMismatch := by
  decide

theorem artifact_too_large_rejects :
    evaluateArtifactRejection
        { validV2Artifact with artifactBytesLen := validV2Artifact.maxArtifactBytes + 1 } =
      some ArtifactReject.artifactTooLarge := by
  decide

theorem decode_failed_rejects :
    evaluateArtifactRejection { validV2Artifact with artifactDecoded := false } =
      some ArtifactReject.artifactDecodeFailed := by
  decide

theorem header_version_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with headerVersionMatches := false } =
      some ArtifactReject.headerVersionMismatch := by
  decide

theorem tx_count_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with txCountMatches := false } =
      some ArtifactReject.txCountMismatch := by
  decide

theorem statement_commitment_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with statementCommitmentMatches := false } =
      some ArtifactReject.statementCommitmentMismatch := by
  decide

theorem public_replay_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with publicReplayMatches := false } =
      some ArtifactReject.publicReplayMismatch := by
  decide

theorem kind_precedes_decode_failure :
    evaluateArtifactRejection
        { validV2Artifact with
          envelopeKind := ArtifactKind.receiptRoot,
          artifactDecoded := false
        } =
      some ArtifactReject.artifactKindMismatch := by
  decide

theorem artifact_too_large_precedes_decode_failure :
    evaluateArtifactRejection
        { validV2Artifact with
          artifactBytesLen := validV2Artifact.maxArtifactBytes + 1,
          artifactDecoded := false
        } =
      some ArtifactReject.artifactTooLarge := by
  decide

theorem artifact_accepts_implies_bytes_within_cap
    {input : ArtifactAdmissionInput}
    (accepted : artifactAccepts input = true) :
    ¬ input.artifactBytesLen > input.maxArtifactBytes := by
  intro hOver
  unfold artifactAccepts evaluateArtifactRejection at accepted
  by_cases hKind : input.envelopeKind != input.expectedKind
  · simp [hKind] at accepted
  · simp [hKind] at accepted
    by_cases hProfile : input.verifierProfileMatches = false
    · simp [hProfile] at accepted
    · simp [hProfile] at accepted
      simp [hOver] at accepted

def recursiveBlockArtifactResourcePolicy
    (input : ArtifactAdmissionInput) : ResourcePolicy :=
  {
    rawByteCap := input.maxArtifactBytes,
    decodedByteCap := input.maxArtifactBytes,
    itemCountCap := 1,
    itemByteCap := input.maxArtifactBytes,
    aggregateByteCap := input.maxArtifactBytes,
    workUnitCap := input.maxArtifactBytes
  }

def recursiveBlockArtifactResourceRequest
    (input : ArtifactAdmissionInput) : ResourceRequest :=
  {
    rawBytes := input.artifactBytesLen,
    decodedBytes := input.artifactBytesLen,
    itemCount := 1,
    maxItemBytes := input.artifactBytesLen,
    aggregateBytes := input.artifactBytesLen,
    workUnits := input.artifactBytesLen
  }

theorem recursive_block_artifact_accepts_implies_bounded_request_facts
    {input : ArtifactAdmissionInput}
    (accepted : artifactAccepts input = true) :
    AcceptedBoundedRequestFacts
      (recursiveBlockArtifactResourcePolicy input)
      (recursiveBlockArtifactResourceRequest input) := by
  have bytesWithin :
      ¬ input.maxArtifactBytes < input.artifactBytesLen := by
    exact artifact_accepts_implies_bytes_within_cap accepted
  apply accepted_bounded_request_exposes_all_caps
  unfold recursiveBlockArtifactResourcePolicy
    recursiveBlockArtifactResourceRequest
    evaluateBoundedRequest
  simp [bytesWithin]

theorem direct_v1_requires_semantic_replay :
    evaluateDirectVerifierRejection ArtifactKind.recursiveBlockV1 =
      some DirectVerifierReject.requiresSemanticReplay := by
  decide

theorem direct_v2_requires_semantic_replay :
    evaluateDirectVerifierRejection ArtifactKind.recursiveBlockV2 =
      some DirectVerifierReject.requiresSemanticReplay := by
  decide

end RecursiveBlockAdmission
end Consensus
end Hegemon

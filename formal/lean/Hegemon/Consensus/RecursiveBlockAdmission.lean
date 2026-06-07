namespace Hegemon
namespace Consensus
namespace RecursiveBlockAdmission

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

theorem artifact_accepts_iff_preconditions (input : ArtifactAdmissionInput) :
    artifactAccepts input = artifactPreconditions input := by
  cases input with
  | mk expectedKind envelopeKind verifierProfileMatches artifactDecoded
      headerVersionMatches txCountMatches statementCommitmentMatches publicReplayMatches =>
      unfold artifactAccepts artifactPreconditions evaluateArtifactRejection
      cases expectedKind <;> cases envelopeKind <;> cases verifierProfileMatches <;>
        cases artifactDecoded <;> cases headerVersionMatches <;> cases txCountMatches <;>
        cases statementCommitmentMatches <;> cases publicReplayMatches <;> simp

def validV2Artifact : ArtifactAdmissionInput :=
  {
    expectedKind := ArtifactKind.recursiveBlockV2,
    envelopeKind := ArtifactKind.recursiveBlockV2,
    verifierProfileMatches := true,
    artifactDecoded := true,
    headerVersionMatches := true,
    txCountMatches := true,
    statementCommitmentMatches := true,
    publicReplayMatches := true
  }

def validV1Artifact : ArtifactAdmissionInput :=
  { validV2Artifact with
    expectedKind := ArtifactKind.recursiveBlockV1,
    envelopeKind := ArtifactKind.recursiveBlockV1
  }

theorem valid_v2_artifact_accepts :
    evaluateArtifactRejection validV2Artifact = none := by
  native_decide

theorem valid_v1_artifact_accepts :
    evaluateArtifactRejection validV1Artifact = none := by
  native_decide

theorem wrong_kind_rejects :
    evaluateArtifactRejection { validV2Artifact with envelopeKind := ArtifactKind.receiptRoot } =
      some ArtifactReject.artifactKindMismatch := by
  native_decide

theorem profile_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with verifierProfileMatches := false } =
      some ArtifactReject.verifierProfileMismatch := by
  native_decide

theorem decode_failed_rejects :
    evaluateArtifactRejection { validV2Artifact with artifactDecoded := false } =
      some ArtifactReject.artifactDecodeFailed := by
  native_decide

theorem header_version_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with headerVersionMatches := false } =
      some ArtifactReject.headerVersionMismatch := by
  native_decide

theorem tx_count_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with txCountMatches := false } =
      some ArtifactReject.txCountMismatch := by
  native_decide

theorem statement_commitment_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with statementCommitmentMatches := false } =
      some ArtifactReject.statementCommitmentMismatch := by
  native_decide

theorem public_replay_mismatch_rejects :
    evaluateArtifactRejection { validV2Artifact with publicReplayMatches := false } =
      some ArtifactReject.publicReplayMismatch := by
  native_decide

theorem kind_precedes_decode_failure :
    evaluateArtifactRejection
        { validV2Artifact with
          envelopeKind := ArtifactKind.receiptRoot,
          artifactDecoded := false
        } =
      some ArtifactReject.artifactKindMismatch := by
  native_decide

theorem direct_v1_requires_semantic_replay :
    evaluateDirectVerifierRejection ArtifactKind.recursiveBlockV1 =
      some DirectVerifierReject.requiresSemanticReplay := by
  native_decide

theorem direct_v2_requires_semantic_replay :
    evaluateDirectVerifierRejection ArtifactKind.recursiveBlockV2 =
      some DirectVerifierReject.requiresSemanticReplay := by
  native_decide

end RecursiveBlockAdmission
end Consensus
end Hegemon

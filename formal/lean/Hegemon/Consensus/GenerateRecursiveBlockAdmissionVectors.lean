import Hegemon.Consensus.RecursiveBlockAdmission

open Hegemon.Consensus.RecursiveBlockAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def artifactKindJson : ArtifactKind -> String
  | ArtifactKind.inlineTx => "inline_tx"
  | ArtifactKind.txLeaf => "tx_leaf"
  | ArtifactKind.receiptRoot => "receipt_root"
  | ArtifactKind.recursiveBlockV1 => "recursive_block_v1"
  | ArtifactKind.recursiveBlockV2 => "recursive_block_v2"

def artifactRejectJson : Option ArtifactReject -> String
  | none => "null"
  | some ArtifactReject.artifactKindMismatch => "\"artifact_kind_mismatch\""
  | some ArtifactReject.verifierProfileMismatch => "\"verifier_profile_mismatch\""
  | some ArtifactReject.artifactDecodeFailed => "\"artifact_decode_failed\""
  | some ArtifactReject.headerVersionMismatch => "\"header_version_mismatch\""
  | some ArtifactReject.txCountMismatch => "\"tx_count_mismatch\""
  | some ArtifactReject.statementCommitmentMismatch => "\"statement_commitment_mismatch\""
  | some ArtifactReject.publicReplayMismatch => "\"public_replay_mismatch\""

def artifactCaseJson (name : String) (input : ArtifactAdmissionInput) : String :=
  let rejection := evaluateArtifactRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"expected_kind\": \"" ++ artifactKindJson input.expectedKind ++ "\",\n"
    ++ "      \"envelope_kind\": \"" ++ artifactKindJson input.envelopeKind ++ "\",\n"
    ++ "      \"verifier_profile_matches\": "
    ++ boolJson input.verifierProfileMatches ++ ",\n"
    ++ "      \"artifact_decoded\": " ++ boolJson input.artifactDecoded ++ ",\n"
    ++ "      \"header_version_matches\": " ++ boolJson input.headerVersionMatches ++ ",\n"
    ++ "      \"tx_count_matches\": " ++ boolJson input.txCountMatches ++ ",\n"
    ++ "      \"statement_commitment_matches\": "
    ++ boolJson input.statementCommitmentMatches ++ ",\n"
    ++ "      \"public_replay_matches\": " ++ boolJson input.publicReplayMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ artifactRejectJson rejection ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"artifact_cases\": [\n"
    ++ artifactCaseJson "valid-recursive-block-v2" validV2Artifact ++ ",\n"
    ++ artifactCaseJson "valid-recursive-block-v1" validV1Artifact ++ ",\n"
    ++ artifactCaseJson "wrong-kind-rejected"
      { validV2Artifact with envelopeKind := ArtifactKind.receiptRoot } ++ ",\n"
    ++ artifactCaseJson "profile-mismatch-rejected"
      { validV2Artifact with verifierProfileMatches := false } ++ ",\n"
    ++ artifactCaseJson "decode-failed-rejected"
      { validV2Artifact with artifactDecoded := false } ++ ",\n"
    ++ artifactCaseJson "header-version-mismatch-rejected"
      { validV2Artifact with headerVersionMatches := false } ++ ",\n"
    ++ artifactCaseJson "tx-count-mismatch-rejected"
      { validV2Artifact with txCountMatches := false } ++ ",\n"
    ++ artifactCaseJson "statement-commitment-mismatch-rejected"
      { validV2Artifact with statementCommitmentMatches := false } ++ ",\n"
    ++ artifactCaseJson "public-replay-mismatch-rejected"
      { validV2Artifact with publicReplayMatches := false } ++ ",\n"
    ++ artifactCaseJson "kind-precedes-decode-failure"
      { validV2Artifact with
        envelopeKind := ArtifactKind.receiptRoot,
        artifactDecoded := false
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

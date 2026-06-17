import Hegemon.Native.CandidateArtifactAdmission

open Hegemon.Native.CandidateArtifactAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CandidateArtifactReject -> String
  | none => "null"
  | some CandidateArtifactReject.stateDeltasPresent => "\"state_deltas_present\""
  | some CandidateArtifactReject.routePayloadDecodeFailed =>
      "\"route_payload_decode_failed\""
  | some CandidateArtifactReject.routePayloadArtifactMismatch =>
      "\"route_payload_artifact_mismatch\""
  | some CandidateArtifactReject.artifactMissing => "\"artifact_missing\""
  | some CandidateArtifactReject.schemaMismatch => "\"schema_mismatch\""
  | some CandidateArtifactReject.txCountZero => "\"tx_count_zero\""
  | some CandidateArtifactReject.txCountTooLarge => "\"tx_count_too_large\""
  | some CandidateArtifactReject.daChunkCountZero => "\"da_chunk_count_zero\""
  | some CandidateArtifactReject.wrongProofMode => "\"wrong_proof_mode\""
  | some CandidateArtifactReject.wrongProofKind => "\"wrong_proof_kind\""
  | some CandidateArtifactReject.verifierProfileMismatch =>
      "\"verifier_profile_mismatch\""
  | some CandidateArtifactReject.commitmentProofPresent =>
      "\"commitment_proof_present\""
  | some CandidateArtifactReject.receiptRootPresent => "\"receipt_root_present\""
  | some CandidateArtifactReject.recursivePayloadMissing =>
      "\"recursive_payload_missing\""
  | some CandidateArtifactReject.recursiveProofEmpty => "\"recursive_proof_empty\""
  | some CandidateArtifactReject.recursiveProofTooLarge =>
      "\"recursive_proof_too_large\""

def candidateArtifactAdmissionCaseJson
    (name : String)
    (input : CandidateArtifactInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"state_deltas_absent\": " ++ boolJson input.stateDeltasAbsent ++ ",\n"
    ++ "      \"route_payload_decodes_exactly\": "
      ++ boolJson input.routePayloadDecodesExactly ++ ",\n"
    ++ "      \"route_payload_matches_artifact\": "
      ++ boolJson input.routePayloadMatchesArtifact ++ ",\n"
    ++ "      \"artifact_present\": " ++ boolJson input.artifactPresent ++ ",\n"
    ++ "      \"schema_matches\": " ++ boolJson input.schemaMatches ++ ",\n"
    ++ "      \"tx_count\": " ++ toString input.txCount ++ ",\n"
    ++ "      \"max_tx_count\": " ++ toString input.maxTxCount ++ ",\n"
    ++ "      \"da_chunk_count\": " ++ toString input.daChunkCount ++ ",\n"
    ++ "      \"proof_mode_recursive_block\": "
      ++ boolJson input.proofModeRecursiveBlock ++ ",\n"
    ++ "      \"proof_kind_recursive_block_v2\": "
      ++ boolJson input.proofKindRecursiveBlockV2 ++ ",\n"
    ++ "      \"verifier_profile_matches\": "
      ++ boolJson input.verifierProfileMatches ++ ",\n"
    ++ "      \"commitment_proof_empty\": "
      ++ boolJson input.commitmentProofEmpty ++ ",\n"
    ++ "      \"receipt_root_absent\": " ++ boolJson input.receiptRootAbsent ++ ",\n"
    ++ "      \"recursive_payload_present\": "
      ++ boolJson input.recursivePayloadPresent ++ ",\n"
    ++ "      \"recursive_proof_bytes\": "
      ++ toString input.recursiveProofBytes ++ ",\n"
    ++ "      \"max_recursive_proof_bytes\": "
      ++ toString input.maxRecursiveProofBytes ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (candidateArtifactAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (candidateArtifactRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"candidate_artifact_admission_cases\": [\n"
    ++ candidateArtifactAdmissionCaseJson "valid-candidate-artifact"
      validCandidateArtifact ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "exact-recursive-proof-limit-accepts"
      {
        validCandidateArtifact with
        recursiveProofBytes := validCandidateArtifact.maxRecursiveProofBytes
      } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "state-deltas-present-rejected"
      { validCandidateArtifact with stateDeltasAbsent := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "route-payload-decode-failed-rejected"
      { validCandidateArtifact with routePayloadDecodesExactly := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "route-payload-artifact-mismatch-rejected"
      { validCandidateArtifact with routePayloadMatchesArtifact := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "artifact-missing-rejected"
      { validCandidateArtifact with artifactPresent := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "schema-mismatch-rejected"
      { validCandidateArtifact with schemaMatches := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "tx-count-zero-rejected"
      { validCandidateArtifact with txCount := 0 } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "tx-count-too-large-rejected"
      { validCandidateArtifact with txCount := 33 } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "da-chunk-count-zero-rejected"
      { validCandidateArtifact with daChunkCount := 0 } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "wrong-proof-mode-rejected"
      { validCandidateArtifact with proofModeRecursiveBlock := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "wrong-proof-kind-rejected"
      { validCandidateArtifact with proofKindRecursiveBlockV2 := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "verifier-profile-mismatch-rejected"
      { validCandidateArtifact with verifierProfileMatches := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "commitment-proof-present-rejected"
      { validCandidateArtifact with commitmentProofEmpty := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "receipt-root-present-rejected"
      { validCandidateArtifact with receiptRootAbsent := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "recursive-payload-missing-rejected"
      { validCandidateArtifact with recursivePayloadPresent := false } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "recursive-proof-empty-rejected"
      { validCandidateArtifact with recursiveProofBytes := 0 } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "recursive-proof-too-large-rejected"
      {
        validCandidateArtifact with
        recursiveProofBytes := validCandidateArtifact.maxRecursiveProofBytes + 1
      } ++ ",\n"
    ++ candidateArtifactAdmissionCaseJson "state-deltas-precede-schema"
      {
        validCandidateArtifact with
        stateDeltasAbsent := false,
        routePayloadDecodesExactly := false,
        schemaMatches := false
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

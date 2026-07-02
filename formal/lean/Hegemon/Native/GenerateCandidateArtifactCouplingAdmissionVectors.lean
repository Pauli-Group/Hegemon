import Hegemon.Native.CandidateArtifactCouplingAdmission

open Hegemon.Native.CandidateArtifactCouplingAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CandidateArtifactCouplingReject -> String
  | none => "null"
  | some CandidateArtifactCouplingReject.candidateWithoutTransfers =>
      "\"candidate_without_transfers\""
  | some CandidateArtifactCouplingReject.missingOrMultipleCandidateArtifact =>
      "\"missing_or_multiple_candidate_artifact\""
  | some CandidateArtifactCouplingReject.candidateTxCountMismatch =>
      "\"candidate_tx_count_mismatch\""

def candidateArtifactCouplingAdmissionCaseJson
    (name : String)
    (input : CandidateArtifactCouplingInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"transfer_count\": " ++ toString input.transferCount ++ ",\n"
    ++ "      \"candidate_artifact_count\": "
      ++ toString input.candidateArtifactCount ++ ",\n"
    ++ "      \"candidate_tx_count_matches\": "
      ++ boolJson input.candidateTxCountMatches ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (candidateArtifactCouplingAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (candidateArtifactCouplingRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"candidate_artifact_coupling_admission_cases\": [\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "empty-block-accepts" emptyBlock ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "one-transfer-matching-candidate-accepts" matchedCandidate ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "multi-transfer-matching-candidate-accepts"
      {
        transferCount := 3,
        candidateArtifactCount := 1,
        candidateTxCountMatches := true
      } ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "candidate-without-transfers-rejected"
      {
        transferCount := 0,
        candidateArtifactCount := 1,
        candidateTxCountMatches := true
      } ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "multiple-candidates-without-transfers-rejected"
      {
        transferCount := 0,
        candidateArtifactCount := 2,
        candidateTxCountMatches := true
      } ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "missing-candidate-rejected"
      {
        transferCount := 1,
        candidateArtifactCount := 0,
        candidateTxCountMatches := true
      } ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "multiple-candidates-rejected"
      {
        transferCount := 1,
        candidateArtifactCount := 2,
        candidateTxCountMatches := true
      } ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "candidate-tx-count-mismatch-rejected"
      {
        transferCount := 2,
        candidateArtifactCount := 1,
        candidateTxCountMatches := false
      } ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "missing-precedes-tx-mismatch"
      {
        transferCount := 2,
        candidateArtifactCount := 0,
        candidateTxCountMatches := false
      } ++ ",\n"
    ++ candidateArtifactCouplingAdmissionCaseJson
      "no-transfers-precedes-tx-mismatch"
      {
        transferCount := 0,
        candidateArtifactCount := 1,
        candidateTxCountMatches := false
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

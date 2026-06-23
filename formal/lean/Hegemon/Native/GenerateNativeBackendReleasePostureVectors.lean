import Hegemon.Native.NativeBackendReleasePosture

open Hegemon.Native.NativeBackendReleasePosture

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option ReleasePostureReject -> String
  | none => "null"
  | some ReleasePostureReject.candidateReviewStateMismatch =>
      "\"candidate_review_state_mismatch\""
  | some ReleasePostureReject.candidateMaturityMismatch =>
      "\"candidate_maturity_mismatch\""
  | some ReleasePostureReject.candidateExternalReviewComplete =>
      "\"candidate_external_review_complete\""
  | some ReleasePostureReject.acceptedReviewStateMismatch =>
      "\"accepted_review_state_mismatch\""
  | some ReleasePostureReject.acceptedExternalReviewIncomplete =>
      "\"accepted_external_review_incomplete\""
  | some ReleasePostureReject.acceptedMissingArtifact =>
      "\"accepted_missing_artifact\""
  | some ReleasePostureReject.acceptedMalformedArtifact =>
      "\"accepted_malformed_artifact\""

def releasePostureCaseJson
    (name : String)
    (input : ReleasePostureInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"require_accepted\": "
      ++ boolJson input.requireAccepted ++ ",\n"
    ++ "      \"review_state_candidate_under_review\": "
      ++ boolJson input.reviewStateCandidateUnderReview ++ ",\n"
    ++ "      \"review_state_accepted\": "
      ++ boolJson input.reviewStateAccepted ++ ",\n"
    ++ "      \"maturity_structural_candidate\": "
      ++ boolJson input.maturityStructuralCandidate ++ ",\n"
    ++ "      \"external_review_known\": "
      ++ boolJson input.externalReviewKnown ++ ",\n"
    ++ "      \"external_review_completed\": "
      ++ boolJson input.externalReviewCompleted ++ ",\n"
    ++ "      \"acceptance_artifact_present\": "
      ++ boolJson input.acceptanceArtifactPresent ++ ",\n"
    ++ "      \"acceptance_artifact_structured\": "
      ++ boolJson input.acceptanceArtifactStructured ++ ",\n"
    ++ "      \"acceptance_artifact_review_accepted\": "
      ++ boolJson input.acceptanceArtifactReviewAccepted ++ ",\n"
    ++ "      \"acceptance_artifact_external_completed\": "
      ++ boolJson input.acceptanceArtifactExternalCompleted ++ ",\n"
    ++ "      \"acceptance_artifact_claim_hash_bound\": "
      ++ boolJson input.acceptanceArtifactClaimHashBound ++ ",\n"
    ++ "      \"acceptance_artifact_manifest_hash_bound\": "
      ++ boolJson input.acceptanceArtifactManifestHashBound ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (releasePostureAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (releasePostureRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"native_backend_release_posture_cases\": [\n"
    ++ releasePostureCaseJson "candidate-package-accepts"
      candidatePackageInput ++ ",\n"
    ++ releasePostureCaseJson "candidate-without-manifest-accepts"
      candidateWithoutManifestInput ++ ",\n"
    ++ releasePostureCaseJson "candidate-wrong-review-state-rejects"
      candidateWrongReviewStateInput ++ ",\n"
    ++ releasePostureCaseJson "candidate-wrong-maturity-rejects"
      candidateWrongMaturityInput ++ ",\n"
    ++ releasePostureCaseJson "candidate-external-complete-rejects"
      candidateExternalCompleteInput ++ ",\n"
    ++ releasePostureCaseJson "accepted-package-accepts"
      acceptedPackageInput ++ ",\n"
    ++ releasePostureCaseJson "accepted-wrong-review-state-rejects"
      acceptedWrongReviewStateInput ++ ",\n"
    ++ releasePostureCaseJson "accepted-external-incomplete-rejects"
      acceptedExternalIncompleteInput ++ ",\n"
    ++ releasePostureCaseJson "accepted-missing-artifact-rejects"
      acceptedMissingArtifactInput ++ ",\n"
    ++ releasePostureCaseJson "accepted-malformed-artifact-rejects"
      acceptedMalformedArtifactInput ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

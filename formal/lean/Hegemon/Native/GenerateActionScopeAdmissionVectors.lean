import Hegemon.Native.ActionScopeAdmission

open Hegemon.Native.ActionScopeAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option ScopeReject -> String
  | none => "null"
  | some ScopeReject.candidateArtifactPayloadWrongRoute =>
      "\"candidate_artifact_payload_wrong_route\""
  | some ScopeReject.bridgeScopeInvalid => "\"bridge_scope_invalid\""
  | some ScopeReject.candidateScopeInvalid => "\"candidate_scope_invalid\""
  | some ScopeReject.candidatePayloadMissing => "\"candidate_payload_missing\""
  | some ScopeReject.coinbaseScopeInvalid => "\"coinbase_scope_invalid\""
  | some ScopeReject.unsupportedActionRoute => "\"unsupported_action_route\""
  | some ScopeReject.transferScopeInvalid => "\"transfer_scope_invalid\""

def routeJson : Option ActionRoute -> String
  | none => "null"
  | some ActionRoute.bridge => "\"bridge\""
  | some ActionRoute.candidateArtifact => "\"candidate_artifact\""
  | some ActionRoute.coinbase => "\"coinbase\""
  | some ActionRoute.transfer => "\"transfer\""

def actionScopeAdmissionCaseJson (name : String) (input : ScopeInput) : String :=
  let route := scopeAdmissionRoute input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"candidate_artifact_payload_scoped\": "
      ++ boolJson input.candidateArtifactPayloadScoped ++ ",\n"
    ++ "      \"bridge_route\": " ++ boolJson input.bridgeRoute ++ ",\n"
    ++ "      \"bridge_scope_valid\": " ++ boolJson input.bridgeScopeValid ++ ",\n"
    ++ "      \"candidate_artifact_route\": "
      ++ boolJson input.candidateArtifactRoute ++ ",\n"
    ++ "      \"candidate_scope_valid\": " ++ boolJson input.candidateScopeValid ++ ",\n"
    ++ "      \"candidate_payload_present\": "
      ++ boolJson input.candidatePayloadPresent ++ ",\n"
    ++ "      \"coinbase_route\": " ++ boolJson input.coinbaseRoute ++ ",\n"
    ++ "      \"coinbase_scope_valid\": " ++ boolJson input.coinbaseScopeValid ++ ",\n"
    ++ "      \"transfer_route\": " ++ boolJson input.transferRoute ++ ",\n"
    ++ "      \"transfer_scope_valid\": " ++ boolJson input.transferScopeValid ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson route.isSome ++ ",\n"
    ++ "      \"expected_route\": " ++ routeJson route ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson (scopeAdmissionRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"action_scope_admission_cases\": [\n"
    ++ actionScopeAdmissionCaseJson "valid-bridge-route" validBridge ++ ",\n"
    ++ actionScopeAdmissionCaseJson "valid-candidate-artifact-route"
      validCandidateArtifact ++ ",\n"
    ++ actionScopeAdmissionCaseJson "valid-coinbase-route" validCoinbase ++ ",\n"
    ++ actionScopeAdmissionCaseJson "valid-transfer-route" validTransfer ++ ",\n"
    ++ actionScopeAdmissionCaseJson "candidate-artifact-payload-wrong-route-rejected"
      { validTransfer with candidateArtifactPayloadScoped := false } ++ ",\n"
    ++ actionScopeAdmissionCaseJson "bridge-scope-invalid-rejected"
      { validBridge with bridgeScopeValid := false } ++ ",\n"
    ++ actionScopeAdmissionCaseJson "candidate-scope-invalid-rejected"
      { validCandidateArtifact with candidateScopeValid := false } ++ ",\n"
    ++ actionScopeAdmissionCaseJson "candidate-payload-missing-rejected"
      { validCandidateArtifact with candidatePayloadPresent := false } ++ ",\n"
    ++ actionScopeAdmissionCaseJson "coinbase-scope-invalid-rejected"
      { validCoinbase with coinbaseScopeValid := false } ++ ",\n"
    ++ actionScopeAdmissionCaseJson "unsupported-action-route-rejected"
      { validTransfer with transferRoute := false, transferScopeValid := false } ++ ",\n"
    ++ actionScopeAdmissionCaseJson "transfer-scope-invalid-rejected"
      { validTransfer with transferScopeValid := false } ++ ",\n"
    ++ actionScopeAdmissionCaseJson "wrong-candidate-artifact-route-precedes-bridge-scope"
      {
        validBridge with
        candidateArtifactPayloadScoped := false,
        bridgeScopeValid := false
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

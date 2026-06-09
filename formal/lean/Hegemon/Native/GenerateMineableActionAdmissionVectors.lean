import Hegemon.Native.MineableActionAdmission

open Hegemon.Native.MineableActionAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option MineableActionReject -> String
  | none => "null"
  | some MineableActionReject.unselectedCandidateArtifact =>
      "\"unselected_candidate_artifact\""
  | some MineableActionReject.sidecarCiphertextMissing =>
      "\"sidecar_ciphertext_missing\""
  | some MineableActionReject.sidecarCiphertextSizeMissing =>
      "\"sidecar_ciphertext_size_missing\""
  | some MineableActionReject.sidecarCiphertextSizeMismatch =>
      "\"sidecar_ciphertext_size_mismatch\""

def mineableActionCaseJson (name : String) (input : MineableActionInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"candidate_artifact_route\": "
      ++ boolJson input.candidateArtifactRoute ++ ",\n"
    ++ "      \"candidate_artifact_selected\": "
      ++ boolJson input.candidateArtifactSelected ++ ",\n"
    ++ "      \"sidecar_transfer_route\": "
      ++ boolJson input.sidecarTransferRoute ++ ",\n"
    ++ "      \"sidecar_ciphertexts_available\": "
      ++ boolJson input.sidecarCiphertextsAvailable ++ ",\n"
    ++ "      \"sidecar_ciphertext_sizes_present\": "
      ++ boolJson input.sidecarCiphertextSizesPresent ++ ",\n"
    ++ "      \"sidecar_ciphertext_sizes_match\": "
      ++ boolJson input.sidecarCiphertextSizesMatch ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (mineableActionAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (mineableActionRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"mineable_action_admission_cases\": [\n"
    ++ mineableActionCaseJson "plain-action-accepts" plainAction ++ ",\n"
    ++ mineableActionCaseJson "selected-candidate-accepts"
      selectedCandidate ++ ",\n"
    ++ mineableActionCaseJson "valid-sidecar-transfer-accepts"
      validSidecarTransfer ++ ",\n"
    ++ mineableActionCaseJson "unselected-candidate-rejected"
      { selectedCandidate with candidateArtifactSelected := false } ++ ",\n"
    ++ mineableActionCaseJson "sidecar-ciphertext-missing-rejected"
      { validSidecarTransfer with sidecarCiphertextsAvailable := false } ++ ",\n"
    ++ mineableActionCaseJson "sidecar-ciphertext-size-missing-rejected"
      { validSidecarTransfer with sidecarCiphertextSizesPresent := false } ++ ",\n"
    ++ mineableActionCaseJson "sidecar-ciphertext-size-mismatch-rejected"
      { validSidecarTransfer with sidecarCiphertextSizesMatch := false } ++ ",\n"
    ++ mineableActionCaseJson "candidate-precedes-sidecar-missing"
      { selectedCandidate with
        candidateArtifactSelected := false,
        sidecarTransferRoute := true,
        sidecarCiphertextsAvailable := false } ++ ",\n"
    ++ mineableActionCaseJson "sidecar-availability-precedes-size-missing"
      { validSidecarTransfer with
        sidecarCiphertextsAvailable := false,
        sidecarCiphertextSizesPresent := false } ++ ",\n"
    ++ mineableActionCaseJson "plain-action-ignores-sidecar-metadata"
      plainAction ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

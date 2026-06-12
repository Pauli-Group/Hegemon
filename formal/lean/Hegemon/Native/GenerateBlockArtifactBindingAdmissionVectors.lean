import Hegemon.Native.BlockArtifactBindingAdmission

open Hegemon.Native.BlockArtifactBindingAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def txLeafActionRejectionJson :
    Option TxLeafActionBindingReject -> String
  | none => "null"
  | some TxLeafActionBindingReject.nullifiersMismatch =>
      "\"nullifiers_mismatch\""
  | some TxLeafActionBindingReject.commitmentsMismatch =>
      "\"commitments_mismatch\""
  | some TxLeafActionBindingReject.ciphertextHashesMismatch =>
      "\"ciphertext_hashes_mismatch\""
  | some TxLeafActionBindingReject.versionMismatch =>
      "\"version_mismatch\""
  | some TxLeafActionBindingReject.feeMismatch =>
      "\"fee_mismatch\""
  | some TxLeafActionBindingReject.ciphertextPayloadHashMismatch =>
      "\"ciphertext_payload_hash_mismatch\""

def candidateArtifactRejectionJson :
    Option CandidateArtifactBindingReject -> String
  | none => "null"
  | some CandidateArtifactBindingReject.daRootMismatch =>
      "\"da_root_mismatch\""
  | some CandidateArtifactBindingReject.txStatementCommitmentMismatch =>
      "\"tx_statement_commitment_mismatch\""
  | some CandidateArtifactBindingReject.recursiveStateRootMismatch =>
      "\"recursive_state_root_mismatch\""

def txLeafActionBindingCaseJson
    (name : String)
    (input : TxLeafActionBindingInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"nullifiers_match\": " ++ boolJson input.nullifiersMatch ++ ",\n"
    ++ "      \"commitments_match\": " ++ boolJson input.commitmentsMatch ++ ",\n"
    ++ "      \"ciphertext_hashes_match\": "
      ++ boolJson input.ciphertextHashesMatch ++ ",\n"
    ++ "      \"version_matches\": " ++ boolJson input.versionMatches ++ ",\n"
    ++ "      \"fee_matches\": " ++ boolJson input.feeMatches ++ ",\n"
    ++ "      \"ciphertext_payload_hashes_match\": "
      ++ boolJson input.ciphertextPayloadHashesMatch ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (txLeafActionBindingAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ txLeafActionRejectionJson
          (txLeafActionBindingRejection input) ++ "\n"
    ++ "    }"

def candidateArtifactBindingCaseJson
    (name : String)
    (input : CandidateArtifactBindingInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"da_root_matches\": " ++ boolJson input.daRootMatches ++ ",\n"
    ++ "      \"tx_statements_commitment_matches\": "
      ++ boolJson input.txStatementsCommitmentMatches ++ ",\n"
    ++ "      \"recursive_state_root_matches\": "
      ++ boolJson input.recursiveStateRootMatches ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (candidateArtifactBindingAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ candidateArtifactRejectionJson
          (candidateArtifactBindingRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"tx_leaf_action_binding_cases\": [\n"
    ++ txLeafActionBindingCaseJson
      "valid-tx-leaf-action-binding" validTxLeafActionBinding ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "nullifiers-mismatch-rejected"
      { validTxLeafActionBinding with nullifiersMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "commitments-mismatch-rejected"
      { validTxLeafActionBinding with commitmentsMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "ciphertext-hashes-mismatch-rejected"
      { validTxLeafActionBinding with ciphertextHashesMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "version-mismatch-rejected"
      { validTxLeafActionBinding with versionMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "fee-mismatch-rejected"
      { validTxLeafActionBinding with feeMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "ciphertext-payload-hash-mismatch-rejected"
      { validTxLeafActionBinding with
        ciphertextPayloadHashesMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "nullifiers-precede-commitments"
      { validTxLeafActionBinding with
        nullifiersMatch := false,
        commitmentsMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "version-precedes-fee-and-payload-hashes"
      { validTxLeafActionBinding with
        versionMatches := false,
        feeMatches := false,
        ciphertextPayloadHashesMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "fee-precedes-payload-hashes"
      { validTxLeafActionBinding with
        feeMatches := false,
        ciphertextPayloadHashesMatch := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"candidate_artifact_binding_cases\": [\n"
    ++ candidateArtifactBindingCaseJson
      "valid-candidate-artifact-binding" validCandidateArtifactBinding ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "da-root-mismatch-rejected"
      { validCandidateArtifactBinding with daRootMatches := false } ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "tx-statement-commitment-mismatch-rejected"
      { validCandidateArtifactBinding with
        txStatementsCommitmentMatches := false } ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "recursive-state-root-mismatch-rejected"
      { validCandidateArtifactBinding with
        recursiveStateRootMatches := false } ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "da-root-precedes-statement-commitment"
      { validCandidateArtifactBinding with
        daRootMatches := false,
        txStatementsCommitmentMatches := false } ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "statement-commitment-precedes-state-root"
      { validCandidateArtifactBinding with
        txStatementsCommitmentMatches := false,
        recursiveStateRootMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

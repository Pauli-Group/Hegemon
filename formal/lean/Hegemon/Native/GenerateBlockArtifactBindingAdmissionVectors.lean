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
  | some TxLeafActionBindingReject.inputCountMismatch =>
      "\"input_count_mismatch\""
  | some TxLeafActionBindingReject.outputCountMismatch =>
      "\"output_count_mismatch\""
  | some TxLeafActionBindingReject.versionMismatch =>
      "\"version_mismatch\""
  | some TxLeafActionBindingReject.feeMismatch =>
      "\"fee_mismatch\""
  | some TxLeafActionBindingReject.stablecoinPayloadMismatch =>
      "\"stablecoin_payload_mismatch\""
  | some TxLeafActionBindingReject.balanceTagMismatch =>
      "\"balance_tag_mismatch\""
  | some TxLeafActionBindingReject.receiptStatementHashMismatch =>
      "\"receipt_statement_hash_mismatch\""
  | some TxLeafActionBindingReject.publicInputsDigestMismatch =>
      "\"public_inputs_digest_mismatch\""
  | some TxLeafActionBindingReject.proofDigestMismatch =>
      "\"proof_digest_mismatch\""
  | some TxLeafActionBindingReject.proofBackendMismatch =>
      "\"proof_backend_mismatch\""
  | some TxLeafActionBindingReject.ciphertextPayloadHashMismatch =>
      "\"ciphertext_payload_hash_mismatch\""

def candidateArtifactRejectionJson :
    Option CandidateArtifactBindingReject -> String
  | none => "null"
  | some CandidateArtifactBindingReject.daRootMismatch =>
      "\"da_root_mismatch\""
  | some CandidateArtifactBindingReject.daChunkCountMismatch =>
      "\"da_chunk_count_mismatch\""
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
    ++ "      \"input_count_matches\": "
      ++ boolJson input.inputCountMatches ++ ",\n"
    ++ "      \"output_count_matches\": "
      ++ boolJson input.outputCountMatches ++ ",\n"
    ++ "      \"version_matches\": " ++ boolJson input.versionMatches ++ ",\n"
    ++ "      \"fee_matches\": " ++ boolJson input.feeMatches ++ ",\n"
    ++ "      \"stablecoin_payload_matches\": "
      ++ boolJson input.stablecoinPayloadMatches ++ ",\n"
    ++ "      \"balance_tag_matches\": "
      ++ boolJson input.balanceTagMatches ++ ",\n"
    ++ "      \"receipt_statement_hash_matches\": "
      ++ boolJson input.receiptStatementHashMatches ++ ",\n"
    ++ "      \"public_inputs_digest_matches\": "
      ++ boolJson input.publicInputsDigestMatches ++ ",\n"
    ++ "      \"proof_digest_matches\": "
      ++ boolJson input.proofDigestMatches ++ ",\n"
    ++ "      \"proof_backend_matches\": "
      ++ boolJson input.proofBackendMatches ++ ",\n"
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
    ++ "      \"da_chunk_count_matches\": "
      ++ boolJson input.daChunkCountMatches ++ ",\n"
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
      "input-count-mismatch-rejected"
      { validTxLeafActionBinding with inputCountMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "output-count-mismatch-rejected"
      { validTxLeafActionBinding with outputCountMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "version-mismatch-rejected"
      { validTxLeafActionBinding with versionMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "fee-mismatch-rejected"
      { validTxLeafActionBinding with feeMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "stablecoin-payload-mismatch-rejected"
      { validTxLeafActionBinding with
        stablecoinPayloadMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "balance-tag-mismatch-rejected"
      { validTxLeafActionBinding with balanceTagMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "receipt-statement-hash-mismatch-rejected"
      { validTxLeafActionBinding with
        receiptStatementHashMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "public-inputs-digest-mismatch-rejected"
      { validTxLeafActionBinding with
        publicInputsDigestMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "proof-digest-mismatch-rejected"
      { validTxLeafActionBinding with proofDigestMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "proof-backend-mismatch-rejected"
      { validTxLeafActionBinding with proofBackendMatches := false } ++ ",\n"
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
      "ciphertext-hashes-precede-counts"
      { validTxLeafActionBinding with
        ciphertextHashesMatch := false,
        inputCountMatches := false,
        outputCountMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "input-count-precedes-output-count-and-version"
      { validTxLeafActionBinding with
        inputCountMatches := false,
        outputCountMatches := false,
        versionMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "output-count-precedes-version"
      { validTxLeafActionBinding with
        outputCountMatches := false,
        versionMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "version-precedes-fee-stablecoin-and-payload-hashes"
      { validTxLeafActionBinding with
        versionMatches := false,
        feeMatches := false,
        stablecoinPayloadMatches := false,
        ciphertextPayloadHashesMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "fee-precedes-stablecoin-and-payload-hashes"
      { validTxLeafActionBinding with
        feeMatches := false,
        stablecoinPayloadMatches := false,
        balanceTagMatches := false,
        ciphertextPayloadHashesMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "stablecoin-payload-precedes-balance-tag"
      { validTxLeafActionBinding with
        stablecoinPayloadMatches := false,
        balanceTagMatches := false,
        receiptStatementHashMatches := false,
        publicInputsDigestMatches := false,
        proofDigestMatches := false,
        proofBackendMatches := false,
        ciphertextPayloadHashesMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "balance-tag-precedes-receipt-and-digests"
      { validTxLeafActionBinding with
        balanceTagMatches := false,
        receiptStatementHashMatches := false,
        publicInputsDigestMatches := false,
        proofDigestMatches := false,
        proofBackendMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "receipt-statement-precedes-digests"
      { validTxLeafActionBinding with
        receiptStatementHashMatches := false,
        publicInputsDigestMatches := false,
        proofDigestMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "public-inputs-digest-precedes-proof-digest"
      { validTxLeafActionBinding with
        publicInputsDigestMatches := false,
        proofDigestMatches := false,
        proofBackendMatches := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "proof-digest-precedes-backend-and-payload"
      { validTxLeafActionBinding with
        proofDigestMatches := false,
        proofBackendMatches := false,
        ciphertextPayloadHashesMatch := false } ++ ",\n"
    ++ txLeafActionBindingCaseJson
      "proof-backend-precedes-payload"
      { validTxLeafActionBinding with
        proofBackendMatches := false,
        ciphertextPayloadHashesMatch := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"candidate_artifact_binding_cases\": [\n"
    ++ candidateArtifactBindingCaseJson
      "valid-candidate-artifact-binding" validCandidateArtifactBinding ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "da-root-mismatch-rejected"
      { validCandidateArtifactBinding with daRootMatches := false } ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "da-chunk-count-mismatch-rejected"
      { validCandidateArtifactBinding with
        daChunkCountMatches := false } ++ ",\n"
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
        daChunkCountMatches := false,
        txStatementsCommitmentMatches := false } ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "da-chunk-count-precedes-statement-commitment"
      { validCandidateArtifactBinding with
        daChunkCountMatches := false,
        txStatementsCommitmentMatches := false,
        recursiveStateRootMatches := false } ++ ",\n"
    ++ candidateArtifactBindingCaseJson
      "statement-commitment-precedes-state-root"
      { validCandidateArtifactBinding with
        txStatementsCommitmentMatches := false,
        recursiveStateRootMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

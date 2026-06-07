import Hegemon.Consensus.ReceiptRootAdmission

open Hegemon.Consensus.ReceiptRootAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def artifactKindJson : ArtifactKind -> String
  | ArtifactKind.inlineTx => "inline_tx"
  | ArtifactKind.txLeaf => "tx_leaf"
  | ArtifactKind.receiptRoot => "receipt_root"
  | ArtifactKind.recursiveBlockV1 => "recursive_block_v1"
  | ArtifactKind.recursiveBlockV2 => "recursive_block_v2"

def payloadRejectJson : Option PayloadReject -> String
  | none => "null"
  | some PayloadReject.leafCountMismatch => "\"leaf_count_mismatch\""
  | some PayloadReject.receiptCountMismatch => "\"receipt_count_mismatch\""
  | some PayloadReject.missingClaimReceipts => "\"missing_claim_receipts\""
  | some PayloadReject.receiptsMismatch => "\"receipts_mismatch\""
  | some PayloadReject.missingTransactionProofs => "\"missing_transaction_proofs\""

def artifactRejectJson : Option ArtifactReject -> String
  | none => "null"
  | some ArtifactReject.artifactKindMismatch => "\"artifact_kind_mismatch\""
  | some ArtifactReject.verifierProfileMismatch => "\"verifier_profile_mismatch\""
  | some ArtifactReject.artifactTooLarge => "\"artifact_too_large\""
  | some ArtifactReject.missingTransactionProofs => "\"missing_transaction_proofs\""
  | some ArtifactReject.transactionProofCountMismatch => "\"transaction_proof_count_mismatch\""

def statementRejectJson : Option StatementReject -> String
  | none => "null"
  | some StatementReject.statementCommitmentMismatch => "\"statement_commitment_mismatch\""

def verifiedMetadataRejectJson : Option VerifiedMetadataReject -> String
  | none => "null"
  | some VerifiedMetadataReject.verifiedLeafCountMismatch => "\"verified_leaf_count_mismatch\""

def payloadCaseJson (name : String) (input : PayloadAdmissionInput) : String :=
  let rejection := evaluatePayloadRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"payload_leaf_count_matches\": "
    ++ boolJson input.payloadLeafCountMatches ++ ",\n"
    ++ "      \"payload_receipt_count_matches\": "
    ++ boolJson input.payloadReceiptCountMatches ++ ",\n"
    ++ "      \"has_claim_receipts\": " ++ boolJson input.hasClaimReceipts ++ ",\n"
    ++ "      \"payload_receipts_match_claims\": "
    ++ boolJson input.payloadReceiptsMatchClaims ++ ",\n"
    ++ "      \"has_tx_artifacts\": " ++ boolJson input.hasTxArtifacts ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ payloadRejectJson rejection ++ "\n"
    ++ "    }"

def artifactCaseJson (name : String) (input : ArtifactAdmissionInput) : String :=
  let rejection := evaluateArtifactRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"envelope_kind\": \"" ++ artifactKindJson input.envelopeKind ++ "\",\n"
    ++ "      \"envelope_verifier_profile_matches\": "
    ++ boolJson input.envelopeVerifierProfileMatches ++ ",\n"
    ++ "      \"artifact_bytes_len\": " ++ toString input.artifactBytesLen ++ ",\n"
    ++ "      \"max_artifact_bytes\": " ++ toString input.maxArtifactBytes ++ ",\n"
    ++ "      \"has_tx_artifacts\": " ++ boolJson input.hasTxArtifacts ++ ",\n"
    ++ "      \"tx_artifact_count_matches\": "
    ++ boolJson input.txArtifactCountMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ artifactRejectJson rejection ++ "\n"
    ++ "    }"

def statementCaseJson (name : String) (input : StatementBindingInput) : String :=
  let rejection := evaluateStatementRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"statement_commitment_matches\": "
    ++ boolJson input.statementCommitmentMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ statementRejectJson rejection ++ "\n"
    ++ "    }"

def verifiedMetadataCaseJson (name : String) (input : VerifiedMetadataInput) : String :=
  let rejection := evaluateVerifiedMetadataRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"verified_leaf_count_matches\": "
    ++ boolJson input.verifiedLeafCountMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ verifiedMetadataRejectJson rejection ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"payload_cases\": [\n"
    ++ payloadCaseJson "valid-payload" validPayload ++ ",\n"
    ++ payloadCaseJson "leaf-count-mismatch-rejected"
      { validPayload with payloadLeafCountMatches := false } ++ ",\n"
    ++ payloadCaseJson "receipt-count-mismatch-rejected"
      { validPayload with payloadReceiptCountMatches := false } ++ ",\n"
    ++ payloadCaseJson "missing-claim-receipts-rejected"
      { validPayload with hasClaimReceipts := false } ++ ",\n"
    ++ payloadCaseJson "receipts-mismatch-rejected"
      { validPayload with payloadReceiptsMatchClaims := false } ++ ",\n"
    ++ payloadCaseJson "missing-tx-artifacts-rejected"
      { validPayload with hasTxArtifacts := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"artifact_cases\": [\n"
    ++ artifactCaseJson "valid-artifact" validArtifact ++ ",\n"
    ++ artifactCaseJson "wrong-kind-rejected"
      { validArtifact with envelopeKind := ArtifactKind.recursiveBlockV2 } ++ ",\n"
    ++ artifactCaseJson "profile-mismatch-rejected"
      { validArtifact with envelopeVerifierProfileMatches := false } ++ ",\n"
    ++ artifactCaseJson "oversized-artifact-rejected"
      { validArtifact with artifactBytesLen := 513 } ++ ",\n"
    ++ artifactCaseJson "missing-tx-artifacts-rejected"
      { validArtifact with hasTxArtifacts := false } ++ ",\n"
    ++ artifactCaseJson "tx-artifact-count-mismatch-rejected"
      { validArtifact with txArtifactCountMatches := false } ++ ",\n"
    ++ artifactCaseJson "exact-size-limit-accepted"
      { validArtifact with artifactBytesLen := 512, maxArtifactBytes := 512 } ++ "\n"
    ++ "  ],\n"
    ++ "  \"statement_cases\": [\n"
    ++ statementCaseJson "valid-statement" validStatement ++ ",\n"
    ++ statementCaseJson "statement-commitment-mismatch-rejected"
      { statementCommitmentMatches := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"verified_metadata_cases\": [\n"
    ++ verifiedMetadataCaseJson "valid-verified-metadata" validVerifiedMetadata ++ ",\n"
    ++ verifiedMetadataCaseJson "verified-leaf-count-mismatch-rejected"
      { verifiedLeafCountMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

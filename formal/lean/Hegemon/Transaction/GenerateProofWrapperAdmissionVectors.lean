import Hegemon.Transaction.ProofWrapperAdmission

open Hegemon.Transaction.ProofWrapperAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option ProofWrapperReject -> String
  | none => "null"
  | some ProofWrapperReject.nonExactConsumption => "\"non_exact_consumption\""
  | some ProofWrapperReject.nonCanonicalReencode => "\"non_canonical_reencode\""
  | some ProofWrapperReject.unsupportedBackend => "\"unsupported_backend\""
  | some ProofWrapperReject.missingProofBytes => "\"missing_proof_bytes\""
  | some ProofWrapperReject.missingSerializedPublicInputs =>
      "\"missing_serialized_public_inputs\""
  | some ProofWrapperReject.invalidPublicInputs => "\"invalid_public_inputs\""
  | some ProofWrapperReject.nullifierVectorMismatch => "\"nullifier_vector_mismatch\""
  | some ProofWrapperReject.commitmentVectorMismatch => "\"commitment_vector_mismatch\""
  | some ProofWrapperReject.balanceSlotMismatch => "\"balance_slot_mismatch\""
  | some ProofWrapperReject.verifierRejected => "\"verifier_rejected\""

def caseJson (name : String) (input : ProofWrapperInput) : String :=
  let rejection := evaluateProofWrapperRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"exact_consumption\": " ++ boolJson input.exactConsumption ++ ",\n"
    ++ "      \"canonical_reencode\": " ++ boolJson input.canonicalReencode ++ ",\n"
    ++ "      \"backend_supported\": " ++ boolJson input.backendSupported ++ ",\n"
    ++ "      \"proof_bytes_present\": " ++ boolJson input.proofBytesPresent ++ ",\n"
    ++ "      \"serialized_public_inputs_present\": "
    ++ boolJson input.serializedPublicInputsPresent ++ ",\n"
    ++ "      \"public_inputs_valid\": " ++ boolJson input.publicInputsValid ++ ",\n"
    ++ "      \"nullifier_vector_agrees\": "
    ++ boolJson input.nullifierVectorAgrees ++ ",\n"
    ++ "      \"commitment_vector_agrees\": "
    ++ boolJson input.commitmentVectorAgrees ++ ",\n"
    ++ "      \"balance_slots_agree\": " ++ boolJson input.balanceSlotsAgree ++ ",\n"
    ++ "      \"verifier_accepts\": " ++ boolJson input.verifierAccepts ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection.isNone) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson rejection ++ "\n"
    ++ "    }"

def metadataProjectionCaseJson
    (name mutation : String)
    (input : ProofWrapperMetadataProjectionInput) : String :=
  let accepted := proofWrapperMetadataProjectionAccepts input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"mutation\": \"" ++ mutation ++ "\",\n"
    ++ "      \"wrapper_nullifiers_equal_bound_statement\": "
    ++ boolJson input.wrapperNullifiersEqualBoundStatement ++ ",\n"
    ++ "      \"wrapper_commitments_equal_bound_statement\": "
    ++ boolJson input.wrapperCommitmentsEqualBoundStatement ++ ",\n"
    ++ "      \"wrapper_balance_slots_equal_bound_statement\": "
    ++ boolJson input.wrapperBalanceSlotsEqualBoundStatement ++ ",\n"
    ++ "      \"serialized_public_inputs_equal_bound_projection\": "
    ++ boolJson input.serializedPublicInputsEqualBoundProjection ++ ",\n"
    ++ "      \"public_nullifier_rows_within_statement_boundary\": "
    ++ boolJson input.publicNullifierRowsWithinStatementBoundary ++ ",\n"
    ++ "      \"public_ciphertext_rows_within_statement_boundary\": "
    ++ boolJson input.publicCiphertextRowsWithinStatementBoundary ++ ",\n"
    ++ "      \"public_asset_rows_within_statement_boundary\": "
    ++ boolJson input.publicAssetRowsWithinStatementBoundary ++ ",\n"
    ++ "      \"expected_projection_valid\": " ++ boolJson accepted ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"proof_wrapper_admission_cases\": [\n"
    ++ caseJson "valid-wrapper" validWrapper ++ ",\n"
    ++ caseJson "non-exact-consumption-rejected"
        { validWrapper with exactConsumption := false } ++ ",\n"
    ++ caseJson "non-canonical-reencode-rejected"
        { validWrapper with canonicalReencode := false } ++ ",\n"
    ++ caseJson "unsupported-backend-rejected"
        { validWrapper with backendSupported := false } ++ ",\n"
    ++ caseJson "missing-proof-bytes-rejected"
        { validWrapper with proofBytesPresent := false } ++ ",\n"
    ++ caseJson "missing-serialized-public-inputs-rejected"
        { validWrapper with serializedPublicInputsPresent := false } ++ ",\n"
    ++ caseJson "invalid-public-inputs-rejected"
        { validWrapper with publicInputsValid := false } ++ ",\n"
    ++ caseJson "nullifier-vector-mismatch-rejected"
        { validWrapper with nullifierVectorAgrees := false } ++ ",\n"
    ++ caseJson "commitment-vector-mismatch-rejected"
        { validWrapper with commitmentVectorAgrees := false } ++ ",\n"
    ++ caseJson "balance-slot-mismatch-rejected"
        { validWrapper with balanceSlotsAgree := false } ++ ",\n"
    ++ caseJson "verifier-rejection-rejected"
        { validWrapper with verifierAccepts := false } ++ ",\n"
    ++ caseJson "codec-precedence-before-backend"
        { validWrapper with exactConsumption := false, backendSupported := false } ++ ",\n"
    ++ caseJson "public-input-precedence-before-summary-vectors"
        { validWrapper with publicInputsValid := false, nullifierVectorAgrees := false } ++ ",\n"
    ++ caseJson "nullifier-vector-precedence-before-commitment-vector"
        { validWrapper with nullifierVectorAgrees := false, commitmentVectorAgrees := false } ++ ",\n"
    ++ caseJson "commitment-vector-precedence-before-balance"
        { validWrapper with commitmentVectorAgrees := false, balanceSlotsAgree := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"proof_wrapper_metadata_projection_cases\": [\n"
    ++ metadataProjectionCaseJson "valid-metadata-projection"
        "none"
        validMetadataProjection ++ ",\n"
    ++ metadataProjectionCaseJson "wrapper-nullifier-metadata-drift-rejected"
        "wrapper_nullifier_drift"
        { validMetadataProjection with
          wrapperNullifiersEqualBoundStatement := false } ++ ",\n"
    ++ metadataProjectionCaseJson "wrapper-commitment-metadata-drift-rejected"
        "wrapper_commitment_drift"
        { validMetadataProjection with
          wrapperCommitmentsEqualBoundStatement := false } ++ ",\n"
    ++ metadataProjectionCaseJson "wrapper-balance-metadata-drift-rejected"
        "wrapper_balance_slot_drift"
        { validMetadataProjection with
          wrapperBalanceSlotsEqualBoundStatement := false } ++ ",\n"
    ++ metadataProjectionCaseJson "serialized-public-input-projection-drift-rejected"
        "serialized_public_input_projection_drift"
        { validMetadataProjection with
          serializedPublicInputsEqualBoundProjection := false } ++ ",\n"
    ++ metadataProjectionCaseJson "public-nullifier-row-outside-boundary-rejected"
        "public_nullifier_row_outside_boundary"
        { validMetadataProjection with
          publicNullifierRowsWithinStatementBoundary := false } ++ ",\n"
    ++ metadataProjectionCaseJson "public-ciphertext-row-outside-boundary-rejected"
        "public_ciphertext_row_outside_boundary"
        { validMetadataProjection with
          publicCiphertextRowsWithinStatementBoundary := false } ++ ",\n"
    ++ metadataProjectionCaseJson "public-asset-row-outside-boundary-rejected"
        "public_asset_row_outside_boundary"
        { validMetadataProjection with
          publicAssetRowsWithinStatementBoundary := false } ++ ",\n"
    ++ metadataProjectionCaseJson "serialized-asset-row-outside-boundary-rejected"
        "serialized_asset_row_outside_boundary"
        { validMetadataProjection with
          publicAssetRowsWithinStatementBoundary := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

import Hegemon.Transaction.SmallWoodVerifierStatementProjection

open Hegemon.Transaction.SmallWoodTranscriptBinding
open Hegemon.Transaction.SmallWoodVerifierStatementProjection

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option VerifierStatementProjectionReject -> String
  | none => "null"
  | some VerifierStatementProjectionReject.candidateWrapperRejected =>
      "\"candidate_wrapper_rejected\""
  | some VerifierStatementProjectionReject.publicStatementBindingRejected =>
      "\"public_statement_binding_rejected\""
  | some VerifierStatementProjectionReject.transcriptBindingRejected =>
      "\"transcript_binding_rejected\""
  | some VerifierStatementProjectionReject.arithmetizationMismatch =>
      "\"arithmetization_mismatch\""
  | some VerifierStatementProjectionReject.publicValuesMismatch =>
      "\"public_values_mismatch\""
  | some VerifierStatementProjectionReject.rowCountMismatch =>
      "\"row_count_mismatch\""
  | some VerifierStatementProjectionReject.packingFactorMismatch =>
      "\"packing_factor_mismatch\""
  | some VerifierStatementProjectionReject.constraintDegreeMismatch =>
      "\"constraint_degree_mismatch\""
  | some VerifierStatementProjectionReject.linearConstraintOffsetsMismatch =>
      "\"linear_constraint_offsets_mismatch\""
  | some VerifierStatementProjectionReject.linearConstraintIndicesMismatch =>
      "\"linear_constraint_indices_mismatch\""
  | some VerifierStatementProjectionReject.linearConstraintCoefficientsMismatch =>
      "\"linear_constraint_coefficients_mismatch\""
  | some VerifierStatementProjectionReject.linearConstraintTargetsMismatch =>
      "\"linear_constraint_targets_mismatch\""
  | some VerifierStatementProjectionReject.auxiliaryWitnessLimbCountMismatch =>
      "\"auxiliary_witness_limb_count_mismatch\""
  | some VerifierStatementProjectionReject.profileMaterialMismatch =>
      "\"profile_material_mismatch\""
  | some VerifierStatementProjectionReject.transcriptBytesMismatch =>
      "\"transcript_bytes_mismatch\""
  | some VerifierStatementProjectionReject.proofBytesEmpty =>
      "\"proof_bytes_empty\""
  | some VerifierStatementProjectionReject.verifierRejected =>
      "\"verifier_rejected\""

def projectionCaseJson
    (name fixture : String)
    (arithmetization : Nat)
    (input : VerifierStatementProjectionInput) : String :=
  let rejection := evaluateSmallWoodVerifierStatementProjectionRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"arithmetization\": " ++ toString arithmetization ++ ",\n"
    ++ "      \"candidate_wrapper_accepted\": "
    ++ boolJson input.candidateWrapperAccepted ++ ",\n"
    ++ "      \"public_statement_binding_accepted\": "
    ++ boolJson input.publicStatementBindingAccepted ++ ",\n"
    ++ "      \"transcript_binding_accepted\": "
    ++ boolJson input.transcriptBindingAccepted ++ ",\n"
    ++ "      \"arithmetization_matches\": "
    ++ boolJson input.arithmetizationMatches ++ ",\n"
    ++ "      \"public_values_match\": " ++ boolJson input.publicValuesMatch ++ ",\n"
    ++ "      \"row_count_matches\": " ++ boolJson input.rowCountMatches ++ ",\n"
    ++ "      \"packing_factor_matches\": "
    ++ boolJson input.packingFactorMatches ++ ",\n"
    ++ "      \"constraint_degree_matches\": "
    ++ boolJson input.constraintDegreeMatches ++ ",\n"
    ++ "      \"linear_constraint_offsets_match\": "
    ++ boolJson input.linearConstraintOffsetsMatch ++ ",\n"
    ++ "      \"linear_constraint_indices_match\": "
    ++ boolJson input.linearConstraintIndicesMatch ++ ",\n"
    ++ "      \"linear_constraint_coefficients_match\": "
    ++ boolJson input.linearConstraintCoefficientsMatch ++ ",\n"
    ++ "      \"linear_constraint_targets_match\": "
    ++ boolJson input.linearConstraintTargetsMatch ++ ",\n"
    ++ "      \"auxiliary_witness_limb_count_matches\": "
    ++ boolJson input.auxiliaryWitnessLimbCountMatches ++ ",\n"
    ++ "      \"profile_material_matches\": "
    ++ boolJson input.profileMaterialMatches ++ ",\n"
    ++ "      \"transcript_bytes_match\": "
    ++ boolJson input.transcriptBytesMatch ++ ",\n"
    ++ "      \"proof_bytes_nonempty\": "
    ++ boolJson input.proofBytesNonempty ++ ",\n"
    ++ "      \"verifier_accepted\": "
    ++ boolJson input.verifierAccepted ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson rejection.isNone ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectJson rejection ++ "\n"
    ++ "    }"

def caseWith
    (f : VerifierStatementProjectionInput -> VerifierStatementProjectionInput) :
    VerifierStatementProjectionInput :=
  f validInlineMerkleProjectionInput

def activeProjectionCase
    (name fixture : String)
    (input : VerifierStatementProjectionInput) :
    String × String × Nat × VerifierStatementProjectionInput :=
  (name, fixture, arithDirectPacked64CompressedLevel5, input)

def projectionCases : List (String × String × Nat × VerifierStatementProjectionInput) :=
  [ activeProjectionCase "active-inline-merkle-verifier-statement-projection"
      "active_inline_merkle" validInlineMerkleProjectionInput,
    activeProjectionCase "stablecoin-inline-merkle-verifier-statement-projection"
      "stablecoin_inline_merkle" validInlineMerkleProjectionInput,
    activeProjectionCase "candidate-wrapper-rejected" "active_inline_merkle"
      (caseWith fun input => { input with candidateWrapperAccepted := false }),
    activeProjectionCase "public-statement-binding-rejected" "active_inline_merkle"
      (caseWith fun input => { input with publicStatementBindingAccepted := false }),
    activeProjectionCase "transcript-binding-rejected" "active_inline_merkle"
      (caseWith fun input => { input with transcriptBindingAccepted := false }),
    activeProjectionCase "arithmetization-mismatch-rejected" "active_inline_merkle"
      (caseWith fun input => { input with arithmetizationMatches := false }),
    activeProjectionCase "public-values-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with publicValuesMatch := false }),
    activeProjectionCase "row-count-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with rowCountMatches := false }),
    activeProjectionCase "packing-factor-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with packingFactorMatches := false }),
    activeProjectionCase "constraint-degree-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with constraintDegreeMatches := false }),
    activeProjectionCase "linear-offsets-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with linearConstraintOffsetsMatch := false }),
    activeProjectionCase "linear-indices-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with linearConstraintIndicesMatch := false }),
    activeProjectionCase "linear-coefficients-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with linearConstraintCoefficientsMatch := false }),
    activeProjectionCase "linear-targets-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with linearConstraintTargetsMatch := false }),
    activeProjectionCase "auxiliary-limb-count-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with auxiliaryWitnessLimbCountMatches := false }),
    activeProjectionCase "profile-material-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with profileMaterialMatches := false }),
    activeProjectionCase "transcript-bytes-drift-rejected" "active_inline_merkle"
      (caseWith fun input => { input with transcriptBytesMatch := false }),
    activeProjectionCase "empty-proof-bytes-rejected" "active_inline_merkle"
      (caseWith fun input => { input with proofBytesNonempty := false }),
    activeProjectionCase "verifier-rejected" "active_inline_merkle"
      (caseWith fun input => { input with verifierAccepted := false }) ]

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"active_circuit_version\": "
    ++ toString activeCircuitVersion ++ ",\n"
    ++ "  \"active_crypto_suite\": "
    ++ toString activeCryptoSuite ++ ",\n"
    ++ "  \"smallwood_verifier_statement_projection_cases\": [\n"
    ++ String.intercalate ",\n"
      (projectionCases.map fun case =>
        projectionCaseJson case.1 case.2.1 case.2.2.1 case.2.2.2)
    ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

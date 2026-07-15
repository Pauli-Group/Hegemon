import Hegemon.Transaction.SmallWoodProductionConstraintRefinement

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson : List Nat -> String
  | [] => "[]"
  | values => "[" ++ String.intercalate "," (values.map toString) ++ "]"

def natMatrixJson (values : List (List Nat)) : String :=
  "[" ++ String.intercalate "," (values.map natArrayJson) ++ "]"

def stringArrayJson (values : List String) : String :=
  "[" ++ String.intercalate "," (values.map fun value => "\"" ++ value ++ "\"") ++ "]"

def productionConstraintFamilyName : ProductionConstraintFamily -> String
  | .mapIdentity => "map_identity"
  | .publicShape => "public_shape"
  | .inputActiveFlag => "input_active_flag"
  | .inputInactivePadding => "input_inactive_padding"
  | .inputNoteCommitment => "input_note_commitment"
  | .inputAuthorizationKey => "input_authorization_key"
  | .inputNullifier => "input_nullifier"
  | .inputPublicBinding => "input_public_binding"
  | .inputMerkleGeometry => "input_merkle_geometry"
  | .inputMerklePath => "input_merkle_path"
  | .outputActiveFlag => "output_active_flag"
  | .outputInactivePadding => "output_inactive_padding"
  | .outputNoteCommitment => "output_note_commitment"
  | .outputPublicBinding => "output_public_binding"
  | .outputCiphertextBinding => "output_ciphertext_binding"
  | .noteHashGeometry => "note_hash_geometry"
  | .balanceInputBinding => "balance_input_binding"
  | .balanceOutputBinding => "balance_output_binding"
  | .balanceSlotMaterialization => "balance_slot_materialization"
  | .nativeConservation => "native_conservation"
  | .stablecoinConservation => "stablecoin_conservation"
  | .balanceSlotAssets => "balance_slot_assets"

def publicFieldRangeJson (range : PublicFieldRange) : String :=
  "{\"name\":\"" ++ range.name ++ "\",\"start\":" ++ toString range.start
    ++ ",\"end\":" ++ toString range.stop ++ "}"

def publicFieldRangesJson (ranges : List PublicFieldRange) : String :=
  "[" ++ String.intercalate "," (ranges.map publicFieldRangeJson) ++ "]"

def nonlinearConstraintFamilySpanJson
    (span : NonlinearConstraintFamilySpan) : String :=
  "{\"name\":\"" ++ span.name ++ "\",\"start\":" ++ toString span.start
    ++ ",\"count\":" ++ toString span.count ++ "}"

def nonlinearConstraintFamilySpansJson
    (spans : List NonlinearConstraintFamilySpan) : String :=
  "[" ++ String.intercalate "," (spans.map nonlinearConstraintFamilySpanJson) ++ "]"

def constraintMapJson
    (name : String)
    (map : ProductionConstraintMap)
    (exactTableDigest : List Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"public_field_ranges\": " ++ publicFieldRangesJson map.publicFieldRanges ++ ",\n"
    ++ "      \"public_values\": " ++ natArrayJson map.publicValues ++ ",\n"
    ++ "      \"public_value_count\": " ++ toString map.publicValueCount ++ ",\n"
    ++ "      \"raw_witness_len\": " ++ toString map.rawWitnessLength ++ ",\n"
    ++ "      \"lppc_row_count\": " ++ toString map.lppcRowCount ++ ",\n"
    ++ "      \"lppc_packing_factor\": " ++ toString map.lppcPackingFactor ++ ",\n"
    ++ "      \"effective_constraint_degree\": " ++ toString map.effectiveConstraintDegree ++ ",\n"
    ++ "      \"linear_constraint_count\": " ++ toString map.linearConstraintCount ++ ",\n"
    ++ "      \"linear_term_count\": " ++ toString map.linearTermCount ++ ",\n"
    ++ "      \"auxiliary_witness_limb_count\": " ++ toString map.auxiliaryWitnessLimbCount ++ ",\n"
    ++ "      \"linear_term_offsets\": " ++ natArrayJson map.linearTermOffsets ++ ",\n"
    ++ "      \"linear_term_indices\": " ++ natArrayJson map.linearTermIndices ++ ",\n"
    ++ "      \"linear_term_coefficients\": " ++ natArrayJson map.linearTermCoefficients ++ ",\n"
    ++ "      \"linear_targets\": " ++ natArrayJson map.linearTargets ++ ",\n"
    ++ "      \"nonlinear_constraint_count\": " ++ toString map.nonlinearConstraintCount ++ ",\n"
    ++ "      \"nonlinear_expression_count\": " ++ toString map.nonlinearExpressionCount ++ ",\n"
    ++ "      \"nonlinear_constraint_roots\": " ++ natArrayJson map.nonlinearConstraintRoots ++ ",\n"
    ++ "      \"nonlinear_program_digest\": " ++ natArrayJson map.nonlinearProgramDigest ++ ",\n"
    ++ "      \"exact_table_digest\": " ++ natArrayJson exactTableDigest ++ "\n"
    ++ "    }"

def mutationCaseJson
    (name : String)
    (map : ProductionConstraintMap) : String :=
  "    {\"name\":\"" ++ name ++ "\",\"expected_valid\":"
    ++ boolJson (productionConstraintMapAccepts .active map) ++ "}"

def artifactMutationCaseJson
    (name : String)
    (artifact : ProductionConstraintArtifact) : String :=
  "    {\"name\":\"" ++ name ++ "\",\"expected_valid\":"
    ++ boolJson (productionConstraintArtifactAccepts .active artifact) ++ "}"

def productionProjectionStatementFields :
    Hegemon.Transaction.StatementHash.StatementFields :=
  { Hegemon.Transaction.StatementHash.validFields with
    circuitVersion := 3
    cryptoSuite := 2 }

def canonicalStatementProjectionJson : String :=
  let bound := Hegemon.Transaction.PublicInputBinding.validBoundPublicInputs
  let fields := productionProjectionStatementFields
  "  \"canonical_statement_projection\": {\n"
    ++ "    \"input_flags\": " ++ natArrayJson bound.inputFlags ++ ",\n"
    ++ "    \"output_flags\": " ++ natArrayJson bound.outputFlags ++ ",\n"
    ++ "    \"nullifiers\": "
    ++ natArrayJson (productionPaddedDigestFelts 2 fields.nullifierSeeds) ++ ",\n"
    ++ "    \"commitments\": "
    ++ natArrayJson (productionPaddedDigestFelts 2 fields.commitmentSeeds) ++ ",\n"
    ++ "    \"ciphertext_hashes\": "
    ++ natArrayJson (productionPaddedDigestFelts 2 fields.ciphertextHashSeeds) ++ ",\n"
    ++ "    \"fee\": " ++ toString bound.fee ++ ",\n"
    ++ "    \"value_balance_sign\": " ++ toString bound.valueBalanceSign ++ ",\n"
    ++ "    \"value_balance_magnitude\": "
    ++ toString bound.valueBalanceMagnitude ++ ",\n"
    ++ "    \"merkle_root\": " ++ natArrayJson (productionDigestFelts bound.merkleRoot) ++ ",\n"
    ++ "    \"balance_slot_assets\": " ++ natArrayJson bound.balanceSlotAssets ++ ",\n"
    ++ "    \"stablecoin_enabled\": " ++ toString bound.stablecoinEnabled ++ ",\n"
    ++ "    \"stablecoin_asset\": " ++ toString bound.stablecoinAsset ++ ",\n"
    ++ "    \"stablecoin_policy_version\": "
    ++ toString bound.stablecoinPolicyVersion ++ ",\n"
    ++ "    \"stablecoin_issuance_sign\": "
    ++ toString bound.stablecoinIssuanceSign ++ ",\n"
    ++ "    \"stablecoin_issuance_magnitude\": "
    ++ toString bound.stablecoinIssuanceMagnitude ++ ",\n"
    ++ "    \"stablecoin_policy_hash\": "
    ++ natArrayJson (productionDigestFelts bound.stablecoinPolicyHash) ++ ",\n"
    ++ "    \"stablecoin_oracle_commitment\": "
    ++ natArrayJson (productionDigestFelts bound.stablecoinOracleCommitment) ++ ",\n"
    ++ "    \"stablecoin_attestation_commitment\": "
    ++ natArrayJson (productionDigestFelts bound.stablecoinAttestationCommitment) ++ ",\n"
    ++ "    \"circuit_version\": " ++ toString fields.circuitVersion ++ ",\n"
    ++ "    \"crypto_suite\": " ++ toString fields.cryptoSuite ++ ",\n"
    ++ "    \"expected_public_values\": "
    ++ natArrayJson (productionVerifierPublicValues bound fields) ++ "\n"
    ++ "  },\n"

def evaluatorProbeMultiplier : Nat := 17
def evaluatorProbeOffset : Nat := 11
def evaluatorProbeLanes : List Nat := [0, 63]

def evaluatorProbeWitnessValue (index : Nat) : Nat :=
  fieldValue (index * evaluatorProbeMultiplier + evaluatorProbeOffset)

def evaluatorProbeWitnessValues (map : ProductionConstraintMap) : List Nat :=
  (List.range (map.lppcRowCount * map.lppcPackingFactor)).map
    evaluatorProbeWitnessValue

def evaluatorProbeLinearValues (map : ProductionConstraintMap) : List Nat :=
  let witnessValues := evaluatorProbeWitnessValues map
  (List.range map.linearConstraintCount).map fun constraint =>
    linearConstraintValue map witnessValues constraint

def evaluatorProbeNonlinearValues
    (map : ProductionConstraintMap)
    (lane : Nat) : List Nat :=
  let witnessValues := evaluatorProbeWitnessValues map
  let expressionValues := evalExpressionProgram map.publicValues
    (witnessLaneRows map witnessValues lane) map.nonlinearExpressions
  map.nonlinearConstraintRoots.map fun root => expressionValues.getD root 1

def evaluatorProbeJson : String :=
  "  \"evaluator_probe\": {\n"
    ++ "    \"multiplier\": " ++ toString evaluatorProbeMultiplier ++ ",\n"
    ++ "    \"offset\": " ++ toString evaluatorProbeOffset ++ ",\n"
    ++ "    \"lanes\": " ++ natArrayJson evaluatorProbeLanes ++ ",\n"
    ++ "    \"linear_values\": "
    ++ natArrayJson (evaluatorProbeLinearValues activeConstraintMap) ++ ",\n"
    ++ "    \"nonlinear_values\": "
    ++ natMatrixJson (evaluatorProbeLanes.map
      (evaluatorProbeNonlinearValues activeConstraintMap)) ++ "\n"
    ++ "  },\n"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"arithmetization\": \"DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2\",\n"
    ++ "  \"constraint_families\": "
    ++ stringArrayJson (productionConstraintFamilies.map productionConstraintFamilyName) ++ ",\n"
    ++ canonicalStatementProjectionJson
    ++ evaluatorProbeJson
    ++ "  \"nonlinear_constraint_families\": "
    ++ nonlinearConstraintFamilySpansJson productionNonlinearConstraintFamilySpans ++ ",\n"
    ++ "  \"fixtures\": [\n"
    ++ constraintMapJson "active" activeConstraintMap activeConstraintTableDigest ++ ",\n"
    ++ constraintMapJson "stablecoin" stablecoinConstraintMap
      stablecoinConstraintTableDigest ++ "\n"
    ++ "  ],\n"
    ++ "  \"mutation_cases\": [\n"
    ++ mutationCaseJson "omitted" omittedFieldMap ++ ",\n"
    ++ mutationCaseJson "reordered" reorderedFieldMap ++ ",\n"
    ++ mutationCaseJson "substituted" substitutedFieldMap ++ ",\n"
    ++ mutationCaseJson "duplicated" duplicatedFieldMap ++ ",\n"
    ++ mutationCaseJson "wrapped" wrappedFieldMap ++ ",\n"
    ++ mutationCaseJson "truncated" truncatedLinearTermCoefficientsMap ++ ",\n"
    ++ mutationCaseJson "count_mismatched" mismatchedConstraintCountMap ++ ",\n"
    ++ artifactMutationCaseJson "table_digest_truncated" truncatedDigestArtifact ++ ",\n"
    ++ artifactMutationCaseJson "table_digest_mismatched"
      mismatchedTableDigestArtifact ++ ",\n"
    ++ mutationCaseJson "nonlinear_expression_substituted" substitutedNonlinearExpressionMap ++ ",\n"
    ++ mutationCaseJson "nonlinear_root_reordered" reorderedNonlinearRootMap ++ ",\n"
    ++ mutationCaseJson "nonlinear_digest_mismatched" mismatchedNonlinearProgramDigestMap ++ ",\n"
    ++ mutationCaseJson "zero_linear_table" zeroLinearTableMap ++ ",\n"
    ++ mutationCaseJson "stale_public_values" stalePublicValueMap ++ ",\n"
    ++ mutationCaseJson "output_hash_value_binding_substituted"
      substitutedOutputHashValueBindingMap ++ ",\n"
    ++ mutationCaseJson "input_hash_value_binding_substituted"
      substitutedInputHashValueBindingMap ++ ",\n"
    ++ mutationCaseJson "monetary_reconstruction_binding_substituted"
      substitutedMonetaryReconstructionBindingMap ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

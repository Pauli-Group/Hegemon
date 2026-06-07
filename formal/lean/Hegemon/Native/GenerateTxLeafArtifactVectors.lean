import Hegemon.Native.TxLeafArtifact

open Hegemon
open Hegemon.Native.TxLeafArtifact

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map fun value => toString value) ++ "]"

def serializedSummaryJson (summary : SerializedSummary) : String :=
  "{ \"input_flag_count\": " ++ toString summary.inputFlagCount
    ++ ", \"output_flag_count\": " ++ toString summary.outputFlagCount
    ++ ", \"balance_slot_count\": " ++ toString summary.balanceSlotCount
    ++ " }"

def publicTxSummaryJson (summary : PublicTxSummary) : String :=
  "{ \"nullifier_count\": " ++ toString summary.nullifierCount
    ++ ", \"commitment_count\": " ++ toString summary.commitmentCount
    ++ ", \"ciphertext_hash_count\": " ++ toString summary.ciphertextHashCount
    ++ ", \"circuit_version\": " ++ toString summary.circuitVersion
    ++ ", \"crypto_suite\": " ++ toString summary.cryptoSuite
    ++ " }"

def commitmentSummaryJson (summary : CommitmentSummary) : String :=
  "{ \"row_count\": " ++ toString summary.rowCount
    ++ ", \"row_coeff_counts\": " ++ natArrayJson summary.rowCoeffCounts
    ++ " }"

def txLeafSummaryJson (summary : TxLeafSummary) : String :=
  "{\n"
    ++ "        \"version\": " ++ toString summary.version ++ ",\n"
    ++ "        \"serialized\": " ++ serializedSummaryJson summary.serialized ++ ",\n"
    ++ "        \"public_tx\": " ++ publicTxSummaryJson summary.publicTx ++ ",\n"
    ++ "        \"stark_proof_len\": " ++ toString summary.starkProofLen ++ ",\n"
    ++ "        \"commitment\": " ++ commitmentSummaryJson summary.commitment ++ ",\n"
    ++ "        \"leaf_version\": " ++ toString summary.leafVersion ++ ",\n"
    ++ "        \"has_explicit_backend\": " ++ boolJson summary.hasExplicitBackend ++ ",\n"
    ++ "        \"proof_backend\": " ++ toString summary.proofBackend ++ "\n"
    ++ "      }"

def summaryFieldJson (summary : Option TxLeafSummary) : String :=
  match summary with
  | none => "null"
  | some value => txLeafSummaryJson value

def txLeafCaseJson (name : String) (artifact : List Byte) : String :=
  let summary := parseNativeTxLeafArtifact artifact
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"artifact_hex\": \"" ++ hexBytes artifact ++ "\",\n"
    ++ "      \"expected_valid\": " ++ boolJson summary.isSome ++ ",\n"
    ++ "      \"expected_summary\": " ++ summaryFieldJson summary ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"native_tx_leaf_artifact_cases\": [\n"
    ++ txLeafCaseJson "valid-smallwood-backend" validArtifact ++ ",\n"
    ++ txLeafCaseJson "valid-missing-backend-defaults-current-backend" missingBackendArtifact ++ ",\n"
    ++ txLeafCaseJson "valid-legacy-missing-backend-defaults-plonky3" legacyMissingBackendArtifact ++ ",\n"
    ++ txLeafCaseJson "trailing-byte-rejected" trailingArtifact ++ ",\n"
    ++ txLeafCaseJson "bad-backend-rejected" badBackendArtifact ++ ",\n"
    ++ txLeafCaseJson "too-many-input-flags-rejected" tooManyInputFlagsArtifact ++ ",\n"
    ++ txLeafCaseJson "too-many-output-flags-rejected" tooManyOutputFlagsArtifact ++ ",\n"
    ++ txLeafCaseJson "too-many-balance-slots-rejected" tooManyBalanceSlotsArtifact ++ ",\n"
    ++ txLeafCaseJson "too-many-nullifiers-rejected" tooManyNullifiersArtifact ++ ",\n"
    ++ txLeafCaseJson "too-many-commitments-rejected" tooManyCommitmentsArtifact ++ ",\n"
    ++ txLeafCaseJson "too-many-ciphertext-hashes-rejected" tooManyCiphertextHashesArtifact ++ ",\n"
    ++ txLeafCaseJson "too-many-commitment-rows-rejected" tooManyRowsArtifact ++ ",\n"
    ++ txLeafCaseJson "too-many-row-coefficients-rejected" tooManyRowCoeffsArtifact ++ ",\n"
    ++ txLeafCaseJson "oversized-stark-proof-len-rejected" oversizedProofLenArtifact ++ ",\n"
    ++ txLeafCaseJson "truncated-artifact-rejected" truncatedArtifact ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

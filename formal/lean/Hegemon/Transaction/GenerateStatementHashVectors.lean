import Hegemon.Transaction.StatementHash

open Hegemon
open Hegemon.Transaction.StatementHash

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def statementHashCaseJson (name : String) (fields : StatementFields) : String :=
  let preimage := statementPreimage fields
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"merkle_root_seed\": " ++ toString fields.merkleRootSeed ++ ",\n"
    ++ "      \"nullifier_seeds\": " ++ natListJson fields.nullifierSeeds ++ ",\n"
    ++ "      \"commitment_seeds\": " ++ natListJson fields.commitmentSeeds ++ ",\n"
    ++ "      \"ciphertext_hash_seeds\": " ++ natListJson fields.ciphertextHashSeeds ++ ",\n"
    ++ "      \"fee\": " ++ toString fields.fee ++ ",\n"
    ++ "      \"value_balance_sign\": " ++ toString fields.valueBalanceSign ++ ",\n"
    ++ "      \"value_balance_magnitude\": " ++ toString fields.valueBalanceMagnitude ++ ",\n"
    ++ "      \"balance_tag_seed\": " ++ toString fields.balanceTagSeed ++ ",\n"
    ++ "      \"circuit_version\": " ++ toString fields.circuitVersion ++ ",\n"
    ++ "      \"crypto_suite\": " ++ toString fields.cryptoSuite ++ ",\n"
    ++ "      \"stablecoin_enabled\": " ++ toString fields.stablecoinEnabled ++ ",\n"
    ++ "      \"stablecoin_asset\": " ++ toString fields.stablecoinAsset ++ ",\n"
    ++ "      \"stablecoin_policy_hash_seed\": " ++ toString fields.stablecoinPolicyHashSeed ++ ",\n"
    ++ "      \"stablecoin_oracle_commitment_seed\": "
    ++ toString fields.stablecoinOracleCommitmentSeed ++ ",\n"
    ++ "      \"stablecoin_attestation_commitment_seed\": "
    ++ toString fields.stablecoinAttestationCommitmentSeed ++ ",\n"
    ++ "      \"stablecoin_issuance_sign\": " ++ toString fields.stablecoinIssuanceSign ++ ",\n"
    ++ "      \"stablecoin_issuance_magnitude\": "
    ++ toString fields.stablecoinIssuanceMagnitude ++ ",\n"
    ++ "      \"stablecoin_policy_version\": " ++ toString fields.stablecoinPolicyVersion ++ ",\n"
    ++ "      \"expected_preimage_hex\": \""
    ++ (match preimage with | some bytes => hexBytes bytes | none => "0x") ++ "\",\n"
    ++ "      \"expected_valid\": " ++ boolJson preimage.isSome ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"statement_hash_cases\": [\n"
    ++ statementHashCaseJson "valid-full-width-negative-value" validFields ++ ",\n"
    ++ statementHashCaseJson "valid-active-vectors-padded" paddedFields ++ ",\n"
    ++ statementHashCaseJson "valid-stablecoin-negative-issuance" stablecoinFields ++ ",\n"
    ++ statementHashCaseJson "too-many-nullifiers-rejected"
        { validFields with nullifierSeeds := [1, 2, 3] } ++ ",\n"
    ++ statementHashCaseJson "too-many-commitments-rejected"
        { validFields with commitmentSeeds := [1, 2, 3] } ++ ",\n"
    ++ statementHashCaseJson "too-many-ciphertext-hashes-rejected"
        { validFields with ciphertextHashSeeds := [1, 2, 3] } ++ ",\n"
    ++ statementHashCaseJson "bad-value-balance-sign-rejected"
        { validFields with valueBalanceSign := 2 } ++ ",\n"
    ++ statementHashCaseJson "bad-stablecoin-issuance-sign-rejected"
        { stablecoinFields with stablecoinIssuanceSign := 2 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

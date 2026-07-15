import Hegemon.Transaction.StatementHash

open Hegemon
open Hegemon.Transaction.StatementHash

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def serializedPublicInputsDigestCaseJson
    (name : String)
    (fields : SerializedPublicInputsFields) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"input_flags\": " ++ natListJson fields.inputFlags ++ ",\n"
    ++ "      \"output_flags\": " ++ natListJson fields.outputFlags ++ ",\n"
    ++ "      \"fee\": " ++ toString fields.fee ++ ",\n"
    ++ "      \"value_balance_sign\": " ++ toString fields.valueBalanceSign ++ ",\n"
    ++ "      \"value_balance_magnitude\": " ++ toString fields.valueBalanceMagnitude ++ ",\n"
    ++ "      \"merkle_root_seed\": " ++ toString fields.merkleRootSeed ++ ",\n"
    ++ "      \"balance_slot_asset_ids\": " ++ natListJson fields.balanceSlotAssetIds ++ ",\n"
    ++ "      \"stablecoin_enabled\": " ++ toString fields.stablecoinEnabled ++ ",\n"
    ++ "      \"stablecoin_asset\": " ++ toString fields.stablecoinAsset ++ ",\n"
    ++ "      \"stablecoin_policy_version\": " ++ toString fields.stablecoinPolicyVersion ++ ",\n"
    ++ "      \"stablecoin_issuance_sign\": " ++ toString fields.stablecoinIssuanceSign ++ ",\n"
    ++ "      \"stablecoin_issuance_magnitude\": "
    ++ toString fields.stablecoinIssuanceMagnitude ++ ",\n"
    ++ "      \"stablecoin_policy_hash_seed\": "
    ++ toString fields.stablecoinPolicyHashSeed ++ ",\n"
    ++ "      \"stablecoin_oracle_commitment_seed\": "
    ++ toString fields.stablecoinOracleCommitmentSeed ++ ",\n"
    ++ "      \"stablecoin_attestation_commitment_seed\": "
    ++ toString fields.stablecoinAttestationCommitmentSeed ++ ",\n"
    ++ "      \"expected_preimage_hex\": \""
    ++ hexBytes (publicInputsDigestPreimage fields) ++ "\",\n"
    ++ "      \"expected_valid\": true\n"
    ++ "    }"

def proofDigestCaseJson
    (name : String)
    (fields : ProofDigestFields) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"backend_wire_id\": " ++ toString fields.backendWireId ++ ",\n"
    ++ "      \"proof_bytes_hex\": \"" ++ hexBytes fields.proofBytes ++ "\",\n"
    ++ "      \"expected_preimage_hex\": \""
    ++ hexBytes (proofDigestPreimage fields) ++ "\",\n"
    ++ "      \"expected_valid\": true\n"
    ++ "    }"

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
    ++ "  ],\n"
    ++ "  \"public_inputs_digest_cases\": [\n"
    ++ serializedPublicInputsDigestCaseJson "valid-public-inputs-digest"
        validSerializedPublicInputs ++ ",\n"
    ++ serializedPublicInputsDigestCaseJson "stablecoin-public-inputs-digest"
        stablecoinSerializedPublicInputs ++ "\n"
    ++ "  ],\n"
    ++ "  \"proof_digest_cases\": [\n"
    ++ proofDigestCaseJson "smallwood-proof-digest-binds-backend"
        smallwoodProofDigestFields ++ ",\n"
    ++ proofDigestCaseJson "smallwood-proof-digest-binds-proof-bytes"
        alternateProofBytesDigestFields ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

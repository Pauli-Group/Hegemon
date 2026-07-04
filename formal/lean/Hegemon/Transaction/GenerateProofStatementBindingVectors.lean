import Hegemon.Transaction.ProofStatementBinding

open Hegemon
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.ProofStatementBinding

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def intJson (value : Int) : String :=
  toString value

def bindingCaseJson (name : String) (fields : BindingFields) : String :=
  let message := bindingMessage fields
  let chunk0Preimage := message.map (bindingHashPreimage 0)
  let chunk1Preimage := message.map (bindingHashPreimage 1)
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"anchor_seed\": " ++ toString fields.anchorSeed ++ ",\n"
    ++ "      \"nullifier_seeds\": " ++ natListJson fields.nullifierSeeds ++ ",\n"
    ++ "      \"commitment_seeds\": " ++ natListJson fields.commitmentSeeds ++ ",\n"
    ++ "      \"ciphertext_hash_seeds\": " ++ natListJson fields.ciphertextHashSeeds ++ ",\n"
    ++ "      \"fee\": " ++ toString fields.fee ++ ",\n"
    ++ "      \"value_balance\": " ++ intJson fields.valueBalance ++ ",\n"
    ++ "      \"balance_slot_assets\": " ++ natListJson fields.balanceSlotAssets ++ ",\n"
    ++ "      \"stablecoin_enabled\": " ++ boolJson fields.stablecoinEnabled ++ ",\n"
    ++ "      \"stablecoin_asset\": " ++ toString fields.stablecoinAsset ++ ",\n"
    ++ "      \"stablecoin_policy_hash_seed\": "
    ++ toString fields.stablecoinPolicyHashSeed ++ ",\n"
    ++ "      \"stablecoin_oracle_commitment_seed\": "
    ++ toString fields.stablecoinOracleCommitmentSeed ++ ",\n"
    ++ "      \"stablecoin_attestation_commitment_seed\": "
    ++ toString fields.stablecoinAttestationCommitmentSeed ++ ",\n"
    ++ "      \"stablecoin_issuance_delta\": "
    ++ intJson fields.stablecoinIssuanceDelta ++ ",\n"
    ++ "      \"stablecoin_policy_version\": "
    ++ toString fields.stablecoinPolicyVersion ++ ",\n"
    ++ "      \"expected_binding_message_hex\": \""
    ++ (match message with | some bytes => hexBytes bytes | none => "0x") ++ "\",\n"
    ++ "      \"expected_binding_hash_chunk0_preimage_hex\": \""
    ++ (match chunk0Preimage with | some bytes => hexBytes bytes | none => "0x")
    ++ "\",\n"
    ++ "      \"expected_binding_hash_chunk1_preimage_hex\": \""
    ++ (match chunk1Preimage with | some bytes => hexBytes bytes | none => "0x")
    ++ "\",\n"
    ++ "      \"expected_valid\": " ++ boolJson message.isSome ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"proof_statement_binding_cases\": [\n"
    ++ bindingCaseJson "valid-proof-binding-no-stablecoin" validFields ++ ",\n"
    ++ bindingCaseJson "valid-proof-binding-stablecoin" stablecoinFields ++ ",\n"
    ++ bindingCaseJson "vector-partition-lengths-are-bound"
        repartitionedLengthFields ++ ",\n"
    ++ bindingCaseJson "field-padding-asset-id-is-not-u64-max-padding"
        fieldPaddingCollisionFields ++ ",\n"
    ++ bindingCaseJson "bad-balance-slot-count-rejected"
        { validFields with balanceSlotAssets := [0, 7, paddingAsset] } ++ ",\n"
    ++ bindingCaseJson "overwidth-stablecoin-policy-version-rejected"
        overwidthPolicyVersionFields ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

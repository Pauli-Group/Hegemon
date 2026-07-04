import Hegemon.Transaction.PublicInputBinding

open Hegemon.Transaction.PublicInputBinding

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def intJson (value : Int) : String :=
  toString value

def boundBalanceSlotAssets (pubFields : PublicFields) (serialized : SerializedFields) : List Nat :=
  match bindPublicInputs pubFields serialized with
  | some bound => bound.balanceSlotAssets
  | none => []

def publicInputBindingCaseJson
    (name : String)
    (pubFields : PublicFields)
    (serialized : SerializedFields) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"public_merkle_root\": " ++ toString pubFields.merkleRoot ++ ",\n"
    ++ "      \"serialized_merkle_root\": " ++ toString serialized.merkleRoot ++ ",\n"
    ++ "      \"public_fee\": " ++ toString pubFields.nativeFee ++ ",\n"
    ++ "      \"serialized_fee\": " ++ toString serialized.fee ++ ",\n"
    ++ "      \"public_value_balance\": " ++ intJson pubFields.valueBalance ++ ",\n"
    ++ "      \"serialized_value_balance_sign\": " ++ toString serialized.valueBalanceSign ++ ",\n"
    ++ "      \"serialized_value_balance_magnitude\": " ++ toString serialized.valueBalanceMagnitude ++ ",\n"
    ++ "      \"public_balance_slot_assets\": " ++ natListJson pubFields.balanceSlotAssets ++ ",\n"
    ++ "      \"serialized_balance_slot_assets\": " ++ natListJson serialized.balanceSlotAssets ++ ",\n"
    ++ "      \"public_stablecoin_enabled\": " ++ toString pubFields.stablecoinEnabled ++ ",\n"
    ++ "      \"serialized_stablecoin_enabled\": " ++ toString serialized.stablecoinEnabled ++ ",\n"
    ++ "      \"public_stablecoin_asset\": " ++ toString pubFields.stablecoinAsset ++ ",\n"
    ++ "      \"serialized_stablecoin_asset\": " ++ toString serialized.stablecoinAsset ++ ",\n"
    ++ "      \"public_stablecoin_policy_version\": " ++ toString pubFields.stablecoinPolicyVersion ++ ",\n"
    ++ "      \"serialized_stablecoin_policy_version\": " ++ toString serialized.stablecoinPolicyVersion ++ ",\n"
    ++ "      \"public_stablecoin_issuance_delta\": " ++ intJson pubFields.stablecoinIssuanceDelta ++ ",\n"
    ++ "      \"serialized_stablecoin_issuance_sign\": " ++ toString serialized.stablecoinIssuanceSign ++ ",\n"
    ++ "      \"serialized_stablecoin_issuance_magnitude\": " ++ toString serialized.stablecoinIssuanceMagnitude ++ ",\n"
    ++ "      \"public_stablecoin_policy_hash\": " ++ toString pubFields.stablecoinPolicyHash ++ ",\n"
    ++ "      \"serialized_stablecoin_policy_hash\": " ++ toString serialized.stablecoinPolicyHash ++ ",\n"
    ++ "      \"public_stablecoin_oracle_commitment\": " ++ toString pubFields.stablecoinOracleCommitment ++ ",\n"
    ++ "      \"serialized_stablecoin_oracle_commitment\": " ++ toString serialized.stablecoinOracleCommitment ++ ",\n"
    ++ "      \"public_stablecoin_attestation_commitment\": " ++ toString pubFields.stablecoinAttestationCommitment ++ ",\n"
    ++ "      \"serialized_stablecoin_attestation_commitment\": " ++ toString serialized.stablecoinAttestationCommitment ++ ",\n"
    ++ "      \"expected_bound_balance_slot_assets\": "
    ++ natListJson (boundBalanceSlotAssets pubFields serialized) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (validBinding pubFields serialized) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"public_input_binding_cases\": [\n"
    ++ publicInputBindingCaseJson "valid-negative-value-balance"
        validPublicFields validSerializedFields ++ ",\n"
    ++ publicInputBindingCaseJson "valid-stablecoin-binding"
        stablecoinPublicFields stablecoinSerializedFields ++ ",\n"
    ++ publicInputBindingCaseJson "valid-omitted-balance-assets-use-public"
        validPublicFields { validSerializedFields with balanceSlotAssets := [] } ++ ",\n"
    ++ publicInputBindingCaseJson "merkle-root-mismatch-rejected"
        validPublicFields { validSerializedFields with merkleRoot := 102 } ++ ",\n"
    ++ publicInputBindingCaseJson "fee-mismatch-rejected"
        validPublicFields { validSerializedFields with fee := 4 } ++ ",\n"
    ++ publicInputBindingCaseJson "value-balance-sign-mismatch-rejected"
        validPublicFields { validSerializedFields with valueBalanceSign := 0 } ++ ",\n"
    ++ publicInputBindingCaseJson "value-balance-magnitude-mismatch-rejected"
        validPublicFields { validSerializedFields with valueBalanceMagnitude := 6 } ++ ",\n"
    ++ publicInputBindingCaseJson "balance-slot-asset-mismatch-rejected"
        validPublicFields { validSerializedFields with balanceSlotAssets := [0, 7, 8, 10] } ++ ",\n"
    ++ publicInputBindingCaseJson "balance-slot-asset-count-rejected"
        validPublicFields { validSerializedFields with balanceSlotAssets := [0, 7, 8] } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-enabled-mismatch-rejected"
      stablecoinPublicFields { stablecoinSerializedFields with stablecoinEnabled := 0 } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-enabled-noncanonical-rejected"
      { stablecoinPublicFields with stablecoinEnabled := 2 }
      { stablecoinSerializedFields with stablecoinEnabled := 2 } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-asset-mismatch-rejected"
        stablecoinPublicFields { stablecoinSerializedFields with stablecoinAsset := 8 } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-policy-version-mismatch-rejected"
        stablecoinPublicFields { stablecoinSerializedFields with stablecoinPolicyVersion := 3 } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-issuance-sign-mismatch-rejected"
        stablecoinPublicFields { stablecoinSerializedFields with stablecoinIssuanceSign := 0 } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-issuance-magnitude-mismatch-rejected"
        stablecoinPublicFields { stablecoinSerializedFields with stablecoinIssuanceMagnitude := 14 } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-policy-hash-mismatch-rejected"
        stablecoinPublicFields { stablecoinSerializedFields with stablecoinPolicyHash := 204 } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-oracle-mismatch-rejected"
        stablecoinPublicFields { stablecoinSerializedFields with stablecoinOracleCommitment := 204 } ++ ",\n"
    ++ publicInputBindingCaseJson "stablecoin-attestation-mismatch-rejected"
        stablecoinPublicFields { stablecoinSerializedFields with stablecoinAttestationCommitment := 204 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

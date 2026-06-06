import Hegemon.Transaction.PublicInputs

open Hegemon.Transaction.PublicInputs

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map toString) ++ "]"

def publicInputCaseJson (name : String) (shape : PublicInputShape) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"input_flags\": " ++ natListJson shape.inputFlags ++ ",\n"
    ++ "      \"output_flags\": " ++ natListJson shape.outputFlags ++ ",\n"
    ++ "      \"nullifiers\": " ++ natListJson shape.nullifiers ++ ",\n"
    ++ "      \"commitments\": " ++ natListJson shape.commitments ++ ",\n"
    ++ "      \"ciphertext_hashes\": " ++ natListJson shape.ciphertextHashes ++ ",\n"
    ++ "      \"balance_slot_assets\": " ++ natListJson shape.balanceSlotAssets ++ ",\n"
    ++ "      \"value_balance_sign\": " ++ toString shape.valueBalanceSign ++ ",\n"
    ++ "      \"stablecoin_enabled\": " ++ toString shape.stablecoinEnabled ++ ",\n"
    ++ "      \"stablecoin_asset\": " ++ toString shape.stablecoinAsset ++ ",\n"
    ++ "      \"stablecoin_issuance_sign\": " ++ toString shape.stablecoinIssuanceSign ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (validPublicInputShape shape) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"public_input_shape_cases\": [\n"
    ++ publicInputCaseJson "valid-one-input-one-output" validShape ++ ",\n"
    ++ publicInputCaseJson "valid-stablecoin-present"
        { validShape with stablecoinEnabled := 1, stablecoinAsset := 7 } ++ ",\n"
    ++ publicInputCaseJson "bad-input-flag-rejected"
        { validShape with inputFlags := [2, 0] } ++ ",\n"
    ++ publicInputCaseJson "inactive-input-nonzero-nullifier-rejected"
        { validShape with inputFlags := [0, 0], nullifiers := [11, 0] } ++ ",\n"
    ++ publicInputCaseJson "active-input-zero-nullifier-rejected"
        { validShape with inputFlags := [1, 0], nullifiers := [0, 0] } ++ ",\n"
    ++ publicInputCaseJson "bad-output-flag-rejected"
        { validShape with outputFlags := [1, 2] } ++ ",\n"
    ++ publicInputCaseJson "inactive-output-nonzero-commitment-rejected"
        { validShape with outputFlags := [0, 0], commitments := [22, 0] } ++ ",\n"
    ++ publicInputCaseJson "active-output-zero-commitment-rejected"
        { validShape with outputFlags := [1, 0], commitments := [0, 0] } ++ ",\n"
    ++ publicInputCaseJson "inactive-output-nonzero-ciphertext-rejected"
        { validShape with outputFlags := [0, 0], commitments := [0, 0], ciphertextHashes := [33, 0] } ++ ",\n"
    ++ publicInputCaseJson "empty-transaction-rejected"
        { validShape with inputFlags := [0, 0], outputFlags := [0, 0], nullifiers := [0, 0], commitments := [0, 0], ciphertextHashes := [0, 0] } ++ ",\n"
    ++ publicInputCaseJson "bad-value-balance-sign-rejected"
        { validShape with valueBalanceSign := 2 } ++ ",\n"
    ++ publicInputCaseJson "bad-stablecoin-enabled-flag-rejected"
        { validShape with stablecoinEnabled := 2 } ++ ",\n"
    ++ publicInputCaseJson "bad-stablecoin-issuance-sign-rejected"
        { validShape with stablecoinIssuanceSign := 2 } ++ ",\n"
    ++ publicInputCaseJson "slot-zero-not-native-rejected"
        { validShape with balanceSlotAssets := [1, 7, paddingAsset, paddingAsset] } ++ ",\n"
    ++ publicInputCaseJson "padding-not-suffix-rejected"
        { validShape with balanceSlotAssets := [0, paddingAsset, 7, paddingAsset] } ++ ",\n"
    ++ publicInputCaseJson "duplicate-asset-rejected"
        { validShape with balanceSlotAssets := [0, 7, 7, paddingAsset] } ++ ",\n"
    ++ publicInputCaseJson "descending-asset-rejected"
        { validShape with balanceSlotAssets := [0, 9, 7, paddingAsset] } ++ ",\n"
    ++ publicInputCaseJson "stablecoin-missing-asset-rejected"
        { validShape with stablecoinEnabled := 1, stablecoinAsset := 42 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

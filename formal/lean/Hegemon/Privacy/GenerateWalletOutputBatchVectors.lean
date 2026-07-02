import Hegemon.Privacy.WalletOutputBatch

open Hegemon.Privacy.WalletOutputBatch

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def kindJson : WalletOutputBatchKind -> String
  | WalletOutputBatchKind.native => "\"native\""
  | WalletOutputBatchKind.stablecoin => "\"stablecoin\""
  | WalletOutputBatchKind.burn => "\"burn\""
  | WalletOutputBatchKind.consolidation => "\"consolidation\""

def walletOutputBatchCaseJson
    (name : String)
    (input : WalletOutputBatchInput)
    (alternatePrivateWitnessSeed alternateLocalMetadataSeed : Nat) :
    String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": " ++ kindJson input.kind ++ ",\n"
    ++ "      \"recipient_count\": " ++ toString input.recipientCount ++ ",\n"
    ++ "      \"recipient_total\": " ++ toString input.recipientTotal ++ ",\n"
    ++ "      \"fee\": " ++ toString input.fee ++ ",\n"
    ++ "      \"selected_asset_total\": " ++ toString input.selectedAssetTotal ++ ",\n"
    ++ "      \"selected_native_total\": " ++ toString input.selectedNativeTotal ++ ",\n"
    ++ "      \"issuance_delta\": " ++ toString input.issuanceDelta ++ ",\n"
    ++ "      \"burn_amount\": " ++ toString input.burnAmount ++ ",\n"
    ++ "      \"private_witness_seed\": " ++ toString input.privateWitnessSeed ++ ",\n"
    ++ "      \"local_metadata_seed\": " ++ toString input.localMetadataSeed ++ ",\n"
    ++ "      \"alternate_private_witness_seed\": "
      ++ toString alternatePrivateWitnessSeed ++ ",\n"
    ++ "      \"alternate_local_metadata_seed\": "
      ++ toString alternateLocalMetadataSeed ++ ",\n"
    ++ "      \"expected_output_count\": "
      ++ toString (walletOutputCount input) ++ ",\n"
    ++ "      \"expected_recipient_output_count\": "
      ++ toString (recipientOutputCount input) ++ ",\n"
    ++ "      \"expected_change_output_count\": "
      ++ toString (changeOutputCount input) ++ ",\n"
    ++ "      \"expected_change_diversifier_index\": "
      ++ toString (expectedChangeDiversifierIndex input) ++ ",\n"
    ++ "      \"expected_change_diversifier_cursor_independent\": "
      ++ boolJson
        (decide (expectedChangeDiversifierIndex
            { input with localMetadataSeed := alternateLocalMetadataSeed } =
          expectedChangeDiversifierIndex input)) ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (walletOutputBatchAccepts input) ++ ",\n"
    ++ "      \"expected_within_max_outputs\": "
      ++ boolJson (walletOutputCount input <= MaxOutputs) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"max_outputs\": " ++ toString MaxOutputs ++ ",\n"
    ++ "  \"wallet_output_batch_cases\": [\n"
    ++ walletOutputBatchCaseJson "native-exact-no-change"
      nativeExactNoChange 111 1101 ++ ",\n"
    ++ walletOutputBatchCaseJson "native-change"
      nativeWithChange 112 1102 ++ ",\n"
    ++ walletOutputBatchCaseJson "stablecoin-issuance-no-input"
      stablecoinIssuanceNoInput 121 1201 ++ ",\n"
    ++ walletOutputBatchCaseJson "stablecoin-asset-change-exact-fee"
      stablecoinAssetChangeExactFee 122 1202 ++ ",\n"
    ++ walletOutputBatchCaseJson "stablecoin-native-change"
      stablecoinNativeChange 123 1203 ++ ",\n"
    ++ walletOutputBatchCaseJson
      "stablecoin-asset-change-rejects-inexact-native-fee"
      stablecoinAssetChangeRejectsInexactNativeFee 124 1204 ++ ",\n"
    ++ walletOutputBatchCaseJson "native-two-recipient-overflow"
      nativeTwoRecipientOverflow 131 1301 ++ ",\n"
    ++ walletOutputBatchCaseJson "burn-exact-no-output"
      burnExactNoOutput 141 1401 ++ ",\n"
    ++ walletOutputBatchCaseJson "burn-asset-and-native-change"
      burnAssetAndNativeChange 142 1402 ++ ",\n"
    ++ walletOutputBatchCaseJson "consolidation-one-output"
      consolidationOneOutput 151 1501 ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

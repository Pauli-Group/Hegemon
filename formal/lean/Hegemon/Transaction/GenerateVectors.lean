import Hegemon.Transaction.Balance

open Hegemon.Transaction

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def slotJson (slot : BalanceSlot) : String :=
  "{ \"asset_id\": " ++ toString slot.assetId
    ++ ", \"delta\": \"" ++ toString slot.delta ++ "\" }"

def slotsJson : Option (List BalanceSlot) -> String
  | none => "null"
  | some slots => "[" ++ String.intercalate ", " (slots.map slotJson) ++ "]"

def noteJson (note : NoteSummary) : String :=
  "{ \"asset_id\": " ++ toString note.assetId
    ++ ", \"value\": " ++ toString note.value ++ " }"

def notesJson (notes : List NoteSummary) : String :=
  "[" ++ String.intercalate ", " (notes.map noteJson) ++ "]"

def balanceCaseJson (name : String) (witness : BalanceWitness) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"inputs\": " ++ notesJson witness.inputs ++ ",\n"
    ++ "      \"outputs\": " ++ notesJson witness.outputs ++ ",\n"
    ++ "      \"fee\": " ++ toString witness.fee ++ ",\n"
    ++ "      \"value_balance\": \"" ++ toString witness.valueBalance ++ "\",\n"
    ++ "      \"stablecoin_enabled\": " ++ boolJson witness.stablecoin.enabled ++ ",\n"
    ++ "      \"stablecoin_asset_id\": " ++ toString witness.stablecoin.assetId ++ ",\n"
    ++ "      \"stablecoin_issuance_delta\": \"" ++ toString witness.stablecoin.issuanceDelta ++ "\",\n"
    ++ "      \"stablecoin_policy_version\": " ++ toString witness.stablecoin.policyVersion ++ ",\n"
    ++ "      \"expected_slots\": " ++ slotsJson (balanceSlots witness) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (validBalance witness) ++ "\n"
    ++ "    }"

def disabledStablecoin : StablecoinBinding :=
  { enabled := false, assetId := 0, issuanceDelta := 0, policyVersion := 0 }

def stablecoin4242 (issuance : Int) : StablecoinBinding :=
  { enabled := true, assetId := 4242, issuanceDelta := issuance, policyVersion := 1 }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"balance_cases\": [\n"
    ++ balanceCaseJson "native-fee-balanced"
        { inputs := [{ assetId := 0, value := 10 }]
          outputs := [{ assetId := 0, value := 7 }]
          fee := 3
          valueBalance := 0
          stablecoin := disabledStablecoin } ++ ",\n"
    ++ balanceCaseJson "native-value-balance-balanced"
        { inputs := [{ assetId := 0, value := 5 }]
          outputs := []
          fee := 3
          valueBalance := -2
          stablecoin := disabledStablecoin } ++ ",\n"
    ++ balanceCaseJson "non-native-conserved"
        { inputs := [{ assetId := 7, value := 4 }]
          outputs := [{ assetId := 7, value := 4 }]
          fee := 0
          valueBalance := 0
          stablecoin := disabledStablecoin } ++ ",\n"
    ++ balanceCaseJson "non-native-counterfeit-rejected"
        { inputs := []
          outputs := [{ assetId := 7, value := 4 }]
          fee := 0
          valueBalance := 0
          stablecoin := disabledStablecoin } ++ ",\n"
    ++ balanceCaseJson "stablecoin-issuance-balanced"
        { inputs := [{ assetId := 0, value := 5 }]
          outputs := [{ assetId := 4242, value := 5 }]
          fee := 5
          valueBalance := 0
          stablecoin := stablecoin4242 (-5) } ++ ",\n"
    ++ balanceCaseJson "stablecoin-issuance-mismatch-rejected"
        { inputs := [{ assetId := 0, value := 5 }]
          outputs := [{ assetId := 4242, value := 5 }]
          fee := 5
          valueBalance := 0
          stablecoin := stablecoin4242 (-4) } ++ ",\n"
    ++ balanceCaseJson "stablecoin-native-asset-rejected"
        { inputs := [{ assetId := 0, value := 5 }]
          outputs := [{ assetId := 0, value := 0 }]
          fee := 5
          valueBalance := 0
          stablecoin := { enabled := true, assetId := 0, issuanceDelta := 0, policyVersion := 1 } } ++ ",\n"
    ++ balanceCaseJson "stablecoin-padding-field-alias-rejected"
        { inputs := [{ assetId := 0, value := 5 }]
          outputs := [{ assetId := paddingFieldAsset, value := 5 }]
          fee := 5
          valueBalance := 0
          stablecoin :=
            { enabled := true
              assetId := paddingFieldAsset
              issuanceDelta := -5
              policyVersion := 1 } } ++ ",\n"
    ++ balanceCaseJson "stablecoin-padding-asset-rejected"
        { inputs := [{ assetId := 0, value := 5 }]
          outputs := [{ assetId := paddingAsset, value := 5 }]
          fee := 5
          valueBalance := 0
          stablecoin :=
            { enabled := true
              assetId := paddingAsset
              issuanceDelta := -5
              policyVersion := 1 } } ++ ",\n"
    ++ balanceCaseJson "too-many-assets-overflows"
        { inputs := [{ assetId := 1, value := 1 }, { assetId := 2, value := 1 }]
          outputs := [{ assetId := 3, value := 1 }, { assetId := 4, value := 1 }]
          fee := 0
          valueBalance := 0
          stablecoin := disabledStablecoin } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

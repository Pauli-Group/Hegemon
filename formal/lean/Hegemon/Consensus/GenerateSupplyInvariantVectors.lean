import Hegemon.Consensus.SupplyInvariant

open Hegemon.Consensus
open Hegemon.Consensus.SupplyInvariant

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => "\"" ++ toString value ++ "\""

def supplyChainStepJson (step : ClaimedSupplyStep) : String :=
  "        {\n"
    ++ "          \"minted\": " ++ toString step.minted ++ ",\n"
    ++ "          \"fees\": \"" ++ toString step.fees ++ "\",\n"
    ++ "          \"burns\": " ++ toString step.burns ++ ",\n"
    ++ "          \"claimed_supply\": \"" ++ toString step.claimedSupply ++ "\"\n"
    ++ "        }"

def joinStrings : List String -> String
  | [] => ""
  | [item] => item
  | item :: rest => item ++ ",\n" ++ joinStrings rest

def supplyChainCaseJson
    (name : String)
    (genesis : Nat)
    (steps : List ClaimedSupplyStep) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"genesis_supply\": \"" ++ toString genesis ++ "\",\n"
    ++ "      \"steps\": [\n"
    ++ joinStrings (steps.map supplyChainStepJson) ++ "\n"
    ++ "      ],\n"
    ++ "      \"expected_final_supply\": "
    ++ optionNatJson (validateClaimedSupplyChain genesis steps) ++ "\n"
    ++ "    }"

def underflowStep : ClaimedSupplyStep :=
  { minted := 0, fees := 0, burns := 50, claimedSupply := 0 }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"supply_chain_cases\": [\n"
    ++ supplyChainCaseJson "valid-two-step-chain" 100 validTwoStepChain ++ ",\n"
    ++ supplyChainCaseJson "counterfeit-claimed-supply-rejected" 100 counterfeitSecondStep ++ ",\n"
    ++ supplyChainCaseJson "underflow-step-rejected" 20 [underflowStep] ++ ",\n"
    ++ supplyChainCaseJson "overflow-step-rejected" (maxSupplyDigest - 5) [overflowStep] ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

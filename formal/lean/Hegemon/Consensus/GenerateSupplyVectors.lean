import Hegemon.Consensus.Supply

open Hegemon.Consensus

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => "\"" ++ toString value ++ "\""

def consensusSupplyCaseJson
    (name : String)
    (parent minted : Nat)
    (fees : Int)
    (burns : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"parent_supply\": \"" ++ toString parent ++ "\",\n"
    ++ "      \"minted\": " ++ toString minted ++ ",\n"
    ++ "      \"fees\": \"" ++ toString fees ++ "\",\n"
    ++ "      \"burns\": " ++ toString burns ++ ",\n"
    ++ "      \"expected_net_delta\": \""
    ++ toString (netNativeDelta minted fees burns) ++ "\",\n"
    ++ "      \"expected_supply\": "
    ++ optionNatJson (expectedConsensusSupply parent minted fees burns) ++ "\n"
    ++ "    }"

def nativeSupplyCaseJson
    (name : String)
    (parent height feeTotal : Nat)
    (hasCoinbase : Bool) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"parent_supply\": \"" ++ toString parent ++ "\",\n"
    ++ "      \"height\": " ++ toString height ++ ",\n"
    ++ "      \"fee_total\": " ++ toString feeTotal ++ ",\n"
    ++ "      \"has_coinbase\": " ++ boolJson hasCoinbase ++ ",\n"
    ++ "      \"expected_delta\": "
    ++ optionNatJson (nativeSupplyDelta height feeTotal hasCoinbase) ++ ",\n"
    ++ "      \"expected_supply\": "
    ++ optionNatJson (advanceNativeSupplyDigest parent height feeTotal hasCoinbase) ++ "\n"
    ++ "    }"

def almostMaxSupply : Nat := maxSupplyDigest - 5

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"consensus_supply_cases\": [\n"
    ++ consensusSupplyCaseJson "minted-plus-fees-advances-supply" 100 25 5 0 ++ ",\n"
    ++ consensusSupplyCaseJson "burns-decrease-supply" 100 0 0 40 ++ ",\n"
    ++ consensusSupplyCaseJson "negative-fees-are-signed" 100 20 (-5) 0 ++ ",\n"
    ++ consensusSupplyCaseJson "underflow-rejected" 20 0 0 50 ++ ",\n"
    ++ consensusSupplyCaseJson "overflow-rejected" almostMaxSupply 10 0 0 ++ "\n"
    ++ "  ],\n"
    ++ "  \"native_supply_cases\": [\n"
    ++ nativeSupplyCaseJson "no-coinbase-keeps-supply" 100 1 0 false ++ ",\n"
    ++ nativeSupplyCaseJson "coinbase-subsidy-advances-supply" 100 1 0 true ++ ",\n"
    ++ nativeSupplyCaseJson "coinbase-fees-advance-supply" 1000 1 7 true ++ ",\n"
    ++ nativeSupplyCaseJson "native-overflow-rejected" almostMaxSupply 1 0 true ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

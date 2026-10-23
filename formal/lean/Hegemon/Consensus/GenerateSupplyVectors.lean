import Hegemon.Consensus.Supply

open Hegemon.Consensus

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => "\"" ++ toString value ++ "\""

def monetaryConstantsJson : String :=
  "  \"monetary_constants\": {\n"
    ++ "    \"coin\": " ++ toString coin ++ ",\n"
    ++ "    \"target_block_seconds\": " ++ toString targetBlockSeconds ++ ",\n"
    ++ "    \"year_seconds\": " ++ toString yearSeconds ++ ",\n"
    ++ "    \"epoch_years\": " ++ toString epochYears ++ ",\n"
    ++ "    \"halving_interval\": " ++ toString halvingInterval ++ ",\n"
    ++ "    \"epoch_seconds\": " ++ toString epochSeconds ++ ",\n"
    ++ "    \"max_monetary_supply\": \"" ++ toString maxMonetarySupply ++ "\",\n"
    ++ "    \"initial_subsidy\": " ++ toString initialSubsidy ++ "\n"
    ++ "  }"

def subsidyScheduleCaseJson
    (name : String)
    (height : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"height\": " ++ toString height ++ ",\n"
    ++ "      \"expected_halving_epoch\": " ++ toString (subsidyEpoch height) ++ ",\n"
    ++ "      \"expected_subsidy\": " ++ toString (blockSubsidy height) ++ ",\n"
    ++ "      \"expected_epoch_budget\": " ++ toString (epochBudget (subsidyEpoch height)) ++ ",\n"
    ++ "      \"expected_scheduled_subsidy\": " ++ toString (scheduledPrefix height) ++ "\n"
    ++ "    }"

def epochBudgetCaseJson (name : String) (epoch : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"epoch\": " ++ toString epoch ++ ",\n"
    ++ "      \"expected_remaining_budget\": " ++ toString (remainingBudget epoch) ++ ",\n"
    ++ "      \"expected_epoch_budget\": " ++ toString (epochBudget epoch) ++ "\n"
    ++ "    }"

def slotSubsidyCaseJson (name : String) (epoch slot : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"epoch\": " ++ toString epoch ++ ",\n"
    ++ "      \"slot\": " ++ toString slot ++ ",\n"
    ++ "      \"expected_subsidy\": " ++ toString (slotSubsidy epoch slot) ++ "\n"
    ++ "    }"

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
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"emission_model\": \"epoch-budget-prefix-differences-v1\",\n"
    ++ monetaryConstantsJson ++ ",\n"
    ++ "  \"subsidy_schedule_cases\": [\n"
    ++ subsidyScheduleCaseJson "zero-height-no-subsidy" 0 ++ ",\n"
    ++ subsidyScheduleCaseJson "first-block-initial-subsidy" 1 ++ ",\n"
    ++ subsidyScheduleCaseJson "first-epoch-last-block-initial-subsidy" halvingInterval ++ ",\n"
    ++ subsidyScheduleCaseJson "first-halving-boundary" (halvingInterval + 1) ++ ",\n"
    ++ subsidyScheduleCaseJson "second-halving-boundary" (2 * halvingInterval + 1) ++ ",\n"
    ++ subsidyScheduleCaseJson "capped-shift-extinction" (64 * halvingInterval + 1) ++ ",\n"
    ++ subsidyScheduleCaseJson "post-cap-remains-extinct" (65 * halvingInterval + 1) ++ ",\n"
    ++ subsidyScheduleCaseJson "epoch9-dust-first-slot" (9 * halvingInterval + 1) ++ ",\n"
    ++ subsidyScheduleCaseJson "epoch9-dust-second-slot" (9 * halvingInterval + 2) ++ ",\n"
    ++ subsidyScheduleCaseJson "epoch9-dust-third-slot" (9 * halvingInterval + 3) ++ ",\n"
    ++ subsidyScheduleCaseJson "before-last-positive-height" 107099999 ++ ",\n"
    ++ subsidyScheduleCaseJson "last-positive-height" 107100000 ++ ",\n"
    ++ subsidyScheduleCaseJson "first-zero-tail-height" 107100001 ++ ",\n"
    ++ subsidyScheduleCaseJson "u64-max-height-tail" maxU64 ++ "\n"
    ++ "  ],\n"
    ++ "  \"epoch_budget_cases\": [\n"
    ++ epochBudgetCaseJson "initial-epoch-budget" 0 ++ ",\n"
    ++ epochBudgetCaseJson "first-halved-budget" 1 ++ ",\n"
    ++ epochBudgetCaseJson "epoch8-budget" 8 ++ ",\n"
    ++ epochBudgetCaseJson "epoch9-dust-budget" 9 ++ ",\n"
    ++ epochBudgetCaseJson "penultimate-positive-budget" 49 ++ ",\n"
    ++ epochBudgetCaseJson "last-positive-budget" 50 ++ ",\n"
    ++ epochBudgetCaseJson "first-zero-budget" 51 ++ ",\n"
    ++ epochBudgetCaseJson "last-bounded-shift-budget" 63 ++ ",\n"
    ++ epochBudgetCaseJson "bounded-shift-limit-budget" 64 ++ ",\n"
    ++ epochBudgetCaseJson "u64-max-epoch-budget" maxU64 ++ "\n"
    ++ "  ],\n"
    ++ "  \"slot_subsidy_cases\": [\n"
    ++ slotSubsidyCaseJson "epoch9-first-dust-slot" 9 0 ++ ",\n"
    ++ slotSubsidyCaseJson "epoch9-second-dust-slot" 9 1 ++ ",\n"
    ++ slotSubsidyCaseJson "epoch9-third-dust-slot" 9 2 ++ ",\n"
    ++ slotSubsidyCaseJson "epoch9-last-dust-slot" 9 (halvingInterval - 1) ++ ",\n"
    ++ slotSubsidyCaseJson "last-positive-epoch-first-slot" 50 0 ++ ",\n"
    ++ slotSubsidyCaseJson "last-positive-epoch-last-slot" 50 (halvingInterval - 1) ++ ",\n"
    ++ slotSubsidyCaseJson "zero-tail-epoch-last-slot" 51 (halvingInterval - 1) ++ "\n"
    ++ "  ],\n"
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
    ++ nativeSupplyCaseJson "native-overflow-rejected" almostMaxSupply 1 0 true ++ ",\n"
    ++ nativeSupplyCaseJson "coinbase-u64-add-overflow" 100 1 maxU64 true ++ ",\n"
    ++ nativeSupplyCaseJson "extinct-u64-max-fees" 0 maxU64 maxU64 true ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

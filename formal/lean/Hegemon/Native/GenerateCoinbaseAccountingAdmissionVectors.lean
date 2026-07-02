import Hegemon.Native.CoinbaseAccountingAdmission

open Hegemon.Native.CoinbaseAccountingAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => "\"" ++ toString value ++ "\""

def rejectionJson : Option CoinbaseAccountingReject -> String
  | none => "null"
  | some CoinbaseAccountingReject.multipleCoinbase => "\"multiple_coinbase\""
  | some CoinbaseAccountingReject.feeTotalOverflow => "\"fee_total_overflow\""
  | some CoinbaseAccountingReject.rewardOverflow => "\"reward_overflow\""
  | some CoinbaseAccountingReject.coinbaseAmountMissing =>
      "\"coinbase_amount_missing\""
  | some CoinbaseAccountingReject.amountMismatch => "\"amount_mismatch\""

def coinbaseAccountingCaseJson
    (name : String)
    (input : CoinbaseAccountingInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"coinbase_count\": " ++ toString input.coinbaseCount ++ ",\n"
    ++ "      \"height\": " ++ toString input.height ++ ",\n"
    ++ "      \"transfer_fee_total\": "
      ++ optionNatJson input.transferFeeTotal ++ ",\n"
    ++ "      \"observed_coinbase_amount\": "
      ++ optionNatJson input.observedCoinbaseAmount ++ ",\n"
    ++ "      \"expected_coinbase_amount\": "
      ++ optionNatJson (expectedCoinbaseAmount input) ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (coinbaseAccountingAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (coinbaseAccountingRejection input) ++ "\n"
    ++ "    }"

def maxU64Input : CoinbaseAccountingInput :=
  {
    coinbaseCount := 1,
    height := 1,
    transferFeeTotal := some Hegemon.Consensus.maxU64,
    observedCoinbaseAmount := none
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"coinbase_accounting_admission_cases\": [\n"
    ++ coinbaseAccountingCaseJson "no-coinbase-burns-fees-accepts"
      noCoinbaseBurnsFees ++ ",\n"
    ++ coinbaseAccountingCaseJson "valid-coinbase-subsidy"
      validCoinbaseSubsidy ++ ",\n"
    ++ coinbaseAccountingCaseJson "valid-coinbase-with-fees"
      validCoinbaseWithFees ++ ",\n"
    ++ coinbaseAccountingCaseJson "multiple-coinbase-rejected"
      { noCoinbaseBurnsFees with coinbaseCount := 2 } ++ ",\n"
    ++ coinbaseAccountingCaseJson "fee-total-overflow-rejected"
      { validCoinbaseSubsidy with transferFeeTotal := none } ++ ",\n"
    ++ coinbaseAccountingCaseJson "reward-overflow-rejected"
      maxU64Input ++ ",\n"
    ++ coinbaseAccountingCaseJson "coinbase-amount-missing-rejected"
      { validCoinbaseSubsidy with observedCoinbaseAmount := none } ++ ",\n"
    ++ coinbaseAccountingCaseJson "coinbase-amount-mismatch-rejected"
      { validCoinbaseSubsidy with observedCoinbaseAmount := some 0 } ++ ",\n"
    ++ coinbaseAccountingCaseJson "multiple-precedes-fee-overflow"
      {
        validCoinbaseSubsidy with
        coinbaseCount := 2,
        transferFeeTotal := none,
        observedCoinbaseAmount := none
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

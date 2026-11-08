import Hegemon.Consensus.TreasuryBatchSupply

open Hegemon.Consensus Hegemon.Consensus.TreasuryBatchSupply

def optJson : Option Nat → String
  | none => "null"
  | some n => toString n
def quotedOptJson : Option Nat → String
  | none => "null"
  | some n => "\"" ++ toString n ++ "\""
def boolJson (b : Bool) : String := if b then "true" else "false"
def entitlementJson (activation : Option Nat) (height : Nat) : String :=
  match entitlement activation height with
  | none => "null"
  | some e => "{\"batch_start\":" ++ toString e.batchStart ++
      ",\"payout_height\":" ++ optJson e.payoutHeight ++
      ",\"accrued_this_block\":" ++ toString e.accruedThisBlock ++
      ",\"pending_after\":" ++ toString e.pendingAfter ++
      ",\"payout\":" ++ toString e.payout ++ "}"
def entitlementCase (name : String) (activation : Option Nat) (height : Nat) : String :=
  "{\"name\":\"" ++ name ++ "\",\"activation\":" ++ optJson activation ++
    ",\"height\":" ++ toString height ++ ",\"expected\":" ++
    entitlementJson activation height ++ "}"

def accountingCase (name : String) (activation parent : Nat) (input : RewardInput) : String :=
  "{\"name\":\"" ++ name ++ "\",\"activation\":" ++ toString activation ++
    ",\"parent_supply\":\"" ++ toString parent ++ "\",\"height\":" ++ toString input.height ++
    ",\"fee_total\":" ++ optJson input.feeTotal ++
    ",\"coinbase_count\":" ++ toString input.coinbaseCount ++
    ",\"primary\":" ++ optJson input.primary ++ ",\"secondary\":" ++ optJson input.secondary ++
    ",\"canonical_and_admitted\":" ++ boolJson input.canonicalAndAdmitted ++
    ",\"placement_valid\":" ++ boolJson input.placementValid ++
    ",\"recipient_valid\":" ++ boolJson input.recipientValid ++
    ",\"expected_issued\":" ++ optJson (activeIssued (some activation) input) ++
    ",\"expected_supply\":" ++ quotedOptJson (advanceActiveSupply parent (some activation) input) ++ "}"

def replayCase (name : String) (parent height fees : Nat) (has : Bool)
    (issued : Option Nat) : String :=
  "{\"name\":\"" ++ name ++ "\",\"parent_supply\":\"" ++ toString parent ++
    "\",\"height\":" ++ toString height ++ ",\"fee_total\":" ++ toString fees ++
    ",\"has_coinbase\":" ++ boolJson has ++ ",\"issued_override\":" ++ optJson issued ++
    ",\"expected_supply\":" ++ quotedOptJson (replayExpectedSupply parent height fees has issued) ++ "}"

def reward (height : Nat) (primary secondary : Option Nat) (fees : Option Nat := some 7)
    (count : Nat := 1) : RewardInput :=
  { height := height, feeTotal := fees, coinbaseCount := count,
    primary := primary, secondary := secondary }

def vectorJson : String :=
  "{\"schema_version\":1,\"evidence_scope\":\"finite-candidate-treasury-actual-issued-model\",\"entitlement_cases\":[" ++
  String.intercalate "," [
    entitlementCase "disabled" none 60,
    entitlementCase "zero-activation-invalid" (some 0) 60,
    entitlementCase "pre-activation" (some 120) 119,
    entitlementCase "activation-no-history" (some 120) 120,
    entitlementCase "migration-before-boundary" (some 120) 178,
    entitlementCase "migration-boundary" (some 120) 179,
    entitlementCase "next-batch" (some 120) 180,
    entitlementCase "fresh-first" (some 1) 1,
    entitlementCase "fresh-before-boundary" (some 1) 59,
    entitlementCase "fresh-boundary" (some 1) 60,
    entitlementCase "fresh-second-boundary" (some 1) 120,
    entitlementCase "halving-crossing-exact-rounding" (some 2099981) 2100040,
    entitlementCase "dust-rounding" (some 18900001) 18900060,
    entitlementCase "final-residual" (some 107099981) 107100040,
    entitlementCase "zero-tail" (some 1) 107100060,
    entitlementCase "payout-height-overflow" (some maxU64) maxU64] ++
  "],\"accounting_cases\":[" ++ String.intercalate "," [
    accountingCase "intermediate-miner-all-fees" 1 100 (reward 59 (some 400000007) none),
    accountingCase "intermediate-miner-forfeiture" 1 100 (reward 59 none none none 0),
    accountingCase "intermediate-early-treasury" 1 100 (reward 59 (some 400000007) (some 100000000)),
    accountingCase "boundary-paired" 1 100 (reward 60 (some 400000007) (some 6000000000)),
    accountingCase "boundary-treasury-only-forfeits-miner-fees" 1 100 (reward 60 (some 6000000000) none),
    accountingCase "boundary-sole-miner-rejects" 1 100 (reward 60 (some 400000007) none),
    accountingCase "boundary-missing-treasury-rejects" 1 100 (reward 60 none none none 0),
    accountingCase "boundary-duplicate-rejects" 1 100 (reward 60 (some 6000000000) none (some 7) 2),
    accountingCase "boundary-wrong-due-rejects" 1 100 (reward 60 (some 6000000001) none),
    accountingCase "boundary-fee-overflow-rejects" 1 100 (reward 60 (some 6000000000) none none),
    accountingCase "boundary-miner-overflow-rejects" 1 100 (reward 60 (some 6000000000) none (some maxU64)),
    accountingCase "boundary-recipient-mismatch-rejects" 1 100
      { (reward 60 (some 6000000000) none) with recipientValid := false },
    accountingCase "boundary-noncanonical-rejects" 1 100
      { (reward 60 (some 6000000000) none) with canonicalAndAdmitted := false },
    accountingCase "boundary-placement-rejects" 1 100
      { (reward 60 (some 6000000000) none) with placementValid := false },
    accountingCase "boundary-supply-overflow-rejects" 1 (maxSupplyDigest - 5)
      (reward 60 (some 6000000000) none),
    accountingCase "migration-first-miner" 120 100 (reward 120 (some 400000007) none),
    accountingCase "migration-first-payout" 120 100 (reward 179 (some 6000000000) none),
    accountingCase "zero-tail-omission" 1 100 (reward 107100060 none none none 0)] ++
  "],\"replay_cases\":[" ++ String.intercalate "," [
    replayCase "historical-disabled" 100 60 7 true none,
    replayCase "actual-zero-during-accrual" 100 59 7 false (some 0),
    replayCase "actual-treasury-only" 100 60 7 true (some 6000000000),
    replayCase "actual-paired" 100 60 7 true (some 6400000007),
    replayCase "actual-supply-overflow" (maxSupplyDigest - 5) 60 7 true (some 6000000000),
    replayCase "actual-zero-at-u128-max" maxSupplyDigest 59 7 false (some 0),
    replayCase "historical-reward-overflow" 100 60 maxU64 true none] ++ "]}\n"

def main : IO Unit := IO.print vectorJson

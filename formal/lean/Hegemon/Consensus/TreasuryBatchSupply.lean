import Hegemon.Consensus.Supply

namespace Hegemon.Consensus.TreasuryBatchSupply

/- This additive model covers the active treasury cadence. Historical Supply,
CoinbaseAccountingAdmission and BlockReplayRefinement remain the disabled-policy
models. Cryptographic note admission and immutable recipient equality are explicit
host predicates; this file does not prove their implementations or whole-node refinement. -/

def batchBlocks : Nat := 60

def sumShares (subsidy : Nat → Nat) (start : Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => sumShares subsidy start n + subsidy (start + n) / 5

structure Entitlement where
  batchStart : Nat
  payoutHeight : Option Nat
  accruedThisBlock : Nat
  pendingAfter : Nat
  payout : Nat
deriving DecidableEq, Repr

def entitlementWith (activation : Option Nat) (height : Nat)
    (subsidy : Nat → Nat) : Option Entitlement := do
  let activation ← activation
  if activation = 0 ∨ height < activation ∨ maxU64 < height then none else do
    let offset := (height - activation) % batchBlocks
    let start := height - offset
    let accrued := sumShares subsidy start (offset + 1)
    if maxU64 < accrued then none else
      some {
        batchStart := start
        payoutHeight := if start + 59 ≤ maxU64 then some (start + 59) else none
        accruedThisBlock := subsidy height / 5
        pendingAfter := if offset = 59 then 0 else accrued
        payout := if offset = 59 then accrued else 0 }

def entitlement (activation : Option Nat) (height : Nat) : Option Entitlement :=
  entitlementWith activation height blockSubsidy

/-- Physical action-12 fields, before contextual logical-role normalization.
The host booleans are separate from amount equality and cannot authorize amounts. -/
structure RewardInput where
  height : Nat
  feeTotal : Option Nat
  coinbaseCount : Nat
  primary : Option Nat
  secondary : Option Nat
  canonicalAndAdmitted : Bool := true
  placementValid : Bool := true
  recipientValid : Bool := true
deriving DecidableEq, Repr

def physicalIssued (input : RewardInput) : Option Nat :=
  match input.primary with
  | none => none
  | some primary => checkedU64Add primary (input.secondary.getD 0)

def minerAmount (height fees : Nat) : Option Nat :=
  checkedU64Add (blockSubsidy height - blockSubsidy height / 5) fees

def allocationMatches (input : RewardInput) (due miner : Nat) : Bool :=
  if due > 0 ∧ input.secondary = none then
    input.primary == some due
  else
    input.primary == some miner &&
      input.secondary == (if due > 0 then some due else none)

/-- Positive due is mandatory even when the miner forfeits. Fees are checked
whenever a reward exists, including treasury-only physical-primary rewards. -/
def issuedForEntitlement (input : RewardInput) (due : Nat) : Option Nat :=
  if input.coinbaseCount > 1 then none
  else if input.coinbaseCount = 0 then
    if due = 0 then some 0 else none
  else if !(input.canonicalAndAdmitted && input.placementValid && input.recipientValid) then none
  else do
    let fees ← input.feeTotal
    let miner ← minerAmount input.height fees
    if allocationMatches input due miner then physicalIssued input else none

def activeIssued (activation : Option Nat) (input : RewardInput) : Option Nat := do
  let due ← entitlement activation input.height
  issuedForEntitlement input due.payout

def advanceActiveSupply (parent : Nat) (activation : Option Nat)
    (input : RewardInput) : Option Nat := do
  let issued ← activeIssued activation input
  increaseSupplyDigest parent issued

/-- Exactly mirrors the replay override: Some(0) is an actual zero delta;
None retains the historical per-block supply model. Admission is separate. -/
def replayExpectedSupply (parent height fees : Nat) (hasCoinbase : Bool)
    (issuedOverride : Option Nat) : Option Nat :=
  match issuedOverride with
  | some issued => increaseSupplyDigest parent issued
  | none => advanceNativeSupplyDigest parent height fees hasCoinbase

theorem sumShares_successor (subsidy : Nat → Nat) (start count : Nat) :
    sumShares subsidy start (count + 1) =
      sumShares subsidy start count + subsidy (start + count) / 5 := rfl

theorem batch_window_at_most_sixty (height activation : Nat) :
    (height - activation) % batchBlocks + 1 ≤ 60 :=
  Nat.succ_le_of_lt (Nat.mod_lt _ (by decide : 0 < batchBlocks))

theorem disabled_entitlement (height : Nat) : entitlement none height = none := rfl

theorem before_activation_no_reaccrual {activation height : Nat}
    (early : height < activation) : entitlement (some activation) height = none := by
  simp [entitlement, entitlementWith, early]

theorem positive_due_cannot_be_omitted {input : RewardInput} {due : Nat}
    (positive : 0 < due) (omitted : input.coinbaseCount = 0) :
    issuedForEntitlement input due = none := by
  simp [issuedForEntitlement, omitted, Nat.ne_of_gt positive]

theorem omitted_zero_due_issues_zero {input : RewardInput}
    (omitted : input.coinbaseCount = 0) :
    issuedForEntitlement input 0 = some 0 := by
  simp [issuedForEntitlement, omitted]

theorem sole_positive_primary_is_treasury {input : RewardInput} {due miner : Nat}
    (positive : 0 < due) (sole : input.secondary = none) :
    allocationMatches input due miner = (input.primary == some due) := by
  simp [allocationMatches, positive, sole]

theorem intermediate_forbids_secondary {input : RewardInput} {miner : Nat}
    (accepted : allocationMatches input 0 miner = true) :
    input.secondary = none := by
  have both : input.primary = some miner ∧ input.secondary = none := by
    simpa [allocationMatches] using accepted
  exact both.2

theorem accepted_one_binds_physical_issuance {input : RewardInput} {due issued : Nat}
    (one : input.coinbaseCount = 1)
    (accepted : issuedForEntitlement input due = some issued) :
    physicalIssued input = some issued := by
  by_cases host : (input.canonicalAndAdmitted && input.placementValid && input.recipientValid) = true
  · cases feesEq : input.feeTotal with
    | none => simp [issuedForEntitlement, one, host, feesEq] at accepted
    | some fees =>
      cases minerEq : minerAmount input.height fees with
      | none => simp [issuedForEntitlement, one, host, feesEq, minerEq] at accepted
      | some miner =>
        by_cases allocation : allocationMatches input due miner = true
        · simpa [issuedForEntitlement, one, host, feesEq, minerEq, allocation] using accepted
        · simp [issuedForEntitlement, one, host, feesEq, minerEq, allocation] at accepted
  · simp [issuedForEntitlement, one, host] at accepted

theorem entitlement_partitions_exact_accrual {activation height : Nat} {due : Entitlement}
    (accepted : entitlement (some activation) height = some due) :
    due.payout + due.pendingAfter =
      sumShares blockSubsidy (height - (height - activation) % batchBlocks)
        ((height - activation) % batchBlocks + 1) := by
  unfold entitlement entitlementWith at accepted
  simp only [bind, Option.bind] at accepted
  split at accepted
  · contradiction
  · split at accepted
    · contradiction
    · cases Option.some.inj accepted
      by_cases boundary : (height - activation) % batchBlocks = 59 <;> simp [boundary]

theorem active_supply_checked {parent issued : Nat} {activation : Option Nat}
    {input : RewardInput} (admitted : activeIssued activation input = some issued)
    (bounded : parent + issued ≤ maxSupplyDigest) :
    advanceActiveSupply parent activation input = some (parent + issued) := by
  simp [advanceActiveSupply, admitted, increaseSupplyDigest_ok bounded]

theorem active_supply_overflow_rejects {parent issued : Nat} {activation : Option Nat}
    {input : RewardInput} (admitted : activeIssued activation input = some issued)
    (overflow : maxSupplyDigest < parent + issued) :
    advanceActiveSupply parent activation input = none := by
  simp [advanceActiveSupply, admitted, increaseSupplyDigest_rejects_overflow overflow]

theorem replay_disabled_is_historical (parent height fees : Nat) (hasCoinbase : Bool) :
    replayExpectedSupply parent height fees hasCoinbase none =
      advanceNativeSupplyDigest parent height fees hasCoinbase := rfl

theorem replay_actual_issuance (parent height fees issued : Nat) (hasCoinbase : Bool) :
    replayExpectedSupply parent height fees hasCoinbase (some issued) =
      increaseSupplyDigest parent issued := rfl

theorem replay_actual_zero_ignores_scheduled_accrual {parent height fees : Nat}
    (bounded : parent ≤ maxSupplyDigest) (hasCoinbase : Bool) :
    replayExpectedSupply parent height fees hasCoinbase (some 0) = some parent := by
  simp [replayExpectedSupply, increaseSupplyDigest, bounded]

end Hegemon.Consensus.TreasuryBatchSupply

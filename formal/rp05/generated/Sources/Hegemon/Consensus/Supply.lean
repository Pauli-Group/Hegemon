namespace Hegemon
namespace Consensus

def maxSupplyDigest : Nat := 340282366920938463463374607431768211455
def maxU64 : Nat := 18446744073709551615

def coin : Nat := 100000000
def targetBlockSeconds : Nat := 60
def yearSeconds : Nat := 31536000
def epochYears : Nat := 4
/-- Fixed 2,100,000-block epochs at the unchanged 60-second target. The four-year
calendar constants remain legacy labels, not a division used by this schedule. -/
def halvingInterval : Nat := 2100000
def epochSeconds : Nat := halvingInterval * targetBlockSeconds
def maxMonetarySupply : Nat := 21000000 * coin
def initialSubsidy : Nat := 5 * coin

def increaseSupplyDigest (parent amount : Nat) : Option Nat :=
  let next := parent + amount
  if next <= maxSupplyDigest then some next else none

def decreaseSupplyDigest (parent amount : Nat) : Option Nat :=
  if amount <= parent then some (parent - amount) else none

def updateSupplyDigest (parent : Nat) (delta : Int) : Option Nat :=
  if delta >= 0 then
    increaseSupplyDigest parent delta.toNat
  else
    decreaseSupplyDigest parent (-delta).toNat

def netNativeDelta (minted : Nat) (fees : Int) (burns : Nat) : Int :=
  Int.ofNat minted + fees - Int.ofNat burns

def expectedConsensusSupply
    (parent minted : Nat)
    (fees : Int)
    (burns : Nat) : Option Nat :=
  updateSupplyDigest parent (netNativeDelta minted fees burns)

def pow2 (exponent : Nat) : Nat :=
  2 ^ exponent

/-- Undistributed budget at the beginning of an epoch; shifts never reach64. -/
def remainingBudget (epoch : Nat) : Nat :=
  if epoch < 64 then maxMonetarySupply / pow2 epoch else 0

def epochBudget (epoch : Nat) : Nat :=
  remainingBudget epoch - remainingBudget (epoch + 1)

/-- A slot receives the difference between adjacent floored prefix allocations.
This distributes every epoch atom, including division dust, exactly once. -/
def slotSubsidy (epoch slot : Nat) : Nat :=
  ((slot + 1) * epochBudget epoch) / halvingInterval -
    (slot * epochBudget epoch) / halvingInterval

def subsidyEpoch (height : Nat) : Nat := (height - 1) / halvingInterval
def subsidySlot (height : Nat) : Nat := (height - 1) % halvingInterval

/-- Retained diagnostic compatibility projection; blockSubsidy uses the full
uncapped epoch and remainingBudget performs the explicit bounded-shift check. -/
def cappedHalvingEpoch (height : Nat) : Nat := Nat.min (subsidyEpoch height) 63

def blockSubsidy (height : Nat) : Nat :=
  if height = 0 then 0 else slotSubsidy (subsidyEpoch height) (subsidySlot height)

/-- Inclusive scheduled subsidy through height h, including zero at genesis.
This is a mathematical schedule prefix, separate from fee-inclusive digest. -/
def scheduledPrefix (height : Nat) : Nat :=
  let epoch := height / halvingInterval
  let slot := height % halvingInterval
  maxMonetarySupply - remainingBudget epoch +
    (slot * epochBudget epoch) / halvingInterval

def checkedU64Add (left right : Nat) : Option Nat :=
  let sum := left + right
  if sum <= maxU64 then some sum else none

def nativeCoinbaseAmount (height feeTotal : Nat) : Option Nat :=
  checkedU64Add (blockSubsidy height) feeTotal

def nativeSupplyDelta (height feeTotal : Nat) (hasCoinbase : Bool) : Option Nat :=
  if hasCoinbase then nativeCoinbaseAmount height feeTotal else some 0

def advanceNativeSupplyDigest
    (parent height feeTotal : Nat)
    (hasCoinbase : Bool) : Option Nat :=
  match nativeSupplyDelta height feeTotal hasCoinbase with
  | none => none
  | some delta => increaseSupplyDigest parent delta

theorem increaseSupplyDigest_ok
    {parent amount : Nat}
    (h : parent + amount <= maxSupplyDigest) :
    increaseSupplyDigest parent amount = some (parent + amount) := by
  unfold increaseSupplyDigest
  simp [h]

theorem increaseSupplyDigest_rejects_overflow
    {parent amount : Nat}
    (h : maxSupplyDigest < parent + amount) :
    increaseSupplyDigest parent amount = none := by
  unfold increaseSupplyDigest
  have notBounded : ¬ parent + amount <= maxSupplyDigest := Nat.not_le.mpr h
  simp [notBounded]

theorem decreaseSupplyDigest_ok
    {parent amount : Nat}
    (h : amount <= parent) :
    decreaseSupplyDigest parent amount = some (parent - amount) := by
  unfold decreaseSupplyDigest
  simp [h]

theorem decreaseSupplyDigest_rejects_underflow
    {parent amount : Nat}
    (h : parent < amount) :
    decreaseSupplyDigest parent amount = none := by
  unfold decreaseSupplyDigest
  have notEnough : ¬ amount <= parent := Nat.not_le.mpr h
  simp [notEnough]

theorem nativeSupplyDelta_without_coinbase
    {height feeTotal : Nat} :
    nativeSupplyDelta height feeTotal false = some 0 := by
  unfold nativeSupplyDelta
  rfl

theorem monetaryConstants_match_tokenomics :
    coin = 100000000
      ∧ targetBlockSeconds = 60
      ∧ yearSeconds = 31536000
      ∧ epochYears = 4
      ∧ halvingInterval = 2100000
      ∧ epochSeconds = 126000000
      ∧ maxMonetarySupply = 2100000000000000
      ∧ initialSubsidy = 500000000 := by
  decide

theorem blockSubsidy_zero_height :
    blockSubsidy 0 = 0 := by
  rfl

theorem blockSubsidy_initial_height :
    blockSubsidy 1 = initialSubsidy := by
  rfl

theorem blockSubsidy_first_epoch_last_block :
    blockSubsidy halvingInterval = initialSubsidy := by
  decide

theorem blockSubsidy_first_halving_boundary :
    blockSubsidy (halvingInterval + 1) = initialSubsidy / 2 := by
  decide

theorem blockSubsidy_second_halving_boundary :
    blockSubsidy (2 * halvingInterval + 1) = initialSubsidy / 4 := by
  decide

theorem blockSubsidy_extinct_at_capped_shift :
    blockSubsidy (64 * halvingInterval + 1) = 0 := by
  decide

theorem blockSubsidy_capped_shift_stable_after_extinction :
    blockSubsidy (65 * halvingInterval + 1) =
      blockSubsidy (64 * halvingInterval + 1) := by
  decide

theorem halvingInterval_pos : 0 < halvingInterval := by decide

theorem remainingBudget_zero : remainingBudget 0 = maxMonetarySupply := by rfl

theorem remainingBudget_at64 : remainingBudget 64 = 0 := by rfl

theorem remainingBudget_after64 {epoch : Nat} (late : 64 ≤ epoch) :
    remainingBudget epoch = 0 := by
  unfold remainingBudget
  simp only [if_neg (Nat.not_lt.mpr late)]

theorem epochBudget_after64 {epoch : Nat} (late : 64 ≤ epoch) :
    epochBudget epoch = 0 := by
  unfold epochBudget
  rw [remainingBudget_after64 late,
    remainingBudget_after64 (Nat.le_trans late (Nat.le_succ epoch))]

theorem slotSubsidy_of_epochBudget_zero {epoch slot : Nat}
    (zero : epochBudget epoch = 0) : slotSubsidy epoch slot = 0 := by
  simp [slotSubsidy, zero]

theorem blockSubsidy_uses_epoch_slot {height : Nat} (nonzero : height ≠ 0) :
    blockSubsidy height = slotSubsidy (subsidyEpoch height) (subsidySlot height) := by
  unfold blockSubsidy
  simp only [if_neg nonzero]

/-- Compatibility theorem name retained; the new formula uses the full epoch
and its slot, not the obsolete per-epoch right-shift payout. -/
theorem blockSubsidy_uses_capped_halving_epoch {height : Nat}
    (nonzero : height ≠ 0) :
    blockSubsidy height = slotSubsidy (subsidyEpoch height) (subsidySlot height) :=
  blockSubsidy_uses_epoch_slot nonzero

theorem blockSubsidy_after_budget_window {height : Nat}
    (late : 64 ≤ subsidyEpoch height) : blockSubsidy height = 0 := by
  by_cases zero : height = 0
  · simp [blockSubsidy, zero]
  · rw [blockSubsidy_uses_epoch_slot zero]
    exact slotSubsidy_of_epochBudget_zero (epochBudget_after64 late)

theorem epoch9_dust_slots :
    epochBudget 9 = 2050781250000 ∧ slotSubsidy 9 0 = 976562 ∧
    slotSubsidy 9 1 = 976563 ∧ slotSubsidy 9 2 = 976562 := by decide

theorem final_positive_subsidy : blockSubsidy 107100000 = 1 := by decide

theorem first_zero_tail_subsidy : blockSubsidy 107100001 = 0 := by decide

theorem scheduledPrefix_zero : scheduledPrefix 0 = 0 := by decide

theorem scheduledPrefix_complete : scheduledPrefix 107100000 = maxMonetarySupply := by decide

theorem scheduledPrefix_tail : scheduledPrefix 107100001 = maxMonetarySupply := by decide

theorem scheduledPrefix_u64_max : scheduledPrefix maxU64 = maxMonetarySupply := by decide

theorem nativeSupplyDelta_with_coinbase
    {height feeTotal amount : Nat}
    (h : nativeCoinbaseAmount height feeTotal = some amount) :
    nativeSupplyDelta height feeTotal true = some amount := by
  unfold nativeSupplyDelta
  exact h

theorem advanceNativeSupplyDigest_checked
    {parent height feeTotal delta : Nat}
    {hasCoinbase : Bool}
    (deltaEq : nativeSupplyDelta height feeTotal hasCoinbase = some delta)
    (bounded : parent + delta <= maxSupplyDigest) :
    advanceNativeSupplyDigest parent height feeTotal hasCoinbase =
      some (parent + delta) := by
  unfold advanceNativeSupplyDigest
  rw [deltaEq]
  exact increaseSupplyDigest_ok bounded

theorem advanceNativeSupplyDigest_rejects_supply_overflow
    {parent height feeTotal delta : Nat}
    {hasCoinbase : Bool}
    (deltaEq : nativeSupplyDelta height feeTotal hasCoinbase = some delta)
    (overflow : maxSupplyDigest < parent + delta) :
    advanceNativeSupplyDigest parent height feeTotal hasCoinbase = none := by
  unfold advanceNativeSupplyDigest
  rw [deltaEq]
  exact increaseSupplyDigest_rejects_overflow overflow

end Consensus
end Hegemon

namespace Hegemon
namespace Consensus

def maxSupplyDigest : Nat := 340282366920938463463374607431768211455
def maxU64 : Nat := 18446744073709551615

def coin : Nat := 100000000
def targetBlockSeconds : Nat := 60
def yearSeconds : Nat := 31536000
def epochYears : Nat := 4
def halvingInterval : Nat := epochYears * yearSeconds / targetBlockSeconds
def maxMonetarySupply : Nat := 21000000 * coin
def initialSubsidy : Nat :=
  maxMonetarySupply * targetBlockSeconds / (2 * epochYears * yearSeconds)

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

def cappedHalvingEpoch (height : Nat) : Nat :=
  if height = 0 then
    0
  else
    Nat.min ((height - 1) / halvingInterval) 63

def blockSubsidy (height : Nat) : Nat :=
  if height = 0 then
    0
  else
    initialSubsidy / pow2 (cappedHalvingEpoch height)

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
      ∧ halvingInterval = 2102400
      ∧ maxMonetarySupply = 2100000000000000
      ∧ initialSubsidy = 499429223 := by
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

theorem blockSubsidy_uses_capped_halving_epoch
    {height : Nat}
    (nonzero : height ≠ 0) :
    blockSubsidy height =
      initialSubsidy / pow2 (cappedHalvingEpoch height) := by
  unfold blockSubsidy
  simp [nonzero]

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

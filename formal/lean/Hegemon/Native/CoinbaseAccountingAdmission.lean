import Hegemon.Consensus.Supply

namespace Hegemon
namespace Native
namespace CoinbaseAccountingAdmission

inductive CoinbaseAccountingReject where
  | multipleCoinbase
  | feeTotalOverflow
  | rewardOverflow
  | coinbaseAmountMissing
  | amountMismatch
deriving DecidableEq, Repr

structure CoinbaseAccountingInput where
  coinbaseCount : Nat
  height : Nat
  transferFeeTotal : Option Nat
  observedCoinbaseAmount : Option Nat
deriving DecidableEq, Repr

def expectedCoinbaseAmount (input : CoinbaseAccountingInput) : Option Nat :=
  match input.transferFeeTotal with
  | none => none
  | some fees => Hegemon.Consensus.nativeCoinbaseAmount input.height fees

def evaluateCoinbaseAccounting
    (input : CoinbaseAccountingInput) : Except CoinbaseAccountingReject Unit :=
  if input.coinbaseCount > 1 then
    Except.error CoinbaseAccountingReject.multipleCoinbase
  else if input.coinbaseCount = 0 then
    Except.ok ()
  else
    match input.transferFeeTotal with
    | none => Except.error CoinbaseAccountingReject.feeTotalOverflow
    | some fees =>
        match Hegemon.Consensus.nativeCoinbaseAmount input.height fees with
        | none => Except.error CoinbaseAccountingReject.rewardOverflow
        | some expected =>
            match input.observedCoinbaseAmount with
            | none => Except.error CoinbaseAccountingReject.coinbaseAmountMissing
            | some observed =>
                if observed = expected then
                  Except.ok ()
                else
                  Except.error CoinbaseAccountingReject.amountMismatch

def coinbaseAccountingAccepts (input : CoinbaseAccountingInput) : Bool :=
  match evaluateCoinbaseAccounting input with
  | Except.ok _ => true
  | Except.error _ => false

def coinbaseAccountingRejection
    (input : CoinbaseAccountingInput) : Option CoinbaseAccountingReject :=
  match evaluateCoinbaseAccounting input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

theorem no_coinbase_accepts
    {input : CoinbaseAccountingInput}
    (noCoinbase : input.coinbaseCount = 0) :
    evaluateCoinbaseAccounting input = Except.ok () := by
  unfold evaluateCoinbaseAccounting
  simp [noCoinbase]

theorem multiple_coinbase_rejects
    {input : CoinbaseAccountingInput}
    (multiple : 1 < input.coinbaseCount) :
    evaluateCoinbaseAccounting input =
      Except.error CoinbaseAccountingReject.multipleCoinbase := by
  unfold evaluateCoinbaseAccounting
  simp [multiple]

theorem fee_total_overflow_rejects
    {input : CoinbaseAccountingInput}
    (oneCoinbase : input.coinbaseCount = 1)
    (feeOverflow : input.transferFeeTotal = none) :
    evaluateCoinbaseAccounting input =
      Except.error CoinbaseAccountingReject.feeTotalOverflow := by
  unfold evaluateCoinbaseAccounting
  simp [oneCoinbase, feeOverflow]

theorem reward_overflow_rejects
    {input : CoinbaseAccountingInput}
    {fees : Nat}
    (oneCoinbase : input.coinbaseCount = 1)
    (feeTotal : input.transferFeeTotal = some fees)
    (rewardOverflow :
      Hegemon.Consensus.nativeCoinbaseAmount input.height fees = none) :
    evaluateCoinbaseAccounting input =
      Except.error CoinbaseAccountingReject.rewardOverflow := by
  unfold evaluateCoinbaseAccounting
  simp [oneCoinbase, feeTotal, rewardOverflow]

theorem coinbase_amount_missing_rejects
    {input : CoinbaseAccountingInput}
    {fees expected : Nat}
    (oneCoinbase : input.coinbaseCount = 1)
    (feeTotal : input.transferFeeTotal = some fees)
    (expectedAmount :
      Hegemon.Consensus.nativeCoinbaseAmount input.height fees = some expected)
    (missing : input.observedCoinbaseAmount = none) :
    evaluateCoinbaseAccounting input =
      Except.error CoinbaseAccountingReject.coinbaseAmountMissing := by
  unfold evaluateCoinbaseAccounting
  simp [oneCoinbase, feeTotal, expectedAmount, missing]

theorem amount_mismatch_rejects
    {input : CoinbaseAccountingInput}
    {fees expected observed : Nat}
    (oneCoinbase : input.coinbaseCount = 1)
    (feeTotal : input.transferFeeTotal = some fees)
    (expectedAmount :
      Hegemon.Consensus.nativeCoinbaseAmount input.height fees = some expected)
    (observedAmount : input.observedCoinbaseAmount = some observed)
    (mismatch : observed ≠ expected) :
    evaluateCoinbaseAccounting input =
      Except.error CoinbaseAccountingReject.amountMismatch := by
  unfold evaluateCoinbaseAccounting
  simp [oneCoinbase, feeTotal, expectedAmount, observedAmount, mismatch]

theorem matching_amount_accepts
    {input : CoinbaseAccountingInput}
    {fees expected : Nat}
    (oneCoinbase : input.coinbaseCount = 1)
    (feeTotal : input.transferFeeTotal = some fees)
    (expectedAmount :
      Hegemon.Consensus.nativeCoinbaseAmount input.height fees = some expected)
    (observedAmount : input.observedCoinbaseAmount = some expected) :
    evaluateCoinbaseAccounting input = Except.ok () := by
  unfold evaluateCoinbaseAccounting
  simp [oneCoinbase, feeTotal, expectedAmount, observedAmount]

def noCoinbaseBurnsFees : CoinbaseAccountingInput :=
  {
    coinbaseCount := 0,
    height := 1,
    transferFeeTotal := none,
    observedCoinbaseAmount := none
  }

def validCoinbaseSubsidy : CoinbaseAccountingInput :=
  {
    coinbaseCount := 1,
    height := 1,
    transferFeeTotal := some 0,
    observedCoinbaseAmount := Hegemon.Consensus.nativeCoinbaseAmount 1 0
  }

def validCoinbaseWithFees : CoinbaseAccountingInput :=
  {
    coinbaseCount := 1,
    height := 1,
    transferFeeTotal := some 7,
    observedCoinbaseAmount := Hegemon.Consensus.nativeCoinbaseAmount 1 7
  }

theorem no_coinbase_burns_fees_accepts :
    evaluateCoinbaseAccounting noCoinbaseBurnsFees = Except.ok () := by
  rfl

theorem valid_coinbase_subsidy_accepts :
    evaluateCoinbaseAccounting validCoinbaseSubsidy = Except.ok () := by
  rfl

theorem valid_coinbase_with_fees_accepts :
    evaluateCoinbaseAccounting validCoinbaseWithFees = Except.ok () := by
  rfl

theorem multiple_precedes_fee_total_overflow
    {input : CoinbaseAccountingInput}
    (multiple : 1 < input.coinbaseCount) :
    evaluateCoinbaseAccounting input =
      Except.error CoinbaseAccountingReject.multipleCoinbase := by
  exact multiple_coinbase_rejects multiple

end CoinbaseAccountingAdmission
end Native
end Hegemon

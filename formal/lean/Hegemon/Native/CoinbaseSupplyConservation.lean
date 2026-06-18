import Hegemon.Consensus.SupplyInvariant
import Hegemon.Native.CoinbaseAccountingAdmission

namespace Hegemon
namespace Native
namespace CoinbaseSupplyConservation

open Hegemon.Consensus
open Hegemon.Consensus.SupplyInvariant
open Hegemon.Native.CoinbaseAccountingAdmission
open Hegemon.Transaction
open Hegemon.Transaction.AssetIsolation
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofSystemBoundary

structure CoinbaseBackedClaimedSupplyCertificate
    (parent next : Nat)
    (input : CoinbaseAccountingInput)
    (step : ClaimedSupplyStep) : Prop where
  accountingAccepted :
    evaluateCoinbaseAccounting input = Except.ok ()
  oneCoinbase :
    input.coinbaseCount = 1
  transferFeeTotal :
    ∃ fees, input.transferFeeTotal = some fees
  observedCoinbaseAmount :
    ∃ observed, input.observedCoinbaseAmount = some observed
  observedMatchesSubsidyPlusFees :
    ∀ {fees observed},
      input.transferFeeTotal = some fees ->
      input.observedCoinbaseAmount = some observed ->
      nativeCoinbaseAmount input.height fees = some observed
  mintedBoundToSubsidy :
    step.minted = blockSubsidy input.height
  feesBoundToTransferTotal :
    ∀ {fees},
      input.transferFeeTotal = some fees ->
      step.fees = Int.ofNat fees
  claimedSupplyDelta :
    applySupplyDelta parent step.delta = some step.claimedSupply
  acceptedNext :
    next = step.claimedSupply

theorem accepted_one_coinbase_accounting_binds_observed_amount
    {input : CoinbaseAccountingInput}
    {fees observed : Nat}
    (oneCoinbase : input.coinbaseCount = 1)
    (feeTotal : input.transferFeeTotal = some fees)
    (observedAmount : input.observedCoinbaseAmount = some observed)
    (accepted : evaluateCoinbaseAccounting input = Except.ok ()) :
    nativeCoinbaseAmount input.height fees = some observed := by
  unfold evaluateCoinbaseAccounting at accepted
  simp [oneCoinbase, feeTotal] at accepted
  cases expectedEq : nativeCoinbaseAmount input.height fees with
  | none =>
      simp [expectedEq] at accepted
  | some expected =>
      simp [expectedEq, observedAmount] at accepted
      simp [accepted]

theorem accepted_one_coinbase_accounting_yields_supply_certificate
    {parent next : Nat}
    {input : CoinbaseAccountingInput}
    {step : ClaimedSupplyStep}
    {fees observed : Nat}
    (oneCoinbase : input.coinbaseCount = 1)
    (feeTotal : input.transferFeeTotal = some fees)
    (observedAmount : input.observedCoinbaseAmount = some observed)
    (mintedBinding : step.minted = blockSubsidy input.height)
    (feeBinding : step.fees = Int.ofNat fees)
    (accountingAccepted : evaluateCoinbaseAccounting input = Except.ok ())
    (supplyAccepted : validateClaimedSupplyStep parent step = some next) :
    CoinbaseBackedClaimedSupplyCertificate parent next input step := by
  have supplyFacts := valid_step_claims_expected_supply supplyAccepted
  exact
    { accountingAccepted := accountingAccepted
      oneCoinbase := oneCoinbase
      transferFeeTotal := ⟨fees, feeTotal⟩
      observedCoinbaseAmount := ⟨observed, observedAmount⟩
      observedMatchesSubsidyPlusFees := by
        intro boundFees boundObserved feeEq observedEq
        have feesEq : boundFees = fees := by
          have someEq : (some boundFees : Option Nat) = some fees := by
            rw [← feeEq, feeTotal]
          simpa using someEq
        have observedEq' : boundObserved = observed := by
          have someEq : (some boundObserved : Option Nat) = some observed := by
            rw [← observedEq, observedAmount]
          simpa using someEq
        simpa [feesEq, observedEq'] using
          accepted_one_coinbase_accounting_binds_observed_amount
            oneCoinbase
            feeTotal
            observedAmount
            accountingAccepted
      mintedBoundToSubsidy := mintedBinding
      feesBoundToTransferTotal := by
        intro boundFees feeEq
        have feesEq : boundFees = fees := by
          have someEq : (some boundFees : Option Nat) = some fees := by
            rw [← feeEq, feeTotal]
          simpa using someEq
        simpa [feesEq] using feeBinding
      claimedSupplyDelta := supplyFacts.left
      acceptedNext := supplyFacts.right }

structure NoCoinbaseClaimedSupplyCertificate
    (parent next : Nat)
    (input : CoinbaseAccountingInput)
    (step : ClaimedSupplyStep) : Prop where
  accountingAccepted :
    evaluateCoinbaseAccounting input = Except.ok ()
  noCoinbase :
    input.coinbaseCount = 0
  noCoinbaseMint :
    step.minted = 0
  claimedSupplyDelta :
    applySupplyDelta parent step.delta = some step.claimedSupply
  acceptedNext :
    next = step.claimedSupply

theorem accepted_no_coinbase_accounting_yields_supply_certificate
    {parent next : Nat}
    {input : CoinbaseAccountingInput}
    {step : ClaimedSupplyStep}
    (noCoinbase : input.coinbaseCount = 0)
    (mintedBinding : step.minted = 0)
    (accountingAccepted : evaluateCoinbaseAccounting input = Except.ok ())
    (supplyAccepted : validateClaimedSupplyStep parent step = some next) :
    NoCoinbaseClaimedSupplyCertificate parent next input step := by
  have supplyFacts := valid_step_claims_expected_supply supplyAccepted
  exact
    { accountingAccepted := accountingAccepted
      noCoinbase := noCoinbase
      noCoinbaseMint := mintedBinding
      claimedSupplyDelta := supplyFacts.left
      acceptedNext := supplyFacts.right }

theorem accepted_one_coinbase_accounting_and_canonical_boundary_yields_supply_integrity_certificate
    {parent next : Nat}
    {input : CoinbaseAccountingInput}
    {step : ClaimedSupplyStep}
    {fees observed : Nat}
    {wrapper : ProofWrapperAdmission.ProofWrapperInput}
    {shape : PublicInputs.PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List SpendAuthorization.InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (oneCoinbase : input.coinbaseCount = 1)
    (feeTotal : input.transferFeeTotal = some fees)
    (observedAmount : input.observedCoinbaseAmount = some observed)
    (mintedBinding : step.minted = blockSubsidy input.height)
    (coinbaseFeeBinding : step.fees = Int.ofNat fees)
    (canonicalFeeBinding :
      step.fees = publicAuthorizedAssetDeltaValue publicFields nativeAsset)
    (accountingAccepted : evaluateCoinbaseAccounting input = Except.ok ())
    (boundary :
      CanonicalProofSystemNoTheftBoundaryFacts
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (supplyAccepted : validateClaimedSupplyStep parent step = some next) :
    CoinbaseBackedClaimedSupplyCertificate parent next input step
      ∧ CanonicalProductionSupplyConservationCertificate
        parent
        next
        step
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots
      ∧ step.fees = Int.ofNat fees
      ∧ step.fees = publicAuthorizedAssetDeltaValue publicFields nativeAsset := by
  exact
    ⟨accepted_one_coinbase_accounting_yields_supply_certificate
      oneCoinbase
      feeTotal
      observedAmount
      mintedBinding
      coinbaseFeeBinding
      accountingAccepted
      supplyAccepted,
    canonical_no_theft_boundary_yields_production_supply_conservation_certificate
      boundary
      canonicalFeeBinding
      supplyAccepted,
    coinbaseFeeBinding,
    canonicalFeeBinding⟩

theorem accepted_no_coinbase_accounting_and_canonical_boundary_yields_supply_integrity_certificate
    {parent next : Nat}
    {input : CoinbaseAccountingInput}
    {step : ClaimedSupplyStep}
    {wrapper : ProofWrapperAdmission.ProofWrapperInput}
    {shape : PublicInputs.PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List SpendAuthorization.InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (noCoinbase : input.coinbaseCount = 0)
    (mintedBinding : step.minted = 0)
    (canonicalFeeBinding :
      step.fees = publicAuthorizedAssetDeltaValue publicFields nativeAsset)
    (accountingAccepted : evaluateCoinbaseAccounting input = Except.ok ())
    (boundary :
      CanonicalProofSystemNoTheftBoundaryFacts
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (supplyAccepted : validateClaimedSupplyStep parent step = some next) :
    NoCoinbaseClaimedSupplyCertificate parent next input step
      ∧ CanonicalProductionSupplyConservationCertificate
        parent
        next
        step
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        spendWitnesses
        balanceWitness
        slots
      ∧ step.minted = 0
      ∧ step.fees = publicAuthorizedAssetDeltaValue publicFields nativeAsset := by
  exact
    ⟨accepted_no_coinbase_accounting_yields_supply_certificate
      noCoinbase
      mintedBinding
      accountingAccepted
      supplyAccepted,
    canonical_no_theft_boundary_yields_production_supply_conservation_certificate
      boundary
      canonicalFeeBinding
      supplyAccepted,
    mintedBinding,
    canonicalFeeBinding⟩

end CoinbaseSupplyConservation
end Native
end Hegemon

import Hegemon.Transaction.PublicInputs

namespace Hegemon
namespace Privacy
namespace WalletOutputBatch

abbrev MaxOutputs : Nat := Hegemon.Transaction.PublicInputs.maxOutputs

inductive WalletOutputBatchKind where
  | native
  | stablecoin
  | burn
  | consolidation
deriving DecidableEq, Repr

structure WalletOutputBatchInput where
  kind : WalletOutputBatchKind
  recipientCount : Nat
  recipientTotal : Nat
  fee : Nat
  selectedAssetTotal : Nat
  selectedNativeTotal : Nat
  issuanceDelta : Int
  burnAmount : Nat
  privateWitnessSeed : Nat
  localMetadataSeed : Nat
deriving DecidableEq, Repr

structure WalletOutputBatchPublicShape where
  kind : WalletOutputBatchKind
  recipientCount : Nat
  recipientTotal : Nat
  fee : Nat
  selectedAssetTotal : Nat
  selectedNativeTotal : Nat
  issuanceDelta : Int
  burnAmount : Nat
deriving DecidableEq, Repr

def boolToNat (flag : Bool) : Nat :=
  if flag then 1 else 0

def requiredNativeSpend (input : WalletOutputBatchInput) : Nat :=
  input.recipientTotal + input.fee

def requiredStablecoinSpend (input : WalletOutputBatchInput) : Option Nat :=
  let required := Int.ofNat input.recipientTotal + input.issuanceDelta
  if required < 0 then none else some required.toNat

def publicShape (input : WalletOutputBatchInput) :
    WalletOutputBatchPublicShape :=
  { kind := input.kind
    recipientCount := input.recipientCount
    recipientTotal := input.recipientTotal
    fee := input.fee
    selectedAssetTotal := input.selectedAssetTotal
    selectedNativeTotal := input.selectedNativeTotal
    issuanceDelta := input.issuanceDelta
    burnAmount := input.burnAmount }

def outputCountFromPublicShape :
    WalletOutputBatchPublicShape -> Nat
  | { kind := WalletOutputBatchKind.native, recipientCount, recipientTotal,
      fee, selectedAssetTotal, .. } =>
      recipientCount + boolToNat (recipientTotal + fee < selectedAssetTotal)
  | { kind := WalletOutputBatchKind.stablecoin, recipientCount,
      recipientTotal, fee, selectedAssetTotal, selectedNativeTotal,
      issuanceDelta, .. } =>
      let required := Int.ofNat recipientTotal + issuanceDelta
      if required < 0 then
        recipientCount
      else
        let requiredNat := required.toNat
        let assetChange := requiredNat < selectedAssetTotal
        let nativeChange :=
          fee > 0 && !assetChange && fee < selectedNativeTotal
        recipientCount + boolToNat assetChange + boolToNat nativeChange
  | { kind := WalletOutputBatchKind.burn, fee, selectedAssetTotal,
      selectedNativeTotal, burnAmount, .. } =>
      boolToNat (burnAmount < selectedAssetTotal)
        + boolToNat (fee > 0 && fee < selectedNativeTotal)
  | { kind := WalletOutputBatchKind.consolidation, .. } =>
      1

def walletOutputCount (input : WalletOutputBatchInput) : Nat :=
  outputCountFromPublicShape (publicShape input)

def recipientShapeAccepts : WalletOutputBatchInput -> Bool
  | { kind := WalletOutputBatchKind.native, recipientCount, .. } =>
      recipientCount = 1
  | { kind := WalletOutputBatchKind.stablecoin, recipientCount, .. } =>
      recipientCount = 1
  | { kind := WalletOutputBatchKind.burn, recipientCount, .. } =>
      recipientCount = 0
  | { kind := WalletOutputBatchKind.consolidation, recipientCount, .. } =>
      recipientCount = 0

def corePlanAccepts : WalletOutputBatchInput -> Bool
  | input@{ kind := WalletOutputBatchKind.native, .. } =>
      recipientShapeAccepts input
        && (requiredNativeSpend input <= input.selectedAssetTotal)
  | input@{ kind := WalletOutputBatchKind.stablecoin, .. } =>
      recipientShapeAccepts input
        && match requiredStablecoinSpend input with
          | none => false
          | some required =>
              let assetChange := required < input.selectedAssetTotal
              required <= input.selectedAssetTotal
                && (input.fee = 0
                  || (if assetChange then
                        input.selectedNativeTotal = input.fee
                      else
                        input.fee <= input.selectedNativeTotal))
  | input@{ kind := WalletOutputBatchKind.burn, .. } =>
      recipientShapeAccepts input
        && input.burnAmount <= input.selectedAssetTotal
        && (input.fee = 0 || input.fee <= input.selectedNativeTotal)
  | input@{ kind := WalletOutputBatchKind.consolidation, .. } =>
      recipientShapeAccepts input
        && input.fee < input.selectedAssetTotal

def walletOutputBatchAccepts (input : WalletOutputBatchInput) : Bool :=
  if walletOutputCount input <= MaxOutputs then
    corePlanAccepts input
  else
    false

theorem output_count_eq_public_shape
    (input : WalletOutputBatchInput) :
    walletOutputCount input =
      outputCountFromPublicShape (publicShape input) := by
  rfl

theorem output_count_ignores_private_witness_seed
    (input : WalletOutputBatchInput) (seed : Nat) :
    walletOutputCount { input with privateWitnessSeed := seed } =
      walletOutputCount input := by
  rfl

theorem output_count_ignores_local_metadata_seed
    (input : WalletOutputBatchInput) (seed : Nat) :
    walletOutputCount { input with localMetadataSeed := seed } =
      walletOutputCount input := by
  rfl

theorem acceptance_ignores_private_witness_seed
    (input : WalletOutputBatchInput) (seed : Nat) :
    walletOutputBatchAccepts { input with privateWitnessSeed := seed } =
      walletOutputBatchAccepts input := by
  cases input with
  | mk kind recipientCount recipientTotal fee selectedAssetTotal
      selectedNativeTotal issuanceDelta burnAmount privateWitnessSeed
      localMetadataSeed =>
      cases kind <;>
        simp [walletOutputBatchAccepts, walletOutputCount, publicShape,
          outputCountFromPublicShape, corePlanAccepts, recipientShapeAccepts,
          requiredNativeSpend, requiredStablecoinSpend] <;> rfl

theorem acceptance_ignores_local_metadata_seed
    (input : WalletOutputBatchInput) (seed : Nat) :
    walletOutputBatchAccepts { input with localMetadataSeed := seed } =
      walletOutputBatchAccepts input := by
  cases input with
  | mk kind recipientCount recipientTotal fee selectedAssetTotal
      selectedNativeTotal issuanceDelta burnAmount privateWitnessSeed
      localMetadataSeed =>
      cases kind <;>
        simp [walletOutputBatchAccepts, walletOutputCount, publicShape,
          outputCountFromPublicShape, corePlanAccepts, recipientShapeAccepts,
          requiredNativeSpend, requiredStablecoinSpend] <;> rfl

theorem accepted_output_count_le_max
    {input : WalletOutputBatchInput}
    (accepted : walletOutputBatchAccepts input = true) :
    walletOutputCount input <= MaxOutputs := by
  unfold walletOutputBatchAccepts at accepted
  split at accepted
  · assumption
  · contradiction

def nativeExactNoChange : WalletOutputBatchInput :=
  { kind := WalletOutputBatchKind.native
    recipientCount := 1
    recipientTotal := 90
    fee := 10
    selectedAssetTotal := 100
    selectedNativeTotal := 0
    issuanceDelta := 0
    burnAmount := 0
    privateWitnessSeed := 11
    localMetadataSeed := 101 }

def nativeWithChange : WalletOutputBatchInput :=
  { nativeExactNoChange with
    recipientTotal := 100
    selectedAssetTotal := 150
    privateWitnessSeed := 12
    localMetadataSeed := 102 }

def stablecoinIssuanceNoInput : WalletOutputBatchInput :=
  { kind := WalletOutputBatchKind.stablecoin
    recipientCount := 1
    recipientTotal := 100
    fee := 0
    selectedAssetTotal := 0
    selectedNativeTotal := 0
    issuanceDelta := -100
    burnAmount := 0
    privateWitnessSeed := 21
    localMetadataSeed := 201 }

def stablecoinAssetChangeExactFee : WalletOutputBatchInput :=
  { stablecoinIssuanceNoInput with
    recipientTotal := 80
    fee := 10
    selectedAssetTotal := 120
    selectedNativeTotal := 10
    issuanceDelta := 20
    privateWitnessSeed := 22
    localMetadataSeed := 202 }

def stablecoinNativeChange : WalletOutputBatchInput :=
  { stablecoinIssuanceNoInput with
    recipientTotal := 100
    fee := 10
    selectedAssetTotal := 80
    selectedNativeTotal := 20
    issuanceDelta := -20
    privateWitnessSeed := 23
    localMetadataSeed := 203 }

def stablecoinAssetChangeRejectsInexactNativeFee :
    WalletOutputBatchInput :=
  { stablecoinAssetChangeExactFee with
    selectedNativeTotal := 20
    privateWitnessSeed := 24
    localMetadataSeed := 204 }

def nativeTwoRecipientOverflow : WalletOutputBatchInput :=
  { nativeExactNoChange with
    recipientCount := 2
    recipientTotal := 200
    fee := 10
    selectedAssetTotal := 300
    privateWitnessSeed := 31
    localMetadataSeed := 301 }

def burnExactNoOutput : WalletOutputBatchInput :=
  { kind := WalletOutputBatchKind.burn
    recipientCount := 0
    recipientTotal := 0
    fee := 0
    selectedAssetTotal := 100
    selectedNativeTotal := 0
    issuanceDelta := 100
    burnAmount := 100
    privateWitnessSeed := 41
    localMetadataSeed := 401 }

def burnAssetAndNativeChange : WalletOutputBatchInput :=
  { burnExactNoOutput with
    fee := 10
    selectedAssetTotal := 120
    selectedNativeTotal := 20
    privateWitnessSeed := 42
    localMetadataSeed := 402 }

def consolidationOneOutput : WalletOutputBatchInput :=
  { kind := WalletOutputBatchKind.consolidation
    recipientCount := 0
    recipientTotal := 0
    fee := 10
    selectedAssetTotal := 110
    selectedNativeTotal := 0
    issuanceDelta := 0
    burnAmount := 0
    privateWitnessSeed := 51
    localMetadataSeed := 501 }

theorem native_exact_no_change_has_one_output :
    walletOutputCount nativeExactNoChange = 1 := by
  decide

theorem native_change_has_two_outputs :
    walletOutputCount nativeWithChange = 2 := by
  decide

theorem stablecoin_issuance_no_input_has_one_output :
    walletOutputCount stablecoinIssuanceNoInput = 1 := by
  decide

theorem stablecoin_asset_change_has_two_outputs :
    walletOutputCount stablecoinAssetChangeExactFee = 2 := by
  decide

theorem stablecoin_native_change_has_two_outputs :
    walletOutputCount stablecoinNativeChange = 2 := by
  decide

theorem stablecoin_asset_change_rejects_inexact_native_fee :
    walletOutputBatchAccepts
      stablecoinAssetChangeRejectsInexactNativeFee = false := by
  decide

theorem native_two_recipient_overflow_rejected_by_max_outputs :
    walletOutputBatchAccepts nativeTwoRecipientOverflow = false := by
  decide

theorem burn_exact_has_zero_outputs :
    walletOutputCount burnExactNoOutput = 0 := by
  decide

theorem burn_asset_and_native_change_has_two_outputs :
    walletOutputCount burnAssetAndNativeChange = 2 := by
  decide

theorem consolidation_has_one_output :
    walletOutputCount consolidationOneOutput = 1 := by
  decide

end WalletOutputBatch
end Privacy
end Hegemon

import Hegemon.Transaction.AcceptedTransactionSoundness

namespace Hegemon
namespace Transaction
namespace AssetIsolation

open Hegemon.Transaction.AcceptedProofArtifact
open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SpendAuthorization

def AuthorizedAssetDelta
    (witness : BalanceWitness)
    (slots : List BalanceSlot)
    (assetId : Nat) : Prop :=
  if assetId = nativeAsset then
    slotDelta assetId slots = nativeExpected witness
  else if witness.stablecoin.enabled = true then
    if assetId = witness.stablecoin.assetId then
      slotDelta assetId slots = witness.stablecoin.issuanceDelta
    else
      slotDelta assetId slots = 0
  else
    slotDelta assetId slots = 0

theorem accepted_transaction_relation_authorized_asset_delta
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (relation :
      AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    AuthorizedAssetDelta balanceWitness slots assetId := by
  unfold AuthorizedAssetDelta
  by_cases native : assetId = nativeAsset
  · simp [native]
    exact accepted_transaction_relation_native_delta relation
  · simp [native]
    by_cases stablecoinEnabled : balanceWitness.stablecoin.enabled = true
    · simp [stablecoinEnabled]
      by_cases selected : assetId = balanceWitness.stablecoin.assetId
      · simp [selected]
        exact
          accepted_transaction_relation_stablecoin_selected_delta
            relation
            stablecoinEnabled
      · simp [selected]
        exact
          accepted_transaction_relation_stablecoin_non_selected_non_native_delta_zero
            relation
            stablecoinEnabled
            native
            selected
    · simp [stablecoinEnabled]
      have stablecoinDisabled :
          balanceWitness.stablecoin.enabled = false := by
        cases h : balanceWitness.stablecoin.enabled <;>
          simp [h] at stablecoinEnabled ⊢
      exact
        accepted_transaction_relation_no_stablecoin_non_native_delta_zero
          relation
          stablecoinDisabled
          native

theorem accepted_transaction_relation_unselected_non_native_delta_zero
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (relation :
      AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (nonNative : assetId ≠ nativeAsset)
    (notStablecoinException :
      balanceWitness.stablecoin.enabled = false
        ∨ assetId ≠ balanceWitness.stablecoin.assetId) :
    slotDelta assetId slots = 0 := by
  by_cases stablecoinEnabled : balanceWitness.stablecoin.enabled = true
  · have notSelected : assetId ≠ balanceWitness.stablecoin.assetId := by
      cases notStablecoinException with
      | inl disabled =>
          rw [stablecoinEnabled] at disabled
          contradiction
      | inr notSelected => exact notSelected
    exact
      accepted_transaction_relation_stablecoin_non_selected_non_native_delta_zero
        relation
        stablecoinEnabled
        nonNative
        notSelected
  · have stablecoinDisabled :
      balanceWitness.stablecoin.enabled = false := by
      cases h : balanceWitness.stablecoin.enabled <;>
        simp [h] at stablecoinEnabled ⊢
    exact
      accepted_transaction_relation_no_stablecoin_non_native_delta_zero
        relation
        stablecoinDisabled
        nonNative

theorem accepted_transaction_relation_only_native_or_selected_stablecoin_may_be_nonzero
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (relation :
      AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (nonNative : assetId ≠ nativeAsset)
    (nonzero : slotDelta assetId slots ≠ 0) :
    balanceWitness.stablecoin.enabled = true
      ∧ assetId = balanceWitness.stablecoin.assetId := by
  by_cases stablecoinEnabled : balanceWitness.stablecoin.enabled = true
  · by_cases selected : assetId = balanceWitness.stablecoin.assetId
    · exact ⟨stablecoinEnabled, selected⟩
    · have zero :
        slotDelta assetId slots = 0 :=
        accepted_transaction_relation_stablecoin_non_selected_non_native_delta_zero
          relation
          stablecoinEnabled
          nonNative
          selected
      exact False.elim (nonzero zero)
  · have stablecoinDisabled :
      balanceWitness.stablecoin.enabled = false := by
      cases h : balanceWitness.stablecoin.enabled <;>
        simp [h] at stablecoinEnabled ⊢
    have zero :
        slotDelta assetId slots = 0 :=
      accepted_transaction_relation_no_stablecoin_non_native_delta_zero
        relation
        stablecoinDisabled
        nonNative
    exact False.elim (nonzero zero)

theorem accepted_wrapper_implies_authorized_asset_delta
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (accepted : proofWrapperAccepts wrapper = true)
    (sound :
      AcceptedTransactionSoundnessAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    AuthorizedAssetDelta balanceWitness slots assetId :=
  accepted_transaction_relation_authorized_asset_delta
    (accepted_wrapper_implies_transaction_relation accepted sound)

theorem accepted_wrapper_only_native_or_selected_stablecoin_may_be_nonzero
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (accepted : proofWrapperAccepts wrapper = true)
    (sound :
      AcceptedTransactionSoundnessAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (nonNative : assetId ≠ nativeAsset)
    (nonzero : slotDelta assetId slots ≠ 0) :
    balanceWitness.stablecoin.enabled = true
      ∧ assetId = balanceWitness.stablecoin.assetId :=
  accepted_transaction_relation_only_native_or_selected_stablecoin_may_be_nonzero
    (accepted_wrapper_implies_transaction_relation accepted sound)
    nonNative
    nonzero

end AssetIsolation
end Transaction
end Hegemon

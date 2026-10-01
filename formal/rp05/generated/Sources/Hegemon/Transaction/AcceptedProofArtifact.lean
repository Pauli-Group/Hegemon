import Hegemon.Transaction.Balance
import Hegemon.Transaction.ProofWrapperAdmission

namespace Hegemon
namespace Transaction
namespace AcceptedProofArtifact

open Hegemon.Transaction.ProofWrapperAdmission

def BalanceSoundnessAssumption
    (wrapper : ProofWrapperInput)
    (witness : BalanceWitness)
    (slots : List BalanceSlot) : Prop :=
  proofWrapperAccepts wrapper = true ->
    balanceSlots witness = some slots ∧ validBalance witness = true

theorem accepted_proof_artifact_statement_surface
    {wrapper : ProofWrapperInput}
    (accepted : proofWrapperAccepts wrapper = true) :
    acceptedProofWrapperSurface wrapper :=
  proofWrapperAccepts_implies_statement_surface accepted

theorem accepted_proof_artifact_native_delta
    {wrapper : ProofWrapperInput}
    {witness : BalanceWitness}
    {slots : List BalanceSlot}
    (accepted : proofWrapperAccepts wrapper = true)
    (soundBalance : BalanceSoundnessAssumption wrapper witness slots) :
    slotDelta nativeAsset slots = nativeExpected witness := by
  have balanceFacts := soundBalance accepted
  exact validBalance_native_delta balanceFacts.left balanceFacts.right

theorem accepted_proof_artifact_no_stablecoin_non_native_delta_zero
    {wrapper : ProofWrapperInput}
    {witness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (accepted : proofWrapperAccepts wrapper = true)
    (soundBalance : BalanceSoundnessAssumption wrapper witness slots)
    (stablecoinDisabled : witness.stablecoin.enabled = false)
    (nonNative : assetId ≠ nativeAsset) :
    slotDelta assetId slots = 0 := by
  have balanceFacts := soundBalance accepted
  exact
    validBalance_no_stablecoin_non_native_delta_zero
      balanceFacts.left
      balanceFacts.right
      stablecoinDisabled
      nonNative

theorem accepted_proof_artifact_stablecoin_selected_delta
    {wrapper : ProofWrapperInput}
    {witness : BalanceWitness}
    {slots : List BalanceSlot}
    (accepted : proofWrapperAccepts wrapper = true)
    (soundBalance : BalanceSoundnessAssumption wrapper witness slots)
    (stablecoinEnabled : witness.stablecoin.enabled = true) :
    slotDelta witness.stablecoin.assetId slots =
      witness.stablecoin.issuanceDelta := by
  have balanceFacts := soundBalance accepted
  exact
    validBalance_stablecoin_selected_delta
      balanceFacts.left
      balanceFacts.right
      stablecoinEnabled

theorem accepted_proof_artifact_stablecoin_non_selected_non_native_delta_zero
    {wrapper : ProofWrapperInput}
    {witness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (accepted : proofWrapperAccepts wrapper = true)
    (soundBalance : BalanceSoundnessAssumption wrapper witness slots)
    (stablecoinEnabled : witness.stablecoin.enabled = true)
    (nonNative : assetId ≠ nativeAsset)
    (notStablecoin : assetId ≠ witness.stablecoin.assetId) :
    slotDelta assetId slots = 0 := by
  have balanceFacts := soundBalance accepted
  exact
    validBalance_stablecoin_non_selected_non_native_delta_zero
      balanceFacts.left
      balanceFacts.right
      stablecoinEnabled
      nonNative
      notStablecoin

end AcceptedProofArtifact
end Transaction
end Hegemon

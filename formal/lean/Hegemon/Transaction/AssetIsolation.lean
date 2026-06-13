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

def authorizedAssetDeltaValue
    (witness : BalanceWitness)
    (assetId : Nat) : Int :=
  if assetId = nativeAsset then
    nativeExpected witness
  else if witness.stablecoin.enabled = true then
    if assetId = witness.stablecoin.assetId then
      witness.stablecoin.issuanceDelta
    else
      0
  else
    0

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

theorem accepted_transaction_relation_authorized_asset_delta_value
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
    slotDelta assetId slots =
      authorizedAssetDeltaValue balanceWitness assetId := by
  unfold authorizedAssetDeltaValue
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

structure AcceptedAssetTransition where
  wrapper : ProofWrapperInput
  shape : PublicInputShape
  merkleRoot : Digest
  spendWitnesses : List InputSpendWitness
  balanceWitness : BalanceWitness
  slots : List BalanceSlot
  relation :
    AcceptedTransactionRelation
      wrapper
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots

def acceptedTransitionDelta
    (assetId : Nat)
    (transition : AcceptedAssetTransition) : Int :=
  slotDelta assetId transition.slots

def acceptedTransitionAuthorizedDelta
    (assetId : Nat)
    (transition : AcceptedAssetTransition) : Int :=
  authorizedAssetDeltaValue transition.balanceWitness assetId

def acceptedChainAssetDelta
    (assetId : Nat) :
    List AcceptedAssetTransition -> Int
  | [] => 0
  | transition :: rest =>
      acceptedTransitionDelta assetId transition
        + acceptedChainAssetDelta assetId rest

def acceptedChainAuthorizedAssetDelta
    (assetId : Nat) :
    List AcceptedAssetTransition -> Int
  | [] => 0
  | transition :: rest =>
      acceptedTransitionAuthorizedDelta assetId transition
        + acceptedChainAuthorizedAssetDelta assetId rest

def transitionHasStablecoinException
    (assetId : Nat)
    (transition : AcceptedAssetTransition) : Prop :=
  transition.balanceWitness.stablecoin.enabled = true
    ∧ assetId = transition.balanceWitness.stablecoin.assetId

theorem accepted_transition_delta_authorized
    {assetId : Nat}
    {transition : AcceptedAssetTransition} :
    acceptedTransitionDelta assetId transition =
      acceptedTransitionAuthorizedDelta assetId transition := by
  exact
    accepted_transaction_relation_authorized_asset_delta_value
      transition.relation

theorem accepted_chain_asset_delta_authorized
    {assetId : Nat}
    {transitions : List AcceptedAssetTransition} :
    acceptedChainAssetDelta assetId transitions =
      acceptedChainAuthorizedAssetDelta assetId transitions := by
  induction transitions with
  | nil =>
      rfl
  | cons transition rest ih =>
      simp [
        acceptedChainAssetDelta,
        acceptedChainAuthorizedAssetDelta,
        accepted_transition_delta_authorized,
        ih
      ]

theorem accepted_chain_non_native_no_exception_delta_zero
    {assetId : Nat}
    {transitions : List AcceptedAssetTransition}
    (nonNative : assetId ≠ nativeAsset)
    (noException :
      ∀ transition,
        transition ∈ transitions ->
          ¬ transitionHasStablecoinException assetId transition) :
    acceptedChainAssetDelta assetId transitions = 0 := by
  induction transitions with
  | nil =>
      rfl
  | cons transition rest ih =>
      have headNoException :
          ¬ transitionHasStablecoinException assetId transition := by
        exact noException transition (by simp)
      have restNoException :
          ∀ transition,
            transition ∈ rest ->
              ¬ transitionHasStablecoinException assetId transition := by
        intro transitionInRest member
        exact noException transitionInRest (by simp [member])
      have headNotStablecoinException :
          transition.balanceWitness.stablecoin.enabled = false
            ∨ assetId ≠ transition.balanceWitness.stablecoin.assetId := by
        by_cases enabled :
            transition.balanceWitness.stablecoin.enabled = true
        · right
          intro selected
          exact headNoException ⟨enabled, selected⟩
        · left
          cases h : transition.balanceWitness.stablecoin.enabled <;>
            simp [h] at enabled ⊢
      have headZero :
          acceptedTransitionDelta assetId transition = 0 := by
        exact
          accepted_transaction_relation_unselected_non_native_delta_zero
            transition.relation
            nonNative
            headNotStablecoinException
      have restZero :
          acceptedChainAssetDelta assetId rest = 0 :=
        ih restNoException
      simp [acceptedChainAssetDelta, headZero, restZero]

theorem accepted_chain_non_native_nonzero_requires_exception
    {assetId : Nat}
    {transitions : List AcceptedAssetTransition}
    (nonNative : assetId ≠ nativeAsset)
    (nonzero : acceptedChainAssetDelta assetId transitions ≠ 0) :
    ∃ transition,
      transition ∈ transitions
        ∧ transitionHasStablecoinException assetId transition := by
  exact Classical.byContradiction fun noWitness =>
    have noException :
        ∀ transition,
          transition ∈ transitions ->
            ¬ transitionHasStablecoinException assetId transition := by
      intro transition member exception
      exact noWitness ⟨transition, member, exception⟩
    nonzero
      (accepted_chain_non_native_no_exception_delta_zero
        nonNative
        noException)

end AssetIsolation
end Transaction
end Hegemon

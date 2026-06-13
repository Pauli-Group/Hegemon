import Hegemon.Transaction.AcceptedProofArtifact
import Hegemon.Transaction.SpendAuthorization

namespace Hegemon
namespace Transaction
namespace AcceptedTransactionSoundness

open Hegemon.Transaction.AcceptedProofArtifact
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SpendAuthorization

def AcceptedTransactionRelation
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop :=
  proofWrapperAccepts wrapper = true
    ∧ acceptedProofWrapperSurface wrapper
    ∧ balanceSlots balanceWitness = some slots
    ∧ validBalance balanceWitness = true
    ∧ validPublicInputShape shape = true
    ∧ authorizeInputSlots
      merkleRoot
      shape.inputFlags
      shape.nullifiers
      spendWitnesses = true

def AcceptedTransactionSoundnessAssumption
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop :=
  proofWrapperAccepts wrapper = true ->
    BalanceSoundnessAssumption wrapper balanceWitness slots
      ∧ SpendAuthorizationSoundnessAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses

theorem accepted_wrapper_implies_transaction_relation
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (accepted : proofWrapperAccepts wrapper = true)
    (sound :
      AcceptedTransactionSoundnessAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    AcceptedTransactionRelation
      wrapper
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots := by
  have soundParts := sound accepted
  have balanceFacts := soundParts.left accepted
  have spendAuthorized := soundParts.right accepted
  exact
    ⟨accepted,
      proofWrapperAccepts_implies_statement_surface accepted,
      balanceFacts.left,
      balanceFacts.right,
      transactionSpendAuthorized_implies_public_shape_valid spendAuthorized,
      transactionSpendAuthorized_implies_slots_authorized spendAuthorized⟩

theorem accepted_transaction_relation_statement_surface
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (relation :
      AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    acceptedProofWrapperSurface wrapper :=
  relation.right.left

theorem accepted_transaction_relation_native_delta
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (relation :
      AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    slotDelta nativeAsset slots = nativeExpected balanceWitness := by
  exact
    validBalance_native_delta
      relation.right.right.left
      relation.right.right.right.left

theorem accepted_transaction_relation_no_stablecoin_non_native_delta_zero
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
    (stablecoinDisabled : balanceWitness.stablecoin.enabled = false)
    (nonNative : assetId ≠ nativeAsset) :
    slotDelta assetId slots = 0 := by
  exact
    validBalance_no_stablecoin_non_native_delta_zero
      relation.right.right.left
      relation.right.right.right.left
      stablecoinDisabled
      nonNative

theorem accepted_transaction_relation_stablecoin_selected_delta
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (relation :
      AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (stablecoinEnabled : balanceWitness.stablecoin.enabled = true) :
    slotDelta balanceWitness.stablecoin.assetId slots =
      balanceWitness.stablecoin.issuanceDelta := by
  exact
    validBalance_stablecoin_selected_delta
      relation.right.right.left
      relation.right.right.right.left
      stablecoinEnabled

theorem accepted_transaction_relation_stablecoin_non_selected_non_native_delta_zero
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
    (stablecoinEnabled : balanceWitness.stablecoin.enabled = true)
    (nonNative : assetId ≠ nativeAsset)
    (notStablecoin : assetId ≠ balanceWitness.stablecoin.assetId) :
    slotDelta assetId slots = 0 := by
  exact
    validBalance_stablecoin_non_selected_non_native_delta_zero
      relation.right.right.left
      relation.right.right.right.left
      stablecoinEnabled
      nonNative
      notStablecoin

theorem accepted_transaction_relation_head_active_input_facts
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot flag publicNullifier : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {witness : InputSpendWitness}
    {spendWitnesses tailWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (relation :
      AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (shapeFlags : shape.inputFlags = flag :: flags)
    (shapeNullifiers : shape.nullifiers = publicNullifier :: nullifiers)
    (witnessShape : spendWitnesses = witness :: tailWitnesses)
    (active : flag = 1) :
    InputSpendFacts merkleRoot publicNullifier witness := by
  have slotsAuthorized := relation.right.right.right.right.right
  rw [shapeFlags, shapeNullifiers, witnessShape] at slotsAuthorized
  exact authorizeInputSlots_head_active_facts active slotsAuthorized

theorem accepted_transaction_relation_active_input_facts_at
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : InputSpendWitness}
    (relation :
      AcceptedTransactionRelation
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots)
    (slot :
      ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
    InputSpendFacts merkleRoot publicNullifier witness := by
  exact
    authorizeInputSlots_active_input_facts_at
      slot
      active
      relation.right.right.right.right.right

theorem accepted_wrapper_implies_head_active_input_facts
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot flag publicNullifier : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {witness : InputSpendWitness}
    {spendWitnesses tailWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (shapeFlags : shape.inputFlags = flag :: flags)
    (shapeNullifiers : shape.nullifiers = publicNullifier :: nullifiers)
    (witnessShape : spendWitnesses = witness :: tailWitnesses)
    (active : flag = 1)
    (accepted : proofWrapperAccepts wrapper = true)
    (sound :
      AcceptedTransactionSoundnessAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    InputSpendFacts merkleRoot publicNullifier witness := by
  exact
    accepted_transaction_relation_head_active_input_facts
      (accepted_wrapper_implies_transaction_relation accepted sound)
      shapeFlags
      shapeNullifiers
      witnessShape
      active

theorem accepted_wrapper_implies_active_input_facts_at
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : InputSpendWitness}
    (slot :
      ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1)
    (accepted : proofWrapperAccepts wrapper = true)
    (sound :
      AcceptedTransactionSoundnessAssumption
        wrapper
        shape
        merkleRoot
        spendWitnesses
        balanceWitness
        slots) :
    InputSpendFacts merkleRoot publicNullifier witness := by
  exact
    accepted_transaction_relation_active_input_facts_at
      (accepted_wrapper_implies_transaction_relation accepted sound)
      slot
      active

end AcceptedTransactionSoundness
end Transaction
end Hegemon

import Hegemon.Transaction.MerklePath
import Hegemon.Transaction.ProofWrapperAdmission
import Hegemon.Transaction.PublicInputs

set_option maxRecDepth 20000

namespace Hegemon
namespace Transaction
namespace SpendAuthorization

open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

def authDigestMod : Nat := 65537

def natEq (left right : Nat) : Bool :=
  if left = right then true else false

theorem natEq_true_eq {left right : Nat} :
    natEq left right = true -> left = right := by
  unfold natEq
  split
  · intro _
    assumption
  · intro impossible
    cases impossible

structure InputSpendWitness where
  value : Nat
  assetId : Nat
  recipientKey : Digest
  authorizationPublicKey : Digest
  spendSecret : Nat
  rho : Nat
  noteRandomness : Nat
  notePosition : Nat
  noteCommitment : Digest
  merkleDepth : Nat
  merkleSiblings : List Digest
deriving DecidableEq, Repr

def noteCommitmentFromWitness (witness : InputSpendWitness) : Digest :=
  (witness.value * 1315423911
    + witness.assetId * 2654435761
    + witness.recipientKey * 97531
    + witness.authorizationPublicKey * 314159
    + witness.rho * 271828
    + witness.noteRandomness * 65537
    + 97) % authDigestMod

def authorizationPublicKeyFromSecret (secret : Nat) : Digest :=
  (secret * 1103515245 + 12345) % authDigestMod

def nullifierKeyFromSecret (secret : Nat) : Digest :=
  (secret * 6364136223846793005 + 1442695040888963407) % authDigestMod

def nullifierFromWitness (witness : InputSpendWitness) : Digest :=
  (nullifierKeyFromSecret witness.spendSecret
    + witness.rho * 16777619
    + witness.notePosition * 1099511628211
    + 41) % authDigestMod

def authorizedInputWitness
    (merkleRoot publicNullifier : Digest)
    (witness : InputSpendWitness) : Bool :=
  natEq (noteCommitmentFromWitness witness) witness.noteCommitment
    && natEq (authorizationPublicKeyFromSecret witness.spendSecret)
      witness.authorizationPublicKey
    && natEq (nullifierFromWitness witness) publicNullifier
    && verifyPathWithDepth
      mockMerkleNode
      witness.merkleDepth
      witness.noteCommitment
      witness.notePosition
      witness.merkleSiblings
      merkleRoot

def InputSpendFacts
    (merkleRoot publicNullifier : Digest)
    (witness : InputSpendWitness) : Prop :=
  noteCommitmentFromWitness witness = witness.noteCommitment
    ∧ authorizationPublicKeyFromSecret witness.spendSecret =
      witness.authorizationPublicKey
    ∧ nullifierFromWitness witness = publicNullifier
    ∧ verifyPathWithDepth
      mockMerkleNode
      witness.merkleDepth
      witness.noteCommitment
      witness.notePosition
      witness.merkleSiblings
      merkleRoot = true

theorem authorizedInputWitness_implies_facts
    {merkleRoot publicNullifier : Digest}
    {witness : InputSpendWitness}
    (authorized : authorizedInputWitness merkleRoot publicNullifier witness = true) :
    InputSpendFacts merkleRoot publicNullifier witness := by
  unfold authorizedInputWitness at authorized
  simp at authorized
  exact
    ⟨natEq_true_eq authorized.left.left.left,
      natEq_true_eq authorized.left.left.right,
      natEq_true_eq authorized.left.right,
      authorized.right⟩

theorem authorizedInputWitness_implies_note_commitment
    {merkleRoot publicNullifier : Digest}
    {witness : InputSpendWitness}
    (authorized : authorizedInputWitness merkleRoot publicNullifier witness = true) :
    noteCommitmentFromWitness witness = witness.noteCommitment :=
  (authorizedInputWitness_implies_facts authorized).left

theorem authorizedInputWitness_implies_spend_authority
    {merkleRoot publicNullifier : Digest}
    {witness : InputSpendWitness}
    (authorized : authorizedInputWitness merkleRoot publicNullifier witness = true) :
    authorizationPublicKeyFromSecret witness.spendSecret =
      witness.authorizationPublicKey :=
  (authorizedInputWitness_implies_facts authorized).right.left

theorem authorizedInputWitness_implies_nullifier
    {merkleRoot publicNullifier : Digest}
    {witness : InputSpendWitness}
    (authorized : authorizedInputWitness merkleRoot publicNullifier witness = true) :
    nullifierFromWitness witness = publicNullifier :=
  (authorizedInputWitness_implies_facts authorized).right.right.left

theorem authorizedInputWitness_implies_membership
    {merkleRoot publicNullifier : Digest}
    {witness : InputSpendWitness}
    (authorized : authorizedInputWitness merkleRoot publicNullifier witness = true) :
    verifyPathWithDepth
      mockMerkleNode
      witness.merkleDepth
      witness.noteCommitment
      witness.notePosition
      witness.merkleSiblings
      merkleRoot = true :=
  (authorizedInputWitness_implies_facts authorized).right.right.right

def authorizeInputSlots
    (merkleRoot : Digest) :
    List Nat -> List Digest -> List InputSpendWitness -> Bool
  | [], [], [] => true
  | flag :: flags, nullifier :: nullifiers, witness :: witnesses =>
      if flag = 0 then
        natEq nullifier 0
          && authorizeInputSlots merkleRoot flags nullifiers witnesses
      else if flag = 1 then
        authorizedInputWitness merkleRoot nullifier witness
          && authorizeInputSlots merkleRoot flags nullifiers witnesses
      else
        false
  | _, _, _ => false

def ActiveInputAt :
    List Nat -> List Digest -> List InputSpendWitness ->
      Nat -> Nat -> Digest -> InputSpendWitness -> Prop
  | flag :: _, nullifier :: _, witness :: _, 0, activeFlag, publicNullifier,
      activeWitness =>
      activeFlag = flag
        ∧ publicNullifier = nullifier
        ∧ activeWitness = witness
  | _ :: flags, _ :: nullifiers, _ :: witnesses, index + 1, activeFlag,
      publicNullifier, activeWitness =>
      ActiveInputAt
        flags
        nullifiers
        witnesses
        index
        activeFlag
        publicNullifier
        activeWitness
  | _, _, _, _, _, _, _ => False

def transactionSpendAuthorized
    (shape : PublicInputShape)
    (merkleRoot : Digest)
    (witnesses : List InputSpendWitness) : Bool :=
  validPublicInputShape shape
    && authorizeInputSlots merkleRoot shape.inputFlags shape.nullifiers witnesses

def acceptedSpendAuthorization
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (merkleRoot : Digest)
    (witnesses : List InputSpendWitness) : Prop :=
  proofWrapperAccepts wrapper = true
    ∧ validPublicInputShape shape = true
    ∧ authorizeInputSlots merkleRoot shape.inputFlags shape.nullifiers witnesses = true

def SpendAuthorizationSoundnessAssumption
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (merkleRoot : Digest)
    (witnesses : List InputSpendWitness) : Prop :=
  proofWrapperAccepts wrapper = true ->
    transactionSpendAuthorized shape merkleRoot witnesses = true

theorem transactionSpendAuthorized_implies_public_shape_valid
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {witnesses : List InputSpendWitness}
    (authorized : transactionSpendAuthorized shape merkleRoot witnesses = true) :
    validPublicInputShape shape = true := by
  unfold transactionSpendAuthorized at authorized
  simp at authorized
  exact authorized.left

theorem transactionSpendAuthorized_implies_slots_authorized
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {witnesses : List InputSpendWitness}
    (authorized : transactionSpendAuthorized shape merkleRoot witnesses = true) :
    authorizeInputSlots merkleRoot shape.inputFlags shape.nullifiers witnesses = true := by
  unfold transactionSpendAuthorized at authorized
  simp at authorized
  exact authorized.right

theorem authorizeInputSlots_head_active_authorized
    {merkleRoot flag publicNullifier : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {witness : InputSpendWitness}
    {witnesses : List InputSpendWitness}
    (active : flag = 1)
    (authorized :
      authorizeInputSlots
        merkleRoot
        (flag :: flags)
        (publicNullifier :: nullifiers)
        (witness :: witnesses) = true) :
    authorizedInputWitness merkleRoot publicNullifier witness = true := by
  unfold authorizeInputSlots at authorized
  simp [active] at authorized
  exact authorized.left

theorem authorizeInputSlots_head_active_facts
    {merkleRoot flag publicNullifier : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {witness : InputSpendWitness}
    {witnesses : List InputSpendWitness}
    (active : flag = 1)
    (authorized :
      authorizeInputSlots
        merkleRoot
        (flag :: flags)
        (publicNullifier :: nullifiers)
        (witness :: witnesses) = true) :
    InputSpendFacts merkleRoot publicNullifier witness :=
  authorizedInputWitness_implies_facts
    (authorizeInputSlots_head_active_authorized active authorized)

theorem authorizeInputSlots_head_inactive_public_nullifier_zero
    {merkleRoot flag publicNullifier : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {witness : InputSpendWitness}
    {witnesses : List InputSpendWitness}
    (inactive : flag = 0)
    (authorized :
      authorizeInputSlots
        merkleRoot
        (flag :: flags)
        (publicNullifier :: nullifiers)
        (witness :: witnesses) = true) :
    publicNullifier = 0 := by
  unfold authorizeInputSlots at authorized
  simp [inactive] at authorized
  exact natEq_true_eq authorized.left

theorem authorizeInputSlots_tail_authorized
    {merkleRoot headFlag headNullifier : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {headWitness : InputSpendWitness}
    {witnesses : List InputSpendWitness}
    (authorized :
      authorizeInputSlots
        merkleRoot
        (headFlag :: flags)
        (headNullifier :: nullifiers)
        (headWitness :: witnesses) = true) :
    authorizeInputSlots merkleRoot flags nullifiers witnesses = true := by
  unfold authorizeInputSlots at authorized
  by_cases inactive : headFlag = 0
  · simp [inactive] at authorized
    exact authorized.right
  · by_cases active : headFlag = 1
    · simp [active] at authorized
      exact authorized.right
    · simp [inactive, active] at authorized

theorem authorizeInputSlots_active_input_facts_at
    {merkleRoot : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {witnesses : List InputSpendWitness}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : InputSpendWitness}
    (slot :
      ActiveInputAt
        flags
        nullifiers
        witnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1)
    (authorized :
      authorizeInputSlots merkleRoot flags nullifiers witnesses = true) :
    InputSpendFacts merkleRoot publicNullifier witness := by
  induction flags generalizing nullifiers witnesses index activeFlag
      publicNullifier witness with
  | nil =>
      cases nullifiers <;> cases witnesses <;> cases index <;>
        simp [ActiveInputAt] at slot
  | cons headFlag tailFlags ih =>
      cases nullifiers with
      | nil =>
          cases witnesses <;> cases index <;> simp [ActiveInputAt] at slot
      | cons headNullifier tailNullifiers =>
          cases witnesses with
          | nil =>
              cases index <;> simp [ActiveInputAt] at slot
          | cons headWitness tailWitnesses =>
              cases index with
              | zero =>
                  simp [ActiveInputAt] at slot
                  cases slot.left
                  cases slot.right.left
                  cases slot.right.right
                  exact
                    authorizeInputSlots_head_active_facts
                      active
                      authorized
              | succ tailIndex =>
                  exact
                    ih
                      slot
                      active
                      (authorizeInputSlots_tail_authorized authorized)

theorem accepted_wrapper_implies_spend_authorization
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot : Digest}
    {witnesses : List InputSpendWitness}
    (accepted : proofWrapperAccepts wrapper = true)
    (soundSpend :
      SpendAuthorizationSoundnessAssumption
        wrapper
        shape
        merkleRoot
        witnesses) :
    acceptedSpendAuthorization wrapper shape merkleRoot witnesses := by
  have authorized := soundSpend accepted
  exact
    ⟨accepted,
      transactionSpendAuthorized_implies_public_shape_valid authorized,
      transactionSpendAuthorized_implies_slots_authorized authorized⟩

theorem accepted_wrapper_head_active_input_facts
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {merkleRoot flag publicNullifier : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {witness : InputSpendWitness}
    {witnesses tailWitnesses : List InputSpendWitness}
    (shapeFlags : shape.inputFlags = flag :: flags)
    (shapeNullifiers : shape.nullifiers = publicNullifier :: nullifiers)
    (witnessShape : witnesses = witness :: tailWitnesses)
    (active : flag = 1)
    (accepted : proofWrapperAccepts wrapper = true)
    (soundSpend :
      SpendAuthorizationSoundnessAssumption
        wrapper
        shape
        merkleRoot
        witnesses) :
    InputSpendFacts merkleRoot publicNullifier witness := by
  have acceptedAuth :=
    accepted_wrapper_implies_spend_authorization accepted soundSpend
  have slotsAuthorized := acceptedAuth.right.right
  rw [shapeFlags, shapeNullifiers, witnessShape] at slotsAuthorized
  exact authorizeInputSlots_head_active_facts active slotsAuthorized

def sampleWitness : InputSpendWitness :=
  let base : InputSpendWitness :=
    { value := 5
      assetId := nativeAsset
      recipientKey := 20
      authorizationPublicKey := authorizationPublicKeyFromSecret 9
      spendSecret := 9
      rho := 3
      noteRandomness := 4
      notePosition := 1
      noteCommitment := 0
      merkleDepth := 0
      merkleSiblings := [] }
  { base with noteCommitment := noteCommitmentFromWitness base }

def sampleAuthorizedShape : PublicInputShape :=
  { validShape with
    inputFlags := [1, 0]
    nullifiers := [nullifierFromWitness sampleWitness, 0] }

theorem sample_authorized_input_accepts :
    authorizedInputWitness
      sampleWitness.noteCommitment
      (nullifierFromWitness sampleWitness)
      sampleWitness = true := by
  decide

theorem sample_transaction_spend_authorized :
    transactionSpendAuthorized
      sampleAuthorizedShape
      sampleWitness.noteCommitment
      [sampleWitness,
        { sampleWitness with noteCommitment := 0, spendSecret := 0 }] = true := by
  decide

theorem active_input_wrong_secret_rejects :
    authorizedInputWitness
      sampleWitness.noteCommitment
      (nullifierFromWitness sampleWitness)
      { sampleWitness with spendSecret := sampleWitness.spendSecret + 1 } = false := by
  decide

theorem active_input_wrong_nullifier_rejects :
    authorizedInputWitness
      sampleWitness.noteCommitment
      (nullifierFromWitness sampleWitness + 1)
      sampleWitness = false := by
  decide

theorem active_input_wrong_membership_root_rejects :
    authorizedInputWitness
      (sampleWitness.noteCommitment + 1)
      (nullifierFromWitness sampleWitness)
      sampleWitness = false := by
  decide

end SpendAuthorization
end Transaction
end Hegemon

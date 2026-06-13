import Hegemon.Transaction.AcceptedTransactionSoundness
import Hegemon.Transaction.ProofStatementBinding
import Hegemon.Transaction.PublicInputBinding
import Hegemon.Transaction.StatementHash

namespace Hegemon
namespace Transaction
namespace CanonicalVerifierBoundary

open Hegemon.Transaction.AcceptedProofArtifact
open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SpendAuthorization

def stablecoinEnabledFlagMatches (flag : Nat) (enabled : Bool) : Prop :=
  (flag = 0 ∧ enabled = false) ∨ (flag = 1 ∧ enabled = true)

structure CanonicalTxStatementSurface
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : PublicInputBinding.PublicFields)
    (serializedFields : PublicInputBinding.SerializedFields)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields : ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest) : Prop where
  accepted : proofWrapperAccepts wrapper = true
  publicShape : validPublicInputShape shape = true
  publicBinding :
    PublicInputBinding.bindPublicInputs publicFields serializedFields = some bound
  relationMerkleRoot : merkleRoot = bound.merkleRoot
  shapeInputFlags : shape.inputFlags = bound.inputFlags
  shapeOutputFlags : shape.outputFlags = bound.outputFlags
  shapeBalanceSlotAssets : shape.balanceSlotAssets = bound.balanceSlotAssets
  shapeValueBalanceSign : shape.valueBalanceSign = bound.valueBalanceSign
  shapeStablecoinEnabled : shape.stablecoinEnabled = bound.stablecoinEnabled
  shapeStablecoinAsset : shape.stablecoinAsset = bound.stablecoinAsset
  shapeStablecoinIssuanceSign :
    shape.stablecoinIssuanceSign = bound.stablecoinIssuanceSign
  statementPreimage :
    StatementHash.statementPreimage statementFields = some statementBytes
  statementMerkleRoot : statementFields.merkleRootSeed = bound.merkleRoot
  statementFee : statementFields.fee = bound.fee
  statementValueBalanceSign :
    statementFields.valueBalanceSign = bound.valueBalanceSign
  statementValueBalanceMagnitude :
    statementFields.valueBalanceMagnitude = bound.valueBalanceMagnitude
  statementBalanceSlotAssetsCount :
    bound.balanceSlotAssets.length = PublicInputs.balanceSlotCount
  statementStablecoinEnabled :
    statementFields.stablecoinEnabled = bound.stablecoinEnabled
  statementStablecoinAsset :
    statementFields.stablecoinAsset = bound.stablecoinAsset
  statementStablecoinPolicyVersion :
    statementFields.stablecoinPolicyVersion = bound.stablecoinPolicyVersion
  statementStablecoinIssuanceSign :
    statementFields.stablecoinIssuanceSign = bound.stablecoinIssuanceSign
  statementStablecoinIssuanceMagnitude :
    statementFields.stablecoinIssuanceMagnitude =
      bound.stablecoinIssuanceMagnitude
  bindingMessage :
    ProofStatementBinding.bindingMessage bindingFields = some bindingBytes
  bindingAnchor : bindingFields.anchorSeed = bound.merkleRoot
  bindingFee : bindingFields.fee = bound.fee
  bindingBalanceSlotAssets :
    bindingFields.balanceSlotAssets = bound.balanceSlotAssets
  bindingStablecoinEnabled :
    stablecoinEnabledFlagMatches
      bound.stablecoinEnabled
      bindingFields.stablecoinEnabled
  bindingStablecoinAsset :
    bindingFields.stablecoinAsset = bound.stablecoinAsset
  bindingStablecoinPolicyVersion :
    bindingFields.stablecoinPolicyVersion = bound.stablecoinPolicyVersion

structure DeployedTxRelationFacts
    (shape : PublicInputShape)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop where
  balanceSlotsEq : balanceSlots balanceWitness = some slots
  validBalanceEq : validBalance balanceWitness = true
  spendAuthorized :
    transactionSpendAuthorized shape merkleRoot spendWitnesses = true

def DeployedTxVerifierSoundnessAssumption
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : PublicInputBinding.PublicFields)
    (serializedFields : PublicInputBinding.SerializedFields)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields : ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop :=
  CanonicalTxStatementSurface
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot ->
    DeployedTxRelationFacts
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots

theorem canonical_statement_surface_public_binding_valid
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot) :
    PublicInputBinding.validBinding publicFields serializedFields = true := by
  unfold PublicInputBinding.validBinding
  rw [surface.publicBinding]

theorem canonical_statement_surface_statement_length
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot) :
    statementBytes.length = StatementHash.expectedPreimageLength := by
  exact StatementHash.statementPreimage_length_of_some surface.statementPreimage

theorem canonical_statement_surface_wrapper_preconditions
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot) :
    proofWrapperPreconditions wrapper = true :=
  (accepts_iff_proof_wrapper_preconditions (input := wrapper)).mp surface.accepted

theorem canonical_statement_surface_statement_surface
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot) :
    acceptedProofWrapperSurface wrapper :=
  proofWrapperAccepts_implies_statement_surface surface.accepted

theorem canonical_statement_surface_public_shape_valid
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot) :
    validPublicInputShape shape = true :=
  surface.publicShape

theorem deployed_soundness_implies_accepted_transaction_soundness_assumption
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (sound :
      DeployedTxVerifierSoundnessAssumption
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
        slots) :
    AcceptedTransactionSoundnessAssumption
      wrapper
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots := by
  intro _accepted
  have facts := sound surface
  exact
    ⟨fun _ => ⟨facts.balanceSlotsEq, facts.validBalanceEq⟩,
      fun _ => facts.spendAuthorized⟩

theorem accepted_wrapper_and_canonical_statement_implies_transaction_relation
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (sound :
      DeployedTxVerifierSoundnessAssumption
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
        slots) :
    AcceptedTransactionRelation
      wrapper
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots :=
  accepted_wrapper_implies_transaction_relation
    surface.accepted
    (deployed_soundness_implies_accepted_transaction_soundness_assumption
      surface
      sound)

theorem canonical_statement_implies_native_delta
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (sound :
      DeployedTxVerifierSoundnessAssumption
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
        slots) :
    slotDelta Hegemon.Transaction.nativeAsset slots = nativeExpected balanceWitness :=
  accepted_transaction_relation_native_delta
    (accepted_wrapper_and_canonical_statement_implies_transaction_relation
      surface
      sound)

theorem canonical_statement_implies_head_active_input_facts
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : PublicInputBinding.PublicFields}
    {serializedFields : PublicInputBinding.SerializedFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot flag publicNullifier : Digest}
    {flags : List Nat}
    {nullifiers : List Digest}
    {witness : InputSpendWitness}
    {spendWitnesses tailWitnesses : List InputSpendWitness}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    (surface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (sound :
      DeployedTxVerifierSoundnessAssumption
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
    (shapeFlags : shape.inputFlags = flag :: flags)
    (shapeNullifiers : shape.nullifiers = publicNullifier :: nullifiers)
    (witnessShape : spendWitnesses = witness :: tailWitnesses)
    (active : flag = 1) :
    InputSpendFacts merkleRoot publicNullifier witness :=
  accepted_transaction_relation_head_active_input_facts
    (accepted_wrapper_and_canonical_statement_implies_transaction_relation
      surface
      sound)
    shapeFlags
    shapeNullifiers
    witnessShape
    active

end CanonicalVerifierBoundary
end Transaction
end Hegemon

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
  shapeNullifiers : shape.nullifiers = statementFields.nullifierSeeds
  shapeCommitments : shape.commitments = statementFields.commitmentSeeds
  shapeCiphertextHashes :
    shape.ciphertextHashes = statementFields.ciphertextHashSeeds
  shapeBalanceSlotAssets : shape.balanceSlotAssets = bound.balanceSlotAssets
  shapeValueBalanceSign : shape.valueBalanceSign = bound.valueBalanceSign
  shapeStablecoinEnabled : shape.stablecoinEnabled = bound.stablecoinEnabled
  shapeStablecoinAsset : shape.stablecoinAsset = bound.stablecoinAsset
  shapeStablecoinIssuanceSign :
    shape.stablecoinIssuanceSign = bound.stablecoinIssuanceSign
  statementPreimage :
    StatementHash.statementPreimage statementFields = some statementBytes
  statementMerkleRoot : statementFields.merkleRootSeed = bound.merkleRoot
  bindingNullifiers :
    bindingFields.nullifierSeeds = statementFields.nullifierSeeds
  bindingCommitments :
    bindingFields.commitmentSeeds = statementFields.commitmentSeeds
  bindingCiphertextHashes :
    bindingFields.ciphertextHashSeeds = statementFields.ciphertextHashSeeds
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
  statementStablecoinPolicyHash :
    statementFields.stablecoinPolicyHashSeed = bound.stablecoinPolicyHash
  statementStablecoinOracleCommitment :
    statementFields.stablecoinOracleCommitmentSeed =
      bound.stablecoinOracleCommitment
  statementStablecoinAttestationCommitment :
    statementFields.stablecoinAttestationCommitmentSeed =
      bound.stablecoinAttestationCommitment
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
  bindingValueBalance :
    PublicInputBinding.signedMagnitudeMatches
      bindingFields.valueBalance
      bound.valueBalanceSign
      bound.valueBalanceMagnitude = true
  bindingBalanceSlotAssets :
    bindingFields.balanceSlotAssets = bound.balanceSlotAssets
  bindingStablecoinEnabled :
    stablecoinEnabledFlagMatches
      bound.stablecoinEnabled
      bindingFields.stablecoinEnabled
  bindingStablecoinAsset :
    bindingFields.stablecoinAsset = bound.stablecoinAsset
  bindingStablecoinPolicyHash :
    bindingFields.stablecoinPolicyHashSeed = bound.stablecoinPolicyHash
  bindingStablecoinOracleCommitment :
    bindingFields.stablecoinOracleCommitmentSeed =
      bound.stablecoinOracleCommitment
  bindingStablecoinAttestationCommitment :
    bindingFields.stablecoinAttestationCommitmentSeed =
      bound.stablecoinAttestationCommitment
  bindingStablecoinIssuanceDelta :
    PublicInputBinding.signedMagnitudeMatches
      bindingFields.stablecoinIssuanceDelta
      bound.stablecoinIssuanceSign
      bound.stablecoinIssuanceMagnitude = true
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

theorem canonical_statement_surface_vectors_bound
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
    shape.nullifiers = statementFields.nullifierSeeds
      ∧ shape.commitments = statementFields.commitmentSeeds
      ∧ shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.nullifierSeeds = statementFields.nullifierSeeds
      ∧ bindingFields.commitmentSeeds = statementFields.commitmentSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds :=
  ⟨surface.shapeNullifiers,
    surface.shapeCommitments,
    surface.shapeCiphertextHashes,
    surface.bindingNullifiers,
    surface.bindingCommitments,
    surface.bindingCiphertextHashes⟩

theorem canonical_statement_surface_value_balance_bound
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
    statementFields.valueBalanceSign = bound.valueBalanceSign
      ∧ statementFields.valueBalanceMagnitude = bound.valueBalanceMagnitude
      ∧ PublicInputBinding.signedMagnitudeMatches
        bindingFields.valueBalance
        bound.valueBalanceSign
        bound.valueBalanceMagnitude = true :=
  ⟨surface.statementValueBalanceSign,
    surface.statementValueBalanceMagnitude,
    surface.bindingValueBalance⟩

theorem canonical_statement_surface_stablecoin_payload_bound
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
    statementFields.stablecoinPolicyHashSeed = bound.stablecoinPolicyHash
      ∧ statementFields.stablecoinOracleCommitmentSeed =
        bound.stablecoinOracleCommitment
      ∧ statementFields.stablecoinAttestationCommitmentSeed =
        bound.stablecoinAttestationCommitment
      ∧ bindingFields.stablecoinPolicyHashSeed = bound.stablecoinPolicyHash
      ∧ bindingFields.stablecoinOracleCommitmentSeed =
        bound.stablecoinOracleCommitment
      ∧ bindingFields.stablecoinAttestationCommitmentSeed =
        bound.stablecoinAttestationCommitment
      ∧ PublicInputBinding.signedMagnitudeMatches
        bindingFields.stablecoinIssuanceDelta
        bound.stablecoinIssuanceSign
        bound.stablecoinIssuanceMagnitude = true :=
  ⟨surface.statementStablecoinPolicyHash,
    surface.statementStablecoinOracleCommitment,
    surface.statementStablecoinAttestationCommitment,
    surface.bindingStablecoinPolicyHash,
    surface.bindingStablecoinOracleCommitment,
    surface.bindingStablecoinAttestationCommitment,
    surface.bindingStablecoinIssuanceDelta⟩

theorem canonical_surface_authorized_active_input_bound_to_statement
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
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : InputSpendWitness}
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
    (authorized :
      transactionSpendAuthorized shape merkleRoot spendWitnesses = true)
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
    InputSpendFacts merkleRoot publicNullifier witness
      ∧ statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
      ∧ ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness := by
  have slotsAuthorized :=
    transactionSpendAuthorized_implies_slots_authorized authorized
  have facts :=
    authorizeInputSlots_active_input_facts_at
      slot
      active
      slotsAuthorized
  have statementRoot : statementFields.merkleRootSeed = merkleRoot := by
    rw [surface.statementMerkleRoot, ← surface.relationMerkleRoot]
  have bindingRoot : bindingFields.anchorSeed = merkleRoot := by
    rw [surface.bindingAnchor, ← surface.relationMerkleRoot]
  have slotStatement :
      ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness := by
    rw [← surface.shapeInputFlags, ← surface.shapeNullifiers]
    exact slot
  have slotBinding :
      ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness := by
    rw [← surface.shapeInputFlags, surface.bindingNullifiers,
      ← surface.shapeNullifiers]
    exact slot
  exact ⟨facts, statementRoot, bindingRoot, slotStatement, slotBinding⟩

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

theorem canonical_statement_implies_active_input_facts_at
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
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : InputSpendWitness}
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
    InputSpendFacts merkleRoot publicNullifier witness :=
  accepted_transaction_relation_active_input_facts_at
    (accepted_wrapper_and_canonical_statement_implies_transaction_relation
      surface
      sound)
    slot
    active

end CanonicalVerifierBoundary
end Transaction
end Hegemon

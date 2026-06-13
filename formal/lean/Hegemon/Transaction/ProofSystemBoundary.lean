import Hegemon.Transaction.CanonicalVerifierBoundary

namespace Hegemon
namespace Transaction
namespace ProofSystemBoundary

open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SpendAuthorization

structure CanonicalDeployedVerifierBoundaryFacts
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
    (slots : List BalanceSlot) : Prop where
  deployedRelationFacts :
    DeployedTxRelationFacts
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots
  acceptedTransactionRelation :
    AcceptedTransactionRelation
      wrapper
      shape
      merkleRoot
      spendWitnesses
      balanceWitness
      slots
  wrapperPreconditions : proofWrapperPreconditions wrapper = true
  publicBindingValid :
    PublicInputBinding.validBinding publicFields serializedFields = true
  publicShapeValid : validPublicInputShape shape = true
  statementLength :
    statementBytes.length = StatementHash.expectedPreimageLength
  statementPreimage :
    StatementHash.statementPreimage statementFields = some statementBytes
  bindingMessage :
    ProofStatementBinding.bindingMessage bindingFields = some bindingBytes
  coreStatementBinding :
    CanonicalStatementCoreBinding
      shape
      bound
      statementFields
      bindingFields
      merkleRoot
  vectorBinding :
    shape.nullifiers = statementFields.nullifierSeeds
      ∧ shape.commitments = statementFields.commitmentSeeds
      ∧ shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.nullifierSeeds = statementFields.nullifierSeeds
      ∧ bindingFields.commitmentSeeds = statementFields.commitmentSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds
  inputVectorBinding :
    shape.inputFlags = bound.inputFlags
      ∧ shape.nullifiers = statementFields.nullifierSeeds
      ∧ bindingFields.nullifierSeeds = statementFields.nullifierSeeds
  outputVectorBinding :
    shape.outputFlags = bound.outputFlags
      ∧ shape.commitments = statementFields.commitmentSeeds
      ∧ shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.commitmentSeeds = statementFields.commitmentSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds
  valueBalanceBinding :
    statementFields.valueBalanceSign = bound.valueBalanceSign
      ∧ statementFields.valueBalanceMagnitude = bound.valueBalanceMagnitude
      ∧ PublicInputBinding.signedMagnitudeMatches
        bindingFields.valueBalance
        bound.valueBalanceSign
        bound.valueBalanceMagnitude = true
  stablecoinPayloadBinding :
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
        bound.stablecoinIssuanceMagnitude = true

theorem deployed_soundness_canonical_surface_implies_boundary_facts
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
    CanonicalDeployedVerifierBoundaryFacts
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
      slots where
  deployedRelationFacts := sound surface
  acceptedTransactionRelation :=
    accepted_wrapper_and_canonical_statement_implies_transaction_relation
      surface
      sound
  wrapperPreconditions :=
    canonical_statement_surface_wrapper_preconditions surface
  publicBindingValid :=
    canonical_statement_surface_public_binding_valid surface
  publicShapeValid :=
    canonical_statement_surface_public_shape_valid surface
  statementLength :=
    canonical_statement_surface_statement_length surface
  statementPreimage := surface.statementPreimage
  bindingMessage := surface.bindingMessage
  coreStatementBinding :=
    canonical_statement_surface_core_binding surface
  vectorBinding :=
    canonical_statement_surface_vectors_bound surface
  inputVectorBinding :=
    canonical_statement_surface_input_vectors_bound surface
  outputVectorBinding :=
    canonical_statement_surface_output_vectors_bound surface
  valueBalanceBinding :=
    canonical_statement_surface_value_balance_bound surface
  stablecoinPayloadBinding :=
    canonical_statement_surface_stablecoin_payload_bound surface

theorem canonical_boundary_facts_expose_spend_and_balance
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
    (facts :
      CanonicalDeployedVerifierBoundaryFacts
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
    balanceSlots balanceWitness = some slots
      ∧ validBalance balanceWitness = true
      ∧ transactionSpendAuthorized shape merkleRoot spendWitnesses = true :=
  ⟨facts.deployedRelationFacts.balanceSlotsEq,
    facts.deployedRelationFacts.validBalanceEq,
    facts.deployedRelationFacts.spendAuthorized⟩

theorem canonical_boundary_facts_core_statement_binding
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
    (facts :
      CanonicalDeployedVerifierBoundaryFacts
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
    CanonicalStatementCoreBinding
      shape
      bound
      statementFields
      bindingFields
      merkleRoot :=
  facts.coreStatementBinding

theorem canonical_boundary_facts_input_slot_bound_to_statement
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
    (facts :
      CanonicalDeployedVerifierBoundaryFacts
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
        witness) :
    InputSlotAuthorizationFacts
        merkleRoot
        activeFlag
        publicNullifier
        witness
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
  have slotFacts :=
    transactionSpendAuthorized_input_slot_facts_at
      facts.deployedRelationFacts.spendAuthorized
      slot
  have statementRoot : statementFields.merkleRootSeed = merkleRoot := by
    rw [facts.coreStatementBinding.statementRoot,
      ← facts.coreStatementBinding.relationRoot]
  have bindingRoot : bindingFields.anchorSeed = merkleRoot := by
    rw [facts.coreStatementBinding.bindingAnchor,
      ← facts.coreStatementBinding.relationRoot]
  rcases facts.inputVectorBinding with
    ⟨shapeFlags, shapeNullifiers, bindingNullifiers⟩
  have slotStatement :
      ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness := by
    rw [← shapeFlags, ← shapeNullifiers]
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
    rw [← shapeFlags, bindingNullifiers, ← shapeNullifiers]
    exact slot
  exact
    ⟨slotFacts, statementRoot, bindingRoot, slotStatement, slotBinding⟩

theorem canonical_boundary_facts_output_slot_bound_to_statement
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
    {publicCommitment publicCiphertextHash : Digest}
    (facts :
      CanonicalDeployedVerifierBoundaryFacts
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
      OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        activeFlag
        publicCommitment
        publicCiphertextHash) :
    OutputSlotFacts
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ OutputSlotAt
        bound.outputFlags
        statementFields.commitmentSeeds
        statementFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ OutputSlotAt
        bound.outputFlags
        bindingFields.commitmentSeeds
        bindingFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash := by
  have slotFacts :=
    validPublicInputShape_output_slot_facts_at
      facts.publicShapeValid
      slot
  rcases facts.outputVectorBinding with
    ⟨shapeFlags,
      shapeCommitments,
      shapeCiphertextHashes,
      bindingCommitments,
      bindingCiphertextHashes⟩
  have slotStatement :
      OutputSlotAt
        bound.outputFlags
        statementFields.commitmentSeeds
        statementFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash := by
    rw [← shapeFlags, ← shapeCommitments, ← shapeCiphertextHashes]
    exact slot
  have slotBinding :
      OutputSlotAt
        bound.outputFlags
        bindingFields.commitmentSeeds
        bindingFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash := by
    rw [← shapeFlags, bindingCommitments, bindingCiphertextHashes,
      ← shapeCommitments, ← shapeCiphertextHashes]
    exact slot
  exact ⟨slotFacts, slotStatement, slotBinding⟩

theorem deployed_soundness_canonical_surface_exposes_spend_and_balance
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
    balanceSlots balanceWitness = some slots
      ∧ validBalance balanceWitness = true
      ∧ transactionSpendAuthorized shape merkleRoot spendWitnesses = true :=
  canonical_boundary_facts_expose_spend_and_balance
    (deployed_soundness_canonical_surface_implies_boundary_facts
      surface
      sound)

end ProofSystemBoundary
end Transaction
end Hegemon

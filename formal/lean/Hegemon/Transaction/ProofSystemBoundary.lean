import Hegemon.Transaction.AssetIsolation
import Hegemon.Transaction.CanonicalVerifierBoundary

namespace Hegemon
namespace Transaction
namespace ProofSystemBoundary

open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.AssetIsolation
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

structure CanonicalDeployedVerifierSpendBoundaryFacts
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
    (spendWitnesses : List InputSpendWitness) : Prop where
  spendAuthorized :
    transactionSpendAuthorized shape merkleRoot spendWitnesses = true
  inputSlotsAuthorized :
    authorizeInputSlots merkleRoot shape.inputFlags shape.nullifiers
      spendWitnesses = true
  spendWitnessesAlign :
    shape.inputFlags.length = shape.nullifiers.length
      ∧ shape.inputFlags.length = spendWitnesses.length
  wrapperPreconditions : proofWrapperPreconditions wrapper = true
  wrapperSurface : acceptedProofWrapperSurface wrapper
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
  inputVectorBinding :
    shape.inputFlags = bound.inputFlags
      ∧ shape.nullifiers = statementFields.nullifierSeeds
      ∧ bindingFields.nullifierSeeds = statementFields.nullifierSeeds

structure CanonicalDeployedVerifierBalancePublicBoundaryFacts
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
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop where
  balancePublicFacts :
    DeployedTxBalancePublicFieldFacts
      publicFields
      balanceWitness
      slots
  balanceSlotsEq : balanceSlots balanceWitness = some slots
  validBalanceEq : validBalance balanceWitness = true
  publicFieldFacts :
    BalancePublicFieldFacts
      publicFields
      balanceWitness
  authorizedPublicDeltaValue :
    ∀ {assetId : Nat},
      slotDelta assetId slots =
        publicAuthorizedAssetDeltaValue publicFields assetId
  wrapperPreconditions : proofWrapperPreconditions wrapper = true
  wrapperSurface : acceptedProofWrapperSurface wrapper
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

structure CanonicalDeployedVerifierInputSlotBoundaryFacts
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
    (slots : List BalanceSlot)
    (index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : InputSpendWitness) : Prop where
  boundaryFacts :
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
      slots
  inputSlotFacts :
    InputSlotAuthorizationFacts
      merkleRoot
      activeFlag
      publicNullifier
      witness
  statementRootBinding : statementFields.merkleRootSeed = merkleRoot
  bindingRootBinding : bindingFields.anchorSeed = merkleRoot
  statementSlot :
    ActiveInputAt
      bound.inputFlags
      statementFields.nullifierSeeds
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
  bindingSlot :
    ActiveInputAt
      bound.inputFlags
      bindingFields.nullifierSeeds
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness

structure CanonicalDeployedVerifierSpendInputSlotBoundaryFacts
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
    (index activeFlag : Nat)
    (publicNullifier : Digest)
    (witness : InputSpendWitness) : Prop where
  spendBoundaryFacts :
    CanonicalDeployedVerifierSpendBoundaryFacts
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
  inputSlotFacts :
    InputSlotAuthorizationFacts
      merkleRoot
      activeFlag
      publicNullifier
      witness
  statementRootBinding : statementFields.merkleRootSeed = merkleRoot
  bindingRootBinding : bindingFields.anchorSeed = merkleRoot
  statementSlot :
    ActiveInputAt
      bound.inputFlags
      statementFields.nullifierSeeds
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness
  bindingSlot :
    ActiveInputAt
      bound.inputFlags
      bindingFields.nullifierSeeds
      spendWitnesses
      index
      activeFlag
      publicNullifier
      witness

structure CanonicalDeployedVerifierOutputSlotBoundaryFacts
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
    (slots : List BalanceSlot)
    (index activeFlag : Nat)
    (publicCommitment publicCiphertextHash : Digest) : Prop where
  boundaryFacts :
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
      slots
  outputSlotFacts :
    OutputSlotFacts
      activeFlag
      publicCommitment
      publicCiphertextHash
  statementSlot :
    OutputSlotAt
      bound.outputFlags
      statementFields.commitmentSeeds
      statementFields.ciphertextHashSeeds
      index
      activeFlag
      publicCommitment
      publicCiphertextHash
  bindingSlot :
    OutputSlotAt
      bound.outputFlags
      bindingFields.commitmentSeeds
      bindingFields.ciphertextHashSeeds
      index
      activeFlag
      publicCommitment
      publicCiphertextHash

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

theorem spend_soundness_canonical_surface_implies_spend_boundary_facts
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
    (spendSound :
      DeployedTxVerifierSpendSoundnessAssumption
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
        spendWitnesses) :
    CanonicalDeployedVerifierSpendBoundaryFacts
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
      spendWitnesses := by
  have authorized := spendSound surface
  exact
    {
      spendAuthorized := authorized,
      inputSlotsAuthorized :=
        transactionSpendAuthorized_implies_slots_authorized authorized,
      spendWitnessesAlign :=
        transactionSpendAuthorized_witnesses_align_with_public_inputs
          authorized,
      wrapperPreconditions :=
        canonical_statement_surface_wrapper_preconditions surface,
      wrapperSurface :=
        canonical_statement_surface_statement_surface surface,
      publicBindingValid :=
        canonical_statement_surface_public_binding_valid surface,
      publicShapeValid :=
        canonical_statement_surface_public_shape_valid surface,
      statementLength :=
        canonical_statement_surface_statement_length surface,
      statementPreimage := surface.statementPreimage,
      bindingMessage := surface.bindingMessage,
      coreStatementBinding :=
        canonical_statement_surface_core_binding surface,
      inputVectorBinding :=
        canonical_statement_surface_input_vectors_bound surface
    }

theorem balance_public_soundness_canonical_surface_implies_balance_public_boundary_facts
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
    (balanceSound :
      DeployedTxVerifierBalancePublicFieldSoundnessAssumption
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
        balanceWitness
        slots) :
    CanonicalDeployedVerifierBalancePublicBoundaryFacts
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
      balanceWitness
      slots := by
  have balanceFacts := balanceSound surface
  exact
    {
      balancePublicFacts := balanceFacts,
      balanceSlotsEq := balanceFacts.balanceSlotsEq,
      validBalanceEq := balanceFacts.validBalanceEq,
      publicFieldFacts := balanceFacts.publicFields,
      authorizedPublicDeltaValue := by
        intro assetId
        exact
          balance_public_field_facts_authorized_asset_delta_value
            balanceFacts.balanceSlotsEq
            balanceFacts.validBalanceEq
            balanceFacts.publicFields,
      wrapperPreconditions :=
        canonical_statement_surface_wrapper_preconditions surface,
      wrapperSurface :=
        canonical_statement_surface_statement_surface surface,
      publicBindingValid :=
        canonical_statement_surface_public_binding_valid surface,
      publicShapeValid :=
        canonical_statement_surface_public_shape_valid surface,
      statementLength :=
        canonical_statement_surface_statement_length surface,
      statementPreimage := surface.statementPreimage,
      bindingMessage := surface.bindingMessage,
      coreStatementBinding :=
        canonical_statement_surface_core_binding surface,
      outputVectorBinding :=
        canonical_statement_surface_output_vectors_bound surface,
      valueBalanceBinding :=
        canonical_statement_surface_value_balance_bound surface,
      stablecoinPayloadBinding :=
        canonical_statement_surface_stablecoin_payload_bound surface
    }

theorem canonical_split_boundary_facts_imply_full_boundary_facts
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
    (spendFacts :
      CanonicalDeployedVerifierSpendBoundaryFacts
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
        spendWitnesses)
    (balanceFacts :
      CanonicalDeployedVerifierBalancePublicBoundaryFacts
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
      slots := by
  rcases spendFacts.inputVectorBinding with
    ⟨_shapeFlags, shapeNullifiers, bindingNullifiers⟩
  rcases balanceFacts.outputVectorBinding with
    ⟨_shapeOutputFlags,
      shapeCommitments,
      shapeCiphertextHashes,
      bindingCommitments,
      bindingCiphertextHashes⟩
  have accepted : proofWrapperAccepts wrapper = true :=
    (accepts_iff_proof_wrapper_preconditions (input := wrapper)).mpr
      spendFacts.wrapperPreconditions
  exact
    {
      deployedRelationFacts :=
        {
          balanceSlotsEq := balanceFacts.balanceSlotsEq,
          validBalanceEq := balanceFacts.validBalanceEq,
          spendAuthorized := spendFacts.spendAuthorized
        },
      acceptedTransactionRelation :=
        ⟨accepted,
          spendFacts.wrapperSurface,
          balanceFacts.balanceSlotsEq,
          balanceFacts.validBalanceEq,
          spendFacts.publicShapeValid,
          spendFacts.inputSlotsAuthorized⟩,
      wrapperPreconditions := spendFacts.wrapperPreconditions,
      publicBindingValid := spendFacts.publicBindingValid,
      publicShapeValid := spendFacts.publicShapeValid,
      statementLength := spendFacts.statementLength,
      statementPreimage := spendFacts.statementPreimage,
      bindingMessage := spendFacts.bindingMessage,
      coreStatementBinding := spendFacts.coreStatementBinding,
      vectorBinding :=
        ⟨shapeNullifiers,
          shapeCommitments,
          shapeCiphertextHashes,
          bindingNullifiers,
          bindingCommitments,
          bindingCiphertextHashes⟩,
      inputVectorBinding := spendFacts.inputVectorBinding,
      outputVectorBinding := balanceFacts.outputVectorBinding,
      valueBalanceBinding := balanceFacts.valueBalanceBinding,
      stablecoinPayloadBinding := balanceFacts.stablecoinPayloadBinding
    }

theorem deployed_soundness_parts_canonical_surface_implies_boundary_facts
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
    (spendSound :
      DeployedTxVerifierSpendSoundnessAssumption
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
        spendWitnesses)
    (balanceSound :
      DeployedTxVerifierBalancePublicFieldSoundnessAssumption
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
      slots :=
  canonical_split_boundary_facts_imply_full_boundary_facts
    (spend_soundness_canonical_surface_implies_spend_boundary_facts
      surface
      spendSound)
    (balance_public_soundness_canonical_surface_implies_balance_public_boundary_facts
      surface
      balanceSound)

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

theorem canonical_boundary_facts_native_delta
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
    slotDelta nativeAsset slots = nativeExpected balanceWitness :=
  accepted_transaction_relation_native_delta
    facts.acceptedTransactionRelation

theorem canonical_boundary_facts_authorized_asset_delta
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
    {assetId : Nat}
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
    AuthorizedAssetDelta balanceWitness slots assetId :=
  accepted_transaction_relation_authorized_asset_delta
    facts.acceptedTransactionRelation

theorem canonical_boundary_facts_authorized_asset_delta_value
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
    {assetId : Nat}
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
    slotDelta assetId slots =
      authorizedAssetDeltaValue balanceWitness assetId :=
  accepted_transaction_relation_authorized_asset_delta_value
    facts.acceptedTransactionRelation

theorem canonical_balance_public_boundary_facts_authorized_public_delta_value
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
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (facts :
      CanonicalDeployedVerifierBalancePublicBoundaryFacts
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
        balanceWitness
        slots) :
    slotDelta assetId slots =
      publicAuthorizedAssetDeltaValue publicFields assetId :=
  facts.authorizedPublicDeltaValue

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

theorem canonical_spend_boundary_facts_input_slot_bound_to_statement
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
    (facts :
      CanonicalDeployedVerifierSpendBoundaryFacts
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
        spendWitnesses)
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
      facts.spendAuthorized
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

theorem balance_public_soundness_canonical_surface_authorized_public_delta_value
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
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
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
    (balanceSound :
      DeployedTxVerifierBalancePublicFieldSoundnessAssumption
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
        balanceWitness
        slots) :
    slotDelta assetId slots =
      publicAuthorizedAssetDeltaValue publicFields assetId :=
  canonical_balance_public_boundary_facts_authorized_public_delta_value
    (balance_public_soundness_canonical_surface_implies_balance_public_boundary_facts
      surface
      balanceSound)

theorem spend_soundness_canonical_surface_input_slot_boundary_facts
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
    (spendSound :
      DeployedTxVerifierSpendSoundnessAssumption
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
        spendWitnesses)
    (slot :
      ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness) :
    CanonicalDeployedVerifierSpendInputSlotBoundaryFacts
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
      index
      activeFlag
      publicNullifier
      witness := by
  have facts :=
    spend_soundness_canonical_surface_implies_spend_boundary_facts
      surface
      spendSound
  have slotFacts :=
    canonical_spend_boundary_facts_input_slot_bound_to_statement facts slot
  exact
    {
      spendBoundaryFacts := facts,
      inputSlotFacts := slotFacts.left,
      statementRootBinding := slotFacts.right.left,
      bindingRootBinding := slotFacts.right.right.left,
      statementSlot := slotFacts.right.right.right.left,
      bindingSlot := slotFacts.right.right.right.right
    }

theorem deployed_soundness_canonical_surface_input_slot_boundary_facts
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
        witness) :
    CanonicalDeployedVerifierInputSlotBoundaryFacts
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
      index
      activeFlag
      publicNullifier
      witness := by
  have facts :=
    deployed_soundness_canonical_surface_implies_boundary_facts
      surface
      sound
  have slotFacts :=
    canonical_boundary_facts_input_slot_bound_to_statement facts slot
  exact
    {
      boundaryFacts := facts,
      inputSlotFacts := slotFacts.left,
      statementRootBinding := slotFacts.right.left,
      bindingRootBinding := slotFacts.right.right.left,
      statementSlot := slotFacts.right.right.right.left,
      bindingSlot := slotFacts.right.right.right.right
    }

theorem deployed_soundness_canonical_surface_output_slot_boundary_facts
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
      OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        activeFlag
        publicCommitment
        publicCiphertextHash) :
    CanonicalDeployedVerifierOutputSlotBoundaryFacts
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
      index
      activeFlag
      publicCommitment
      publicCiphertextHash := by
  have facts :=
    deployed_soundness_canonical_surface_implies_boundary_facts
      surface
      sound
  have slotFacts :=
    canonical_boundary_facts_output_slot_bound_to_statement facts slot
  exact
    {
      boundaryFacts := facts,
      outputSlotFacts := slotFacts.left,
      statementSlot := slotFacts.right.left,
      bindingSlot := slotFacts.right.right
    }

end ProofSystemBoundary
end Transaction
end Hegemon

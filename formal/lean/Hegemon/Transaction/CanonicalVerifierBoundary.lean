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

structure BalancePublicFieldFacts
    (publicFields : PublicInputBinding.PublicFields)
    (balanceWitness : BalanceWitness) : Prop where
  fee : balanceWitness.fee = publicFields.nativeFee
  valueBalance : balanceWitness.valueBalance = publicFields.valueBalance
  stablecoinEnabled :
    stablecoinEnabledFlagMatches
      publicFields.stablecoinEnabled
      balanceWitness.stablecoin.enabled
  stablecoinAsset :
    balanceWitness.stablecoin.assetId = publicFields.stablecoinAsset
  stablecoinIssuanceDelta :
    balanceWitness.stablecoin.issuanceDelta =
      publicFields.stablecoinIssuanceDelta
  stablecoinPolicyVersion :
    balanceWitness.stablecoin.policyVersion =
      publicFields.stablecoinPolicyVersion

def publicAuthorizedAssetDeltaValue
    (publicFields : PublicInputBinding.PublicFields)
    (assetId : Nat) : Int :=
  if assetId = Hegemon.Transaction.nativeAsset then
    Int.ofNat publicFields.nativeFee - publicFields.valueBalance
  else if publicFields.stablecoinEnabled = 1 then
    if assetId = publicFields.stablecoinAsset then
      publicFields.stablecoinIssuanceDelta
    else
      0
  else
    0

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

structure CanonicalStatementCoreBinding
    (shape : PublicInputShape)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields)
    (bindingFields : ProofStatementBinding.BindingFields)
    (merkleRoot : Digest) : Prop where
  relationRoot : merkleRoot = bound.merkleRoot
  statementRoot : statementFields.merkleRootSeed = bound.merkleRoot
  bindingAnchor : bindingFields.anchorSeed = bound.merkleRoot
  statementFee : statementFields.fee = bound.fee
  bindingFee : bindingFields.fee = bound.fee
  shapeBalanceSlotAssets : shape.balanceSlotAssets = bound.balanceSlotAssets
  bindingBalanceSlotAssets :
    bindingFields.balanceSlotAssets = bound.balanceSlotAssets
  balanceSlotAssetsCount :
    bound.balanceSlotAssets.length = PublicInputs.balanceSlotCount
  shapeValueBalanceSign : shape.valueBalanceSign = bound.valueBalanceSign
  statementValueBalanceSign :
    statementFields.valueBalanceSign = bound.valueBalanceSign
  statementValueBalanceMagnitude :
    statementFields.valueBalanceMagnitude = bound.valueBalanceMagnitude
  bindingValueBalance :
    PublicInputBinding.signedMagnitudeMatches
      bindingFields.valueBalance
      bound.valueBalanceSign
      bound.valueBalanceMagnitude = true
  shapeStablecoinEnabled : shape.stablecoinEnabled = bound.stablecoinEnabled
  shapeStablecoinAsset : shape.stablecoinAsset = bound.stablecoinAsset
  shapeStablecoinIssuanceSign :
    shape.stablecoinIssuanceSign = bound.stablecoinIssuanceSign
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

structure DeployedTxBalancePublicFieldFacts
    (publicFields : PublicInputBinding.PublicFields)
    (balanceWitness : BalanceWitness)
    (slots : List BalanceSlot) : Prop where
  balanceSlotsEq : balanceSlots balanceWitness = some slots
  validBalanceEq : validBalance balanceWitness = true
  publicFields :
    BalancePublicFieldFacts
      publicFields
      balanceWitness

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

def DeployedTxVerifierSpendSoundnessAssumption
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
    (spendWitnesses : List InputSpendWitness) : Prop :=
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
    transactionSpendAuthorized shape merkleRoot spendWitnesses = true

def DeployedTxVerifierBalancePublicFieldSoundnessAssumption
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
    DeployedTxBalancePublicFieldFacts
      publicFields
      balanceWitness
      slots

abbrev DeployedTxVerifierBalancePublicFieldsSoundnessAssumption :=
  DeployedTxVerifierBalancePublicFieldSoundnessAssumption

theorem deployed_soundness_parts_imply_deployed_tx_verifier_soundness_assumption
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
      slots := by
  intro surface
  have balanceFacts := balanceSound surface
  exact
    {
      balanceSlotsEq := balanceFacts.balanceSlotsEq,
      validBalanceEq := balanceFacts.validBalanceEq,
      spendAuthorized := spendSound surface
    }

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

theorem canonical_statement_surface_core_binding
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
    CanonicalStatementCoreBinding
      shape
      bound
      statementFields
      bindingFields
      merkleRoot where
  relationRoot := surface.relationMerkleRoot
  statementRoot := surface.statementMerkleRoot
  bindingAnchor := surface.bindingAnchor
  statementFee := surface.statementFee
  bindingFee := surface.bindingFee
  shapeBalanceSlotAssets := surface.shapeBalanceSlotAssets
  bindingBalanceSlotAssets := surface.bindingBalanceSlotAssets
  balanceSlotAssetsCount := surface.statementBalanceSlotAssetsCount
  shapeValueBalanceSign := surface.shapeValueBalanceSign
  statementValueBalanceSign := surface.statementValueBalanceSign
  statementValueBalanceMagnitude := surface.statementValueBalanceMagnitude
  bindingValueBalance := surface.bindingValueBalance
  shapeStablecoinEnabled := surface.shapeStablecoinEnabled
  shapeStablecoinAsset := surface.shapeStablecoinAsset
  shapeStablecoinIssuanceSign := surface.shapeStablecoinIssuanceSign
  statementStablecoinEnabled := surface.statementStablecoinEnabled
  statementStablecoinAsset := surface.statementStablecoinAsset
  statementStablecoinPolicyHash := surface.statementStablecoinPolicyHash
  statementStablecoinOracleCommitment :=
    surface.statementStablecoinOracleCommitment
  statementStablecoinAttestationCommitment :=
    surface.statementStablecoinAttestationCommitment
  statementStablecoinPolicyVersion := surface.statementStablecoinPolicyVersion
  statementStablecoinIssuanceSign := surface.statementStablecoinIssuanceSign
  statementStablecoinIssuanceMagnitude :=
    surface.statementStablecoinIssuanceMagnitude
  bindingStablecoinEnabled := surface.bindingStablecoinEnabled
  bindingStablecoinAsset := surface.bindingStablecoinAsset
  bindingStablecoinPolicyHash := surface.bindingStablecoinPolicyHash
  bindingStablecoinOracleCommitment :=
    surface.bindingStablecoinOracleCommitment
  bindingStablecoinAttestationCommitment :=
    surface.bindingStablecoinAttestationCommitment
  bindingStablecoinIssuanceDelta := surface.bindingStablecoinIssuanceDelta
  bindingStablecoinPolicyVersion := surface.bindingStablecoinPolicyVersion

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

theorem canonical_statement_surface_input_vectors_bound
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
    shape.inputFlags = bound.inputFlags
      ∧ shape.nullifiers = statementFields.nullifierSeeds
      ∧ bindingFields.nullifierSeeds = statementFields.nullifierSeeds :=
  ⟨surface.shapeInputFlags,
    surface.shapeNullifiers,
    surface.bindingNullifiers⟩

theorem canonical_statement_surface_output_vectors_bound
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
    shape.outputFlags = bound.outputFlags
      ∧ shape.commitments = statementFields.commitmentSeeds
      ∧ shape.ciphertextHashes = statementFields.ciphertextHashSeeds
      ∧ bindingFields.commitmentSeeds = statementFields.commitmentSeeds
      ∧ bindingFields.ciphertextHashSeeds =
        statementFields.ciphertextHashSeeds :=
  ⟨surface.shapeOutputFlags,
    surface.shapeCommitments,
    surface.shapeCiphertextHashes,
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

theorem canonical_statement_spend_soundness_active_input_bound_to_statement
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
        witness :=
  canonical_surface_authorized_active_input_bound_to_statement
    surface
    (spendSound surface)
    slot
    active

theorem canonical_surface_authorized_input_slot_bound_to_statement
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
  have facts :=
    transactionSpendAuthorized_input_slot_facts_at
      authorized
      slot
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

theorem canonical_surface_output_slot_bound_to_statement
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
  have facts :=
    validPublicInputShape_output_slot_facts_at
      surface.publicShape
      slot
  have slotStatement :
      OutputSlotAt
        bound.outputFlags
        statementFields.commitmentSeeds
        statementFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash := by
    rw [← surface.shapeOutputFlags, ← surface.shapeCommitments,
      ← surface.shapeCiphertextHashes]
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
    rw [← surface.shapeOutputFlags, surface.bindingCommitments,
      surface.bindingCiphertextHashes, ← surface.shapeCommitments,
      ← surface.shapeCiphertextHashes]
    exact slot
  exact ⟨facts, slotStatement, slotBinding⟩

theorem balance_public_field_facts_authorized_asset_delta_value
    {publicFields : PublicInputBinding.PublicFields}
    {balanceWitness : BalanceWitness}
    {slots : List BalanceSlot}
    {assetId : Nat}
    (balanceSlotsEq : balanceSlots balanceWitness = some slots)
    (validBalanceEq : validBalance balanceWitness = true)
    (publicFacts : BalancePublicFieldFacts publicFields balanceWitness) :
    slotDelta assetId slots =
      publicAuthorizedAssetDeltaValue publicFields assetId := by
  unfold publicAuthorizedAssetDeltaValue
  by_cases native : assetId = Hegemon.Transaction.nativeAsset
  · simp [native]
    calc
      slotDelta Hegemon.Transaction.nativeAsset slots =
          nativeExpected balanceWitness :=
        validBalance_native_delta balanceSlotsEq validBalanceEq
      _ = Int.ofNat publicFields.nativeFee - publicFields.valueBalance := by
        unfold nativeExpected
        rw [publicFacts.fee, publicFacts.valueBalance]
  · simp [native]
    rcases publicFacts.stablecoinEnabled with disabled | enabled
    · rcases disabled with ⟨publicDisabled, witnessDisabled⟩
      simp [publicDisabled]
      exact
        validBalance_no_stablecoin_non_native_delta_zero
          balanceSlotsEq
          validBalanceEq
          witnessDisabled
          native
    · rcases enabled with ⟨publicEnabled, witnessEnabled⟩
      simp [publicEnabled]
      by_cases selected : assetId = publicFields.stablecoinAsset
      · simp [selected]
        calc
          slotDelta publicFields.stablecoinAsset slots =
              slotDelta balanceWitness.stablecoin.assetId slots := by
                rw [publicFacts.stablecoinAsset]
          _ = balanceWitness.stablecoin.issuanceDelta :=
              validBalance_stablecoin_selected_delta
                balanceSlotsEq
                validBalanceEq
                witnessEnabled
          _ = publicFields.stablecoinIssuanceDelta :=
              publicFacts.stablecoinIssuanceDelta
      · simp [selected]
        have notWitnessSelected :
            assetId ≠ balanceWitness.stablecoin.assetId := by
          intro witnessSelected
          apply selected
          rw [← publicFacts.stablecoinAsset]
          exact witnessSelected
        exact
          validBalance_stablecoin_non_selected_non_native_delta_zero
            balanceSlotsEq
            validBalanceEq
            witnessEnabled
            native
            notWitnessSelected

theorem canonical_statement_balance_soundness_public_authorized_asset_delta_value
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
      publicAuthorizedAssetDeltaValue publicFields assetId := by
  have facts := balanceSound surface
  exact
    balance_public_field_facts_authorized_asset_delta_value
      facts.balanceSlotsEq
      facts.validBalanceEq
      facts.publicFields

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

theorem canonical_statement_implies_input_slot_facts_at
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
    InputSlotAuthorizationFacts
      merkleRoot
      activeFlag
      publicNullifier
      witness :=
  accepted_transaction_relation_input_slot_facts_at
    (accepted_wrapper_and_canonical_statement_implies_transaction_relation
      surface
      sound)
    slot

theorem canonical_statement_implies_output_slot_facts_at
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
    OutputSlotFacts
      activeFlag
      publicCommitment
      publicCiphertextHash :=
  accepted_transaction_relation_output_slot_facts_at
    (accepted_wrapper_and_canonical_statement_implies_transaction_relation
      surface
      sound)
    slot

end CanonicalVerifierBoundary
end Transaction
end Hegemon

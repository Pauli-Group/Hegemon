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

structure StablecoinMintExceptionSurface
    (publicFields : PublicInputBinding.PublicFields)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields)
    (bindingFields : ProofStatementBinding.BindingFields)
    (assetId : Nat)
    (delta : Int) : Prop where
  publicEnabled : publicFields.stablecoinEnabled = 1
  selectedAsset : assetId = publicFields.stablecoinAsset
  deltaValue : delta = publicFields.stablecoinIssuanceDelta
  publicDeltaMatchesBound :
    PublicInputBinding.signedMagnitudeMatches
      delta
      bound.stablecoinIssuanceSign
      bound.stablecoinIssuanceMagnitude = true
  boundEnabled : bound.stablecoinEnabled = publicFields.stablecoinEnabled
  boundAsset : bound.stablecoinAsset = publicFields.stablecoinAsset
  boundPolicyHash :
    bound.stablecoinPolicyHash = publicFields.stablecoinPolicyHash
  boundOracleCommitment :
    bound.stablecoinOracleCommitment =
      publicFields.stablecoinOracleCommitment
  boundAttestationCommitment :
    bound.stablecoinAttestationCommitment =
      publicFields.stablecoinAttestationCommitment
  boundPolicyVersion :
    bound.stablecoinPolicyVersion = publicFields.stablecoinPolicyVersion
  statementEnabled :
    statementFields.stablecoinEnabled = bound.stablecoinEnabled
  statementAsset :
    statementFields.stablecoinAsset = bound.stablecoinAsset
  statementPolicyHash :
    statementFields.stablecoinPolicyHashSeed = bound.stablecoinPolicyHash
  statementOracleCommitment :
    statementFields.stablecoinOracleCommitmentSeed =
      bound.stablecoinOracleCommitment
  statementAttestationCommitment :
    statementFields.stablecoinAttestationCommitmentSeed =
      bound.stablecoinAttestationCommitment
  statementPolicyVersion :
    statementFields.stablecoinPolicyVersion = bound.stablecoinPolicyVersion
  statementIssuanceSign :
    statementFields.stablecoinIssuanceSign =
      bound.stablecoinIssuanceSign
  statementIssuanceMagnitude :
    statementFields.stablecoinIssuanceMagnitude =
      bound.stablecoinIssuanceMagnitude
  bindingEnabled :
    stablecoinEnabledFlagMatches
      bound.stablecoinEnabled
      bindingFields.stablecoinEnabled
  bindingAsset :
    bindingFields.stablecoinAsset = bound.stablecoinAsset
  bindingPolicyHash :
    bindingFields.stablecoinPolicyHashSeed = bound.stablecoinPolicyHash
  bindingOracleCommitment :
    bindingFields.stablecoinOracleCommitmentSeed =
      bound.stablecoinOracleCommitment
  bindingAttestationCommitment :
    bindingFields.stablecoinAttestationCommitmentSeed =
      bound.stablecoinAttestationCommitment
  bindingIssuanceDelta :
    PublicInputBinding.signedMagnitudeMatches
      bindingFields.stablecoinIssuanceDelta
      bound.stablecoinIssuanceSign
      bound.stablecoinIssuanceMagnitude = true
  bindingPolicyVersion :
    bindingFields.stablecoinPolicyVersion = bound.stablecoinPolicyVersion

structure StablecoinMintExceptionPayload where
  assetId : Nat
  delta : Int
  policyHash : Digest
  oracleCommitment : Digest
  attestationCommitment : Digest
  policyVersion : Nat
deriving DecidableEq, Repr

def stablecoinMintExceptionPayload
    (publicFields : PublicInputBinding.PublicFields)
    (assetId : Nat)
    (delta : Int) : StablecoinMintExceptionPayload :=
  { assetId := assetId
    delta := delta
    policyHash := publicFields.stablecoinPolicyHash
    oracleCommitment := publicFields.stablecoinOracleCommitment
    attestationCommitment := publicFields.stablecoinAttestationCommitment
    policyVersion := publicFields.stablecoinPolicyVersion }

abbrev LiveStablecoinPolicyAuthorizes :=
  StablecoinMintExceptionPayload -> Prop

structure AuthorizedStablecoinMintExceptionSurface
    (publicFields : PublicInputBinding.PublicFields)
    (bound : PublicInputBinding.BoundPublicInputs)
    (statementFields : StatementHash.StatementFields)
    (bindingFields : ProofStatementBinding.BindingFields)
    (assetId : Nat)
    (delta : Int)
    (livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes) : Prop where
  exceptionSurface :
    StablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta
  authorizedPayload :
    livePolicyAuthorizes
      (stablecoinMintExceptionPayload publicFields assetId delta)
  publicPayloadSelected :
    (stablecoinMintExceptionPayload publicFields assetId delta).assetId =
      publicFields.stablecoinAsset
      ∧ (stablecoinMintExceptionPayload publicFields assetId delta).delta =
        publicFields.stablecoinIssuanceDelta
  boundPayloadBinding :
    bound.stablecoinAsset =
      (stablecoinMintExceptionPayload publicFields assetId delta).assetId
      ∧ bound.stablecoinPolicyHash =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyHash
      ∧ bound.stablecoinOracleCommitment =
        (stablecoinMintExceptionPayload publicFields assetId delta).oracleCommitment
      ∧ bound.stablecoinAttestationCommitment =
        (stablecoinMintExceptionPayload publicFields assetId delta).attestationCommitment
      ∧ bound.stablecoinPolicyVersion =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyVersion
  statementPayloadBinding :
    statementFields.stablecoinAsset =
      (stablecoinMintExceptionPayload publicFields assetId delta).assetId
      ∧ statementFields.stablecoinPolicyHashSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyHash
      ∧ statementFields.stablecoinOracleCommitmentSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).oracleCommitment
      ∧ statementFields.stablecoinAttestationCommitmentSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).attestationCommitment
      ∧ statementFields.stablecoinPolicyVersion =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyVersion
  statementPayloadDeltaEncoding :
    PublicInputBinding.signedMagnitudeMatches
      (stablecoinMintExceptionPayload publicFields assetId delta).delta
      statementFields.stablecoinIssuanceSign
      statementFields.stablecoinIssuanceMagnitude = true
  bindingPayloadBinding :
    bindingFields.stablecoinAsset =
      (stablecoinMintExceptionPayload publicFields assetId delta).assetId
      ∧ bindingFields.stablecoinPolicyHashSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyHash
      ∧ bindingFields.stablecoinOracleCommitmentSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).oracleCommitment
      ∧ bindingFields.stablecoinAttestationCommitmentSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).attestationCommitment
      ∧ bindingFields.stablecoinPolicyVersion =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyVersion
  bindingPayloadDeltaEncoding :
    PublicInputBinding.signedMagnitudeMatches
      bindingFields.stablecoinIssuanceDelta
      statementFields.stablecoinIssuanceSign
      statementFields.stablecoinIssuanceMagnitude = true

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

theorem canonical_statement_surface_p3_public_input_binding_facts
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
    PublicInputBinding.PublicInputP3BindingFacts
      publicFields
      serializedFields
      bound :=
  PublicInputBinding.bindPublicInputs_some_implies_p3_binding_facts
    surface.publicBinding

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

theorem canonical_statement_surface_stablecoin_mint_exception_surface
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
    {assetId : Nat}
    {delta : Int}
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
    (publicEnabled : publicFields.stablecoinEnabled = 1)
    (selectedAsset : assetId = publicFields.stablecoinAsset)
    (deltaValue : delta = publicFields.stablecoinIssuanceDelta) :
    StablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta := by
  have p3Facts :=
    canonical_statement_surface_p3_public_input_binding_facts surface
  rcases
      PublicInputBinding.stablecoinBindingMatches_true_fields
        p3Facts.publicStablecoinBindingMatches with
    ⟨hEnabled, hAsset, hPolicyVersion, hIssuance, hPolicyHash, hOracle,
      hAttestation⟩
  exact
    { publicEnabled := publicEnabled
      selectedAsset := selectedAsset
      deltaValue := deltaValue
      publicDeltaMatchesBound := by
        rw [deltaValue, p3Facts.boundStablecoinIssuanceSign,
          p3Facts.boundStablecoinIssuanceMagnitude]
        exact hIssuance
      boundEnabled := by
        rw [p3Facts.boundStablecoinEnabled, ← hEnabled]
      boundAsset := by
        rw [p3Facts.boundStablecoinAsset, ← hAsset]
      boundPolicyHash := by
        rw [p3Facts.boundStablecoinPolicyHash, ← hPolicyHash]
      boundOracleCommitment := by
        rw [p3Facts.boundStablecoinOracleCommitment, ← hOracle]
      boundAttestationCommitment := by
        rw [p3Facts.boundStablecoinAttestationCommitment, ← hAttestation]
      boundPolicyVersion := by
        rw [p3Facts.boundStablecoinPolicyVersion, ← hPolicyVersion]
      statementEnabled := surface.statementStablecoinEnabled
      statementAsset := surface.statementStablecoinAsset
      statementPolicyHash := surface.statementStablecoinPolicyHash
      statementOracleCommitment :=
        surface.statementStablecoinOracleCommitment
      statementAttestationCommitment :=
        surface.statementStablecoinAttestationCommitment
      statementPolicyVersion := surface.statementStablecoinPolicyVersion
      statementIssuanceSign := surface.statementStablecoinIssuanceSign
      statementIssuanceMagnitude :=
        surface.statementStablecoinIssuanceMagnitude
      bindingEnabled := surface.bindingStablecoinEnabled
      bindingAsset := surface.bindingStablecoinAsset
      bindingPolicyHash := surface.bindingStablecoinPolicyHash
      bindingOracleCommitment := surface.bindingStablecoinOracleCommitment
      bindingAttestationCommitment :=
        surface.bindingStablecoinAttestationCommitment
      bindingIssuanceDelta := surface.bindingStablecoinIssuanceDelta
      bindingPolicyVersion := surface.bindingStablecoinPolicyVersion }

theorem stablecoin_mint_exception_authorized_payload_bound_to_statement
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (exceptionSurface :
      StablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta)
    (authorized :
      livePolicyAuthorizes
        (stablecoinMintExceptionPayload publicFields assetId delta)) :
    AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta
      livePolicyAuthorizes := by
  exact
    { exceptionSurface := exceptionSurface
      authorizedPayload := authorized
      publicPayloadSelected := by
        simp [stablecoinMintExceptionPayload, exceptionSurface.selectedAsset,
          exceptionSurface.deltaValue]
      boundPayloadBinding := by
        simp [stablecoinMintExceptionPayload, exceptionSurface.selectedAsset,
          exceptionSurface.boundAsset, exceptionSurface.boundPolicyHash,
          exceptionSurface.boundOracleCommitment,
          exceptionSurface.boundAttestationCommitment,
          exceptionSurface.boundPolicyVersion]
      statementPayloadBinding := by
        simp [stablecoinMintExceptionPayload, exceptionSurface.selectedAsset,
          exceptionSurface.statementAsset, exceptionSurface.boundAsset,
          exceptionSurface.statementPolicyHash,
          exceptionSurface.boundPolicyHash,
          exceptionSurface.statementOracleCommitment,
          exceptionSurface.boundOracleCommitment,
          exceptionSurface.statementAttestationCommitment,
          exceptionSurface.boundAttestationCommitment,
          exceptionSurface.statementPolicyVersion,
          exceptionSurface.boundPolicyVersion]
      statementPayloadDeltaEncoding := by
        simp [stablecoinMintExceptionPayload,
          exceptionSurface.statementIssuanceSign,
          exceptionSurface.statementIssuanceMagnitude,
          exceptionSurface.publicDeltaMatchesBound]
      bindingPayloadBinding := by
        simp [stablecoinMintExceptionPayload, exceptionSurface.selectedAsset,
          exceptionSurface.bindingAsset, exceptionSurface.boundAsset,
          exceptionSurface.bindingPolicyHash, exceptionSurface.boundPolicyHash,
          exceptionSurface.bindingOracleCommitment,
          exceptionSurface.boundOracleCommitment,
          exceptionSurface.bindingAttestationCommitment,
          exceptionSurface.boundAttestationCommitment,
          exceptionSurface.bindingPolicyVersion,
          exceptionSurface.boundPolicyVersion]
      bindingPayloadDeltaEncoding := by
        simp [exceptionSurface.statementIssuanceSign,
          exceptionSurface.statementIssuanceMagnitude,
          exceptionSurface.bindingIssuanceDelta] }

theorem authorized_stablecoin_mint_exception_surface_live_authorizes_canonical_payload
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (surface :
      AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta
        livePolicyAuthorizes) :
    livePolicyAuthorizes
      (stablecoinMintExceptionPayload publicFields assetId delta) :=
  surface.authorizedPayload

theorem authorized_stablecoin_mint_exception_surface_canonical_payload_eq_public_fields
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (surface :
      AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta
        livePolicyAuthorizes) :
    stablecoinMintExceptionPayload publicFields assetId delta =
      { assetId := publicFields.stablecoinAsset
        delta := publicFields.stablecoinIssuanceDelta
        policyHash := publicFields.stablecoinPolicyHash
        oracleCommitment := publicFields.stablecoinOracleCommitment
        attestationCommitment := publicFields.stablecoinAttestationCommitment
        policyVersion := publicFields.stablecoinPolicyVersion } := by
  rcases surface.publicPayloadSelected with ⟨selectedAsset, deltaValue⟩
  have selectedAsset' : assetId = publicFields.stablecoinAsset := by
    simpa [stablecoinMintExceptionPayload] using selectedAsset
  have deltaValue' : delta = publicFields.stablecoinIssuanceDelta := by
    simpa [stablecoinMintExceptionPayload] using deltaValue
  simp [stablecoinMintExceptionPayload, selectedAsset', deltaValue']

theorem authorized_stablecoin_mint_exception_surface_bound_payload_fields
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (surface :
      AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta
        livePolicyAuthorizes) :
    bound.stablecoinAsset =
        (stablecoinMintExceptionPayload publicFields assetId delta).assetId
      ∧ bound.stablecoinPolicyHash =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyHash
      ∧ bound.stablecoinOracleCommitment =
        (stablecoinMintExceptionPayload publicFields assetId delta).oracleCommitment
      ∧ bound.stablecoinAttestationCommitment =
        (stablecoinMintExceptionPayload publicFields assetId delta).attestationCommitment
      ∧ bound.stablecoinPolicyVersion =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyVersion :=
  surface.boundPayloadBinding

theorem authorized_stablecoin_mint_exception_surface_statement_payload_fields
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (surface :
      AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta
        livePolicyAuthorizes) :
    statementFields.stablecoinAsset =
        (stablecoinMintExceptionPayload publicFields assetId delta).assetId
      ∧ statementFields.stablecoinPolicyHashSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyHash
      ∧ statementFields.stablecoinOracleCommitmentSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).oracleCommitment
      ∧ statementFields.stablecoinAttestationCommitmentSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).attestationCommitment
      ∧ statementFields.stablecoinPolicyVersion =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyVersion :=
  surface.statementPayloadBinding

theorem authorized_stablecoin_mint_exception_surface_binding_payload_fields
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (surface :
      AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta
        livePolicyAuthorizes) :
    bindingFields.stablecoinAsset =
        (stablecoinMintExceptionPayload publicFields assetId delta).assetId
      ∧ bindingFields.stablecoinPolicyHashSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyHash
      ∧ bindingFields.stablecoinOracleCommitmentSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).oracleCommitment
      ∧ bindingFields.stablecoinAttestationCommitmentSeed =
        (stablecoinMintExceptionPayload publicFields assetId delta).attestationCommitment
      ∧ bindingFields.stablecoinPolicyVersion =
        (stablecoinMintExceptionPayload publicFields assetId delta).policyVersion :=
  surface.bindingPayloadBinding

theorem authorized_stablecoin_mint_exception_surface_policy_metadata_preserved
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (surface :
      AuthorizedStablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        delta
        livePolicyAuthorizes) :
    bound.stablecoinPolicyHash = publicFields.stablecoinPolicyHash
      ∧ bound.stablecoinOracleCommitment =
        publicFields.stablecoinOracleCommitment
      ∧ bound.stablecoinAttestationCommitment =
        publicFields.stablecoinAttestationCommitment
      ∧ bound.stablecoinPolicyVersion =
        publicFields.stablecoinPolicyVersion
      ∧ statementFields.stablecoinPolicyHashSeed =
        publicFields.stablecoinPolicyHash
      ∧ statementFields.stablecoinOracleCommitmentSeed =
        publicFields.stablecoinOracleCommitment
      ∧ statementFields.stablecoinAttestationCommitmentSeed =
        publicFields.stablecoinAttestationCommitment
      ∧ statementFields.stablecoinPolicyVersion =
        publicFields.stablecoinPolicyVersion
      ∧ bindingFields.stablecoinPolicyHashSeed =
        publicFields.stablecoinPolicyHash
      ∧ bindingFields.stablecoinOracleCommitmentSeed =
        publicFields.stablecoinOracleCommitment
      ∧ bindingFields.stablecoinAttestationCommitmentSeed =
        publicFields.stablecoinAttestationCommitment
      ∧ bindingFields.stablecoinPolicyVersion =
        publicFields.stablecoinPolicyVersion := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa [stablecoinMintExceptionPayload] using
      surface.boundPayloadBinding.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.boundPayloadBinding.2.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.boundPayloadBinding.2.2.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.boundPayloadBinding.2.2.2.2
  · simpa [stablecoinMintExceptionPayload] using
      surface.statementPayloadBinding.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.statementPayloadBinding.2.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.statementPayloadBinding.2.2.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.statementPayloadBinding.2.2.2.2
  · simpa [stablecoinMintExceptionPayload] using
      surface.bindingPayloadBinding.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.bindingPayloadBinding.2.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.bindingPayloadBinding.2.2.2.1
  · simpa [stablecoinMintExceptionPayload] using
      surface.bindingPayloadBinding.2.2.2.2

theorem authorized_stablecoin_mint_exception_surface_no_unauthorized_payload
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (notAuthorized :
      ¬ livePolicyAuthorizes
        (stablecoinMintExceptionPayload publicFields assetId delta)) :
    ¬ AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta
      livePolicyAuthorizes := by
  intro surface
  exact notAuthorized surface.authorizedPayload

theorem authorized_stablecoin_mint_exception_surface_no_mismatched_asset
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (mismatch : assetId ≠ publicFields.stablecoinAsset) :
    ¬ AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta
      livePolicyAuthorizes := by
  intro surface
  exact mismatch surface.exceptionSurface.selectedAsset

theorem authorized_stablecoin_mint_exception_surface_no_mismatched_delta
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (mismatch : delta ≠ publicFields.stablecoinIssuanceDelta) :
    ¬ AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta
      livePolicyAuthorizes := by
  intro surface
  exact mismatch surface.exceptionSurface.deltaValue

theorem authorized_stablecoin_mint_exception_surface_no_mismatched_public_payload
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (mismatch :
      stablecoinMintExceptionPayload publicFields assetId delta ≠
        { assetId := publicFields.stablecoinAsset
          delta := publicFields.stablecoinIssuanceDelta
          policyHash := publicFields.stablecoinPolicyHash
          oracleCommitment := publicFields.stablecoinOracleCommitment
          attestationCommitment := publicFields.stablecoinAttestationCommitment
          policyVersion := publicFields.stablecoinPolicyVersion }) :
    ¬ AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta
      livePolicyAuthorizes := by
  intro surface
  exact mismatch
    (authorized_stablecoin_mint_exception_surface_canonical_payload_eq_public_fields
      surface)

theorem authorized_stablecoin_mint_exception_surface_no_policy_metadata_mismatch
    {publicFields : PublicInputBinding.PublicFields}
    {bound : PublicInputBinding.BoundPublicInputs}
    {statementFields : StatementHash.StatementFields}
    {bindingFields : ProofStatementBinding.BindingFields}
    {assetId : Nat}
    {delta : Int}
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
    (mismatch :
      bound.stablecoinPolicyHash ≠ publicFields.stablecoinPolicyHash
        ∨ bound.stablecoinOracleCommitment ≠
          publicFields.stablecoinOracleCommitment
        ∨ bound.stablecoinAttestationCommitment ≠
          publicFields.stablecoinAttestationCommitment
        ∨ bound.stablecoinPolicyVersion ≠
          publicFields.stablecoinPolicyVersion
        ∨ statementFields.stablecoinPolicyHashSeed ≠
          publicFields.stablecoinPolicyHash
        ∨ statementFields.stablecoinOracleCommitmentSeed ≠
          publicFields.stablecoinOracleCommitment
        ∨ statementFields.stablecoinAttestationCommitmentSeed ≠
          publicFields.stablecoinAttestationCommitment
        ∨ statementFields.stablecoinPolicyVersion ≠
          publicFields.stablecoinPolicyVersion
        ∨ bindingFields.stablecoinPolicyHashSeed ≠
          publicFields.stablecoinPolicyHash
        ∨ bindingFields.stablecoinOracleCommitmentSeed ≠
          publicFields.stablecoinOracleCommitment
        ∨ bindingFields.stablecoinAttestationCommitmentSeed ≠
          publicFields.stablecoinAttestationCommitment
        ∨ bindingFields.stablecoinPolicyVersion ≠
          publicFields.stablecoinPolicyVersion) :
    ¬ AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      delta
      livePolicyAuthorizes := by
  intro surface
  rcases
      authorized_stablecoin_mint_exception_surface_policy_metadata_preserved
        surface with
    ⟨boundPolicyHash, boundOracle, boundAttestation, boundPolicyVersion,
      statementPolicyHash, statementOracle, statementAttestation,
      statementPolicyVersion, bindingPolicyHash, bindingOracle,
      bindingAttestation, bindingPolicyVersion⟩
  rcases mismatch with
    boundPolicyHashMismatch | boundOracleMismatch | boundAttestationMismatch |
    boundPolicyVersionMismatch | statementPolicyHashMismatch |
    statementOracleMismatch | statementAttestationMismatch |
    statementPolicyVersionMismatch | bindingPolicyHashMismatch |
    bindingOracleMismatch | bindingAttestationMismatch |
    bindingPolicyVersionMismatch
  · exact boundPolicyHashMismatch boundPolicyHash
  · exact boundOracleMismatch boundOracle
  · exact boundAttestationMismatch boundAttestation
  · exact boundPolicyVersionMismatch boundPolicyVersion
  · exact statementPolicyHashMismatch statementPolicyHash
  · exact statementOracleMismatch statementOracle
  · exact statementAttestationMismatch statementAttestation
  · exact statementPolicyVersionMismatch statementPolicyVersion
  · exact bindingPolicyHashMismatch bindingPolicyHash
  · exact bindingOracleMismatch bindingOracle
  · exact bindingAttestationMismatch bindingAttestation
  · exact bindingPolicyVersionMismatch bindingPolicyVersion

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

theorem canonical_statement_spend_soundness_input_slot_bound_to_statement
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
        witness :=
  canonical_surface_authorized_input_slot_bound_to_statement
    surface
    (spendSound surface)
    slot

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

theorem canonical_statement_balance_soundness_public_field_facts
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
    DeployedTxBalancePublicFieldFacts
      publicFields
      balanceWitness
      slots :=
  balanceSound surface

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

theorem public_authorized_asset_delta_value_non_native_nonzero_requires_stablecoin_exception
    {publicFields : PublicInputBinding.PublicFields}
    {assetId : Nat}
    (nonNative : assetId ≠ Hegemon.Transaction.nativeAsset)
    (nonzero :
      publicAuthorizedAssetDeltaValue publicFields assetId ≠ 0) :
    publicFields.stablecoinEnabled = 1
      ∧ assetId = publicFields.stablecoinAsset := by
  by_cases native : assetId = Hegemon.Transaction.nativeAsset
  · exact False.elim (nonNative native)
  · by_cases enabled : publicFields.stablecoinEnabled = 1
    · by_cases selected : assetId = publicFields.stablecoinAsset
      · exact ⟨enabled, selected⟩
      · exfalso
        apply nonzero
        simp [publicAuthorizedAssetDeltaValue, native, enabled, selected]
    · exfalso
      apply nonzero
      simp [publicAuthorizedAssetDeltaValue, native, enabled]

theorem canonical_statement_balance_soundness_non_native_nonzero_public_stablecoin_exception
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
        slots)
    (nonNative : assetId ≠ Hegemon.Transaction.nativeAsset)
    (nonzero : slotDelta assetId slots ≠ 0) :
    publicFields.stablecoinEnabled = 1
      ∧ assetId = publicFields.stablecoinAsset := by
  have deltaEq :
      slotDelta assetId slots =
        publicAuthorizedAssetDeltaValue publicFields assetId :=
    canonical_statement_balance_soundness_public_authorized_asset_delta_value
      surface
      balanceSound
  have publicNonzero :
      publicAuthorizedAssetDeltaValue publicFields assetId ≠ 0 := by
    intro publicZero
    apply nonzero
    rw [deltaEq, publicZero]
  exact
    public_authorized_asset_delta_value_non_native_nonzero_requires_stablecoin_exception
      nonNative
      publicNonzero

theorem canonical_statement_balance_soundness_non_native_nonzero_stablecoin_mint_exception_surface
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
        slots)
    (nonNative : assetId ≠ Hegemon.Transaction.nativeAsset)
    (nonzero : slotDelta assetId slots ≠ 0) :
    StablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      (slotDelta assetId slots) := by
  have exceptionFacts :
      publicFields.stablecoinEnabled = 1
        ∧ assetId = publicFields.stablecoinAsset :=
    canonical_statement_balance_soundness_non_native_nonzero_public_stablecoin_exception
      surface
      balanceSound
      nonNative
      nonzero
  have deltaEq :
      slotDelta assetId slots =
        publicAuthorizedAssetDeltaValue publicFields assetId :=
    canonical_statement_balance_soundness_public_authorized_asset_delta_value
      surface
      balanceSound
  have publicDelta :
      publicAuthorizedAssetDeltaValue publicFields assetId =
        publicFields.stablecoinIssuanceDelta := by
    have selectedNonNative :
        publicFields.stablecoinAsset ≠ Hegemon.Transaction.nativeAsset := by
      intro stablecoinNative
      apply nonNative
      rw [exceptionFacts.right, stablecoinNative]
    simp [publicAuthorizedAssetDeltaValue, selectedNonNative, exceptionFacts.left,
      exceptionFacts.right]
  exact
    canonical_statement_surface_stablecoin_mint_exception_surface
      surface
      exceptionFacts.left
      exceptionFacts.right
      (by rw [deltaEq, publicDelta])

theorem canonical_statement_balance_soundness_authorized_stablecoin_mint_exception_surface
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
    {livePolicyAuthorizes : LiveStablecoinPolicyAuthorizes}
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
        slots)
    (nonNative : assetId ≠ Hegemon.Transaction.nativeAsset)
    (nonzero : slotDelta assetId slots ≠ 0)
    (authorized :
      livePolicyAuthorizes
        (stablecoinMintExceptionPayload
          publicFields
          assetId
          (slotDelta assetId slots))) :
    AuthorizedStablecoinMintExceptionSurface
      publicFields
      bound
      statementFields
      bindingFields
      assetId
      (slotDelta assetId slots)
      livePolicyAuthorizes := by
  have exceptionSurface :
      StablecoinMintExceptionSurface
        publicFields
        bound
        statementFields
        bindingFields
        assetId
        (slotDelta assetId slots) :=
    canonical_statement_balance_soundness_non_native_nonzero_stablecoin_mint_exception_surface
      surface
      balanceSound
      nonNative
      nonzero
  exact
    stablecoin_mint_exception_authorized_payload_bound_to_statement
      exceptionSurface
      authorized

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

import Hegemon.Native.BlockArtifactBindingAdmission
import Hegemon.Native.TransferActionPayloadAdmission
import Hegemon.Transaction.AssetIsolation
import Hegemon.Transaction.CanonicalVerifierBoundary
import Hegemon.Transaction.ProofSystemBoundary

namespace Hegemon
namespace Native
namespace TxLeafCanonicalSurface

open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.TransferActionPayloadAdmission
open Hegemon.Transaction.AcceptedProofArtifact
open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.AssetIsolation
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.ProofSystemBoundary
open Hegemon.Transaction.PublicInputs

def TxLeafActionBindingFacts
    (input : TxLeafActionBindingInput) : Prop :=
  input.nullifiersMatch = true
    ∧ input.commitmentsMatch = true
    ∧ input.ciphertextHashesMatch = true
    ∧ input.inputCountMatches = true
    ∧ input.outputCountMatches = true
    ∧ input.versionMatches = true
    ∧ input.feeMatches = true
    ∧ input.stablecoinPayloadMatches = true
    ∧ input.balanceTagMatches = true
    ∧ input.receiptStatementHashMatches = true
    ∧ input.publicInputsDigestMatches = true
    ∧ input.proofDigestMatches = true
    ∧ input.proofBackendMatches = true
    ∧ input.ciphertextPayloadHashesMatch = true

structure NativeTxLeafCanonicalArtifactBoundaryFacts
    (input : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (balanceWitness : Hegemon.Transaction.BalanceWitness)
    (slots : List Hegemon.Transaction.BalanceSlot)
    (assetId : Nat) : Prop where
  canonicalBoundaryFacts :
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
  wrapperSurface : acceptedProofWrapperSurface wrapper
  rootBinding :
    statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
  feeBinding :
    statementFields.fee = bound.fee
      ∧ bindingFields.fee = bound.fee
  balanceSlotAssetBinding :
    shape.balanceSlotAssets = bound.balanceSlotAssets
      ∧ bindingFields.balanceSlotAssets = bound.balanceSlotAssets
      ∧ bound.balanceSlotAssets.length = Hegemon.Transaction.balanceSlotCount
  stablecoinIdentityBinding :
    shape.stablecoinEnabled = bound.stablecoinEnabled
      ∧ shape.stablecoinAsset = bound.stablecoinAsset
      ∧ shape.stablecoinIssuanceSign = bound.stablecoinIssuanceSign
      ∧ statementFields.stablecoinEnabled = bound.stablecoinEnabled
      ∧ statementFields.stablecoinAsset = bound.stablecoinAsset
      ∧ statementFields.stablecoinPolicyVersion = bound.stablecoinPolicyVersion
      ∧ statementFields.stablecoinIssuanceSign =
        bound.stablecoinIssuanceSign
      ∧ statementFields.stablecoinIssuanceMagnitude =
        bound.stablecoinIssuanceMagnitude
      ∧ stablecoinEnabledFlagMatches
        bound.stablecoinEnabled
        bindingFields.stablecoinEnabled
      ∧ bindingFields.stablecoinAsset = bound.stablecoinAsset
      ∧ bindingFields.stablecoinPolicyVersion =
        bound.stablecoinPolicyVersion
  txLeafActionPreconditions :
    txLeafActionBindingPreconditions input = true
  txLeafActionBindingFacts : TxLeafActionBindingFacts input
  spendAndBalance :
    Hegemon.Transaction.balanceSlots balanceWitness = some slots
      ∧ Hegemon.Transaction.validBalance balanceWitness = true
      ∧ Hegemon.Transaction.SpendAuthorization.transactionSpendAuthorized
        shape
        merkleRoot
        spendWitnesses = true
  authorizedAssetDelta :
    AuthorizedAssetDelta balanceWitness slots assetId
  nativeStatementArtifactBinding :
    input.receiptStatementHashMatches = true
      ∧ input.publicInputsDigestMatches = true
      ∧ input.proofDigestMatches = true
      ∧ input.proofBackendMatches = true
      ∧ input.ciphertextPayloadHashesMatch = true

structure NativeTxLeafAcceptedArtifactStatementBoundaryFacts
    (input : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (balanceWitness : Hegemon.Transaction.BalanceWitness)
    (slots : List Hegemon.Transaction.BalanceSlot) : Prop where
  canonicalBoundaryFacts :
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
  wrapperPreconditions : proofWrapperPreconditions wrapper = true
  publicBindingValid :
    Hegemon.Transaction.PublicInputBinding.validBinding
      publicFields
      serializedFields = true
  publicShapeValid : validPublicInputShape shape = true
  statementLength :
    statementBytes.length =
      Hegemon.Transaction.StatementHash.expectedPreimageLength
  statementPreimage :
    Hegemon.Transaction.StatementHash.statementPreimage
      statementFields = some statementBytes
  bindingMessage :
    Hegemon.Transaction.ProofStatementBinding.bindingMessage
      bindingFields = some bindingBytes
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
  nativeStatementArtifactBinding :
    input.receiptStatementHashMatches = true
      ∧ input.publicInputsDigestMatches = true
      ∧ input.proofDigestMatches = true
      ∧ input.proofBackendMatches = true
      ∧ input.ciphertextPayloadHashesMatch = true
  txLeafActionPreconditions :
    txLeafActionBindingPreconditions input = true
  txLeafActionBindingFacts : TxLeafActionBindingFacts input

structure ProofKeyedNativeTxLeafCanonicalArtifactBoundaryFacts
    (payload : TransferPayloadInput)
    (input : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness)
    (balanceWitness : Hegemon.Transaction.BalanceWitness)
    (slots : List Hegemon.Transaction.BalanceSlot)
    (assetId : Nat) : Prop where
  transferPayloadPreconditions :
    transferPayloadPreconditions payload = true
  transferPayloadBindingFacts : TransferPayloadBindingFacts payload
  proofKeyedPayload : payload.proofBindingHashMatchesKey = true
  payloadBindingHashMatches : payload.bindingHashMatches = true
  nativeArtifactBoundary :
    NativeTxLeafCanonicalArtifactBoundaryFacts
      input
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
      assetId

theorem tx_leaf_action_accepts_implies_preconditions
    {input : TxLeafActionBindingInput}
    (accepted : txLeafActionBindingAccepts input = true) :
    txLeafActionBindingPreconditions input = true := by
  rw [← tx_leaf_action_accepts_iff_preconditions input]
  exact accepted

theorem tx_leaf_action_accepts_implies_binding_facts
    {input : TxLeafActionBindingInput}
    (accepted : txLeafActionBindingAccepts input = true) :
    TxLeafActionBindingFacts input := by
  have preconditions :=
    tx_leaf_action_accepts_implies_preconditions accepted
  cases input with
  | mk nullifiersMatch commitmentsMatch ciphertextHashesMatch
      inputCountMatches outputCountMatches versionMatches feeMatches
      stablecoinPayloadMatches balanceTagMatches receiptStatementHashMatches
      publicInputsDigestMatches proofDigestMatches proofBackendMatches
      ciphertextPayloadHashesMatch =>
      simp [
        TxLeafActionBindingFacts,
        txLeafActionBindingPreconditions
      ] at preconditions ⊢
      rcases preconditions with ⟨h0123456789012, h13⟩
      rcases h0123456789012 with ⟨h012345678901, h12⟩
      rcases h012345678901 with ⟨h01234567890, h11⟩
      rcases h01234567890 with ⟨h0123456789, h10⟩
      rcases h0123456789 with ⟨h012345678, h9⟩
      rcases h012345678 with ⟨h01234567, h8⟩
      rcases h01234567 with ⟨h0123456, h7⟩
      rcases h0123456 with ⟨h012345, h6⟩
      rcases h012345 with ⟨h01234, h5⟩
      rcases h01234 with ⟨h0123, h4⟩
      rcases h0123 with ⟨h012, h3⟩
      rcases h012 with ⟨h01, h2⟩
      rcases h01 with ⟨h0, h1⟩
      exact
        ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10,
          h11, h12, h13⟩

theorem native_tx_leaf_binding_and_canonical_surface_implies_transaction_relation
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
        slots
      ∧ txLeafActionBindingPreconditions input = true
      ∧ TxLeafActionBindingFacts input := by
  exact
    ⟨accepted_wrapper_and_canonical_statement_implies_transaction_relation
        surface
        sound,
      tx_leaf_action_accepts_implies_preconditions bindingAccepted,
      tx_leaf_action_accepts_implies_binding_facts bindingAccepted⟩

theorem native_tx_leaf_deployed_verifier_boundary_facts
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
        slots
      ∧ txLeafActionBindingPreconditions input = true
      ∧ TxLeafActionBindingFacts input := by
  exact
    ⟨deployed_soundness_canonical_surface_implies_boundary_facts
        surface
        sound,
      tx_leaf_action_accepts_implies_preconditions bindingAccepted,
      tx_leaf_action_accepts_implies_binding_facts bindingAccepted⟩

theorem native_tx_leaf_binding_and_canonical_surface_statement_proof_facts
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    Hegemon.Transaction.StatementHash.statementPreimage
        statementFields = some statementBytes
      ∧ statementBytes.length =
        Hegemon.Transaction.StatementHash.expectedPreimageLength
      ∧ Hegemon.Transaction.ProofStatementBinding.bindingMessage
        bindingFields = some bindingBytes
      ∧ Hegemon.Transaction.PublicInputBinding.validBinding
        publicFields
        serializedFields = true
      ∧ proofWrapperPreconditions wrapper = true
      ∧ acceptedProofWrapperSurface wrapper
      ∧ input.receiptStatementHashMatches = true
      ∧ input.publicInputsDigestMatches = true
      ∧ input.proofDigestMatches = true
      ∧ input.proofBackendMatches = true
      ∧ input.ciphertextPayloadHashesMatch = true := by
  have txLeafFacts :=
    tx_leaf_action_accepts_implies_binding_facts bindingAccepted
  rcases txLeafFacts with
    ⟨_hNullifiers, _hCommitments, _hCiphertextHashes, _hInputCount,
      _hOutputCount, _hVersion, _hFee, _hStablecoinPayload, _hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, hCiphertextPayloadHashes⟩
  exact
    ⟨surface.statementPreimage,
      canonical_statement_surface_statement_length surface,
      surface.bindingMessage,
      canonical_statement_surface_public_binding_valid surface,
      canonical_statement_surface_wrapper_preconditions surface,
      canonical_statement_surface_statement_surface surface,
      hReceiptStatementHash,
      hPublicInputsDigest,
      hProofDigest,
      hProofBackend,
      hCiphertextPayloadHashes⟩

theorem native_tx_leaf_accepted_artifact_statement_boundary_facts
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    NativeTxLeafAcceptedArtifactStatementBoundaryFacts
      input
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
  have boundaryAndNative :=
    native_tx_leaf_deployed_verifier_boundary_facts
      bindingAccepted
      surface
      sound
  rcases boundaryAndNative with
    ⟨canonicalFacts, txLeafPreconditions, txLeafFacts⟩
  rcases txLeafFacts with
    ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
      hOutputCount, hVersion, hFee, hStablecoinPayload, hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, hCiphertextPayloadHashes⟩
  exact
    { canonicalBoundaryFacts := canonicalFacts
      wrapperPreconditions := canonicalFacts.wrapperPreconditions
      publicBindingValid := canonicalFacts.publicBindingValid
      publicShapeValid := canonicalFacts.publicShapeValid
      statementLength := canonicalFacts.statementLength
      statementPreimage := canonicalFacts.statementPreimage
      bindingMessage := canonicalFacts.bindingMessage
      coreStatementBinding := canonicalFacts.coreStatementBinding
      vectorBinding := canonicalFacts.vectorBinding
      inputVectorBinding := canonicalFacts.inputVectorBinding
      outputVectorBinding := canonicalFacts.outputVectorBinding
      nativeStatementArtifactBinding :=
        ⟨hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
          hProofBackend, hCiphertextPayloadHashes⟩
      txLeafActionPreconditions := txLeafPreconditions
      txLeafActionBindingFacts :=
        ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
          hOutputCount, hVersion, hFee, hStablecoinPayload, hBalanceTag,
          hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
          hProofBackend, hCiphertextPayloadHashes⟩ }

theorem native_tx_leaf_canonical_artifact_boundary_facts
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId : Nat}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    NativeTxLeafCanonicalArtifactBoundaryFacts
      input
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
      assetId := by
  have boundaryAndNative :=
    native_tx_leaf_deployed_verifier_boundary_facts
      bindingAccepted
      surface
      sound
  rcases boundaryAndNative with
    ⟨canonicalFacts, txLeafPreconditions, txLeafFacts⟩
  have spendAndBalance :=
    canonical_boundary_facts_expose_spend_and_balance canonicalFacts
  have assetDelta :
      AuthorizedAssetDelta balanceWitness slots assetId :=
    accepted_transaction_relation_authorized_asset_delta
      canonicalFacts.acceptedTransactionRelation
  have statementRoot : statementFields.merkleRootSeed = merkleRoot := by
    rw [surface.statementMerkleRoot, ← surface.relationMerkleRoot]
  have bindingRoot : bindingFields.anchorSeed = merkleRoot := by
    rw [surface.bindingAnchor, ← surface.relationMerkleRoot]
  rcases txLeafFacts with
    ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
      hOutputCount, hVersion, hFee, hStablecoinPayload, hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, hCiphertextPayloadHashes⟩
  exact
    { canonicalBoundaryFacts := canonicalFacts
      wrapperSurface :=
        canonical_statement_surface_statement_surface surface
      rootBinding := ⟨statementRoot, bindingRoot⟩
      feeBinding :=
        ⟨surface.statementFee, surface.bindingFee⟩
      balanceSlotAssetBinding :=
        ⟨surface.shapeBalanceSlotAssets, surface.bindingBalanceSlotAssets,
          surface.statementBalanceSlotAssetsCount⟩
      stablecoinIdentityBinding :=
        ⟨surface.shapeStablecoinEnabled, surface.shapeStablecoinAsset,
          surface.shapeStablecoinIssuanceSign,
          surface.statementStablecoinEnabled, surface.statementStablecoinAsset,
          surface.statementStablecoinPolicyVersion,
          surface.statementStablecoinIssuanceSign,
          surface.statementStablecoinIssuanceMagnitude,
          surface.bindingStablecoinEnabled, surface.bindingStablecoinAsset,
          surface.bindingStablecoinPolicyVersion⟩
      txLeafActionPreconditions := txLeafPreconditions
      txLeafActionBindingFacts :=
        ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
          hOutputCount, hVersion, hFee, hStablecoinPayload, hBalanceTag,
          hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
          hProofBackend, hCiphertextPayloadHashes⟩
      spendAndBalance := spendAndBalance
      authorizedAssetDelta := assetDelta
      nativeStatementArtifactBinding :=
        ⟨hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
          hProofBackend, hCiphertextPayloadHashes⟩ }

theorem proof_keyed_transfer_payload_canonical_artifact_boundary_facts
    {payload : TransferPayloadInput}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId : Nat}
    (payloadAccepted : transferPayloadAccepts payload = true)
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    ProofKeyedNativeTxLeafCanonicalArtifactBoundaryFacts
      payload
      input
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
      assetId := by
  have payloadPreconditions :=
    transfer_payload_accepts_implies_preconditions payloadAccepted
  have payloadBindingFacts :=
    transfer_payload_accepts_implies_binding_facts payloadAccepted
  have nativeArtifactFacts :=
    native_tx_leaf_canonical_artifact_boundary_facts
      (assetId := assetId)
      bindingAccepted
      surface
      sound
  exact
    { transferPayloadPreconditions := payloadPreconditions
      transferPayloadBindingFacts := payloadBindingFacts
      proofKeyedPayload := payloadBindingFacts.right.left
      payloadBindingHashMatches := payloadBindingFacts.left
      nativeArtifactBoundary := nativeArtifactFacts }

theorem native_tx_leaf_binding_and_canonical_surface_authorizes_asset_delta
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId : Nat}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    AuthorizedAssetDelta balanceWitness slots assetId
      ∧ TxLeafActionBindingFacts input := by
  have relationFacts :=
    native_tx_leaf_binding_and_canonical_surface_implies_transaction_relation
      bindingAccepted
      surface
      sound
  exact
    ⟨accepted_transaction_relation_authorized_asset_delta
        relationFacts.left,
      relationFacts.right.right⟩

theorem native_tx_leaf_binding_and_canonical_surface_authorized_asset_delta_value
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId : Nat}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
    Hegemon.Transaction.slotDelta assetId slots =
        authorizedAssetDeltaValue balanceWitness assetId
      ∧ TxLeafActionBindingFacts input := by
  have relationFacts :=
    native_tx_leaf_binding_and_canonical_surface_implies_transaction_relation
      bindingAccepted
      surface
      sound
  exact
    ⟨accepted_transaction_relation_authorized_asset_delta_value
        relationFacts.left,
      relationFacts.right.right⟩

theorem native_tx_leaf_binding_and_canonical_surface_active_input_bound_to_statement
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
    Hegemon.Transaction.SpendAuthorization.InputSpendFacts
        merkleRoot
        publicNullifier
        witness
      ∧ statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ TxLeafActionBindingFacts input := by
  have boundFacts :=
    canonical_surface_authorized_active_input_bound_to_statement
      surface
      (sound surface).spendAuthorized
      slot
      active
  exact
    ⟨boundFacts.left,
      boundFacts.right.left,
      boundFacts.right.right.left,
      boundFacts.right.right.right.left,
      boundFacts.right.right.right.right,
      tx_leaf_action_accepts_implies_binding_facts bindingAccepted⟩

theorem native_tx_leaf_deployed_boundary_input_slot_facts
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness) :
    Hegemon.Transaction.SpendAuthorization.InputSlotAuthorizationFacts
        merkleRoot
        activeFlag
        publicNullifier
        witness
      ∧ statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ TxLeafActionBindingFacts input := by
  have boundaryAndNative :=
    native_tx_leaf_deployed_verifier_boundary_facts
      bindingAccepted
      surface
      sound
  rcases boundaryAndNative with
    ⟨canonicalFacts, _txLeafPreconditions, txLeafFacts⟩
  have slotFacts :=
    canonical_boundary_facts_input_slot_bound_to_statement
      canonicalFacts
      slot
  exact
    ⟨slotFacts.left,
      slotFacts.right.left,
      slotFacts.right.right.left,
      slotFacts.right.right.right.left,
      slotFacts.right.right.right.right,
      txLeafFacts⟩

theorem native_tx_leaf_canonical_artifact_boundary_input_slot_facts
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId : Nat}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (facts :
      NativeTxLeafCanonicalArtifactBoundaryFacts
        input
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
        assetId)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness) :
    Hegemon.Transaction.SpendAuthorization.InputSlotAuthorizationFacts
        merkleRoot
        activeFlag
        publicNullifier
        witness
      ∧ statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ TxLeafActionBindingFacts input := by
  have slotFacts :=
    canonical_boundary_facts_input_slot_bound_to_statement
      facts.canonicalBoundaryFacts
      slot
  exact
    ⟨slotFacts.left,
      slotFacts.right.left,
      slotFacts.right.right.left,
      slotFacts.right.right.right.left,
      slotFacts.right.right.right.right,
      facts.txLeafActionBindingFacts⟩

theorem native_tx_leaf_canonical_artifact_boundary_active_input_no_theft
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (facts :
      NativeTxLeafCanonicalArtifactBoundaryFacts
        input
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
        assetId)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
    Hegemon.Transaction.SpendAuthorization.InputSpendFacts
        merkleRoot
        publicNullifier
        witness
      ∧ proofWrapperPreconditions wrapper = true
      ∧ acceptedProofWrapperSurface wrapper
      ∧ Hegemon.Transaction.PublicInputBinding.validBinding
        publicFields
        serializedFields = true
      ∧ Hegemon.Transaction.StatementHash.statementPreimage
        statementFields = some statementBytes
      ∧ Hegemon.Transaction.ProofStatementBinding.bindingMessage
        bindingFields = some bindingBytes
      ∧ statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ input.nullifiersMatch = true
      ∧ input.inputCountMatches = true
      ∧ input.receiptStatementHashMatches = true
      ∧ input.publicInputsDigestMatches = true
      ∧ input.proofDigestMatches = true
      ∧ input.proofBackendMatches = true := by
  have slotFacts :=
    canonical_boundary_facts_input_slot_bound_to_statement
      facts.canonicalBoundaryFacts
      slot
  have spendFacts :
      Hegemon.Transaction.SpendAuthorization.InputSpendFacts
        merkleRoot
        publicNullifier
        witness :=
    slotFacts.left.left active
  rcases facts.txLeafActionBindingFacts with
    ⟨hNullifiers, _hCommitments, _hCiphertextHashes, hInputCount,
      _hOutputCount, _hVersion, _hFee, _hStablecoinPayload, _hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, _hCiphertextPayloadHashes⟩
  exact
    ⟨spendFacts,
      facts.canonicalBoundaryFacts.wrapperPreconditions,
      facts.wrapperSurface,
      facts.canonicalBoundaryFacts.publicBindingValid,
      facts.canonicalBoundaryFacts.statementPreimage,
      facts.canonicalBoundaryFacts.bindingMessage,
      slotFacts.right.left,
      slotFacts.right.right.left,
      slotFacts.right.right.right.left,
      slotFacts.right.right.right.right,
      hNullifiers,
      hInputCount,
      hReceiptStatementHash,
      hPublicInputsDigest,
      hProofDigest,
      hProofBackend⟩

theorem proof_keyed_transfer_payload_active_input_no_theft
    {payload : TransferPayloadInput}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (facts :
      ProofKeyedNativeTxLeafCanonicalArtifactBoundaryFacts
        payload
        input
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
        assetId)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
    Hegemon.Transaction.SpendAuthorization.InputSpendFacts
        merkleRoot
        publicNullifier
        witness
      ∧ payload.bindingHashMatches = true
      ∧ payload.proofBindingHashMatchesKey = true
      ∧ proofWrapperPreconditions wrapper = true
      ∧ acceptedProofWrapperSurface wrapper
      ∧ Hegemon.Transaction.StatementHash.statementPreimage
        statementFields = some statementBytes
      ∧ Hegemon.Transaction.ProofStatementBinding.bindingMessage
        bindingFields = some bindingBytes
      ∧ input.receiptStatementHashMatches = true
      ∧ input.publicInputsDigestMatches = true
      ∧ input.proofDigestMatches = true
      ∧ input.proofBackendMatches = true := by
  have noTheft :=
    native_tx_leaf_canonical_artifact_boundary_active_input_no_theft
      facts.nativeArtifactBoundary
      slot
      active
  rcases noTheft with
    ⟨spendFacts, wrapperPreconditions, wrapperSurface, _publicBindingValid,
      statementPreimage, bindingMessage, _statementRoot, _bindingRoot,
      _statementSlot, _bindingSlot, _nullifiers, _inputCount,
      receiptStatementHash, publicInputsDigest, proofDigest, proofBackend⟩
  exact
    ⟨spendFacts,
      facts.payloadBindingHashMatches,
      facts.proofKeyedPayload,
      wrapperPreconditions,
      wrapperSurface,
      statementPreimage,
      bindingMessage,
      receiptStatementHash,
      publicInputsDigest,
      proofDigest,
      proofBackend⟩

theorem proof_keyed_transfer_payload_active_input_no_theft_full_binding
    {payload : TransferPayloadInput}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (facts :
      ProofKeyedNativeTxLeafCanonicalArtifactBoundaryFacts
        payload
        input
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
        assetId)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness)
    (active : activeFlag = 1) :
    Hegemon.Transaction.SpendAuthorization.InputSpendFacts
        merkleRoot
        publicNullifier
        witness
      ∧ TransferPayloadBindingFacts payload
      ∧ payload.bindingHashMatches = true
      ∧ payload.proofBindingHashMatchesKey = true
      ∧ payload.feeMatches = true
      ∧ proofWrapperPreconditions wrapper = true
      ∧ acceptedProofWrapperSurface wrapper
      ∧ Hegemon.Transaction.PublicInputBinding.validBinding
        publicFields
        serializedFields = true
      ∧ Hegemon.Transaction.StatementHash.statementPreimage
        statementFields = some statementBytes
      ∧ Hegemon.Transaction.ProofStatementBinding.bindingMessage
        bindingFields = some bindingBytes
      ∧ statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ TxLeafActionBindingFacts input
      ∧ input.nullifiersMatch = true
      ∧ input.inputCountMatches = true
      ∧ input.feeMatches = true
      ∧ input.receiptStatementHashMatches = true
      ∧ input.publicInputsDigestMatches = true
      ∧ input.proofDigestMatches = true
      ∧ input.proofBackendMatches = true
      ∧ input.ciphertextPayloadHashesMatch = true := by
  have noTheft :=
    native_tx_leaf_canonical_artifact_boundary_active_input_no_theft
      facts.nativeArtifactBoundary
      slot
      active
  rcases noTheft with
    ⟨spendFacts, wrapperPreconditions, wrapperSurface,
      publicBindingValid, statementPreimage, bindingMessage,
      statementRoot, bindingRoot, statementSlot, bindingSlot,
      nullifiers, inputCount, receiptStatementHash,
      publicInputsDigest, proofDigest, proofBackend⟩
  rcases facts.transferPayloadBindingFacts with
    ⟨payloadBindingHash, proofBindingHash, payloadFee⟩
  rcases facts.nativeArtifactBoundary.txLeafActionBindingFacts with
    ⟨_hNullifiers, _hCommitments, _hCiphertextHashes, _hInputCount,
      _hOutputCount, _hVersion, hFee, _hStablecoinPayload, _hBalanceTag,
      _hReceiptStatementHash, _hPublicInputsDigest, _hProofDigest,
      _hProofBackend, hCiphertextPayloadHashes⟩
  exact
    ⟨spendFacts,
      facts.transferPayloadBindingFacts,
      payloadBindingHash,
      proofBindingHash,
      payloadFee,
      wrapperPreconditions,
      wrapperSurface,
      publicBindingValid,
      statementPreimage,
      bindingMessage,
      statementRoot,
      bindingRoot,
      statementSlot,
      bindingSlot,
      facts.nativeArtifactBoundary.txLeafActionBindingFacts,
      nullifiers,
      inputCount,
      hFee,
      receiptStatementHash,
      publicInputsDigest,
      proofDigest,
      proofBackend,
      hCiphertextPayloadHashes⟩

theorem proof_keyed_transfer_payload_input_slot_authorization_full_binding
    {payload : TransferPayloadInput}
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (facts :
      ProofKeyedNativeTxLeafCanonicalArtifactBoundaryFacts
        payload
        input
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
        assetId)
    (slot :
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness) :
    Hegemon.Transaction.SpendAuthorization.InputSlotAuthorizationFacts
        merkleRoot
        activeFlag
        publicNullifier
        witness
      ∧ TransferPayloadBindingFacts payload
      ∧ payload.bindingHashMatches = true
      ∧ payload.proofBindingHashMatchesKey = true
      ∧ payload.feeMatches = true
      ∧ proofWrapperPreconditions wrapper = true
      ∧ acceptedProofWrapperSurface wrapper
      ∧ Hegemon.Transaction.PublicInputBinding.validBinding
        publicFields
        serializedFields = true
      ∧ Hegemon.Transaction.StatementHash.statementPreimage
        statementFields = some statementBytes
      ∧ Hegemon.Transaction.ProofStatementBinding.bindingMessage
        bindingFields = some bindingBytes
      ∧ statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ TxLeafActionBindingFacts input
      ∧ input.nullifiersMatch = true
      ∧ input.inputCountMatches = true
      ∧ input.feeMatches = true
      ∧ input.receiptStatementHashMatches = true
      ∧ input.publicInputsDigestMatches = true
      ∧ input.proofDigestMatches = true
      ∧ input.proofBackendMatches = true
      ∧ input.ciphertextPayloadHashesMatch = true := by
  have slotFacts :=
    native_tx_leaf_canonical_artifact_boundary_input_slot_facts
      facts.nativeArtifactBoundary
      slot
  rcases slotFacts with
    ⟨inputSlotFacts, statementRoot, bindingRoot, statementSlot,
      bindingSlot, txLeafFacts⟩
  rcases facts.transferPayloadBindingFacts with
    ⟨payloadBindingHash, proofBindingHash, payloadFee⟩
  rcases txLeafFacts with
    ⟨hNullifiers, _hCommitments, _hCiphertextHashes, hInputCount,
      _hOutputCount, _hVersion, hFee, _hStablecoinPayload, _hBalanceTag,
      hReceiptStatementHash, hPublicInputsDigest, hProofDigest,
      hProofBackend, hCiphertextPayloadHashes⟩
  exact
    ⟨inputSlotFacts,
      facts.transferPayloadBindingFacts,
      payloadBindingHash,
      proofBindingHash,
      payloadFee,
      facts.nativeArtifactBoundary.canonicalBoundaryFacts.wrapperPreconditions,
      facts.nativeArtifactBoundary.wrapperSurface,
      facts.nativeArtifactBoundary.canonicalBoundaryFacts.publicBindingValid,
      facts.nativeArtifactBoundary.canonicalBoundaryFacts.statementPreimage,
      facts.nativeArtifactBoundary.canonicalBoundaryFacts.bindingMessage,
      statementRoot,
      bindingRoot,
      statementSlot,
      bindingSlot,
      facts.nativeArtifactBoundary.txLeafActionBindingFacts,
      hNullifiers,
      hInputCount,
      hFee,
      hReceiptStatementHash,
      hPublicInputsDigest,
      hProofDigest,
      hProofBackend,
      hCiphertextPayloadHashes⟩

theorem native_tx_leaf_binding_and_canonical_surface_input_slot_bound_to_statement
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses :
      List Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {index activeFlag : Nat}
    {publicNullifier : Digest}
    {witness : Hegemon.Transaction.SpendAuthorization.InputSpendWitness}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
      Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        shape.inputFlags
        shape.nullifiers
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness) :
    Hegemon.Transaction.SpendAuthorization.InputSlotAuthorizationFacts
        merkleRoot
        activeFlag
        publicNullifier
        witness
      ∧ statementFields.merkleRootSeed = merkleRoot
      ∧ bindingFields.anchorSeed = merkleRoot
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        statementFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ Hegemon.Transaction.SpendAuthorization.ActiveInputAt
        bound.inputFlags
        bindingFields.nullifierSeeds
        spendWitnesses
        index
        activeFlag
        publicNullifier
        witness
      ∧ TxLeafActionBindingFacts input := by
  have boundFacts :=
    canonical_surface_authorized_input_slot_bound_to_statement
      surface
      (sound surface).spendAuthorized
      slot
  exact
    ⟨boundFacts.left,
      boundFacts.right.left,
      boundFacts.right.right.left,
      boundFacts.right.right.right.left,
      boundFacts.right.right.right.right,
      tx_leaf_action_accepts_implies_binding_facts bindingAccepted⟩

theorem native_tx_leaf_binding_and_canonical_surface_output_slot_bound_to_statement
    {input : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields : Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields : Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields : Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {index activeFlag : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (bindingAccepted : txLeafActionBindingAccepts input = true)
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
      Hegemon.Transaction.PublicInputs.OutputSlotAt
        shape.outputFlags
        shape.commitments
        shape.ciphertextHashes
        index
        activeFlag
        publicCommitment
        publicCiphertextHash) :
    Hegemon.Transaction.PublicInputs.OutputSlotFacts
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ Hegemon.Transaction.PublicInputs.OutputSlotAt
        bound.outputFlags
        statementFields.commitmentSeeds
        statementFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ Hegemon.Transaction.PublicInputs.OutputSlotAt
        bound.outputFlags
        bindingFields.commitmentSeeds
        bindingFields.ciphertextHashSeeds
        index
        activeFlag
        publicCommitment
        publicCiphertextHash
      ∧ TxLeafActionBindingFacts input := by
  have boundFacts :=
    canonical_surface_output_slot_bound_to_statement
      surface
      slot
  exact
    ⟨boundFacts.left,
      boundFacts.right.left,
      boundFacts.right.right,
      tx_leaf_action_accepts_implies_binding_facts bindingAccepted⟩

end TxLeafCanonicalSurface
end Native
end Hegemon

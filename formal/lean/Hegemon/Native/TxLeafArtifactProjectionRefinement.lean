import Hegemon.Native.PendingActionBytePublicationRefinement
import Hegemon.Native.RawIngressPendingActionPublicationRefinement
import Hegemon.Native.TxLeafArtifact
import Hegemon.Transaction.ProofSystemBoundary

namespace Hegemon
namespace Native
namespace TxLeafArtifactProjectionRefinement

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.PendingActionBytePublicationRefinement
open Hegemon.Native.PendingActionReload
open Hegemon.Native.RawIngressPendingActionPublicationRefinement
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofSystemBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs
open Hegemon.Transaction.SpendAuthorization

private theorem readCappedU32_le
    {cap : Nat}
    {input rest : List Byte}
    {value : Nat}
    (h : readCappedU32 cap input = some (value, rest)) :
    value <= cap := by
  unfold readCappedU32 at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  rcases h with ⟨a, _hread, hif⟩
  by_cases hle : a.fst <= cap
  · simp [hle] at hif
    rw [← hif.left]
    exact hle
  · simp [hle] at hif

private theorem parseSerializedInputs_shape
    {input rest : List Byte}
    {summary : SerializedSummary}
    (h : parseSerializedInputs input = some (summary, rest)) :
    summary.inputFlagCount <= TxLeafArtifact.maxInputs
      ∧ summary.outputFlagCount <= TxLeafArtifact.maxOutputs
      ∧ summary.balanceSlotCount <= TxLeafArtifact.balanceSlots := by
  unfold parseSerializedInputs at h
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  rcases h with ⟨⟨inputFlagCount, rest0⟩, hInputCount, h⟩
  rcases h with ⟨rest1, _hRest1, h⟩
  rcases h with ⟨⟨outputFlagCount, rest2⟩, hOutputCount, h⟩
  rcases h with ⟨rest3, _hRest3, h⟩
  rcases h with ⟨rest4, _hRest4, h⟩
  rcases h with ⟨rest5, _hRest5, h⟩
  rcases h with ⟨rest6, _hRest6, h⟩
  rcases h with ⟨rest7, _hRest7, h⟩
  rcases h with ⟨⟨balanceSlotCount, rest8⟩, hBalanceCount, h⟩
  rcases h with ⟨rest9, _hRest9, h⟩
  rcases h with ⟨rest10, _hRest10, h⟩
  rcases h with ⟨rest11, _hRest11, h⟩
  rcases h with ⟨rest12, _hRest12, h⟩
  rcases h with ⟨rest13, _hRest13, h⟩
  rcases h with ⟨rest14, _hRest14, h⟩
  rcases h with ⟨rest15, _hRest15, hFinal⟩
  simp at hFinal
  rcases hFinal with ⟨hSummary, _hRest⟩
  cases hSummary
  exact
    ⟨readCappedU32_le hInputCount,
      readCappedU32_le hOutputCount,
      readCappedU32_le hBalanceCount⟩

private theorem parsePublicTx_shape
    {input rest : List Byte}
    {summary : PublicTxSummary}
    (h : parsePublicTx input = some (summary, rest)) :
    summary.nullifierCount <= TxLeafArtifact.maxInputs
      ∧ summary.commitmentCount <= TxLeafArtifact.maxOutputs
      ∧ summary.ciphertextHashCount <= TxLeafArtifact.maxOutputs := by
  unfold parsePublicTx at h
  simp [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  rcases h with
    ⟨nullifierCount, rest0, hNullifierCount, rest1, _hRest1,
      commitmentCount, rest2, hCommitmentCount, rest3, _hRest3,
      ciphertextHashCount, rest4, hCiphertextHashCount, rest5, _hRest5,
      rest6, _hRest6, circuitVersion, rest7, _hCircuit, cryptoSuite,
      rest8, _hSuite, _hSummary⟩
  exact
    ⟨readCappedU32_le hNullifierCount,
      readCappedU32_le hCommitmentCount,
      readCappedU32_le hCiphertextHashCount⟩

private theorem parseRows_coeffs_le
    {count : Nat}
    {input rest : List Byte}
    {rows : List Nat}
    (h : parseRows count input = some (rows, rest)) :
    ∀ coeffCount, coeffCount ∈ rows -> coeffCount <= matrixCols := by
  induction count generalizing input rows rest with
  | zero =>
      simp [parseRows] at h
      rcases h with ⟨hRows, _hRest⟩
      cases hRows
      intro coeffCount hmem
      simp at hmem
  | succ count ih =>
      simp [parseRows, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
      rcases h with
        ⟨coeffCount, rest0, hCoeff, rest1, _hRest1, tailRows,
          hTailParse, hRows⟩
      cases hRows
      intro value hmem
      simp at hmem
      rcases hmem with hHead | hTailMem
      · rw [hHead]
        exact readCappedU32_le hCoeff
      · exact ih (rows := tailRows) hTailParse value hTailMem

private theorem parseCommitment_shape
    {input rest : List Byte}
    {summary : CommitmentSummary}
    (h : parseCommitment input = some (summary, rest)) :
    summary.rowCount <= matrixRows
      ∧ (∀ coeffCount,
          coeffCount ∈ summary.rowCoeffCounts -> coeffCount <= matrixCols) := by
  unfold parseCommitment at h
  simp [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  rcases h with
    ⟨rest0, _hRest0, rowCount, rest1, hRowCount, rowCoeffCounts,
      hRows, hSummary⟩
  cases hSummary
  exact
    ⟨readCappedU32_le hRowCount,
      parseRows_coeffs_le hRows⟩

private theorem parseBackend_facts
    {defaultBackend : Nat}
    {input : List Byte}
    {hasExplicitBackend : Bool}
    {proofBackend : Nat}
    (h : parseBackend defaultBackend input =
      some (hasExplicitBackend, proofBackend)) :
    (hasExplicitBackend = true ∧ validBackendWire proofBackend = true)
      ∨ (hasExplicitBackend = false ∧ proofBackend = defaultBackend) := by
  cases input with
  | nil =>
      simp [parseBackend] at h
      exact Or.inr ⟨h.left, h.right.symm⟩
  | cons wire rest =>
      cases rest with
      | nil =>
          unfold parseBackend at h
          by_cases hValid : validBackendWire wire
          · simp [hValid] at h
            rcases h with ⟨hExplicit, hBackend⟩
            exact Or.inl
              ⟨hExplicit, by
                rw [← hBackend]
                exact hValid⟩
          · simp [hValid] at h
      | cons _second _more =>
          simp [parseBackend] at h

structure AcceptedNativeTxLeafArtifactByteShapeFacts
    (artifactBytes : List Byte)
    (summary : TxLeafSummary) : Prop where
  parsed :
    parseNativeTxLeafArtifact artifactBytes = some summary
  serializedInputFlagCountBound :
    summary.serialized.inputFlagCount <= TxLeafArtifact.maxInputs
  serializedOutputFlagCountBound :
    summary.serialized.outputFlagCount <= TxLeafArtifact.maxOutputs
  serializedBalanceSlotCountBound :
    summary.serialized.balanceSlotCount <= TxLeafArtifact.balanceSlots
  publicNullifierCountBound :
    summary.publicTx.nullifierCount <= TxLeafArtifact.maxInputs
  publicCommitmentCountBound :
    summary.publicTx.commitmentCount <= TxLeafArtifact.maxOutputs
  publicCiphertextHashCountBound :
    summary.publicTx.ciphertextHashCount <= TxLeafArtifact.maxOutputs
  starkProofLenBound :
    summary.starkProofLen <= maxNativeTxStarkProofBytes
  commitmentRowCountBound :
    summary.commitment.rowCount <= matrixRows
  commitmentRowCoeffCountBound :
    ∀ coeffCount,
      coeffCount ∈ summary.commitment.rowCoeffCounts ->
        coeffCount <= matrixCols
  backendExplicitOrDefault :
    (summary.hasExplicitBackend = true
        ∧ validBackendWire summary.proofBackend = true)
      ∨ (summary.hasExplicitBackend = false
        ∧ summary.proofBackend =
          defaultBackendForVersion
            summary.publicTx.circuitVersion
            summary.publicTx.cryptoSuite)

structure NativeTxLeafArtifactCanonicalProjectionAssumptions
    (summary : TxLeafSummary)
    (txLeaf : TxLeafActionBindingInput)
    (shape : PublicInputShape)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields) : Prop where
  serializedInputFlagsProject :
    summary.serialized.inputFlagCount = serializedFields.inputFlags.length
  serializedOutputFlagsProject :
    summary.serialized.outputFlagCount = serializedFields.outputFlags.length
  boundInputFlagsProject :
    serializedFields.inputFlags = bound.inputFlags
  boundOutputFlagsProject :
    serializedFields.outputFlags = bound.outputFlags
  shapeInputFlagsProject :
    shape.inputFlags = bound.inputFlags
  shapeOutputFlagsProject :
    shape.outputFlags = bound.outputFlags
  balanceSlotsProject :
    summary.serialized.balanceSlotCount = bound.balanceSlotAssets.length
  nullifierCountProjects :
    summary.publicTx.nullifierCount = statementFields.nullifierSeeds.length
  commitmentCountProjects :
    summary.publicTx.commitmentCount = statementFields.commitmentSeeds.length
  ciphertextHashCountProjects :
    summary.publicTx.ciphertextHashCount =
      statementFields.ciphertextHashSeeds.length
  bindingNullifiersProject :
    bindingFields.nullifierSeeds = statementFields.nullifierSeeds
  bindingCommitmentsProject :
    bindingFields.commitmentSeeds = statementFields.commitmentSeeds
  bindingCiphertextHashesProject :
    bindingFields.ciphertextHashSeeds =
      statementFields.ciphertextHashSeeds
  nativeVectorGates :
    txLeaf.nullifiersMatch = true
      ∧ txLeaf.commitmentsMatch = true
      ∧ txLeaf.ciphertextHashesMatch = true
      ∧ txLeaf.inputCountMatches = true
      ∧ txLeaf.outputCountMatches = true
  nativeScalarGates :
    txLeaf.versionMatches = true
      ∧ txLeaf.feeMatches = true
      ∧ txLeaf.stablecoinPayloadMatches = true
      ∧ txLeaf.balanceTagMatches = true
  nativeStatementProofGates :
    txLeaf.receiptStatementHashMatches = true
      ∧ txLeaf.publicInputsDigestMatches = true
      ∧ txLeaf.proofDigestMatches = true
      ∧ txLeaf.proofBackendMatches = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true

structure NativeTxLeafArtifactCanonicalVectorCountEvidence
    (summary : TxLeafSummary)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields :
      Hegemon.Transaction.StatementHash.StatementFields) : Prop where
  serializedInputFlagsProject :
    summary.serialized.inputFlagCount = serializedFields.inputFlags.length
  serializedOutputFlagsProject :
    summary.serialized.outputFlagCount = serializedFields.outputFlags.length
  balanceSlotsProject :
    summary.serialized.balanceSlotCount = bound.balanceSlotAssets.length
  nullifierCountProjects :
    summary.publicTx.nullifierCount = statementFields.nullifierSeeds.length
  commitmentCountProjects :
    summary.publicTx.commitmentCount = statementFields.commitmentSeeds.length
  ciphertextHashCountProjects :
    summary.publicTx.ciphertextHashCount =
      statementFields.ciphertextHashSeeds.length

structure ParsedTxLeafArtifactSerializedPublicVectorFacts
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (shape : PublicInputShape)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields :
      Hegemon.Transaction.StatementHash.StatementFields)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields) : Prop where
  artifactByteShapeFacts :
    AcceptedNativeTxLeafArtifactByteShapeFacts
      artifactBytes
      summary
  serializedInputFlagsProject :
    summary.serialized.inputFlagCount = serializedFields.inputFlags.length
  serializedOutputFlagsProject :
    summary.serialized.outputFlagCount = serializedFields.outputFlags.length
  boundInputFlagsProject :
    serializedFields.inputFlags = bound.inputFlags
  boundOutputFlagsProject :
    serializedFields.outputFlags = bound.outputFlags
  shapeInputFlagsProject :
    shape.inputFlags = bound.inputFlags
  shapeOutputFlagsProject :
    shape.outputFlags = bound.outputFlags
  balanceSlotsProject :
    summary.serialized.balanceSlotCount = bound.balanceSlotAssets.length
  nullifierCountProjects :
    summary.publicTx.nullifierCount = statementFields.nullifierSeeds.length
  commitmentCountProjects :
    summary.publicTx.commitmentCount = statementFields.commitmentSeeds.length
  ciphertextHashCountProjects :
    summary.publicTx.ciphertextHashCount =
      statementFields.ciphertextHashSeeds.length
  bindingNullifiersProject :
    bindingFields.nullifierSeeds = statementFields.nullifierSeeds
  bindingCommitmentsProject :
    bindingFields.commitmentSeeds = statementFields.commitmentSeeds
  bindingCiphertextHashesProject :
    bindingFields.ciphertextHashSeeds =
      statementFields.ciphertextHashSeeds

structure ParsedTxLeafArtifactNativeBindingGateFacts
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (txLeaf : TxLeafActionBindingInput) : Prop where
  artifactByteShapeFacts :
    AcceptedNativeTxLeafArtifactByteShapeFacts
      artifactBytes
      summary
  nativeVectorGates :
    txLeaf.nullifiersMatch = true
      ∧ txLeaf.commitmentsMatch = true
      ∧ txLeaf.ciphertextHashesMatch = true
      ∧ txLeaf.inputCountMatches = true
      ∧ txLeaf.outputCountMatches = true
  nativeScalarGates :
    txLeaf.versionMatches = true
      ∧ txLeaf.feeMatches = true
      ∧ txLeaf.stablecoinPayloadMatches = true
      ∧ txLeaf.balanceTagMatches = true
  nativeStatementProofGates :
    txLeaf.receiptStatementHashMatches = true
      ∧ txLeaf.publicInputsDigestMatches = true
      ∧ txLeaf.proofDigestMatches = true
      ∧ txLeaf.proofBackendMatches = true
      ∧ txLeaf.ciphertextPayloadHashesMatch = true

structure ParsedNativeTxLeafArtifactCanonicalFacts
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (txLeaf : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest) : Prop where
  artifactByteShapeFacts :
    AcceptedNativeTxLeafArtifactByteShapeFacts
      artifactBytes
      summary
  projectionAssumptions :
    NativeTxLeafArtifactCanonicalProjectionAssumptions
      summary
      txLeaf
      shape
      serializedFields
      bound
      statementFields
      bindingFields
  txLeafAccepted :
    txLeafActionBindingAccepts txLeaf = true
  txLeafFullStatementArtifactFacts :
    NativeTxLeafFullStatementArtifactFacts
      txLeaf
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

structure ParsedNativeTxLeafCanonicalArtifactBoundaryFacts
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (txLeaf : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest)
    (spendWitnesses : List InputSpendWitness)
    (balanceWitness : Hegemon.Transaction.BalanceWitness)
    (slots : List Hegemon.Transaction.BalanceSlot)
    (assetId : Nat) : Prop where
  parsedCanonicalFacts :
    ParsedNativeTxLeafArtifactCanonicalFacts
      artifactBytes
      summary
      txLeaf
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
  canonicalArtifactBoundaryFacts :
    NativeTxLeafCanonicalArtifactBoundaryFacts
      txLeaf
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

structure ParsedPendingActionByteTxLeafPublicationFacts
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (pendingReload : PendingActionReloadInput)
    (actionHash : AdmissionInput)
    (wireProjection :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionInput)
    (wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (txLeaf : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest) : Prop where
  txLeafPublicationFacts :
    PendingActionByteTxLeafPublicationFacts
      pendingDecode
      blockActionDecode
      pendingReload
      actionHash
      wireProjection
      wireOutput
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
      txLeaf
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
  parsedCanonicalFacts :
    ParsedNativeTxLeafArtifactCanonicalFacts
      artifactBytes
      summary
      txLeaf
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

structure ParsedRawIngressPendingActionTxLeafPublicationFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (artifactBytes : List Byte)
    (summary : TxLeafSummary)
    (txLeaf : TxLeafActionBindingInput)
    (wrapper : ProofWrapperInput)
    (shape : PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields : Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Digest) : Prop where
  rawIngressTxLeafPublicationFacts :
    RawIngressPendingActionTxLeafPublicationFacts
      surface
      pendingDecode
      blockActionDecode
      actionHash
      wireOutput
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
      txLeaf
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
  parsedCanonicalFacts :
    ParsedNativeTxLeafArtifactCanonicalFacts
      artifactBytes
      summary
      txLeaf
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

theorem accepted_native_tx_leaf_artifact_bytes_expose_shape_facts
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary) :
    AcceptedNativeTxLeafArtifactByteShapeFacts
      artifactBytes
      summary := by
  have parsedOriginal := parsed
  unfold parseNativeTxLeafArtifact at parsed
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at parsed
  rcases parsed with
    ⟨⟨version, rest0⟩, _hVersion, rest1, _hRest1, rest2, _hRest2,
      rest3, _hRest3, rest4, _hRest4, rest5, _hRest5, rest6,
      _hRest6, ⟨serialized, rest7⟩, hSerialized, ⟨publicTx, rest8⟩,
      hPublicTx, ⟨starkProofLen, rest9⟩, hStarkProofLen, rest10,
      _hRest10, ⟨commitment, rest11⟩, hCommitment,
      ⟨leafVersion, rest12⟩, _hLeaf,
      ⟨hasExplicitBackend, proofBackend⟩, hBackend, hSummary⟩
  simp at hSummary
  cases hSummary
  have serializedFacts := parseSerializedInputs_shape hSerialized
  have publicTxFacts := parsePublicTx_shape hPublicTx
  have commitmentFacts := parseCommitment_shape hCommitment
  exact
    { parsed := parsedOriginal
      serializedInputFlagCountBound := serializedFacts.left
      serializedOutputFlagCountBound := serializedFacts.right.left
      serializedBalanceSlotCountBound := serializedFacts.right.right
      publicNullifierCountBound := publicTxFacts.left
      publicCommitmentCountBound := publicTxFacts.right.left
      publicCiphertextHashCountBound := publicTxFacts.right.right
      starkProofLenBound := readCappedU32_le hStarkProofLen
      commitmentRowCountBound := commitmentFacts.left
      commitmentRowCoeffCountBound := commitmentFacts.right
      backendExplicitOrDefault := parseBackend_facts hBackend }

theorem tx_leaf_projection_assumptions_accept_binding
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {shape : PublicInputShape}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    (projection :
      NativeTxLeafArtifactCanonicalProjectionAssumptions
        summary
        txLeaf
        shape
        serializedFields
        bound
        statementFields
        bindingFields) :
    txLeafActionBindingAccepts txLeaf = true := by
  rw [tx_leaf_action_accepts_iff_preconditions]
  rcases projection.nativeVectorGates with
    ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
      hOutputCount⟩
  rcases projection.nativeScalarGates with
    ⟨hVersion, hFee, hStablecoin, hBalanceTag⟩
  rcases projection.nativeStatementProofGates with
    ⟨hReceipt, hPublicInputs, hProofDigest, hProofBackend,
      hCiphertextPayload⟩
  simp [txLeafActionBindingPreconditions, hNullifiers, hCommitments,
    hCiphertextHashes, hInputCount, hOutputCount, hVersion, hFee,
    hStablecoin, hBalanceTag, hReceipt, hPublicInputs, hProofDigest,
    hProofBackend, hCiphertextPayload]

theorem parsed_tx_leaf_artifact_projects_serialized_public_vectors
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (counts :
      NativeTxLeafArtifactCanonicalVectorCountEvidence
        summary
        serializedFields
        bound
        statementFields)
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
    ParsedTxLeafArtifactSerializedPublicVectorFacts
      artifactBytes
      summary
      shape
      serializedFields
      bound
      statementFields
      bindingFields := by
  have byteFacts :=
    accepted_native_tx_leaf_artifact_bytes_expose_shape_facts parsed
  have p3Facts :=
    canonical_statement_surface_p3_public_input_binding_facts surface
  exact
    { artifactByteShapeFacts := byteFacts
      serializedInputFlagsProject :=
        counts.serializedInputFlagsProject
      serializedOutputFlagsProject :=
        counts.serializedOutputFlagsProject
      boundInputFlagsProject := p3Facts.boundInputFlags.symm
      boundOutputFlagsProject := p3Facts.boundOutputFlags.symm
      shapeInputFlagsProject := surface.shapeInputFlags
      shapeOutputFlagsProject := surface.shapeOutputFlags
      balanceSlotsProject := counts.balanceSlotsProject
      nullifierCountProjects := counts.nullifierCountProjects
      commitmentCountProjects := counts.commitmentCountProjects
      ciphertextHashCountProjects :=
        counts.ciphertextHashCountProjects
      bindingNullifiersProject := surface.bindingNullifiers
      bindingCommitmentsProject := surface.bindingCommitments
      bindingCiphertextHashesProject := surface.bindingCiphertextHashes }

theorem parsed_tx_leaf_artifact_projects_native_binding_gates
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (accepted : txLeafActionBindingAccepts txLeaf = true) :
    ParsedTxLeafArtifactNativeBindingGateFacts
      artifactBytes
      summary
      txLeaf := by
  have byteFacts :=
    accepted_native_tx_leaf_artifact_bytes_expose_shape_facts parsed
  have gateFacts :=
    tx_leaf_action_accepts_implies_binding_facts accepted
  rcases gateFacts with
    ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
      hOutputCount, hVersion, hFee, hStablecoin, hBalanceTag,
      hReceipt, hPublicInputs, hProofDigest, hProofBackend,
      hCiphertextPayload⟩
  exact
    { artifactByteShapeFacts := byteFacts
      nativeVectorGates :=
        ⟨hNullifiers, hCommitments, hCiphertextHashes, hInputCount,
          hOutputCount⟩
      nativeScalarGates :=
        ⟨hVersion, hFee, hStablecoin, hBalanceTag⟩
      nativeStatementProofGates :=
        ⟨hReceipt, hPublicInputs, hProofDigest, hProofBackend,
          hCiphertextPayload⟩ }

theorem accepted_native_tx_leaf_artifact_derives_canonical_projection_assumptions
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (counts :
      NativeTxLeafArtifactCanonicalVectorCountEvidence
        summary
        serializedFields
        bound
        statementFields)
    (accepted : txLeafActionBindingAccepts txLeaf = true)
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
    NativeTxLeafArtifactCanonicalProjectionAssumptions
      summary
      txLeaf
      shape
      serializedFields
      bound
      statementFields
      bindingFields := by
  have vectorFacts :=
    parsed_tx_leaf_artifact_projects_serialized_public_vectors
      parsed
      counts
      surface
  have gateFacts :=
    parsed_tx_leaf_artifact_projects_native_binding_gates
      parsed
      accepted
  exact
    { serializedInputFlagsProject :=
        vectorFacts.serializedInputFlagsProject
      serializedOutputFlagsProject :=
        vectorFacts.serializedOutputFlagsProject
      boundInputFlagsProject := vectorFacts.boundInputFlagsProject
      boundOutputFlagsProject := vectorFacts.boundOutputFlagsProject
      shapeInputFlagsProject := vectorFacts.shapeInputFlagsProject
      shapeOutputFlagsProject := vectorFacts.shapeOutputFlagsProject
      balanceSlotsProject := vectorFacts.balanceSlotsProject
      nullifierCountProjects := vectorFacts.nullifierCountProjects
      commitmentCountProjects := vectorFacts.commitmentCountProjects
      ciphertextHashCountProjects :=
        vectorFacts.ciphertextHashCountProjects
      bindingNullifiersProject := vectorFacts.bindingNullifiersProject
      bindingCommitmentsProject := vectorFacts.bindingCommitmentsProject
      bindingCiphertextHashesProject :=
        vectorFacts.bindingCiphertextHashesProject
      nativeVectorGates := gateFacts.nativeVectorGates
      nativeScalarGates := gateFacts.nativeScalarGates
      nativeStatementProofGates :=
        gateFacts.nativeStatementProofGates }

theorem accepted_native_tx_leaf_artifact_projection_binds_full_statement_artifact
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (projection :
      NativeTxLeafArtifactCanonicalProjectionAssumptions
        summary
        txLeaf
        shape
        serializedFields
        bound
        statementFields
        bindingFields)
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
    ParsedNativeTxLeafArtifactCanonicalFacts
      artifactBytes
      summary
      txLeaf
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot := by
  have byteFacts :=
    accepted_native_tx_leaf_artifact_bytes_expose_shape_facts parsed
  have txLeafAccepted :=
    tx_leaf_projection_assumptions_accept_binding projection
  have txLeafFacts :=
    native_tx_leaf_binding_and_canonical_surface_full_statement_artifact_facts
      txLeafAccepted
      surface
  exact
    { artifactByteShapeFacts := byteFacts
      projectionAssumptions := projection
      txLeafAccepted := txLeafAccepted
      txLeafFullStatementArtifactFacts := txLeafFacts }

theorem accepted_native_tx_leaf_artifact_binds_full_statement_artifact_from_derived_projection
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (counts :
      NativeTxLeafArtifactCanonicalVectorCountEvidence
        summary
        serializedFields
        bound
        statementFields)
    (accepted : txLeafActionBindingAccepts txLeaf = true)
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
    ParsedNativeTxLeafArtifactCanonicalFacts
      artifactBytes
      summary
      txLeaf
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot := by
  have projection :=
    accepted_native_tx_leaf_artifact_derives_canonical_projection_assumptions
      parsed
      counts
      accepted
      surface
  have byteFacts :=
    accepted_native_tx_leaf_artifact_bytes_expose_shape_facts parsed
  have txLeafFacts :=
    native_tx_leaf_binding_and_canonical_surface_full_statement_artifact_facts
      accepted
      surface
  exact
    { artifactByteShapeFacts := byteFacts
      projectionAssumptions := projection
      txLeafAccepted := accepted
      txLeafFullStatementArtifactFacts := txLeafFacts }

theorem accepted_native_tx_leaf_artifact_projection_binds_canonical_artifact_boundary_facts
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    {assetId : Nat}
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (projection :
      NativeTxLeafArtifactCanonicalProjectionAssumptions
        summary
        txLeaf
        shape
        serializedFields
        bound
        statementFields
        bindingFields)
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
    (deployedSoundness :
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
    ParsedNativeTxLeafCanonicalArtifactBoundaryFacts
      artifactBytes
      summary
      txLeaf
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
  have parsedCanonicalFacts :=
    accepted_native_tx_leaf_artifact_projection_binds_full_statement_artifact
      parsed
      projection
      surface
  have canonicalArtifactBoundaryFacts :=
    native_tx_leaf_canonical_artifact_boundary_facts
      (assetId := assetId)
      parsedCanonicalFacts.txLeafAccepted
      surface
      deployedSoundness
  exact
    { parsedCanonicalFacts := parsedCanonicalFacts
      canonicalArtifactBoundaryFacts := canonicalArtifactBoundaryFacts }

theorem accepted_pending_action_bytes_bind_parsed_tx_leaf_publication
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReloadInput}
    {actionHash : AdmissionInput}
    {wireProjection :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionInput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (pendingReloadAccepted :
      pendingActionReloadAccepts pendingReload = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireProjectionAccepted :
      ActionWireReplayProjectionAdmission.evaluateActionWireReplayProjection
        wireProjection =
          Except.ok wireOutput)
    (wireActionCountMatchesDeclared :
      wireProjection.actionCount =
        blockActionDecode.declaredTxCount)
    (blockIndexAccepted : blockIndexReloadAccepts blockIndex = true)
    (canonicalStateAccepted :
      canonicalStateReloadAccepts canonicalState = true)
    (canonicalReorgAccepted :
      canonicalReorgChainAccepts reorgChain = true)
    (atomicCommitAccepted :
      atomicCommitManifestAccepts commitManifest = true)
    (durabilityAccepted :
      storageDurabilityAccepts durability = true)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final)
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (projection :
      NativeTxLeafArtifactCanonicalProjectionAssumptions
        summary
        txLeaf
        shape
        serializedFields
        bound
        statementFields
        bindingFields)
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
    ParsedPendingActionByteTxLeafPublicationFacts
      pendingDecode
      blockActionDecode
      pendingReload
      actionHash
      wireProjection
      wireOutput
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
      artifactBytes
      summary
      txLeaf
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot := by
  have parsedCanonicalFacts :=
    accepted_native_tx_leaf_artifact_projection_binds_full_statement_artifact
      parsed
      projection
      surface
  have txLeafPublicationFacts :=
    accepted_pending_action_bytes_bind_tx_leaf_publication
      pendingDecodeAccepted
      blockActionDecodeAccepted
      pendingReloadAccepted
      actionHashAccepted
      wireProjectionAccepted
      wireActionCountMatchesDeclared
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
      parsedCanonicalFacts.txLeafAccepted
      surface
  exact
    { txLeafPublicationFacts := txLeafPublicationFacts
      parsedCanonicalFacts := parsedCanonicalFacts }

theorem accepted_raw_ingress_pending_action_bytes_bind_parsed_tx_leaf_publication
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    (rawIngressFacts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireActionCountMatchesDeclared :
      surface.daSidecarReplay.wireReplayProjection.actionCount =
        blockActionDecode.declaredTxCount)
    (blockIndexAccepted : blockIndexReloadAccepts blockIndex = true)
    (canonicalStateAccepted :
      canonicalStateReloadAccepts canonicalState = true)
    (canonicalReorgAccepted :
      canonicalReorgChainAccepts reorgChain = true)
    (atomicCommitAccepted :
      atomicCommitManifestAccepts commitManifest = true)
    (durabilityAccepted :
      storageDurabilityAccepts durability = true)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final)
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (projection :
      NativeTxLeafArtifactCanonicalProjectionAssumptions
        summary
        txLeaf
        shape
        serializedFields
        bound
        statementFields
        bindingFields)
    (canonicalSurface :
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
    ParsedRawIngressPendingActionTxLeafPublicationFacts
      surface
      pendingDecode
      blockActionDecode
      actionHash
      wireOutput
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
      artifactBytes
      summary
      txLeaf
      wrapper
      shape
      publicFields
      serializedFields
      bound
      statementFields
      statementBytes
      bindingFields
      bindingBytes
      merkleRoot := by
  have parsedCanonicalFacts :=
    accepted_native_tx_leaf_artifact_projection_binds_full_statement_artifact
      parsed
      projection
      canonicalSurface
  have rawTxLeafFacts :=
    accepted_raw_ingress_pending_action_bytes_bind_tx_leaf_publication
      rawIngressFacts
      sidecarRoute
      pendingDecodeAccepted
      blockActionDecodeAccepted
      actionHashAccepted
      wireActionCountMatchesDeclared
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
      parsedCanonicalFacts.txLeafAccepted
      canonicalSurface
  exact
    { rawIngressTxLeafPublicationFacts := rawTxLeafFacts
      parsedCanonicalFacts := parsedCanonicalFacts }

theorem accepted_raw_ingress_pending_action_bytes_bind_parsed_tx_leaf_deployed_boundary_facts
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    {balanceWitness : Hegemon.Transaction.BalanceWitness}
    {slots : List Hegemon.Transaction.BalanceSlot}
    (rawIngressFacts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireActionCountMatchesDeclared :
      surface.daSidecarReplay.wireReplayProjection.actionCount =
        blockActionDecode.declaredTxCount)
    (blockIndexAccepted : blockIndexReloadAccepts blockIndex = true)
    (canonicalStateAccepted :
      canonicalStateReloadAccepts canonicalState = true)
    (canonicalReorgAccepted :
      canonicalReorgChainAccepts reorgChain = true)
    (atomicCommitAccepted :
      atomicCommitManifestAccepts commitManifest = true)
    (durabilityAccepted :
      storageDurabilityAccepts durability = true)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final)
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (projection :
      NativeTxLeafArtifactCanonicalProjectionAssumptions
        summary
        txLeaf
        shape
        serializedFields
        bound
        statementFields
        bindingFields)
    (canonicalSurface :
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
    (deployedSoundness :
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
    ParsedRawIngressPendingActionTxLeafPublicationFacts
      surface
      pendingDecode
      blockActionDecode
      actionHash
      wireOutput
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
      artifactBytes
      summary
      txLeaf
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
      ∧ CanonicalDeployedVerifierBoundaryFacts
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
  have parsedPublicationFacts :=
    accepted_raw_ingress_pending_action_bytes_bind_parsed_tx_leaf_publication
      rawIngressFacts
      sidecarRoute
      pendingDecodeAccepted
      blockActionDecodeAccepted
      actionHashAccepted
      wireActionCountMatchesDeclared
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
      parsed
      projection
      canonicalSurface
  have boundaryFacts :=
    deployed_soundness_canonical_surface_implies_boundary_facts
      canonicalSurface
      deployedSoundness
  exact ⟨parsedPublicationFacts, boundaryFacts⟩

theorem accepted_raw_ingress_pending_action_bytes_bind_parsed_tx_leaf_spend_boundary_facts
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamEffect.ActionStreamOutput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {spendWitnesses : List InputSpendWitness}
    (rawIngressFacts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireActionCountMatchesDeclared :
      surface.daSidecarReplay.wireReplayProjection.actionCount =
        blockActionDecode.declaredTxCount)
    (blockIndexAccepted : blockIndexReloadAccepts blockIndex = true)
    (canonicalStateAccepted :
      canonicalStateReloadAccepts canonicalState = true)
    (canonicalReorgAccepted :
      canonicalReorgChainAccepts reorgChain = true)
    (atomicCommitAccepted :
      atomicCommitManifestAccepts commitManifest = true)
    (durabilityAccepted :
      storageDurabilityAccepts durability = true)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final)
    (parsed :
      parseNativeTxLeafArtifact artifactBytes = some summary)
    (projection :
      NativeTxLeafArtifactCanonicalProjectionAssumptions
        summary
        txLeaf
        shape
        serializedFields
        bound
        statementFields
        bindingFields)
    (canonicalSurface :
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
    (spendSoundness :
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
    ParsedRawIngressPendingActionTxLeafPublicationFacts
      surface
      pendingDecode
      blockActionDecode
      actionHash
      wireOutput
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
      artifactBytes
      summary
      txLeaf
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
      ∧ CanonicalDeployedVerifierSpendBoundaryFacts
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
  have parsedPublicationFacts :=
    accepted_raw_ingress_pending_action_bytes_bind_parsed_tx_leaf_publication
      rawIngressFacts
      sidecarRoute
      pendingDecodeAccepted
      blockActionDecodeAccepted
      actionHashAccepted
      wireActionCountMatchesDeclared
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
      parsed
      projection
      canonicalSurface
  have boundaryFacts :=
    spend_soundness_canonical_surface_implies_spend_boundary_facts
      canonicalSurface
      spendSoundness
  exact ⟨parsedPublicationFacts, boundaryFacts⟩

end TxLeafArtifactProjectionRefinement
end Native
end Hegemon

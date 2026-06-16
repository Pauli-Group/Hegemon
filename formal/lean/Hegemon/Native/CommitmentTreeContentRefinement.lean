import Hegemon.Native.CommitmentTreeRefinement
import Hegemon.Native.RawIngressFullBytePublicationSurface

namespace Hegemon
namespace Native
namespace CommitmentTreeContentRefinement

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.PendingActionByteReplayRowCountBinding
open Hegemon.Native.RawIngressFullBytePublicationSurface
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafArtifactProjectionRefinement
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.ActionHashAdmission
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

def commitmentIndexesFrom : Nat -> List Nat -> List Nat
  | _start, [] => []
  | start, _commitment :: rest =>
      start :: commitmentIndexesFrom (start + 1) rest

def orderedDecodedCommitments
    (rows : List PendingActionFieldProjectionRow) : List Nat :=
  flattenRows (rows.map (fun row => row.commitments))

def orderedDecodedCommitmentIndexes
    (rows : List PendingActionFieldProjectionRow) : List Nat :=
  flattenRows
    (rows.map
      (fun row =>
        commitmentIndexesFrom row.commitmentStart row.commitments))

def orderedDecodedNullifiers
    (rows : List PendingActionFieldProjectionRow) : List Nat :=
  flattenRows (rows.map (fun row => row.nullifiers))

def orderedPlannedBridgeReplayKeys
    (rows : List PendingActionFieldProjectionRow) : List Nat :=
  rows.filterMap (fun row => row.bridgeReplayKey)

theorem rowsWithOffsets_values
    (start : Nat)
    (values : List Nat) :
    (rowsWithOffsets start values).map (fun entry => entry.2) =
      values := by
  induction values generalizing start with
  | nil =>
      rfl
  | cons value rest ih =>
      simp [rowsWithOffsets, ih]

theorem rowsWithOffsets_indexes
    (start : Nat)
    (values : List Nat) :
    (rowsWithOffsets start values).map (fun entry => entry.1) =
      commitmentIndexesFrom start values := by
  induction values generalizing start with
  | nil =>
      rfl
  | cons value rest ih =>
      simp [rowsWithOffsets, commitmentIndexesFrom, ih]

theorem projectedCommitmentRows_values
    (rows : List PendingActionFieldProjectionRow) :
    (projectedCommitmentRows rows).map (fun entry => entry.2) =
      orderedDecodedCommitments rows := by
  induction rows with
  | nil =>
      rfl
  | cons row rest ih =>
      simpa [
        projectedCommitmentRows,
        orderedDecodedCommitments,
        flattenRows,
        rowsWithOffsets_values
      ] using ih

theorem projectedCommitmentRows_indexes
    (rows : List PendingActionFieldProjectionRow) :
    (projectedCommitmentRows rows).map (fun entry => entry.1) =
      orderedDecodedCommitmentIndexes rows := by
  induction rows with
  | nil =>
      rfl
  | cons row rest ih =>
      simpa [
        projectedCommitmentRows,
        orderedDecodedCommitmentIndexes,
        flattenRows,
        rowsWithOffsets_indexes
      ] using ih

theorem projectedCommitmentRows_length
    (rows : List PendingActionFieldProjectionRow) :
    (projectedCommitmentRows rows).length =
      (orderedDecodedCommitments rows).length := by
  rw [← projectedCommitmentRows_values rows]
  simp

theorem projectedNullifierRows_values
    (rows : List PendingActionFieldProjectionRow) :
    projectedNullifierRows rows =
      orderedDecodedNullifiers rows := by
  rfl

theorem projectedNullifierRows_length
    (rows : List PendingActionFieldProjectionRow) :
    (projectedNullifierRows rows).length =
      (orderedDecodedNullifiers rows).length := by
  rw [projectedNullifierRows_values rows]

theorem projectedBridgeReplayRows_eq_planned_replay_keys
    (rows : List PendingActionFieldProjectionRow) :
    projectedBridgeReplayRows rows =
      orderedPlannedBridgeReplayKeys rows := by
  rfl

theorem projectedBridgeReplayRows_length
    (rows : List PendingActionFieldProjectionRow) :
    (projectedBridgeReplayRows rows).length =
      (orderedPlannedBridgeReplayKeys rows).length := by
  rw [projectedBridgeReplayRows_eq_planned_replay_keys rows]

theorem canonical_commitment_rows_bind_ordered_decoded_content
    {decodedRows : List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (canonicalCommitmentRowsMatchDecoded :
      canonicalRows.commitmentRows =
        projectedCommitmentRows decodedRows) :
    canonicalRows.commitmentRows.map (fun entry => entry.2) =
      orderedDecodedCommitments decodedRows := by
  rw [canonicalCommitmentRowsMatchDecoded]
  exact projectedCommitmentRows_values decodedRows

theorem canonical_commitment_rows_bind_ordered_decoded_indexes
    {decodedRows : List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (canonicalCommitmentRowsMatchDecoded :
      canonicalRows.commitmentRows =
        projectedCommitmentRows decodedRows) :
    canonicalRows.commitmentRows.map (fun entry => entry.1) =
      orderedDecodedCommitmentIndexes decodedRows := by
  rw [canonicalCommitmentRowsMatchDecoded]
  exact projectedCommitmentRows_indexes decodedRows

theorem canonical_commitment_rows_bind_ordered_decoded_length
    {decodedRows : List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (canonicalCommitmentRowsMatchDecoded :
      canonicalRows.commitmentRows =
        projectedCommitmentRows decodedRows) :
    canonicalRows.commitmentRows.length =
      (orderedDecodedCommitments decodedRows).length := by
  rw [canonicalCommitmentRowsMatchDecoded]
  exact projectedCommitmentRows_length decodedRows

theorem canonical_nullifier_rows_bind_ordered_decoded_content
    {decodedRows : List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (canonicalNullifierRowsMatchDecoded :
      canonicalRows.nullifierRows =
        projectedNullifierRows decodedRows) :
    canonicalRows.nullifierRows =
      orderedDecodedNullifiers decodedRows := by
  rw [canonicalNullifierRowsMatchDecoded]
  exact projectedNullifierRows_values decodedRows

theorem canonical_nullifier_rows_bind_ordered_decoded_length
    {decodedRows : List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (canonicalNullifierRowsMatchDecoded :
      canonicalRows.nullifierRows =
        projectedNullifierRows decodedRows) :
    canonicalRows.nullifierRows.length =
      (orderedDecodedNullifiers decodedRows).length := by
  rw [canonicalNullifierRowsMatchDecoded]
  exact projectedNullifierRows_length decodedRows

theorem canonical_bridge_replay_rows_bind_planned_replay_keys
    {plannedRows : List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (canonicalBridgeReplayRowsMatchPlanned :
      canonicalRows.bridgeReplayRows =
        projectedBridgeReplayRows plannedRows) :
    canonicalRows.bridgeReplayRows =
      orderedPlannedBridgeReplayKeys plannedRows := by
  rw [canonicalBridgeReplayRowsMatchPlanned]
  exact projectedBridgeReplayRows_eq_planned_replay_keys plannedRows

theorem canonical_bridge_replay_rows_bind_planned_replay_count
    {plannedRows : List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (canonicalBridgeReplayRowsMatchPlanned :
      canonicalRows.bridgeReplayRows =
        projectedBridgeReplayRows plannedRows) :
    canonicalRows.bridgeReplayRows.length =
      (orderedPlannedBridgeReplayKeys plannedRows).length := by
  rw [canonicalBridgeReplayRowsMatchPlanned]
  exact projectedBridgeReplayRows_length plannedRows

structure RawIngressCommitmentTreeContentFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
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
    (txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput)
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
    (validation : BlockActionValidationInput)
    (validationSummary : BlockActionValidationSummary)
    (materializedActionCount materializedPayloadCount : Nat)
    (decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow)
    (canonicalRows : PendingActionCanonicalFieldRows) : Prop where
  fieldProjectionFacts :
    RawIngressFullByteFieldProjectionFacts
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
      validation
      validationSummary
      materializedActionCount
      materializedPayloadCount
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows
  acceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  commitmentRootPublication :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  replayedLeafCursor :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount
  decodedRowsAcceptedByValidation :
    validationRows = decodedRows
  plannedRowsProjectAcceptedActions :
    plannedRows = materializedRows
  wireRowsProjectPlannedActions :
    wireRows = plannedRows
  exactCanonicalCommitmentRows :
    canonicalRows.commitmentRows =
      projectedCommitmentRows decodedRows
  orderedCanonicalCommitmentContent :
    canonicalRows.commitmentRows.map (fun entry => entry.2) =
      orderedDecodedCommitments decodedRows
  orderedCanonicalCommitmentIndexes :
    canonicalRows.commitmentRows.map (fun entry => entry.1) =
      orderedDecodedCommitmentIndexes decodedRows
  canonicalCommitmentRowCount :
    canonicalRows.commitmentRows.length =
      (orderedDecodedCommitments decodedRows).length

structure RawIngressReplaySetContentFacts
    (surface : RawIngressSidecarReplaySurface)
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (actionHash : AdmissionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
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
    (txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput)
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
    (validation : BlockActionValidationInput)
    (validationSummary : BlockActionValidationSummary)
    (materializedActionCount materializedPayloadCount : Nat)
    (decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow)
    (canonicalRows : PendingActionCanonicalFieldRows) : Prop where
  fieldProjectionFacts :
    RawIngressFullByteFieldProjectionFacts
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
      validation
      validationSummary
      materializedActionCount
      materializedPayloadCount
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows
  acceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  replayedLeafCursor :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup
  decodedRowsAcceptedByValidation :
    validationRows = decodedRows
  plannedRowsProjectAcceptedActions :
    plannedRows = materializedRows
  wireRowsProjectPlannedActions :
    wireRows = plannedRows
  exactCanonicalNullifierRows :
    canonicalRows.nullifierRows =
      projectedNullifierRows decodedRows
  exactCanonicalBridgeReplayRows :
    canonicalRows.bridgeReplayRows =
      projectedBridgeReplayRows plannedRows
  orderedCanonicalNullifierContent :
    canonicalRows.nullifierRows =
      orderedDecodedNullifiers decodedRows
  canonicalNullifierRowCount :
    canonicalRows.nullifierRows.length =
      (orderedDecodedNullifiers decodedRows).length
  orderedCanonicalBridgeReplayKeys :
    canonicalRows.bridgeReplayRows =
      orderedPlannedBridgeReplayKeys plannedRows
  canonicalBridgeReplayRowCount :
    canonicalRows.bridgeReplayRows.length =
      (orderedPlannedBridgeReplayKeys plannedRows).length

theorem raw_ingress_full_byte_field_projection_binds_commitment_tree_content
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput}
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
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {materializedActionCount materializedPayloadCount : Nat}
    {decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (facts :
      RawIngressFullByteFieldProjectionFacts
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
        validation
        validationSummary
        materializedActionCount
        materializedPayloadCount
        decodedRows
        validationRows
        materializedRows
        plannedRows
        wireRows
        canonicalRows) :
    RawIngressCommitmentTreeContentFacts
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
      validation
      validationSummary
      materializedActionCount
      materializedPayloadCount
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows := by
  let publicationFacts :=
    facts.productionProjectionSurface.fullBytePublicationFacts
  let fieldEvidence :=
    facts.fieldProjectionFacts.fieldProjectionEvidence
  exact
    {
      fieldProjectionFacts := facts,
      acceptedLedgerTreeReplay :=
        publicationFacts.acceptedLedgerTreeReplay,
      commitmentRootPublication :=
        publicationFacts.commitmentRootPublication,
      replayedLeafCursor :=
        publicationFacts.replayedLeafCursor,
      decodedRowsAcceptedByValidation :=
        fieldEvidence.validationRowsProjectDecoded,
      plannedRowsProjectAcceptedActions :=
        fieldEvidence.plannedRowsProjectMaterialized,
      wireRowsProjectPlannedActions :=
        fieldEvidence.wireRowsProjectPlanned,
      exactCanonicalCommitmentRows :=
        facts.canonicalCommitmentRowsMatchDecoded,
      orderedCanonicalCommitmentContent :=
        canonical_commitment_rows_bind_ordered_decoded_content
          facts.canonicalCommitmentRowsMatchDecoded,
      orderedCanonicalCommitmentIndexes :=
        canonical_commitment_rows_bind_ordered_decoded_indexes
          facts.canonicalCommitmentRowsMatchDecoded,
      canonicalCommitmentRowCount :=
        canonical_commitment_rows_bind_ordered_decoded_length
          facts.canonicalCommitmentRowsMatchDecoded
    }

theorem raw_ingress_full_byte_field_projection_binds_replay_set_content
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput}
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
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {materializedActionCount materializedPayloadCount : Nat}
    {decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (facts :
      RawIngressFullByteFieldProjectionFacts
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
        validation
        validationSummary
        materializedActionCount
        materializedPayloadCount
        decodedRows
        validationRows
        materializedRows
        plannedRows
        wireRows
        canonicalRows) :
    RawIngressReplaySetContentFacts
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
      validation
      validationSummary
      materializedActionCount
      materializedPayloadCount
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows := by
  let publicationFacts :=
    facts.productionProjectionSurface.fullBytePublicationFacts
  let fieldEvidence :=
    facts.fieldProjectionFacts.fieldProjectionEvidence
  exact
    {
      fieldProjectionFacts := facts,
      acceptedLedgerTreeReplay :=
        publicationFacts.acceptedLedgerTreeReplay,
      replayedLeafCursor :=
        publicationFacts.replayedLeafCursor,
      finalSpentNullifiersUnique :=
        publicationFacts.finalSpentNullifiersUnique,
      finalBridgeReplaysUnique :=
        publicationFacts.finalBridgeReplaysUnique,
      decodedRowsAcceptedByValidation :=
        fieldEvidence.validationRowsProjectDecoded,
      plannedRowsProjectAcceptedActions :=
        fieldEvidence.plannedRowsProjectMaterialized,
      wireRowsProjectPlannedActions :=
        fieldEvidence.wireRowsProjectPlanned,
      exactCanonicalNullifierRows :=
        facts.canonicalNullifierRowsMatchDecoded,
      exactCanonicalBridgeReplayRows :=
        facts.canonicalBridgeReplayRowsMatchPlanned,
      orderedCanonicalNullifierContent :=
        canonical_nullifier_rows_bind_ordered_decoded_content
          facts.canonicalNullifierRowsMatchDecoded,
      canonicalNullifierRowCount :=
        canonical_nullifier_rows_bind_ordered_decoded_length
          facts.canonicalNullifierRowsMatchDecoded,
      orderedCanonicalBridgeReplayKeys :=
        canonical_bridge_replay_rows_bind_planned_replay_keys
          facts.canonicalBridgeReplayRowsMatchPlanned,
      canonicalBridgeReplayRowCount :=
        canonical_bridge_replay_rows_bind_planned_replay_count
          facts.canonicalBridgeReplayRowsMatchPlanned
    }

theorem accepted_raw_ingress_full_byte_publication_binds_commitment_tree_content
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput}
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
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {materializedActionCount materializedPayloadCount : Nat}
    {decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (facts :
      RawIngressFullBytePublicationFacts
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
        merkleRoot)
    (blockActionValidationAccepted :
      evaluateBlockActionValidation validation =
        Except.ok validationSummary)
    (productionProjectionFacts :
      PendingActionProductionProjectionFacts
        blockActionDecode
        surface.daSidecarReplay.wireReplayProjection
        validation
        materializedActionCount
        materializedPayloadCount)
    (fieldProjectionEvidence :
      PendingActionOrderedFieldProjectionEvidence
        decodedRows
        validationRows
        materializedRows
        plannedRows
        wireRows
        canonicalRows)
    (decodedRowsMatchPayloadCount :
      decodedRows.length =
        blockActionDecode.actualActionPayloadCount) :
    RawIngressCommitmentTreeContentFacts
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
      validation
      validationSummary
      materializedActionCount
      materializedPayloadCount
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows := by
  have fieldFacts :=
    accepted_raw_ingress_full_byte_publication_surface_binds_field_projection_rows
      facts
      blockActionValidationAccepted
      productionProjectionFacts
      fieldProjectionEvidence
      decodedRowsMatchPayloadCount
  exact
    raw_ingress_full_byte_field_projection_binds_commitment_tree_content
      fieldFacts

theorem accepted_raw_ingress_full_byte_publication_binds_replay_set_content
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : BlockArtifactBindingAdmission.TxLeafActionBindingInput}
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
    {validation : BlockActionValidationInput}
    {validationSummary : BlockActionValidationSummary}
    {materializedActionCount materializedPayloadCount : Nat}
    {decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (facts :
      RawIngressFullBytePublicationFacts
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
        merkleRoot)
    (blockActionValidationAccepted :
      evaluateBlockActionValidation validation =
        Except.ok validationSummary)
    (productionProjectionFacts :
      PendingActionProductionProjectionFacts
        blockActionDecode
        surface.daSidecarReplay.wireReplayProjection
        validation
        materializedActionCount
        materializedPayloadCount)
    (fieldProjectionEvidence :
      PendingActionOrderedFieldProjectionEvidence
        decodedRows
        validationRows
        materializedRows
        plannedRows
        wireRows
        canonicalRows)
    (decodedRowsMatchPayloadCount :
      decodedRows.length =
        blockActionDecode.actualActionPayloadCount) :
    RawIngressReplaySetContentFacts
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
      validation
      validationSummary
      materializedActionCount
      materializedPayloadCount
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows := by
  have fieldFacts :=
    accepted_raw_ingress_full_byte_publication_surface_binds_field_projection_rows
      facts
      blockActionValidationAccepted
      productionProjectionFacts
      fieldProjectionEvidence
      decodedRowsMatchPayloadCount
  exact
    raw_ingress_full_byte_field_projection_binds_replay_set_content
      fieldFacts

end CommitmentTreeContentRefinement
end Native
end Hegemon

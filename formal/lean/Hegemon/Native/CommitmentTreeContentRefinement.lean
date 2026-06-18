import Hegemon.Consensus.CommitmentTreeAppend
import Hegemon.Native.ActionPlanApplicationAdmission
import Hegemon.Native.CommitmentTreeRefinement
import Hegemon.Native.NativePublicationRowEquivalence
import Hegemon.Native.RawIngressFullBytePublicationSurface

namespace Hegemon
namespace Native
namespace CommitmentTreeContentRefinement

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionStateEffect
open Hegemon.Native.ActionPlanApplicationAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.MinedBlockCommitPublication
open Hegemon.Native.NativePublicationRowEquivalence
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

def orderedDecodedCiphertextIndexRows
    (rows : List PendingActionFieldProjectionRow) :
    List (Nat × Nat × Nat × Nat) :=
  projectedCiphertextIndexRows rows

def orderedPlannedCiphertextArchiveRows
    (rows : List PendingActionFieldProjectionRow) : List (Nat × Nat) :=
  projectedCiphertextArchiveRows rows

def rawIngressAppendSummaries
    (depth historyLimit : Nat)
    (initial : NativeLedgerTreeReplayState)
    (decodedRows : List PendingActionFieldProjectionRow) :
    List Consensus.CommitmentTreeAppend.AppendSummary :=
  Consensus.CommitmentTreeAppend.appendSummaries
    depth
    historyLimit
    initial.ledger.leafCount
    (orderedDecodedCommitments decodedRows).length

def rowCommitmentCounts
    (rows : List PendingActionFieldProjectionRow) : List Nat :=
  rows.map (fun row => row.commitments.length)

def rowCommitmentStarts
    (rows : List PendingActionFieldProjectionRow) : List Nat :=
  rows.map (fun row => row.commitmentStart)

def rowActionPlanInput
    (leafStart : Nat)
    (rows : List PendingActionFieldProjectionRow) :
    ActionPlanApplicationInput :=
  {
    leafStart := leafStart,
    actionCommitmentCounts := rowCommitmentCounts rows,
    plannedStarts := rowCommitmentStarts rows
  }

def decodedRowsFollowLeafCursor :
    Nat -> List PendingActionFieldProjectionRow -> Prop
  | _, [] => True
  | leaf, row :: rest =>
      row.commitmentStart = leaf ∧
      decodedRowsFollowLeafCursor
        (leaf + row.commitments.length)
        rest

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

theorem checkedAddU64_eq_some_value
    {leaf count next : Nat}
    (checked :
      checkedAddU64 leaf count =
        some next) :
    next = leaf + count := by
  unfold checkedAddU64 at checked
  split at checked
  · cases checked
    rfl
  · contradiction

def rowActionPlanFromAccepts
    (leaf : Nat)
    (rows : List PendingActionFieldProjectionRow)
    (applied : Nat) : Bool :=
  match
    evaluateActionPlanApplicationFrom
      leaf
      (rowCommitmentCounts rows)
      (rowCommitmentStarts rows)
      applied with
  | Except.ok _ => true
  | Except.error _ => false

theorem decodedRowsFollowLeafCursor_of_row_action_plan_from_accepts
    (leaf : Nat)
    (rows : List PendingActionFieldProjectionRow)
    (applied : Nat)
    (accepted :
      rowActionPlanFromAccepts leaf rows applied =
        true) :
    decodedRowsFollowLeafCursor leaf rows := by
  induction rows generalizing leaf applied with
  | nil =>
      trivial
  | cons row rest ih =>
      unfold rowActionPlanFromAccepts at accepted
      simp [rowCommitmentCounts, rowCommitmentStarts] at accepted
      by_cases startMatches : row.commitmentStart = leaf
      · cases addChecked :
          checkedAddU64 leaf row.commitments.length with
        | none =>
            simp [
              evaluateActionPlanApplicationFrom,
              startMatches,
              addChecked
            ] at accepted
        | some nextLeaf =>
            have nextLeaf_eq :
                nextLeaf =
                  leaf + row.commitments.length :=
              checkedAddU64_eq_some_value addChecked
            have restAccepted :
                rowActionPlanFromAccepts nextLeaf rest (applied + 1) =
                  true := by
              simpa [
                rowActionPlanFromAccepts,
                evaluateActionPlanApplicationFrom,
                startMatches,
                addChecked
              ] using accepted
            constructor
            · exact startMatches
            · rw [nextLeaf_eq] at restAccepted
              exact ih (leaf + row.commitments.length) (applied + 1) restAccepted
      · simp [
          evaluateActionPlanApplicationFrom,
          startMatches
        ] at accepted

theorem decodedRowsFollowLeafCursor_of_action_plan_accepts
    (leaf : Nat)
    (rows : List PendingActionFieldProjectionRow)
    (accepted :
      actionPlanApplicationAccepts
        (rowActionPlanInput leaf rows) =
        true) :
    decodedRowsFollowLeafCursor leaf rows := by
  apply
    decodedRowsFollowLeafCursor_of_row_action_plan_from_accepts
      leaf rows 0
  simpa [
    rowActionPlanFromAccepts,
    rowActionPlanInput,
    actionPlanApplicationAccepts,
    evaluateActionPlanApplication
  ] using accepted

theorem commitmentIndexesFrom_eq_rangePrime
    (start : Nat)
    (values : List Nat) :
    commitmentIndexesFrom start values =
      List.range' start values.length := by
  induction values generalizing start with
  | nil =>
      rfl
  | cons value rest ih =>
      simp [commitmentIndexesFrom, List.range'_succ, ih]

theorem range_map_add_eq_rangePrime
    (start count : Nat) :
    (List.range count).map (fun offset => start + offset) =
      List.range' start count := by
  induction count with
  | zero =>
      rfl
  | succ count ih =>
      rw [List.range_succ]
      simp [List.map_append, ih]
      have concatRange :=
        List.range'_concat (s := start) (n := count) (step := 1)
      simpa using concatRange.symm

theorem orderedDecodedCommitmentIndexes_eq_rangePrime_of_cursor
    (leaf : Nat)
    (rows : List PendingActionFieldProjectionRow)
    (cursor :
      decodedRowsFollowLeafCursor leaf rows) :
    orderedDecodedCommitmentIndexes rows =
      List.range' leaf (orderedDecodedCommitments rows).length := by
  induction rows generalizing leaf with
  | nil =>
      rfl
  | cons row rest ih =>
      rcases cursor with ⟨startMatches, restCursor⟩
      have restIndexes :=
        ih (leaf + row.commitments.length) restCursor
      simp [
        orderedDecodedCommitmentIndexes,
        orderedDecodedCommitments,
        commitmentIndexesFrom_eq_rangePrime
      ] at restIndexes
      simp [
        orderedDecodedCommitmentIndexes,
        orderedDecodedCommitments,
        flattenRows,
        commitmentIndexesFrom_eq_rangePrime,
        startMatches
      ]
      rw [restIndexes]
      have appendRange :=
        List.range'_append
          (s := leaf)
          (m := row.commitments.length)
          (n := (orderedDecodedCommitments rest).length)
          (step := 1)
      simpa [orderedDecodedCommitments] using appendRange

theorem rawIngressAppendSummaries_indexes_eq_rangePrime
    (depth historyLimit : Nat)
    (initial : NativeLedgerTreeReplayState)
    (decodedRows : List PendingActionFieldProjectionRow) :
    (rawIngressAppendSummaries depth historyLimit initial decodedRows).map
        (fun summary => summary.leafIndex) =
      List.range'
        initial.ledger.leafCount
        (orderedDecodedCommitments decodedRows).length := by
  simpa [
    rawIngressAppendSummaries,
    Consensus.CommitmentTreeAppend.appendSummaries,
    Consensus.CommitmentTreeAppend.appendSummary,
    List.map_map
  ] using
    range_map_add_eq_rangePrime
      initial.ledger.leafCount
      (orderedDecodedCommitments decodedRows).length

theorem rawIngressAppendSummaries_indexes_eq_orderedDecodedCommitmentIndexes_of_action_plan
    (depth historyLimit : Nat)
    (initial : NativeLedgerTreeReplayState)
    (decodedRows : List PendingActionFieldProjectionRow)
    (accepted :
      actionPlanApplicationAccepts
        (rowActionPlanInput initial.ledger.leafCount decodedRows) =
        true) :
    (rawIngressAppendSummaries depth historyLimit initial decodedRows).map
        (fun summary => summary.leafIndex) =
      orderedDecodedCommitmentIndexes decodedRows := by
  rw [rawIngressAppendSummaries_indexes_eq_rangePrime]
  exact
    (orderedDecodedCommitmentIndexes_eq_rangePrime_of_cursor
      initial.ledger.leafCount
      decodedRows
      (decodedRowsFollowLeafCursor_of_action_plan_accepts
        initial.ledger.leafCount
        decodedRows
        accepted)).symm

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

structure RawIngressCommitmentAppendPublicationFacts
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
    (canonicalRows : PendingActionCanonicalFieldRows)
    (depth historyLimit : Nat) : Prop where
  contentFacts :
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
      canonicalRows
  appendMutationSummaryCount :
    (rawIngressAppendSummaries depth historyLimit initial decodedRows).length =
      (orderedDecodedCommitments decodedRows).length
  decodedRowsAcceptedByRowStartPlan :
    actionPlanApplicationAccepts
      (rowActionPlanInput initial.ledger.leafCount decodedRows) =
      true
  appendMutationIndexesMatchDecoded :
    (rawIngressAppendSummaries depth historyLimit initial decodedRows).map
        (fun summary => summary.leafIndex) =
      orderedDecodedCommitmentIndexes decodedRows
  appendMutationIndexesMatchCanonicalRows :
    (rawIngressAppendSummaries depth historyLimit initial decodedRows).map
        (fun summary => summary.leafIndex) =
      canonicalRows.commitmentRows.map (fun entry => entry.1)
  canonicalCommitmentRowsDriveAppendCount :
    (rawIngressAppendSummaries depth historyLimit initial decodedRows).length =
      canonicalRows.commitmentRows.length
  commitmentRootPublishedWithAppendSurface :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  replayedLeafCursorPublishedWithAppendSurface :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount

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

theorem raw_ingress_commitment_tree_content_binds_append_publication_surface
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
        canonicalRows)
    (depth historyLimit : Nat)
    (decodedRowsAcceptedByRowStartPlan :
      actionPlanApplicationAccepts
        (rowActionPlanInput initial.ledger.leafCount decodedRows) =
        true) :
    RawIngressCommitmentAppendPublicationFacts
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
      depth
      historyLimit := by
  have appendMutationSummaryCount :
      (rawIngressAppendSummaries depth historyLimit initial decodedRows).length =
        (orderedDecodedCommitments decodedRows).length := by
    simp [rawIngressAppendSummaries, Consensus.CommitmentTreeAppend.appendSummaries]
  have appendMutationIndexesMatchDecoded :
      (rawIngressAppendSummaries depth historyLimit initial decodedRows).map
          (fun summary => summary.leafIndex) =
        orderedDecodedCommitmentIndexes decodedRows :=
    rawIngressAppendSummaries_indexes_eq_orderedDecodedCommitmentIndexes_of_action_plan
      depth
      historyLimit
      initial
      decodedRows
      decodedRowsAcceptedByRowStartPlan
  exact
    {
      contentFacts := facts,
      appendMutationSummaryCount := appendMutationSummaryCount,
      decodedRowsAcceptedByRowStartPlan := decodedRowsAcceptedByRowStartPlan,
      appendMutationIndexesMatchDecoded :=
        appendMutationIndexesMatchDecoded,
      appendMutationIndexesMatchCanonicalRows := by
        rw [appendMutationIndexesMatchDecoded]
        exact facts.orderedCanonicalCommitmentIndexes.symm,
      canonicalCommitmentRowsDriveAppendCount := by
        rw [appendMutationSummaryCount]
        exact facts.canonicalCommitmentRowCount.symm,
      commitmentRootPublishedWithAppendSurface :=
        facts.commitmentRootPublication,
      replayedLeafCursorPublishedWithAppendSurface :=
        facts.replayedLeafCursor
    }

theorem accepted_raw_ingress_full_byte_publication_binds_commitment_append_publication
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
        blockActionDecode.actualActionPayloadCount)
    (depth historyLimit : Nat)
    (decodedRowsAcceptedByRowStartPlan :
      actionPlanApplicationAccepts
        (rowActionPlanInput initial.ledger.leafCount decodedRows) =
        true) :
    RawIngressCommitmentAppendPublicationFacts
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
      depth
      historyLimit := by
  have contentFacts :=
    accepted_raw_ingress_full_byte_publication_binds_commitment_tree_content
      facts
      blockActionValidationAccepted
      productionProjectionFacts
      fieldProjectionEvidence
      decodedRowsMatchPayloadCount
  exact
    raw_ingress_commitment_tree_content_binds_append_publication_surface
      contentFacts
      depth
      historyLimit
      decodedRowsAcceptedByRowStartPlan

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

structure RawIngressLedgerIntegrityPublicationFacts
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
    (canonicalRows : PendingActionCanonicalFieldRows)
    (depth historyLimit : Nat) : Prop where
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
  appendPublicationFacts :
    RawIngressCommitmentAppendPublicationFacts
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
      depth
      historyLimit
  replaySetContentFacts :
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
      canonicalRows
  acceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  supplyIntegrityPublication :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  commitmentRootPublication :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  leafCursorPublication :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount
  finalNullifierNoDoubleSpend :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplayNoDoubleImport :
    final.ledger.consumedBridgeReplays.Nodup
  exactCanonicalCommitmentRows :
    canonicalRows.commitmentRows =
      projectedCommitmentRows decodedRows
  exactCanonicalNullifierRows :
    canonicalRows.nullifierRows =
      projectedNullifierRows decodedRows
  exactCanonicalBridgeReplayRows :
    canonicalRows.bridgeReplayRows =
      projectedBridgeReplayRows plannedRows
  orderedCanonicalCommitmentContent :
    canonicalRows.commitmentRows.map (fun entry => entry.2) =
      orderedDecodedCommitments decodedRows
  orderedCanonicalCommitmentIndexes :
    canonicalRows.commitmentRows.map (fun entry => entry.1) =
      orderedDecodedCommitmentIndexes decodedRows
  orderedCanonicalNullifierContent :
    canonicalRows.nullifierRows =
      orderedDecodedNullifiers decodedRows
  orderedCanonicalBridgeReplayKeys :
    canonicalRows.bridgeReplayRows =
      orderedPlannedBridgeReplayKeys plannedRows
  appendMutationIndexesMatchCanonicalRows :
    (rawIngressAppendSummaries depth historyLimit initial decodedRows).map
        (fun summary => summary.leafIndex) =
      canonicalRows.commitmentRows.map (fun entry => entry.1)
  appendMutationCountMatchesCanonicalRows :
    (rawIngressAppendSummaries depth historyLimit initial decodedRows).length =
      canonicalRows.commitmentRows.length

theorem raw_ingress_full_byte_field_projection_binds_ledger_integrity_publication
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
        canonicalRows)
    (depth historyLimit : Nat)
    (decodedRowsAcceptedByRowStartPlan :
      actionPlanApplicationAccepts
        (rowActionPlanInput initial.ledger.leafCount decodedRows) =
        true) :
    RawIngressLedgerIntegrityPublicationFacts
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
      depth
      historyLimit := by
  have contentFacts :=
    raw_ingress_full_byte_field_projection_binds_commitment_tree_content
      facts
  have appendFacts :=
    raw_ingress_commitment_tree_content_binds_append_publication_surface
      contentFacts
      depth
      historyLimit
      decodedRowsAcceptedByRowStartPlan
  have replayFacts :=
    raw_ingress_full_byte_field_projection_binds_replay_set_content
      facts
  exact
    {
      fieldProjectionFacts := facts,
      appendPublicationFacts := appendFacts,
      replaySetContentFacts := replayFacts,
      acceptedLedgerTreeReplay :=
        contentFacts.acceptedLedgerTreeReplay,
      supplyIntegrityPublication :=
        facts.productionProjectionSurface.fullBytePublicationFacts.replayedSupply,
      commitmentRootPublication :=
        appendFacts.commitmentRootPublishedWithAppendSurface,
      leafCursorPublication :=
        appendFacts.replayedLeafCursorPublishedWithAppendSurface,
      finalNullifierNoDoubleSpend :=
        replayFacts.finalSpentNullifiersUnique,
      finalBridgeReplayNoDoubleImport :=
        replayFacts.finalBridgeReplaysUnique,
      exactCanonicalCommitmentRows :=
        contentFacts.exactCanonicalCommitmentRows,
      exactCanonicalNullifierRows :=
        replayFacts.exactCanonicalNullifierRows,
      exactCanonicalBridgeReplayRows :=
        replayFacts.exactCanonicalBridgeReplayRows,
      orderedCanonicalCommitmentContent :=
        contentFacts.orderedCanonicalCommitmentContent,
      orderedCanonicalCommitmentIndexes :=
        contentFacts.orderedCanonicalCommitmentIndexes,
      orderedCanonicalNullifierContent :=
        replayFacts.orderedCanonicalNullifierContent,
      orderedCanonicalBridgeReplayKeys :=
        replayFacts.orderedCanonicalBridgeReplayKeys,
      appendMutationIndexesMatchCanonicalRows :=
        appendFacts.appendMutationIndexesMatchCanonicalRows,
      appendMutationCountMatchesCanonicalRows :=
        appendFacts.canonicalCommitmentRowsDriveAppendCount
    }

structure NativePublicationRowsCommitmentReplayContentFacts
    (rows : NativePublicationRows) : Prop where
  nativePublicationRows :
    rows.equivalent
  exactCanonicalCommitmentRows :
    rows.canonicalRows.commitmentRows =
      projectedCommitmentRows rows.decodedRows
  orderedCanonicalCommitmentContent :
    rows.canonicalRows.commitmentRows.map (fun entry => entry.2) =
      orderedDecodedCommitments rows.decodedRows
  orderedCanonicalCommitmentIndexes :
    rows.canonicalRows.commitmentRows.map (fun entry => entry.1) =
      orderedDecodedCommitmentIndexes rows.decodedRows
  canonicalCommitmentRowCount :
    rows.canonicalRows.commitmentRows.length =
      (orderedDecodedCommitments rows.decodedRows).length
  exactCanonicalNullifierRows :
    rows.canonicalRows.nullifierRows =
      projectedNullifierRows rows.decodedRows
  orderedCanonicalNullifierContent :
    rows.canonicalRows.nullifierRows =
      orderedDecodedNullifiers rows.decodedRows
  canonicalNullifierRowCount :
    rows.canonicalRows.nullifierRows.length =
      (orderedDecodedNullifiers rows.decodedRows).length
  exactCanonicalBridgeReplayRows :
    rows.canonicalRows.bridgeReplayRows =
      projectedBridgeReplayRows rows.plannedRows
  orderedCanonicalBridgeReplayKeys :
    rows.canonicalRows.bridgeReplayRows =
      orderedPlannedBridgeReplayKeys rows.plannedRows
  canonicalBridgeReplayRowCount :
    rows.canonicalRows.bridgeReplayRows.length =
      (orderedPlannedBridgeReplayKeys rows.plannedRows).length

theorem native_publication_rows_equivalence_binds_commitment_replay_content
    {rows : NativePublicationRows}
    (facts : rows.equivalent) :
    NativePublicationRowsCommitmentReplayContentFacts rows := by
  exact
    {
      nativePublicationRows := facts,
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
          facts.canonicalCommitmentRowsMatchDecoded,
      exactCanonicalNullifierRows :=
        facts.canonicalNullifierRowsMatchDecoded,
      orderedCanonicalNullifierContent :=
        canonical_nullifier_rows_bind_ordered_decoded_content
          facts.canonicalNullifierRowsMatchDecoded,
      canonicalNullifierRowCount :=
        canonical_nullifier_rows_bind_ordered_decoded_length
          facts.canonicalNullifierRowsMatchDecoded,
      exactCanonicalBridgeReplayRows :=
        facts.canonicalBridgeReplayRowsMatchPlanned,
      orderedCanonicalBridgeReplayKeys :=
        canonical_bridge_replay_rows_bind_planned_replay_keys
          facts.canonicalBridgeReplayRowsMatchPlanned,
      canonicalBridgeReplayRowCount :=
        canonical_bridge_replay_rows_bind_planned_replay_count
          facts.canonicalBridgeReplayRowsMatchPlanned
    }

structure NativePublicationRowsCiphertextContentFacts
    (rows : NativePublicationRows) : Prop where
  nativePublicationRows :
    rows.equivalent
  validationRowsProjectDecoded :
    rows.validationRows = rows.decodedRows
  materializedRowsProjectDecoded :
    rows.materializedRows = rows.decodedRows
  plannedRowsProjectDecoded :
    rows.plannedRows = rows.decodedRows
  wireRowsProjectDecoded :
    rows.wireRows = rows.decodedRows
  exactCanonicalCiphertextIndexRows :
    rows.canonicalRows.ciphertextIndexRows =
      projectedCiphertextIndexRows rows.decodedRows
  exactCanonicalCiphertextArchiveRows :
    rows.canonicalRows.ciphertextArchiveRows =
      projectedCiphertextArchiveRows rows.plannedRows
  exactCanonicalCiphertextArchiveRowsDecoded :
    rows.canonicalRows.ciphertextArchiveRows =
      projectedCiphertextArchiveRows rows.decodedRows
  orderedCanonicalCiphertextIndexRows :
    rows.canonicalRows.ciphertextIndexRows =
      orderedDecodedCiphertextIndexRows rows.decodedRows
  orderedCanonicalCiphertextArchiveRows :
    rows.canonicalRows.ciphertextArchiveRows =
      orderedPlannedCiphertextArchiveRows rows.plannedRows
  orderedCanonicalCiphertextArchiveRowsDecoded :
    rows.canonicalRows.ciphertextArchiveRows =
      orderedPlannedCiphertextArchiveRows rows.decodedRows
  canonicalCiphertextIndexRowCount :
    rows.canonicalRows.ciphertextIndexRows.length =
      (orderedDecodedCiphertextIndexRows rows.decodedRows).length
  canonicalCiphertextArchiveRowCount :
    rows.canonicalRows.ciphertextArchiveRows.length =
      (orderedPlannedCiphertextArchiveRows rows.plannedRows).length
  canonicalCiphertextArchiveDecodedRowCount :
    rows.canonicalRows.ciphertextArchiveRows.length =
      (orderedPlannedCiphertextArchiveRows rows.decodedRows).length

theorem native_publication_rows_equivalence_binds_ciphertext_content
    {rows : NativePublicationRows}
    (facts : rows.equivalent) :
    NativePublicationRowsCiphertextContentFacts rows := by
  have plannedDecoded : rows.plannedRows = rows.decodedRows := by
    calc
      rows.plannedRows = rows.materializedRows :=
        facts.plannedRowsProjectMaterialized
      _ = rows.decodedRows :=
        facts.materializedRowsProjectDecoded
  have wireDecoded : rows.wireRows = rows.decodedRows := by
    calc
      rows.wireRows = rows.plannedRows :=
        facts.wireRowsProjectPlanned
      _ = rows.decodedRows :=
        plannedDecoded
  have archiveDecoded :
      rows.canonicalRows.ciphertextArchiveRows =
        projectedCiphertextArchiveRows rows.decodedRows := by
    calc
      rows.canonicalRows.ciphertextArchiveRows =
          projectedCiphertextArchiveRows rows.plannedRows :=
        facts.canonicalCiphertextArchiveRowsMatchPlanned
      _ = projectedCiphertextArchiveRows rows.decodedRows := by
        rw [plannedDecoded]
  exact
    {
      nativePublicationRows := facts,
      validationRowsProjectDecoded :=
        facts.validationRowsProjectDecoded,
      materializedRowsProjectDecoded :=
        facts.materializedRowsProjectDecoded,
      plannedRowsProjectDecoded :=
        plannedDecoded,
      wireRowsProjectDecoded :=
        wireDecoded,
      exactCanonicalCiphertextIndexRows :=
        facts.canonicalCiphertextIndexRowsMatchDecoded,
      exactCanonicalCiphertextArchiveRows :=
        facts.canonicalCiphertextArchiveRowsMatchPlanned,
      exactCanonicalCiphertextArchiveRowsDecoded :=
        archiveDecoded,
      orderedCanonicalCiphertextIndexRows := by
        simpa [orderedDecodedCiphertextIndexRows] using
          facts.canonicalCiphertextIndexRowsMatchDecoded,
      orderedCanonicalCiphertextArchiveRows := by
        simpa [orderedPlannedCiphertextArchiveRows] using
          facts.canonicalCiphertextArchiveRowsMatchPlanned,
      orderedCanonicalCiphertextArchiveRowsDecoded := by
        simpa [orderedPlannedCiphertextArchiveRows] using
          archiveDecoded,
      canonicalCiphertextIndexRowCount := by
        simpa [orderedDecodedCiphertextIndexRows] using
          congrArg List.length
            facts.canonicalCiphertextIndexRowsMatchDecoded,
      canonicalCiphertextArchiveRowCount := by
        simpa [orderedPlannedCiphertextArchiveRows] using
          congrArg List.length
            facts.canonicalCiphertextArchiveRowsMatchPlanned,
      canonicalCiphertextArchiveDecodedRowCount := by
        simpa [orderedPlannedCiphertextArchiveRows] using
          congrArg List.length archiveDecoded
    }

structure NativePublicationPathFamilyCommitmentReplayContentFacts
    (minedInput : MinedBlockCommitPublicationInput)
    (rawIngress minedCommit announcedImport syncImport reorgReplay
      canonicalIndexRebuild blockRange startupRepair :
        NativePublicationRows) : Prop where
  pathFamilyRows :
    NativePublicationPathFamilyRowEquivalenceFacts
      minedInput
      rawIngress
      minedCommit
      announcedImport
      syncImport
      reorgReplay
      canonicalIndexRebuild
      blockRange
      startupRepair
  rawIngressContent :
    NativePublicationRowsCommitmentReplayContentFacts rawIngress
  minedCommitContent :
    NativePublicationRowsCommitmentReplayContentFacts minedCommit
  announcedImportContent :
    NativePublicationRowsCommitmentReplayContentFacts announcedImport
  syncImportContent :
    NativePublicationRowsCommitmentReplayContentFacts syncImport
  reorgReplayContent :
    NativePublicationRowsCommitmentReplayContentFacts reorgReplay
  canonicalIndexRebuildContent :
    NativePublicationRowsCommitmentReplayContentFacts canonicalIndexRebuild
  blockRangeContent :
    NativePublicationRowsCommitmentReplayContentFacts blockRange
  startupRepairContent :
    NativePublicationRowsCommitmentReplayContentFacts startupRepair
  minedAndStartupShareDecodedRows :
    minedCommit.decodedRows = startupRepair.decodedRows
  rebuildAndBlockRangeShareCanonicalRows :
    canonicalIndexRebuild.canonicalRows = blockRange.canonicalRows

theorem accepted_native_publication_path_family_binds_commitment_replay_content
    {minedInput : MinedBlockCommitPublicationInput}
    {rawIngress minedCommit announcedImport syncImport reorgReplay
      canonicalIndexRebuild blockRange startupRepair :
        NativePublicationRows}
    (rawIngressRows : rawIngress.equivalent)
    (minedAccepted :
      minedBlockCommitPublicationAccepts minedInput = true)
    (minedRows : minedCommit.equivalent)
    (announcedRows : announcedImport.equivalent)
    (syncRows : syncImport.equivalent)
    (reorgRows : reorgReplay.equivalent)
    (rebuildRows : canonicalIndexRebuild.equivalent)
    (blockRangeRows : blockRange.equivalent)
    (startupRows : startupRepair.equivalent)
    (minedStartupDecoded :
      minedCommit.decodedRows = startupRepair.decodedRows)
    (rebuildBlockRangeCanonical :
      canonicalIndexRebuild.canonicalRows = blockRange.canonicalRows) :
    NativePublicationPathFamilyCommitmentReplayContentFacts
      minedInput
      rawIngress
      minedCommit
      announcedImport
      syncImport
      reorgReplay
      canonicalIndexRebuild
      blockRange
      startupRepair := by
  let pathRows :=
    accepted_native_publication_path_family_binds_native_publication_rows
      rawIngressRows
      minedAccepted
      minedRows
      announcedRows
      syncRows
      reorgRows
      rebuildRows
      blockRangeRows
      startupRows
      minedStartupDecoded
      rebuildBlockRangeCanonical
  exact
    {
      pathFamilyRows := pathRows,
      rawIngressContent :=
        native_publication_rows_equivalence_binds_commitment_replay_content
          rawIngressRows,
      minedCommitContent :=
        native_publication_rows_equivalence_binds_commitment_replay_content
          minedRows,
      announcedImportContent :=
        native_publication_rows_equivalence_binds_commitment_replay_content
          announcedRows,
      syncImportContent :=
        native_publication_rows_equivalence_binds_commitment_replay_content
          syncRows,
      reorgReplayContent :=
        native_publication_rows_equivalence_binds_commitment_replay_content
          reorgRows,
      canonicalIndexRebuildContent :=
        native_publication_rows_equivalence_binds_commitment_replay_content
          rebuildRows,
      blockRangeContent :=
        native_publication_rows_equivalence_binds_commitment_replay_content
          blockRangeRows,
      startupRepairContent :=
        native_publication_rows_equivalence_binds_commitment_replay_content
          startupRows,
      minedAndStartupShareDecodedRows :=
        pathRows.minedAndStartupShareDecodedRows,
      rebuildAndBlockRangeShareCanonicalRows :=
        pathRows.rebuildAndBlockRangeShareCanonicalRows
    }

structure NativePublicationPathFamilyCiphertextContentFacts
    (minedInput : MinedBlockCommitPublicationInput)
    (rawIngress minedCommit announcedImport syncImport reorgReplay
      canonicalIndexRebuild blockRange startupRepair :
        NativePublicationRows) : Prop where
  pathFamilyRows :
    NativePublicationPathFamilyRowEquivalenceFacts
      minedInput
      rawIngress
      minedCommit
      announcedImport
      syncImport
      reorgReplay
      canonicalIndexRebuild
      blockRange
      startupRepair
  rawIngressContent :
    NativePublicationRowsCiphertextContentFacts rawIngress
  minedCommitContent :
    NativePublicationRowsCiphertextContentFacts minedCommit
  announcedImportContent :
    NativePublicationRowsCiphertextContentFacts announcedImport
  syncImportContent :
    NativePublicationRowsCiphertextContentFacts syncImport
  reorgReplayContent :
    NativePublicationRowsCiphertextContentFacts reorgReplay
  canonicalIndexRebuildContent :
    NativePublicationRowsCiphertextContentFacts canonicalIndexRebuild
  blockRangeContent :
    NativePublicationRowsCiphertextContentFacts blockRange
  startupRepairContent :
    NativePublicationRowsCiphertextContentFacts startupRepair
  minedAndStartupShareDecodedRows :
    minedCommit.decodedRows = startupRepair.decodedRows
  minedAndStartupShareCiphertextIndexProjection :
    projectedCiphertextIndexRows minedCommit.decodedRows =
      projectedCiphertextIndexRows startupRepair.decodedRows
  minedAndStartupShareCiphertextArchiveProjection :
    projectedCiphertextArchiveRows minedCommit.decodedRows =
      projectedCiphertextArchiveRows startupRepair.decodedRows
  minedAndStartupShareCanonicalCiphertextIndexRows :
    minedCommit.canonicalRows.ciphertextIndexRows =
      startupRepair.canonicalRows.ciphertextIndexRows
  minedAndStartupShareCanonicalCiphertextArchiveRows :
    minedCommit.canonicalRows.ciphertextArchiveRows =
      startupRepair.canonicalRows.ciphertextArchiveRows
  rebuildAndBlockRangeShareCanonicalRows :
    canonicalIndexRebuild.canonicalRows = blockRange.canonicalRows
  rebuildAndBlockRangeShareCanonicalCiphertextRows :
    canonicalIndexRebuild.canonicalRows.ciphertextIndexRows =
        blockRange.canonicalRows.ciphertextIndexRows
      ∧ canonicalIndexRebuild.canonicalRows.ciphertextArchiveRows =
        blockRange.canonicalRows.ciphertextArchiveRows

theorem accepted_native_publication_path_family_binds_ciphertext_content
    {minedInput : MinedBlockCommitPublicationInput}
    {rawIngress minedCommit announcedImport syncImport reorgReplay
      canonicalIndexRebuild blockRange startupRepair :
        NativePublicationRows}
    (rawIngressRows : rawIngress.equivalent)
    (minedAccepted :
      minedBlockCommitPublicationAccepts minedInput = true)
    (minedRows : minedCommit.equivalent)
    (announcedRows : announcedImport.equivalent)
    (syncRows : syncImport.equivalent)
    (reorgRows : reorgReplay.equivalent)
    (rebuildRows : canonicalIndexRebuild.equivalent)
    (blockRangeRows : blockRange.equivalent)
    (startupRows : startupRepair.equivalent)
    (minedStartupDecoded :
      minedCommit.decodedRows = startupRepair.decodedRows)
    (rebuildBlockRangeCanonical :
      canonicalIndexRebuild.canonicalRows = blockRange.canonicalRows) :
    NativePublicationPathFamilyCiphertextContentFacts
      minedInput
      rawIngress
      minedCommit
      announcedImport
      syncImport
      reorgReplay
      canonicalIndexRebuild
      blockRange
      startupRepair := by
  let pathRows :=
    accepted_native_publication_path_family_binds_native_publication_rows
      rawIngressRows
      minedAccepted
      minedRows
      announcedRows
      syncRows
      reorgRows
      rebuildRows
      blockRangeRows
      startupRows
      minedStartupDecoded
      rebuildBlockRangeCanonical
  let minedContent :=
    native_publication_rows_equivalence_binds_ciphertext_content
      minedRows
  let startupContent :=
    native_publication_rows_equivalence_binds_ciphertext_content
      startupRows
  have indexProjection :
      projectedCiphertextIndexRows minedCommit.decodedRows =
        projectedCiphertextIndexRows startupRepair.decodedRows := by
    rw [minedStartupDecoded]
  have archiveProjection :
      projectedCiphertextArchiveRows minedCommit.decodedRows =
        projectedCiphertextArchiveRows startupRepair.decodedRows := by
    rw [minedStartupDecoded]
  have minedStartupCanonicalIndex :
      minedCommit.canonicalRows.ciphertextIndexRows =
        startupRepair.canonicalRows.ciphertextIndexRows := by
    calc
      minedCommit.canonicalRows.ciphertextIndexRows =
          projectedCiphertextIndexRows minedCommit.decodedRows :=
        minedContent.exactCanonicalCiphertextIndexRows
      _ = projectedCiphertextIndexRows startupRepair.decodedRows :=
        indexProjection
      _ = startupRepair.canonicalRows.ciphertextIndexRows :=
        startupContent.exactCanonicalCiphertextIndexRows.symm
  have minedStartupCanonicalArchive :
      minedCommit.canonicalRows.ciphertextArchiveRows =
        startupRepair.canonicalRows.ciphertextArchiveRows := by
    calc
      minedCommit.canonicalRows.ciphertextArchiveRows =
          projectedCiphertextArchiveRows minedCommit.decodedRows :=
        minedContent.exactCanonicalCiphertextArchiveRowsDecoded
      _ = projectedCiphertextArchiveRows startupRepair.decodedRows :=
        archiveProjection
      _ = startupRepair.canonicalRows.ciphertextArchiveRows :=
        startupContent.exactCanonicalCiphertextArchiveRowsDecoded.symm
  have rebuildBlockRangeCiphertext :
      canonicalIndexRebuild.canonicalRows.ciphertextIndexRows =
          blockRange.canonicalRows.ciphertextIndexRows
        ∧ canonicalIndexRebuild.canonicalRows.ciphertextArchiveRows =
          blockRange.canonicalRows.ciphertextArchiveRows := by
    exact
      ⟨congrArg PendingActionCanonicalFieldRows.ciphertextIndexRows
          rebuildBlockRangeCanonical,
        congrArg PendingActionCanonicalFieldRows.ciphertextArchiveRows
          rebuildBlockRangeCanonical⟩
  exact
    {
      pathFamilyRows := pathRows,
      rawIngressContent :=
        native_publication_rows_equivalence_binds_ciphertext_content
          rawIngressRows,
      minedCommitContent := minedContent,
      announcedImportContent :=
        native_publication_rows_equivalence_binds_ciphertext_content
          announcedRows,
      syncImportContent :=
        native_publication_rows_equivalence_binds_ciphertext_content
          syncRows,
      reorgReplayContent :=
        native_publication_rows_equivalence_binds_ciphertext_content
          reorgRows,
      canonicalIndexRebuildContent :=
        native_publication_rows_equivalence_binds_ciphertext_content
          rebuildRows,
      blockRangeContent :=
        native_publication_rows_equivalence_binds_ciphertext_content
          blockRangeRows,
      startupRepairContent := startupContent,
      minedAndStartupShareDecodedRows :=
        pathRows.minedAndStartupShareDecodedRows,
      minedAndStartupShareCiphertextIndexProjection :=
        indexProjection,
      minedAndStartupShareCiphertextArchiveProjection :=
        archiveProjection,
      minedAndStartupShareCanonicalCiphertextIndexRows :=
        minedStartupCanonicalIndex,
      minedAndStartupShareCanonicalCiphertextArchiveRows :=
        minedStartupCanonicalArchive,
      rebuildAndBlockRangeShareCanonicalRows :=
        pathRows.rebuildAndBlockRangeShareCanonicalRows,
      rebuildAndBlockRangeShareCanonicalCiphertextRows :=
        rebuildBlockRangeCiphertext
    }

end CommitmentTreeContentRefinement
end Native
end Hegemon

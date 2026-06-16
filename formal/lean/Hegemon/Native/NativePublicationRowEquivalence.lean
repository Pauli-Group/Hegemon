import Hegemon.Native.MinedBlockCommitPublication
import Hegemon.Native.RawIngressFullBytePublicationSurface

namespace Hegemon
namespace Native
namespace NativePublicationRowEquivalence

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalPublicationRefinement
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.MinedBlockCommitPublication
open Hegemon.Native.PendingActionByteParserRefinement
open Hegemon.Native.PendingActionByteReplayRowCountBinding
open Hegemon.Native.RawIngressFullBytePublicationSurface
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

structure NativePublicationRowEquivalenceFacts
    (decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow)
    (canonicalRows : PendingActionCanonicalFieldRows) : Prop where
  validationRowsProjectDecoded :
    validationRows = decodedRows
  materializedRowsProjectDecoded :
    materializedRows = decodedRows
  plannedRowsProjectMaterialized :
    plannedRows = materializedRows
  wireRowsProjectPlanned :
    wireRows = plannedRows
  validationRowsMatchDecodedRows :
    validationRows.length = decodedRows.length
  materializedRowsMatchDecodedRows :
    materializedRows.length = decodedRows.length
  plannedRowsMatchMaterializedRows :
    plannedRows.length = materializedRows.length
  wireRowsMatchPlannedRows :
    wireRows.length = plannedRows.length
  canonicalCommitmentRowsMatchDecoded :
    canonicalRows.commitmentRows = projectedCommitmentRows decodedRows
  canonicalNullifierRowsMatchDecoded :
    canonicalRows.nullifierRows = projectedNullifierRows decodedRows
  canonicalBridgeReplayRowsMatchPlanned :
    canonicalRows.bridgeReplayRows = projectedBridgeReplayRows plannedRows
  canonicalCiphertextIndexRowsMatchDecoded :
    canonicalRows.ciphertextIndexRows =
      projectedCiphertextIndexRows decodedRows
  canonicalCiphertextArchiveRowsMatchPlanned :
    canonicalRows.ciphertextArchiveRows =
      projectedCiphertextArchiveRows plannedRows

structure MinedCommitNativePublicationRowEquivalenceFacts
    (input : MinedBlockCommitPublicationInput)
    (decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow)
    (canonicalRows : PendingActionCanonicalFieldRows) : Prop where
  minedCommitFacts : MinedBlockCommitPublicationFacts input
  nativePublicationRows :
    NativePublicationRowEquivalenceFacts
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows

theorem raw_ingress_full_byte_field_projection_binds_native_publication_rows
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : CodecAdmission.ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : AcceptedChain.NativeLedgerTreeReplayState}
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
    NativePublicationRowEquivalenceFacts
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows := by
  exact
    {
      validationRowsProjectDecoded :=
        facts.fieldProjectionFacts.fieldProjectionEvidence.validationRowsProjectDecoded,
      materializedRowsProjectDecoded :=
        facts.fieldProjectionFacts.fieldProjectionEvidence.materializedRowsProjectDecoded,
      plannedRowsProjectMaterialized :=
        facts.fieldProjectionFacts.fieldProjectionEvidence.plannedRowsProjectMaterialized,
      wireRowsProjectPlanned :=
        facts.fieldProjectionFacts.fieldProjectionEvidence.wireRowsProjectPlanned,
      validationRowsMatchDecodedRows :=
        facts.fieldProjectionFacts.validationRowsMatchDecodedRows,
      materializedRowsMatchDecodedRows :=
        facts.fieldProjectionFacts.materializedRowsMatchDecodedRows,
      plannedRowsMatchMaterializedRows :=
        facts.fieldProjectionFacts.plannedRowsMatchMaterializedRows,
      wireRowsMatchPlannedRows :=
        facts.fieldProjectionFacts.wireRowsMatchPlannedRows,
      canonicalCommitmentRowsMatchDecoded :=
        facts.canonicalCommitmentRowsMatchDecoded,
      canonicalNullifierRowsMatchDecoded :=
        facts.canonicalNullifierRowsMatchDecoded,
      canonicalBridgeReplayRowsMatchPlanned :=
        facts.canonicalBridgeReplayRowsMatchPlanned,
      canonicalCiphertextIndexRowsMatchDecoded :=
        facts.canonicalCiphertextIndexRowsMatchDecoded,
      canonicalCiphertextArchiveRowsMatchPlanned :=
        facts.canonicalCiphertextArchiveRowsMatchPlanned
    }

theorem accepted_raw_ingress_full_byte_publication_binds_native_publication_rows
    {surface : RawIngressSidecarReplaySurface}
    {pendingDecode : CodecAdmission.ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput :
      ActionWireReplayProjectionAdmission.ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : AcceptedChain.NativeLedgerTreeReplayState}
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
    NativePublicationRowEquivalenceFacts
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows :=
  raw_ingress_full_byte_field_projection_binds_native_publication_rows
    facts

theorem accepted_mined_block_commit_binds_native_publication_rows
    {input : MinedBlockCommitPublicationInput}
    {decodedRows validationRows materializedRows plannedRows wireRows :
      List PendingActionFieldProjectionRow}
    {canonicalRows : PendingActionCanonicalFieldRows}
    (accepted : minedBlockCommitPublicationAccepts input = true)
    (rows :
      NativePublicationRowEquivalenceFacts
        decodedRows
        validationRows
        materializedRows
        plannedRows
        wireRows
        canonicalRows) :
    MinedCommitNativePublicationRowEquivalenceFacts
      input
      decodedRows
      validationRows
      materializedRows
      plannedRows
      wireRows
      canonicalRows := by
  exact
    {
      minedCommitFacts :=
        accepted_mined_block_commit_publication_facts accepted,
      nativePublicationRows := rows
    }

end NativePublicationRowEquivalence
end Native
end Hegemon

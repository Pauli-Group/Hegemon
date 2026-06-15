import Hegemon.Native.ActionHashAdmission
import Hegemon.Native.ActionWireReplayProjectionAdmission
import Hegemon.Native.CanonicalPublicationRefinement
import Hegemon.Native.CodecAdmission
import Hegemon.Native.PendingActionReload
import Hegemon.Native.TxLeafCanonicalSurface

namespace Hegemon
namespace Native
namespace PendingActionBytePublicationRefinement

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalPublicationRefinement
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.PendingActionReload
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Transaction.CanonicalVerifierBoundary

structure PendingActionBytePublicationFacts
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (pendingReload : PendingActionReloadInput)
    (actionHash : AdmissionInput)
    (wireProjection : ActionWireReplayProjectionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) where
  pendingDecodePreconditions :
    exactDecodePreconditions pendingDecode = true
  pendingDecodeExact :
    pendingDecode.parserAccepts = true
      ∧ pendingDecode.consumedAllBytes = true
      ∧ pendingDecode.canonicalReencodeMatches = true
  blockActionDecodePreconditions :
    blockActionDecodePreconditions blockActionDecode = true
  blockActionDecodeExact :
    actionCountMatches blockActionDecode = true
      ∧ blockActionDecode.everyActionDecodesExactly = true
  pendingReloadPreconditions :
    pendingActionReloadPreconditions pendingReload = true
  actionHashPreconditions :
    admissionPreconditions actionHash = true
  wireProjectionPreconditions :
    actionWireReplayProjectionPreconditions wireProjection = true
  acceptedWireProjection :
    evaluateActionWireReplayProjection wireProjection =
      Except.ok wireOutput
  projectedActionRowsMatchDecodedPayloads :
    wireOutput.projectedActionCount =
      blockActionDecode.actualActionPayloadCount
  canonicalPublicationFacts :
    CanonicalPublicationReplayFacts
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      (rawTreeReplayInputs blocks)
  rawTreeCarriedStatePreconditions :
    rawProjectedTreeCarriedStatePreconditions initial blocks = true

theorem accepted_pending_action_bytes_bind_raw_canonical_publication
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReloadInput}
    {actionHash : AdmissionInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (pendingReloadAccepted :
      pendingActionReloadAccepts pendingReload = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireProjectionAccepted :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (projectedActionRowsMatchDecodedPayloads :
      wireOutput.projectedActionCount =
        blockActionDecode.actualActionPayloadCount)
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
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    PendingActionBytePublicationFacts
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
      blocks := by
  have pendingDecodePreconditionsOk :
      exactDecodePreconditions pendingDecode = true :=
    (exact_accepts_iff_preconditions
      (input := pendingDecode)).mp pendingDecodeAccepted
  have pendingDecodeExactOk :
      pendingDecode.parserAccepts = true
        ∧ pendingDecode.consumedAllBytes = true
        ∧ pendingDecode.canonicalReencodeMatches = true :=
    exact_decode_acceptance_excludes_malleability
      pendingDecodeAccepted
  have blockActionDecodePreconditionsOk :
      blockActionDecodePreconditions blockActionDecode = true :=
    (block_action_decode_accepts_iff_preconditions
      (input := blockActionDecode)).mp blockActionDecodeAccepted
  have blockActionDecodeExactOk :
      actionCountMatches blockActionDecode = true
        ∧ blockActionDecode.everyActionDecodesExactly = true :=
    block_action_decode_acceptance_excludes_malleability
      blockActionDecodeAccepted
  have pendingReloadPreconditionsOk :
      pendingActionReloadPreconditions pendingReload = true :=
    (accepts_iff_pending_action_reload_preconditions
      (input := pendingReload)).mp pendingReloadAccepted
  have actionHashPreconditionsOk :
      admissionPreconditions actionHash = true :=
    (accepts_iff_admission_preconditions
      (input := actionHash)).mp actionHashAccepted
  have wireProjectionAccepts :
      actionWireReplayProjectionAccepts wireProjection = true := by
    simp [actionWireReplayProjectionAccepts, wireProjectionAccepted]
  have wireProjectionPreconditionsOk :
      actionWireReplayProjectionPreconditions wireProjection = true :=
    by
      simpa [wireProjectionAccepts] using
        (accepts_iff_wire_replay_projection_preconditions wireProjection)
  have canonicalFacts :=
    accepted_raw_canonical_publication_refines_ledger_tree_replay
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  exact
    {
      pendingDecodePreconditions := pendingDecodePreconditionsOk,
      pendingDecodeExact := pendingDecodeExactOk,
      blockActionDecodePreconditions := blockActionDecodePreconditionsOk,
      blockActionDecodeExact := blockActionDecodeExactOk,
      pendingReloadPreconditions := pendingReloadPreconditionsOk,
      actionHashPreconditions := actionHashPreconditionsOk,
      wireProjectionPreconditions := wireProjectionPreconditionsOk,
      acceptedWireProjection := wireProjectionAccepted,
      projectedActionRowsMatchDecodedPayloads :=
        projectedActionRowsMatchDecodedPayloads,
      canonicalPublicationFacts := canonicalFacts.left,
      rawTreeCarriedStatePreconditions := canonicalFacts.right
    }

structure PendingActionByteTxLeafPublicationFacts
    (pendingDecode : ExactDecodeInput)
    (blockActionDecode : BlockActionDecodeInput)
    (pendingReload : PendingActionReloadInput)
    (actionHash : AdmissionInput)
    (wireProjection : ActionWireReplayProjectionInput)
    (wireOutput : ActionWireReplayProjectionOutput)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (txLeaf : TxLeafActionBindingInput)
    (wrapper : Hegemon.Transaction.ProofWrapperAdmission.ProofWrapperInput)
    (shape : Hegemon.Transaction.PublicInputs.PublicInputShape)
    (publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields)
    (serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields)
    (bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs)
    (statementFields :
      Hegemon.Transaction.StatementHash.StatementFields)
    (statementBytes : List Byte)
    (bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields)
    (bindingBytes : List Byte)
    (merkleRoot : Hegemon.Transaction.PublicInputs.Digest) : Prop where
  bytePublicationFacts :
    PendingActionBytePublicationFacts
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

theorem accepted_pending_action_bytes_bind_tx_leaf_publication
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {pendingReload : PendingActionReloadInput}
    {actionHash : AdmissionInput}
    {wireProjection : ActionWireReplayProjectionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : Hegemon.Transaction.ProofWrapperAdmission.ProofWrapperInput}
    {shape : Hegemon.Transaction.PublicInputs.PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields :
      Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Hegemon.Transaction.PublicInputs.Digest}
    (pendingDecodeAccepted :
      exactDecodeAccepts pendingDecode = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (pendingReloadAccepted :
      pendingActionReloadAccepts pendingReload = true)
    (actionHashAccepted :
      admissionAccepts actionHash = true)
    (wireProjectionAccepted :
      evaluateActionWireReplayProjection wireProjection =
        Except.ok wireOutput)
    (projectedActionRowsMatchDecodedPayloads :
      wireOutput.projectedActionCount =
        blockActionDecode.actualActionPayloadCount)
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
    (txLeafAccepted :
      txLeafActionBindingAccepts txLeaf = true)
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
      merkleRoot := by
  have byteFacts :=
    accepted_pending_action_bytes_bind_raw_canonical_publication
      pendingDecodeAccepted
      blockActionDecodeAccepted
      pendingReloadAccepted
      actionHashAccepted
      wireProjectionAccepted
      projectedActionRowsMatchDecodedPayloads
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  have txLeafFacts :=
    native_tx_leaf_binding_and_canonical_surface_full_statement_artifact_facts
      txLeafAccepted
      surface
  exact
    {
      bytePublicationFacts := byteFacts,
      txLeafFullStatementArtifactFacts := txLeafFacts
    }

end PendingActionBytePublicationRefinement
end Native
end Hegemon

import Hegemon.Native.CanonicalPublicationRefinement
import Hegemon.Native.RawIngressSidecarReplayRecoverability

namespace Hegemon
namespace Native
namespace RawIngressDaSidecarCanonicalPublication

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionRequestProjectionAdmission
open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CandidateArtifactCouplingAdmission
open Hegemon.Native.CanonicalPublicationRefinement
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.DaSidecarReplayBinding
open Hegemon.Native.PendingActionReload
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.SidecarUploadAdmission
open Hegemon.Native.StagedCiphertextReload
open Hegemon.Native.StagedProofReload
open Hegemon.Native.StorageDurabilityAdmission

structure RawIngressDaSidecarCanonicalExternalAssumptions
    (daAvailability parserInternals hashSecurityEquivalence
      storageDurability proofSoundness completeNativeNodeEquivalence :
      Prop) : Prop where
  daAvailabilityExplicit : daAvailability
  parserInternalsExplicit : parserInternals
  hashSecurityEquivalenceExplicit : hashSecurityEquivalence
  storageDurabilityExplicit : storageDurability
  proofSoundnessExplicit : proofSoundness
  completeNativeNodeEquivalenceExplicit : completeNativeNodeEquivalence

theorem ledger_blocks_from_raw_tree_replay_inputs_eq_raw_replay_inputs
    (blocks : List RawDecodedNativeTreeReplayBlock) :
    ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks) =
      rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks) := by
  induction blocks with
  | nil =>
      rfl
  | cons block rest ih =>
      change
        replayInputFromProjection
            (projectionFromRawDecodedBlock block.decodedReplay) ::
          ledgerBlocksFromTreeReplay (rawTreeReplayInputs rest) =
        replayInputFromProjection
            (projectionFromRawDecodedBlock block.decodedReplay) ::
          rawReplayInputs (rawDecodedBlocksFromTreeReplay rest)
      rw [ih]

theorem proof_metadata_preconditions_expose_binding_hash
    {input : ProofMetadataInput}
    (preconditions : proofMetadataPreconditions input = true) :
    input.bindingHashPresent = true
      ∧ input.bindingHashValid = true
      ∧ input.proofPresent = true := by
  cases input with
  | mk bindingHashPresent bindingHashValid proofPresent =>
      cases bindingHashPresent <;> cases bindingHashValid <;>
        cases proofPresent <;>
          simp [proofMetadataPreconditions] at preconditions ⊢

theorem proof_decoded_preconditions_expose_size_and_hash
    {input : ProofDecodedInput}
    (preconditions : proofDecodedPreconditions input = true) :
    input.proofBytes ≠ 0
      ∧ ¬ input.proofBytes > input.maxProofBytes
      ∧ input.proofBindingHashMatchesKey = true := by
  unfold proofDecodedPreconditions at preconditions
  by_cases empty : input.proofBytes = 0
  · simp [empty] at preconditions
  · by_cases tooLarge : input.proofBytes > input.maxProofBytes
    · simp [empty, tooLarge] at preconditions
    · cases hashMatches : input.proofBindingHashMatchesKey
      · simp [empty, tooLarge, hashMatches] at preconditions
      · exact ⟨empty, tooLarge, rfl⟩

structure RawIngressDaSidecarCanonicalPublicationFacts
    (surface : RawIngressSidecarReplaySurface)
    (semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock)
    (daAvailability parserInternals hashSecurityEquivalence
      storageDurability proofSoundness completeNativeNodeEquivalence :
      Prop) : Prop where
  externalAssumptions :
    RawIngressDaSidecarCanonicalExternalAssumptions
      daAvailability
      parserInternals
      hashSecurityEquivalence
      storageDurability
      proofSoundness
      completeNativeNodeEquivalence
  rawIngressPublicationFacts :
    RawIngressLedgerTreePublicationFacts
      surface
      semanticFields
      initial
      final
      blocks
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
  rawProjectedReplayWitness :
    rawProjectedLedgerTreeStateAfter initial blocks = some final
  ledgerProjectionMatchesRawReplay :
    ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks) =
      rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)
  actionRequestOk :
    actionRequestProjectionPreconditions surface.actionRequest = true
  pendingReloadOk :
    pendingActionReloadPreconditions surface.pendingReload = true
  stagedCiphertextReloadOk :
    stagedCiphertextReloadPreconditions
      surface.stagedCiphertextReload = true
  stagedProofReloadOk :
    stagedProofReloadPreconditions surface.stagedProofReload = true
  sidecarCiphertextsAvailable :
    surface.transferState.sidecarCiphertextsAvailable = true
  sidecarCiphertextSizesPresent :
    surface.transferState.sidecarCiphertextSizesPresent = true
  sidecarCiphertextSizesMatch :
    surface.transferState.sidecarCiphertextSizesMatch = true
  candidateDaRootMatches :
    surface.daSidecarReplay.candidateBinding.daRootMatches = true
  candidateTxStatementsCommitmentMatches :
    surface.daSidecarReplay.candidateBinding.txStatementsCommitmentMatches =
      true
  candidateRecursiveStateRootMatches :
    surface.daSidecarReplay.candidateBinding.recursiveStateRootMatches =
      true
  candidateArtifactCouplingOk :
    candidateArtifactCouplingPreconditions
      surface.daSidecarReplay.candidateCoupling = true
  provenBatchDaRootMatches :
    surface.daSidecarReplay.provenBatchBinding.daRootMatches = true
  provenBatchHasChunks :
    surface.daSidecarReplay.provenBatchBinding.daChunkCount ≠ 0
  semanticDaRootBound :
    semanticFields.daRoot =
      surface.daSidecarReplay.recursiveSemanticSource.daRoot
  candidateTxCountNonzero :
    surface.daSidecarReplay.candidateArtifact.txCount ≠ 0
  candidateDaChunkCountNonzero :
    surface.daSidecarReplay.candidateArtifact.daChunkCount ≠ 0
  actionStreamOk :
    actionStreamPreconditions surface.daSidecarReplay.actionStream = true
  wireReplayProjectionOk :
    actionWireReplayProjectionPreconditions
      surface.daSidecarReplay.wireReplayProjection = true
  wireReplayPlannedCount :
    surface.daSidecarReplay.wireReplayProjection.actionCount =
      surface.daSidecarReplay.wireReplayProjection.plannedCount
  wireReplayActionCount :
    surface.daSidecarReplay.wireReplayProjection.actionCount =
      surface.daSidecarReplay.wireReplayProjection.actions.length
  ciphertextRequestWithinBound :
    ¬ surface.daSidecarReplay.ciphertextRequest.itemCount >
      surface.daSidecarReplay.ciphertextRequest.maxItems
  ciphertextCapacityOk :
    capacityPreconditions surface.daSidecarReplay.ciphertextCapacity = true
  proofRequestWithinBound :
    ¬ surface.daSidecarReplay.proofRequest.itemCount >
      surface.daSidecarReplay.proofRequest.maxItems
  proofCapacityOk :
    capacityPreconditions surface.daSidecarReplay.proofCapacity = true
  proofMetadataOk :
    proofMetadataPreconditions surface.daSidecarReplay.proofMetadata = true
  proofBindingHashPresent :
    surface.daSidecarReplay.proofMetadata.bindingHashPresent = true
  proofBindingHashValid :
    surface.daSidecarReplay.proofMetadata.bindingHashValid = true
  proofPresent :
    surface.daSidecarReplay.proofMetadata.proofPresent = true
  proofDecodedOk :
    proofDecodedPreconditions surface.daSidecarReplay.proofDecoded = true
  proofBytesNonzero :
    surface.daSidecarReplay.proofDecoded.proofBytes ≠ 0
  proofBytesWithinMax :
    ¬ surface.daSidecarReplay.proofDecoded.proofBytes >
      surface.daSidecarReplay.proofDecoded.maxProofBytes
  proofBindingHashMatchesKey :
    surface.daSidecarReplay.proofDecoded.proofBindingHashMatchesKey = true
  blockIndexPreconditions :
    blockIndexReloadPreconditions blockIndex = true
  canonicalStatePreconditions :
    canonicalStateReloadPreconditions canonicalState = true
  canonicalReorgPreconditions :
    canonicalReorgChainPreconditions reorgChain = true
  atomicCommitPreconditions :
    atomicCommitManifestPreconditions commitManifest = true
  modeledStorageDurabilityPreconditions :
    storageDurabilityPreconditions durability = true
  rawIngressAcceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  canonicalAcceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain
      initial
      (rawTreeReplayInputs blocks) =
      some final
  commitmentRootPublication :
    expectedCommitmentRootAfter
      initial.commitmentRoot
      (rawTreeReplayInputs blocks) =
      some final.commitmentRoot
  rawIngressAcceptedLedgerReplay :
    validateNativeLedgerReplayChain
      initial.ledger
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger
  canonicalAcceptedLedgerReplay :
    validateNativeLedgerReplayChain
      initial.ledger
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger
  rawIngressReplayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.supply
  canonicalReplayedSupply :
    expectedNativeSupplyAfter
      initial.ledger.supply
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger.supply
  rawIngressReplayedLeafCursor :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
      some final.ledger.leafCount
  canonicalReplayedLeafCursor :
    expectedNativeLeafCountAfter
      initial.ledger.leafCount
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) =
      some final.ledger.leafCount
  rawIngressCanonicalCommitmentPlan :
    nativeLedgerReplayCommitmentPlanPreconditions
      initial.ledger
      (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) = true
  canonicalCommitmentPlan :
    nativeLedgerReplayCommitmentPlanPreconditions
      initial.ledger
      (ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks)) = true
  rawIngressTreeCarriedStatePreconditions :
    rawProjectedTreeCarriedStatePreconditions initial blocks = true
  canonicalRawTreeCarriedStatePreconditions :
    rawProjectedTreeCarriedStatePreconditions initial blocks = true
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup

theorem accepted_raw_ingress_da_sidecar_canonical_publication
    {surface : RawIngressSidecarReplaySurface}
    {streamOutput : ActionStreamOutput}
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
    {daAvailability parserInternals hashSecurityEquivalence
      storageDurability proofSoundness completeNativeNodeEquivalence :
      Prop}
    (rawIngressFacts :
      AcceptedRawIngressSidecarReplay
        surface
        streamOutput
        wireOutput
        semanticFields)
    (sidecarRoute : surface.transferState.sidecarRoute = true)
    (blockIndexAccepted : blockIndexReloadAccepts blockIndex = true)
    (canonicalStateAccepted :
      canonicalStateReloadAccepts canonicalState = true)
    (canonicalReorgAccepted :
      canonicalReorgChainAccepts reorgChain = true)
    (atomicCommitAccepted :
      atomicCommitManifestAccepts commitManifest = true)
    (durabilityAccepted :
      storageDurabilityAccepts durability = true)
    (externalAssumptions :
      RawIngressDaSidecarCanonicalExternalAssumptions
        daAvailability
        parserInternals
        hashSecurityEquivalence
        storageDurability
        proofSoundness
        completeNativeNodeEquivalence)
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (acceptedRaw :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    RawIngressDaSidecarCanonicalPublicationFacts
      surface
      semanticFields
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks
      daAvailability
      parserInternals
      hashSecurityEquivalence
      storageDurability
      proofSoundness
      completeNativeNodeEquivalence := by
  have rawPublicationFacts :=
    raw_ingress_publication_equivalent_to_raw_ledger_tree_replay
      rawIngressFacts
      sidecarRoute
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  rcases
    accepted_raw_canonical_publication_refines_ledger_tree_replay
      (blockIndex := blockIndex)
      (canonicalState := canonicalState)
      (reorgChain := reorgChain)
      (commitManifest := commitManifest)
      (durability := durability)
      (initial := initial)
      (final := final)
      (blocks := blocks)
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw with
    ⟨canonicalFacts, canonicalCarriedState⟩
  have ledgerProjection :=
    ledger_blocks_from_raw_tree_replay_inputs_eq_raw_replay_inputs blocks
  have couplingAccepts :
      candidateArtifactCouplingAccepts
        surface.daSidecarReplay.candidateCoupling = true := by
    simp [
      candidateArtifactCouplingAccepts,
      rawIngressFacts.daSidecarReplayFacts.candidateCouplingAccepted
    ]
  have couplingPreconditions :
      candidateArtifactCouplingPreconditions
        surface.daSidecarReplay.candidateCoupling = true :=
    (accepts_iff_coupling_preconditions
      (input := surface.daSidecarReplay.candidateCoupling)).mp
      couplingAccepts
  have proofMetadataHash :=
    proof_metadata_preconditions_expose_binding_hash
      rawPublicationFacts.proofMetadataOk
  have proofDecodedHash :=
    proof_decoded_preconditions_expose_size_and_hash
      rawPublicationFacts.proofDecodedOk
  exact
    {
      externalAssumptions := externalAssumptions,
      rawIngressPublicationFacts := rawPublicationFacts,
      canonicalPublicationFacts := canonicalFacts,
      rawProjectedReplayWitness := acceptedRaw,
      ledgerProjectionMatchesRawReplay := ledgerProjection,
      actionRequestOk := rawPublicationFacts.actionRequestOk,
      pendingReloadOk := rawPublicationFacts.pendingReloadOk,
      stagedCiphertextReloadOk :=
        rawPublicationFacts.stagedCiphertextReloadOk,
      stagedProofReloadOk := rawPublicationFacts.stagedProofReloadOk,
      sidecarCiphertextsAvailable :=
        rawPublicationFacts.sidecarCiphertextsAvailable,
      sidecarCiphertextSizesPresent :=
        rawPublicationFacts.sidecarCiphertextSizesPresent,
      sidecarCiphertextSizesMatch :=
        rawPublicationFacts.sidecarCiphertextSizesMatch,
      candidateDaRootMatches :=
        rawPublicationFacts.candidateDaRootMatches,
      candidateTxStatementsCommitmentMatches :=
        rawPublicationFacts.candidateTxStatementsCommitmentMatches,
      candidateRecursiveStateRootMatches :=
        rawPublicationFacts.candidateRecursiveStateRootMatches,
      candidateArtifactCouplingOk := couplingPreconditions,
      provenBatchDaRootMatches :=
        rawPublicationFacts.provenBatchDaRootMatches,
      provenBatchHasChunks := rawPublicationFacts.provenBatchHasChunks,
      semanticDaRootBound := rawPublicationFacts.semanticDaRootBound,
      candidateTxCountNonzero :=
        rawPublicationFacts.candidateTxCountNonzero,
      candidateDaChunkCountNonzero :=
        rawPublicationFacts.candidateDaChunkCountNonzero,
      actionStreamOk := rawPublicationFacts.actionStreamOk,
      wireReplayProjectionOk :=
        rawPublicationFacts.wireReplayProjectionOk,
      wireReplayPlannedCount :=
        rawPublicationFacts.wireReplayPlannedCount,
      wireReplayActionCount :=
        rawPublicationFacts.wireReplayActionCount,
      ciphertextRequestWithinBound :=
        rawPublicationFacts.ciphertextRequestWithinBound,
      ciphertextCapacityOk := rawPublicationFacts.ciphertextCapacityOk,
      proofRequestWithinBound :=
        rawPublicationFacts.proofRequestWithinBound,
      proofCapacityOk := rawPublicationFacts.proofCapacityOk,
      proofMetadataOk := rawPublicationFacts.proofMetadataOk,
      proofBindingHashPresent := proofMetadataHash.1,
      proofBindingHashValid := proofMetadataHash.2.1,
      proofPresent := proofMetadataHash.2.2,
      proofDecodedOk := rawPublicationFacts.proofDecodedOk,
      proofBytesNonzero := proofDecodedHash.1,
      proofBytesWithinMax := proofDecodedHash.2.1,
      proofBindingHashMatchesKey := proofDecodedHash.2.2,
      blockIndexPreconditions :=
        canonicalFacts.blockIndexPreconditions,
      canonicalStatePreconditions :=
        canonicalFacts.canonicalStatePreconditions,
      canonicalReorgPreconditions :=
        canonicalFacts.canonicalReorgPreconditions,
      atomicCommitPreconditions :=
        canonicalFacts.atomicCommitPreconditions,
      modeledStorageDurabilityPreconditions :=
        canonicalFacts.storageDurabilityPreconditions,
      rawIngressAcceptedLedgerTreeReplay :=
        rawPublicationFacts.acceptedLedgerTreeReplay,
      canonicalAcceptedLedgerTreeReplay :=
        canonicalFacts.acceptedLedgerTreeReplay,
      commitmentRootPublication :=
        canonicalFacts.commitmentRootPublication,
      rawIngressAcceptedLedgerReplay :=
        rawPublicationFacts.acceptedLedgerReplay,
      canonicalAcceptedLedgerReplay :=
        canonicalFacts.acceptedLedgerReplay,
      rawIngressReplayedSupply := rawPublicationFacts.replayedSupply,
      canonicalReplayedSupply := canonicalFacts.replayedSupply,
      rawIngressReplayedLeafCursor :=
        rawPublicationFacts.replayedLeafCursor,
      canonicalReplayedLeafCursor :=
        canonicalFacts.replayedLeafCursor,
      rawIngressCanonicalCommitmentPlan :=
        rawPublicationFacts.canonicalCommitmentPlan,
      canonicalCommitmentPlan := canonicalFacts.canonicalCommitmentPlan,
      rawIngressTreeCarriedStatePreconditions :=
        rawPublicationFacts.rawTreeCarriedState,
      canonicalRawTreeCarriedStatePreconditions :=
        canonicalCarriedState,
      finalSpentNullifiersUnique :=
        canonicalFacts.finalSpentNullifiersUnique,
      finalBridgeReplaysUnique :=
        canonicalFacts.finalBridgeReplaysUnique
    }

end RawIngressDaSidecarCanonicalPublication
end Native
end Hegemon

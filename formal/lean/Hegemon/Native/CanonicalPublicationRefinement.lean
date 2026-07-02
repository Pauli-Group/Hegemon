import Hegemon.Native.AcceptedChain
import Hegemon.Native.AtomicCommitManifestAdmission
import Hegemon.Native.BlockIndexReload
import Hegemon.Native.BlockReplayInputProjection
import Hegemon.Native.CanonicalReorgChainAdmission
import Hegemon.Native.CanonicalStateReload
import Hegemon.Native.StorageDurabilityAdmission

namespace Hegemon
namespace Native
namespace CanonicalPublicationRefinement

open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayRefinement
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Consensus.TreeTransition

abbrev NativeLedgerTreeReplayBlock :=
  BlockReplayInput × TreeTransitionInput

structure CanonicalPublicationReplayFacts
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List NativeLedgerTreeReplayBlock) where
  blockIndexPreconditions :
    blockIndexReloadPreconditions blockIndex = true
  canonicalStatePreconditions :
    canonicalStateReloadPreconditions canonicalState = true
  canonicalReorgPreconditions :
    canonicalReorgChainPreconditions reorgChain = true
  atomicCommitPreconditions :
    atomicCommitManifestPreconditions commitManifest = true
  storageDurabilityPreconditions :
    storageDurabilityPreconditions durability = true
  acceptedLedgerTreeReplay :
    validateNativeLedgerTreeReplayChain initial blocks = some final
  acceptedLedgerReplay :
    validateNativeLedgerReplayChain
        initial.ledger
        (ledgerBlocksFromTreeReplay blocks) =
      some final.ledger
  commitmentRootPublication :
    expectedCommitmentRootAfter initial.commitmentRoot blocks =
      some final.commitmentRoot
  replayedSupply :
    expectedNativeSupplyAfter
        initial.ledger.supply
        (ledgerBlocksFromTreeReplay blocks) =
      some final.ledger.supply
  replayedLeafCursor :
    expectedNativeLeafCountAfter
        initial.ledger.leafCount
        (ledgerBlocksFromTreeReplay blocks) =
      some final.ledger.leafCount
  canonicalCommitmentPlan :
    nativeLedgerReplayCommitmentPlanPreconditions
        initial.ledger
        (ledgerBlocksFromTreeReplay blocks) = true
  finalSpentNullifiersUnique :
    final.ledger.spentNullifiers.Nodup
  finalBridgeReplaysUnique :
    final.ledger.consumedBridgeReplays.Nodup

theorem accepted_canonical_publication_refines_ledger_tree_replay
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List NativeLedgerTreeReplayBlock}
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
    (acceptedReplay :
      validateNativeLedgerTreeReplayChain initial blocks = some final) :
    CanonicalPublicationReplayFacts
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        blocks := by
  have blockIndexPreconditionsOk :
      blockIndexReloadPreconditions blockIndex = true :=
    (accepts_iff_block_index_reload_preconditions
      (input := blockIndex)).mp blockIndexAccepted
  have canonicalStatePreconditionsOk :
      canonicalStateReloadPreconditions canonicalState = true :=
    (accepts_iff_canonical_state_reload_preconditions
      (input := canonicalState)).mp canonicalStateAccepted
  have canonicalReorgPreconditionsOk :
      canonicalReorgChainPreconditions reorgChain = true :=
    (accepts_iff_canonical_reorg_chain_preconditions
      (input := reorgChain)).mp canonicalReorgAccepted
  have atomicCommitPreconditionsOk :
      atomicCommitManifestPreconditions commitManifest = true :=
    (accepts_iff_atomic_commit_manifest_preconditions
      (input := commitManifest)).mp atomicCommitAccepted
  have storageDurabilityPreconditionsOk :
      storageDurabilityPreconditions durability = true :=
    (accepts_iff_storage_durability_preconditions
      (input := durability)).mp durabilityAccepted
  have replayFacts :=
    accepted_native_ledger_tree_replay_chain_integrity_from
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedReplay
  exact
    {
      blockIndexPreconditions := blockIndexPreconditionsOk,
      canonicalStatePreconditions := canonicalStatePreconditionsOk,
      canonicalReorgPreconditions := canonicalReorgPreconditionsOk,
      atomicCommitPreconditions := atomicCommitPreconditionsOk,
      storageDurabilityPreconditions := storageDurabilityPreconditionsOk,
      acceptedLedgerTreeReplay := acceptedReplay,
      acceptedLedgerReplay := replayFacts.left,
      commitmentRootPublication := replayFacts.right.left,
      replayedSupply := replayFacts.right.right.left,
      replayedLeafCursor := replayFacts.right.right.right.left,
      canonicalCommitmentPlan := replayFacts.right.right.right.right.left,
      finalSpentNullifiersUnique :=
        replayFacts.right.right.right.right.right.left,
      finalBridgeReplaysUnique :=
        replayFacts.right.right.right.right.right.right
    }

theorem accepted_raw_canonical_publication_refines_ledger_tree_replay
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
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
    CanonicalPublicationReplayFacts
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        (rawTreeReplayInputs blocks)
      ∧ rawProjectedTreeCarriedStatePreconditions initial blocks = true := by
  have rawReplayFacts :=
    accepted_raw_projected_ledger_tree_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedRaw
  have publicationFacts :=
    accepted_canonical_publication_refines_ledger_tree_replay
      blockIndexAccepted
      canonicalStateAccepted
      canonicalReorgAccepted
      atomicCommitAccepted
      durabilityAccepted
      initialNullifiersNodup
      initialBridgeReplaysNodup
      rawReplayFacts.left
  exact
    ⟨publicationFacts,
      rawReplayFacts.right.right.right.right.right.right.left⟩

end CanonicalPublicationRefinement
end Native
end Hegemon

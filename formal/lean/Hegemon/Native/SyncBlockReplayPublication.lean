import Hegemon.Native.CanonicalPublicationRefinement
import Hegemon.Native.CodecAdmission
import Hegemon.Native.SyncAdmission

namespace Hegemon
namespace Native
namespace SyncBlockReplayPublication

open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalPublicationRefinement
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.SyncAdmission

def rawDecodedTreeReplayActionCount :
    List RawDecodedNativeTreeReplayBlock -> Nat
  | [] => 0
  | block :: rest =>
      block.decodedReplay.decodedActions.length +
        rawDecodedTreeReplayActionCount rest

structure SyncBlockReplayPublicationFacts
    (syncDecode : SyncDecodeInput)
    (responseCount : SyncResponseCountInput)
    (blockActionDecode : BlockActionDecodeInput)
    (blockIndex : BlockIndexReloadInput)
    (canonicalState : CanonicalStateReloadInput)
    (reorgChain : CanonicalReorgChainInput)
    (commitManifest : AtomicCommitManifestInput)
    (durability : StorageDurabilityInput)
    (initial final : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) : Prop where
  syncWirePreconditions :
    syncDecodePreconditions syncDecode = true
  syncDecodeExact :
    syncDecode.boundedWireDecodeAccepts = true
      ∧ syncDecode.consumedAllBytes = true
  responseCountWithinLimit :
    responseCount.blockCount ≤ responseCount.maxBlocks
  syncResponseBlockCountMatchesRawReplay :
    blocks.length = responseCount.blockCount
  syncResponseBlocksWithinLimit :
    blocks.length ≤ responseCount.maxBlocks
  blockActionDecodePreconditions :
    blockActionDecodePreconditions blockActionDecode = true
  blockActionDecodeExact :
    actionCountMatches blockActionDecode = true
      ∧ blockActionDecode.everyActionDecodesExactly = true
  blockActionDecodeDeclaredRowsMatch :
    blockActionDecode.declaredTxCount =
      blockActionDecode.actualActionPayloadCount
  blockActionDecodedRowsMatchRawReplay :
    blockActionDecode.actualActionPayloadCount =
      rawDecodedTreeReplayActionCount blocks
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

theorem accepted_sync_block_response_binds_raw_canonical_publication
    {syncDecode : SyncDecodeInput}
    {responseCount : SyncResponseCountInput}
    {blockActionDecode : BlockActionDecodeInput}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (syncAccepted : syncDecodeAccepts syncDecode = true)
    (responseCountAccepted :
      responseCountAccepts responseCount = true)
    (blockActionDecodeAccepted :
      blockActionDecodeAccepts blockActionDecode = true)
    (syncBlockCountMatches :
      blocks.length = responseCount.blockCount)
    (decodedRowsMatchRawReplay :
      blockActionDecode.actualActionPayloadCount =
        rawDecodedTreeReplayActionCount blocks)
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
    SyncBlockReplayPublicationFacts
      syncDecode
      responseCount
      blockActionDecode
      blockIndex
      canonicalState
      reorgChain
      commitManifest
      durability
      initial
      final
      blocks := by
  have syncPreconditionsOk :
      syncDecodePreconditions syncDecode = true :=
    (sync_accepts_iff_preconditions
      (input := syncDecode)).mp syncAccepted
  have syncExact :=
    sync_decode_acceptance_excludes_malleability syncAccepted
  have responseWithinLimit :
      responseCount.blockCount ≤ responseCount.maxBlocks :=
    (response_count_accepts_iff_within_limit
      (input := responseCount)).mp responseCountAccepted
  have blocksWithinLimit :
      blocks.length ≤ responseCount.maxBlocks := by
    simpa [syncBlockCountMatches] using responseWithinLimit
  have blockDecodePreconditionsOk :
      blockActionDecodePreconditions blockActionDecode = true :=
    (block_action_decode_accepts_iff_preconditions
      (input := blockActionDecode)).mp blockActionDecodeAccepted
  have blockDecodeExact :=
    block_action_decode_acceptance_excludes_malleability
      blockActionDecodeAccepted
  have declaredRowsMatch :=
    block_action_decode_acceptance_binds_declared_count
      blockActionDecodeAccepted
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
      syncWirePreconditions := syncPreconditionsOk,
      syncDecodeExact := syncExact,
      responseCountWithinLimit := responseWithinLimit,
      syncResponseBlockCountMatchesRawReplay := syncBlockCountMatches,
      syncResponseBlocksWithinLimit := blocksWithinLimit,
      blockActionDecodePreconditions := blockDecodePreconditionsOk,
      blockActionDecodeExact := blockDecodeExact,
      blockActionDecodeDeclaredRowsMatch := declaredRowsMatch,
      blockActionDecodedRowsMatchRawReplay := decodedRowsMatchRawReplay,
      canonicalPublicationFacts := canonicalFacts.left,
      rawTreeCarriedStatePreconditions := canonicalFacts.right
    }

end SyncBlockReplayPublication
end Native
end Hegemon

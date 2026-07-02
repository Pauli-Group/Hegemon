import Hegemon.Native.AcceptedChain

namespace Hegemon
namespace Native
namespace BlockReplayInputProjection

open Hegemon.Native.AcceptedChain
open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.BlockReplayRefinement
open Hegemon.Consensus.TreeTransition

structure NativeBlockReplayProjection where
  carried : NativeLedgerReplayState
  actions : List StreamAction
  height : Nat
  feeTotal : Nat
  hasCoinbase : Bool
  claimedSupply : Nat
  txCountMatches : Bool
  stateRootMatches : Bool
  kernelRootMatches : Bool
  nullifierRootMatches : Bool
  extrinsicsRootMatches : Bool
  messageRootMatches : Bool
  messageCountMatches : Bool
  headerMmrRootMatches : Bool
  headerMmrLenMatches : Bool
deriving DecidableEq, Repr

structure RawDecodedNativeReplayBlock where
  carriedSupply : Nat
  carriedLeafCount : Nat
  carriedSpentNullifiers : List Nat
  carriedConsumedBridgeReplays : List Nat
  decodedActions : List StreamAction
  decodedHeight : Nat
  decodedFeeTotal : Nat
  decodedHasCoinbase : Bool
  decodedClaimedSupply : Nat
  decodedTxCountMatches : Bool
  decodedStateRootMatches : Bool
  decodedKernelRootMatches : Bool
  decodedNullifierRootMatches : Bool
  decodedExtrinsicsRootMatches : Bool
  decodedMessageRootMatches : Bool
  decodedMessageCountMatches : Bool
  decodedHeaderMmrRootMatches : Bool
  decodedHeaderMmrLenMatches : Bool
deriving DecidableEq, Repr

structure NativeLedgerTreeReplayProjection where
  replay : NativeBlockReplayProjection
  treeInput : TreeTransitionInput
deriving DecidableEq, Repr

structure RawDecodedNativeTreeReplayBlock where
  decodedReplay : RawDecodedNativeReplayBlock
  decodedTreeInput : TreeTransitionInput
deriving DecidableEq, Repr

def projectionFromRawDecodedBlock
    (block : RawDecodedNativeReplayBlock) : NativeBlockReplayProjection :=
  {
    carried :=
      {
        supply := block.carriedSupply,
        leafCount := block.carriedLeafCount,
        spentNullifiers := block.carriedSpentNullifiers,
        consumedBridgeReplays := block.carriedConsumedBridgeReplays
      },
    actions := block.decodedActions,
    height := block.decodedHeight,
    feeTotal := block.decodedFeeTotal,
    hasCoinbase := block.decodedHasCoinbase,
    claimedSupply := block.decodedClaimedSupply,
    txCountMatches := block.decodedTxCountMatches,
    stateRootMatches := block.decodedStateRootMatches,
    kernelRootMatches := block.decodedKernelRootMatches,
    nullifierRootMatches := block.decodedNullifierRootMatches,
    extrinsicsRootMatches := block.decodedExtrinsicsRootMatches,
    messageRootMatches := block.decodedMessageRootMatches,
    messageCountMatches := block.decodedMessageCountMatches,
    headerMmrRootMatches := block.decodedHeaderMmrRootMatches,
    headerMmrLenMatches := block.decodedHeaderMmrLenMatches
  }

def replayInputFromProjection
    (projection : NativeBlockReplayProjection) : BlockReplayInput :=
  {
    leafStart := projection.carried.leafCount,
    spentNullifiers := projection.carried.spentNullifiers,
    consumedBridgeReplays := projection.carried.consumedBridgeReplays,
    actions := projection.actions,
    parentSupply := projection.carried.supply,
    height := projection.height,
    feeTotal := projection.feeTotal,
    hasCoinbase := projection.hasCoinbase,
    claimedSupply := projection.claimedSupply,
    txCountMatches := projection.txCountMatches,
    stateRootMatches := projection.stateRootMatches,
    kernelRootMatches := projection.kernelRootMatches,
    nullifierRootMatches := projection.nullifierRootMatches,
    extrinsicsRootMatches := projection.extrinsicsRootMatches,
    messageRootMatches := projection.messageRootMatches,
    messageCountMatches := projection.messageCountMatches,
    headerMmrRootMatches := projection.headerMmrRootMatches,
    headerMmrLenMatches := projection.headerMmrLenMatches
  }

def projectedReplayInputs :
    List NativeBlockReplayProjection -> List BlockReplayInput
  | [] => []
  | projection :: rest =>
      replayInputFromProjection projection :: projectedReplayInputs rest

def rawNativeReplayProjections :
    List RawDecodedNativeReplayBlock -> List NativeBlockReplayProjection
  | [] => []
  | block :: rest =>
      projectionFromRawDecodedBlock block :: rawNativeReplayProjections rest

def replayInputFromRawDecodedBlock
    (block : RawDecodedNativeReplayBlock) : BlockReplayInput :=
  replayInputFromProjection (projectionFromRawDecodedBlock block)

def rawReplayInputs
    (blocks : List RawDecodedNativeReplayBlock) : List BlockReplayInput :=
  projectedReplayInputs (rawNativeReplayProjections blocks)

def projectionCarriesState
    (state : NativeLedgerReplayState)
    (projection : NativeBlockReplayProjection) : Bool :=
  if projection.carried.supply = state.supply then
    if projection.carried.leafCount = state.leafCount then
      if projection.carried.spentNullifiers = state.spentNullifiers then
        if projection.carried.consumedBridgeReplays =
            state.consumedBridgeReplays then
          true
        else
          false
      else
        false
    else
      false
  else
    false

def projectedCarriedStatePreconditions :
    NativeLedgerReplayState -> List NativeBlockReplayProjection -> Bool
  | _, [] => true
  | state, projection :: rest =>
      if projectionCarriesState state projection then
        match evaluateBlockReplayRefinement
            (replayInputFromProjection projection) with
        | Except.error _ => false
        | Except.ok summary =>
            projectedCarriedStatePreconditions
              (nextLedgerState
                state
                (replayInputFromProjection projection)
                summary)
              rest
      else
        false

def projectedLedgerStateAfter :
    NativeLedgerReplayState -> List NativeBlockReplayProjection ->
      Option NativeLedgerReplayState
  | state, [] => some state
  | state, projection :: rest =>
      if projectionCarriesState state projection then
        match evaluateBlockReplayRefinement
            (replayInputFromProjection projection) with
        | Except.error _ => none
        | Except.ok summary =>
            projectedLedgerStateAfter
              (nextLedgerState
                state
                (replayInputFromProjection projection)
                summary)
              rest
      else
        none

def rawProjectedCarriedStatePreconditions
    (state : NativeLedgerReplayState)
    (blocks : List RawDecodedNativeReplayBlock) : Bool :=
  projectedCarriedStatePreconditions state (rawNativeReplayProjections blocks)

def rawProjectedLedgerStateAfter
    (state : NativeLedgerReplayState)
    (blocks : List RawDecodedNativeReplayBlock) :
      Option NativeLedgerReplayState :=
  projectedLedgerStateAfter state (rawNativeReplayProjections blocks)

def treeReplayInputFromProjection
    (projection : NativeLedgerTreeReplayProjection) :
      BlockReplayInput × TreeTransitionInput :=
  (replayInputFromProjection projection.replay, projection.treeInput)

def projectedTreeReplayInputs :
    List NativeLedgerTreeReplayProjection ->
      List (BlockReplayInput × TreeTransitionInput)
  | [] => []
  | projection :: rest =>
      treeReplayInputFromProjection projection ::
        projectedTreeReplayInputs rest

def replayProjectionsFromTreeReplay :
    List NativeLedgerTreeReplayProjection -> List NativeBlockReplayProjection
  | [] => []
  | projection :: rest =>
      projection.replay :: replayProjectionsFromTreeReplay rest

def rawNativeTreeReplayProjections :
    List RawDecodedNativeTreeReplayBlock ->
      List NativeLedgerTreeReplayProjection
  | [] => []
  | block :: rest =>
      {
        replay := projectionFromRawDecodedBlock block.decodedReplay,
        treeInput := block.decodedTreeInput
      } :: rawNativeTreeReplayProjections rest

def rawDecodedBlocksFromTreeReplay :
    List RawDecodedNativeTreeReplayBlock -> List RawDecodedNativeReplayBlock
  | [] => []
  | block :: rest =>
      block.decodedReplay :: rawDecodedBlocksFromTreeReplay rest

def rawTreeReplayInputs
    (blocks : List RawDecodedNativeTreeReplayBlock) :
      List (BlockReplayInput × TreeTransitionInput) :=
  projectedTreeReplayInputs (rawNativeTreeReplayProjections blocks)

def projectedTreeCarriedStatePreconditions
    (state : NativeLedgerTreeReplayState)
    (projections : List NativeLedgerTreeReplayProjection) : Bool :=
  projectedCarriedStatePreconditions
    state.ledger
    (replayProjectionsFromTreeReplay projections)

def rawProjectedTreeCarriedStatePreconditions
    (state : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) : Bool :=
  projectedTreeCarriedStatePreconditions
    state
    (rawNativeTreeReplayProjections blocks)

def projectedLedgerTreeStateAfter :
    NativeLedgerTreeReplayState ->
      List NativeLedgerTreeReplayProjection ->
        Option NativeLedgerTreeReplayState
  | state, [] => some state
  | state, projection :: rest =>
      if projectionCarriesState state.ledger projection.replay then
        match evaluateBlockReplayRefinement
            (replayInputFromProjection projection.replay) with
        | Except.error _ => none
        | Except.ok summary =>
            if projection.treeInput.parentRoot = state.commitmentRoot then
              if treeTransitionAccepts projection.treeInput then
                projectedLedgerTreeStateAfter
                  (nextLedgerTreeState
                    state
                    (replayInputFromProjection projection.replay)
                    summary
                    projection.treeInput)
                  rest
              else
                none
            else
              none
      else
        none

def rawProjectedLedgerTreeStateAfter
    (state : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) :
      Option NativeLedgerTreeReplayState :=
  projectedLedgerTreeStateAfter state (rawNativeTreeReplayProjections blocks)

theorem replayInputFromProjection_projects_carried_state
    (projection : NativeBlockReplayProjection) :
    (replayInputFromProjection projection).parentSupply =
        projection.carried.supply
      ∧ (replayInputFromProjection projection).leafStart =
        projection.carried.leafCount
      ∧ (replayInputFromProjection projection).spentNullifiers =
        projection.carried.spentNullifiers
      ∧ (replayInputFromProjection projection).consumedBridgeReplays =
        projection.carried.consumedBridgeReplays
      ∧ (replayInputFromProjection projection).actions =
        projection.actions := by
  simp [replayInputFromProjection]

theorem replayInputFromRawDecodedBlock_projects_decoded_fields
    (block : RawDecodedNativeReplayBlock) :
    (replayInputFromRawDecodedBlock block).parentSupply =
        block.carriedSupply
      ∧ (replayInputFromRawDecodedBlock block).leafStart =
        block.carriedLeafCount
      ∧ (replayInputFromRawDecodedBlock block).spentNullifiers =
        block.carriedSpentNullifiers
      ∧ (replayInputFromRawDecodedBlock block).consumedBridgeReplays =
        block.carriedConsumedBridgeReplays
      ∧ (replayInputFromRawDecodedBlock block).actions =
        block.decodedActions := by
  simp [
    replayInputFromRawDecodedBlock,
    replayInputFromProjection,
    projectionFromRawDecodedBlock
  ]

theorem projection_carries_state_of_replay_fields_eq
    {state : NativeLedgerReplayState}
    {projection : NativeBlockReplayProjection}
    (parentEq :
      (replayInputFromProjection projection).parentSupply =
        state.supply)
    (leafEq :
      (replayInputFromProjection projection).leafStart =
        state.leafCount)
    (spentEq :
      (replayInputFromProjection projection).spentNullifiers =
        state.spentNullifiers)
    (consumedEq :
      (replayInputFromProjection projection).consumedBridgeReplays =
        state.consumedBridgeReplays) :
    projectionCarriesState state projection = true := by
  have parentEq' : projection.carried.supply = state.supply := by
    simpa [replayInputFromProjection] using parentEq
  have leafEq' : projection.carried.leafCount = state.leafCount := by
    simpa [replayInputFromProjection] using leafEq
  have spentEq' :
      projection.carried.spentNullifiers = state.spentNullifiers := by
    simpa [replayInputFromProjection] using spentEq
  have consumedEq' :
      projection.carried.consumedBridgeReplays =
        state.consumedBridgeReplays := by
    simpa [replayInputFromProjection] using consumedEq
  simp [
    projectionCarriesState,
    parentEq',
    leafEq',
    spentEq',
    consumedEq'
  ]

theorem accepted_projected_native_block_claims_carried_state
    {projection : NativeBlockReplayProjection}
    {summary : BlockReplaySummary}
    (accepted :
      evaluateBlockReplayRefinement
        (replayInputFromProjection projection) =
          Except.ok summary) :
    (replayInputFromProjection projection).parentSupply =
        projection.carried.supply
      ∧ (replayInputFromProjection projection).leafStart =
        projection.carried.leafCount
      ∧ (replayInputFromProjection projection).spentNullifiers =
        projection.carried.spentNullifiers
      ∧ (replayInputFromProjection projection).consumedBridgeReplays =
        projection.carried.consumedBridgeReplays
      ∧ summary.expectedSupply =
        (replayInputFromProjection projection).claimedSupply := by
  have supplyFacts := accepted_claims_expected_supply accepted
  exact
    ⟨by simp [replayInputFromProjection],
      by simp [replayInputFromProjection],
      by simp [replayInputFromProjection],
      by simp [replayInputFromProjection],
      supplyFacts.right⟩

theorem accepted_projected_native_ledger_replay_chain_carried_states
    {initial final : NativeLedgerReplayState}
    {projections : List NativeBlockReplayProjection}
    (accepted :
      validateNativeLedgerReplayChain
          initial
          (projectedReplayInputs projections) =
        some final) :
    projectedCarriedStatePreconditions initial projections = true := by
  induction projections generalizing initial with
  | nil =>
      rfl
  | cons projection rest ih =>
      unfold projectedReplayInputs at accepted
      unfold validateNativeLedgerReplayChain at accepted
      unfold projectedCarriedStatePreconditions
      by_cases parentEq :
          (replayInputFromProjection projection).parentSupply =
            initial.supply
      · simp [parentEq] at accepted
        by_cases leafEq :
            (replayInputFromProjection projection).leafStart =
              initial.leafCount
        · simp [leafEq] at accepted
          by_cases spentEq :
              (replayInputFromProjection projection).spentNullifiers =
                initial.spentNullifiers
          · simp [spentEq] at accepted
            by_cases consumedEq :
                (replayInputFromProjection projection).consumedBridgeReplays =
                  initial.consumedBridgeReplays
            · simp [consumedEq] at accepted
              cases replayResult :
                  evaluateBlockReplayRefinement
                    (replayInputFromProjection projection) with
              | error rejection =>
                  simp [replayResult] at accepted
              | ok summary =>
                  have carries :=
                    projection_carries_state_of_replay_fields_eq
                      parentEq
                      leafEq
                      spentEq
                      consumedEq
                  simp [carries, replayResult] at accepted ⊢
                  exact ih accepted
            · simp [consumedEq] at accepted
          · simp [spentEq] at accepted
        · simp [leafEq] at accepted
      · simp [parentEq] at accepted

theorem accepted_projected_native_ledger_replay_chain_startup_equivalence
    {initial final : NativeLedgerReplayState}
    {projections : List NativeBlockReplayProjection}
    (initialNullifiersNodup : initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup : initial.consumedBridgeReplays.Nodup)
    (accepted :
      validateNativeLedgerReplayChain
          initial
          (projectedReplayInputs projections) =
        some final) :
    expectedNativeSupplyAfter
        initial.supply
        (projectedReplayInputs projections) =
        some final.supply
      ∧ expectedNativeLeafCountAfter
          initial.leafCount
          (projectedReplayInputs projections) =
          some final.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          initial
          (projectedReplayInputs projections) = true
      ∧ projectedCarriedStatePreconditions initial projections = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup := by
  have replayEquivalence :=
    accepted_native_ledger_replay_chain_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      accepted
  exact
    ⟨replayEquivalence.left,
      replayEquivalence.right.left,
      replayEquivalence.right.right.left,
      accepted_projected_native_ledger_replay_chain_carried_states accepted,
      replayEquivalence.right.right.right.left,
      replayEquivalence.right.right.right.right⟩

theorem projectedLedgerStateAfter_eq_validate_projected_replay
    (initial : NativeLedgerReplayState)
    (projections : List NativeBlockReplayProjection) :
    projectedLedgerStateAfter initial projections =
      validateNativeLedgerReplayChain
        initial
        (projectedReplayInputs projections) := by
  induction projections generalizing initial with
  | nil =>
      rfl
  | cons projection rest ih =>
      unfold projectedLedgerStateAfter
      unfold projectedReplayInputs
      unfold validateNativeLedgerReplayChain
      unfold projectionCarriesState
      by_cases parentEq :
          projection.carried.supply = initial.supply
      · simp [replayInputFromProjection, parentEq]
        by_cases leafEq :
            projection.carried.leafCount = initial.leafCount
        · simp [leafEq]
          by_cases spentEq :
              projection.carried.spentNullifiers =
                initial.spentNullifiers
          · simp [spentEq]
            by_cases consumedEq :
                projection.carried.consumedBridgeReplays =
                  initial.consumedBridgeReplays
            · simp [consumedEq]
              split
              · simp_all
              · simp_all
            · simp [consumedEq]
          · simp [spentEq]
        · simp [leafEq]
      · simp [replayInputFromProjection, parentEq]

theorem rawProjectedLedgerStateAfter_eq_validate_raw_replay
    (initial : NativeLedgerReplayState)
    (blocks : List RawDecodedNativeReplayBlock) :
    rawProjectedLedgerStateAfter initial blocks =
      validateNativeLedgerReplayChain initial (rawReplayInputs blocks) := by
  simp [
    rawProjectedLedgerStateAfter,
    rawReplayInputs,
    projectedLedgerStateAfter_eq_validate_projected_replay
  ]

theorem accepted_projected_ledger_state_after_startup_equivalence
    {initial final : NativeLedgerReplayState}
    {projections : List NativeBlockReplayProjection}
    (initialNullifiersNodup : initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup : initial.consumedBridgeReplays.Nodup)
    (accepted : projectedLedgerStateAfter initial projections = some final) :
    validateNativeLedgerReplayChain
        initial
        (projectedReplayInputs projections) =
        some final
      ∧ expectedNativeSupplyAfter
          initial.supply
          (projectedReplayInputs projections) =
          some final.supply
      ∧ expectedNativeLeafCountAfter
          initial.leafCount
          (projectedReplayInputs projections) =
          some final.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          initial
          (projectedReplayInputs projections) = true
      ∧ projectedCarriedStatePreconditions initial projections = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup := by
  have acceptedReplay := accepted
  rw [projectedLedgerStateAfter_eq_validate_projected_replay] at acceptedReplay
  have replayEquivalence :=
    accepted_projected_native_ledger_replay_chain_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedReplay
  exact
    ⟨acceptedReplay,
      replayEquivalence.left,
      replayEquivalence.right.left,
      replayEquivalence.right.right.left,
      replayEquivalence.right.right.right.left,
      replayEquivalence.right.right.right.right.left,
      replayEquivalence.right.right.right.right.right⟩

theorem accepted_raw_projected_ledger_state_after_startup_equivalence
    {initial final : NativeLedgerReplayState}
    {blocks : List RawDecodedNativeReplayBlock}
    (initialNullifiersNodup : initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup : initial.consumedBridgeReplays.Nodup)
    (accepted : rawProjectedLedgerStateAfter initial blocks = some final) :
    validateNativeLedgerReplayChain
        initial
        (rawReplayInputs blocks) =
        some final
      ∧ expectedNativeSupplyAfter
          initial.supply
          (rawReplayInputs blocks) =
          some final.supply
      ∧ expectedNativeLeafCountAfter
          initial.leafCount
          (rawReplayInputs blocks) =
          some final.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          initial
          (rawReplayInputs blocks) = true
      ∧ rawProjectedCarriedStatePreconditions initial blocks = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup := by
  have acceptedProjected :
      projectedLedgerStateAfter
          initial
          (rawNativeReplayProjections blocks) =
        some final := by
    simpa [rawProjectedLedgerStateAfter] using accepted
  have equivalence :=
    accepted_projected_ledger_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedProjected
  simpa [
    rawReplayInputs,
    rawProjectedCarriedStatePreconditions
  ] using equivalence

theorem treeReplayInputFromProjection_projects_carried_state
    (projection : NativeLedgerTreeReplayProjection) :
    (treeReplayInputFromProjection projection).fst.parentSupply =
        projection.replay.carried.supply
      ∧ (treeReplayInputFromProjection projection).fst.leafStart =
        projection.replay.carried.leafCount
      ∧ (treeReplayInputFromProjection projection).fst.spentNullifiers =
        projection.replay.carried.spentNullifiers
      ∧ (treeReplayInputFromProjection projection).fst.consumedBridgeReplays =
        projection.replay.carried.consumedBridgeReplays
      ∧ (treeReplayInputFromProjection projection).fst.actions =
        projection.replay.actions
      ∧ (treeReplayInputFromProjection projection).snd =
        projection.treeInput := by
  simp [treeReplayInputFromProjection, replayInputFromProjection]

theorem ledgerBlocksFromProjectedTreeReplayInputs
    (projections : List NativeLedgerTreeReplayProjection) :
    ledgerBlocksFromTreeReplay (projectedTreeReplayInputs projections) =
      projectedReplayInputs (replayProjectionsFromTreeReplay projections) := by
  induction projections with
  | nil =>
      rfl
  | cons projection rest ih =>
      cases projection
      simp [
        projectedTreeReplayInputs,
        treeReplayInputFromProjection,
        projectedReplayInputs,
        replayProjectionsFromTreeReplay
      ]
      simpa [ledgerBlocksFromTreeReplay] using ih

theorem projectedLedgerTreeStateAfter_eq_validate_projected_tree_replay
    (initial : NativeLedgerTreeReplayState)
    (projections : List NativeLedgerTreeReplayProjection) :
    projectedLedgerTreeStateAfter initial projections =
      validateNativeLedgerTreeReplayChain
        initial
        (projectedTreeReplayInputs projections) := by
  induction projections generalizing initial with
  | nil =>
      rfl
  | cons projection rest ih =>
      cases projection with
      | mk replay treeInput =>
          unfold projectedLedgerTreeStateAfter
          unfold projectedTreeReplayInputs
          unfold treeReplayInputFromProjection
          unfold validateNativeLedgerTreeReplayChain
          unfold projectionCarriesState
          by_cases parentEq :
              replay.carried.supply = initial.ledger.supply
          · simp [replayInputFromProjection, parentEq]
            by_cases leafEq :
                replay.carried.leafCount = initial.ledger.leafCount
            · simp [leafEq]
              by_cases spentEq :
                  replay.carried.spentNullifiers =
                    initial.ledger.spentNullifiers
              · simp [spentEq]
                by_cases consumedEq :
                    replay.carried.consumedBridgeReplays =
                      initial.ledger.consumedBridgeReplays
                · simp [consumedEq]
                  split
                  · simp_all
                  · rename_i _ summary hEval
                    by_cases rootEq :
                        treeInput.parentRoot =
                          initial.commitmentRoot
                    · simp [rootEq]
                      by_cases treeOk :
                          treeTransitionAccepts treeInput = true
                      · simp [treeOk]
                        simpa [
                          hEval,
                          replayInputFromProjection,
                          parentEq,
                          leafEq,
                          spentEq,
                          consumedEq
                        ] using
                          ih
                            (nextLedgerTreeState
                              initial
                              (replayInputFromProjection replay)
                              summary
                              treeInput)
                      · simp [hEval, treeOk]
                    · simp [hEval, rootEq]
                · simp [consumedEq]
              · simp [spentEq]
            · simp [leafEq]
          · simp [replayInputFromProjection, parentEq]

theorem accepted_projected_ledger_tree_state_after_startup_equivalence
    {initial final : NativeLedgerTreeReplayState}
    {projections : List NativeLedgerTreeReplayProjection}
    (initialNullifiersNodup : initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (accepted :
      projectedLedgerTreeStateAfter initial projections = some final) :
    validateNativeLedgerTreeReplayChain
        initial
        (projectedTreeReplayInputs projections) =
        some final
      ∧ expectedCommitmentRootAfter
          initial.commitmentRoot
          (projectedTreeReplayInputs projections) =
        some final.commitmentRoot
      ∧ validateNativeLedgerReplayChain
          initial.ledger
          (ledgerBlocksFromTreeReplay
            (projectedTreeReplayInputs projections)) =
        some final.ledger
      ∧ expectedNativeSupplyAfter
          initial.ledger.supply
          (ledgerBlocksFromTreeReplay
            (projectedTreeReplayInputs projections)) =
        some final.ledger.supply
      ∧ expectedNativeLeafCountAfter
          initial.ledger.leafCount
          (ledgerBlocksFromTreeReplay
            (projectedTreeReplayInputs projections)) =
        some final.ledger.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          initial.ledger
          (ledgerBlocksFromTreeReplay
            (projectedTreeReplayInputs projections)) = true
      ∧ projectedTreeCarriedStatePreconditions
          initial
          projections = true
      ∧ final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup := by
  have acceptedReplay := accepted
  rw [
    projectedLedgerTreeStateAfter_eq_validate_projected_tree_replay
  ] at acceptedReplay
  have integrity :=
    accepted_native_ledger_tree_replay_chain_integrity_from
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedReplay
  have projectedLedgerAccepted :
      validateNativeLedgerReplayChain
          initial.ledger
          (projectedReplayInputs
            (replayProjectionsFromTreeReplay projections)) =
        some final.ledger := by
    simpa [ledgerBlocksFromProjectedTreeReplayInputs] using
      integrity.left
  have carried :=
    accepted_projected_native_ledger_replay_chain_carried_states
      projectedLedgerAccepted
  exact
    ⟨acceptedReplay,
      integrity.right.left,
      integrity.left,
      integrity.right.right.left,
      integrity.right.right.right.left,
      integrity.right.right.right.right.left,
      by
        simpa [projectedTreeCarriedStatePreconditions] using carried,
      integrity.right.right.right.right.right.left,
      integrity.right.right.right.right.right.right⟩

theorem replayProjectionsFromRawTreeReplay
    (blocks : List RawDecodedNativeTreeReplayBlock) :
    replayProjectionsFromTreeReplay
        (rawNativeTreeReplayProjections blocks) =
      rawNativeReplayProjections (rawDecodedBlocksFromTreeReplay blocks) := by
  induction blocks with
  | nil =>
      rfl
  | cons block rest ih =>
      simp [
        rawNativeTreeReplayProjections,
        replayProjectionsFromTreeReplay,
        rawDecodedBlocksFromTreeReplay,
        rawNativeReplayProjections,
        ih
      ]

theorem ledgerBlocksFromRawTreeReplayInputs
    (blocks : List RawDecodedNativeTreeReplayBlock) :
    ledgerBlocksFromTreeReplay (rawTreeReplayInputs blocks) =
      rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks) := by
  simp [
    rawTreeReplayInputs,
    rawReplayInputs,
    ledgerBlocksFromProjectedTreeReplayInputs,
    replayProjectionsFromRawTreeReplay
  ]

theorem rawProjectedLedgerTreeStateAfter_eq_validate_raw_tree_replay
    (initial : NativeLedgerTreeReplayState)
    (blocks : List RawDecodedNativeTreeReplayBlock) :
    rawProjectedLedgerTreeStateAfter initial blocks =
      validateNativeLedgerTreeReplayChain
        initial
        (rawTreeReplayInputs blocks) := by
  simp [
    rawProjectedLedgerTreeStateAfter,
    rawTreeReplayInputs,
    projectedLedgerTreeStateAfter_eq_validate_projected_tree_replay
  ]

theorem accepted_raw_projected_ledger_tree_state_after_startup_equivalence
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    (initialNullifiersNodup : initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (accepted :
      rawProjectedLedgerTreeStateAfter initial blocks = some final) :
    validateNativeLedgerTreeReplayChain
        initial
        (rawTreeReplayInputs blocks) =
        some final
      ∧ expectedCommitmentRootAfter
          initial.commitmentRoot
          (rawTreeReplayInputs blocks) =
        some final.commitmentRoot
      ∧ validateNativeLedgerReplayChain
          initial.ledger
          (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
        some final.ledger
      ∧ expectedNativeSupplyAfter
          initial.ledger.supply
          (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
        some final.ledger.supply
      ∧ expectedNativeLeafCountAfter
          initial.ledger.leafCount
          (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) =
        some final.ledger.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          initial.ledger
          (rawReplayInputs (rawDecodedBlocksFromTreeReplay blocks)) = true
      ∧ rawProjectedTreeCarriedStatePreconditions
          initial
          blocks = true
      ∧ final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup := by
  have acceptedProjected :
      projectedLedgerTreeStateAfter
          initial
          (rawNativeTreeReplayProjections blocks) =
        some final := by
    simpa [rawProjectedLedgerTreeStateAfter] using accepted
  have equivalence :=
    accepted_projected_ledger_tree_state_after_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      acceptedProjected
  simpa [
    rawTreeReplayInputs,
    rawProjectedTreeCarriedStatePreconditions,
    rawReplayInputs,
    ledgerBlocksFromProjectedTreeReplayInputs,
    replayProjectionsFromRawTreeReplay
  ] using equivalence

def rawDecodedBlockFromProjection
    (projection : NativeBlockReplayProjection) :
      RawDecodedNativeReplayBlock :=
  {
    carriedSupply := projection.carried.supply,
    carriedLeafCount := projection.carried.leafCount,
    carriedSpentNullifiers := projection.carried.spentNullifiers,
    carriedConsumedBridgeReplays := projection.carried.consumedBridgeReplays,
    decodedActions := projection.actions,
    decodedHeight := projection.height,
    decodedFeeTotal := projection.feeTotal,
    decodedHasCoinbase := projection.hasCoinbase,
    decodedClaimedSupply := projection.claimedSupply,
    decodedTxCountMatches := projection.txCountMatches,
    decodedStateRootMatches := projection.stateRootMatches,
    decodedKernelRootMatches := projection.kernelRootMatches,
    decodedNullifierRootMatches := projection.nullifierRootMatches,
    decodedExtrinsicsRootMatches := projection.extrinsicsRootMatches,
    decodedMessageRootMatches := projection.messageRootMatches,
    decodedMessageCountMatches := projection.messageCountMatches,
    decodedHeaderMmrRootMatches := projection.headerMmrRootMatches,
    decodedHeaderMmrLenMatches := projection.headerMmrLenMatches
  }

def rawDecodedBlocksFromProjections :
    List NativeBlockReplayProjection -> List RawDecodedNativeReplayBlock
  | [] => []
  | projection :: rest =>
      rawDecodedBlockFromProjection projection ::
        rawDecodedBlocksFromProjections rest

theorem raw_decoded_block_projection_round_trips
    (projection : NativeBlockReplayProjection) :
    projectionFromRawDecodedBlock
        (rawDecodedBlockFromProjection projection) =
      projection := by
  cases projection with
  | mk carried actions height feeTotal hasCoinbase claimedSupply
      txCountMatches stateRootMatches kernelRootMatches
      nullifierRootMatches extrinsicsRootMatches messageRootMatches
      messageCountMatches headerMmrRootMatches headerMmrLenMatches =>
      cases carried
      rfl

theorem raw_decoded_blocks_projection_round_trips
    (projections : List NativeBlockReplayProjection) :
    rawNativeReplayProjections
        (rawDecodedBlocksFromProjections projections) =
      projections := by
  induction projections with
  | nil =>
      rfl
  | cons projection rest ih =>
      simp [
        rawDecodedBlocksFromProjections,
        rawNativeReplayProjections,
        raw_decoded_block_projection_round_trips,
        ih
      ]

def rawDecodedTreeBlockFromProjection
    (projection : NativeLedgerTreeReplayProjection) :
      RawDecodedNativeTreeReplayBlock :=
  {
    decodedReplay := rawDecodedBlockFromProjection projection.replay,
    decodedTreeInput := projection.treeInput
  }

def rawDecodedTreeBlocksFromProjections :
    List NativeLedgerTreeReplayProjection ->
      List RawDecodedNativeTreeReplayBlock
  | [] => []
  | projection :: rest =>
      rawDecodedTreeBlockFromProjection projection ::
        rawDecodedTreeBlocksFromProjections rest

theorem raw_decoded_tree_block_projection_round_trips
    (projection : NativeLedgerTreeReplayProjection) :
    rawNativeTreeReplayProjections
        [rawDecodedTreeBlockFromProjection projection] =
      [projection] := by
  cases projection with
  | mk replay treeInput =>
      simp [
        rawNativeTreeReplayProjections,
        rawDecodedTreeBlockFromProjection,
        raw_decoded_block_projection_round_trips
      ]

theorem raw_decoded_tree_blocks_projection_round_trips
    (projections : List NativeLedgerTreeReplayProjection) :
    rawNativeTreeReplayProjections
        (rawDecodedTreeBlocksFromProjections projections) =
      projections := by
  induction projections with
  | nil =>
      rfl
  | cons projection rest ih =>
      cases projection with
      | mk replay treeInput =>
          simp [
            rawDecodedTreeBlocksFromProjections,
            rawNativeTreeReplayProjections,
            rawDecodedTreeBlockFromProjection,
            raw_decoded_block_projection_round_trips,
            ih
          ]

def validNativeReplayProjectionChain : List NativeBlockReplayProjection :=
  [
    {
      carried := initialNativeLedgerState 100 10,
      actions := validReplay.actions,
      height := validReplay.height,
      feeTotal := validReplay.feeTotal,
      hasCoinbase := validReplay.hasCoinbase,
      claimedSupply := validReplay.claimedSupply,
      txCountMatches := validReplay.txCountMatches,
      stateRootMatches := validReplay.stateRootMatches,
      kernelRootMatches := validReplay.kernelRootMatches,
      nullifierRootMatches := validReplay.nullifierRootMatches,
      extrinsicsRootMatches := validReplay.extrinsicsRootMatches,
      messageRootMatches := validReplay.messageRootMatches,
      messageCountMatches := validReplay.messageCountMatches,
      headerMmrRootMatches := validReplay.headerMmrRootMatches,
      headerMmrLenMatches := validReplay.headerMmrLenMatches
    },
    {
      carried :=
        {
          supply := 100,
          leafCount := 12,
          spentNullifiers := [1],
          consumedBridgeReplays := []
        },
      actions := [
        {
          commitmentCount := 1,
          ciphertextCount := 1,
          nullifiers := [2],
          bridgeReplayKey := some 7
        }
      ],
      height := 2,
      feeTotal := validReplay.feeTotal,
      hasCoinbase := validReplay.hasCoinbase,
      claimedSupply := validReplay.claimedSupply,
      txCountMatches := validReplay.txCountMatches,
      stateRootMatches := validReplay.stateRootMatches,
      kernelRootMatches := validReplay.kernelRootMatches,
      nullifierRootMatches := validReplay.nullifierRootMatches,
      extrinsicsRootMatches := validReplay.extrinsicsRootMatches,
      messageRootMatches := validReplay.messageRootMatches,
      messageCountMatches := validReplay.messageCountMatches,
      headerMmrRootMatches := validReplay.headerMmrRootMatches,
      headerMmrLenMatches := validReplay.headerMmrLenMatches
    }
  ]

def validRawDecodedNativeReplayChain :
    List RawDecodedNativeReplayBlock :=
  rawDecodedBlocksFromProjections validNativeReplayProjectionChain

theorem valid_projected_native_ledger_replay_chain_accepts :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState 100 10)
        (projectedReplayInputs validNativeReplayProjectionChain) =
      some
        {
          supply := 100,
          leafCount := 13,
          spentNullifiers := [2, 1],
          consumedBridgeReplays := [7]
        } := by
  rfl

theorem valid_projected_ledger_state_after_accepts :
    projectedLedgerStateAfter
        (initialNativeLedgerState 100 10)
        validNativeReplayProjectionChain =
      some
        {
          supply := 100,
          leafCount := 13,
          spentNullifiers := [2, 1],
          consumedBridgeReplays := [7]
        } := by
  rfl

theorem valid_projected_native_ledger_replay_chain_startup_equivalence :
    expectedNativeSupplyAfter
        100
        (projectedReplayInputs validNativeReplayProjectionChain) =
        some 100
      ∧ expectedNativeLeafCountAfter
          10
          (projectedReplayInputs validNativeReplayProjectionChain) =
          some 13
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          (initialNativeLedgerState 100 10)
          (projectedReplayInputs validNativeReplayProjectionChain) = true
      ∧ projectedCarriedStatePreconditions
          (initialNativeLedgerState 100 10)
          validNativeReplayProjectionChain = true := by
  have accepted := valid_projected_native_ledger_replay_chain_accepts
  have equivalence :=
    accepted_projected_native_ledger_replay_chain_startup_equivalence
      (by simp [initialNativeLedgerState])
      (by simp [initialNativeLedgerState])
      accepted
  exact
    ⟨equivalence.left,
      equivalence.right.left,
      equivalence.right.right.left,
      equivalence.right.right.right.left⟩

theorem valid_projected_ledger_state_after_startup_equivalence :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState 100 10)
        (projectedReplayInputs validNativeReplayProjectionChain) =
        some
          {
            supply := 100,
            leafCount := 13,
            spentNullifiers := [2, 1],
            consumedBridgeReplays := [7]
          }
      ∧ expectedNativeSupplyAfter
          100
          (projectedReplayInputs validNativeReplayProjectionChain) =
          some 100
      ∧ expectedNativeLeafCountAfter
          10
          (projectedReplayInputs validNativeReplayProjectionChain) =
          some 13
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          (initialNativeLedgerState 100 10)
          (projectedReplayInputs validNativeReplayProjectionChain) = true
      ∧ projectedCarriedStatePreconditions
          (initialNativeLedgerState 100 10)
          validNativeReplayProjectionChain = true
      ∧ [2, 1].Nodup
      ∧ [7].Nodup := by
  have accepted := valid_projected_ledger_state_after_accepts
  have equivalence :=
    accepted_projected_ledger_state_after_startup_equivalence
      (by simp [initialNativeLedgerState])
      (by simp [initialNativeLedgerState])
      accepted
  exact equivalence

theorem valid_raw_projected_ledger_state_after_accepts :
    rawProjectedLedgerStateAfter
        (initialNativeLedgerState 100 10)
        validRawDecodedNativeReplayChain =
      some
        {
          supply := 100,
          leafCount := 13,
          spentNullifiers := [2, 1],
          consumedBridgeReplays := [7]
        } := by
  rw [
    rawProjectedLedgerStateAfter,
    validRawDecodedNativeReplayChain,
    raw_decoded_blocks_projection_round_trips
  ]
  exact valid_projected_ledger_state_after_accepts

theorem valid_raw_projected_ledger_state_after_startup_equivalence :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState 100 10)
        (rawReplayInputs validRawDecodedNativeReplayChain) =
        some
          {
            supply := 100,
            leafCount := 13,
            spentNullifiers := [2, 1],
            consumedBridgeReplays := [7]
          }
      ∧ expectedNativeSupplyAfter
          100
          (rawReplayInputs validRawDecodedNativeReplayChain) =
          some 100
      ∧ expectedNativeLeafCountAfter
          10
          (rawReplayInputs validRawDecodedNativeReplayChain) =
          some 13
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          (initialNativeLedgerState 100 10)
          (rawReplayInputs validRawDecodedNativeReplayChain) = true
      ∧ rawProjectedCarriedStatePreconditions
          (initialNativeLedgerState 100 10)
          validRawDecodedNativeReplayChain = true
      ∧ [2, 1].Nodup
      ∧ [7].Nodup := by
  have accepted := valid_raw_projected_ledger_state_after_accepts
  exact
    accepted_raw_projected_ledger_state_after_startup_equivalence
      (by simp [initialNativeLedgerState])
      (by simp [initialNativeLedgerState])
      accepted

def acceptedTreeInputFromRoot (root : Nat) : TreeTransitionInput :=
  {
    parentRoot := root,
    appliedRoot := root + 1,
    proofStartingRoot := root,
    proofEndingRoot := root + 1,
    applyCommitmentsSucceeds := true
  }

def treeReplayProjectionsWithRoots :
    Nat -> List NativeBlockReplayProjection ->
      List NativeLedgerTreeReplayProjection
  | _, [] => []
  | root, projection :: rest =>
      {
        replay := projection,
        treeInput := acceptedTreeInputFromRoot root
      } :: treeReplayProjectionsWithRoots (root + 1) rest

def validNativeLedgerTreeReplayProjectionChain :
    List NativeLedgerTreeReplayProjection :=
  treeReplayProjectionsWithRoots 50 validNativeReplayProjectionChain

def validRawDecodedNativeLedgerTreeReplayChain :
    List RawDecodedNativeTreeReplayBlock :=
  rawDecodedTreeBlocksFromProjections
    validNativeLedgerTreeReplayProjectionChain

theorem valid_projected_ledger_tree_state_after_accepts :
    projectedLedgerTreeStateAfter
        (initialNativeLedgerTreeState 100 10 50)
        validNativeLedgerTreeReplayProjectionChain =
      some
        {
          ledger :=
            {
              supply := 100,
              leafCount := 13,
              spentNullifiers := [2, 1],
              consumedBridgeReplays := [7]
            },
          commitmentRoot := 52
        } := by
  rfl

theorem valid_raw_projected_ledger_tree_state_after_accepts :
    rawProjectedLedgerTreeStateAfter
        (initialNativeLedgerTreeState 100 10 50)
        validRawDecodedNativeLedgerTreeReplayChain =
      some
        {
          ledger :=
            {
              supply := 100,
              leafCount := 13,
              spentNullifiers := [2, 1],
              consumedBridgeReplays := [7]
            },
          commitmentRoot := 52
        } := by
  rw [
    rawProjectedLedgerTreeStateAfter,
    validRawDecodedNativeLedgerTreeReplayChain,
    raw_decoded_tree_blocks_projection_round_trips
  ]
  exact valid_projected_ledger_tree_state_after_accepts

theorem valid_raw_projected_ledger_tree_state_after_startup_equivalence :
    validateNativeLedgerTreeReplayChain
        (initialNativeLedgerTreeState 100 10 50)
        (rawTreeReplayInputs validRawDecodedNativeLedgerTreeReplayChain) =
        some
          {
            ledger :=
              {
                supply := 100,
                leafCount := 13,
                spentNullifiers := [2, 1],
                consumedBridgeReplays := [7]
              },
            commitmentRoot := 52
          }
      ∧ expectedCommitmentRootAfter
          50
          (rawTreeReplayInputs validRawDecodedNativeLedgerTreeReplayChain) =
        some 52
      ∧ validateNativeLedgerReplayChain
          (initialNativeLedgerState 100 10)
          (rawReplayInputs
            (rawDecodedBlocksFromTreeReplay
              validRawDecodedNativeLedgerTreeReplayChain)) =
        some
          {
            supply := 100,
            leafCount := 13,
            spentNullifiers := [2, 1],
            consumedBridgeReplays := [7]
          }
      ∧ expectedNativeSupplyAfter
          100
          (rawReplayInputs
            (rawDecodedBlocksFromTreeReplay
              validRawDecodedNativeLedgerTreeReplayChain)) =
        some 100
      ∧ expectedNativeLeafCountAfter
          10
          (rawReplayInputs
            (rawDecodedBlocksFromTreeReplay
              validRawDecodedNativeLedgerTreeReplayChain)) =
        some 13
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          (initialNativeLedgerState 100 10)
          (rawReplayInputs
            (rawDecodedBlocksFromTreeReplay
              validRawDecodedNativeLedgerTreeReplayChain)) = true
      ∧ rawProjectedTreeCarriedStatePreconditions
          (initialNativeLedgerTreeState 100 10 50)
          validRawDecodedNativeLedgerTreeReplayChain = true
      ∧ [2, 1].Nodup
      ∧ [7].Nodup := by
  have accepted := valid_raw_projected_ledger_tree_state_after_accepts
  exact
    accepted_raw_projected_ledger_tree_state_after_startup_equivalence
      (by simp [initialNativeLedgerTreeState, initialNativeLedgerState])
      (by simp [initialNativeLedgerTreeState, initialNativeLedgerState])
      accepted

theorem stale_raw_projected_ledger_tree_root_rejects :
    rawProjectedLedgerTreeStateAfter
        (initialNativeLedgerTreeState 100 10 49)
        validRawDecodedNativeLedgerTreeReplayChain =
      none := by
  rfl

def staleProjectedCarriedStateChain : List NativeBlockReplayProjection :=
  [
    {
      carried :=
        {
          supply := 101,
          leafCount := 10,
          spentNullifiers := [],
          consumedBridgeReplays := []
        },
      actions := validReplay.actions,
      height := validReplay.height,
      feeTotal := validReplay.feeTotal,
      hasCoinbase := validReplay.hasCoinbase,
      claimedSupply := validReplay.claimedSupply,
      txCountMatches := validReplay.txCountMatches,
      stateRootMatches := validReplay.stateRootMatches,
      kernelRootMatches := validReplay.kernelRootMatches,
      nullifierRootMatches := validReplay.nullifierRootMatches,
      extrinsicsRootMatches := validReplay.extrinsicsRootMatches,
      messageRootMatches := validReplay.messageRootMatches,
      messageCountMatches := validReplay.messageCountMatches,
      headerMmrRootMatches := validReplay.headerMmrRootMatches,
      headerMmrLenMatches := validReplay.headerMmrLenMatches
    }
  ]

def staleRawDecodedCarriedStateChain :
    List RawDecodedNativeReplayBlock :=
  rawDecodedBlocksFromProjections staleProjectedCarriedStateChain

theorem stale_projected_carried_state_rejects :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState 100 10)
        (projectedReplayInputs staleProjectedCarriedStateChain) =
      none := by
  rfl

theorem stale_raw_projected_carried_state_rejects :
    rawProjectedLedgerStateAfter
        (initialNativeLedgerState 100 10)
        staleRawDecodedCarriedStateChain =
      none := by
  rw [
    rawProjectedLedgerStateAfter,
    staleRawDecodedCarriedStateChain,
    raw_decoded_blocks_projection_round_trips,
    projectedLedgerStateAfter_eq_validate_projected_replay
  ]
  exact stale_projected_carried_state_rejects

end BlockReplayInputProjection
end Native
end Hegemon

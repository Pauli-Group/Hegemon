import Hegemon.Native.BlockReplayRefinement
import Hegemon.Native.CommitmentTreeRefinement

namespace Hegemon
namespace Native
namespace AcceptedChain

open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.BlockReplayRefinement
open Hegemon.Native.CommitmentTreeRefinement
open Hegemon.Consensus.TreeTransition

def validateNativeReplayChain
    (parentSupply : Nat)
    (spentNullifiers : List Nat) :
    List BlockReplayInput -> Option Nat
  | [] => some parentSupply
  | block :: rest =>
      if block.parentSupply = parentSupply then
        if block.spentNullifiers = spentNullifiers then
          match evaluateBlockReplayRefinement block with
          | Except.error _ => none
          | Except.ok summary =>
              validateNativeReplayChain
                summary.expectedSupply
                (importedNullifierStateFrom spentNullifiers block.actions)
                rest
        else
          none
      else
        none

def replayedNullifierState :
    List Nat -> List BlockReplayInput -> List Nat
  | spentNullifiers, [] => spentNullifiers
  | spentNullifiers, block :: rest =>
      replayedNullifierState
        (importedNullifierStateFrom spentNullifiers block.actions)
        rest

def chainNullifiers (blocks : List BlockReplayInput) : List Nat :=
  replayedNullifierState [] blocks

def expectedNativeSupplyAfter
    (parentSupply : Nat) :
    List BlockReplayInput -> Option Nat
  | [] => some parentSupply
  | block :: rest =>
      if block.parentSupply = parentSupply then
        match expectedSupply block with
        | none => none
        | some next => expectedNativeSupplyAfter next rest
      else
        none

def nativeReplayChainNullifierPreconditions :
    List Nat ->
    List BlockReplayInput -> Bool
  | _, [] => true
  | spentNullifiers, block :: rest =>
      if block.spentNullifiers = spentNullifiers then
        actionStreamPreconditions (streamInput block)
          && nativeReplayChainNullifierPreconditions
            (importedNullifierStateFrom spentNullifiers block.actions)
            rest
      else
        false

theorem accepted_native_replay_chain_no_counterfeiting_from
    {parentSupply final : Nat}
    {spentNullifiers : List Nat}
    {blocks : List BlockReplayInput}
    (accepted :
      validateNativeReplayChain parentSupply spentNullifiers blocks =
        some final) :
    expectedNativeSupplyAfter parentSupply blocks = some final := by
  induction blocks generalizing parentSupply spentNullifiers with
  | nil =>
      simp [validateNativeReplayChain, expectedNativeSupplyAfter] at accepted ⊢
      exact accepted
  | cons block rest ih =>
      unfold validateNativeReplayChain at accepted
      unfold expectedNativeSupplyAfter
      by_cases parentEq : block.parentSupply = parentSupply
      · simp [parentEq] at accepted ⊢
        by_cases spentMatches : block.spentNullifiers = spentNullifiers
        · simp [spentMatches] at accepted
          cases replayResult : evaluateBlockReplayRefinement block with
          | error rejection =>
              simp [replayResult] at accepted
          | ok summary =>
              have supplyFacts := accepted_claims_expected_supply replayResult
              rw [supplyFacts.left]
              simp [replayResult] at accepted
              exact ih accepted
        · simp [spentMatches] at accepted
      · simp [parentEq] at accepted

theorem accepted_native_replay_chain_no_counterfeiting
    {genesis final : Nat}
    {blocks : List BlockReplayInput}
    (accepted : validateNativeReplayChain genesis [] blocks = some final) :
    expectedNativeSupplyAfter genesis blocks = some final :=
  accepted_native_replay_chain_no_counterfeiting_from accepted

theorem accepted_native_replay_chain_nullifier_preconditions_from
    {parentSupply final : Nat}
    {spentNullifiers : List Nat}
    {blocks : List BlockReplayInput}
    (accepted :
      validateNativeReplayChain parentSupply spentNullifiers blocks =
        some final) :
    nativeReplayChainNullifierPreconditions spentNullifiers blocks = true := by
  induction blocks generalizing parentSupply spentNullifiers with
  | nil =>
      rfl
  | cons block rest ih =>
      unfold validateNativeReplayChain at accepted
      unfold nativeReplayChainNullifierPreconditions
      by_cases parentEq : block.parentSupply = parentSupply
      · simp [parentEq] at accepted
        by_cases spentMatches : block.spentNullifiers = spentNullifiers
        · simp [spentMatches]
          simp [spentMatches] at accepted
          cases replayResult : evaluateBlockReplayRefinement block with
          | error rejection =>
              simp [replayResult] at accepted
          | ok summary =>
              have streamOk := accepted_has_action_stream_effect replayResult
              have streamAcceptsTrue :
                  actionStreamAccepts (streamInput block) = true := by
                simp [actionStreamAccepts, streamOk]
              have streamPreconditionsTrue :
                  actionStreamPreconditions (streamInput block) = true := by
                rw [← accepts_iff_stream_preconditions (streamInput block)]
                exact streamAcceptsTrue
              simp [replayResult] at accepted
              simp [streamPreconditionsTrue, ih accepted]
        · simp [spentMatches] at accepted
      · simp [parentEq] at accepted

theorem accepted_native_replay_chain_nullifier_preconditions
    {genesis final : Nat}
    {blocks : List BlockReplayInput}
    (accepted : validateNativeReplayChain genesis [] blocks = some final) :
    nativeReplayChainNullifierPreconditions [] blocks = true :=
  accepted_native_replay_chain_nullifier_preconditions_from accepted

theorem accepted_native_replay_chain_nullifiers_unique_from
    {parentSupply final : Nat}
    {spentNullifiers : List Nat}
    {blocks : List BlockReplayInput}
    (spentNodup : spentNullifiers.Nodup)
    (accepted :
      validateNativeReplayChain parentSupply spentNullifiers blocks =
        some final) :
    (replayedNullifierState spentNullifiers blocks).Nodup := by
  induction blocks generalizing parentSupply spentNullifiers with
  | nil =>
      simp [replayedNullifierState]
      exact spentNodup
  | cons block rest ih =>
      unfold validateNativeReplayChain at accepted
      unfold replayedNullifierState
      by_cases parentEq : block.parentSupply = parentSupply
      · simp [parentEq] at accepted
        by_cases spentMatches : block.spentNullifiers = spentNullifiers
        · simp [spentMatches] at accepted
          cases replayResult : evaluateBlockReplayRefinement block with
          | error rejection =>
              simp [replayResult] at accepted
          | ok summary =>
              have streamOk := accepted_has_action_stream_effect replayResult
              have streamSpentNodup :
                  (streamInput block).spentNullifiers.Nodup := by
                simp [streamInput, spentMatches, spentNodup]
              have nextSpentNodup :
                  (importedNullifierStateFrom
                    spentNullifiers
                    block.actions).Nodup := by
                have preserved :=
                  evaluateActionStreamEffect_preserves_imported_nullifier_nodup
                    streamSpentNodup
                    streamOk
                simpa [streamInput, spentMatches] using preserved
              simp [replayResult] at accepted
              exact ih nextSpentNodup accepted
        · simp [spentMatches] at accepted
      · simp [parentEq] at accepted

theorem accepted_native_replay_chain_nullifiers_unique
    {genesis final : Nat}
    {blocks : List BlockReplayInput}
    (accepted : validateNativeReplayChain genesis [] blocks = some final) :
    (chainNullifiers blocks).Nodup := by
  exact accepted_native_replay_chain_nullifiers_unique_from
    (by simp : ([] : List Nat).Nodup)
    accepted

theorem accepted_native_replay_chain_startup_equivalence
    {genesis final : Nat}
    {blocks : List BlockReplayInput}
    (accepted : validateNativeReplayChain genesis [] blocks = some final) :
    expectedNativeSupplyAfter genesis blocks = some final
      ∧ nativeReplayChainNullifierPreconditions [] blocks = true
      ∧ (chainNullifiers blocks).Nodup := by
  exact
    ⟨accepted_native_replay_chain_no_counterfeiting accepted,
      accepted_native_replay_chain_nullifier_preconditions accepted,
      accepted_native_replay_chain_nullifiers_unique accepted⟩

structure NativeLedgerReplayState where
  supply : Nat
  leafCount : Nat
  spentNullifiers : List Nat
  consumedBridgeReplays : List Nat
deriving DecidableEq, Repr

def initialNativeLedgerState
    (supply leafCount : Nat) : NativeLedgerReplayState :=
  {
    supply := supply,
    leafCount := leafCount,
    spentNullifiers := [],
    consumedBridgeReplays := []
  }

def nextLedgerState
    (state : NativeLedgerReplayState)
    (block : BlockReplayInput)
    (summary : BlockReplaySummary) : NativeLedgerReplayState :=
  {
    supply := summary.expectedSupply,
    leafCount := summary.nextLeafCount,
    spentNullifiers :=
      importedNullifierStateFrom state.spentNullifiers block.actions,
    consumedBridgeReplays :=
      importedBridgeReplayStateFrom state.consumedBridgeReplays block.actions
  }

def validateNativeLedgerReplayChain
    (state : NativeLedgerReplayState) :
    List BlockReplayInput -> Option NativeLedgerReplayState
  | [] => some state
  | block :: rest =>
      if block.parentSupply = state.supply then
        if block.leafStart = state.leafCount then
          if block.spentNullifiers = state.spentNullifiers then
            if block.consumedBridgeReplays = state.consumedBridgeReplays then
              match evaluateBlockReplayRefinement block with
              | Except.error _ => none
              | Except.ok summary =>
                  validateNativeLedgerReplayChain
                    (nextLedgerState state block summary)
                    rest
            else
              none
          else
            none
        else
          none
      else
        none

def expectedNativeLeafCountAfter
    (leafCount : Nat) :
    List BlockReplayInput -> Option Nat
  | [] => some leafCount
  | block :: rest =>
      if block.leafStart = leafCount then
        match evaluateBlockReplayRefinement block with
        | Except.error _ => none
        | Except.ok summary =>
            expectedNativeLeafCountAfter summary.nextLeafCount rest
      else
        none

def nativeLedgerReplayCommitmentPlanPreconditions :
    NativeLedgerReplayState -> List BlockReplayInput -> Bool
  | _, [] => true
  | state, block :: rest =>
      if block.leafStart = state.leafCount then
        match evaluateBlockReplayRefinement block with
        | Except.error _ => false
        | Except.ok summary =>
            match commitmentStartsFrom state.leafCount block.actions with
            | none => false
            | some (nextLeaf, plannedStarts) =>
                if nextLeaf = summary.nextLeafCount then
                  if plannedStarts = summary.plannedStarts then
                    nativeLedgerReplayCommitmentPlanPreconditions
                      (nextLedgerState state block summary)
                      rest
                  else
                    false
                else
                  false
      else
        false

theorem accepted_native_ledger_replay_chain_supply_from
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (accepted :
      validateNativeLedgerReplayChain initial blocks = some final) :
    expectedNativeSupplyAfter initial.supply blocks = some final.supply := by
  induction blocks generalizing initial with
  | nil =>
      simp [validateNativeLedgerReplayChain] at accepted
      subst final
      rfl
  | cons block rest ih =>
      unfold validateNativeLedgerReplayChain at accepted
      unfold expectedNativeSupplyAfter
      by_cases parentEq : block.parentSupply = initial.supply
      · simp [parentEq] at accepted ⊢
        by_cases leafEq : block.leafStart = initial.leafCount
        · simp [leafEq] at accepted
          by_cases spentEq :
              block.spentNullifiers = initial.spentNullifiers
          · simp [spentEq] at accepted
            by_cases consumedEq :
                block.consumedBridgeReplays =
                  initial.consumedBridgeReplays
            · simp [consumedEq] at accepted
              cases replayResult : evaluateBlockReplayRefinement block with
              | error rejection =>
                  simp [replayResult] at accepted
              | ok summary =>
                  have supplyFacts :=
                    accepted_claims_expected_supply replayResult
                  rw [supplyFacts.left]
                  simp [replayResult] at accepted
                  simpa [nextLedgerState] using ih accepted
            · simp [consumedEq] at accepted
          · simp [spentEq] at accepted
        · simp [leafEq] at accepted
      · simp [parentEq] at accepted

theorem accepted_native_ledger_replay_chain_leaf_cursor_from
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (accepted :
      validateNativeLedgerReplayChain initial blocks = some final) :
    expectedNativeLeafCountAfter initial.leafCount blocks =
      some final.leafCount := by
  induction blocks generalizing initial with
  | nil =>
      simp [validateNativeLedgerReplayChain] at accepted
      subst final
      rfl
  | cons block rest ih =>
      unfold validateNativeLedgerReplayChain at accepted
      unfold expectedNativeLeafCountAfter
      by_cases parentEq : block.parentSupply = initial.supply
      · simp [parentEq] at accepted
        by_cases leafEq : block.leafStart = initial.leafCount
        · simp [leafEq] at accepted ⊢
          by_cases spentEq :
              block.spentNullifiers = initial.spentNullifiers
          · simp [spentEq] at accepted
            by_cases consumedEq :
                block.consumedBridgeReplays =
                  initial.consumedBridgeReplays
            · simp [consumedEq] at accepted
              cases replayResult : evaluateBlockReplayRefinement block with
              | error rejection =>
                  simp [replayResult] at accepted
              | ok summary =>
                  simp [replayResult] at accepted ⊢
                  simpa [nextLedgerState] using ih accepted
            · simp [consumedEq] at accepted
          · simp [spentEq] at accepted
        · simp [leafEq] at accepted
      · simp [parentEq] at accepted

theorem accepted_native_ledger_replay_chain_commitment_plans_canonical_from
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (accepted :
      validateNativeLedgerReplayChain initial blocks = some final) :
    nativeLedgerReplayCommitmentPlanPreconditions initial blocks = true := by
  induction blocks generalizing initial with
  | nil =>
      rfl
  | cons block rest ih =>
      unfold validateNativeLedgerReplayChain at accepted
      unfold nativeLedgerReplayCommitmentPlanPreconditions
      by_cases parentEq : block.parentSupply = initial.supply
      · simp [parentEq] at accepted
        by_cases leafEq : block.leafStart = initial.leafCount
        · simp [leafEq] at accepted ⊢
          by_cases spentEq :
              block.spentNullifiers = initial.spentNullifiers
          · simp [spentEq] at accepted
            by_cases consumedEq :
                block.consumedBridgeReplays =
                  initial.consumedBridgeReplays
            · simp [consumedEq] at accepted
              cases replayResult : evaluateBlockReplayRefinement block with
              | error rejection =>
                  simp [replayResult] at accepted
              | ok summary =>
                  have streamOk :=
                    accepted_has_action_stream_effect replayResult
                  have startsOk :
                      commitmentStartsFrom
                          initial.leafCount
                          block.actions =
                        some
                          (summary.nextLeafCount,
                            summary.plannedStarts) := by
                    simpa [streamInput, leafEq] using
                      accepted_stream_commitment_starts_from streamOk
                  simp [replayResult, startsOk] at accepted ⊢
                  exact ih accepted
            · simp [consumedEq] at accepted
          · simp [spentEq] at accepted
        · simp [leafEq] at accepted
      · simp [parentEq] at accepted

theorem accepted_native_ledger_replay_chain_nullifiers_unique_from
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (initialNodup : initial.spentNullifiers.Nodup)
    (accepted :
      validateNativeLedgerReplayChain initial blocks = some final) :
    final.spentNullifiers.Nodup := by
  induction blocks generalizing initial with
  | nil =>
      simp [validateNativeLedgerReplayChain] at accepted
      subst final
      exact initialNodup
  | cons block rest ih =>
      unfold validateNativeLedgerReplayChain at accepted
      by_cases parentEq : block.parentSupply = initial.supply
      · simp [parentEq] at accepted
        by_cases leafEq : block.leafStart = initial.leafCount
        · simp [leafEq] at accepted
          by_cases spentEq :
              block.spentNullifiers = initial.spentNullifiers
          · simp [spentEq] at accepted
            by_cases consumedEq :
                block.consumedBridgeReplays =
                  initial.consumedBridgeReplays
            · simp [consumedEq] at accepted
              cases replayResult : evaluateBlockReplayRefinement block with
              | error rejection =>
                  simp [replayResult] at accepted
              | ok summary =>
                  have streamOk :=
                    accepted_has_action_stream_effect replayResult
                  have streamSpentNodup :
                      (streamInput block).spentNullifiers.Nodup := by
                    simp [streamInput, spentEq, initialNodup]
                  have nextSpentNodup :
                      (importedNullifierStateFrom
                        initial.spentNullifiers
                        block.actions).Nodup := by
                    have preserved :=
                      evaluateActionStreamEffect_preserves_imported_nullifier_nodup
                        streamSpentNodup
                        streamOk
                    simpa [streamInput, spentEq] using preserved
                  simp [replayResult] at accepted
                  exact ih
                    (by
                      simpa [nextLedgerState] using nextSpentNodup)
                    accepted
            · simp [consumedEq] at accepted
          · simp [spentEq] at accepted
        · simp [leafEq] at accepted
      · simp [parentEq] at accepted

theorem accepted_native_ledger_replay_chain_bridge_replays_unique_from
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (initialNodup : initial.consumedBridgeReplays.Nodup)
    (accepted :
      validateNativeLedgerReplayChain initial blocks = some final) :
    final.consumedBridgeReplays.Nodup := by
  induction blocks generalizing initial with
  | nil =>
      simp [validateNativeLedgerReplayChain] at accepted
      subst final
      exact initialNodup
  | cons block rest ih =>
      unfold validateNativeLedgerReplayChain at accepted
      by_cases parentEq : block.parentSupply = initial.supply
      · simp [parentEq] at accepted
        by_cases leafEq : block.leafStart = initial.leafCount
        · simp [leafEq] at accepted
          by_cases spentEq :
              block.spentNullifiers = initial.spentNullifiers
          · simp [spentEq] at accepted
            by_cases consumedEq :
                block.consumedBridgeReplays =
                  initial.consumedBridgeReplays
            · simp [consumedEq] at accepted
              cases replayResult : evaluateBlockReplayRefinement block with
              | error rejection =>
                  simp [replayResult] at accepted
              | ok summary =>
                  have streamOk :=
                    accepted_has_action_stream_effect replayResult
                  have streamConsumedNodup :
                      (streamInput block).consumedBridgeReplays.Nodup := by
                    simp [streamInput, consumedEq, initialNodup]
                  have nextConsumedNodup :
                      (importedBridgeReplayStateFrom
                        initial.consumedBridgeReplays
                        block.actions).Nodup := by
                    have preserved :=
                      evaluateActionStreamEffect_preserves_imported_bridge_replay_nodup
                        streamConsumedNodup
                        streamOk
                    simpa [streamInput, consumedEq] using preserved
                  simp [replayResult] at accepted
                  exact ih
                    (by
                      simpa [nextLedgerState] using nextConsumedNodup)
                    accepted
            · simp [consumedEq] at accepted
          · simp [spentEq] at accepted
        · simp [leafEq] at accepted
      · simp [parentEq] at accepted

theorem accepted_native_ledger_replay_chain_startup_equivalence
    {initial final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (initialNullifiersNodup : initial.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup : initial.consumedBridgeReplays.Nodup)
    (accepted :
      validateNativeLedgerReplayChain initial blocks = some final) :
    expectedNativeSupplyAfter initial.supply blocks = some final.supply
      ∧ expectedNativeLeafCountAfter initial.leafCount blocks =
          some final.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions initial blocks = true
      ∧ final.spentNullifiers.Nodup
      ∧ final.consumedBridgeReplays.Nodup := by
  exact
    ⟨accepted_native_ledger_replay_chain_supply_from accepted,
      accepted_native_ledger_replay_chain_leaf_cursor_from accepted,
      accepted_native_ledger_replay_chain_commitment_plans_canonical_from
        accepted,
      accepted_native_ledger_replay_chain_nullifiers_unique_from
        initialNullifiersNodup
        accepted,
      accepted_native_ledger_replay_chain_bridge_replays_unique_from
        initialBridgeReplaysNodup
        accepted⟩

structure NativeLedgerTreeReplayState where
  ledger : NativeLedgerReplayState
  commitmentRoot : Nat
deriving DecidableEq, Repr

def initialNativeLedgerTreeState
    (supply leafCount commitmentRoot : Nat) :
    NativeLedgerTreeReplayState :=
  {
    ledger := initialNativeLedgerState supply leafCount,
    commitmentRoot := commitmentRoot
  }

def nextLedgerTreeState
    (state : NativeLedgerTreeReplayState)
    (block : BlockReplayInput)
    (summary : BlockReplaySummary)
    (treeInput : TreeTransitionInput) :
    NativeLedgerTreeReplayState :=
  {
    ledger := nextLedgerState state.ledger block summary,
    commitmentRoot := treeInput.appliedRoot
  }

def ledgerBlocksFromTreeReplay
    (blocks : List (BlockReplayInput × TreeTransitionInput)) :
    List BlockReplayInput :=
  blocks.map Prod.fst

def validateNativeLedgerTreeReplayChain
    (state : NativeLedgerTreeReplayState) :
    List (BlockReplayInput × TreeTransitionInput) ->
      Option NativeLedgerTreeReplayState
  | [] => some state
  | (block, treeInput) :: rest =>
      if block.parentSupply = state.ledger.supply then
        if block.leafStart = state.ledger.leafCount then
          if block.spentNullifiers = state.ledger.spentNullifiers then
            if block.consumedBridgeReplays =
                state.ledger.consumedBridgeReplays then
              match evaluateBlockReplayRefinement block with
              | Except.error _ => none
              | Except.ok summary =>
                  if treeInput.parentRoot = state.commitmentRoot then
                    if treeTransitionAccepts treeInput then
                      validateNativeLedgerTreeReplayChain
                        (nextLedgerTreeState
                          state
                          block
                          summary
                          treeInput)
                        rest
                    else
                      none
                  else
                    none
            else
              none
          else
            none
        else
          none
      else
        none

def expectedCommitmentRootAfter
    (commitmentRoot : Nat) :
    List (BlockReplayInput × TreeTransitionInput) -> Option Nat
  | [] => some commitmentRoot
  | (_block, treeInput) :: rest =>
      if treeInput.parentRoot = commitmentRoot then
        if treeTransitionAccepts treeInput then
          expectedCommitmentRootAfter treeInput.appliedRoot rest
        else
          none
      else
        none

theorem accepted_native_ledger_tree_replay_chain_root_from
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List (BlockReplayInput × TreeTransitionInput)}
    (accepted :
      validateNativeLedgerTreeReplayChain initial blocks = some final) :
    expectedCommitmentRootAfter initial.commitmentRoot blocks =
      some final.commitmentRoot := by
  induction blocks generalizing initial with
  | nil =>
      simp [validateNativeLedgerTreeReplayChain] at accepted
      subst final
      rfl
  | cons pair rest ih =>
      cases pair with
      | mk block treeInput =>
          unfold validateNativeLedgerTreeReplayChain at accepted
          unfold expectedCommitmentRootAfter
          by_cases parentEq : block.parentSupply = initial.ledger.supply
          · simp [parentEq] at accepted
            by_cases leafEq : block.leafStart = initial.ledger.leafCount
            · simp [leafEq] at accepted
              by_cases spentEq :
                  block.spentNullifiers =
                    initial.ledger.spentNullifiers
              · simp [spentEq] at accepted
                by_cases consumedEq :
                    block.consumedBridgeReplays =
                      initial.ledger.consumedBridgeReplays
                · simp [consumedEq] at accepted
                  cases replayResult :
                      evaluateBlockReplayRefinement block with
                  | error rejection =>
                      simp [replayResult] at accepted
                  | ok summary =>
                      simp [replayResult] at accepted
                      by_cases rootEq :
                          treeInput.parentRoot =
                            initial.commitmentRoot
                      · simp [rootEq] at accepted ⊢
                        by_cases treeOk :
                            treeTransitionAccepts treeInput = true
                        · simp [treeOk] at accepted ⊢
                          simpa [nextLedgerTreeState] using
                            ih accepted
                        · simp [treeOk] at accepted
                      · simp [rootEq] at accepted ⊢
                · simp [consumedEq] at accepted
              · simp [spentEq] at accepted
            · simp [leafEq] at accepted
          · simp [parentEq] at accepted

theorem accepted_native_ledger_tree_replay_chain_ledger_from
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List (BlockReplayInput × TreeTransitionInput)}
    (accepted :
      validateNativeLedgerTreeReplayChain initial blocks = some final) :
    validateNativeLedgerReplayChain
        initial.ledger
        (ledgerBlocksFromTreeReplay blocks) =
      some final.ledger := by
  induction blocks generalizing initial with
  | nil =>
      simp [
        validateNativeLedgerTreeReplayChain,
        validateNativeLedgerReplayChain,
        ledgerBlocksFromTreeReplay
      ] at accepted ⊢
      subst final
      rfl
  | cons pair rest ih =>
      cases pair with
      | mk block treeInput =>
          unfold validateNativeLedgerTreeReplayChain at accepted
          unfold validateNativeLedgerReplayChain
          simp [ledgerBlocksFromTreeReplay]
          by_cases parentEq : block.parentSupply = initial.ledger.supply
          · simp [parentEq] at accepted ⊢
            by_cases leafEq : block.leafStart = initial.ledger.leafCount
            · simp [leafEq] at accepted ⊢
              by_cases spentEq :
                  block.spentNullifiers =
                    initial.ledger.spentNullifiers
              · simp [spentEq] at accepted ⊢
                by_cases consumedEq :
                    block.consumedBridgeReplays =
                      initial.ledger.consumedBridgeReplays
                · simp [consumedEq] at accepted ⊢
                  cases replayResult :
                      evaluateBlockReplayRefinement block with
                  | error rejection =>
                      simp [replayResult] at accepted
                  | ok summary =>
                      simp [replayResult] at accepted ⊢
                      by_cases rootEq :
                          treeInput.parentRoot =
                            initial.commitmentRoot
                      · simp [rootEq] at accepted
                        by_cases treeOk :
                            treeTransitionAccepts treeInput = true
                        · simp [treeOk] at accepted
                          simpa [nextLedgerTreeState] using
                            ih accepted
                        · simp [treeOk] at accepted
                      · simp [rootEq] at accepted
                · simp [consumedEq] at accepted
              · simp [spentEq] at accepted
            · simp [leafEq] at accepted
          · simp [parentEq] at accepted

theorem accepted_native_ledger_tree_replay_chain_integrity_from
    {initial final : NativeLedgerTreeReplayState}
    {blocks : List (BlockReplayInput × TreeTransitionInput)}
    (initialNullifiersNodup :
      initial.ledger.spentNullifiers.Nodup)
    (initialBridgeReplaysNodup :
      initial.ledger.consumedBridgeReplays.Nodup)
    (accepted :
      validateNativeLedgerTreeReplayChain initial blocks = some final) :
    validateNativeLedgerReplayChain
        initial.ledger
        (ledgerBlocksFromTreeReplay blocks) =
        some final.ledger
      ∧ expectedCommitmentRootAfter initial.commitmentRoot blocks =
        some final.commitmentRoot
      ∧ expectedNativeSupplyAfter
          initial.ledger.supply
          (ledgerBlocksFromTreeReplay blocks) =
        some final.ledger.supply
      ∧ expectedNativeLeafCountAfter
          initial.ledger.leafCount
          (ledgerBlocksFromTreeReplay blocks) =
        some final.ledger.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          initial.ledger
          (ledgerBlocksFromTreeReplay blocks) = true
      ∧ final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup := by
  have ledgerAccepted :=
    accepted_native_ledger_tree_replay_chain_ledger_from accepted
  have rootAccepted :=
    accepted_native_ledger_tree_replay_chain_root_from accepted
  have startup :=
    accepted_native_ledger_replay_chain_startup_equivalence
      initialNullifiersNodup
      initialBridgeReplaysNodup
      ledgerAccepted
  exact
    ⟨ledgerAccepted,
      rootAccepted,
      startup.left,
      startup.right.left,
      startup.right.right.left,
      startup.right.right.right.left,
      startup.right.right.right.right⟩

theorem accepted_native_ledger_tree_replay_chain_integrity
    {genesis leafCount commitmentRoot : Nat}
    {final : NativeLedgerTreeReplayState}
    {blocks : List (BlockReplayInput × TreeTransitionInput)}
    (accepted :
      validateNativeLedgerTreeReplayChain
          (initialNativeLedgerTreeState
            genesis
            leafCount
            commitmentRoot)
          blocks =
        some final) :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState genesis leafCount)
        (ledgerBlocksFromTreeReplay blocks) =
        some final.ledger
      ∧ expectedCommitmentRootAfter commitmentRoot blocks =
        some final.commitmentRoot
      ∧ expectedNativeSupplyAfter
          genesis
          (ledgerBlocksFromTreeReplay blocks) =
        some final.ledger.supply
      ∧ expectedNativeLeafCountAfter
          leafCount
          (ledgerBlocksFromTreeReplay blocks) =
        some final.ledger.leafCount
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          (initialNativeLedgerState genesis leafCount)
          (ledgerBlocksFromTreeReplay blocks) = true
      ∧ final.ledger.spentNullifiers.Nodup
      ∧ final.ledger.consumedBridgeReplays.Nodup := by
  simpa [initialNativeLedgerTreeState] using
    accepted_native_ledger_tree_replay_chain_integrity_from
      (initial := initialNativeLedgerTreeState
        genesis
        leafCount
        commitmentRoot)
      (by simp [initialNativeLedgerTreeState, initialNativeLedgerState])
      (by simp [initialNativeLedgerTreeState, initialNativeLedgerState])
      accepted

theorem accepted_native_ledger_replay_chain_nullifiers_unique
    {genesis leafCount : Nat}
    {final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (accepted :
      validateNativeLedgerReplayChain
          (initialNativeLedgerState genesis leafCount)
          blocks =
        some final) :
    final.spentNullifiers.Nodup :=
  accepted_native_ledger_replay_chain_nullifiers_unique_from
    (by simp [initialNativeLedgerState])
    accepted

theorem accepted_native_ledger_replay_chain_bridge_replays_unique
    {genesis leafCount : Nat}
    {final : NativeLedgerReplayState}
    {blocks : List BlockReplayInput}
    (accepted :
      validateNativeLedgerReplayChain
          (initialNativeLedgerState genesis leafCount)
          blocks =
        some final) :
    final.consumedBridgeReplays.Nodup :=
  accepted_native_ledger_replay_chain_bridge_replays_unique_from
    (by simp [initialNativeLedgerState])
    accepted

def validNativeReplayChain : List BlockReplayInput :=
  [
    validReplay,
    {
      validReplay with
      parentSupply := 100,
      height := 2,
      spentNullifiers := [1],
      actions := [
        {
          commitmentCount := 2,
          ciphertextCount := 2,
          nullifiers := [2],
          bridgeReplayKey := none
        }
      ]
    }
  ]

theorem valid_native_replay_chain_accepts :
    validateNativeReplayChain 100 [] validNativeReplayChain = some 100 := by
  rfl

theorem valid_native_replay_chain_no_counterfeiting :
    expectedNativeSupplyAfter 100 validNativeReplayChain = some 100 := by
  exact accepted_native_replay_chain_no_counterfeiting
    valid_native_replay_chain_accepts

theorem valid_native_replay_chain_nullifier_preconditions :
    nativeReplayChainNullifierPreconditions [] validNativeReplayChain = true := by
  exact accepted_native_replay_chain_nullifier_preconditions
    valid_native_replay_chain_accepts

theorem valid_native_replay_chain_nullifiers_unique :
    (chainNullifiers validNativeReplayChain).Nodup := by
  exact accepted_native_replay_chain_nullifiers_unique
    valid_native_replay_chain_accepts

def counterfeitSecondNativeReplay : List BlockReplayInput :=
  [
    validReplay,
    {
      validReplay with
      parentSupply := 100,
      height := 2,
      spentNullifiers := [1],
      claimedSupply := 101
    }
  ]

theorem counterfeit_second_native_replay_rejects :
    validateNativeReplayChain 100 [] counterfeitSecondNativeReplay = none := by
  rfl

def duplicateNullifierNativeReplayChain : List BlockReplayInput :=
  [
    validReplay,
    {
      validReplay with
      parentSupply := 100,
      height := 2,
      spentNullifiers := [1]
    }
  ]

theorem duplicate_nullifier_native_replay_chain_rejects :
    validateNativeReplayChain 100 [] duplicateNullifierNativeReplayChain = none := by
  rfl

def staleSpentNativeReplayChain : List BlockReplayInput :=
  [validReplay, { validReplay with parentSupply := 100, height := 2 }]

theorem stale_spent_native_replay_chain_rejects :
    validateNativeReplayChain 100 [] staleSpentNativeReplayChain = none := by
  rfl

def validNativeLedgerReplayChain : List BlockReplayInput :=
  [
    validReplay,
    {
      validReplay with
      parentSupply := 100,
      height := 2,
      leafStart := 12,
      spentNullifiers := [1],
      consumedBridgeReplays := [],
      actions := [
        {
          commitmentCount := 1,
          ciphertextCount := 1,
          nullifiers := [2],
          bridgeReplayKey := some 7
        }
      ]
    }
  ]

theorem valid_native_ledger_replay_chain_accepts :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState 100 10)
        validNativeLedgerReplayChain =
      some
        {
          supply := 100,
          leafCount := 13,
          spentNullifiers := [2, 1],
          consumedBridgeReplays := [7]
        } := by
  rfl

theorem valid_native_ledger_replay_chain_startup_equivalence :
    expectedNativeSupplyAfter 100 validNativeLedgerReplayChain = some 100
      ∧ expectedNativeLeafCountAfter 10 validNativeLedgerReplayChain =
          some 13
      ∧ nativeLedgerReplayCommitmentPlanPreconditions
          (initialNativeLedgerState 100 10)
          validNativeLedgerReplayChain = true := by
  have accepted := valid_native_ledger_replay_chain_accepts
  have equivalence :=
    accepted_native_ledger_replay_chain_startup_equivalence
      (by simp [initialNativeLedgerState])
      (by simp [initialNativeLedgerState])
      accepted
  exact ⟨equivalence.left, equivalence.right.left, equivalence.right.right.left⟩

def staleLeafNativeLedgerReplayChain : List BlockReplayInput :=
  [
    validReplay,
    {
      validReplay with
      parentSupply := 100,
      height := 2,
      leafStart := 10,
      spentNullifiers := [1],
      consumedBridgeReplays := [],
      actions := [
        {
          commitmentCount := 1,
          ciphertextCount := 1,
          nullifiers := [2],
          bridgeReplayKey := none
        }
      ]
    }
  ]

theorem stale_leaf_native_ledger_replay_chain_rejects :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState 100 10)
        staleLeafNativeLedgerReplayChain =
      none := by
  rfl

def duplicateBridgeReplayNativeLedgerReplayChain : List BlockReplayInput :=
  [
    {
      validReplay with
      actions := [
        {
          commitmentCount := 2,
          ciphertextCount := 2,
          nullifiers := [1],
          bridgeReplayKey := some 7
        }
      ]
    },
    {
      validReplay with
      parentSupply := 100,
      height := 2,
      leafStart := 12,
      spentNullifiers := [1],
      consumedBridgeReplays := [7],
      actions := [
        {
          commitmentCount := 0,
          ciphertextCount := 0,
          nullifiers := [],
          bridgeReplayKey := some 7
        }
      ]
    }
  ]

theorem duplicate_bridge_replay_native_ledger_replay_chain_rejects :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState 100 10)
        duplicateBridgeReplayNativeLedgerReplayChain =
      none := by
  rfl

def staleBridgeReplayNativeLedgerReplayChain : List BlockReplayInput :=
  [
    {
      validReplay with
      actions := [
        {
          commitmentCount := 2,
          ciphertextCount := 2,
          nullifiers := [1],
          bridgeReplayKey := some 7
        }
      ]
    },
    {
      validReplay with
      parentSupply := 100,
      height := 2,
      leafStart := 12,
      spentNullifiers := [1],
      consumedBridgeReplays := [],
      actions := [
        {
          commitmentCount := 0,
          ciphertextCount := 0,
          nullifiers := [],
          bridgeReplayKey := none
        }
      ]
    }
  ]

theorem stale_bridge_replay_native_ledger_replay_chain_rejects :
    validateNativeLedgerReplayChain
        (initialNativeLedgerState 100 10)
        staleBridgeReplayNativeLedgerReplayChain =
      none := by
  rfl

end AcceptedChain
end Native
end Hegemon

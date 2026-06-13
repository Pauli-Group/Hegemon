import Hegemon.Native.BlockReplayRefinement

namespace Hegemon
namespace Native
namespace AcceptedChain

open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.BlockReplayRefinement

def actionNullifiers : List StreamAction -> List Nat
  | [] => []
  | action :: rest => action.nullifiers ++ actionNullifiers rest

def validateNativeReplayChain
    (parentSupply : Nat)
    (spentNullifiers : List Nat) :
    List BlockReplayInput -> Option Nat
  | [] => some parentSupply
  | block :: rest =>
      if block.parentSupply = parentSupply then
        if block.spentNullifiers = spentNullifiers then
          if (actionNullifiers block.actions ++ spentNullifiers).Nodup then
            match evaluateBlockReplayRefinement block with
            | Except.error _ => none
            | Except.ok summary =>
                validateNativeReplayChain
                  summary.expectedSupply
                  (actionNullifiers block.actions ++ spentNullifiers)
                  rest
          else
            none
        else
          none
      else
        none

def replayedNullifierState :
    List Nat -> List BlockReplayInput -> List Nat
  | spentNullifiers, [] => spentNullifiers
  | spentNullifiers, block :: rest =>
      replayedNullifierState
        (actionNullifiers block.actions ++ spentNullifiers)
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
            (actionNullifiers block.actions ++ spentNullifiers)
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
          by_cases nullifiersNodup :
              (actionNullifiers block.actions ++ spentNullifiers).Nodup
          · simp [nullifiersNodup] at accepted
            cases replayResult : evaluateBlockReplayRefinement block with
            | error rejection =>
                simp [replayResult] at accepted
            | ok summary =>
                have supplyFacts := accepted_claims_expected_supply replayResult
                rw [supplyFacts.left]
                simp [replayResult] at accepted
                exact ih accepted
          · simp [nullifiersNodup] at accepted
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
          by_cases nullifiersNodup :
              (actionNullifiers block.actions ++ spentNullifiers).Nodup
          · simp [nullifiersNodup] at accepted
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
          · simp [nullifiersNodup] at accepted
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
          by_cases nullifiersNodup :
              (actionNullifiers block.actions ++ spentNullifiers).Nodup
          · simp [nullifiersNodup] at accepted
            cases replayResult : evaluateBlockReplayRefinement block with
            | error rejection =>
                simp [replayResult] at accepted
            | ok summary =>
                simp [replayResult] at accepted
                exact ih nullifiersNodup accepted
          · simp [nullifiersNodup] at accepted
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

end AcceptedChain
end Native
end Hegemon

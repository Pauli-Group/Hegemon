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

namespace Hegemon
namespace Native
namespace ActionWireReplayProjectionAdmission

inductive ActionWireReplayProjectionReject where
  | planLengthMismatch
  | ciphertextCountMismatch
  | ciphertextHashMismatch
  | ciphertextSizeMismatch
  | replayKeyMismatch
deriving DecidableEq, Repr

structure WireReplayAction where
  ciphertextHashCount : Nat
  ciphertextSizeCount : Nat
  plannedCiphertextCount : Nat
  ciphertextHashesMatch : Bool
  ciphertextSizesMatch : Bool
  plannedReplayPresent : Bool
  replayKeyMatches : Bool
deriving DecidableEq, Repr

structure ActionWireReplayProjectionInput where
  actionCount : Nat
  plannedCount : Nat
  actions : List WireReplayAction
deriving DecidableEq, Repr

structure ActionWireReplayProjectionOutput where
  projectedActionCount : Nat
  projectedCiphertextRowCount : Nat
  projectedBridgeReplayRowCount : Nat
deriving DecidableEq, Repr

def wireReplayActionCountsMatch (action : WireReplayAction) : Bool :=
  action.ciphertextHashCount = action.ciphertextSizeCount
    && action.ciphertextHashCount = action.plannedCiphertextCount

def evaluateActionWireReplayProjectionFrom :
    Nat ->
    Nat ->
    Nat ->
    List WireReplayAction ->
    Except ActionWireReplayProjectionReject ActionWireReplayProjectionOutput
  | projected, ciphertextRows, replayRows, [] =>
      Except.ok
        { projectedActionCount := projected,
          projectedCiphertextRowCount := ciphertextRows,
          projectedBridgeReplayRowCount := replayRows }
  | projected, ciphertextRows, replayRows, action :: rest =>
      if wireReplayActionCountsMatch action then
        if action.ciphertextHashesMatch then
          if action.ciphertextSizesMatch then
            if action.replayKeyMatches then
              evaluateActionWireReplayProjectionFrom
                (projected + 1)
                (ciphertextRows + action.plannedCiphertextCount)
                (replayRows + if action.plannedReplayPresent then 1 else 0)
                rest
            else
              Except.error ActionWireReplayProjectionReject.replayKeyMismatch
          else
            Except.error ActionWireReplayProjectionReject.ciphertextSizeMismatch
        else
          Except.error ActionWireReplayProjectionReject.ciphertextHashMismatch
      else
        Except.error ActionWireReplayProjectionReject.ciphertextCountMismatch

def actionWireReplayPlanCountsMatch
    (input : ActionWireReplayProjectionInput) : Bool :=
  input.actionCount = input.plannedCount
    && input.actionCount = input.actions.length

def evaluateActionWireReplayProjection
    (input : ActionWireReplayProjectionInput) :
    Except ActionWireReplayProjectionReject ActionWireReplayProjectionOutput :=
  if actionWireReplayPlanCountsMatch input then
    evaluateActionWireReplayProjectionFrom 0 0 0 input.actions
  else
    Except.error ActionWireReplayProjectionReject.planLengthMismatch

def actionWireReplayProjectionAccepts
    (input : ActionWireReplayProjectionInput) : Bool :=
  match evaluateActionWireReplayProjection input with
  | Except.ok _ => true
  | Except.error _ => false

def wireReplayActionsPreconditions :
    List WireReplayAction -> Bool
  | [] => true
  | action :: rest =>
      if wireReplayActionCountsMatch action then
        if action.ciphertextHashesMatch then
          if action.ciphertextSizesMatch then
            if action.replayKeyMatches then
              wireReplayActionsPreconditions rest
            else
              false
          else
            false
        else
          false
      else
        false

def actionWireReplayProjectionPreconditions
    (input : ActionWireReplayProjectionInput) : Bool :=
  if actionWireReplayPlanCountsMatch input then
    wireReplayActionsPreconditions input.actions
  else
    false

theorem accepts_from_iff_wire_replay_actions_preconditions
    (projected ciphertextRows replayRows : Nat)
    (actions : List WireReplayAction) :
    (match evaluateActionWireReplayProjectionFrom
        projected ciphertextRows replayRows actions with
      | Except.ok _ => true
      | Except.error _ => false) =
      wireReplayActionsPreconditions actions := by
  induction actions generalizing projected ciphertextRows replayRows with
  | nil =>
      rfl
  | cons action rest ih =>
      by_cases hCounts : wireReplayActionCountsMatch action
      · cases hHashes : action.ciphertextHashesMatch <;>
          cases hSizes : action.ciphertextSizesMatch <;>
          cases hReplay : action.replayKeyMatches <;>
          simp [
            evaluateActionWireReplayProjectionFrom,
            wireReplayActionsPreconditions,
            hCounts,
            hHashes,
            hSizes,
            hReplay,
            ih
          ]
      · simp [
          evaluateActionWireReplayProjectionFrom,
          wireReplayActionsPreconditions,
          hCounts
        ]

theorem accepts_iff_wire_replay_projection_preconditions
    (input : ActionWireReplayProjectionInput) :
    actionWireReplayProjectionAccepts input =
      actionWireReplayProjectionPreconditions input := by
  by_cases hCounts : actionWireReplayPlanCountsMatch input
  · simp [
      actionWireReplayProjectionAccepts,
      actionWireReplayProjectionPreconditions,
      evaluateActionWireReplayProjection,
      hCounts,
      accepts_from_iff_wire_replay_actions_preconditions
    ]
  · simp [
      actionWireReplayProjectionAccepts,
      actionWireReplayProjectionPreconditions,
      evaluateActionWireReplayProjection,
      hCounts
    ]

def validMixedProjection : ActionWireReplayProjectionInput :=
  {
    actionCount := 2,
    plannedCount := 2,
    actions := [
      {
        ciphertextHashCount := 1,
        ciphertextSizeCount := 1,
        plannedCiphertextCount := 1,
        ciphertextHashesMatch := true,
        ciphertextSizesMatch := true,
        plannedReplayPresent := false,
        replayKeyMatches := true
      },
      {
        ciphertextHashCount := 0,
        ciphertextSizeCount := 0,
        plannedCiphertextCount := 0,
        ciphertextHashesMatch := true,
        ciphertextSizesMatch := true,
        plannedReplayPresent := true,
        replayKeyMatches := true
      }
    ]
  }

theorem valid_mixed_projection_accepts :
    evaluateActionWireReplayProjection validMixedProjection =
      Except.ok
        { projectedActionCount := 2,
          projectedCiphertextRowCount := 1,
          projectedBridgeReplayRowCount := 1 } := by
  rfl

def emptyProjection : ActionWireReplayProjectionInput :=
  {
    actionCount := 0,
    plannedCount := 0,
    actions := []
  }

theorem empty_projection_accepts :
    evaluateActionWireReplayProjection emptyProjection =
      Except.ok
        { projectedActionCount := 0,
          projectedCiphertextRowCount := 0,
          projectedBridgeReplayRowCount := 0 } := by
  rfl

def planLengthMismatch : ActionWireReplayProjectionInput :=
  {
    actionCount := 2,
    plannedCount := 1,
    actions := [
      {
        ciphertextHashCount := 0,
        ciphertextSizeCount := 0,
        plannedCiphertextCount := 0,
        ciphertextHashesMatch := true,
        ciphertextSizesMatch := true,
        plannedReplayPresent := false,
        replayKeyMatches := true
      }
    ]
  }

theorem plan_length_mismatch_rejects :
    evaluateActionWireReplayProjection planLengthMismatch =
      Except.error ActionWireReplayProjectionReject.planLengthMismatch := by
  rfl

def ciphertextCountMismatch : ActionWireReplayProjectionInput :=
  {
    actionCount := 1,
    plannedCount := 1,
    actions := [
      {
        ciphertextHashCount := 1,
        ciphertextSizeCount := 1,
        plannedCiphertextCount := 0,
        ciphertextHashesMatch := true,
        ciphertextSizesMatch := true,
        plannedReplayPresent := false,
        replayKeyMatches := true
      }
    ]
  }

theorem ciphertext_count_mismatch_rejects :
    evaluateActionWireReplayProjection ciphertextCountMismatch =
      Except.error ActionWireReplayProjectionReject.ciphertextCountMismatch := by
  rfl

def ciphertextHashMismatch : ActionWireReplayProjectionInput :=
  {
    actionCount := 1,
    plannedCount := 1,
    actions := [
      {
        ciphertextHashCount := 1,
        ciphertextSizeCount := 1,
        plannedCiphertextCount := 1,
        ciphertextHashesMatch := false,
        ciphertextSizesMatch := true,
        plannedReplayPresent := false,
        replayKeyMatches := true
      }
    ]
  }

theorem ciphertext_hash_mismatch_rejects :
    evaluateActionWireReplayProjection ciphertextHashMismatch =
      Except.error ActionWireReplayProjectionReject.ciphertextHashMismatch := by
  rfl

def ciphertextSizeMismatch : ActionWireReplayProjectionInput :=
  {
    actionCount := 1,
    plannedCount := 1,
    actions := [
      {
        ciphertextHashCount := 1,
        ciphertextSizeCount := 1,
        plannedCiphertextCount := 1,
        ciphertextHashesMatch := true,
        ciphertextSizesMatch := false,
        plannedReplayPresent := false,
        replayKeyMatches := true
      }
    ]
  }

theorem ciphertext_size_mismatch_rejects :
    evaluateActionWireReplayProjection ciphertextSizeMismatch =
      Except.error ActionWireReplayProjectionReject.ciphertextSizeMismatch := by
  rfl

def replayKeyMismatch : ActionWireReplayProjectionInput :=
  {
    actionCount := 1,
    plannedCount := 1,
    actions := [
      {
        ciphertextHashCount := 0,
        ciphertextSizeCount := 0,
        plannedCiphertextCount := 0,
        ciphertextHashesMatch := true,
        ciphertextSizesMatch := true,
        plannedReplayPresent := true,
        replayKeyMatches := false
      }
    ]
  }

theorem replay_key_mismatch_rejects :
    evaluateActionWireReplayProjection replayKeyMismatch =
      Except.error ActionWireReplayProjectionReject.replayKeyMismatch := by
  rfl

def count_mismatch_precedes_hash_input : ActionWireReplayProjectionInput :=
  {
    actionCount := 1,
    plannedCount := 1,
    actions := [
      {
        ciphertextHashCount := 1,
        ciphertextSizeCount := 1,
        plannedCiphertextCount := 0,
        ciphertextHashesMatch := false,
        ciphertextSizesMatch := false,
        plannedReplayPresent := true,
        replayKeyMatches := false
      }
    ]
  }

theorem count_mismatch_precedes_hash :
    evaluateActionWireReplayProjection count_mismatch_precedes_hash_input =
      Except.error ActionWireReplayProjectionReject.ciphertextCountMismatch := by
  rfl

def hash_mismatch_precedes_size_input : ActionWireReplayProjectionInput :=
  {
    actionCount := 1,
    plannedCount := 1,
    actions := [
      {
        ciphertextHashCount := 1,
        ciphertextSizeCount := 1,
        plannedCiphertextCount := 1,
        ciphertextHashesMatch := false,
        ciphertextSizesMatch := false,
        plannedReplayPresent := true,
        replayKeyMatches := false
      }
    ]
  }

theorem hash_mismatch_precedes_size :
    evaluateActionWireReplayProjection hash_mismatch_precedes_size_input =
      Except.error ActionWireReplayProjectionReject.ciphertextHashMismatch := by
  rfl

def size_mismatch_precedes_replay_input : ActionWireReplayProjectionInput :=
  {
    actionCount := 1,
    plannedCount := 1,
    actions := [
      {
        ciphertextHashCount := 1,
        ciphertextSizeCount := 1,
        plannedCiphertextCount := 1,
        ciphertextHashesMatch := true,
        ciphertextSizesMatch := false,
        plannedReplayPresent := true,
        replayKeyMatches := false
      }
    ]
  }

theorem size_mismatch_precedes_replay :
    evaluateActionWireReplayProjection size_mismatch_precedes_replay_input =
      Except.error ActionWireReplayProjectionReject.ciphertextSizeMismatch := by
  rfl

end ActionWireReplayProjectionAdmission
end Native
end Hegemon

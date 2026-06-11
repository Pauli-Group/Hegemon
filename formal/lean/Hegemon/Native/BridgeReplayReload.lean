namespace Hegemon
namespace Native
namespace BridgeReplayReload

inductive BridgeReplayReloadReject where
  | malformedReplayKey
  | invalidReplayMarker
  | canonicalReplayDuplicate
  | missingConsumedReplayKey
  | extraConsumedReplayKey
deriving DecidableEq, Repr

structure BridgeReplayReloadInput where
  replayKeysWellFormed : Bool
  replayMarkersValid : Bool
  canonicalReplayKeysUnique : Bool
  noMissingLoadedReplayKeys : Bool
  noExtraLoadedReplayKeys : Bool
deriving DecidableEq, Repr

def orderedChecks (input : BridgeReplayReloadInput) :
    List (Bool × BridgeReplayReloadReject) :=
  [
    (input.replayKeysWellFormed,
      BridgeReplayReloadReject.malformedReplayKey),
    (input.replayMarkersValid,
      BridgeReplayReloadReject.invalidReplayMarker),
    (input.canonicalReplayKeysUnique,
      BridgeReplayReloadReject.canonicalReplayDuplicate),
    (input.noMissingLoadedReplayKeys,
      BridgeReplayReloadReject.missingConsumedReplayKey),
    (input.noExtraLoadedReplayKeys,
      BridgeReplayReloadReject.extraConsumedReplayKey)
  ]

def firstReject :
    List (Bool × BridgeReplayReloadReject) ->
      Option BridgeReplayReloadReject
  | [] => none
  | (ok, reject) :: rest => if ok then firstReject rest else some reject

def allChecks : List (Bool × BridgeReplayReloadReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allChecks rest

theorem first_reject_none_iff_all_checks
    {checks : List (Bool × BridgeReplayReloadReject)} :
    firstReject checks = none ↔ allChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstReject, allChecks]
  | cons head rest ih =>
      cases head with
      | mk ok reject =>
          cases ok <;> simp [firstReject, allChecks, ih]

def evaluateBridgeReplayReloadRejection
    (input : BridgeReplayReloadInput) :
      Option BridgeReplayReloadReject :=
  firstReject (orderedChecks input)

def bridgeReplayReloadAccepts
    (input : BridgeReplayReloadInput) : Bool :=
  evaluateBridgeReplayReloadRejection input = none

def bridgeReplayReloadPreconditions
    (input : BridgeReplayReloadInput) : Bool :=
  allChecks (orderedChecks input)

theorem accepts_iff_bridge_replay_reload_preconditions
    {input : BridgeReplayReloadInput} :
    bridgeReplayReloadAccepts input = true ↔
      bridgeReplayReloadPreconditions input = true := by
  unfold bridgeReplayReloadAccepts bridgeReplayReloadPreconditions
  unfold evaluateBridgeReplayReloadRejection
  simpa using
    (first_reject_none_iff_all_checks
      (checks := orderedChecks input))

def valid : BridgeReplayReloadInput :=
  {
    replayKeysWellFormed := true,
    replayMarkersValid := true,
    canonicalReplayKeysUnique := true,
    noMissingLoadedReplayKeys := true,
    noExtraLoadedReplayKeys := true
  }

theorem valid_accepts :
    evaluateBridgeReplayReloadRejection valid = none := by
  decide

def malformedReplayKey : BridgeReplayReloadInput :=
  { valid with replayKeysWellFormed := false }

theorem malformed_replay_key_rejects :
    evaluateBridgeReplayReloadRejection malformedReplayKey =
      some BridgeReplayReloadReject.malformedReplayKey := by
  decide

def invalidReplayMarker : BridgeReplayReloadInput :=
  { valid with replayMarkersValid := false }

theorem invalid_replay_marker_rejects :
    evaluateBridgeReplayReloadRejection invalidReplayMarker =
      some BridgeReplayReloadReject.invalidReplayMarker := by
  decide

def canonicalReplayDuplicate : BridgeReplayReloadInput :=
  { valid with canonicalReplayKeysUnique := false }

theorem canonical_replay_duplicate_rejects :
    evaluateBridgeReplayReloadRejection canonicalReplayDuplicate =
      some BridgeReplayReloadReject.canonicalReplayDuplicate := by
  decide

def missingConsumedReplayKey : BridgeReplayReloadInput :=
  { valid with noMissingLoadedReplayKeys := false }

theorem missing_consumed_replay_key_rejects :
    evaluateBridgeReplayReloadRejection missingConsumedReplayKey =
      some BridgeReplayReloadReject.missingConsumedReplayKey := by
  decide

def extraConsumedReplayKey : BridgeReplayReloadInput :=
  { valid with noExtraLoadedReplayKeys := false }

theorem extra_consumed_replay_key_rejects :
    evaluateBridgeReplayReloadRejection extraConsumedReplayKey =
      some BridgeReplayReloadReject.extraConsumedReplayKey := by
  decide

def malformed_key_precedes_marker_input :
    BridgeReplayReloadInput :=
  { valid with
    replayKeysWellFormed := false
    replayMarkersValid := false }

theorem malformed_key_precedes_marker :
    evaluateBridgeReplayReloadRejection
      malformed_key_precedes_marker_input =
        some BridgeReplayReloadReject.malformedReplayKey := by
  decide

def marker_precedes_canonical_duplicate_input :
    BridgeReplayReloadInput :=
  { valid with
    replayMarkersValid := false
    canonicalReplayKeysUnique := false }

theorem marker_precedes_canonical_duplicate :
    evaluateBridgeReplayReloadRejection
      marker_precedes_canonical_duplicate_input =
        some BridgeReplayReloadReject.invalidReplayMarker := by
  decide

def canonical_duplicate_precedes_missing_input :
    BridgeReplayReloadInput :=
  { valid with
    canonicalReplayKeysUnique := false
    noMissingLoadedReplayKeys := false }

theorem canonical_duplicate_precedes_missing :
    evaluateBridgeReplayReloadRejection
      canonical_duplicate_precedes_missing_input =
        some BridgeReplayReloadReject.canonicalReplayDuplicate := by
  decide

def missing_precedes_extra_input :
    BridgeReplayReloadInput :=
  { valid with
    noMissingLoadedReplayKeys := false
    noExtraLoadedReplayKeys := false }

theorem missing_precedes_extra :
    evaluateBridgeReplayReloadRejection
      missing_precedes_extra_input =
        some BridgeReplayReloadReject.missingConsumedReplayKey := by
  decide

end BridgeReplayReload
end Native
end Hegemon

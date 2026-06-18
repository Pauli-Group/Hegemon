import Hegemon.Native.ActionStreamEffect

namespace Hegemon
namespace Native
namespace BridgeReplayReload

open Hegemon.Native.ActionStreamEffect

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

structure LoadedConsumedReplayStateFacts
    (input : BridgeReplayReloadInput)
    (canonicalLoaded consumedLoaded : List Nat) : Prop where
  reloadAccepted :
    bridgeReplayReloadAccepts input = true
  reloadPreconditions :
    bridgeReplayReloadPreconditions input = true
  replayKeysWellFormed :
    input.replayKeysWellFormed = true
  replayMarkersValid :
    input.replayMarkersValid = true
  canonicalReplayKeysUniqueAccepted :
    input.canonicalReplayKeysUnique = true
  noMissingLoadedReplayKeys :
    input.noMissingLoadedReplayKeys = true
  noExtraLoadedReplayKeys :
    input.noExtraLoadedReplayKeys = true
  canonicalReplayKeysNodup :
    canonicalLoaded.Nodup
  consumedLoadedMatchesCanonical :
    consumedLoaded = canonicalLoaded
  consumedLoadedNodup :
    consumedLoaded.Nodup

structure LoadedConsumedReplayHandoffFacts
    (input : BridgeReplayReloadInput)
    (canonicalLoaded consumedLoaded : List Nat)
    (replay : Nat) : Prop where
  loadedStateFacts :
    LoadedConsumedReplayStateFacts
      input
      canonicalLoaded
      consumedLoaded
  replayInCanonicalHistory :
    replay ∈ canonicalLoaded
  replayInLoadedConsumed :
    replay ∈ consumedLoaded
  loadedDuplicateRejects :
    importBridgeReplay consumedLoaded (some replay) =
      Except.error ActionStreamReject.bridgeReplayDuplicate

structure LoadedConsumedReplayProjectionReloadFacts
    (input : BridgeReplayReloadInput)
    (canonicalLoaded consumedLoaded projectedConsumed importedConsumed :
      List Nat)
    (replay : Nat) : Prop where
  loadedHandoffFacts :
    LoadedConsumedReplayHandoffFacts
      input
      canonicalLoaded
      consumedLoaded
      replay
  projectedConsumedMatchesLoaded :
    projectedConsumed = consumedLoaded
  loadedConsumedMatchesImported :
    consumedLoaded = importedConsumed
  projectedConsumedMatchesImported :
    projectedConsumed = importedConsumed
  replayInProjectedConsumed :
    replay ∈ projectedConsumed
  replayInImportedConsumed :
    replay ∈ importedConsumed
  projectedConsumedNodup :
    projectedConsumed.Nodup
  importedConsumedNodup :
    importedConsumed.Nodup
  projectedDuplicateRejects :
    importBridgeReplay projectedConsumed (some replay) =
      Except.error ActionStreamReject.bridgeReplayDuplicate
  importedDuplicateRejects :
    importBridgeReplay importedConsumed (some replay) =
      Except.error ActionStreamReject.bridgeReplayDuplicate

theorem accepted_bridge_replay_reload_exposes_loaded_consumed_state
    {input : BridgeReplayReloadInput}
    {canonicalLoaded consumedLoaded : List Nat}
    (accepted : bridgeReplayReloadAccepts input = true)
    (canonicalNodup : canonicalLoaded.Nodup)
    (consumedMatchesCanonical :
      consumedLoaded = canonicalLoaded) :
    LoadedConsumedReplayStateFacts
      input
      canonicalLoaded
      consumedLoaded := by
  have preconditions :
      bridgeReplayReloadPreconditions input = true :=
    (accepts_iff_bridge_replay_reload_preconditions
      (input := input)).mp accepted
  have acceptedFields :
      input.replayKeysWellFormed = true
        ∧ input.replayMarkersValid = true
        ∧ input.canonicalReplayKeysUnique = true
        ∧ input.noMissingLoadedReplayKeys = true
        ∧ input.noExtraLoadedReplayKeys = true := by
    unfold bridgeReplayReloadPreconditions at preconditions
    simpa [orderedChecks, allChecks] using preconditions
  have consumedNodup : consumedLoaded.Nodup := by
    simpa [consumedMatchesCanonical] using canonicalNodup
  exact
    {
      reloadAccepted := accepted,
      reloadPreconditions := preconditions,
      replayKeysWellFormed := acceptedFields.left,
      replayMarkersValid := acceptedFields.right.left,
      canonicalReplayKeysUniqueAccepted :=
        acceptedFields.right.right.left,
      noMissingLoadedReplayKeys :=
        acceptedFields.right.right.right.left,
      noExtraLoadedReplayKeys :=
        acceptedFields.right.right.right.right,
      canonicalReplayKeysNodup := canonicalNodup,
      consumedLoadedMatchesCanonical := consumedMatchesCanonical,
      consumedLoadedNodup := consumedNodup
    }

theorem accepted_bridge_replay_reload_exposes_loaded_consumed_replay_handoff_facts
    {input : BridgeReplayReloadInput}
    {canonicalLoaded consumedLoaded : List Nat}
    {replay : Nat}
    (accepted : bridgeReplayReloadAccepts input = true)
    (canonicalNodup : canonicalLoaded.Nodup)
    (consumedMatchesCanonical :
      consumedLoaded = canonicalLoaded)
    (replayInCanonical : replay ∈ canonicalLoaded) :
    LoadedConsumedReplayHandoffFacts
      input
      canonicalLoaded
      consumedLoaded
      replay := by
  have loadedStateFacts :=
    accepted_bridge_replay_reload_exposes_loaded_consumed_state
      accepted
      canonicalNodup
      consumedMatchesCanonical
  have replayInLoaded : replay ∈ consumedLoaded := by
    rw [consumedMatchesCanonical]
    exact replayInCanonical
  have duplicateRejects :
      importBridgeReplay consumedLoaded (some replay) =
        Except.error ActionStreamReject.bridgeReplayDuplicate := by
    have present :
        containsNat replay consumedLoaded = true :=
      containsNat_true_iff.mpr replayInLoaded
    simp [importBridgeReplay, present]
  exact
    {
      loadedStateFacts := loadedStateFacts,
      replayInCanonicalHistory := replayInCanonical,
      replayInLoadedConsumed := replayInLoaded,
      loadedDuplicateRejects := duplicateRejects
    }

theorem accepted_bridge_replay_reload_projects_loaded_consumed_replay
    {input : BridgeReplayReloadInput}
    {canonicalLoaded consumedLoaded projectedConsumed importedConsumed :
      List Nat}
    {replay : Nat}
    (reloadFacts :
      LoadedConsumedReplayHandoffFacts
        input
        canonicalLoaded
        consumedLoaded
        replay)
    (projectedMatchesLoaded :
      projectedConsumed = consumedLoaded)
    (loadedMatchesImported :
      consumedLoaded = importedConsumed) :
    LoadedConsumedReplayProjectionReloadFacts
      input
      canonicalLoaded
      consumedLoaded
      projectedConsumed
      importedConsumed
      replay := by
  have projectedMatchesImported :
      projectedConsumed = importedConsumed := by
    rw [projectedMatchesLoaded, loadedMatchesImported]
  have replayInProjected :
      replay ∈ projectedConsumed := by
    rw [projectedMatchesLoaded]
    exact reloadFacts.replayInLoadedConsumed
  have replayInImported :
      replay ∈ importedConsumed := by
    rw [← loadedMatchesImported]
    exact reloadFacts.replayInLoadedConsumed
  have projectedNodup :
      projectedConsumed.Nodup := by
    rw [projectedMatchesLoaded]
    exact reloadFacts.loadedStateFacts.consumedLoadedNodup
  have importedNodup :
      importedConsumed.Nodup := by
    rw [← loadedMatchesImported]
    exact reloadFacts.loadedStateFacts.consumedLoadedNodup
  have projectedRejects :
      importBridgeReplay projectedConsumed (some replay) =
        Except.error ActionStreamReject.bridgeReplayDuplicate := by
    have present :
        containsNat replay projectedConsumed = true :=
      containsNat_true_iff.mpr replayInProjected
    simp [importBridgeReplay, present]
  have importedRejects :
      importBridgeReplay importedConsumed (some replay) =
        Except.error ActionStreamReject.bridgeReplayDuplicate := by
    have present :
        containsNat replay importedConsumed = true :=
      containsNat_true_iff.mpr replayInImported
    simp [importBridgeReplay, present]
  exact
    {
      loadedHandoffFacts := reloadFacts,
      projectedConsumedMatchesLoaded := projectedMatchesLoaded,
      loadedConsumedMatchesImported := loadedMatchesImported,
      projectedConsumedMatchesImported := projectedMatchesImported,
      replayInProjectedConsumed := replayInProjected,
      replayInImportedConsumed := replayInImported,
      projectedConsumedNodup := projectedNodup,
      importedConsumedNodup := importedNodup,
      projectedDuplicateRejects := projectedRejects,
      importedDuplicateRejects := importedRejects
    }

theorem accepted_bridge_replay_reload_projected_imported_replay_rejects_duplicate
    {input : BridgeReplayReloadInput}
    {canonicalLoaded consumedLoaded projectedConsumed importedConsumed :
      List Nat}
    {replay : Nat}
    (facts :
      LoadedConsumedReplayProjectionReloadFacts
        input
        canonicalLoaded
        consumedLoaded
        projectedConsumed
        importedConsumed
        replay) :
    replay ∈ projectedConsumed
      ∧ replay ∈ importedConsumed
      ∧ importBridgeReplay projectedConsumed (some replay) =
        Except.error ActionStreamReject.bridgeReplayDuplicate
      ∧ importBridgeReplay importedConsumed (some replay) =
        Except.error ActionStreamReject.bridgeReplayDuplicate := by
  exact
    ⟨facts.replayInProjectedConsumed,
      facts.replayInImportedConsumed,
      facts.projectedDuplicateRejects,
      facts.importedDuplicateRejects⟩

theorem accepted_bridge_replay_reload_loaded_consumed_replay_rejects_duplicate
    {input : BridgeReplayReloadInput}
    {canonicalLoaded consumedLoaded : List Nat}
    {replay : Nat}
    (accepted : bridgeReplayReloadAccepts input = true)
    (canonicalNodup : canonicalLoaded.Nodup)
    (consumedMatchesCanonical :
      consumedLoaded = canonicalLoaded)
    (replayInCanonical : replay ∈ canonicalLoaded) :
    replay ∈ consumedLoaded
      ∧ importBridgeReplay consumedLoaded (some replay) =
        Except.error ActionStreamReject.bridgeReplayDuplicate := by
  have facts :=
    accepted_bridge_replay_reload_exposes_loaded_consumed_replay_handoff_facts
      accepted
      canonicalNodup
      consumedMatchesCanonical
      replayInCanonical
  exact
    ⟨facts.replayInLoadedConsumed,
      facts.loadedDuplicateRejects⟩

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

namespace Hegemon
namespace Native
namespace PendingActionReload

inductive PendingActionReloadReject where
  | malformedActionKey
  | keyHashMismatch
  | recomputedHashMismatch
  | duplicatePendingAction
deriving DecidableEq, Repr

structure PendingActionReloadInput where
  keyWellFormed : Bool
  embeddedHashMatchesKey : Bool
  recomputedHashMatchesEmbedded : Bool
  actionHashUnique : Bool
deriving DecidableEq, Repr

def orderedChecks (input : PendingActionReloadInput) :
    List (Bool × PendingActionReloadReject) :=
  [
    (input.keyWellFormed,
      PendingActionReloadReject.malformedActionKey),
    (input.embeddedHashMatchesKey,
      PendingActionReloadReject.keyHashMismatch),
    (input.recomputedHashMatchesEmbedded,
      PendingActionReloadReject.recomputedHashMismatch),
    (input.actionHashUnique,
      PendingActionReloadReject.duplicatePendingAction)
  ]

def firstReject :
    List (Bool × PendingActionReloadReject) ->
      Option PendingActionReloadReject
  | [] => none
  | (ok, reject) :: rest => if ok then firstReject rest else some reject

def allChecks : List (Bool × PendingActionReloadReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allChecks rest

theorem first_reject_none_iff_all_checks
    {checks : List (Bool × PendingActionReloadReject)} :
    firstReject checks = none ↔ allChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstReject, allChecks]
  | cons head rest ih =>
      cases head with
      | mk ok reject =>
          cases ok <;> simp [firstReject, allChecks, ih]

def evaluatePendingActionReloadRejection
    (input : PendingActionReloadInput) :
      Option PendingActionReloadReject :=
  firstReject (orderedChecks input)

def pendingActionReloadAccepts
    (input : PendingActionReloadInput) : Bool :=
  evaluatePendingActionReloadRejection input = none

def pendingActionReloadPreconditions
    (input : PendingActionReloadInput) : Bool :=
  allChecks (orderedChecks input)

theorem accepts_iff_pending_action_reload_preconditions
    {input : PendingActionReloadInput} :
    pendingActionReloadAccepts input = true ↔
      pendingActionReloadPreconditions input = true := by
  unfold pendingActionReloadAccepts pendingActionReloadPreconditions
  unfold evaluatePendingActionReloadRejection
  simpa using
    (first_reject_none_iff_all_checks
      (checks := orderedChecks input))

def valid : PendingActionReloadInput :=
  {
    keyWellFormed := true,
    embeddedHashMatchesKey := true,
    recomputedHashMatchesEmbedded := true,
    actionHashUnique := true
  }

theorem valid_accepts :
    evaluatePendingActionReloadRejection valid = none := by
  decide

def malformedActionKey : PendingActionReloadInput :=
  { valid with keyWellFormed := false }

theorem malformed_action_key_rejects :
    evaluatePendingActionReloadRejection malformedActionKey =
      some PendingActionReloadReject.malformedActionKey := by
  decide

def keyHashMismatch : PendingActionReloadInput :=
  { valid with embeddedHashMatchesKey := false }

theorem key_hash_mismatch_rejects :
    evaluatePendingActionReloadRejection keyHashMismatch =
      some PendingActionReloadReject.keyHashMismatch := by
  decide

def recomputedHashMismatch : PendingActionReloadInput :=
  { valid with recomputedHashMatchesEmbedded := false }

theorem recomputed_hash_mismatch_rejects :
    evaluatePendingActionReloadRejection recomputedHashMismatch =
      some PendingActionReloadReject.recomputedHashMismatch := by
  decide

def duplicatePendingAction : PendingActionReloadInput :=
  { valid with actionHashUnique := false }

theorem duplicate_pending_action_rejects :
    evaluatePendingActionReloadRejection duplicatePendingAction =
      some PendingActionReloadReject.duplicatePendingAction := by
  decide

def malformed_key_precedes_key_hash_mismatch_input :
    PendingActionReloadInput :=
  { valid with
    keyWellFormed := false
    embeddedHashMatchesKey := false }

theorem malformed_key_precedes_key_hash_mismatch :
    evaluatePendingActionReloadRejection
      malformed_key_precedes_key_hash_mismatch_input =
        some PendingActionReloadReject.malformedActionKey := by
  decide

def key_hash_mismatch_precedes_recomputed_hash_mismatch_input :
    PendingActionReloadInput :=
  { valid with
    embeddedHashMatchesKey := false
    recomputedHashMatchesEmbedded := false }

theorem key_hash_mismatch_precedes_recomputed_hash_mismatch :
    evaluatePendingActionReloadRejection
      key_hash_mismatch_precedes_recomputed_hash_mismatch_input =
        some PendingActionReloadReject.keyHashMismatch := by
  decide

def recomputed_hash_mismatch_precedes_duplicate_input :
    PendingActionReloadInput :=
  { valid with
    recomputedHashMatchesEmbedded := false
    actionHashUnique := false }

theorem recomputed_hash_mismatch_precedes_duplicate :
    evaluatePendingActionReloadRejection
      recomputed_hash_mismatch_precedes_duplicate_input =
        some PendingActionReloadReject.recomputedHashMismatch := by
  decide

end PendingActionReload
end Native
end Hegemon

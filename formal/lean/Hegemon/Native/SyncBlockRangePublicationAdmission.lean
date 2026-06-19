namespace Hegemon
namespace Native
namespace SyncBlockRangePublicationAdmission

inductive SyncBlockRangePublicationReject where
  | rangeNotAdmitted
  | servedCountMismatch
  | firstHeightMismatch
  | lastHeightMismatch
  | heightContinuityMismatch
  | parentHashMismatch
  | canonicalRowsUnverified
  | actionBodiesUnverified
deriving DecidableEq, Repr

structure SyncBlockRangePublicationInput where
  rangeAdmitted : Bool
  servedCountMatchesRange : Bool
  firstHeightMatchesRange : Bool
  lastHeightMatchesRange : Bool
  servedHeightsContiguous : Bool
  previousParentAnchorVerified : Bool
  parentHashesContiguous : Bool
  canonicalRowsVerified : Bool
  actionBodiesVerified : Bool
deriving DecidableEq, Repr

def orderedChecks (input : SyncBlockRangePublicationInput) :
    List (Bool × SyncBlockRangePublicationReject) :=
  [
    (input.rangeAdmitted, SyncBlockRangePublicationReject.rangeNotAdmitted),
    (input.servedCountMatchesRange,
      SyncBlockRangePublicationReject.servedCountMismatch),
    (input.firstHeightMatchesRange,
      SyncBlockRangePublicationReject.firstHeightMismatch),
    (input.lastHeightMatchesRange,
      SyncBlockRangePublicationReject.lastHeightMismatch),
    (input.servedHeightsContiguous,
      SyncBlockRangePublicationReject.heightContinuityMismatch),
    (input.previousParentAnchorVerified,
      SyncBlockRangePublicationReject.parentHashMismatch),
    (input.parentHashesContiguous,
      SyncBlockRangePublicationReject.parentHashMismatch),
    (input.canonicalRowsVerified,
      SyncBlockRangePublicationReject.canonicalRowsUnverified),
    (input.actionBodiesVerified,
      SyncBlockRangePublicationReject.actionBodiesUnverified)
  ]

def firstReject : List (Bool × SyncBlockRangePublicationReject) ->
    Option SyncBlockRangePublicationReject
  | [] => none
  | (ok, reject) :: rest => if ok then firstReject rest else some reject

def allChecks : List (Bool × SyncBlockRangePublicationReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allChecks rest

theorem first_reject_none_iff_all_checks
    {checks : List (Bool × SyncBlockRangePublicationReject)} :
    firstReject checks = none ↔ allChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstReject, allChecks]
  | cons head rest ih =>
      cases head with
      | mk ok reject =>
          cases ok <;> simp [firstReject, allChecks, ih]

def evaluateSyncBlockRangePublication
    (input : SyncBlockRangePublicationInput) :
    Option SyncBlockRangePublicationReject :=
  firstReject (orderedChecks input)

def syncBlockRangePublicationAccepts
    (input : SyncBlockRangePublicationInput) : Bool :=
  evaluateSyncBlockRangePublication input = none

def syncBlockRangePublicationPreconditions
    (input : SyncBlockRangePublicationInput) : Bool :=
  allChecks (orderedChecks input)

theorem accepts_iff_sync_block_range_publication_preconditions
    {input : SyncBlockRangePublicationInput} :
    syncBlockRangePublicationAccepts input = true ↔
      syncBlockRangePublicationPreconditions input = true := by
  unfold syncBlockRangePublicationAccepts
  unfold syncBlockRangePublicationPreconditions
  unfold evaluateSyncBlockRangePublication
  by_cases checksOk : firstReject (orderedChecks input) = none
  · have allOk : allChecks (orderedChecks input) = true :=
      (first_reject_none_iff_all_checks).mp checksOk
    simp [checksOk, allOk]
  · have allNotOk : allChecks (orderedChecks input) = false := by
      cases allH : allChecks (orderedChecks input) <;> simp
      have rejectNone : firstReject (orderedChecks input) = none :=
        (first_reject_none_iff_all_checks).mpr allH
      contradiction
    cases rejectH : firstReject (orderedChecks input) with
    | none =>
        contradiction
    | some reject =>
        simp [allNotOk]

def valid : SyncBlockRangePublicationInput :=
  {
    rangeAdmitted := true,
    servedCountMatchesRange := true,
    firstHeightMatchesRange := true,
    lastHeightMatchesRange := true,
    servedHeightsContiguous := true,
    previousParentAnchorVerified := true,
    parentHashesContiguous := true,
    canonicalRowsVerified := true,
    actionBodiesVerified := true
  }

theorem valid_accepts :
    evaluateSyncBlockRangePublication valid = none := by
  decide

def rangeNotAdmitted : SyncBlockRangePublicationInput :=
  { valid with rangeAdmitted := false }

theorem range_not_admitted_rejects :
    evaluateSyncBlockRangePublication rangeNotAdmitted =
      some SyncBlockRangePublicationReject.rangeNotAdmitted := by
  decide

def servedCountMismatch : SyncBlockRangePublicationInput :=
  { valid with servedCountMatchesRange := false }

theorem served_count_mismatch_rejects :
    evaluateSyncBlockRangePublication servedCountMismatch =
      some SyncBlockRangePublicationReject.servedCountMismatch := by
  decide

def firstHeightMismatch : SyncBlockRangePublicationInput :=
  { valid with firstHeightMatchesRange := false }

theorem first_height_mismatch_rejects :
    evaluateSyncBlockRangePublication firstHeightMismatch =
      some SyncBlockRangePublicationReject.firstHeightMismatch := by
  decide

def lastHeightMismatch : SyncBlockRangePublicationInput :=
  { valid with lastHeightMatchesRange := false }

theorem last_height_mismatch_rejects :
    evaluateSyncBlockRangePublication lastHeightMismatch =
      some SyncBlockRangePublicationReject.lastHeightMismatch := by
  decide

def heightContinuityMismatch : SyncBlockRangePublicationInput :=
  { valid with servedHeightsContiguous := false }

theorem height_continuity_mismatch_rejects :
    evaluateSyncBlockRangePublication heightContinuityMismatch =
      some SyncBlockRangePublicationReject.heightContinuityMismatch := by
  decide

def parentHashMismatch : SyncBlockRangePublicationInput :=
  { valid with parentHashesContiguous := false }

theorem parent_hash_mismatch_rejects :
    evaluateSyncBlockRangePublication parentHashMismatch =
      some SyncBlockRangePublicationReject.parentHashMismatch := by
  decide

def previousParentAnchorMismatch : SyncBlockRangePublicationInput :=
  { valid with previousParentAnchorVerified := false }

theorem previous_parent_anchor_mismatch_rejects :
    evaluateSyncBlockRangePublication previousParentAnchorMismatch =
      some SyncBlockRangePublicationReject.parentHashMismatch := by
  decide

def canonicalRowsUnverified : SyncBlockRangePublicationInput :=
  { valid with canonicalRowsVerified := false }

theorem canonical_rows_unverified_rejects :
    evaluateSyncBlockRangePublication canonicalRowsUnverified =
      some SyncBlockRangePublicationReject.canonicalRowsUnverified := by
  decide

def actionBodiesUnverified : SyncBlockRangePublicationInput :=
  { valid with actionBodiesVerified := false }

theorem action_bodies_unverified_rejects :
    evaluateSyncBlockRangePublication actionBodiesUnverified =
      some SyncBlockRangePublicationReject.actionBodiesUnverified := by
  decide

def countPrecedesHeightMismatch : SyncBlockRangePublicationInput :=
  { valid with
    servedCountMatchesRange := false,
    firstHeightMatchesRange := false,
    servedHeightsContiguous := false }

theorem served_count_precedes_height_mismatch :
    evaluateSyncBlockRangePublication countPrecedesHeightMismatch =
      some SyncBlockRangePublicationReject.servedCountMismatch := by
  decide

def parentPrecedesVerificationMismatch : SyncBlockRangePublicationInput :=
  { valid with
    previousParentAnchorVerified := false,
    parentHashesContiguous := false,
    canonicalRowsVerified := false,
    actionBodiesVerified := false }

theorem parent_hash_precedes_verification_mismatch :
    evaluateSyncBlockRangePublication parentPrecedesVerificationMismatch =
      some SyncBlockRangePublicationReject.parentHashMismatch := by
  decide

end SyncBlockRangePublicationAdmission
end Native
end Hegemon

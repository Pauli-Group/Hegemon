namespace Hegemon
namespace Native
namespace CanonicalStateReload

inductive CanonicalStateReloadReject where
  | malformedNullifierKey
  | invalidNullifierMarker
  | malformedCommitmentKey
  | malformedCommitmentValue
  | commitmentIndexGap
  | commitmentTreeRebuildFailed
  | commitmentRootMismatch
  | nullifierRootMismatch
deriving DecidableEq, Repr

structure CanonicalStateReloadInput where
  nullifierKeysWellFormed : Bool
  nullifierMarkersValid : Bool
  commitmentKeysWellFormed : Bool
  commitmentValuesWellFormed : Bool
  commitmentIndexesContiguous : Bool
  commitmentTreeRebuilt : Bool
  commitmentRootMatchesBest : Bool
  nullifierRootMatchesBest : Bool
deriving DecidableEq, Repr

def orderedChecks (input : CanonicalStateReloadInput) :
    List (Bool × CanonicalStateReloadReject) :=
  [
    (input.nullifierKeysWellFormed,
      CanonicalStateReloadReject.malformedNullifierKey),
    (input.nullifierMarkersValid,
      CanonicalStateReloadReject.invalidNullifierMarker),
    (input.commitmentKeysWellFormed,
      CanonicalStateReloadReject.malformedCommitmentKey),
    (input.commitmentValuesWellFormed,
      CanonicalStateReloadReject.malformedCommitmentValue),
    (input.commitmentIndexesContiguous,
      CanonicalStateReloadReject.commitmentIndexGap),
    (input.commitmentTreeRebuilt,
      CanonicalStateReloadReject.commitmentTreeRebuildFailed),
    (input.commitmentRootMatchesBest,
      CanonicalStateReloadReject.commitmentRootMismatch),
    (input.nullifierRootMatchesBest,
      CanonicalStateReloadReject.nullifierRootMismatch)
  ]

def firstReject :
    List (Bool × CanonicalStateReloadReject) ->
      Option CanonicalStateReloadReject
  | [] => none
  | (ok, reject) :: rest => if ok then firstReject rest else some reject

def allChecks : List (Bool × CanonicalStateReloadReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allChecks rest

theorem first_reject_none_iff_all_checks
    {checks : List (Bool × CanonicalStateReloadReject)} :
    firstReject checks = none ↔ allChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstReject, allChecks]
  | cons head rest ih =>
      cases head with
      | mk ok reject =>
          cases ok <;> simp [firstReject, allChecks, ih]

def evaluateCanonicalStateReloadRejection
    (input : CanonicalStateReloadInput) :
      Option CanonicalStateReloadReject :=
  firstReject (orderedChecks input)

def canonicalStateReloadAccepts
    (input : CanonicalStateReloadInput) : Bool :=
  evaluateCanonicalStateReloadRejection input = none

def canonicalStateReloadPreconditions
    (input : CanonicalStateReloadInput) : Bool :=
  allChecks (orderedChecks input)

theorem accepts_iff_canonical_state_reload_preconditions
    {input : CanonicalStateReloadInput} :
    canonicalStateReloadAccepts input = true ↔
      canonicalStateReloadPreconditions input = true := by
  unfold canonicalStateReloadAccepts canonicalStateReloadPreconditions
  unfold evaluateCanonicalStateReloadRejection
  simpa using
    (first_reject_none_iff_all_checks
      (checks := orderedChecks input))

def valid : CanonicalStateReloadInput :=
  {
    nullifierKeysWellFormed := true,
    nullifierMarkersValid := true,
    commitmentKeysWellFormed := true,
    commitmentValuesWellFormed := true,
    commitmentIndexesContiguous := true,
    commitmentTreeRebuilt := true,
    commitmentRootMatchesBest := true,
    nullifierRootMatchesBest := true
  }

theorem valid_accepts :
    evaluateCanonicalStateReloadRejection valid = none := by
  decide

def malformedNullifierKey : CanonicalStateReloadInput :=
  { valid with nullifierKeysWellFormed := false }

theorem malformed_nullifier_key_rejects :
    evaluateCanonicalStateReloadRejection malformedNullifierKey =
      some CanonicalStateReloadReject.malformedNullifierKey := by
  decide

def invalidNullifierMarker : CanonicalStateReloadInput :=
  { valid with nullifierMarkersValid := false }

theorem invalid_nullifier_marker_rejects :
    evaluateCanonicalStateReloadRejection invalidNullifierMarker =
      some CanonicalStateReloadReject.invalidNullifierMarker := by
  decide

def malformedCommitmentKey : CanonicalStateReloadInput :=
  { valid with commitmentKeysWellFormed := false }

theorem malformed_commitment_key_rejects :
    evaluateCanonicalStateReloadRejection malformedCommitmentKey =
      some CanonicalStateReloadReject.malformedCommitmentKey := by
  decide

def malformedCommitmentValue : CanonicalStateReloadInput :=
  { valid with commitmentValuesWellFormed := false }

theorem malformed_commitment_value_rejects :
    evaluateCanonicalStateReloadRejection malformedCommitmentValue =
      some CanonicalStateReloadReject.malformedCommitmentValue := by
  decide

def commitmentIndexGap : CanonicalStateReloadInput :=
  { valid with commitmentIndexesContiguous := false }

theorem commitment_index_gap_rejects :
    evaluateCanonicalStateReloadRejection commitmentIndexGap =
      some CanonicalStateReloadReject.commitmentIndexGap := by
  decide

def commitmentTreeRebuildFailed : CanonicalStateReloadInput :=
  { valid with commitmentTreeRebuilt := false }

theorem commitment_tree_rebuild_failed_rejects :
    evaluateCanonicalStateReloadRejection commitmentTreeRebuildFailed =
      some CanonicalStateReloadReject.commitmentTreeRebuildFailed := by
  decide

def commitmentRootMismatch : CanonicalStateReloadInput :=
  { valid with commitmentRootMatchesBest := false }

theorem commitment_root_mismatch_rejects :
    evaluateCanonicalStateReloadRejection commitmentRootMismatch =
      some CanonicalStateReloadReject.commitmentRootMismatch := by
  decide

def nullifierRootMismatch : CanonicalStateReloadInput :=
  { valid with nullifierRootMatchesBest := false }

theorem nullifier_root_mismatch_rejects :
    evaluateCanonicalStateReloadRejection nullifierRootMismatch =
      some CanonicalStateReloadReject.nullifierRootMismatch := by
  decide

def nullifier_key_precedes_commitment_key_input :
    CanonicalStateReloadInput :=
  { valid with
    nullifierKeysWellFormed := false
    commitmentKeysWellFormed := false }

theorem nullifier_key_precedes_commitment_key :
    evaluateCanonicalStateReloadRejection
      nullifier_key_precedes_commitment_key_input =
        some CanonicalStateReloadReject.malformedNullifierKey := by
  decide

def commitment_key_precedes_commitment_value_input :
    CanonicalStateReloadInput :=
  { valid with
    commitmentKeysWellFormed := false
    commitmentValuesWellFormed := false }

theorem commitment_key_precedes_commitment_value :
    evaluateCanonicalStateReloadRejection
      commitment_key_precedes_commitment_value_input =
        some CanonicalStateReloadReject.malformedCommitmentKey := by
  decide

def commitment_root_precedes_nullifier_root_input :
    CanonicalStateReloadInput :=
  { valid with
    commitmentRootMatchesBest := false
    nullifierRootMatchesBest := false }

theorem commitment_root_precedes_nullifier_root :
    evaluateCanonicalStateReloadRejection
      commitment_root_precedes_nullifier_root_input =
        some CanonicalStateReloadReject.commitmentRootMismatch := by
  decide

end CanonicalStateReload
end Native
end Hegemon

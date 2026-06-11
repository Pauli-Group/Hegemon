namespace Hegemon
namespace Native
namespace StagedCiphertextReload

inductive StagedCiphertextReloadReject where
  | malformedCiphertextKey
  | oversizedCiphertext
  | ciphertextHashMismatch
  | stagedCiphertextCapacityReached
deriving DecidableEq, Repr

structure StagedCiphertextReloadInput where
  keyWellFormed : Bool
  ciphertextWithinLimit : Bool
  ciphertextHashMatchesKey : Bool
  capacityAvailable : Bool
deriving DecidableEq, Repr

def orderedChecks (input : StagedCiphertextReloadInput) :
    List (Bool × StagedCiphertextReloadReject) :=
  [
    (input.keyWellFormed,
      StagedCiphertextReloadReject.malformedCiphertextKey),
    (input.ciphertextWithinLimit,
      StagedCiphertextReloadReject.oversizedCiphertext),
    (input.ciphertextHashMatchesKey,
      StagedCiphertextReloadReject.ciphertextHashMismatch),
    (input.capacityAvailable,
      StagedCiphertextReloadReject.stagedCiphertextCapacityReached)
  ]

def firstReject :
    List (Bool × StagedCiphertextReloadReject) ->
      Option StagedCiphertextReloadReject
  | [] => none
  | (ok, reject) :: rest => if ok then firstReject rest else some reject

def allChecks : List (Bool × StagedCiphertextReloadReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allChecks rest

theorem first_reject_none_iff_all_checks
    {checks : List (Bool × StagedCiphertextReloadReject)} :
    firstReject checks = none ↔ allChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstReject, allChecks]
  | cons head rest ih =>
      cases head with
      | mk ok reject =>
          cases ok <;> simp [firstReject, allChecks, ih]

def evaluateStagedCiphertextReloadRejection
    (input : StagedCiphertextReloadInput) :
      Option StagedCiphertextReloadReject :=
  firstReject (orderedChecks input)

def stagedCiphertextReloadAccepts
    (input : StagedCiphertextReloadInput) : Bool :=
  evaluateStagedCiphertextReloadRejection input = none

def stagedCiphertextReloadPreconditions
    (input : StagedCiphertextReloadInput) : Bool :=
  allChecks (orderedChecks input)

theorem accepts_iff_staged_ciphertext_reload_preconditions
    {input : StagedCiphertextReloadInput} :
    stagedCiphertextReloadAccepts input = true ↔
      stagedCiphertextReloadPreconditions input = true := by
  unfold stagedCiphertextReloadAccepts stagedCiphertextReloadPreconditions
  unfold evaluateStagedCiphertextReloadRejection
  simpa using
    (first_reject_none_iff_all_checks
      (checks := orderedChecks input))

def valid : StagedCiphertextReloadInput :=
  {
    keyWellFormed := true,
    ciphertextWithinLimit := true,
    ciphertextHashMatchesKey := true,
    capacityAvailable := true
  }

theorem valid_accepts :
    evaluateStagedCiphertextReloadRejection valid = none := by
  decide

def malformedCiphertextKey : StagedCiphertextReloadInput :=
  { valid with keyWellFormed := false }

theorem malformed_ciphertext_key_rejects :
    evaluateStagedCiphertextReloadRejection malformedCiphertextKey =
      some StagedCiphertextReloadReject.malformedCiphertextKey := by
  decide

def oversizedCiphertext : StagedCiphertextReloadInput :=
  { valid with ciphertextWithinLimit := false }

theorem oversized_ciphertext_rejects :
    evaluateStagedCiphertextReloadRejection oversizedCiphertext =
      some StagedCiphertextReloadReject.oversizedCiphertext := by
  decide

def ciphertextHashMismatch : StagedCiphertextReloadInput :=
  { valid with ciphertextHashMatchesKey := false }

theorem ciphertext_hash_mismatch_rejects :
    evaluateStagedCiphertextReloadRejection ciphertextHashMismatch =
      some StagedCiphertextReloadReject.ciphertextHashMismatch := by
  decide

def stagedCiphertextCapacityReached : StagedCiphertextReloadInput :=
  { valid with capacityAvailable := false }

theorem staged_ciphertext_capacity_reached_rejects :
    evaluateStagedCiphertextReloadRejection stagedCiphertextCapacityReached =
      some StagedCiphertextReloadReject.stagedCiphertextCapacityReached := by
  decide

def malformed_key_precedes_oversize_input :
    StagedCiphertextReloadInput :=
  { valid with
    keyWellFormed := false
    ciphertextWithinLimit := false }

theorem malformed_key_precedes_oversize :
    evaluateStagedCiphertextReloadRejection
      malformed_key_precedes_oversize_input =
        some StagedCiphertextReloadReject.malformedCiphertextKey := by
  decide

def oversize_precedes_hash_mismatch_input :
    StagedCiphertextReloadInput :=
  { valid with
    ciphertextWithinLimit := false
    ciphertextHashMatchesKey := false }

theorem oversize_precedes_hash_mismatch :
    evaluateStagedCiphertextReloadRejection
      oversize_precedes_hash_mismatch_input =
        some StagedCiphertextReloadReject.oversizedCiphertext := by
  decide

def hash_mismatch_precedes_capacity_input :
    StagedCiphertextReloadInput :=
  { valid with
    ciphertextHashMatchesKey := false
    capacityAvailable := false }

theorem hash_mismatch_precedes_capacity :
    evaluateStagedCiphertextReloadRejection
      hash_mismatch_precedes_capacity_input =
        some StagedCiphertextReloadReject.ciphertextHashMismatch := by
  decide

end StagedCiphertextReload
end Native
end Hegemon

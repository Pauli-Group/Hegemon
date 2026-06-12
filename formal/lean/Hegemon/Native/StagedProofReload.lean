namespace Hegemon
namespace Native
namespace StagedProofReload

inductive StagedProofReloadReject where
  | malformedProofKey
  | emptyProof
  | oversizedProof
  | stagedProofCapacityReached
  | stagedProofByteCapacityReached
  | proofBindingHashMismatch
deriving DecidableEq, Repr

structure StagedProofReloadInput where
  keyWellFormed : Bool
  proofNonempty : Bool
  proofWithinLimit : Bool
  capacityAvailable : Bool
  byteCapacityAvailable : Bool
  proofBindingHashMatchesKey : Bool
deriving DecidableEq, Repr

def orderedChecks (input : StagedProofReloadInput) :
    List (Bool × StagedProofReloadReject) :=
  [
    (input.keyWellFormed,
      StagedProofReloadReject.malformedProofKey),
    (input.proofNonempty,
      StagedProofReloadReject.emptyProof),
    (input.proofWithinLimit,
      StagedProofReloadReject.oversizedProof),
    (input.capacityAvailable,
      StagedProofReloadReject.stagedProofCapacityReached),
    (input.byteCapacityAvailable,
      StagedProofReloadReject.stagedProofByteCapacityReached),
    (input.proofBindingHashMatchesKey,
      StagedProofReloadReject.proofBindingHashMismatch)
  ]

def firstReject :
    List (Bool × StagedProofReloadReject) ->
      Option StagedProofReloadReject
  | [] => none
  | (ok, reject) :: rest => if ok then firstReject rest else some reject

def allChecks : List (Bool × StagedProofReloadReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allChecks rest

theorem first_reject_none_iff_all_checks
    {checks : List (Bool × StagedProofReloadReject)} :
    firstReject checks = none ↔ allChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstReject, allChecks]
  | cons head rest ih =>
      cases head with
      | mk ok reject =>
          cases ok <;> simp [firstReject, allChecks, ih]

def evaluateStagedProofReloadRejection
    (input : StagedProofReloadInput) :
      Option StagedProofReloadReject :=
  firstReject (orderedChecks input)

def stagedProofReloadAccepts
    (input : StagedProofReloadInput) : Bool :=
  evaluateStagedProofReloadRejection input = none

def stagedProofReloadPreconditions
    (input : StagedProofReloadInput) : Bool :=
  allChecks (orderedChecks input)

theorem accepts_iff_staged_proof_reload_preconditions
    {input : StagedProofReloadInput} :
    stagedProofReloadAccepts input = true ↔
      stagedProofReloadPreconditions input = true := by
  unfold stagedProofReloadAccepts stagedProofReloadPreconditions
  unfold evaluateStagedProofReloadRejection
  simpa using
    (first_reject_none_iff_all_checks
      (checks := orderedChecks input))

def valid : StagedProofReloadInput :=
  {
    keyWellFormed := true,
    proofNonempty := true,
    proofWithinLimit := true,
    capacityAvailable := true,
    byteCapacityAvailable := true,
    proofBindingHashMatchesKey := true
  }

theorem valid_accepts :
    evaluateStagedProofReloadRejection valid = none := by
  decide

def malformedProofKey : StagedProofReloadInput :=
  { valid with keyWellFormed := false }

theorem malformed_proof_key_rejects :
    evaluateStagedProofReloadRejection malformedProofKey =
      some StagedProofReloadReject.malformedProofKey := by
  decide

def emptyProof : StagedProofReloadInput :=
  { valid with proofNonempty := false }

theorem empty_proof_rejects :
    evaluateStagedProofReloadRejection emptyProof =
      some StagedProofReloadReject.emptyProof := by
  decide

def oversizedProof : StagedProofReloadInput :=
  { valid with proofWithinLimit := false }

theorem oversized_proof_rejects :
    evaluateStagedProofReloadRejection oversizedProof =
      some StagedProofReloadReject.oversizedProof := by
  decide

def stagedProofCapacityReached : StagedProofReloadInput :=
  { valid with capacityAvailable := false }

theorem staged_proof_capacity_reached_rejects :
    evaluateStagedProofReloadRejection stagedProofCapacityReached =
      some StagedProofReloadReject.stagedProofCapacityReached := by
  decide

def stagedProofByteCapacityReached : StagedProofReloadInput :=
  { valid with byteCapacityAvailable := false }

theorem staged_proof_byte_capacity_reached_rejects :
    evaluateStagedProofReloadRejection stagedProofByteCapacityReached =
      some StagedProofReloadReject.stagedProofByteCapacityReached := by
  decide

def proofBindingHashMismatch : StagedProofReloadInput :=
  { valid with proofBindingHashMatchesKey := false }

theorem proof_binding_hash_mismatch_rejects :
    evaluateStagedProofReloadRejection proofBindingHashMismatch =
      some StagedProofReloadReject.proofBindingHashMismatch := by
  decide

def malformed_key_precedes_empty_input :
    StagedProofReloadInput :=
  { valid with
    keyWellFormed := false
    proofNonempty := false }

theorem malformed_key_precedes_empty :
    evaluateStagedProofReloadRejection
      malformed_key_precedes_empty_input =
        some StagedProofReloadReject.malformedProofKey := by
  decide

def empty_precedes_oversize_input :
    StagedProofReloadInput :=
  { valid with
    proofNonempty := false
    proofWithinLimit := false }

theorem empty_precedes_oversize :
    evaluateStagedProofReloadRejection
      empty_precedes_oversize_input =
        some StagedProofReloadReject.emptyProof := by
  decide

def oversize_precedes_capacity_input :
    StagedProofReloadInput :=
  { valid with
    proofWithinLimit := false
    capacityAvailable := false }

theorem oversize_precedes_capacity :
    evaluateStagedProofReloadRejection
      oversize_precedes_capacity_input =
        some StagedProofReloadReject.oversizedProof := by
  decide

def capacity_precedes_byte_capacity_input :
    StagedProofReloadInput :=
  { valid with
    capacityAvailable := false
    byteCapacityAvailable := false }

theorem capacity_precedes_byte_capacity :
    evaluateStagedProofReloadRejection
      capacity_precedes_byte_capacity_input =
        some StagedProofReloadReject.stagedProofCapacityReached := by
  decide

def byte_capacity_precedes_binding_mismatch_input :
    StagedProofReloadInput :=
  { valid with
    byteCapacityAvailable := false
    proofBindingHashMatchesKey := false }

theorem byte_capacity_precedes_binding_mismatch :
    evaluateStagedProofReloadRejection
      byte_capacity_precedes_binding_mismatch_input =
        some StagedProofReloadReject.stagedProofByteCapacityReached := by
  decide

end StagedProofReload
end Native
end Hegemon

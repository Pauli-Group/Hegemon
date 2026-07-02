namespace Hegemon
namespace Native
namespace CanonicalReorgChainAdmission

inductive CanonicalReorgChainReject where
  | chainEmpty
  | genesisMismatch
  | bestMetadataMismatch
  | canonicalHeightMismatch
  | chainIdMismatch
  | rulesHashMismatch
  | hashWorkHashMismatch
  | parentHashMismatch
  | blockRecordCountMismatch
  | blockRecordMismatch
  | heightEntryCountMismatch
  | heightEntryMismatch
deriving DecidableEq, Repr

structure CanonicalReorgChainInput where
  chainNonempty : Bool
  genesisMatchesExpected : Bool
  bestMetadataMatchesChain : Bool
  canonicalHeightsContiguous : Bool
  canonicalChainIdsMatch : Bool
  canonicalRulesHashesMatch : Bool
  canonicalHashesMatchWorkHashes : Bool
  canonicalParentHashesContiguous : Bool
  blockRecordCountMatchesChain : Bool
  blockRecordsMatchChain : Bool
  heightEntryCountMatchesChain : Bool
  heightEntriesMatchChain : Bool
deriving DecidableEq, Repr

def orderedChecks (input : CanonicalReorgChainInput) :
    List (Bool × CanonicalReorgChainReject) :=
  [
    (input.chainNonempty, CanonicalReorgChainReject.chainEmpty),
    (input.genesisMatchesExpected, CanonicalReorgChainReject.genesisMismatch),
    (input.bestMetadataMatchesChain, CanonicalReorgChainReject.bestMetadataMismatch),
    (input.canonicalHeightsContiguous, CanonicalReorgChainReject.canonicalHeightMismatch),
    (input.canonicalChainIdsMatch, CanonicalReorgChainReject.chainIdMismatch),
    (input.canonicalRulesHashesMatch, CanonicalReorgChainReject.rulesHashMismatch),
    (input.canonicalHashesMatchWorkHashes, CanonicalReorgChainReject.hashWorkHashMismatch),
    (input.canonicalParentHashesContiguous, CanonicalReorgChainReject.parentHashMismatch),
    (input.blockRecordCountMatchesChain, CanonicalReorgChainReject.blockRecordCountMismatch),
    (input.blockRecordsMatchChain, CanonicalReorgChainReject.blockRecordMismatch),
    (input.heightEntryCountMatchesChain, CanonicalReorgChainReject.heightEntryCountMismatch),
    (input.heightEntriesMatchChain, CanonicalReorgChainReject.heightEntryMismatch)
  ]

def firstReject : List (Bool × CanonicalReorgChainReject) ->
    Option CanonicalReorgChainReject
  | [] => none
  | (ok, reject) :: rest => if ok then firstReject rest else some reject

def allChecks : List (Bool × CanonicalReorgChainReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allChecks rest

theorem first_reject_none_iff_all_checks
    {checks : List (Bool × CanonicalReorgChainReject)} :
    firstReject checks = none ↔ allChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstReject, allChecks]
  | cons head rest ih =>
      cases head with
      | mk ok reject =>
          cases ok <;> simp [firstReject, allChecks, ih]

def evaluateCanonicalReorgChainRejection
    (input : CanonicalReorgChainInput) :
    Option CanonicalReorgChainReject :=
  firstReject (orderedChecks input)

def canonicalReorgChainAccepts (input : CanonicalReorgChainInput) : Bool :=
  evaluateCanonicalReorgChainRejection input = none

def canonicalReorgChainPreconditions
    (input : CanonicalReorgChainInput) : Bool :=
  allChecks (orderedChecks input)

theorem accepts_iff_canonical_reorg_chain_preconditions
    {input : CanonicalReorgChainInput} :
    canonicalReorgChainAccepts input = true ↔
      canonicalReorgChainPreconditions input = true := by
  unfold canonicalReorgChainAccepts canonicalReorgChainPreconditions
  unfold evaluateCanonicalReorgChainRejection
  by_cases checks_ok : firstReject (orderedChecks input) = none
  · have all_ok : allChecks (orderedChecks input) = true :=
      (first_reject_none_iff_all_checks).mp checks_ok
    simp [checks_ok, all_ok]
  · have all_not_ok : allChecks (orderedChecks input) = false := by
      cases all_h : allChecks (orderedChecks input) <;> simp
      have reject_none : firstReject (orderedChecks input) = none :=
        (first_reject_none_iff_all_checks).mpr all_h
      contradiction
    cases reject_h : firstReject (orderedChecks input) with
    | none =>
        contradiction
    | some reject =>
        simp [all_not_ok]

def valid : CanonicalReorgChainInput :=
  {
    chainNonempty := true,
    genesisMatchesExpected := true,
    bestMetadataMatchesChain := true,
    canonicalHeightsContiguous := true,
    canonicalChainIdsMatch := true,
    canonicalRulesHashesMatch := true,
    canonicalHashesMatchWorkHashes := true,
    canonicalParentHashesContiguous := true,
    blockRecordCountMatchesChain := true,
    blockRecordsMatchChain := true,
    heightEntryCountMatchesChain := true,
    heightEntriesMatchChain := true
  }

theorem valid_accepts :
    evaluateCanonicalReorgChainRejection valid = none := by
  decide

def chainEmpty : CanonicalReorgChainInput :=
  { valid with chainNonempty := false }

theorem empty_chain_rejects :
    evaluateCanonicalReorgChainRejection chainEmpty =
      some CanonicalReorgChainReject.chainEmpty := by
  decide

def genesisMismatch : CanonicalReorgChainInput :=
  { valid with genesisMatchesExpected := false }

theorem genesis_mismatch_rejects :
    evaluateCanonicalReorgChainRejection genesisMismatch =
      some CanonicalReorgChainReject.genesisMismatch := by
  decide

def bestMetadataMismatch : CanonicalReorgChainInput :=
  { valid with bestMetadataMatchesChain := false }

theorem best_metadata_mismatch_rejects :
    evaluateCanonicalReorgChainRejection bestMetadataMismatch =
      some CanonicalReorgChainReject.bestMetadataMismatch := by
  decide

def canonicalHeightMismatch : CanonicalReorgChainInput :=
  { valid with canonicalHeightsContiguous := false }

theorem canonical_height_mismatch_rejects :
    evaluateCanonicalReorgChainRejection canonicalHeightMismatch =
      some CanonicalReorgChainReject.canonicalHeightMismatch := by
  decide

def chainIdMismatch : CanonicalReorgChainInput :=
  { valid with canonicalChainIdsMatch := false }

theorem chain_id_mismatch_rejects :
    evaluateCanonicalReorgChainRejection chainIdMismatch =
      some CanonicalReorgChainReject.chainIdMismatch := by
  decide

def rulesHashMismatch : CanonicalReorgChainInput :=
  { valid with canonicalRulesHashesMatch := false }

theorem rules_hash_mismatch_rejects :
    evaluateCanonicalReorgChainRejection rulesHashMismatch =
      some CanonicalReorgChainReject.rulesHashMismatch := by
  decide

def hashWorkHashMismatch : CanonicalReorgChainInput :=
  { valid with canonicalHashesMatchWorkHashes := false }

theorem hash_work_hash_mismatch_rejects :
    evaluateCanonicalReorgChainRejection hashWorkHashMismatch =
      some CanonicalReorgChainReject.hashWorkHashMismatch := by
  decide

def parentHashMismatch : CanonicalReorgChainInput :=
  { valid with canonicalParentHashesContiguous := false }

theorem parent_hash_mismatch_rejects :
    evaluateCanonicalReorgChainRejection parentHashMismatch =
      some CanonicalReorgChainReject.parentHashMismatch := by
  decide

def blockRecordCountMismatch : CanonicalReorgChainInput :=
  { valid with blockRecordCountMatchesChain := false,
               blockRecordsMatchChain := false }

theorem block_record_count_mismatch_rejects :
    evaluateCanonicalReorgChainRejection blockRecordCountMismatch =
      some CanonicalReorgChainReject.blockRecordCountMismatch := by
  decide

def blockRecordMismatch : CanonicalReorgChainInput :=
  { valid with blockRecordsMatchChain := false }

theorem block_record_mismatch_rejects :
    evaluateCanonicalReorgChainRejection blockRecordMismatch =
      some CanonicalReorgChainReject.blockRecordMismatch := by
  decide

def heightEntryCountMismatch : CanonicalReorgChainInput :=
  { valid with heightEntryCountMatchesChain := false,
               heightEntriesMatchChain := false }

theorem height_entry_count_mismatch_rejects :
    evaluateCanonicalReorgChainRejection heightEntryCountMismatch =
      some CanonicalReorgChainReject.heightEntryCountMismatch := by
  decide

def heightEntryMismatch : CanonicalReorgChainInput :=
  { valid with heightEntriesMatchChain := false }

theorem height_entry_mismatch_rejects :
    evaluateCanonicalReorgChainRejection heightEntryMismatch =
      some CanonicalReorgChainReject.heightEntryMismatch := by
  decide

def structuralBeforeWriteProjection : CanonicalReorgChainInput :=
  { valid with chainNonempty := false,
               blockRecordCountMatchesChain := false,
               heightEntryCountMatchesChain := false }

theorem structural_precedes_write_projection :
    evaluateCanonicalReorgChainRejection structuralBeforeWriteProjection =
      some CanonicalReorgChainReject.chainEmpty := by
  decide

def blockRecordCountPrecedence : CanonicalReorgChainInput :=
  { valid with blockRecordCountMatchesChain := false,
               blockRecordsMatchChain := false,
               heightEntriesMatchChain := false }

theorem block_record_count_precedes_record_mismatch :
    evaluateCanonicalReorgChainRejection blockRecordCountPrecedence =
      some CanonicalReorgChainReject.blockRecordCountMismatch := by
  decide

def heightEntryCountPrecedence : CanonicalReorgChainInput :=
  { valid with heightEntryCountMatchesChain := false,
               heightEntriesMatchChain := false }

theorem height_entry_count_precedes_height_entry_mismatch :
    evaluateCanonicalReorgChainRejection heightEntryCountPrecedence =
      some CanonicalReorgChainReject.heightEntryCountMismatch := by
  decide

end CanonicalReorgChainAdmission
end Native
end Hegemon

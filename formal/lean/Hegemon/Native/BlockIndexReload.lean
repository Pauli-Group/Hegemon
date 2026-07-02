namespace Hegemon
namespace Native
namespace BlockIndexReload

inductive BlockIndexReloadReject where
  | chainReconstructionFailed
  | chainEmpty
  | genesisMismatch
  | bestMetadataMismatch
  | canonicalHeightMismatch
  | chainIdMismatch
  | rulesHashMismatch
  | hashWorkHashMismatch
  | parentHashMismatch
  | malformedHeightKey
  | malformedHeightValue
  | extraHeightIndex
  | heightIndexMismatch
  | heightHashMismatch
  | missingHeightIndex
  | genesisMarkerInvalidLength
  | genesisMarkerMismatch
deriving DecidableEq, Repr

structure BlockIndexReloadInput where
  chainReconstructed : Bool
  chainNonempty : Bool
  genesisMatchesExpected : Bool
  bestMetadataMatchesChain : Bool
  canonicalHeightsContiguous : Bool
  canonicalChainIdsMatch : Bool
  canonicalRulesHashesMatch : Bool
  canonicalHashesMatchWorkHashes : Bool
  canonicalParentHashesContiguous : Bool
  heightKeysWellFormed : Bool
  heightValuesWellFormed : Bool
  noExtraHeightIndexes : Bool
  heightIndexHeightsMatchChain : Bool
  heightIndexHashesMatchChain : Bool
  allCanonicalHeightsIndexed : Bool
  genesisMarkerPresent : Bool
  genesisMarkerLengthValid : Bool
  genesisMarkerMatchesExpected : Bool
deriving DecidableEq, Repr

def orderedChecks (input : BlockIndexReloadInput) :
    List (Bool × BlockIndexReloadReject) :=
  [
    (input.chainReconstructed, BlockIndexReloadReject.chainReconstructionFailed),
    (input.chainNonempty, BlockIndexReloadReject.chainEmpty),
    (input.genesisMatchesExpected, BlockIndexReloadReject.genesisMismatch),
    (input.bestMetadataMatchesChain, BlockIndexReloadReject.bestMetadataMismatch),
    (input.canonicalHeightsContiguous, BlockIndexReloadReject.canonicalHeightMismatch),
    (input.canonicalChainIdsMatch, BlockIndexReloadReject.chainIdMismatch),
    (input.canonicalRulesHashesMatch, BlockIndexReloadReject.rulesHashMismatch),
    (input.canonicalHashesMatchWorkHashes, BlockIndexReloadReject.hashWorkHashMismatch),
    (input.canonicalParentHashesContiguous, BlockIndexReloadReject.parentHashMismatch),
    (input.heightKeysWellFormed, BlockIndexReloadReject.malformedHeightKey),
    (input.heightValuesWellFormed, BlockIndexReloadReject.malformedHeightValue),
    (input.noExtraHeightIndexes, BlockIndexReloadReject.extraHeightIndex),
    (input.heightIndexHeightsMatchChain, BlockIndexReloadReject.heightIndexMismatch),
    (input.heightIndexHashesMatchChain, BlockIndexReloadReject.heightHashMismatch),
    (input.allCanonicalHeightsIndexed, BlockIndexReloadReject.missingHeightIndex)
  ]

def firstReject : List (Bool × BlockIndexReloadReject) -> Option BlockIndexReloadReject
  | [] => none
  | (ok, reject) :: rest => if ok then firstReject rest else some reject

def allChecks : List (Bool × BlockIndexReloadReject) -> Bool
  | [] => true
  | (ok, _) :: rest => ok && allChecks rest

theorem first_reject_none_iff_all_checks
    {checks : List (Bool × BlockIndexReloadReject)} :
    firstReject checks = none ↔ allChecks checks = true := by
  induction checks with
  | nil =>
      simp [firstReject, allChecks]
  | cons head rest ih =>
      cases head with
      | mk ok reject =>
          cases ok <;> simp [firstReject, allChecks, ih]

def evaluateBlockIndexReloadRejection
    (input : BlockIndexReloadInput) : Option BlockIndexReloadReject :=
  match firstReject (orderedChecks input) with
  | some reject => some reject
  | none =>
      if input.genesisMarkerPresent = false then
        none
      else if input.genesisMarkerLengthValid = false then
        some BlockIndexReloadReject.genesisMarkerInvalidLength
      else if input.genesisMarkerMatchesExpected = false then
        some BlockIndexReloadReject.genesisMarkerMismatch
      else
        none

def blockIndexReloadAccepts (input : BlockIndexReloadInput) : Bool :=
  evaluateBlockIndexReloadRejection input = none

def genesisMarkerPrecondition (input : BlockIndexReloadInput) : Bool :=
  (!input.genesisMarkerPresent)
    || (input.genesisMarkerLengthValid && input.genesisMarkerMatchesExpected)

def blockIndexReloadPreconditions (input : BlockIndexReloadInput) : Bool :=
  allChecks (orderedChecks input) && genesisMarkerPrecondition input

def blockIndexReloadRepairsGenesisMarker (input : BlockIndexReloadInput) : Bool :=
  blockIndexReloadAccepts input && !input.genesisMarkerPresent

theorem accepts_iff_block_index_reload_preconditions
    {input : BlockIndexReloadInput} :
    blockIndexReloadAccepts input = true ↔
      blockIndexReloadPreconditions input = true := by
  unfold blockIndexReloadAccepts blockIndexReloadPreconditions
  unfold evaluateBlockIndexReloadRejection
  by_cases checks_ok : firstReject (orderedChecks input) = none
  · have all_ok : allChecks (orderedChecks input) = true :=
      (first_reject_none_iff_all_checks).mp checks_ok
    simp [checks_ok, all_ok, genesisMarkerPrecondition]
    cases input.genesisMarkerPresent <;>
      cases input.genesisMarkerLengthValid <;>
      cases input.genesisMarkerMatchesExpected <;>
      simp
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

def valid : BlockIndexReloadInput :=
  {
    chainReconstructed := true,
    chainNonempty := true,
    genesisMatchesExpected := true,
    bestMetadataMatchesChain := true,
    canonicalHeightsContiguous := true,
    canonicalChainIdsMatch := true,
    canonicalRulesHashesMatch := true,
    canonicalHashesMatchWorkHashes := true,
    canonicalParentHashesContiguous := true,
    heightKeysWellFormed := true,
    heightValuesWellFormed := true,
    noExtraHeightIndexes := true,
    heightIndexHeightsMatchChain := true,
    heightIndexHashesMatchChain := true,
    allCanonicalHeightsIndexed := true,
    genesisMarkerPresent := true,
    genesisMarkerLengthValid := true,
    genesisMarkerMatchesExpected := true
  }

theorem valid_accepts :
    evaluateBlockIndexReloadRejection valid = none := by
  decide

def missingGenesisMarker : BlockIndexReloadInput :=
  { valid with
    genesisMarkerPresent := false
    genesisMarkerLengthValid := false
    genesisMarkerMatchesExpected := false }

theorem missing_genesis_marker_accepts_and_repairs :
    evaluateBlockIndexReloadRejection missingGenesisMarker = none
      ∧ blockIndexReloadRepairsGenesisMarker missingGenesisMarker = true := by
  decide

def chainReconstructionFailed : BlockIndexReloadInput :=
  { valid with chainReconstructed := false }

theorem chain_reconstruction_failure_rejects :
    evaluateBlockIndexReloadRejection chainReconstructionFailed =
      some BlockIndexReloadReject.chainReconstructionFailed := by
  decide

def chainEmpty : BlockIndexReloadInput :=
  { valid with chainNonempty := false }

theorem chain_empty_rejects :
    evaluateBlockIndexReloadRejection chainEmpty =
      some BlockIndexReloadReject.chainEmpty := by
  decide

def genesisMismatch : BlockIndexReloadInput :=
  { valid with genesisMatchesExpected := false }

theorem genesis_mismatch_rejects :
    evaluateBlockIndexReloadRejection genesisMismatch =
      some BlockIndexReloadReject.genesisMismatch := by
  decide

def bestMetadataMismatch : BlockIndexReloadInput :=
  { valid with bestMetadataMatchesChain := false }

theorem best_metadata_mismatch_rejects :
    evaluateBlockIndexReloadRejection bestMetadataMismatch =
      some BlockIndexReloadReject.bestMetadataMismatch := by
  decide

def canonicalHeightMismatch : BlockIndexReloadInput :=
  { valid with canonicalHeightsContiguous := false }

theorem canonical_height_mismatch_rejects :
    evaluateBlockIndexReloadRejection canonicalHeightMismatch =
      some BlockIndexReloadReject.canonicalHeightMismatch := by
  decide

def chainIdMismatch : BlockIndexReloadInput :=
  { valid with canonicalChainIdsMatch := false }

theorem chain_id_mismatch_rejects :
    evaluateBlockIndexReloadRejection chainIdMismatch =
      some BlockIndexReloadReject.chainIdMismatch := by
  decide

def rulesHashMismatch : BlockIndexReloadInput :=
  { valid with canonicalRulesHashesMatch := false }

theorem rules_hash_mismatch_rejects :
    evaluateBlockIndexReloadRejection rulesHashMismatch =
      some BlockIndexReloadReject.rulesHashMismatch := by
  decide

def hashWorkHashMismatch : BlockIndexReloadInput :=
  { valid with canonicalHashesMatchWorkHashes := false }

theorem hash_work_hash_mismatch_rejects :
    evaluateBlockIndexReloadRejection hashWorkHashMismatch =
      some BlockIndexReloadReject.hashWorkHashMismatch := by
  decide

def parentHashMismatch : BlockIndexReloadInput :=
  { valid with canonicalParentHashesContiguous := false }

theorem parent_hash_mismatch_rejects :
    evaluateBlockIndexReloadRejection parentHashMismatch =
      some BlockIndexReloadReject.parentHashMismatch := by
  decide

def malformedHeightKey : BlockIndexReloadInput :=
  { valid with heightKeysWellFormed := false }

theorem malformed_height_key_rejects :
    evaluateBlockIndexReloadRejection malformedHeightKey =
      some BlockIndexReloadReject.malformedHeightKey := by
  decide

def malformedHeightValue : BlockIndexReloadInput :=
  { valid with heightValuesWellFormed := false }

theorem malformed_height_value_rejects :
    evaluateBlockIndexReloadRejection malformedHeightValue =
      some BlockIndexReloadReject.malformedHeightValue := by
  decide

def extraHeightIndex : BlockIndexReloadInput :=
  { valid with noExtraHeightIndexes := false }

theorem extra_height_index_rejects :
    evaluateBlockIndexReloadRejection extraHeightIndex =
      some BlockIndexReloadReject.extraHeightIndex := by
  decide

def heightIndexMismatch : BlockIndexReloadInput :=
  { valid with heightIndexHeightsMatchChain := false }

theorem height_index_mismatch_rejects :
    evaluateBlockIndexReloadRejection heightIndexMismatch =
      some BlockIndexReloadReject.heightIndexMismatch := by
  decide

def heightHashMismatch : BlockIndexReloadInput :=
  { valid with heightIndexHashesMatchChain := false }

theorem height_hash_mismatch_rejects :
    evaluateBlockIndexReloadRejection heightHashMismatch =
      some BlockIndexReloadReject.heightHashMismatch := by
  decide

def missingHeightIndex : BlockIndexReloadInput :=
  { valid with allCanonicalHeightsIndexed := false }

theorem missing_height_index_rejects :
    evaluateBlockIndexReloadRejection missingHeightIndex =
      some BlockIndexReloadReject.missingHeightIndex := by
  decide

def genesisMarkerInvalidLength : BlockIndexReloadInput :=
  { valid with genesisMarkerLengthValid := false }

theorem genesis_marker_invalid_length_rejects :
    evaluateBlockIndexReloadRejection genesisMarkerInvalidLength =
      some BlockIndexReloadReject.genesisMarkerInvalidLength := by
  decide

def genesisMarkerMismatch : BlockIndexReloadInput :=
  { valid with genesisMarkerMatchesExpected := false }

theorem genesis_marker_mismatch_rejects :
    evaluateBlockIndexReloadRejection genesisMarkerMismatch =
      some BlockIndexReloadReject.genesisMarkerMismatch := by
  decide

def genesis_precedes_best_mismatch_input : BlockIndexReloadInput :=
  { valid with
    genesisMatchesExpected := false
    bestMetadataMatchesChain := false }

theorem genesis_precedes_best_mismatch :
    evaluateBlockIndexReloadRejection genesis_precedes_best_mismatch_input =
      some BlockIndexReloadReject.genesisMismatch := by
  decide

def malformed_key_precedes_extra_height_input : BlockIndexReloadInput :=
  { valid with
    heightKeysWellFormed := false
    noExtraHeightIndexes := false }

theorem malformed_key_precedes_extra_height :
    evaluateBlockIndexReloadRejection malformed_key_precedes_extra_height_input =
      some BlockIndexReloadReject.malformedHeightKey := by
  decide

def malformed_value_precedes_height_hash_input : BlockIndexReloadInput :=
  { valid with
    heightValuesWellFormed := false
    heightIndexHashesMatchChain := false }

theorem malformed_value_precedes_height_hash :
    evaluateBlockIndexReloadRejection malformed_value_precedes_height_hash_input =
      some BlockIndexReloadReject.malformedHeightValue := by
  decide

def marker_length_precedes_marker_mismatch_input : BlockIndexReloadInput :=
  { valid with
    genesisMarkerLengthValid := false
    genesisMarkerMatchesExpected := false }

theorem marker_length_precedes_marker_mismatch :
    evaluateBlockIndexReloadRejection marker_length_precedes_marker_mismatch_input =
      some BlockIndexReloadReject.genesisMarkerInvalidLength := by
  decide

end BlockIndexReload
end Native
end Hegemon

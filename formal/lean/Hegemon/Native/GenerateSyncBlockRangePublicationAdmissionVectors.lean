import Hegemon.Native.SyncBlockRangePublicationAdmission

open Hegemon.Native.SyncBlockRangePublicationAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option SyncBlockRangePublicationReject -> String
  | none => "null"
  | some SyncBlockRangePublicationReject.rangeNotAdmitted =>
      "\"range_not_admitted\""
  | some SyncBlockRangePublicationReject.servedCountMismatch =>
      "\"served_count_mismatch\""
  | some SyncBlockRangePublicationReject.firstHeightMismatch =>
      "\"first_height_mismatch\""
  | some SyncBlockRangePublicationReject.lastHeightMismatch =>
      "\"last_height_mismatch\""
  | some SyncBlockRangePublicationReject.heightContinuityMismatch =>
      "\"height_continuity_mismatch\""
  | some SyncBlockRangePublicationReject.parentHashMismatch =>
      "\"parent_hash_mismatch\""
  | some SyncBlockRangePublicationReject.canonicalRowsUnverified =>
      "\"canonical_rows_unverified\""
  | some SyncBlockRangePublicationReject.actionBodiesUnverified =>
      "\"action_bodies_unverified\""

def syncBlockRangePublicationCaseJson
    (name : String)
    (input : SyncBlockRangePublicationInput) : String :=
  let result := evaluateSyncBlockRangePublication input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"range_admitted\": " ++ boolJson input.rangeAdmitted ++ ",\n"
    ++ "      \"served_count_matches_range\": "
      ++ boolJson input.servedCountMatchesRange ++ ",\n"
    ++ "      \"first_height_matches_range\": "
      ++ boolJson input.firstHeightMatchesRange ++ ",\n"
    ++ "      \"last_height_matches_range\": "
      ++ boolJson input.lastHeightMatchesRange ++ ",\n"
    ++ "      \"served_heights_contiguous\": "
      ++ boolJson input.servedHeightsContiguous ++ ",\n"
    ++ "      \"previous_parent_anchor_verified\": "
      ++ boolJson input.previousParentAnchorVerified ++ ",\n"
    ++ "      \"parent_hashes_contiguous\": "
      ++ boolJson input.parentHashesContiguous ++ ",\n"
    ++ "      \"canonical_rows_verified\": "
      ++ boolJson input.canonicalRowsVerified ++ ",\n"
    ++ "      \"action_bodies_verified\": "
      ++ boolJson input.actionBodiesVerified ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"sync_block_range_publication_cases\": [\n"
    ++ syncBlockRangePublicationCaseJson
      "valid-sync-block-range-publication" valid ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "range-not-admitted-rejected" rangeNotAdmitted ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "served-count-mismatch-rejected" servedCountMismatch ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "first-height-mismatch-rejected" firstHeightMismatch ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "last-height-mismatch-rejected" lastHeightMismatch ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "height-continuity-mismatch-rejected" heightContinuityMismatch ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "previous-parent-anchor-mismatch-rejected"
      previousParentAnchorMismatch ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "parent-hash-mismatch-rejected" parentHashMismatch ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "canonical-rows-unverified-rejected" canonicalRowsUnverified ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "action-bodies-unverified-rejected" actionBodiesUnverified ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "served-count-precedes-height-mismatch" countPrecedesHeightMismatch ++ ",\n"
    ++ syncBlockRangePublicationCaseJson
      "parent-hash-precedes-verification-mismatch"
      parentPrecedesVerificationMismatch ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

import Hegemon.Privacy.CiphertextArchiveBoundary

open Hegemon.Privacy.CiphertextArchiveBoundary

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CiphertextArchiveBoundaryRejection -> String
  | none => "null"
  | some CiphertextArchiveBoundaryRejection.indexGap => "\"index_gap\""
  | some CiphertextArchiveBoundaryRejection.indexBeyondLeafCount =>
      "\"index_beyond_leaf_count\""

def walletPageRejectionJson : Option WalletPageAdmissionRejection -> String
  | none => "null"
  | some WalletPageAdmissionRejection.pageTooLarge => "\"page_too_large\""

def walletSyncSnapshotRejectionJson :
    Option WalletSyncSnapshotAdmissionRejection -> String
  | none => "null"
  | some WalletSyncSnapshotAdmissionRejection.depthMismatch =>
      "\"depth_mismatch\""
  | some WalletSyncSnapshotAdmissionRejection.leafCountExceedsTreeCapacity =>
      "\"leaf_count_exceeds_tree_capacity\""
  | some WalletSyncSnapshotAdmissionRejection.ciphertextIndexExceedsTreeCapacity =>
      "\"ciphertext_index_exceeds_tree_capacity\""
  | some WalletSyncSnapshotAdmissionRejection.commitmentSnapshotTooLarge =>
      "\"commitment_snapshot_too_large\""
  | some WalletSyncSnapshotAdmissionRejection.ciphertextSnapshotTooLarge =>
      "\"ciphertext_snapshot_too_large\""

def natArrayJson : List Nat -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ rest.foldl
        (fun acc value => acc ++ ", " ++ toString value)
        (toString first) ++ "]"

def caseJson (case : CiphertextArchiveBoundaryCase) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ case.name ++ "\",\n"
    ++ "      \"leaf_count\": " ++ toString case.leafCount ++ ",\n"
    ++ "      \"archive_indices\": " ++ natArrayJson case.archiveIndices ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (accepts case) ++ ",\n"
    ++ "      \"expected_error\": " ++ rejectionJson (firstRejection case) ++ "\n"
    ++ "    }"

def walletPageCaseJson (case : WalletPageAdmissionCase) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ case.name ++ "\",\n"
    ++ "      \"requested_limit\": " ++ toString case.requestedLimit ++ ",\n"
    ++ "      \"returned_entries\": " ++ toString case.returnedEntries ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (walletPageAccepts case) ++ ",\n"
      ++ "      \"expected_error\": " ++ walletPageRejectionJson (walletPageRejection case) ++ "\n"
      ++ "    }"

def walletSyncSnapshotCaseJson (case : WalletSyncSnapshotAdmissionCase) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ case.name ++ "\",\n"
    ++ "      \"expected_depth\": " ++ toString case.expectedDepth ++ ",\n"
    ++ "      \"depth\": " ++ toString case.depth ++ ",\n"
    ++ "      \"leaf_count\": " ++ toString case.leafCount ++ ",\n"
    ++ "      \"next_index\": " ++ toString case.nextIndex ++ ",\n"
    ++ "      \"commitment_cursor\": " ++ toString case.commitmentCursor ++ ",\n"
    ++ "      \"ciphertext_cursor\": " ++ toString case.ciphertextCursor ++ ",\n"
    ++ "      \"tree_capacity\": " ++ toString case.treeCapacity ++ ",\n"
    ++ "      \"max_snapshot_gap\": " ++ toString case.maxSnapshotGap ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (walletSyncSnapshotAccepts case) ++ ",\n"
    ++ "      \"expected_error\": "
      ++ walletSyncSnapshotRejectionJson (walletSyncSnapshotRejection case) ++ "\n"
    ++ "    }"

def casesJson : List CiphertextArchiveBoundaryCase -> String
  | [] => ""
  | [case] => caseJson case
  | case :: rest => caseJson case ++ ",\n" ++ casesJson rest

def walletPageCasesJson : List WalletPageAdmissionCase -> String
  | [] => ""
  | [case] => walletPageCaseJson case
  | case :: rest => walletPageCaseJson case ++ ",\n" ++ walletPageCasesJson rest

def walletSyncSnapshotCasesJson : List WalletSyncSnapshotAdmissionCase -> String
  | [] => ""
  | [case] => walletSyncSnapshotCaseJson case
  | case :: rest =>
      walletSyncSnapshotCaseJson case ++ ",\n"
        ++ walletSyncSnapshotCasesJson rest

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"ciphertext_archive_boundary_cases\": [\n"
    ++ casesJson allCases ++ "\n"
    ++ "  ],\n"
      ++ "  \"wallet_page_admission_cases\": [\n"
      ++ walletPageCasesJson walletPageCases ++ "\n"
      ++ "  ],\n"
      ++ "  \"wallet_sync_snapshot_admission_cases\": [\n"
      ++ walletSyncSnapshotCasesJson walletSyncSnapshotCases ++ "\n"
      ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

import Hegemon.Native.AtomicCommitManifestAdmission

open Hegemon.Native.AtomicCommitManifestAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def kindJson : AtomicCommitKind -> String
  | AtomicCommitKind.minedBlockCommit => "\"mined_block_commit\""
  | AtomicCommitKind.canonicalReorgCommit => "\"canonical_reorg_commit\""
  | AtomicCommitKind.canonicalIndexRepair => "\"canonical_index_repair\""
  | AtomicCommitKind.noncanonicalBlockRecord => "\"noncanonical_block_record\""

def rejectionJson : Option AtomicCommitManifestReject -> String
  | none => "null"
  | some AtomicCommitManifestReject.minedPlanLengthMismatch =>
      "\"mined_plan_length_mismatch\""
  | some AtomicCommitManifestReject.blockRecordWritesMismatch =>
      "\"block_record_writes_mismatch\""
  | some AtomicCommitManifestReject.heightIndexWritesMismatch =>
      "\"height_index_writes_mismatch\""
  | some AtomicCommitManifestReject.bestPointerWritesMismatch =>
      "\"best_pointer_writes_mismatch\""
  | some AtomicCommitManifestReject.canonicalIndexClearMismatch =>
      "\"canonical_index_clear_mismatch\""
  | some AtomicCommitManifestReject.pendingTreeClearMismatch =>
      "\"pending_tree_clear_mismatch\""
  | some AtomicCommitManifestReject.pendingActionRemovalMismatch =>
      "\"pending_action_removal_mismatch\""
  | some AtomicCommitManifestReject.pendingActionWriteMismatch =>
      "\"pending_action_write_mismatch\""
  | some AtomicCommitManifestReject.commitmentWriteMismatch =>
      "\"commitment_write_mismatch\""
  | some AtomicCommitManifestReject.nullifierWriteMismatch =>
      "\"nullifier_write_mismatch\""
  | some AtomicCommitManifestReject.bridgeReplayWriteMismatch =>
      "\"bridge_replay_write_mismatch\""
  | some AtomicCommitManifestReject.ciphertextIndexWriteMismatch =>
      "\"ciphertext_index_write_mismatch\""
  | some AtomicCommitManifestReject.ciphertextArchiveWriteMismatch =>
      "\"ciphertext_archive_write_mismatch\""
  | some AtomicCommitManifestReject.stagedCiphertextRemovalMismatch =>
      "\"staged_ciphertext_removal_mismatch\""

def natJson (value : Nat) : String :=
  toString value

def caseJson (name : String) (input : AtomicCommitManifestInput) : String :=
  let result := evaluateAtomicCommitManifestRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": " ++ kindJson input.kind ++ ",\n"
    ++ "      \"action_count\": " ++ natJson input.actionCount ++ ",\n"
    ++ "      \"planned_action_count\": " ++ natJson input.plannedActionCount ++ ",\n"
    ++ "      \"chain_block_count\": " ++ natJson input.chainBlockCount ++ ",\n"
    ++ "      \"height_entry_count\": " ++ natJson input.heightEntryCount ++ ",\n"
    ++ "      \"pending_entry_count\": " ++ natJson input.pendingEntryCount ++ ",\n"
    ++ "      \"source_commitment_count\": " ++ natJson input.sourceCommitmentCount ++ ",\n"
    ++ "      \"source_nullifier_count\": " ++ natJson input.sourceNullifierCount ++ ",\n"
    ++ "      \"source_bridge_replay_count\": " ++ natJson input.sourceBridgeReplayCount ++ ",\n"
    ++ "      \"source_ciphertext_index_count\": " ++ natJson input.sourceCiphertextIndexCount ++ ",\n"
    ++ "      \"source_ciphertext_archive_count\": " ++ natJson input.sourceCiphertextArchiveCount ++ ",\n"
    ++ "      \"source_staged_ciphertext_removal_count\": " ++ natJson input.sourceStagedCiphertextRemovalCount ++ ",\n"
    ++ "      \"block_record_writes\": " ++ natJson input.blockRecordWrites ++ ",\n"
    ++ "      \"height_index_writes\": " ++ natJson input.heightIndexWrites ++ ",\n"
    ++ "      \"best_pointer_writes\": " ++ natJson input.bestPointerWrites ++ ",\n"
    ++ "      \"canonical_index_cleared\": " ++ boolJson input.canonicalIndexCleared ++ ",\n"
    ++ "      \"pending_tree_cleared\": " ++ boolJson input.pendingTreeCleared ++ ",\n"
    ++ "      \"pending_action_removals\": " ++ natJson input.pendingActionRemovals ++ ",\n"
    ++ "      \"pending_action_writes\": " ++ natJson input.pendingActionWrites ++ ",\n"
    ++ "      \"commitment_writes\": " ++ natJson input.commitmentWrites ++ ",\n"
    ++ "      \"nullifier_writes\": " ++ natJson input.nullifierWrites ++ ",\n"
    ++ "      \"bridge_replay_writes\": " ++ natJson input.bridgeReplayWrites ++ ",\n"
    ++ "      \"ciphertext_index_writes\": " ++ natJson input.ciphertextIndexWrites ++ ",\n"
    ++ "      \"ciphertext_archive_writes\": " ++ natJson input.ciphertextArchiveWrites ++ ",\n"
    ++ "      \"staged_ciphertext_removals\": " ++ natJson input.stagedCiphertextRemovals ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"atomic_commit_manifest_admission_cases\": [\n"
    ++ caseJson "valid-mined-block-commit" validMinedBlockCommit ++ ",\n"
    ++ caseJson "valid-canonical-reorg-commit" validCanonicalReorgCommit ++ ",\n"
    ++ caseJson "valid-canonical-index-repair" validCanonicalIndexRepair ++ ",\n"
    ++ caseJson "valid-noncanonical-block-record" validNoncanonicalBlockRecord ++ ",\n"
    ++ caseJson "mined-plan-length-mismatch-rejected"
      { validMinedBlockCommit with plannedActionCount := 1 } ++ ",\n"
    ++ caseJson "block-record-write-mismatch-rejected"
      { validMinedBlockCommit with blockRecordWrites := 0 } ++ ",\n"
    ++ caseJson "height-index-write-mismatch-rejected"
      { validMinedBlockCommit with heightIndexWrites := 0 } ++ ",\n"
    ++ caseJson "best-pointer-write-mismatch-rejected"
      { validMinedBlockCommit with bestPointerWrites := 0 } ++ ",\n"
    ++ caseJson "canonical-index-clear-mismatch-rejected"
      { validCanonicalReorgCommit with canonicalIndexCleared := false } ++ ",\n"
    ++ caseJson "pending-tree-clear-mismatch-rejected"
      { validCanonicalReorgCommit with pendingTreeCleared := false } ++ ",\n"
    ++ caseJson "pending-action-removal-mismatch-rejected"
      { validMinedBlockCommit with pendingActionRemovals := 1 } ++ ",\n"
    ++ caseJson "pending-action-write-mismatch-rejected"
      { validCanonicalReorgCommit with pendingActionWrites := 0 } ++ ",\n"
    ++ caseJson "commitment-write-mismatch-rejected"
      { validMinedBlockCommit with commitmentWrites := 2 } ++ ",\n"
    ++ caseJson "nullifier-write-mismatch-rejected"
      { validMinedBlockCommit with nullifierWrites := 1 } ++ ",\n"
    ++ caseJson "bridge-replay-write-mismatch-rejected"
      { validMinedBlockCommit with bridgeReplayWrites := 0 } ++ ",\n"
    ++ caseJson "ciphertext-index-write-mismatch-rejected"
      { validMinedBlockCommit with ciphertextIndexWrites := 2 } ++ ",\n"
    ++ caseJson "ciphertext-archive-write-mismatch-rejected"
      { validMinedBlockCommit with ciphertextArchiveWrites := 2 } ++ ",\n"
    ++ caseJson "staged-ciphertext-removal-mismatch-rejected"
      { validMinedBlockCommit with stagedCiphertextRemovals := 2 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

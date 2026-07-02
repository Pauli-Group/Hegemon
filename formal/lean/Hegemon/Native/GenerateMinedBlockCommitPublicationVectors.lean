import Hegemon.Native.MinedBlockCommitPublication

open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockCommitmentAdmission
open Hegemon.Native.MinedBlockCommitPublication
open Hegemon.Native.MinedWorkAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def kindJson : AtomicCommitKind -> String
  | AtomicCommitKind.minedBlockCommit => "\"mined_block_commit\""
  | AtomicCommitKind.canonicalReorgCommit => "\"canonical_reorg_commit\""
  | AtomicCommitKind.canonicalIndexRepair => "\"canonical_index_repair\""
  | AtomicCommitKind.noncanonicalBlockRecord =>
      "\"noncanonical_block_record\""

def rejectionJson :
    Option MinedBlockCommitPublicationReject -> String
  | none => "null"
  | some MinedBlockCommitPublicationReject.minedWorkRejected =>
      "\"mined_work_rejected\""
  | some MinedBlockCommitPublicationReject.blockCommitmentRejected =>
      "\"block_commitment_rejected\""
  | some MinedBlockCommitPublicationReject.commitKindMismatch =>
      "\"commit_kind_mismatch\""
  | some MinedBlockCommitPublicationReject.commitManifestRejected =>
      "\"commit_manifest_rejected\""

def minedWorkJson (input : MinedWorkInput) : String :=
  "      \"best_height\": " ++ toString input.bestHeight ++ ",\n"
    ++ "      \"work_height\": " ++ toString input.workHeight ++ ",\n"
    ++ "      \"parent_hash_matches\": "
    ++ boolJson input.parentHashMatches ++ ",\n"

def blockCommitmentJson (input : CommitmentInput) : String :=
  "      \"tx_count_matches\": " ++ boolJson input.txCountMatches ++ ",\n"
    ++ "      \"state_root_matches\": "
    ++ boolJson input.stateRootMatches ++ ",\n"
    ++ "      \"kernel_root_matches\": "
    ++ boolJson input.kernelRootMatches ++ ",\n"
    ++ "      \"nullifier_root_matches\": "
    ++ boolJson input.nullifierRootMatches ++ ",\n"
    ++ "      \"extrinsics_root_matches\": "
    ++ boolJson input.extrinsicsRootMatches ++ ",\n"
    ++ "      \"message_root_matches\": "
    ++ boolJson input.messageRootMatches ++ ",\n"
    ++ "      \"message_count_matches\": "
    ++ boolJson input.messageCountMatches ++ ",\n"
    ++ "      \"header_mmr_root_matches\": "
    ++ boolJson input.headerMmrRootMatches ++ ",\n"
    ++ "      \"header_mmr_len_matches\": "
    ++ boolJson input.headerMmrLenMatches ++ ",\n"
    ++ "      \"supply_digest_matches\": "
    ++ boolJson input.supplyDigestMatches ++ ",\n"

def manifestJson (input : AtomicCommitManifestInput) : String :=
  "      \"commit_kind\": " ++ kindJson input.kind ++ ",\n"
    ++ "      \"action_count\": " ++ toString input.actionCount ++ ",\n"
    ++ "      \"planned_action_count\": "
    ++ toString input.plannedActionCount ++ ",\n"
    ++ "      \"chain_block_count\": "
    ++ toString input.chainBlockCount ++ ",\n"
    ++ "      \"height_entry_count\": "
    ++ toString input.heightEntryCount ++ ",\n"
    ++ "      \"pending_entry_count\": "
    ++ toString input.pendingEntryCount ++ ",\n"
    ++ "      \"source_commitment_count\": "
    ++ toString input.sourceCommitmentCount ++ ",\n"
    ++ "      \"source_nullifier_count\": "
    ++ toString input.sourceNullifierCount ++ ",\n"
    ++ "      \"source_bridge_replay_count\": "
    ++ toString input.sourceBridgeReplayCount ++ ",\n"
    ++ "      \"source_ciphertext_index_count\": "
    ++ toString input.sourceCiphertextIndexCount ++ ",\n"
    ++ "      \"source_ciphertext_archive_count\": "
    ++ toString input.sourceCiphertextArchiveCount ++ ",\n"
    ++ "      \"source_staged_ciphertext_removal_count\": "
    ++ toString input.sourceStagedCiphertextRemovalCount ++ ",\n"
    ++ "      \"block_record_writes\": "
    ++ toString input.blockRecordWrites ++ ",\n"
    ++ "      \"height_index_writes\": "
    ++ toString input.heightIndexWrites ++ ",\n"
    ++ "      \"best_pointer_writes\": "
    ++ toString input.bestPointerWrites ++ ",\n"
    ++ "      \"canonical_index_cleared\": "
    ++ boolJson input.canonicalIndexCleared ++ ",\n"
    ++ "      \"pending_tree_cleared\": "
    ++ boolJson input.pendingTreeCleared ++ ",\n"
    ++ "      \"pending_action_removals\": "
    ++ toString input.pendingActionRemovals ++ ",\n"
    ++ "      \"pending_action_writes\": "
    ++ toString input.pendingActionWrites ++ ",\n"
    ++ "      \"commitment_writes\": "
    ++ toString input.commitmentWrites ++ ",\n"
    ++ "      \"nullifier_writes\": "
    ++ toString input.nullifierWrites ++ ",\n"
    ++ "      \"bridge_replay_writes\": "
    ++ toString input.bridgeReplayWrites ++ ",\n"
    ++ "      \"ciphertext_index_writes\": "
    ++ toString input.ciphertextIndexWrites ++ ",\n"
    ++ "      \"ciphertext_archive_writes\": "
    ++ toString input.ciphertextArchiveWrites ++ ",\n"
    ++ "      \"staged_ciphertext_removals\": "
    ++ toString input.stagedCiphertextRemovals ++ ",\n"

def publicationCaseJson
    (name : String)
    (input : MinedBlockCommitPublicationInput) : String :=
  let rejection := evaluateMinedBlockCommitPublicationRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ minedWorkJson input.minedWork
    ++ blockCommitmentJson input.blockCommitment
    ++ manifestJson input.commitManifest
    ++ "      \"expected_valid\": "
    ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": "
    ++ rejectionJson rejection ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"mined_block_commit_publication_cases\": [\n"
    ++ publicationCaseJson
      "valid-mined-block-commit-publication"
      validMinedBlockCommitPublication ++ ",\n"
    ++ publicationCaseJson
      "max-height-predecessor-valid-publication"
      { validMinedBlockCommitPublication with
        minedWork := maxPredecessorAcceptsMaxHeight } ++ ",\n"
    ++ publicationCaseJson
      "mined-work-rejects-before-block-commitment"
      { validMinedBlockCommitPublication with
        minedWork := parentMismatch,
        blockCommitment :=
          { Hegemon.Native.BlockCommitmentAdmission.valid with
            txCountMatches := false } } ++ ",\n"
    ++ publicationCaseJson
      "mined-work-height-overflow-rejected"
      { validMinedBlockCommitPublication with
        minedWork := heightOverflow } ++ ",\n"
    ++ publicationCaseJson
      "block-commitment-rejects-before-commit-kind"
      { validMinedBlockCommitPublication with
        blockCommitment :=
          { Hegemon.Native.BlockCommitmentAdmission.valid with
            supplyDigestMatches := false },
        commitManifest := validCanonicalReorgCommit } ++ ",\n"
    ++ publicationCaseJson
      "commit-kind-mismatch-rejected"
      { validMinedBlockCommitPublication with
        commitManifest := validCanonicalReorgCommit } ++ ",\n"
    ++ publicationCaseJson
      "commit-kind-rejects-before-manifest-shape"
      { validMinedBlockCommitPublication with
        commitManifest :=
          { validCanonicalReorgCommit with
            blockRecordWrites := 0 } } ++ ",\n"
    ++ publicationCaseJson
      "commit-manifest-rejected-after-mined-kind"
      { validMinedBlockCommitPublication with
        commitManifest :=
          { validMinedBlockCommit with
            pendingActionRemovals := 0 } } ++ ",\n"
    ++ publicationCaseJson
      "mined-plan-length-rejected-after-commit-kind"
      { validMinedBlockCommitPublication with
        commitManifest :=
          { validMinedBlockCommit with
            plannedActionCount := 1 } } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

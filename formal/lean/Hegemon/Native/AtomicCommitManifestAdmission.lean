namespace Hegemon
namespace Native
namespace AtomicCommitManifestAdmission

inductive AtomicCommitKind where
  | minedBlockCommit
  | canonicalReorgCommit
  | canonicalIndexRepair
  | noncanonicalBlockRecord
deriving DecidableEq, Repr

inductive AtomicCommitManifestReject where
  | minedPlanLengthMismatch
  | blockRecordWritesMismatch
  | heightIndexWritesMismatch
  | bestPointerWritesMismatch
  | canonicalIndexClearMismatch
  | pendingTreeClearMismatch
  | pendingActionRemovalMismatch
  | pendingActionWriteMismatch
  | commitmentWriteMismatch
  | nullifierWriteMismatch
  | bridgeReplayWriteMismatch
  | ciphertextIndexWriteMismatch
  | ciphertextArchiveWriteMismatch
  | stagedCiphertextRemovalMismatch
deriving DecidableEq, Repr

structure AtomicCommitManifestInput where
  kind : AtomicCommitKind
  actionCount : Nat
  plannedActionCount : Nat
  chainBlockCount : Nat
  heightEntryCount : Nat
  pendingEntryCount : Nat
  sourceCommitmentCount : Nat
  sourceNullifierCount : Nat
  sourceBridgeReplayCount : Nat
  sourceCiphertextIndexCount : Nat
  sourceCiphertextArchiveCount : Nat
  sourceStagedCiphertextRemovalCount : Nat
  blockRecordWrites : Nat
  heightIndexWrites : Nat
  bestPointerWrites : Nat
  canonicalIndexCleared : Bool
  pendingTreeCleared : Bool
  pendingActionRemovals : Nat
  pendingActionWrites : Nat
  commitmentWrites : Nat
  nullifierWrites : Nat
  bridgeReplayWrites : Nat
  ciphertextIndexWrites : Nat
  ciphertextArchiveWrites : Nat
  stagedCiphertextRemovals : Nat
deriving DecidableEq, Repr

def expectedBlockRecordWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => 1
  | AtomicCommitKind.canonicalReorgCommit => input.chainBlockCount
  | AtomicCommitKind.canonicalIndexRepair => 0
  | AtomicCommitKind.noncanonicalBlockRecord => 1

def expectedHeightIndexWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => 1
  | AtomicCommitKind.canonicalReorgCommit => input.heightEntryCount
  | AtomicCommitKind.canonicalIndexRepair => 0
  | AtomicCommitKind.noncanonicalBlockRecord => 0

def expectedBestPointerWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => 1
  | AtomicCommitKind.canonicalReorgCommit => 1
  | AtomicCommitKind.canonicalIndexRepair => 0
  | AtomicCommitKind.noncanonicalBlockRecord => 0

def expectedCanonicalIndexCleared (input : AtomicCommitManifestInput) : Bool :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => false
  | AtomicCommitKind.canonicalReorgCommit => true
  | AtomicCommitKind.canonicalIndexRepair => true
  | AtomicCommitKind.noncanonicalBlockRecord => false

def expectedPendingTreeCleared (input : AtomicCommitManifestInput) : Bool :=
  match input.kind with
  | AtomicCommitKind.canonicalReorgCommit => true
  | _ => false

def expectedPendingActionRemovals (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => input.actionCount
  | _ => 0

def expectedPendingActionWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.canonicalReorgCommit => input.pendingEntryCount
  | _ => 0

def expectedCommitmentWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => input.sourceCommitmentCount
  | AtomicCommitKind.canonicalReorgCommit => input.sourceCommitmentCount
  | AtomicCommitKind.canonicalIndexRepair => input.sourceCommitmentCount
  | AtomicCommitKind.noncanonicalBlockRecord => 0

def expectedNullifierWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => input.sourceNullifierCount
  | AtomicCommitKind.canonicalReorgCommit => input.sourceNullifierCount
  | AtomicCommitKind.canonicalIndexRepair => input.sourceNullifierCount
  | AtomicCommitKind.noncanonicalBlockRecord => 0

def expectedBridgeReplayWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => input.sourceBridgeReplayCount
  | AtomicCommitKind.canonicalReorgCommit => input.sourceBridgeReplayCount
  | AtomicCommitKind.canonicalIndexRepair => input.sourceBridgeReplayCount
  | AtomicCommitKind.noncanonicalBlockRecord => 0

def expectedCiphertextIndexWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => input.sourceCiphertextIndexCount
  | AtomicCommitKind.canonicalReorgCommit => input.sourceCiphertextIndexCount
  | AtomicCommitKind.canonicalIndexRepair => input.sourceCiphertextIndexCount
  | AtomicCommitKind.noncanonicalBlockRecord => 0

def expectedCiphertextArchiveWrites (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => input.sourceCiphertextArchiveCount
  | AtomicCommitKind.canonicalReorgCommit => input.sourceCiphertextArchiveCount
  | AtomicCommitKind.canonicalIndexRepair => input.sourceCiphertextArchiveCount
  | AtomicCommitKind.noncanonicalBlockRecord => 0

def expectedStagedCiphertextRemovals (input : AtomicCommitManifestInput) : Nat :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => input.sourceStagedCiphertextRemovalCount
  | _ => 0

def minedPlanLengthMatches (input : AtomicCommitManifestInput) : Bool :=
  match input.kind with
  | AtomicCommitKind.minedBlockCommit => input.actionCount == input.plannedActionCount
  | _ => true

def blockRecordWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.blockRecordWrites == expectedBlockRecordWrites input

def heightIndexWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.heightIndexWrites == expectedHeightIndexWrites input

def bestPointerWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.bestPointerWrites == expectedBestPointerWrites input

def canonicalIndexClearMatches (input : AtomicCommitManifestInput) : Bool :=
  input.canonicalIndexCleared == expectedCanonicalIndexCleared input

def pendingTreeClearMatches (input : AtomicCommitManifestInput) : Bool :=
  input.pendingTreeCleared == expectedPendingTreeCleared input

def pendingActionRemovalsMatch (input : AtomicCommitManifestInput) : Bool :=
  input.pendingActionRemovals == expectedPendingActionRemovals input

def pendingActionWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.pendingActionWrites == expectedPendingActionWrites input

def commitmentWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.commitmentWrites == expectedCommitmentWrites input

def nullifierWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.nullifierWrites == expectedNullifierWrites input

def bridgeReplayWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.bridgeReplayWrites == expectedBridgeReplayWrites input

def ciphertextIndexWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.ciphertextIndexWrites == expectedCiphertextIndexWrites input

def ciphertextArchiveWritesMatch (input : AtomicCommitManifestInput) : Bool :=
  input.ciphertextArchiveWrites == expectedCiphertextArchiveWrites input

def stagedCiphertextRemovalsMatch (input : AtomicCommitManifestInput) : Bool :=
  input.stagedCiphertextRemovals == expectedStagedCiphertextRemovals input

def atomicCommitManifestPreconditions
    (input : AtomicCommitManifestInput) : Bool :=
  minedPlanLengthMatches input
    && blockRecordWritesMatch input
    && heightIndexWritesMatch input
    && bestPointerWritesMatch input
    && canonicalIndexClearMatches input
    && pendingTreeClearMatches input
    && pendingActionRemovalsMatch input
    && pendingActionWritesMatch input
    && commitmentWritesMatch input
    && nullifierWritesMatch input
    && bridgeReplayWritesMatch input
    && ciphertextIndexWritesMatch input
    && ciphertextArchiveWritesMatch input
    && stagedCiphertextRemovalsMatch input

def firstAtomicCommitManifestRejection
    (input : AtomicCommitManifestInput) : AtomicCommitManifestReject :=
  if minedPlanLengthMatches input = false then
    AtomicCommitManifestReject.minedPlanLengthMismatch
  else if blockRecordWritesMatch input = false then
    AtomicCommitManifestReject.blockRecordWritesMismatch
  else if heightIndexWritesMatch input = false then
    AtomicCommitManifestReject.heightIndexWritesMismatch
  else if bestPointerWritesMatch input = false then
    AtomicCommitManifestReject.bestPointerWritesMismatch
  else if canonicalIndexClearMatches input = false then
    AtomicCommitManifestReject.canonicalIndexClearMismatch
  else if pendingTreeClearMatches input = false then
    AtomicCommitManifestReject.pendingTreeClearMismatch
  else if pendingActionRemovalsMatch input = false then
    AtomicCommitManifestReject.pendingActionRemovalMismatch
  else if pendingActionWritesMatch input = false then
    AtomicCommitManifestReject.pendingActionWriteMismatch
  else if commitmentWritesMatch input = false then
    AtomicCommitManifestReject.commitmentWriteMismatch
  else if nullifierWritesMatch input = false then
    AtomicCommitManifestReject.nullifierWriteMismatch
  else if bridgeReplayWritesMatch input = false then
    AtomicCommitManifestReject.bridgeReplayWriteMismatch
  else if ciphertextIndexWritesMatch input = false then
    AtomicCommitManifestReject.ciphertextIndexWriteMismatch
  else if ciphertextArchiveWritesMatch input = false then
    AtomicCommitManifestReject.ciphertextArchiveWriteMismatch
  else if stagedCiphertextRemovalsMatch input = false then
    AtomicCommitManifestReject.stagedCiphertextRemovalMismatch
  else
    AtomicCommitManifestReject.stagedCiphertextRemovalMismatch

def evaluateAtomicCommitManifestRejection
    (input : AtomicCommitManifestInput) :
    Option AtomicCommitManifestReject :=
  if atomicCommitManifestPreconditions input then
    none
  else
    some (firstAtomicCommitManifestRejection input)

def atomicCommitManifestAccepts (input : AtomicCommitManifestInput) : Bool :=
  evaluateAtomicCommitManifestRejection input = none

theorem accepts_iff_atomic_commit_manifest_preconditions
    {input : AtomicCommitManifestInput} :
    atomicCommitManifestAccepts input = true ↔
      atomicCommitManifestPreconditions input = true := by
  by_cases h : atomicCommitManifestPreconditions input <;>
    simp [
      atomicCommitManifestAccepts,
      evaluateAtomicCommitManifestRejection,
      h
    ]

def validMinedBlockCommit : AtomicCommitManifestInput :=
  {
    kind := AtomicCommitKind.minedBlockCommit,
    actionCount := 2,
    plannedActionCount := 2,
    chainBlockCount := 0,
    heightEntryCount := 0,
    pendingEntryCount := 0,
    sourceCommitmentCount := 3,
    sourceNullifierCount := 2,
    sourceBridgeReplayCount := 1,
    sourceCiphertextIndexCount := 3,
    sourceCiphertextArchiveCount := 3,
    sourceStagedCiphertextRemovalCount := 3,
    blockRecordWrites := 1,
    heightIndexWrites := 1,
    bestPointerWrites := 1,
    canonicalIndexCleared := false,
    pendingTreeCleared := false,
    pendingActionRemovals := 2,
    pendingActionWrites := 0,
    commitmentWrites := 3,
    nullifierWrites := 2,
    bridgeReplayWrites := 1,
    ciphertextIndexWrites := 3,
    ciphertextArchiveWrites := 3,
    stagedCiphertextRemovals := 3
  }

def validCanonicalReorgCommit : AtomicCommitManifestInput :=
  {
    kind := AtomicCommitKind.canonicalReorgCommit,
    actionCount := 0,
    plannedActionCount := 0,
    chainBlockCount := 4,
    heightEntryCount := 4,
    pendingEntryCount := 1,
    sourceCommitmentCount := 5,
    sourceNullifierCount := 3,
    sourceBridgeReplayCount := 2,
    sourceCiphertextIndexCount := 5,
    sourceCiphertextArchiveCount := 5,
    sourceStagedCiphertextRemovalCount := 0,
    blockRecordWrites := 4,
    heightIndexWrites := 4,
    bestPointerWrites := 1,
    canonicalIndexCleared := true,
    pendingTreeCleared := true,
    pendingActionRemovals := 0,
    pendingActionWrites := 1,
    commitmentWrites := 5,
    nullifierWrites := 3,
    bridgeReplayWrites := 2,
    ciphertextIndexWrites := 5,
    ciphertextArchiveWrites := 5,
    stagedCiphertextRemovals := 0
  }

def validCanonicalIndexRepair : AtomicCommitManifestInput :=
  {
    validCanonicalReorgCommit with
    kind := AtomicCommitKind.canonicalIndexRepair,
    chainBlockCount := 0,
    heightEntryCount := 0,
    pendingEntryCount := 0,
    blockRecordWrites := 0,
    heightIndexWrites := 0,
    bestPointerWrites := 0,
    pendingTreeCleared := false,
    pendingActionWrites := 0
  }

def validNoncanonicalBlockRecord : AtomicCommitManifestInput :=
  {
    validMinedBlockCommit with
    kind := AtomicCommitKind.noncanonicalBlockRecord,
    actionCount := 0,
    plannedActionCount := 0,
    sourceCommitmentCount := 0,
    sourceNullifierCount := 0,
    sourceBridgeReplayCount := 0,
    sourceCiphertextIndexCount := 0,
    sourceCiphertextArchiveCount := 0,
    sourceStagedCiphertextRemovalCount := 0,
    heightIndexWrites := 0,
    bestPointerWrites := 0,
    pendingActionRemovals := 0,
    commitmentWrites := 0,
    nullifierWrites := 0,
    bridgeReplayWrites := 0,
    ciphertextIndexWrites := 0,
    ciphertextArchiveWrites := 0,
    stagedCiphertextRemovals := 0
  }

theorem valid_mined_block_commit_accepts :
    evaluateAtomicCommitManifestRejection validMinedBlockCommit = none := by
  rfl

theorem valid_canonical_reorg_commit_accepts :
    evaluateAtomicCommitManifestRejection validCanonicalReorgCommit = none := by
  rfl

theorem valid_canonical_index_repair_accepts :
    evaluateAtomicCommitManifestRejection validCanonicalIndexRepair = none := by
  rfl

theorem valid_noncanonical_block_record_accepts :
    evaluateAtomicCommitManifestRejection validNoncanonicalBlockRecord = none := by
  rfl

theorem rejects_mined_plan_length_mismatch :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with plannedActionCount := 1 } =
      some AtomicCommitManifestReject.minedPlanLengthMismatch := by
  rfl

theorem rejects_missing_block_record_write :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with blockRecordWrites := 0 } =
      some AtomicCommitManifestReject.blockRecordWritesMismatch := by
  rfl

theorem rejects_missing_height_index_write :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with heightIndexWrites := 0 } =
      some AtomicCommitManifestReject.heightIndexWritesMismatch := by
  rfl

theorem rejects_missing_best_pointer_write :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with bestPointerWrites := 0 } =
      some AtomicCommitManifestReject.bestPointerWritesMismatch := by
  rfl

theorem rejects_missing_canonical_index_clear :
    evaluateAtomicCommitManifestRejection
      { validCanonicalReorgCommit with canonicalIndexCleared := false } =
      some AtomicCommitManifestReject.canonicalIndexClearMismatch := by
  rfl

theorem rejects_missing_pending_tree_clear :
    evaluateAtomicCommitManifestRejection
      { validCanonicalReorgCommit with pendingTreeCleared := false } =
      some AtomicCommitManifestReject.pendingTreeClearMismatch := by
  rfl

theorem rejects_missing_pending_action_removal :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with pendingActionRemovals := 1 } =
      some AtomicCommitManifestReject.pendingActionRemovalMismatch := by
  rfl

theorem rejects_pending_action_write_mismatch :
    evaluateAtomicCommitManifestRejection
      { validCanonicalReorgCommit with pendingActionWrites := 0 } =
      some AtomicCommitManifestReject.pendingActionWriteMismatch := by
  rfl

theorem rejects_commitment_write_mismatch :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with commitmentWrites := 2 } =
      some AtomicCommitManifestReject.commitmentWriteMismatch := by
  rfl

theorem rejects_nullifier_write_mismatch :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with nullifierWrites := 1 } =
      some AtomicCommitManifestReject.nullifierWriteMismatch := by
  rfl

theorem rejects_bridge_replay_write_mismatch :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with bridgeReplayWrites := 0 } =
      some AtomicCommitManifestReject.bridgeReplayWriteMismatch := by
  rfl

theorem rejects_ciphertext_index_write_mismatch :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with ciphertextIndexWrites := 2 } =
      some AtomicCommitManifestReject.ciphertextIndexWriteMismatch := by
  rfl

theorem rejects_ciphertext_archive_write_mismatch :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with ciphertextArchiveWrites := 2 } =
      some AtomicCommitManifestReject.ciphertextArchiveWriteMismatch := by
  rfl

theorem rejects_staged_ciphertext_removal_mismatch :
    evaluateAtomicCommitManifestRejection
      { validMinedBlockCommit with stagedCiphertextRemovals := 2 } =
      some AtomicCommitManifestReject.stagedCiphertextRemovalMismatch := by
  rfl

end AtomicCommitManifestAdmission
end Native
end Hegemon

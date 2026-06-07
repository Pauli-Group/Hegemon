namespace Hegemon
namespace Native
namespace BlockCommitmentAdmission

inductive CommitmentReject where
  | txCountMismatch
  | stateRootMismatch
  | kernelRootMismatch
  | nullifierRootMismatch
  | extrinsicsRootMismatch
  | messageRootMismatch
  | messageCountMismatch
  | headerMmrRootMismatch
  | headerMmrLenMismatch
  | supplyDigestMismatch
deriving DecidableEq, Repr

structure CommitmentInput where
  txCountMatches : Bool
  stateRootMatches : Bool
  kernelRootMatches : Bool
  nullifierRootMatches : Bool
  extrinsicsRootMatches : Bool
  messageRootMatches : Bool
  messageCountMatches : Bool
  headerMmrRootMatches : Bool
  headerMmrLenMatches : Bool
  supplyDigestMatches : Bool
deriving DecidableEq, Repr

def evaluateCommitmentRejection (input : CommitmentInput) : Option CommitmentReject :=
  if input.txCountMatches = false then
    some CommitmentReject.txCountMismatch
  else if input.stateRootMatches = false then
    some CommitmentReject.stateRootMismatch
  else if input.kernelRootMatches = false then
    some CommitmentReject.kernelRootMismatch
  else if input.nullifierRootMatches = false then
    some CommitmentReject.nullifierRootMismatch
  else if input.extrinsicsRootMatches = false then
    some CommitmentReject.extrinsicsRootMismatch
  else if input.messageRootMatches = false then
    some CommitmentReject.messageRootMismatch
  else if input.messageCountMatches = false then
    some CommitmentReject.messageCountMismatch
  else if input.headerMmrRootMatches = false then
    some CommitmentReject.headerMmrRootMismatch
  else if input.headerMmrLenMatches = false then
    some CommitmentReject.headerMmrLenMismatch
  else if input.supplyDigestMatches = false then
    some CommitmentReject.supplyDigestMismatch
  else
    none

def commitmentAccepts (input : CommitmentInput) : Bool :=
  evaluateCommitmentRejection input = none

def commitmentPreconditions (input : CommitmentInput) : Bool :=
  input.txCountMatches
    && input.stateRootMatches
    && input.kernelRootMatches
    && input.nullifierRootMatches
    && input.extrinsicsRootMatches
    && input.messageRootMatches
    && input.messageCountMatches
    && input.headerMmrRootMatches
    && input.headerMmrLenMatches
    && input.supplyDigestMatches

theorem accepts_iff_commitment_preconditions
    {input : CommitmentInput} :
    commitmentAccepts input = true ↔ commitmentPreconditions input = true := by
  cases input with
  | mk txCountMatches stateRootMatches kernelRootMatches nullifierRootMatches
      extrinsicsRootMatches messageRootMatches messageCountMatches headerMmrRootMatches
      headerMmrLenMatches supplyDigestMatches =>
      cases txCountMatches <;>
        cases stateRootMatches <;>
        cases kernelRootMatches <;>
        cases nullifierRootMatches <;>
        cases extrinsicsRootMatches <;>
        cases messageRootMatches <;>
        cases messageCountMatches <;>
        cases headerMmrRootMatches <;>
        cases headerMmrLenMatches <;>
        cases supplyDigestMatches <;>
        simp [
          commitmentAccepts,
          commitmentPreconditions,
          evaluateCommitmentRejection
        ]

def valid : CommitmentInput :=
  {
    txCountMatches := true,
    stateRootMatches := true,
    kernelRootMatches := true,
    nullifierRootMatches := true,
    extrinsicsRootMatches := true,
    messageRootMatches := true,
    messageCountMatches := true,
    headerMmrRootMatches := true,
    headerMmrLenMatches := true,
    supplyDigestMatches := true
  }

theorem valid_accepts :
    evaluateCommitmentRejection valid = none := by
  rfl

theorem tx_count_mismatch_rejects
    {input : CommitmentInput}
    (mismatch : input.txCountMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.txCountMismatch := by
  unfold evaluateCommitmentRejection
  simp [mismatch]

theorem state_root_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (mismatch : input.stateRootMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.stateRootMismatch := by
  unfold evaluateCommitmentRejection
  simp [txCountMatches, mismatch]

theorem kernel_root_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateRootMatches : input.stateRootMatches = true)
    (mismatch : input.kernelRootMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.kernelRootMismatch := by
  unfold evaluateCommitmentRejection
  simp [txCountMatches, stateRootMatches, mismatch]

theorem nullifier_root_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateRootMatches : input.stateRootMatches = true)
    (kernelRootMatches : input.kernelRootMatches = true)
    (mismatch : input.nullifierRootMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.nullifierRootMismatch := by
  unfold evaluateCommitmentRejection
  simp [txCountMatches, stateRootMatches, kernelRootMatches, mismatch]

theorem extrinsics_root_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateRootMatches : input.stateRootMatches = true)
    (kernelRootMatches : input.kernelRootMatches = true)
    (nullifierRootMatches : input.nullifierRootMatches = true)
    (mismatch : input.extrinsicsRootMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.extrinsicsRootMismatch := by
  unfold evaluateCommitmentRejection
  simp [txCountMatches, stateRootMatches, kernelRootMatches, nullifierRootMatches, mismatch]

theorem message_root_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateRootMatches : input.stateRootMatches = true)
    (kernelRootMatches : input.kernelRootMatches = true)
    (nullifierRootMatches : input.nullifierRootMatches = true)
    (extrinsicsRootMatches : input.extrinsicsRootMatches = true)
    (mismatch : input.messageRootMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.messageRootMismatch := by
  unfold evaluateCommitmentRejection
  simp [
    txCountMatches,
    stateRootMatches,
    kernelRootMatches,
    nullifierRootMatches,
    extrinsicsRootMatches,
    mismatch
  ]

theorem message_count_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateRootMatches : input.stateRootMatches = true)
    (kernelRootMatches : input.kernelRootMatches = true)
    (nullifierRootMatches : input.nullifierRootMatches = true)
    (extrinsicsRootMatches : input.extrinsicsRootMatches = true)
    (messageRootMatches : input.messageRootMatches = true)
    (mismatch : input.messageCountMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.messageCountMismatch := by
  unfold evaluateCommitmentRejection
  simp [
    txCountMatches,
    stateRootMatches,
    kernelRootMatches,
    nullifierRootMatches,
    extrinsicsRootMatches,
    messageRootMatches,
    mismatch
  ]

theorem header_mmr_root_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateRootMatches : input.stateRootMatches = true)
    (kernelRootMatches : input.kernelRootMatches = true)
    (nullifierRootMatches : input.nullifierRootMatches = true)
    (extrinsicsRootMatches : input.extrinsicsRootMatches = true)
    (messageRootMatches : input.messageRootMatches = true)
    (messageCountMatches : input.messageCountMatches = true)
    (mismatch : input.headerMmrRootMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.headerMmrRootMismatch := by
  unfold evaluateCommitmentRejection
  simp [
    txCountMatches,
    stateRootMatches,
    kernelRootMatches,
    nullifierRootMatches,
    extrinsicsRootMatches,
    messageRootMatches,
    messageCountMatches,
    mismatch
  ]

theorem header_mmr_len_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateRootMatches : input.stateRootMatches = true)
    (kernelRootMatches : input.kernelRootMatches = true)
    (nullifierRootMatches : input.nullifierRootMatches = true)
    (extrinsicsRootMatches : input.extrinsicsRootMatches = true)
    (messageRootMatches : input.messageRootMatches = true)
    (messageCountMatches : input.messageCountMatches = true)
    (headerMmrRootMatches : input.headerMmrRootMatches = true)
    (mismatch : input.headerMmrLenMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.headerMmrLenMismatch := by
  unfold evaluateCommitmentRejection
  simp [
    txCountMatches,
    stateRootMatches,
    kernelRootMatches,
    nullifierRootMatches,
    extrinsicsRootMatches,
    messageRootMatches,
    messageCountMatches,
    headerMmrRootMatches,
    mismatch
  ]

theorem supply_digest_mismatch_rejects
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateRootMatches : input.stateRootMatches = true)
    (kernelRootMatches : input.kernelRootMatches = true)
    (nullifierRootMatches : input.nullifierRootMatches = true)
    (extrinsicsRootMatches : input.extrinsicsRootMatches = true)
    (messageRootMatches : input.messageRootMatches = true)
    (messageCountMatches : input.messageCountMatches = true)
    (headerMmrRootMatches : input.headerMmrRootMatches = true)
    (headerMmrLenMatches : input.headerMmrLenMatches = true)
    (mismatch : input.supplyDigestMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.supplyDigestMismatch := by
  unfold evaluateCommitmentRejection
  simp [
    txCountMatches,
    stateRootMatches,
    kernelRootMatches,
    nullifierRootMatches,
    extrinsicsRootMatches,
    messageRootMatches,
    messageCountMatches,
    headerMmrRootMatches,
    headerMmrLenMatches,
    mismatch
  ]

theorem state_root_precedes_supply_digest
    {input : CommitmentInput}
    (txCountMatches : input.txCountMatches = true)
    (stateMismatch : input.stateRootMatches = false) :
    evaluateCommitmentRejection input =
      some CommitmentReject.stateRootMismatch := by
  unfold evaluateCommitmentRejection
  simp [txCountMatches, stateMismatch]

end BlockCommitmentAdmission
end Native
end Hegemon

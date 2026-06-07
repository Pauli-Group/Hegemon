namespace Hegemon
namespace Native
namespace CandidateArtifactAdmission

inductive CandidateArtifactReject where
  | stateDeltasPresent
  | artifactMissing
  | schemaMismatch
  | txCountZero
  | txCountTooLarge
  | daChunkCountZero
  | wrongProofMode
  | wrongProofKind
  | verifierProfileMismatch
  | commitmentProofPresent
  | receiptRootPresent
  | recursivePayloadMissing
  | recursiveProofEmpty
  | recursiveProofTooLarge
deriving DecidableEq, Repr

structure CandidateArtifactInput where
  stateDeltasAbsent : Bool
  artifactPresent : Bool
  schemaMatches : Bool
  txCount : Nat
  maxTxCount : Nat
  daChunkCount : Nat
  proofModeRecursiveBlock : Bool
  proofKindRecursiveBlockV2 : Bool
  verifierProfileMatches : Bool
  commitmentProofEmpty : Bool
  receiptRootAbsent : Bool
  recursivePayloadPresent : Bool
  recursiveProofBytes : Nat
  maxRecursiveProofBytes : Nat
deriving DecidableEq, Repr

def evaluateCandidateArtifact
    (input : CandidateArtifactInput) : Except CandidateArtifactReject Unit :=
  if input.stateDeltasAbsent = false then
    Except.error CandidateArtifactReject.stateDeltasPresent
  else if input.artifactPresent = false then
    Except.error CandidateArtifactReject.artifactMissing
  else if input.schemaMatches = false then
    Except.error CandidateArtifactReject.schemaMismatch
  else if input.txCount = 0 then
    Except.error CandidateArtifactReject.txCountZero
  else if input.txCount > input.maxTxCount then
    Except.error CandidateArtifactReject.txCountTooLarge
  else if input.daChunkCount = 0 then
    Except.error CandidateArtifactReject.daChunkCountZero
  else if input.proofModeRecursiveBlock = false then
    Except.error CandidateArtifactReject.wrongProofMode
  else if input.proofKindRecursiveBlockV2 = false then
    Except.error CandidateArtifactReject.wrongProofKind
  else if input.verifierProfileMatches = false then
    Except.error CandidateArtifactReject.verifierProfileMismatch
  else if input.commitmentProofEmpty = false then
    Except.error CandidateArtifactReject.commitmentProofPresent
  else if input.receiptRootAbsent = false then
    Except.error CandidateArtifactReject.receiptRootPresent
  else if input.recursivePayloadPresent = false then
    Except.error CandidateArtifactReject.recursivePayloadMissing
  else if input.recursiveProofBytes = 0 then
    Except.error CandidateArtifactReject.recursiveProofEmpty
  else if input.recursiveProofBytes > input.maxRecursiveProofBytes then
    Except.error CandidateArtifactReject.recursiveProofTooLarge
  else
    Except.ok ()

def candidateArtifactAccepts (input : CandidateArtifactInput) : Bool :=
  match evaluateCandidateArtifact input with
  | Except.ok _ => true
  | Except.error _ => false

def candidateArtifactRejection
    (input : CandidateArtifactInput) : Option CandidateArtifactReject :=
  match evaluateCandidateArtifact input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def validCandidateArtifact : CandidateArtifactInput :=
  {
    stateDeltasAbsent := true,
    artifactPresent := true,
    schemaMatches := true,
    txCount := 1,
    maxTxCount := 32,
    daChunkCount := 1,
    proofModeRecursiveBlock := true,
    proofKindRecursiveBlockV2 := true,
    verifierProfileMatches := true,
    commitmentProofEmpty := true,
    receiptRootAbsent := true,
    recursivePayloadPresent := true,
    recursiveProofBytes := 32,
    maxRecursiveProofBytes := 522159
  }

theorem valid_candidate_artifact_accepts :
    evaluateCandidateArtifact validCandidateArtifact = Except.ok () := by
  rfl

theorem state_deltas_present_rejects
    {input : CandidateArtifactInput}
    (deltasPresent : input.stateDeltasAbsent = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.stateDeltasPresent := by
  unfold evaluateCandidateArtifact
  simp [deltasPresent]

theorem artifact_missing_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (missing : input.artifactPresent = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.artifactMissing := by
  unfold evaluateCandidateArtifact
  simp [noDeltas, missing]

theorem schema_mismatch_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (mismatch : input.schemaMatches = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.schemaMismatch := by
  unfold evaluateCandidateArtifact
  simp [noDeltas, present, mismatch]

theorem tx_count_zero_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (zeroTx : input.txCount = 0) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.txCountZero := by
  unfold evaluateCandidateArtifact
  simp [noDeltas, present, schema, zeroTx]

theorem tx_count_too_large_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (tooLarge : input.txCount > input.maxTxCount) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.txCountTooLarge := by
  unfold evaluateCandidateArtifact
  simp [noDeltas, present, schema, nonzeroTx, tooLarge]

theorem da_chunk_count_zero_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (zeroChunks : input.daChunkCount = 0) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.daChunkCountZero := by
  unfold evaluateCandidateArtifact
  simp [noDeltas, present, schema, nonzeroTx, txInBounds, zeroChunks]

theorem wrong_proof_mode_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (nonzeroChunks : input.daChunkCount ≠ 0)
    (wrongMode : input.proofModeRecursiveBlock = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.wrongProofMode := by
  unfold evaluateCandidateArtifact
  simp [
    noDeltas,
    present,
    schema,
    nonzeroTx,
    txInBounds,
    nonzeroChunks,
    wrongMode
  ]

theorem wrong_proof_kind_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (nonzeroChunks : input.daChunkCount ≠ 0)
    (mode : input.proofModeRecursiveBlock = true)
    (wrongKind : input.proofKindRecursiveBlockV2 = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.wrongProofKind := by
  unfold evaluateCandidateArtifact
  simp [
    noDeltas,
    present,
    schema,
    nonzeroTx,
    txInBounds,
    nonzeroChunks,
    mode,
    wrongKind
  ]

theorem verifier_profile_mismatch_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (nonzeroChunks : input.daChunkCount ≠ 0)
    (mode : input.proofModeRecursiveBlock = true)
    (kind : input.proofKindRecursiveBlockV2 = true)
    (profileMismatch : input.verifierProfileMatches = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.verifierProfileMismatch := by
  unfold evaluateCandidateArtifact
  simp [
    noDeltas,
    present,
    schema,
    nonzeroTx,
    txInBounds,
    nonzeroChunks,
    mode,
    kind,
    profileMismatch
  ]

theorem commitment_proof_present_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (nonzeroChunks : input.daChunkCount ≠ 0)
    (mode : input.proofModeRecursiveBlock = true)
    (kind : input.proofKindRecursiveBlockV2 = true)
    (profile : input.verifierProfileMatches = true)
    (commitmentProofPresent : input.commitmentProofEmpty = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.commitmentProofPresent := by
  unfold evaluateCandidateArtifact
  simp [
    noDeltas,
    present,
    schema,
    nonzeroTx,
    txInBounds,
    nonzeroChunks,
    mode,
    kind,
    profile,
    commitmentProofPresent
  ]

theorem receipt_root_present_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (nonzeroChunks : input.daChunkCount ≠ 0)
    (mode : input.proofModeRecursiveBlock = true)
    (kind : input.proofKindRecursiveBlockV2 = true)
    (profile : input.verifierProfileMatches = true)
    (commitmentProofEmpty : input.commitmentProofEmpty = true)
    (receiptPresent : input.receiptRootAbsent = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.receiptRootPresent := by
  unfold evaluateCandidateArtifact
  simp [
    noDeltas,
    present,
    schema,
    nonzeroTx,
    txInBounds,
    nonzeroChunks,
    mode,
    kind,
    profile,
    commitmentProofEmpty,
    receiptPresent
  ]

theorem recursive_payload_missing_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (nonzeroChunks : input.daChunkCount ≠ 0)
    (mode : input.proofModeRecursiveBlock = true)
    (kind : input.proofKindRecursiveBlockV2 = true)
    (profile : input.verifierProfileMatches = true)
    (commitmentProofEmpty : input.commitmentProofEmpty = true)
    (receiptAbsent : input.receiptRootAbsent = true)
    (payloadMissing : input.recursivePayloadPresent = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.recursivePayloadMissing := by
  unfold evaluateCandidateArtifact
  simp [
    noDeltas,
    present,
    schema,
    nonzeroTx,
    txInBounds,
    nonzeroChunks,
    mode,
    kind,
    profile,
    commitmentProofEmpty,
    receiptAbsent,
    payloadMissing
  ]

theorem recursive_proof_empty_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (nonzeroChunks : input.daChunkCount ≠ 0)
    (mode : input.proofModeRecursiveBlock = true)
    (kind : input.proofKindRecursiveBlockV2 = true)
    (profile : input.verifierProfileMatches = true)
    (commitmentProofEmpty : input.commitmentProofEmpty = true)
    (receiptAbsent : input.receiptRootAbsent = true)
    (payloadPresent : input.recursivePayloadPresent = true)
    (proofEmpty : input.recursiveProofBytes = 0) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.recursiveProofEmpty := by
  unfold evaluateCandidateArtifact
  simp [
    noDeltas,
    present,
    schema,
    nonzeroTx,
    txInBounds,
    nonzeroChunks,
    mode,
    kind,
    profile,
    commitmentProofEmpty,
    receiptAbsent,
    payloadPresent,
    proofEmpty
  ]

theorem recursive_proof_too_large_rejects
    {input : CandidateArtifactInput}
    (noDeltas : input.stateDeltasAbsent = true)
    (present : input.artifactPresent = true)
    (schema : input.schemaMatches = true)
    (nonzeroTx : input.txCount ≠ 0)
    (txInBounds : ¬ input.txCount > input.maxTxCount)
    (nonzeroChunks : input.daChunkCount ≠ 0)
    (mode : input.proofModeRecursiveBlock = true)
    (kind : input.proofKindRecursiveBlockV2 = true)
    (profile : input.verifierProfileMatches = true)
    (commitmentProofEmpty : input.commitmentProofEmpty = true)
    (receiptAbsent : input.receiptRootAbsent = true)
    (payloadPresent : input.recursivePayloadPresent = true)
    (proofNonempty : input.recursiveProofBytes ≠ 0)
    (tooLarge : input.recursiveProofBytes > input.maxRecursiveProofBytes) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.recursiveProofTooLarge := by
  unfold evaluateCandidateArtifact
  simp [
    noDeltas,
    present,
    schema,
    nonzeroTx,
    txInBounds,
    nonzeroChunks,
    mode,
    kind,
    profile,
    commitmentProofEmpty,
    receiptAbsent,
    payloadPresent,
    proofNonempty,
    tooLarge
  ]

theorem state_deltas_precede_artifact_validation
    {input : CandidateArtifactInput}
    (deltasPresent : input.stateDeltasAbsent = false) :
    evaluateCandidateArtifact input =
      Except.error CandidateArtifactReject.stateDeltasPresent := by
  exact state_deltas_present_rejects deltasPresent

end CandidateArtifactAdmission
end Native
end Hegemon

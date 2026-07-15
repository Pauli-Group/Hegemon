namespace Hegemon
namespace Consensus

inductive VerificationMode where
  | inlineRequired
  | selfContained
deriving DecidableEq, Repr

inductive BatchMode where
  | inlineTx
  | receiptRoot
  | recursiveBlock
deriving DecidableEq, Repr

inductive ProofPolicyReject where
  | emptyBlockCarriesProof
  | missingTransactionProofs
  | transactionProofCountMismatch
  | unsupportedInlineRequired
  | missingProvenBatch
  | missingTransactionValidityClaims
  | legacyInlineBatch
  | retiredReceiptRoot
  | recursiveBlockCommitmentProofBytes
  | recursiveBlockReceiptRootPayload
  | missingRecursiveBlockArtifact
deriving DecidableEq, Repr

structure ProofPolicyInput where
  txCount : Nat
  verificationMode : VerificationMode
  hasProvenBatch : Bool
  batchMode : BatchMode
  commitmentProofBytes : Nat
  hasBlockArtifact : Bool
  hasReceiptRoot : Bool
  hasTxValidityArtifacts : Bool
  txValidityArtifactCount : Nat
  hasTxValidityClaims : Bool
deriving DecidableEq, Repr

def emptyBlockHasProofPayload (input : ProofPolicyInput) : Bool :=
  input.hasProvenBatch
    || input.hasBlockArtifact
    || input.hasTxValidityArtifacts
    || input.hasTxValidityClaims

def evaluateProofPolicy (input : ProofPolicyInput) : Option ProofPolicyReject :=
  if input.txCount = 0 then
    if emptyBlockHasProofPayload input then
      some ProofPolicyReject.emptyBlockCarriesProof
    else
      none
  else if !input.hasTxValidityArtifacts then
    some ProofPolicyReject.missingTransactionProofs
  else if input.txValidityArtifactCount != input.txCount then
    some ProofPolicyReject.transactionProofCountMismatch
  else if input.verificationMode = VerificationMode.inlineRequired then
    some ProofPolicyReject.unsupportedInlineRequired
  else if !input.hasProvenBatch then
    some ProofPolicyReject.missingProvenBatch
  else if !input.hasTxValidityClaims then
    some ProofPolicyReject.missingTransactionValidityClaims
  else
    match input.batchMode with
    | BatchMode.inlineTx =>
        some ProofPolicyReject.legacyInlineBatch
    | BatchMode.receiptRoot =>
        some ProofPolicyReject.retiredReceiptRoot
    | BatchMode.recursiveBlock =>
        if input.commitmentProofBytes != 0 then
          some ProofPolicyReject.recursiveBlockCommitmentProofBytes
        else if input.hasReceiptRoot then
          some ProofPolicyReject.recursiveBlockReceiptRootPayload
        else if input.hasBlockArtifact then
          none
        else
          some ProofPolicyReject.missingRecursiveBlockArtifact

def policyAccepts (input : ProofPolicyInput) : Bool :=
  evaluateProofPolicy input = none

theorem empty_clean_accepts
    {input : ProofPolicyInput}
    (zero : input.txCount = 0)
    (clean : emptyBlockHasProofPayload input = false) :
    evaluateProofPolicy input = none := by
  unfold evaluateProofPolicy
  simp [zero, clean]

theorem empty_with_payload_rejects
    {input : ProofPolicyInput}
    (zero : input.txCount = 0)
    (dirty : emptyBlockHasProofPayload input = true) :
    evaluateProofPolicy input =
      some ProofPolicyReject.emptyBlockCarriesProof := by
  unfold evaluateProofPolicy
  simp [zero, dirty]

theorem nonempty_requires_tx_artifacts
    {input : ProofPolicyInput}
    (nonzero : input.txCount ≠ 0)
    (missing : input.hasTxValidityArtifacts = false) :
    evaluateProofPolicy input =
      some ProofPolicyReject.missingTransactionProofs := by
  unfold evaluateProofPolicy
  simp [nonzero, missing]

theorem nonempty_rejects_tx_artifact_count_mismatch
    {input : ProofPolicyInput}
    (nonzero : input.txCount ≠ 0)
    (hasArtifacts : input.hasTxValidityArtifacts = true)
    (mismatch : input.txValidityArtifactCount != input.txCount) :
    evaluateProofPolicy input =
      some ProofPolicyReject.transactionProofCountMismatch := by
  unfold evaluateProofPolicy
  simp [nonzero, hasArtifacts, mismatch]

theorem nonempty_rejects_inline_required
    {input : ProofPolicyInput}
    (nonzero : input.txCount ≠ 0)
    (hasArtifacts : input.hasTxValidityArtifacts = true)
    (countMatch : input.txValidityArtifactCount = input.txCount)
    (mode : input.verificationMode = VerificationMode.inlineRequired) :
    evaluateProofPolicy input =
      some ProofPolicyReject.unsupportedInlineRequired := by
  unfold evaluateProofPolicy
  simp [nonzero, hasArtifacts, countMatch, mode]

theorem nonempty_requires_proven_batch
    {input : ProofPolicyInput}
    (nonzero : input.txCount ≠ 0)
    (hasArtifacts : input.hasTxValidityArtifacts = true)
    (countMatch : input.txValidityArtifactCount = input.txCount)
    (mode : input.verificationMode = VerificationMode.selfContained)
    (missingBatch : input.hasProvenBatch = false) :
    evaluateProofPolicy input =
      some ProofPolicyReject.missingProvenBatch := by
  unfold evaluateProofPolicy
  simp [nonzero, hasArtifacts, countMatch, mode, missingBatch]

theorem recursive_rejects_commitment_proof_bytes
    {input : ProofPolicyInput}
    (nonzero : input.txCount ≠ 0)
    (hasArtifacts : input.hasTxValidityArtifacts = true)
    (countMatch : input.txValidityArtifactCount = input.txCount)
    (mode : input.verificationMode = VerificationMode.selfContained)
    (hasBatch : input.hasProvenBatch = true)
    (hasClaims : input.hasTxValidityClaims = true)
    (batchMode : input.batchMode = BatchMode.recursiveBlock)
    (hasBytes : input.commitmentProofBytes != 0) :
    evaluateProofPolicy input =
      some ProofPolicyReject.recursiveBlockCommitmentProofBytes := by
  unfold evaluateProofPolicy
  simp [nonzero, hasArtifacts, countMatch, mode, hasBatch, hasClaims, batchMode, hasBytes]

theorem receipt_root_is_retired
    {input : ProofPolicyInput}
    (nonzero : input.txCount ≠ 0)
    (hasArtifacts : input.hasTxValidityArtifacts = true)
    (countMatch : input.txValidityArtifactCount = input.txCount)
    (mode : input.verificationMode = VerificationMode.selfContained)
    (hasBatch : input.hasProvenBatch = true)
    (hasClaims : input.hasTxValidityClaims = true)
    (batchMode : input.batchMode = BatchMode.receiptRoot) :
    evaluateProofPolicy input =
      some ProofPolicyReject.retiredReceiptRoot := by
  unfold evaluateProofPolicy
  simp [nonzero, hasArtifacts, countMatch, mode, hasBatch, hasClaims, batchMode]

theorem recursive_requires_block_artifact
    {input : ProofPolicyInput}
    (nonzero : input.txCount ≠ 0)
    (hasArtifacts : input.hasTxValidityArtifacts = true)
    (countMatch : input.txValidityArtifactCount = input.txCount)
    (mode : input.verificationMode = VerificationMode.selfContained)
    (hasBatch : input.hasProvenBatch = true)
    (hasClaims : input.hasTxValidityClaims = true)
    (batchMode : input.batchMode = BatchMode.recursiveBlock)
    (noBytes : input.commitmentProofBytes = 0)
    (noReceiptRoot : input.hasReceiptRoot = false)
    (missingArtifact : input.hasBlockArtifact = false) :
    evaluateProofPolicy input =
      some ProofPolicyReject.missingRecursiveBlockArtifact := by
  unfold evaluateProofPolicy
  simp [
    nonzero,
    hasArtifacts,
    countMatch,
    mode,
    hasBatch,
    hasClaims,
    batchMode,
    noBytes,
    noReceiptRoot,
    missingArtifact
  ]

theorem recursive_complete_accepts
    {input : ProofPolicyInput}
    (nonzero : input.txCount ≠ 0)
    (hasArtifacts : input.hasTxValidityArtifacts = true)
    (countMatch : input.txValidityArtifactCount = input.txCount)
    (mode : input.verificationMode = VerificationMode.selfContained)
    (hasBatch : input.hasProvenBatch = true)
    (hasClaims : input.hasTxValidityClaims = true)
    (batchMode : input.batchMode = BatchMode.recursiveBlock)
    (noBytes : input.commitmentProofBytes = 0)
    (noReceiptRoot : input.hasReceiptRoot = false)
    (hasArtifact : input.hasBlockArtifact = true) :
    evaluateProofPolicy input = none := by
  unfold evaluateProofPolicy
  simp [
    nonzero,
    hasArtifacts,
    countMatch,
    mode,
    hasBatch,
    hasClaims,
    batchMode,
    noBytes,
    noReceiptRoot,
    hasArtifact
  ]

end Consensus
end Hegemon

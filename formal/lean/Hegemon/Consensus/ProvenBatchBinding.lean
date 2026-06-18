namespace Hegemon
namespace Consensus
namespace ProvenBatchBinding

inductive BatchMode where
  | inlineTx
  | receiptRoot
  | recursiveBlock
deriving DecidableEq, Repr

inductive ArtifactKind where
  | inlineTx
  | txLeaf
  | receiptRoot
  | recursiveBlockV1
  | recursiveBlockV2
deriving DecidableEq, Repr

inductive BindingReject where
  | incompatibleRoute
  | txCountMismatch
  | statementCommitmentMismatch
  | daRootMismatch
  | daChunkCountZero
  | missingRecursiveBlockArtifact
  | artifactKindMismatch
  | artifactVerifierProfileMismatch
  | recursiveBlockReceiptRootPayload
deriving DecidableEq, Repr

structure BindingInput where
  batchMode : BatchMode
  proofKind : ArtifactKind
  txCount : Nat
  expectedTxCount : Nat
  statementCommitmentMatches : Bool
  daRootMatches : Bool
  daChunkCount : Nat
  hasArtifact : Bool
  artifactKind : ArtifactKind
  artifactVerifierProfileMatches : Bool
  hasReceiptRoot : Bool
deriving DecidableEq, Repr

def routeCompatible (mode : BatchMode) (kind : ArtifactKind) : Bool :=
  match mode with
  | BatchMode.inlineTx => kind = ArtifactKind.inlineTx
  | BatchMode.receiptRoot => kind = ArtifactKind.receiptRoot
  | BatchMode.recursiveBlock =>
      kind = ArtifactKind.recursiveBlockV1 || kind = ArtifactKind.recursiveBlockV2

def evaluateBinding (input : BindingInput) : Option BindingReject :=
  if routeCompatible input.batchMode input.proofKind = false then
    some BindingReject.incompatibleRoute
  else if input.txCount != input.expectedTxCount then
    some BindingReject.txCountMismatch
  else if input.statementCommitmentMatches = false then
    some BindingReject.statementCommitmentMismatch
  else if input.daRootMatches = false then
    some BindingReject.daRootMismatch
  else if input.daChunkCount = 0 then
    some BindingReject.daChunkCountZero
  else if input.batchMode = BatchMode.recursiveBlock && input.hasArtifact = false then
    some BindingReject.missingRecursiveBlockArtifact
  else if input.hasArtifact && input.artifactKind != input.proofKind then
    some BindingReject.artifactKindMismatch
  else if input.hasArtifact && input.artifactVerifierProfileMatches = false then
    some BindingReject.artifactVerifierProfileMismatch
  else if input.batchMode = BatchMode.recursiveBlock && input.hasReceiptRoot then
    some BindingReject.recursiveBlockReceiptRootPayload
  else
    none

def acceptsBinding (input : BindingInput) : Bool :=
  evaluateBinding input = none

def bindingPreconditions (input : BindingInput) : Bool :=
  if routeCompatible input.batchMode input.proofKind = false then
    false
  else if input.txCount != input.expectedTxCount then
    false
  else if input.statementCommitmentMatches = false then
    false
  else if input.daRootMatches = false then
    false
  else if input.daChunkCount = 0 then
    false
  else if input.batchMode = BatchMode.recursiveBlock && input.hasArtifact = false then
    false
  else if input.hasArtifact && input.artifactKind != input.proofKind then
    false
  else if input.hasArtifact && input.artifactVerifierProfileMatches = false then
    false
  else if input.batchMode = BatchMode.recursiveBlock && input.hasReceiptRoot then
    false
  else
    true

theorem accepts_iff_binding_preconditions (input : BindingInput) :
    acceptsBinding input = bindingPreconditions input := by
  unfold acceptsBinding bindingPreconditions evaluateBinding
  repeat (split <;> simp_all)
  by_cases hasArtifact : input.hasArtifact = true
  · simp [hasArtifact] at *
    have artifactKindMatches : input.artifactKind = input.proofKind := by
      simp_all
    have artifactProfileMatches : input.artifactVerifierProfileMatches = true := by
      simp_all
    simp [artifactKindMatches, artifactProfileMatches]
  · have noArtifact : input.hasArtifact = false := by
      cases hArtifactValue : input.hasArtifact
      · rfl
      · exfalso
        exact hasArtifact hArtifactValue
    by_cases recursive : input.batchMode = BatchMode.recursiveBlock
    · simp [noArtifact, recursive] at *
    · simp [noArtifact, recursive] at *

def validRecursiveBlockV2 : BindingInput :=
  {
    batchMode := BatchMode.recursiveBlock,
    proofKind := ArtifactKind.recursiveBlockV2,
    txCount := 2,
    expectedTxCount := 2,
    statementCommitmentMatches := true,
    daRootMatches := true,
    daChunkCount := 1,
    hasArtifact := true,
    artifactKind := ArtifactKind.recursiveBlockV2,
    artifactVerifierProfileMatches := true,
    hasReceiptRoot := false
  }

def validReceiptRoot : BindingInput :=
  {
    batchMode := BatchMode.receiptRoot,
    proofKind := ArtifactKind.receiptRoot,
    txCount := 2,
    expectedTxCount := 2,
    statementCommitmentMatches := true,
    daRootMatches := true,
    daChunkCount := 1,
    hasArtifact := false,
    artifactKind := ArtifactKind.receiptRoot,
    artifactVerifierProfileMatches := true,
    hasReceiptRoot := true
  }

theorem valid_recursive_block_v2_accepts :
    evaluateBinding validRecursiveBlockV2 = none := by
  decide

theorem valid_receipt_root_accepts :
    evaluateBinding validReceiptRoot = none := by
  decide

theorem rejects_incompatible_recursive_route :
    evaluateBinding { validRecursiveBlockV2 with proofKind := ArtifactKind.receiptRoot } =
      some BindingReject.incompatibleRoute := by
  decide

theorem rejects_incompatible_receipt_route :
    evaluateBinding { validReceiptRoot with proofKind := ArtifactKind.recursiveBlockV2 } =
      some BindingReject.incompatibleRoute := by
  decide

theorem rejects_tx_count_mismatch :
    evaluateBinding { validRecursiveBlockV2 with txCount := 1 } =
      some BindingReject.txCountMismatch := by
  decide

theorem rejects_statement_commitment_mismatch :
    evaluateBinding { validRecursiveBlockV2 with statementCommitmentMatches := false } =
      some BindingReject.statementCommitmentMismatch := by
  decide

theorem rejects_da_root_mismatch :
    evaluateBinding { validRecursiveBlockV2 with daRootMatches := false } =
      some BindingReject.daRootMismatch := by
  decide

theorem rejects_da_chunk_count_zero :
    evaluateBinding { validRecursiveBlockV2 with daChunkCount := 0 } =
      some BindingReject.daChunkCountZero := by
  decide

theorem rejects_missing_recursive_block_artifact :
    evaluateBinding { validRecursiveBlockV2 with hasArtifact := false } =
      some BindingReject.missingRecursiveBlockArtifact := by
  decide

theorem rejects_artifact_kind_mismatch :
    evaluateBinding { validRecursiveBlockV2 with artifactKind := ArtifactKind.recursiveBlockV1 } =
      some BindingReject.artifactKindMismatch := by
  decide

theorem rejects_artifact_profile_mismatch :
    evaluateBinding { validRecursiveBlockV2 with artifactVerifierProfileMatches := false } =
      some BindingReject.artifactVerifierProfileMismatch := by
  decide

theorem rejects_recursive_block_receipt_root_payload :
    evaluateBinding { validRecursiveBlockV2 with hasReceiptRoot := true } =
      some BindingReject.recursiveBlockReceiptRootPayload := by
  decide

theorem receipt_root_skips_block_artifact_checks :
    evaluateBinding
      { validReceiptRoot with
        hasArtifact := false,
        artifactKind := ArtifactKind.recursiveBlockV2,
        artifactVerifierProfileMatches := false
      } = none := by
  decide

theorem recursive_v1_route_is_compatible :
    routeCompatible BatchMode.recursiveBlock ArtifactKind.recursiveBlockV1 = true := by
  decide

theorem tx_leaf_is_not_block_artifact_route :
    routeCompatible BatchMode.recursiveBlock ArtifactKind.txLeaf = false := by
  decide

end ProvenBatchBinding
end Consensus
end Hegemon

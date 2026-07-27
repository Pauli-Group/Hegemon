import Hegemon.Consensus.ProofPolicy

namespace Hegemon
namespace Consensus
namespace NativeTxLeafAuthorityBoundary

inductive BackendVerificationReject where
  | noncanonicalArtifact
  | metadataMismatch
  | transactionOrReceiptMismatch
  | proofBackendMismatch
  | emptyEmbeddedProof
  | receiptReconstructionMismatch
  | embeddedTransactionProofRejected
  | publicWitnessRejected
  | statementDigestMismatch
  | deterministicCommitmentMismatch
  | nativeLeafIntegrityRejected
deriving DecidableEq, Repr

structure BackendVerificationInput where
  canonicalArtifact : Bool
  metadataMatches : Bool
  transactionAndReceiptMatch : Bool
  proofBackendMatches : Bool
  embeddedProofNonempty : Bool
  receiptReconstructionMatches : Bool
  embeddedTransactionProofAccepted : Bool
  publicWitnessAccepted : Bool
  statementDigestMatches : Bool
  deterministicCommitmentMatches : Bool
  nativeLeafIntegrityAccepted : Bool
deriving DecidableEq, Repr

def evaluateBackendVerificationRejection
    (input : BackendVerificationInput) : Option BackendVerificationReject :=
  if input.canonicalArtifact = false then
    some BackendVerificationReject.noncanonicalArtifact
  else if input.metadataMatches = false then
    some BackendVerificationReject.metadataMismatch
  else if input.transactionAndReceiptMatch = false then
    some BackendVerificationReject.transactionOrReceiptMismatch
  else if input.proofBackendMatches = false then
    some BackendVerificationReject.proofBackendMismatch
  else if input.embeddedProofNonempty = false then
    some BackendVerificationReject.emptyEmbeddedProof
  else if input.receiptReconstructionMatches = false then
    some BackendVerificationReject.receiptReconstructionMismatch
  else if input.embeddedTransactionProofAccepted = false then
    some BackendVerificationReject.embeddedTransactionProofRejected
  else if input.publicWitnessAccepted = false then
    some BackendVerificationReject.publicWitnessRejected
  else if input.statementDigestMatches = false then
    some BackendVerificationReject.statementDigestMismatch
  else if input.deterministicCommitmentMatches = false then
    some BackendVerificationReject.deterministicCommitmentMismatch
  else if input.nativeLeafIntegrityAccepted = false then
    some BackendVerificationReject.nativeLeafIntegrityRejected
  else
    none

def backendVerificationAccepts (input : BackendVerificationInput) : Bool :=
  input.canonicalArtifact
    && input.metadataMatches
    && input.transactionAndReceiptMatch
    && input.proofBackendMatches
    && input.embeddedProofNonempty
    && input.receiptReconstructionMatches
    && input.embeddedTransactionProofAccepted
    && input.publicWitnessAccepted
    && input.statementDigestMatches
    && input.deterministicCommitmentMatches
    && input.nativeLeafIntegrityAccepted

theorem accepts_iff_no_backend_rejection (input : BackendVerificationInput) :
    backendVerificationAccepts input = true ↔
      evaluateBackendVerificationRejection input = none := by
  rcases input with
    ⟨canonicalArtifact, metadataMatches, transactionAndReceiptMatch,
      proofBackendMatches, embeddedProofNonempty, receiptReconstructionMatches,
      embeddedTransactionProofAccepted, publicWitnessAccepted,
      statementDigestMatches, deterministicCommitmentMatches,
      nativeLeafIntegrityAccepted⟩
  cases canonicalArtifact <;> cases metadataMatches <;>
    cases transactionAndReceiptMatch <;> cases proofBackendMatches <;>
    cases embeddedProofNonempty <;> cases receiptReconstructionMatches <;>
    cases embeddedTransactionProofAccepted <;> cases publicWitnessAccepted <;>
    cases statementDigestMatches <;> cases deterministicCommitmentMatches <;>
    cases nativeLeafIntegrityAccepted <;>
    decide

theorem backend_acceptance_requires_embedded_transaction_proof
    {input : BackendVerificationInput}
    (accepted : backendVerificationAccepts input = true) :
    input.embeddedTransactionProofAccepted = true := by
  simp [backendVerificationAccepts, Bool.and_eq_true] at accepted
  exact accepted.1.1.1.1.2

def validBackendVerification : BackendVerificationInput :=
  { canonicalArtifact := true
    metadataMatches := true
    transactionAndReceiptMatch := true
    proofBackendMatches := true
    embeddedProofNonempty := true
    receiptReconstructionMatches := true
    embeddedTransactionProofAccepted := true
    publicWitnessAccepted := true
    statementDigestMatches := true
    deterministicCommitmentMatches := true
    nativeLeafIntegrityAccepted := true }

theorem deterministic_commitment_cannot_replace_embedded_proof :
    evaluateBackendVerificationRejection
        { validBackendVerification with embeddedTransactionProofAccepted := false } =
      some BackendVerificationReject.embeddedTransactionProofRejected := by
  decide

theorem native_leaf_integrity_cannot_replace_embedded_proof :
    backendVerificationAccepts
        { validBackendVerification with
          embeddedTransactionProofAccepted := false
          nativeLeafIntegrityAccepted := true } = false := by
  decide

structure VerifiedCacheRecord where
  originalInput : BackendVerificationInput
  originalBackendAcceptance : backendVerificationAccepts originalInput = true

inductive AcceptedVerificationPath where
  | uncached
      (input : BackendVerificationInput)
      (accepted : backendVerificationAccepts input = true)
  | cacheHit (record : VerifiedCacheRecord)

def AcceptedVerificationPath.embeddedTransactionProofAccepted :
    AcceptedVerificationPath → Bool
  | .uncached input _ => input.embeddedTransactionProofAccepted
  | .cacheHit record => record.originalInput.embeddedTransactionProofAccepted

theorem every_accepted_path_inherits_embedded_transaction_proof_acceptance
    (path : AcceptedVerificationPath) :
    path.embeddedTransactionProofAccepted = true := by
  cases path with
  | uncached input accepted =>
      exact backend_acceptance_requires_embedded_transaction_proof accepted
  | cacheHit record =>
      exact backend_acceptance_requires_embedded_transaction_proof
        record.originalBackendAcceptance

inductive ProductionRegistryArtifactKind where
  | inlineTx
  | txLeaf
  | receiptRoot
  | recursiveBlockV1
  | recursiveBlockV2
deriving DecidableEq, Repr

def productionRegistryIncludes : ProductionRegistryArtifactKind → Bool
  | .inlineTx => true
  | .txLeaf => true
  | .receiptRoot => false
  | .recursiveBlockV1 => true
  | .recursiveBlockV2 => true

theorem receipt_root_has_no_production_verifier_dispatch :
    productionRegistryIncludes .receiptRoot = false := by
  decide

theorem receipt_root_is_rejected_before_native_fold_dispatch
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
  exact Hegemon.Consensus.receipt_root_is_retired nonzero hasArtifacts countMatch mode
    hasBatch hasClaims batchMode

end NativeTxLeafAuthorityBoundary
end Consensus
end Hegemon

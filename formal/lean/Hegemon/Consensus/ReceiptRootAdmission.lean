namespace Hegemon
namespace Consensus
namespace ReceiptRootAdmission

inductive ArtifactKind where
  | inlineTx
  | txLeaf
  | receiptRoot
  | recursiveBlockV1
  | recursiveBlockV2
deriving DecidableEq, Repr

inductive PayloadReject where
  | leafCountMismatch
  | receiptCountMismatch
  | missingClaimReceipts
  | receiptsMismatch
  | missingTransactionProofs
deriving DecidableEq, Repr

inductive ArtifactReject where
  | artifactKindMismatch
  | verifierProfileMismatch
  | artifactTooLarge
  | missingTransactionProofs
  | transactionProofCountMismatch
deriving DecidableEq, Repr

inductive StatementReject where
  | statementCommitmentMismatch
deriving DecidableEq, Repr

inductive VerifiedMetadataReject where
  | verifiedLeafCountMismatch
deriving DecidableEq, Repr

structure PayloadAdmissionInput where
  payloadLeafCountMatches : Bool
  payloadReceiptCountMatches : Bool
  hasClaimReceipts : Bool
  payloadReceiptsMatchClaims : Bool
  hasTxArtifacts : Bool
deriving DecidableEq, Repr

structure ArtifactAdmissionInput where
  envelopeKind : ArtifactKind
  envelopeVerifierProfileMatches : Bool
  artifactBytesLen : Nat
  maxArtifactBytes : Nat
  hasTxArtifacts : Bool
  txArtifactCountMatches : Bool
deriving DecidableEq, Repr

structure StatementBindingInput where
  statementCommitmentMatches : Bool
deriving DecidableEq, Repr

structure VerifiedMetadataInput where
  verifiedLeafCountMatches : Bool
deriving DecidableEq, Repr

def evaluatePayloadRejection (input : PayloadAdmissionInput) : Option PayloadReject :=
  if input.payloadLeafCountMatches = false then
    some PayloadReject.leafCountMismatch
  else if input.payloadReceiptCountMatches = false then
    some PayloadReject.receiptCountMismatch
  else if input.hasClaimReceipts = false then
    some PayloadReject.missingClaimReceipts
  else if input.payloadReceiptsMatchClaims = false then
    some PayloadReject.receiptsMismatch
  else if input.hasTxArtifacts = false then
    some PayloadReject.missingTransactionProofs
  else
    none

def evaluateArtifactRejection (input : ArtifactAdmissionInput) : Option ArtifactReject :=
  if input.envelopeKind != ArtifactKind.receiptRoot then
    some ArtifactReject.artifactKindMismatch
  else if input.envelopeVerifierProfileMatches = false then
    some ArtifactReject.verifierProfileMismatch
  else if input.artifactBytesLen > input.maxArtifactBytes then
    some ArtifactReject.artifactTooLarge
  else if input.hasTxArtifacts = false then
    some ArtifactReject.missingTransactionProofs
  else if input.txArtifactCountMatches = false then
    some ArtifactReject.transactionProofCountMismatch
  else
    none

def evaluateStatementRejection (input : StatementBindingInput) : Option StatementReject :=
  if input.statementCommitmentMatches then
    none
  else
    some StatementReject.statementCommitmentMismatch

def evaluateVerifiedMetadataRejection
    (input : VerifiedMetadataInput) : Option VerifiedMetadataReject :=
  if input.verifiedLeafCountMatches then
    none
  else
    some VerifiedMetadataReject.verifiedLeafCountMismatch

def payloadPreconditions (input : PayloadAdmissionInput) : Bool :=
  if input.payloadLeafCountMatches = false then
    false
  else if input.payloadReceiptCountMatches = false then
    false
  else if input.hasClaimReceipts = false then
    false
  else if input.payloadReceiptsMatchClaims = false then
    false
  else if input.hasTxArtifacts = false then
    false
  else
    true

def artifactPreconditions (input : ArtifactAdmissionInput) : Bool :=
  if input.envelopeKind != ArtifactKind.receiptRoot then
    false
  else if input.envelopeVerifierProfileMatches = false then
    false
  else if input.artifactBytesLen > input.maxArtifactBytes then
    false
  else if input.hasTxArtifacts = false then
    false
  else if input.txArtifactCountMatches = false then
    false
  else
    true

def statementPreconditions (input : StatementBindingInput) : Bool :=
  input.statementCommitmentMatches

def verifiedMetadataPreconditions (input : VerifiedMetadataInput) : Bool :=
  input.verifiedLeafCountMatches

def payloadAccepts (input : PayloadAdmissionInput) : Bool :=
  evaluatePayloadRejection input = none

def artifactAccepts (input : ArtifactAdmissionInput) : Bool :=
  evaluateArtifactRejection input = none

def statementAccepts (input : StatementBindingInput) : Bool :=
  evaluateStatementRejection input = none

def verifiedMetadataAccepts (input : VerifiedMetadataInput) : Bool :=
  evaluateVerifiedMetadataRejection input = none

theorem payload_accepts_iff_preconditions (input : PayloadAdmissionInput) :
    payloadAccepts input = payloadPreconditions input := by
  cases input with
  | mk payloadLeafCountMatches payloadReceiptCountMatches hasClaimReceipts
      payloadReceiptsMatchClaims hasTxArtifacts =>
      unfold payloadAccepts payloadPreconditions evaluatePayloadRejection
      cases payloadLeafCountMatches <;> cases payloadReceiptCountMatches <;>
        cases hasClaimReceipts <;> cases payloadReceiptsMatchClaims <;>
        cases hasTxArtifacts <;> simp

theorem artifact_accepts_iff_preconditions (input : ArtifactAdmissionInput) :
    artifactAccepts input = artifactPreconditions input := by
  cases input with
  | mk envelopeKind envelopeVerifierProfileMatches artifactBytesLen maxArtifactBytes
      hasTxArtifacts txArtifactCountMatches =>
      unfold artifactAccepts artifactPreconditions evaluateArtifactRejection
      by_cases oversized : artifactBytesLen > maxArtifactBytes
      · cases envelopeKind <;> cases envelopeVerifierProfileMatches <;>
          cases hasTxArtifacts <;> cases txArtifactCountMatches <;> simp [oversized]
      · cases envelopeKind <;> cases envelopeVerifierProfileMatches <;>
          cases hasTxArtifacts <;> cases txArtifactCountMatches <;> simp [oversized]

theorem statement_accepts_iff_preconditions (input : StatementBindingInput) :
    statementAccepts input = statementPreconditions input := by
  cases input with
  | mk statementCommitmentMatches =>
      unfold statementAccepts statementPreconditions evaluateStatementRejection
      cases statementCommitmentMatches <;> simp

theorem verified_metadata_accepts_iff_preconditions (input : VerifiedMetadataInput) :
    verifiedMetadataAccepts input = verifiedMetadataPreconditions input := by
  cases input with
  | mk verifiedLeafCountMatches =>
      unfold verifiedMetadataAccepts verifiedMetadataPreconditions
        evaluateVerifiedMetadataRejection
      cases verifiedLeafCountMatches <;> simp

def validPayload : PayloadAdmissionInput :=
  {
    payloadLeafCountMatches := true,
    payloadReceiptCountMatches := true,
    hasClaimReceipts := true,
    payloadReceiptsMatchClaims := true,
    hasTxArtifacts := true
  }

def validArtifact : ArtifactAdmissionInput :=
  {
    envelopeKind := ArtifactKind.receiptRoot,
    envelopeVerifierProfileMatches := true,
    artifactBytesLen := 512,
    maxArtifactBytes := 512,
    hasTxArtifacts := true,
    txArtifactCountMatches := true
  }

def validStatement : StatementBindingInput :=
  { statementCommitmentMatches := true }

def validVerifiedMetadata : VerifiedMetadataInput :=
  { verifiedLeafCountMatches := true }

theorem valid_payload_accepts :
    evaluatePayloadRejection validPayload = none := by
  native_decide

theorem payload_leaf_count_mismatch_rejects :
    evaluatePayloadRejection { validPayload with payloadLeafCountMatches := false } =
      some PayloadReject.leafCountMismatch := by
  native_decide

theorem payload_receipt_count_mismatch_rejects :
    evaluatePayloadRejection { validPayload with payloadReceiptCountMatches := false } =
      some PayloadReject.receiptCountMismatch := by
  native_decide

theorem payload_missing_claim_receipts_rejects :
    evaluatePayloadRejection { validPayload with hasClaimReceipts := false } =
      some PayloadReject.missingClaimReceipts := by
  native_decide

theorem payload_receipts_mismatch_rejects :
    evaluatePayloadRejection { validPayload with payloadReceiptsMatchClaims := false } =
      some PayloadReject.receiptsMismatch := by
  native_decide

theorem payload_missing_tx_artifacts_rejects :
    evaluatePayloadRejection { validPayload with hasTxArtifacts := false } =
      some PayloadReject.missingTransactionProofs := by
  native_decide

theorem valid_artifact_accepts :
    evaluateArtifactRejection validArtifact = none := by
  native_decide

theorem artifact_wrong_kind_rejects :
    evaluateArtifactRejection { validArtifact with envelopeKind := ArtifactKind.recursiveBlockV2 } =
      some ArtifactReject.artifactKindMismatch := by
  native_decide

theorem artifact_profile_mismatch_rejects :
    evaluateArtifactRejection { validArtifact with envelopeVerifierProfileMatches := false } =
      some ArtifactReject.verifierProfileMismatch := by
  native_decide

theorem artifact_oversized_rejects :
    evaluateArtifactRejection { validArtifact with artifactBytesLen := 513 } =
      some ArtifactReject.artifactTooLarge := by
  native_decide

theorem artifact_missing_tx_artifacts_rejects :
    evaluateArtifactRejection { validArtifact with hasTxArtifacts := false } =
      some ArtifactReject.missingTransactionProofs := by
  native_decide

theorem artifact_tx_count_mismatch_rejects :
    evaluateArtifactRejection { validArtifact with txArtifactCountMatches := false } =
      some ArtifactReject.transactionProofCountMismatch := by
  native_decide

theorem exact_artifact_size_limit_accepts :
    evaluateArtifactRejection { validArtifact with artifactBytesLen := 512, maxArtifactBytes := 512 } =
      none := by
  native_decide

theorem statement_binding_accepts :
    evaluateStatementRejection validStatement = none := by
  native_decide

theorem statement_commitment_mismatch_rejects :
    evaluateStatementRejection { statementCommitmentMatches := false } =
      some StatementReject.statementCommitmentMismatch := by
  native_decide

theorem verified_metadata_accepts :
    evaluateVerifiedMetadataRejection validVerifiedMetadata = none := by
  native_decide

theorem verified_leaf_count_mismatch_rejects :
    evaluateVerifiedMetadataRejection { verifiedLeafCountMatches := false } =
      some VerifiedMetadataReject.verifiedLeafCountMismatch := by
  native_decide

end ReceiptRootAdmission
end Consensus
end Hegemon

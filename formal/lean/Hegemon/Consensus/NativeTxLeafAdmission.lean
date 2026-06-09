namespace Hegemon
namespace Consensus
namespace NativeTxLeafAdmission

inductive ArtifactKind where
  | inlineTx
  | txLeaf
  | receiptRoot
  | recursiveBlockV1
  | recursiveBlockV2
deriving DecidableEq, Repr

inductive AdmissionReject where
  | missingEnvelope
  | artifactKindMismatch
  | envelopeVerifierProfileMismatch
  | artifactTooLarge
  | receiptVerifierProfileMismatch
  | artifactHashMismatch
  | cacheReceiptMismatch
  | cacheTransactionMismatch
deriving DecidableEq, Repr

inductive AdmissionOutcome where
  | needsBackendVerification
  | cacheHit
deriving DecidableEq, Repr

structure AdmissionInput where
  hasEnvelope : Bool
  envelopeKind : ArtifactKind
  envelopeVerifierProfileMatches : Bool
  artifactBytesLen : Nat
  maxArtifactBytes : Nat
  receiptVerifierProfileMatches : Bool
  hasExpectedArtifactHash : Bool
  expectedArtifactHashMatches : Bool
  hasCacheEntry : Bool
  cacheReceiptMatches : Bool
  cacheTransactionMatches : Bool
deriving DecidableEq, Repr

def evaluateAdmissionRejection (input : AdmissionInput) : Option AdmissionReject :=
  if input.hasEnvelope = false then
    some AdmissionReject.missingEnvelope
  else if input.envelopeKind != ArtifactKind.txLeaf then
    some AdmissionReject.artifactKindMismatch
  else if input.envelopeVerifierProfileMatches = false then
    some AdmissionReject.envelopeVerifierProfileMismatch
  else if input.artifactBytesLen > input.maxArtifactBytes then
    some AdmissionReject.artifactTooLarge
  else if input.receiptVerifierProfileMatches = false then
    some AdmissionReject.receiptVerifierProfileMismatch
  else if input.hasExpectedArtifactHash && input.expectedArtifactHashMatches = false then
    some AdmissionReject.artifactHashMismatch
  else if input.hasCacheEntry && input.cacheReceiptMatches = false then
    some AdmissionReject.cacheReceiptMismatch
  else if input.hasCacheEntry && input.cacheTransactionMatches = false then
    some AdmissionReject.cacheTransactionMismatch
  else
    none

def admissionOutcome (input : AdmissionInput) : AdmissionOutcome :=
  if input.hasCacheEntry then
    AdmissionOutcome.cacheHit
  else
    AdmissionOutcome.needsBackendVerification

def evaluateAdmission (input : AdmissionInput) : Except AdmissionReject AdmissionOutcome :=
  match evaluateAdmissionRejection input with
  | some rejection => Except.error rejection
  | none => Except.ok (admissionOutcome input)

def admissionPreconditions (input : AdmissionInput) : Bool :=
  if input.hasEnvelope = false then
    false
  else if input.envelopeKind != ArtifactKind.txLeaf then
    false
  else if input.envelopeVerifierProfileMatches = false then
    false
  else if input.artifactBytesLen > input.maxArtifactBytes then
    false
  else if input.receiptVerifierProfileMatches = false then
    false
  else if input.hasExpectedArtifactHash && input.expectedArtifactHashMatches = false then
    false
  else if input.hasCacheEntry && input.cacheReceiptMatches = false then
    false
  else if input.hasCacheEntry && input.cacheTransactionMatches = false then
    false
  else
    true

def admissionAccepts (input : AdmissionInput) : Bool :=
  evaluateAdmissionRejection input = none

theorem accepts_iff_admission_preconditions (input : AdmissionInput) :
    admissionAccepts input = admissionPreconditions input := by
  cases input with
  | mk hasEnvelope envelopeKind envelopeVerifierProfileMatches artifactBytesLen maxArtifactBytes
      receiptVerifierProfileMatches hasExpectedArtifactHash expectedArtifactHashMatches
      hasCacheEntry cacheReceiptMatches cacheTransactionMatches =>
      unfold admissionAccepts admissionPreconditions evaluateAdmissionRejection
      by_cases oversized : artifactBytesLen > maxArtifactBytes
      · cases hasEnvelope <;> cases envelopeKind <;> cases envelopeVerifierProfileMatches <;>
          cases receiptVerifierProfileMatches <;> cases hasExpectedArtifactHash <;>
          cases expectedArtifactHashMatches <;> cases hasCacheEntry <;>
          cases cacheReceiptMatches <;> cases cacheTransactionMatches <;> simp [oversized]
      · cases hasEnvelope <;> cases envelopeKind <;> cases envelopeVerifierProfileMatches <;>
          cases receiptVerifierProfileMatches <;> cases hasExpectedArtifactHash <;>
          cases expectedArtifactHashMatches <;> cases hasCacheEntry <;>
          cases cacheReceiptMatches <;> cases cacheTransactionMatches <;> simp [oversized]

def validUncached : AdmissionInput :=
  {
    hasEnvelope := true,
    envelopeKind := ArtifactKind.txLeaf,
    envelopeVerifierProfileMatches := true,
    artifactBytesLen := 512,
    maxArtifactBytes := 512,
    receiptVerifierProfileMatches := true,
    hasExpectedArtifactHash := true,
    expectedArtifactHashMatches := true,
    hasCacheEntry := false,
    cacheReceiptMatches := true,
    cacheTransactionMatches := true
  }

def validCacheHit : AdmissionInput :=
  { validUncached with hasCacheEntry := true, artifactBytesLen := 128 }

theorem valid_uncached_requires_backend_verification :
    evaluateAdmissionRejection validUncached = none ∧
      admissionOutcome validUncached = AdmissionOutcome.needsBackendVerification := by
  decide

theorem valid_cache_hit_accepts :
    evaluateAdmissionRejection validCacheHit = none ∧
      admissionOutcome validCacheHit = AdmissionOutcome.cacheHit := by
  decide

theorem missing_envelope_rejects :
    evaluateAdmissionRejection { validUncached with hasEnvelope := false } =
      some AdmissionReject.missingEnvelope := by
  decide

theorem wrong_artifact_kind_rejects :
    evaluateAdmissionRejection { validUncached with envelopeKind := ArtifactKind.receiptRoot } =
      some AdmissionReject.artifactKindMismatch := by
  decide

theorem envelope_profile_mismatch_rejects :
    evaluateAdmissionRejection { validUncached with envelopeVerifierProfileMatches := false } =
      some AdmissionReject.envelopeVerifierProfileMismatch := by
  decide

theorem oversized_artifact_rejects :
    evaluateAdmissionRejection { validUncached with artifactBytesLen := 513 } =
      some AdmissionReject.artifactTooLarge := by
  decide

theorem receipt_profile_mismatch_rejects :
    evaluateAdmissionRejection { validUncached with receiptVerifierProfileMatches := false } =
      some AdmissionReject.receiptVerifierProfileMismatch := by
  decide

theorem expected_hash_mismatch_rejects :
    evaluateAdmissionRejection { validUncached with expectedArtifactHashMatches := false } =
      some AdmissionReject.artifactHashMismatch := by
  decide

theorem missing_expected_hash_skips_hash_check :
    evaluateAdmissionRejection
      { validUncached with
        hasExpectedArtifactHash := false,
        expectedArtifactHashMatches := false
      } = none := by
  decide

theorem cache_receipt_mismatch_rejects :
    evaluateAdmissionRejection { validCacheHit with cacheReceiptMatches := false } =
      some AdmissionReject.cacheReceiptMismatch := by
  decide

theorem cache_transaction_mismatch_rejects :
    evaluateAdmissionRejection { validCacheHit with cacheTransactionMatches := false } =
      some AdmissionReject.cacheTransactionMismatch := by
  decide

theorem exact_size_limit_accepts :
    evaluateAdmissionRejection { validUncached with artifactBytesLen := 512, maxArtifactBytes := 512 } =
      none := by
  decide

end NativeTxLeafAdmission
end Consensus
end Hegemon

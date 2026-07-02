import Hegemon.Consensus.NativeTxLeafAdmission

open Hegemon.Consensus.NativeTxLeafAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def artifactKindJson : ArtifactKind -> String
  | ArtifactKind.inlineTx => "inline_tx"
  | ArtifactKind.txLeaf => "tx_leaf"
  | ArtifactKind.receiptRoot => "receipt_root"
  | ArtifactKind.recursiveBlockV1 => "recursive_block_v1"
  | ArtifactKind.recursiveBlockV2 => "recursive_block_v2"

def admissionRejectJson : Option AdmissionReject -> String
  | none => "null"
  | some AdmissionReject.missingEnvelope => "\"missing_envelope\""
  | some AdmissionReject.artifactKindMismatch => "\"artifact_kind_mismatch\""
  | some AdmissionReject.envelopeVerifierProfileMismatch =>
      "\"envelope_verifier_profile_mismatch\""
  | some AdmissionReject.artifactTooLarge => "\"artifact_too_large\""
  | some AdmissionReject.receiptVerifierProfileMismatch =>
      "\"receipt_verifier_profile_mismatch\""
  | some AdmissionReject.artifactHashMismatch => "\"artifact_hash_mismatch\""
  | some AdmissionReject.cacheReceiptMismatch => "\"cache_receipt_mismatch\""
  | some AdmissionReject.cacheTransactionMismatch => "\"cache_transaction_mismatch\""

def admissionOutcomeJson : AdmissionInput -> String
  | input =>
      match evaluateAdmission input with
      | Except.ok AdmissionOutcome.needsBackendVerification => "\"needs_backend_verification\""
      | Except.ok AdmissionOutcome.cacheHit => "\"cache_hit\""
      | Except.error _ => "null"

def nativeTxLeafAdmissionCaseJson (name : String) (input : AdmissionInput) : String :=
  let rejection := evaluateAdmissionRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"has_envelope\": " ++ boolJson input.hasEnvelope ++ ",\n"
    ++ "      \"envelope_kind\": \"" ++ artifactKindJson input.envelopeKind ++ "\",\n"
    ++ "      \"envelope_verifier_profile_matches\": "
    ++ boolJson input.envelopeVerifierProfileMatches ++ ",\n"
    ++ "      \"artifact_bytes_len\": " ++ toString input.artifactBytesLen ++ ",\n"
    ++ "      \"max_artifact_bytes\": " ++ toString input.maxArtifactBytes ++ ",\n"
    ++ "      \"receipt_verifier_profile_matches\": "
    ++ boolJson input.receiptVerifierProfileMatches ++ ",\n"
    ++ "      \"has_expected_artifact_hash\": "
    ++ boolJson input.hasExpectedArtifactHash ++ ",\n"
    ++ "      \"expected_artifact_hash_matches\": "
    ++ boolJson input.expectedArtifactHashMatches ++ ",\n"
    ++ "      \"has_cache_entry\": " ++ boolJson input.hasCacheEntry ++ ",\n"
    ++ "      \"cache_receipt_matches\": " ++ boolJson input.cacheReceiptMatches ++ ",\n"
    ++ "      \"cache_transaction_matches\": "
    ++ boolJson input.cacheTransactionMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ admissionRejectJson rejection ++ ",\n"
    ++ "      \"expected_outcome\": " ++ admissionOutcomeJson input ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"native_tx_leaf_admission_cases\": [\n"
    ++ nativeTxLeafAdmissionCaseJson "valid-uncached-needs-backend" validUncached ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "valid-cache-hit" validCacheHit ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "missing-envelope-rejected"
      { validUncached with hasEnvelope := false } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "wrong-artifact-kind-rejected"
      { validUncached with envelopeKind := ArtifactKind.receiptRoot } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "envelope-profile-mismatch-rejected"
      { validUncached with envelopeVerifierProfileMatches := false } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "oversized-artifact-rejected"
      { validUncached with artifactBytesLen := 513 } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "receipt-profile-mismatch-rejected"
      { validUncached with receiptVerifierProfileMatches := false } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "expected-hash-mismatch-rejected"
      { validUncached with expectedArtifactHashMatches := false } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "missing-expected-hash-skips-hash-check"
      { validUncached with
        hasExpectedArtifactHash := false,
        expectedArtifactHashMatches := false
      } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "cache-receipt-mismatch-rejected"
      { validCacheHit with cacheReceiptMatches := false } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "cache-transaction-mismatch-rejected"
      { validCacheHit with cacheTransactionMatches := false } ++ ",\n"
    ++ nativeTxLeafAdmissionCaseJson "exact-size-limit-accepted"
      { validUncached with artifactBytesLen := 512, maxArtifactBytes := 512 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

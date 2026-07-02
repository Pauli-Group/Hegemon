import Hegemon.Native.StablecoinPolicyAuthorization

open Hegemon.Native.StablecoinPolicyAuthorization

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option StablecoinPolicyReject -> String
  | none => "null"
  | some StablecoinPolicyReject.policyMissing => "\"policy_missing\""
  | some StablecoinPolicyReject.policyInactive => "\"policy_inactive\""
  | some StablecoinPolicyReject.policyNotLive => "\"policy_not_live\""
  | some StablecoinPolicyReject.assetMismatch => "\"asset_mismatch\""
  | some StablecoinPolicyReject.policyHashMismatch => "\"policy_hash_mismatch\""
  | some StablecoinPolicyReject.policyVersionMismatch =>
      "\"policy_version_mismatch\""
  | some StablecoinPolicyReject.oracleCommitmentMismatch =>
      "\"oracle_commitment_mismatch\""
  | some StablecoinPolicyReject.attestationCommitmentMismatch =>
      "\"attestation_commitment_mismatch\""
  | some StablecoinPolicyReject.attestationDisputed =>
      "\"attestation_disputed\""
  | some StablecoinPolicyReject.oracleStale => "\"oracle_stale\""
  | some StablecoinPolicyReject.issuanceZero => "\"issuance_zero\""
  | some StablecoinPolicyReject.issuanceOverLimit =>
      "\"issuance_over_limit\""

def stablecoinPolicyCaseJson
    (name : String)
    (input : StablecoinPolicyAuthorizationInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"stablecoin_present\": " ++ boolJson input.stablecoinPresent ++ ",\n"
    ++ "      \"policy_known\": " ++ boolJson input.policyKnown ++ ",\n"
    ++ "      \"policy_active\": " ++ boolJson input.policyActive ++ ",\n"
    ++ "      \"policy_lifecycle_open\": "
      ++ boolJson input.policyLifecycleOpen ++ ",\n"
    ++ "      \"asset_matches\": " ++ boolJson input.assetMatches ++ ",\n"
    ++ "      \"policy_hash_matches\": " ++ boolJson input.policyHashMatches ++ ",\n"
    ++ "      \"policy_version_matches\": "
      ++ boolJson input.policyVersionMatches ++ ",\n"
    ++ "      \"oracle_commitment_matches\": "
      ++ boolJson input.oracleCommitmentMatches ++ ",\n"
    ++ "      \"attestation_commitment_matches\": "
      ++ boolJson input.attestationCommitmentMatches ++ ",\n"
    ++ "      \"attestation_not_disputed\": "
      ++ boolJson input.attestationNotDisputed ++ ",\n"
    ++ "      \"oracle_fresh\": " ++ boolJson input.oracleFresh ++ ",\n"
    ++ "      \"issuance_nonzero\": " ++ boolJson input.issuanceNonzero ++ ",\n"
    ++ "      \"issuance_within_limit\": "
      ++ boolJson input.issuanceWithinLimit ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (stablecoinPolicyAuthorizationAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (stablecoinPolicyAuthorizationRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"stablecoin_policy_authorization_cases\": [\n"
    ++ stablecoinPolicyCaseJson "absent-stablecoin-accepts"
      absentStablecoinInput ++ ",\n"
    ++ stablecoinPolicyCaseJson "complete-policy-authorization-accepts"
      authorizedPolicyInput ++ ",\n"
    ++ stablecoinPolicyCaseJson "policy-missing-rejected"
      { authorizedPolicyInput with policyKnown := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "policy-inactive-rejected"
      { authorizedPolicyInput with policyActive := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "policy-not-live-rejected"
      { authorizedPolicyInput with policyLifecycleOpen := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "asset-mismatch-rejected"
      { authorizedPolicyInput with assetMatches := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "policy-hash-mismatch-rejected"
      { authorizedPolicyInput with policyHashMatches := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "policy-version-mismatch-rejected"
      { authorizedPolicyInput with policyVersionMatches := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "oracle-commitment-mismatch-rejected"
      { authorizedPolicyInput with oracleCommitmentMatches := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "attestation-commitment-mismatch-rejected"
      { authorizedPolicyInput with attestationCommitmentMatches := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "attestation-disputed-rejected"
      { authorizedPolicyInput with attestationNotDisputed := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "oracle-stale-rejected"
      { authorizedPolicyInput with oracleFresh := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "issuance-zero-rejected"
      { authorizedPolicyInput with issuanceNonzero := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "issuance-over-limit-rejected"
      { authorizedPolicyInput with issuanceWithinLimit := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "missing-precedes-all-other-failures"
      { authorizedPolicyInput with
        policyKnown := false,
        policyActive := false,
        policyLifecycleOpen := false,
        assetMatches := false,
        policyHashMatches := false,
        policyVersionMatches := false,
        oracleCommitmentMatches := false,
        attestationCommitmentMatches := false,
        attestationNotDisputed := false,
        oracleFresh := false,
        issuanceNonzero := false,
        issuanceWithinLimit := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "policy-active-precedes-binding-mismatch"
      { authorizedPolicyInput with
        policyActive := false,
        policyLifecycleOpen := false,
        assetMatches := false,
        policyHashMatches := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "policy-lifecycle-precedes-binding-mismatch"
      { authorizedPolicyInput with
        policyLifecycleOpen := false,
        assetMatches := false,
        policyHashMatches := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "attestation-dispute-precedes-stale-oracle"
      { authorizedPolicyInput with
        attestationNotDisputed := false,
        oracleFresh := false,
        issuanceNonzero := false } ++ ",\n"
    ++ stablecoinPolicyCaseJson "oracle-freshness-precedes-issuance-bounds"
      { authorizedPolicyInput with
        oracleFresh := false,
        issuanceNonzero := false,
        issuanceWithinLimit := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

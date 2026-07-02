import Hegemon.Transaction.TxValidityClaimMatching

open Hegemon.Transaction.TxValidityClaimMatching

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def claimMatchRejectJson : Option ClaimMatchReject -> String
  | none => "null"
  | some ClaimMatchReject.countMismatch => "\"count_mismatch\""
  | some ClaimMatchReject.receiptStatementHashMismatch =>
      "\"receipt_statement_hash_mismatch\""
  | some ClaimMatchReject.receiptProofDigestMismatch =>
      "\"receipt_proof_digest_mismatch\""
  | some ClaimMatchReject.receiptPublicInputsDigestMismatch =>
      "\"receipt_public_inputs_digest_mismatch\""
  | some ClaimMatchReject.receiptVerifierProfileMismatch =>
      "\"receipt_verifier_profile_mismatch\""
  | some ClaimMatchReject.bindingStatementHashMismatch =>
      "\"binding_statement_hash_mismatch\""
  | some ClaimMatchReject.bindingAnchorRootMismatch =>
      "\"binding_anchor_root_mismatch\""
  | some ClaimMatchReject.bindingFeeMismatch => "\"binding_fee_mismatch\""
  | some ClaimMatchReject.bindingCircuitVersionMismatch =>
      "\"binding_circuit_version_mismatch\""

def claimMatchCaseJson (name : String) (input : ClaimMatchInput) : String :=
  let rejection := evaluateClaimMatchRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"count_matches\": " ++ boolJson input.countMatches ++ ",\n"
    ++ "      \"receipt_statement_hash_matches\": "
    ++ boolJson input.receiptStatementHashMatches ++ ",\n"
    ++ "      \"receipt_proof_digest_matches\": "
    ++ boolJson input.receiptProofDigestMatches ++ ",\n"
    ++ "      \"receipt_public_inputs_digest_matches\": "
    ++ boolJson input.receiptPublicInputsDigestMatches ++ ",\n"
    ++ "      \"receipt_verifier_profile_matches\": "
    ++ boolJson input.receiptVerifierProfileMatches ++ ",\n"
    ++ "      \"binding_statement_hash_matches\": "
    ++ boolJson input.bindingStatementHashMatches ++ ",\n"
    ++ "      \"binding_anchor_root_matches\": "
    ++ boolJson input.bindingAnchorRootMatches ++ ",\n"
    ++ "      \"binding_fee_matches\": "
    ++ boolJson input.bindingFeeMatches ++ ",\n"
    ++ "      \"binding_circuit_version_matches\": "
    ++ boolJson input.bindingCircuitVersionMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson rejection.isNone ++ ",\n"
    ++ "      \"expected_rejection\": " ++ claimMatchRejectJson rejection ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"tx_validity_claim_match_cases\": [\n"
    ++ claimMatchCaseJson "valid-exact-match" validClaimMatch ++ ",\n"
    ++ claimMatchCaseJson "count-mismatch-rejected"
      { validClaimMatch with countMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "receipt-statement-hash-mismatch-rejected"
      { validClaimMatch with receiptStatementHashMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "receipt-proof-digest-mismatch-rejected"
      { validClaimMatch with receiptProofDigestMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "receipt-public-inputs-digest-mismatch-rejected"
      { validClaimMatch with receiptPublicInputsDigestMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "receipt-verifier-profile-mismatch-rejected"
      { validClaimMatch with receiptVerifierProfileMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "binding-statement-hash-mismatch-rejected"
      { validClaimMatch with bindingStatementHashMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "binding-anchor-root-mismatch-rejected"
      { validClaimMatch with bindingAnchorRootMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "binding-fee-mismatch-rejected"
      { validClaimMatch with bindingFeeMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "binding-circuit-version-mismatch-rejected"
      { validClaimMatch with bindingCircuitVersionMatches := false } ++ ",\n"
    ++ claimMatchCaseJson "receipt-statement-precedes-root-mismatch"
      { validClaimMatch with
        receiptStatementHashMatches := false,
        bindingAnchorRootMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson

import Hegemon.Native.BlockCommitmentAdmission

open Hegemon.Native.BlockCommitmentAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CommitmentReject -> String
  | none => "null"
  | some CommitmentReject.txCountMismatch => "\"tx_count_mismatch\""
  | some CommitmentReject.stateRootMismatch => "\"state_root_mismatch\""
  | some CommitmentReject.kernelRootMismatch => "\"kernel_root_mismatch\""
  | some CommitmentReject.nullifierRootMismatch => "\"nullifier_root_mismatch\""
  | some CommitmentReject.extrinsicsRootMismatch => "\"extrinsics_root_mismatch\""
  | some CommitmentReject.messageRootMismatch => "\"message_root_mismatch\""
  | some CommitmentReject.messageCountMismatch => "\"message_count_mismatch\""
  | some CommitmentReject.headerMmrRootMismatch => "\"header_mmr_root_mismatch\""
  | some CommitmentReject.headerMmrLenMismatch => "\"header_mmr_len_mismatch\""
  | some CommitmentReject.supplyDigestMismatch => "\"supply_digest_mismatch\""

def blockCommitmentCaseJson (name : String) (input : CommitmentInput) : String :=
  let result := evaluateCommitmentRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"tx_count_matches\": " ++ boolJson input.txCountMatches ++ ",\n"
    ++ "      \"state_root_matches\": " ++ boolJson input.stateRootMatches ++ ",\n"
    ++ "      \"kernel_root_matches\": " ++ boolJson input.kernelRootMatches ++ ",\n"
    ++ "      \"nullifier_root_matches\": " ++ boolJson input.nullifierRootMatches ++ ",\n"
    ++ "      \"extrinsics_root_matches\": " ++ boolJson input.extrinsicsRootMatches ++ ",\n"
    ++ "      \"message_root_matches\": " ++ boolJson input.messageRootMatches ++ ",\n"
    ++ "      \"message_count_matches\": " ++ boolJson input.messageCountMatches ++ ",\n"
    ++ "      \"header_mmr_root_matches\": " ++ boolJson input.headerMmrRootMatches ++ ",\n"
    ++ "      \"header_mmr_len_matches\": " ++ boolJson input.headerMmrLenMatches ++ ",\n"
    ++ "      \"supply_digest_matches\": " ++ boolJson input.supplyDigestMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def validInput : CommitmentInput :=
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

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"block_commitment_admission_cases\": [\n"
    ++ blockCommitmentCaseJson "valid-block-commitments" validInput ++ ",\n"
    ++ blockCommitmentCaseJson "tx-count-mismatch-rejected"
      { validInput with txCountMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "state-root-mismatch-rejected"
      { validInput with stateRootMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "kernel-root-mismatch-rejected"
      { validInput with kernelRootMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "nullifier-root-mismatch-rejected"
      { validInput with nullifierRootMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "extrinsics-root-mismatch-rejected"
      { validInput with extrinsicsRootMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "message-root-mismatch-rejected"
      { validInput with messageRootMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "message-count-mismatch-rejected"
      { validInput with messageCountMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "header-mmr-root-mismatch-rejected"
      { validInput with headerMmrRootMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "header-mmr-len-mismatch-rejected"
      { validInput with headerMmrLenMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "supply-digest-mismatch-rejected"
      { validInput with supplyDigestMatches := false } ++ ",\n"
    ++ blockCommitmentCaseJson "state-root-precedes-supply-digest"
      { validInput with stateRootMatches := false, supplyDigestMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
